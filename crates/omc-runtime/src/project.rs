//! Lock-graph driver: wire an `omc.lock` + `omc.toml` project into in-cell
//! execution.
//!
//! [`execute_project`] takes a project directory and an [`ExecTarget`] (an
//! explicit entry source file, or an installed package resolved through the
//! lock), lowers the entry and EVERY transitively-imported dependency to real
//! bytecode via the matching language front end, assembles the closed
//! [`LinkUnit`] graph, and hands it to [`crate::execute`] so the whole program
//! is linked, whole-program verified (cross-package taint), and run under the
//! project policy + broker.
//!
//! Deny-by-default is preserved end to end:
//! - the policy is built ONLY from the manifest grants (same parsing the CLI
//!   uses);
//! - an import that does not resolve to a locked package is a hard error;
//! - a dependency whose REAL source cannot be lowered (out-of-subset) is a hard
//!   error — never silently skipped, never host-executed.
//!
//! The package SOURCE is lowered offline and only verified bytecode runs inside
//! the fueled VM; this driver never executes install/runtime scripts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use omc_cap::{CapabilityBroker, Policy};
use omc_format::Value;
use omc_linker::{ImportRef, LinkUnit};
use omc_registry::{
    parse_capability_grant, parse_flow_rule, read_locked_package_entry_source, read_lockfile,
    read_manifest, Ecosystem, LockedPackage, OmcLock, PackageSpec,
};
use omc_taint::Labeled;

use crate::{execute, ExecError};

/// What to run inside the project: an explicit entry source file, or an
/// installed package name resolved through the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecTarget {
    /// An explicit source file on disk (relative to the project dir or absolute).
    /// The ecosystem is inferred from its extension (`.js`/`.mjs`/`.cjs` -> npm,
    /// `.py` -> pypi). It is lowered as a synthetic entry module that may
    /// `require`/`import` lock-resolved packages.
    EntryFile {
        /// Path to the entry source file.
        path: PathBuf,
        /// The package name to stamp on the synthetic entry module id.
        name: String,
        /// The version to stamp on the synthetic entry module id.
        version: String,
    },
    /// An installed package (by name) whose entry source comes from the lock's
    /// cached archive. If `ecosystem` is `None`, the lock is searched across
    /// ecosystems and an ambiguous match is an error.
    Package {
        /// The package name as it appears in the lock.
        name: String,
        /// Restrict resolution to one ecosystem, if known.
        ecosystem: Option<Ecosystem>,
    },
}

impl ExecTarget {
    /// An entry source file with a default synthetic module identity.
    pub fn entry_file(path: impl Into<PathBuf>) -> Self {
        Self::EntryFile {
            path: path.into(),
            name: "omc-entry".to_owned(),
            version: "0.0.0".to_owned(),
        }
    }

    /// An installed package resolved through the lock.
    pub fn package(name: impl Into<String>) -> Self {
        Self::Package {
            name: name.into(),
            ecosystem: None,
        }
    }
}

/// Read the lockfile + manifest for `project_dir`, resolve `entry` to its real
/// source, lower the entry and every transitively-imported dependency, assemble
/// the closed link graph, and run it through the verify -> link -> execute
/// pipeline under the manifest policy.
///
/// Returns the entry module's result value (with taint label). Any failure —
/// unreadable lock, unparseable grant, unresolved import, unlowerable
/// dependency, verification rejection, or runtime trap — is surfaced as an
/// [`ExecError`]; nothing falls back to host execution.
pub fn execute_project(
    project_dir: &Path,
    entry: ExecTarget,
    args: Vec<Labeled<Value>>,
    broker: &mut dyn CapabilityBroker,
) -> Result<Labeled<Value>, ExecError> {
    let policy = project_policy(project_dir)?;
    execute_project_with_policy(project_dir, entry, &policy, args, broker)
}

/// Like [`execute_project`] but with the policy supplied by the caller. This lets
/// a CLI layer one-shot `--allow`/`--allow-flow` grants on top of the manifest
/// policy and have them apply to the WHOLE graph (not just leaf runs), keeping
/// the graph and leaf code paths on a single consistent policy. The manifest
/// remains the source of the persistent project policy; the caller just decides
/// the final policy it is run under. Deny-by-default is unchanged: every member
/// module is still whole-program verified against this policy before it runs.
pub fn execute_project_with_policy(
    project_dir: &Path,
    entry: ExecTarget,
    policy: &Policy,
    args: Vec<Labeled<Value>>,
    broker: &mut dyn CapabilityBroker,
) -> Result<Labeled<Value>, ExecError> {
    let lock = read_lockfile(project_dir.join("omc.lock")).map_err(to_lock_error)?;

    // 1. Resolve the entry to a lowered module + its import table.
    let (entry_id, mut graph) = match entry {
        ExecTarget::EntryFile {
            path,
            name,
            version,
        } => {
            let full_path = if path.is_absolute() {
                path.clone()
            } else {
                project_dir.join(&path)
            };
            let ecosystem = infer_ecosystem(&full_path)?;
            let source = std::fs::read_to_string(&full_path).map_err(|error| {
                ExecError::Io(format!("reading entry `{}`: {error}", full_path.display()))
            })?;
            let module_id = module_id(ecosystem, &name, &version);
            let lowered = lower_source(ecosystem, &name, &version, &source)?;
            let mut graph = HashMap::new();
            graph.insert(module_id.clone(), lowered);
            (module_id, graph)
        }
        ExecTarget::Package { name, ecosystem } => {
            let package = resolve_entry_package(&lock, &name, ecosystem)?;
            let module_id = locked_module_id(package);
            let lowered = lower_locked_package(project_dir, package)?;
            let mut graph = HashMap::new();
            graph.insert(module_id.clone(), lowered);
            (module_id, graph)
        }
    };

    // 2. Transitively lower every dependency reachable through the lowered
    //    modules' import tables. `pending` holds module ids whose imports still
    //    need to be walked. The importer's lock `dependencies` resolve each
    //    `ImportSpec.package` -> a concrete locked package.
    let mut pending: Vec<String> = vec![entry_id.clone()];
    while let Some(importer_id) = pending.pop() {
        let imports = graph
            .get(&importer_id)
            .map(|lowered| lowered.imports.clone())
            .unwrap_or_default();
        if imports.is_empty() {
            continue;
        }
        // The importer's lock entry supplies the dependency-name -> locked
        // package edges. The synthetic entry file has no lock entry; its
        // imports resolve against the lock's full package set by name.
        let importer_pkg = lock
            .packages
            .iter()
            .find(|pkg| locked_module_id(pkg) == importer_id);
        for spec in imports {
            let dep_pkg = resolve_import(&lock, importer_pkg, &importer_id, &spec.package)?;
            let dep_id = locked_module_id(dep_pkg);
            if !graph.contains_key(&dep_id) {
                let lowered = lower_locked_package(project_dir, dep_pkg)?;
                graph.insert(dep_id.clone(), lowered);
                pending.push(dep_id);
            }
        }
    }

    // 3. Turn each lowered module + its import table into a LinkUnit, mapping
    //    every ImportSpec to a concrete ImportRef (module id from the lock,
    //    function = the member name or the target's entry function name).
    let mut units = Vec::with_capacity(graph.len());
    for (module_id, lowered) in &graph {
        let importer_pkg = lock
            .packages
            .iter()
            .find(|pkg| &locked_module_id(pkg) == module_id);
        let mut imports = Vec::with_capacity(lowered.imports.len());
        for spec in &lowered.imports {
            let dep_pkg = resolve_import(&lock, importer_pkg, module_id, &spec.package)?;
            let dep_id = locked_module_id(dep_pkg);
            let function = match &spec.member {
                Some(member) => member.clone(),
                None => target_entry_function(&graph, &dep_id, module_id, &spec.package)?,
            };
            imports.push(ImportRef {
                module: dep_id,
                function,
            });
        }
        units.push(LinkUnit {
            module: lowered.module.clone(),
            imports,
        });
    }

    // 4. Link + whole-program verify + run the closed graph in-cell.
    execute(units, &entry_id, policy, broker, args)
}

/// Build the project [`Policy`] from the manifest's `policy.allow` /
/// `policy.allow-flow`, reusing the SAME grant parsing the CLI uses.
fn project_policy(project_dir: &Path) -> Result<Policy, ExecError> {
    let manifest = read_manifest(project_dir.join("omc.toml")).map_err(to_lock_error)?;
    let mut policy = Policy::pure();
    for grant in &manifest.policy.allow {
        let capability = parse_capability_grant(grant)
            .map_err(|error| ExecError::Lock(format!("policy grant `{grant}`: {error}")))?;
        policy = policy.allow_capability(capability);
    }
    for flow in &manifest.policy.allow_flow {
        let rule = parse_flow_rule(flow)
            .map_err(|error| ExecError::Lock(format!("policy flow `{flow}`: {error}")))?;
        policy = policy.allow_flow_rule(rule);
    }
    Ok(policy)
}

/// A module lowered from real source, paired with its positional import table.
type Lowered = omc_format::CompileOutput;

/// Lower an in-memory source string through the matching front end. A
/// FrontendError (out-of-subset / unlowerable) is a hard [`ExecError::Lower`].
fn lower_source(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    source: &str,
) -> Result<Lowered, ExecError> {
    match ecosystem {
        Ecosystem::Npm => {
            let meta = omc_frontend_js::PackageMeta {
                package: name.to_owned(),
                version: version.to_owned(),
                declared_behavior: omc_format::BehaviorType::Unknown,
            };
            omc_frontend_js::compile(source, &meta)
                .map_err(|error| ExecError::Lower(format!("{}: {error}", module_id(ecosystem, name, version))))
        }
        Ecosystem::Pypi => {
            let meta = omc_frontend_py::PackageMeta {
                package: name.to_owned(),
                version: version.to_owned(),
                declared_behavior: omc_format::BehaviorType::Unknown,
            };
            omc_frontend_py::compile(source, &meta)
                .map_err(|error| ExecError::Lower(format!("{}: {error}", module_id(ecosystem, name, version))))
        }
    }
}

/// Read a locked package's real entry source from its cached archive and lower
/// it. Both archive errors and lowering errors fail closed.
fn lower_locked_package(
    project_dir: &Path,
    package: &LockedPackage,
) -> Result<Lowered, ExecError> {
    let entry = read_locked_package_entry_source(project_dir, package)
        .map_err(|error| ExecError::Lock(format!("entry source for {}: {error}", locked_module_id(package))))?;
    lower_source(package.ecosystem, &package.name, &package.version, &entry.source)
}

/// Resolve the ENTRY package (by name, optionally ecosystem) in the lock.
/// Ambiguous (same name across ecosystems with no hint) and missing both fail.
fn resolve_entry_package<'a>(
    lock: &'a OmcLock,
    name: &str,
    ecosystem: Option<Ecosystem>,
) -> Result<&'a LockedPackage, ExecError> {
    let matches: Vec<&LockedPackage> = lock
        .packages
        .iter()
        .filter(|pkg| pkg.name == name && ecosystem.map_or(true, |eco| pkg.ecosystem == eco))
        .collect();
    match matches.as_slice() {
        [] => Err(ExecError::Lock(format!(
            "entry package `{name}` is not present in omc.lock"
        ))),
        [package] => Ok(package),
        _ => Err(ExecError::Lock(format!(
            "entry package `{name}` is ambiguous in omc.lock; specify an ecosystem"
        ))),
    }
}

/// Resolve one `ImportSpec.package` referenced by `importer_id` to a concrete
/// locked package.
///
/// When the importer is itself a locked package, the resolution is driven by its
/// lock `dependencies` edges (`"eco:name@ver"` specs) so the version is exactly
/// the one the importer was locked against. For a synthetic entry file (no lock
/// entry) the import resolves against the lock's package set by name. Either way,
/// an import that does not resolve to a locked package is a HARD error —
/// deny-by-default, never host-executed.
fn resolve_import<'a>(
    lock: &'a OmcLock,
    importer_pkg: Option<&LockedPackage>,
    importer_id: &str,
    package: &str,
) -> Result<&'a LockedPackage, ExecError> {
    if let Some(importer) = importer_pkg {
        // Find the dependency edge whose parsed name matches the import.
        for dep_spec in importer
            .dependencies
            .iter()
            .chain(importer.optional_dependencies.iter())
            .chain(importer.peer_dependencies.iter())
        {
            let spec = PackageSpec::parse(dep_spec).map_err(|error| {
                ExecError::Lock(format!(
                    "{importer_id}: malformed dependency spec `{dep_spec}`: {error}"
                ))
            })?;
            if spec.name == package && spec.ecosystem == importer.ecosystem {
                return find_locked_by_name(lock, importer.ecosystem, &spec.name).ok_or_else(|| {
                    ExecError::Lock(format!(
                        "{importer_id}: dependency `{package}` is declared but not present in omc.lock"
                    ))
                });
            }
        }
        return Err(ExecError::Lock(format!(
            "{importer_id}: imports `{package}`, which is not a declared lock dependency"
        )));
    }

    // Synthetic entry file: resolve the bare import name against the lock. We do
    // not know the ecosystem of the import a priori, so match by name and reject
    // an ambiguous cross-ecosystem hit.
    let matches: Vec<&LockedPackage> =
        lock.packages.iter().filter(|pkg| pkg.name == package).collect();
    match matches.as_slice() {
        [] => Err(ExecError::Lock(format!(
            "entry `{importer_id}` imports `{package}`, which is not present in omc.lock"
        ))),
        [pkg] => Ok(pkg),
        _ => Err(ExecError::Lock(format!(
            "entry `{importer_id}` import `{package}` is ambiguous across ecosystems in omc.lock"
        ))),
    }
}

/// Find a locked package by ecosystem + exact name.
fn find_locked_by_name<'a>(
    lock: &'a OmcLock,
    ecosystem: Ecosystem,
    name: &str,
) -> Option<&'a LockedPackage> {
    lock.packages
        .iter()
        .find(|pkg| pkg.ecosystem == ecosystem && pkg.name == name)
}

/// The target export name for an import with no explicit member: the lowered
/// target module's entry function name. Failing closed if the target was not
/// lowered or has no entry function.
fn target_entry_function(
    graph: &HashMap<String, Lowered>,
    dep_id: &str,
    importer_id: &str,
    package: &str,
) -> Result<String, ExecError> {
    let target = graph.get(dep_id).ok_or_else(|| {
        ExecError::Lock(format!(
            "{importer_id}: import `{package}` resolved to `{dep_id}` which was not lowered"
        ))
    })?;
    target
        .module
        .entry()
        .map(|function| function.name.clone())
        .ok_or_else(|| {
            ExecError::Lower(format!("target module `{dep_id}` has no entry function to import"))
        })
}

/// The canonical `eco:name@version` id of a locked package (matches `Module.id`).
fn locked_module_id(package: &LockedPackage) -> String {
    module_id(package.ecosystem, &package.name, &package.version)
}

/// Format a module id from its parts: `npm:{name}@{ver}` / `pypi:{name}@{ver}`.
fn module_id(ecosystem: Ecosystem, name: &str, version: &str) -> String {
    format!("{ecosystem}:{name}@{version}")
}

/// Infer the ecosystem of an entry source file from its extension.
fn infer_ecosystem(path: &Path) -> Result<Ecosystem, ExecError> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("js") | Some("mjs") | Some("cjs") => Ok(Ecosystem::Npm),
        Some("py") => Ok(Ecosystem::Pypi),
        _ => Err(ExecError::Lower(format!(
            "cannot infer ecosystem for entry `{}` (expected .js/.mjs/.cjs or .py)",
            path.display()
        ))),
    }
}

/// Map a registry error raised while reading the lock/manifest to a Lock error.
fn to_lock_error(error: omc_registry::OmcRegistryError) -> ExecError {
    ExecError::Lock(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Write as _;

    use omc_cap::{Capability, MemoryBroker, Policy};
    use omc_registry::{Behavior, LockedPackage, OmcLock, Verdict};
    use sha2::{Digest, Sha256};

    // ---- test fixtures -----------------------------------------------------

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Build a minimal npm `.tgz` (gzip tarball) containing a package.json with
    /// `main` and the named source files, each entry prefixed with `package/`.
    fn npm_tgz(main: &str, files: &[(&str, &str)]) -> Vec<u8> {
        let package_json = format!(r#"{{"name":"x","version":"1.0.0","main":"{main}"}}"#);
        let mut entries: Vec<(String, String)> =
            vec![("package.json".to_owned(), package_json)];
        for (path, content) in files {
            entries.push(((*path).to_owned(), (*content).to_owned()));
        }
        tgz(&entries.iter().map(|(p, c)| (format!("package/{p}"), c.clone())).collect::<Vec<_>>())
    }

    /// Build a minimal pypi sdist `.tar.gz` with a top-level dist directory and
    /// the named source files.
    fn pypi_targz(files: &[(&str, &str)]) -> Vec<u8> {
        tgz(&files
            .iter()
            .map(|(p, c)| (format!("dist-1.0.0/{p}"), (*c).to_owned()))
            .collect::<Vec<_>>())
    }

    fn tgz(entries: &[(String, String)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let encoder =
                flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            for (path, content) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                archive
                    .append_data(&mut header, path, content.as_bytes())
                    .unwrap();
            }
            archive.into_inner().unwrap().finish().unwrap();
        }
        bytes
    }

    /// Write an archive into the project's cache and return a populated
    /// LockedPackage pointing at it (sha256 verified by the reader).
    fn locked_pkg(
        project_dir: &Path,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        archive_bytes: &[u8],
        dependencies: Vec<String>,
    ) -> LockedPackage {
        let rel = format!(".omc/cache/{ecosystem}/{name}-{version}.tgz");
        let archive_path = project_dir.join(&rel);
        fs::create_dir_all(archive_path.parent().unwrap()).unwrap();
        fs::write(&archive_path, archive_bytes).unwrap();
        LockedPackage {
            ecosystem,
            name: name.to_owned(),
            version: version.to_owned(),
            source_url: format!("https://example/{name}"),
            archive: rel,
            artifact: format!(".omc/artifacts/{name}.json"),
            sha256: sha256_hex(archive_bytes),
            behavior: Behavior::Pure,
            verdict: Verdict::Accepted,
            dependencies,
            optional_dependencies: Vec::new(),
            peer_dependencies: Vec::new(),
            grants: Vec::new(),
            capabilities: Vec::new(),
            verifier_findings: Vec::new(),
        }
    }

    /// Persist an OmcLock to `<project>/omc.lock` so `read_lockfile` reads it.
    fn write_lock(project_dir: &Path, packages: Vec<LockedPackage>) {
        let lock = OmcLock {
            version: 1,
            packages,
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        };
        let toml = toml::to_string(&lock).unwrap();
        let mut file = fs::File::create(project_dir.join("omc.lock")).unwrap();
        file.write_all(toml.as_bytes()).unwrap();
    }

    fn write_manifest(project_dir: &Path, allow: &[&str], allow_flow: &[&str]) {
        let allow_list = allow
            .iter()
            .map(|grant| format!("\"{grant}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let flow_list = allow_flow
            .iter()
            .map(|flow| format!("\"{flow}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let manifest = format!(
            "[project]\nname = \"demo\"\nversion = \"0.0.0\"\n\n[policy]\nallow = [{allow_list}]\nallow-flow = [{flow_list}]\n"
        );
        fs::write(project_dir.join("omc.toml"), manifest).unwrap();
    }

    // ---- graph assembly + import resolution --------------------------------

    /// A locked npm package importing another locked package runs end to end:
    /// the driver reads both archives, lowers both, resolves the import edge from
    /// the lock, links the graph, and executes the entry.
    #[test]
    fn package_entry_imports_locked_dependency_and_runs() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);

        let is_odd = locked_pkg(
            project,
            Ecosystem::Npm,
            "is-odd",
            "3.0.1",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function isOdd(n) { return n % 2 === 1; };",
                )],
            ),
            Vec::new(),
        );
        let is_even = locked_pkg(
            project,
            Ecosystem::Npm,
            "is-even",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function isEven(n) { const dep = require('is-odd'); return !dep(n); };",
                )],
            ),
            vec!["npm:is-odd@^3.0.0".to_owned()],
        );
        write_lock(project, vec![is_even, is_odd]);

        let mut broker = MemoryBroker::new();
        let result = execute_project(
            project,
            ExecTarget::package("is-even"),
            vec![Labeled::public(Value::Int(4))],
            &mut broker,
        )
        .unwrap();
        // isEven(4) = !isOdd(4) = !false = true.
        assert_eq!(result.value, Value::Bool(true));
    }

    /// An explicit entry source FILE that requires a locked package: the entry
    /// has no lock entry, so the import resolves against the lock by name.
    #[test]
    fn entry_file_imports_locked_dependency_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);

        let is_odd = locked_pkg(
            project,
            Ecosystem::Npm,
            "is-odd",
            "3.0.1",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function isOdd(n) { return n % 2 === 1; };",
                )],
            ),
            Vec::new(),
        );
        write_lock(project, vec![is_odd]);

        fs::write(
            project.join("main.js"),
            "module.exports = function main(n) { const dep = require('is-odd'); return dep(n); };",
        )
        .unwrap();

        let mut broker = MemoryBroker::new();
        let result = execute_project(
            project,
            ExecTarget::entry_file("main.js"),
            vec![Labeled::public(Value::Int(7))],
            &mut broker,
        )
        .unwrap();
        assert_eq!(result.value, Value::Bool(true));
    }

    /// A leaf package with no imports runs through the same path.
    #[test]
    fn leaf_package_runs() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);
        let is_odd = locked_pkg(
            project,
            Ecosystem::Npm,
            "is-odd",
            "3.0.1",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function isOdd(n) { return n % 2 === 1; };",
                )],
            ),
            Vec::new(),
        );
        write_lock(project, vec![is_odd]);

        let mut broker = MemoryBroker::new();
        let result = execute_project(
            project,
            ExecTarget::package("is-odd"),
            vec![Labeled::public(Value::Int(3))],
            &mut broker,
        )
        .unwrap();
        assert_eq!(result.value, Value::Bool(true));
    }

    // ---- deny-by-default ---------------------------------------------------

    /// An import to a package that the importer does NOT declare in its lock
    /// dependencies is a hard Lock error — never silently skipped.
    #[test]
    fn undeclared_import_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);

        // is-even requires is-odd, but the lock gives is-even NO dependency edge.
        let is_odd = locked_pkg(
            project,
            Ecosystem::Npm,
            "is-odd",
            "3.0.1",
            &npm_tgz(
                "index.js",
                &[("index.js", "module.exports = function isOdd(n) { return n % 2 === 1; };")],
            ),
            Vec::new(),
        );
        let is_even = locked_pkg(
            project,
            Ecosystem::Npm,
            "is-even",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function isEven(n) { const dep = require('is-odd'); return !dep(n); };",
                )],
            ),
            Vec::new(), // <- no declared dependency
        );
        write_lock(project, vec![is_even, is_odd]);

        let mut broker = MemoryBroker::new();
        let err = execute_project(
            project,
            ExecTarget::package("is-even"),
            vec![Labeled::public(Value::Int(4))],
            &mut broker,
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Lock(_)), "got {err}");
    }

    /// A declared dependency that is MISSING from the lock packages is rejected.
    #[test]
    fn missing_dependency_package_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);

        let is_even = locked_pkg(
            project,
            Ecosystem::Npm,
            "is-even",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function isEven(n) { const dep = require('is-odd'); return !dep(n); };",
                )],
            ),
            vec!["npm:is-odd@^3.0.0".to_owned()], // declared but not locked
        );
        write_lock(project, vec![is_even]);

        let mut broker = MemoryBroker::new();
        let err = execute_project(
            project,
            ExecTarget::package("is-even"),
            vec![Labeled::public(Value::Int(4))],
            &mut broker,
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Lock(_)), "got {err}");
    }

    /// A dependency whose REAL source is outside the supported subset is a hard
    /// Lower error — never host-executed, never silently dropped.
    #[test]
    fn unlowerable_dependency_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);

        // The dependency's source uses a construct outside the JS subset (a
        // class declaration) so the front end rejects it.
        let broken = locked_pkg(
            project,
            Ecosystem::Npm,
            "broken-dep",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[("index.js", "class Oops { @@@ not valid js @@@ }")],
            ),
            Vec::new(),
        );
        let app = locked_pkg(
            project,
            Ecosystem::Npm,
            "app",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function main(n) { const d = require('broken-dep'); return d(n); };",
                )],
            ),
            vec!["npm:broken-dep@1.0.0".to_owned()],
        );
        write_lock(project, vec![app, broken]);

        let mut broker = MemoryBroker::new();
        let err = execute_project(
            project,
            ExecTarget::package("app"),
            vec![Labeled::public(Value::Int(1))],
            &mut broker,
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Lower(_)), "got {err}");
    }

    /// A package that is not in the lock at all is rejected at entry resolution.
    #[test]
    fn unknown_entry_package_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);
        write_lock(project, Vec::new());

        let mut broker = MemoryBroker::new();
        let err = execute_project(
            project,
            ExecTarget::package("ghost"),
            vec![],
            &mut broker,
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Lock(_)), "got {err}");
    }

    // ---- policy is built from the manifest ---------------------------------

    /// The policy comes from the MANIFEST: a package that reads env is rejected
    /// at verification unless the manifest grants the capability. Here no grant
    /// is present, so the env-reading entry is denied.
    #[test]
    fn manifest_policy_denies_ungranted_capability() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]); // empty policy

        let reader = locked_pkg(
            project,
            Ecosystem::Npm,
            "read-home",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function readHome() { return process.env.HOME; };",
                )],
            ),
            Vec::new(),
        );
        write_lock(project, vec![reader]);

        let mut broker = MemoryBroker::new().with_env("HOME", "/home/omc");
        let err = execute_project(
            project,
            ExecTarget::package("read-home"),
            vec![],
            &mut broker,
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Verify { .. }), "got {err}");
    }

    /// The same env-reading package runs once the MANIFEST grants `env:HOME`,
    /// proving the policy is sourced from the manifest grants.
    #[test]
    fn manifest_policy_admits_granted_capability() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &["env:HOME"], &[]);

        let reader = locked_pkg(
            project,
            Ecosystem::Npm,
            "read-home",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function readHome() { return process.env.HOME; };",
                )],
            ),
            Vec::new(),
        );
        write_lock(project, vec![reader]);

        let mut broker = MemoryBroker::new().with_env("HOME", "/home/omc");
        let result = execute_project(
            project,
            ExecTarget::package("read-home"),
            vec![],
            &mut broker,
        )
        .unwrap();
        assert_eq!(result.value, Value::String("/home/omc".to_owned()));
    }

    /// `execute_project_with_policy` runs the graph under the CALLER's policy,
    /// not the manifest. This is what lets the CLI layer one-shot
    /// `--allow`/`--allow-flow` grants on top of the manifest for graph runs
    /// (previously the graph path silently ignored CLI flags). With an EMPTY
    /// manifest, the same env-reading package is denied under a pure injected
    /// policy and admitted under an injected policy that grants `env:HOME`.
    #[test]
    fn injected_policy_is_used_for_graph_runs() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]); // manifest grants nothing

        let reader = locked_pkg(
            project,
            Ecosystem::Npm,
            "read-home",
            "1.0.0",
            &npm_tgz(
                "index.js",
                &[(
                    "index.js",
                    "module.exports = function readHome() { return process.env.HOME; };",
                )],
            ),
            Vec::new(),
        );
        write_lock(project, vec![reader]);

        // Pure injected policy: denied at verification despite nothing in the
        // manifest changing.
        let mut broker = MemoryBroker::new().with_env("HOME", "/home/omc");
        let err = execute_project_with_policy(
            project,
            ExecTarget::package("read-home"),
            &Policy::pure(),
            vec![],
            &mut broker,
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Verify { .. }), "got {err}");

        // Caller injects the grant (as the CLI would from `--allow env:HOME`):
        // the same graph now runs.
        let granted = Policy::pure().allow_capability(Capability::EnvRead("HOME".to_owned()));
        let mut broker = MemoryBroker::new().with_env("HOME", "/home/omc");
        let result = execute_project_with_policy(
            project,
            ExecTarget::package("read-home"),
            &granted,
            vec![],
            &mut broker,
        )
        .unwrap();
        assert_eq!(result.value, Value::String("/home/omc".to_owned()));
    }

    // ---- pypi entry-source location ----------------------------------------

    /// A pypi package's entry source is located at `{name}/__init__.py` and
    /// lowered/run through the py front end.
    #[test]
    fn pypi_package_entry_source_is_located_and_run() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        write_manifest(project, &[], &[]);

        let pkg = locked_pkg(
            project,
            Ecosystem::Pypi,
            "mathy",
            "1.0.0",
            &pypi_targz(&[("mathy/__init__.py", "def main(n):\n    return n + 1\n")]),
            Vec::new(),
        );
        write_lock(project, vec![pkg]);

        let mut broker = MemoryBroker::new();
        let result = execute_project(
            project,
            ExecTarget::package("mathy"),
            vec![Labeled::public(Value::Int(41))],
            &mut broker,
        )
        .unwrap();
        assert_eq!(result.value, Value::Int(42));
    }
}
