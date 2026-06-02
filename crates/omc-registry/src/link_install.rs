//! High-level package link/install orchestration: the public `link_package` /
//! `add_package_graph` / `remove_manifest_dependency` entry points and the
//! private graph-resolution and manifest-writing helpers they drive.

use crate::*;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use omc_cap::{Capability, Policy};
use reqwest::blocking::Client;

// These root-level imports are private `use` declarations in lib.rs and so do
// NOT flow in through `use crate::*`.
use crate::verify::{grants_all_host_capabilities, module_from_profile, render_verify_finding};

pub fn link_package(spec: &PackageSpec, options: &LinkOptions) -> Result<LinkReport> {
    init_project(&options.project_dir, None)?;
    let options = options_with_manifest_policy(options)?;

    let client = Client::builder().user_agent("omc-prototype/0.1").build()?;
    let (report, _) = link_package_inner(&client, spec, false, &options, true)?
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(spec.requested()))?;
    Ok(report)
}

pub fn add_package_graph(spec: &PackageSpec, options: &LinkOptions) -> Result<Vec<LinkReport>> {
    init_project(&options.project_dir, None)?;
    let options = options_with_manifest_policy(options)?;

    let client = Client::builder().user_agent("omc-prototype/0.1").build()?;
    let reports = resolve_package_graph(&client, spec, &options)?;

    if options.save_manifest_dependency {
        let Some(root) = reports.first() else {
            return Ok(reports);
        };
        let spec = manifest_spec_for_locked_root(spec, &root.locked);
        write_manifest_dependency(
            &options.project_dir,
            &spec,
            &root.locked.version,
            options.save_dependency_kind,
        )?;
    }

    Ok(reports)
}

pub fn remove_manifest_dependency(
    project_dir: impl AsRef<Path>,
    spec: &PackageSpec,
) -> Result<bool> {
    let project_dir = project_dir.as_ref();
    init_project(project_dir, None)?;

    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    let removed = manifest.dependencies.remove(&spec.package_key()).is_some()
        || manifest
            .dev_dependencies
            .remove(&spec.package_key())
            .is_some()
        || manifest
            .optional_dependencies
            .remove(&spec.package_key())
            .is_some()
        || manifest
            .peer_dependencies
            .remove(&spec.package_key())
            .is_some();
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(removed)
}

/// Serializes the lock-file read-modify-write across parallel resolver workers
/// (the lock is one shared file per project).
static LOCK_FILE_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Apply `f` to every item, running up to `available_parallelism` calls at once
/// and returning results in input order. Used to resolve+download+profile a whole
/// dependency level concurrently. Each result slot is written by exactly one
/// worker, so the per-slot `Mutex` is uncontended (it just satisfies the borrow
/// checker for disjoint indices).
fn parallel_map<T, R>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R>
where
    T: Sync,
    R: Send,
{
    let n = items.len();
    if n <= 1 {
        return items.iter().map(&f).collect();
    }
    let cap = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .min(n);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let slots: Vec<std::sync::Mutex<Option<R>>> =
        (0..n).map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..cap {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let value = f(&items[i]);
                *slots[i].lock().unwrap_or_else(|err| err.into_inner()) = Some(value);
            });
        }
    });
    slots
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .unwrap_or_else(|err| err.into_inner())
                .expect("every slot is filled by a worker")
        })
        .collect()
}

/// What resolving one package in a BFS level yields: its link report plus the
/// dependencies to fan out into the next level (`None` when a platform-incompatible
/// optional dependency is skipped).
type ResolvedNode = Result<Option<(LinkReport, Vec<PackageDependency>)>>;

/// Resolve the dependency graph of `spec` as a level-parallel breadth-first
/// search: each BFS level (a package and its siblings) is resolved, downloaded,
/// and profiled concurrently across cores, then deduplicated by resolved
/// `eco:name@version` (post-resolution, exactly as the old sequential DFS did)
/// before fanning out to the next level. Dependency graphs are wide and shallow,
/// so per-level parallelism captures most of the speedup with no work-stealing.
pub(crate) fn resolve_package_graph(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<Vec<LinkReport>> {
    // Pre-create the per-project signing key so parallel workers only read it.
    ensure_artifact_signing_key(&options.project_dir)?;

    let mut reports = Vec::new();
    let mut seen = BTreeSet::new();
    let mut frontier: Vec<(PackageSpec, bool)> = vec![(spec.clone(), false)];

    while !frontier.is_empty() {
        let level: Vec<ResolvedNode> = parallel_map(&frontier, |(spec, optional)| {
            link_package_inner(client, spec, *optional, options, false)
        });

        let mut next: Vec<(PackageSpec, bool)> = Vec::new();
        for ((spec, _optional), result) in frontier.iter().zip(level) {
            let Some((report, dependencies)) = result? else {
                continue;
            };
            let resolved_key = format!(
                "{}:{}@{}",
                report.locked.ecosystem,
                spec.name_with_extras(),
                report.locked.version
            );
            if !seen.insert(resolved_key) {
                continue;
            }

            let follow_dependencies = should_follow_locked_dependencies(&report.locked, options);
            reports.push(report);

            if follow_dependencies {
                for dependency in dependencies {
                    if dependency.optional && !options.include_optional_dependencies {
                        continue;
                    }
                    if dependency.peer && !options.include_peer_dependencies {
                        continue;
                    }
                    next.push((dependency.spec, dependency.optional));
                }
            }
        }
        frontier = next;
    }
    Ok(reports)
}

fn link_package_inner(
    client: &Client,
    spec: &PackageSpec,
    optional_dependency: bool,
    options: &LinkOptions,
    update_manifest: bool,
) -> Result<Option<(LinkReport, Vec<PackageDependency>)>> {
    let mut resolved = resolve_package(client, spec, options)?;
    if !resolved.platform_compatible {
        if optional_dependency {
            return Ok(None);
        }

        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{} is not compatible with this platform",
            spec.requested()
        )));
    }

    let archive_bytes = download_artifact(client, &resolved, &options.project_dir)?;
    let sha256 = sha256_hex(&archive_bytes);

    if let Some(expected) = &resolved.expected_sha256 {
        if !expected.eq_ignore_ascii_case(&sha256) {
            return Err(OmcRegistryError::DigestMismatch {
                name: resolved.name.clone(),
                expected: expected.clone(),
                actual: sha256,
            });
        }
    }
    if let Some(expected) = &resolved.expected_sha1 {
        let actual = sha1_hex(&archive_bytes);
        if !expected.eq_ignore_ascii_case(&actual) {
            return Err(OmcRegistryError::DigestMismatch {
                name: resolved.name.clone(),
                expected: format!("sha1:{expected}"),
                actual: format!("sha1:{actual}"),
            });
        }
    }
    if let Some(expected) = &resolved.expected_integrity {
        verify_npm_integrity(&resolved.name, expected, &archive_bytes)?;
    }
    if resolved.ecosystem == Ecosystem::Npm {
        if let Some(integrities) = options.npm_integrities.get(&spec.constraint_key()) {
            for integrity in integrities {
                verify_npm_integrity(&resolved.name, integrity, &archive_bytes)?;
            }
        }
    }
    if let Some(hashes) = options.hashes.get(&spec.constraint_key()) {
        if !hashes.contains(&sha256) {
            return Err(OmcRegistryError::DigestMismatch {
                name: resolved.name.clone(),
                expected: hashes.iter().cloned().collect::<Vec<_>>().join(","),
                actual: sha256,
            });
        }
    }

    let dependencies = if resolved.npm_direct_tarball {
        let manifest = npm_manifest_from_tgz(&archive_bytes)?;
        if manifest.version != resolved.version {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "locked npm tarball version mismatch for `{}`: expected {}, got {}",
                resolved.name, resolved.version, manifest.version
            )));
        }
        resolved.platform_compatible = npm_manifest_platform_compatible(&manifest)
            && npm_manifest_engine_compatible(&manifest, options);
        resolved.npm_scripts = manifest.scripts.clone().unwrap_or_default();
        npm_manifest_runtime_dependencies(&manifest)
    } else if resolved.pypi_direct_wheel {
        pypi_wheel_dependencies(&archive_bytes, &spec.extras)?
    } else if is_python_sdist_filename(&resolved.filename) && resolved.dependencies.is_empty() {
        pypi_sdist_dependencies(&archive_bytes, &resolved.filename, &spec.extras)?
    } else {
        resolved.dependencies.clone()
    };
    if !resolved.platform_compatible {
        if optional_dependency {
            return Ok(None);
        }

        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{} is not compatible with this platform",
            spec.requested()
        )));
    }
    let archive_path = cache_archive(&options.project_dir, &resolved, &sha256, &archive_bytes)?;
    let profile = profile_archive(&resolved, &archive_bytes)?;
    let module = module_from_profile(&resolved, &profile.capabilities);
    let explicit_grants_all_host = grants_all_host_capabilities(&options.allowed_capabilities);
    let policy = policy_from_link_options(options);
    let policy = options
        .allowed_flows
        .iter()
        .cloned()
        .fold(policy, Policy::allow_flow_rule);
    let policy = if explicit_grants_all_host {
        policy.allow_all_flows()
    } else {
        policy
    };
    // Layer the optional per-package `omc.policy` DSL on top of the flat grants
    // so each dependency is verified against ITS block (deny-by-default: a
    // package with no matching block keeps just the default/[policy] grants).
    let policy = effective_package_policy(
        &options.project_dir,
        policy,
        resolved.ecosystem,
        &resolved.name,
        &resolved.version,
    )?;
    // Installing a package runs NONE of its source: OMC never executes
    // install/postinstall scripts and never imports the package. So the
    // network/env/file-read/dns/time/random a library uses *when your app later
    // calls it* are not install-time risks and shouldn't block the install — a
    // legitimate `omc add stripe` should not have to "grant" stripe's runtime
    // API surface. We auto-accept those BENIGN runtime capabilities at the
    // install gate (they remain recorded on the artifact, informational).
    //
    // The genuinely install-/malware-relevant behaviours stay deny-by-default
    // and still block: process spawn (which also represents npm lifecycle
    // scripts — the Shai-Hulud vector), dynamic eval / unresolved obfuscation,
    // file WRITES (persistence/backdoor), reads of SENSITIVE files (denied even
    // under a wildcard grant by the sensitive-read guard), and every
    // secret-source -> sink data FLOW (the exfiltration shape — which is also
    // why a package that *combines* a secret read with a network sink still
    // needs an explicit flow grant).
    let policy = allow_benign_runtime_capabilities(policy);
    let verification = verify_module(&module, &policy);
    let verifier_findings = verification
        .err()
        .map(|error| {
            error
                .findings
                .into_iter()
                .map(render_verify_finding)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let verdict = if verifier_findings.is_empty() {
        Verdict::Accepted
    } else {
        Verdict::Blocked
    };
    let behavior = if profile.capabilities.is_empty() {
        Behavior::Pure
    } else {
        Behavior::HostCapability
    };

    let mut artifact = OmcArtifact {
        schema: ARTIFACT_SCHEMA,
        package: ArtifactPackage {
            ecosystem: resolved.ecosystem,
            name: resolved.name.clone(),
            version: resolved.version.clone(),
        },
        source_url: resolved.source_url.clone(),
        source_sha256: sha256.clone(),
        compiler: "omc-prototype-source-profiler".to_owned(),
        microcode: module,
        behavior,
        verdict,
        grants: options
            .allowed_capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
        dependencies: dependencies
            .iter()
            .filter(|dependency| !dependency.optional && !dependency.peer)
            .map(|dependency| dependency.spec.requested())
            .collect(),
        optional_dependencies: dependencies
            .iter()
            .filter(|dependency| dependency.optional)
            .map(|dependency| dependency.spec.requested())
            .collect(),
        peer_dependencies: dependencies
            .iter()
            .filter(|dependency| dependency.peer)
            .map(|dependency| dependency.spec.requested())
            .collect(),
        files_scanned: profile.files_scanned,
        capabilities: profile.capabilities,
        verifier_findings: verifier_findings.clone(),
        signature: None,
    };
    sign_artifact(&options.project_dir, &mut artifact)?;
    let artifact_path = write_artifact(&options.project_dir, &resolved, &artifact)?;
    let artifact_sha256 = artifact_payload_sha256(&artifact)?;

    let locked = LockedPackage {
        ecosystem: resolved.ecosystem,
        name: resolved.name.clone(),
        version: resolved.version.clone(),
        source_url: resolved.source_url.clone(),
        archive: relative_path(&options.project_dir, &archive_path),
        artifact: relative_path(&options.project_dir, &artifact_path),
        sha256,
        artifact_sha256,
        behavior,
        verdict,
        dependencies: artifact.dependencies.clone(),
        optional_dependencies: artifact.optional_dependencies.clone(),
        peer_dependencies: artifact.peer_dependencies.clone(),
        grants: artifact.grants.clone(),
        capabilities: artifact.capabilities.clone(),
        verifier_findings,
    };

    if locked.verdict == Verdict::Blocked && !options.record_blocked {
        return Err(OmcRegistryError::BlockedPackage {
            spec: spec.requested(),
            suggestion: Some(Box::new(build_block_suggestion(
                locked.ecosystem,
                &locked.name,
                &locked.version,
                &locked.verifier_findings,
            ))),
        });
    }

    if update_manifest && options.save_manifest_dependency {
        let spec = manifest_spec_for_locked_root(spec, &locked);
        write_manifest_dependency(
            &options.project_dir,
            &spec,
            &resolved.version,
            options.save_dependency_kind,
        )?;
    }

    let lockfile = options.project_dir.join(LOCKFILE);
    {
        // The lock is a single shared file per project; serialize the
        // read-modify-write so parallel resolver workers can't clobber each
        // other's entries (or race the lock signing-key creation).
        let _guard = LOCK_FILE_MUTEX
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let mut lock = read_lockfile(&lockfile)?;
        ensure_lock_signing_key(&options.project_dir, &mut lock)?;
        lock.upsert(locked.clone());
        fs::write(&lockfile, toml::to_string_pretty(&lock)?)?;
    }

    let manifest_path = options.project_dir.join(MANIFEST);
    Ok(Some((
        LinkReport {
            locked,
            artifact,
            lockfile,
            manifest: manifest_path,
        },
        dependencies,
    )))
}

pub(crate) fn write_manifest_dependency(
    project_dir: &Path,
    spec: &PackageSpec,
    version: &str,
    kind: ManifestDependencyKind,
) -> Result<()> {
    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    let requirement = spec
        .direct_url
        .as_ref()
        .cloned()
        .unwrap_or_else(|| version.to_owned());
    let key = spec.package_key();
    remove_manifest_dependency_entry(&mut manifest, &key);
    manifest_dependency_map_mut(&mut manifest, kind).insert(key, requirement);
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(())
}

fn remove_manifest_dependency_entry(manifest: &mut OmcManifest, key: &str) {
    manifest.dependencies.remove(key);
    manifest.dev_dependencies.remove(key);
    manifest.optional_dependencies.remove(key);
    manifest.peer_dependencies.remove(key);
}

fn manifest_dependency_map_mut(
    manifest: &mut OmcManifest,
    kind: ManifestDependencyKind,
) -> &mut BTreeMap<String, String> {
    match kind {
        ManifestDependencyKind::Production => &mut manifest.dependencies,
        ManifestDependencyKind::Dev => &mut manifest.dev_dependencies,
        ManifestDependencyKind::Optional => &mut manifest.optional_dependencies,
        ManifestDependencyKind::Peer => &mut manifest.peer_dependencies,
    }
}

pub(crate) fn manifest_spec_for_locked_root(
    spec: &PackageSpec,
    locked: &LockedPackage,
) -> PackageSpec {
    if spec.direct_url.is_none() || spec.name == locked.name {
        return spec.clone();
    }
    let mut spec = spec.clone();
    spec.name = locked.name.clone();
    spec
}

pub(crate) fn options_with_manifest_policy(options: &LinkOptions) -> Result<LinkOptions> {
    let mut options = options.clone();
    let manifest = read_manifest(options.project_dir.join(MANIFEST))?;
    apply_manifest_config(&manifest, &mut options)?;
    Ok(options)
}

pub(crate) fn policy_from_link_options(options: &LinkOptions) -> Policy {
    default_public_capabilities()
        .into_iter()
        .chain(options.allowed_capabilities.iter().cloned())
        .fold(Policy::pure(), Policy::allow_capability)
}

pub(crate) fn default_public_capabilities() -> Vec<Capability> {
    DEFAULT_PUBLIC_ENV_READS
        .iter()
        .map(|name| Capability::EnvRead((*name).to_owned()))
        .collect()
}
