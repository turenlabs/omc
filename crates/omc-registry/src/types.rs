use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use omc_cap::{Capability, FlowRule};
use omc_format::Module;
use serde::{Deserialize, Serialize};

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
    pub(crate) fn new(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: Option<String>,
    ) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version,
            extras: BTreeSet::new(),
            direct_url: None,
        }
    }

    pub(crate) fn with_extras(
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

    pub(crate) fn with_direct_url(
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

    pub(crate) fn constraint_key(&self) -> String {
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

    pub(crate) fn name_with_extras(&self) -> String {
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

pub(crate) fn parse_npm_spec(raw: &str, rest: &str) -> Result<PackageSpec> {
    if let Some((name, url)) = rest.split_once(" @ ") {
        let name = name.trim();
        let url = url.trim();
        if name.is_empty() || url.is_empty() {
            return Err(OmcRegistryError::UnsupportedSpec(raw.to_owned()));
        }
        let url = npm_github_archive_url(url)?.unwrap_or_else(|| url.to_owned());
        return Ok(PackageSpec::with_direct_url(
            Ecosystem::Npm,
            name,
            url,
            BTreeSet::new(),
        ));
    }

    if let Some((alias, target)) = rest.split_once("@npm:") {
        if alias.is_empty() || target.is_empty() {
            return Err(OmcRegistryError::UnsupportedSpec(raw.to_owned()));
        }
        return Ok(PackageSpec::new(
            Ecosystem::Npm,
            alias,
            Some(format!("npm:{target}")),
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
    #[serde(default, rename = "optional-dependencies")]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "peer-dependencies")]
    pub peer_dependencies: BTreeMap<String, String>,
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
    #[serde(
        default,
        rename = "npm-optional-local-paths",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub npm_optional_local_paths: Vec<String>,
    #[serde(
        default,
        rename = "npm-peer-local-paths",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub npm_peer_local_paths: Vec<String>,
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
    #[serde(default, rename = "allow-flow")]
    pub allow_flow: Vec<String>,
    /// Project-wide minimum release age (a supply-chain freshness floor): a
    /// package version must have been published at least this long ago to be
    /// installed. A duration like "14d"/"12h"/"2w"/"7"(days). Per-package
    /// `min-age` rules in `omc.policy` layer on top of this. Optional.
    #[serde(
        default,
        rename = "min-release-age",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_release_age: Option<String>,
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
        self.allow.is_empty() && self.allow_flow.is_empty() && self.min_release_age.is_none()
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
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
            npm_local_paths: Vec::new(),
            npm_dev_local_paths: Vec::new(),
            npm_optional_local_paths: Vec::new(),
            npm_peer_local_paths: Vec::new(),
            policy: ManifestPolicy::default(),
            registries: ManifestRegistries::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ManifestDependencyKind {
    #[default]
    Production,
    Dev,
    Optional,
    Peer,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OmcLock {
    pub version: u32,
    /// F3 trust anchor: the base64 ed25519 PUBLIC key of the project's artifact
    /// signing key, pinned on first sign. `install --locked`/`ci` require every
    /// artifact's embedded `signature.public_key` to equal this value, so an
    /// attacker who re-signs a tampered artifact with their OWN key is rejected.
    /// Optional + skip-if-empty for back-compat with pre-F3 lockfiles (which are
    /// then treated as untrusted and must be re-locked).
    #[serde(
        default,
        rename = "signing-key",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_key: Option<String>,
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
    #[serde(default)]
    pub local_sources: Vec<LockedLocalSource>,
    #[serde(default)]
    pub python_vcs: Vec<LockedPythonVcsDependency>,
}

impl OmcLock {
    pub fn new() -> Self {
        Self {
            version: 1,
            signing_key: None,
            packages: Vec::new(),
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        }
    }

    pub(crate) fn upsert(&mut self, package: LockedPackage) {
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

    pub(crate) fn replace_local_sources(&mut self, mut sources: Vec<LockedLocalSource>) {
        sources.sort_by(|left, right| {
            locked_local_source_sort_key(left).cmp(&locked_local_source_sort_key(right))
        });
        sources.dedup_by(|left, right| {
            locked_local_source_request_key(left) == locked_local_source_request_key(right)
        });
        self.local_sources = sources;
    }

    pub(crate) fn replace_python_vcs(&mut self, mut dependencies: Vec<LockedPythonVcsDependency>) {
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
    /// F3 trust anchor: sha256 of the artifact JSON payload (signature stripped)
    /// recorded at lock time. `install --locked`/`ci` re-hash the on-disk
    /// artifact and require it to equal this, so a tampered artifact (even one
    /// re-signed with the project's own key) is rejected. serde default keeps
    /// pre-F3 lockfiles parseable (an empty value disables the pin for that
    /// entry, so old locks must be re-locked to gain the protection).
    #[serde(
        default,
        rename = "artifact-sha256",
        skip_serializing_if = "String::is_empty"
    )]
    pub artifact_sha256: String,
    pub behavior: Behavior,
    pub verdict: Verdict,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub optional_dependencies: Vec<String>,
    #[serde(default)]
    pub peer_dependencies: Vec<String>,
    #[serde(default)]
    pub grants: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<CapabilityFinding>,
    #[serde(default)]
    pub verifier_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedLocalSource {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub source_url: String,
    pub source_path: String,
    pub artifact: String,
    pub sha256: String,
    pub behavior: Behavior,
    pub verdict: Verdict,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PypiCheckIssue {
    Missing {
        package: String,
        version: String,
        requirement: String,
    },
    Incompatible {
        package: String,
        version: String,
        requirement: String,
        installed_name: String,
        installed_version: String,
    },
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
    #[serde(default)]
    pub peer_dependencies: Vec<String>,
    pub files_scanned: usize,
    pub capabilities: Vec<CapabilityFinding>,
    pub verifier_findings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ArtifactSignature>,
}

#[derive(Debug, Clone)]
pub struct CompileSourceOptions {
    pub project_dir: PathBuf,
    pub source_path: PathBuf,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub allowed_capabilities: Vec<Capability>,
    pub allowed_flows: Vec<FlowRule>,
    pub write_artifact: bool,
}

#[derive(Debug, Clone)]
pub struct CompileSourceReport {
    pub artifact: OmcArtifact,
    pub artifact_path: Option<PathBuf>,
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
    pub allowed_flows: Vec<FlowRule>,
    pub constraints: BTreeMap<String, String>,
    pub npm_overrides: BTreeMap<String, String>,
    pub hashes: BTreeMap<String, BTreeSet<String>>,
    pub npm_integrities: BTreeMap<String, BTreeSet<String>>,
    pub npm_resolved: BTreeMap<String, String>,
    pub npm_registry_url: Option<String>,
    pub npm_before: Option<String>,
    pub npm_engine_strict: bool,
    pub npm_offline: bool,
    pub pypi_binary_all: Option<PypiBinaryMode>,
    pub pypi_binary_packages: BTreeMap<String, PypiBinaryMode>,
    pub pypi_index_url: Option<String>,
    pub pypi_extra_index_urls: Vec<String>,
    pub pypi_find_links: Vec<String>,
    pub pypi_no_index: bool,
    pub pypi_require_hashes: bool,
    pub pypi_include_dependencies: bool,
    pub pypi_allow_prereleases: bool,
    pub pypi_release_controls: PypiReleaseControls,
    pub pypi_uploaded_prior_to: Option<String>,
    pub pypi_target_python: Option<String>,
    pub pypi_target_implementation: Option<String>,
    pub pypi_target_platforms: Vec<String>,
    pub pypi_target_abis: Vec<String>,
    pub pypi_environment_base_dir: Option<PathBuf>,
    pub python_target_dir: Option<PathBuf>,
    pub python_bin_dir: Option<PathBuf>,
    pub python_target_overwrite_existing: bool,
    pub npm_local_paths: Vec<PathBuf>,
    pub npm_discovered_local_paths: Vec<PathBuf>,
    pub python_local_paths: Vec<PathBuf>,
    pub python_local_requirements: Vec<PythonLocalRequirement>,
    pub python_vcs_requirements: Vec<PythonVcsRequirement>,
    pub python_vcs_locks: Vec<LockedPythonVcsDependency>,
    pub requirement_files: Vec<PathBuf>,
    pub constraint_files: Vec<PathBuf>,
    pub project_extras: BTreeSet<String>,
    pub include_dev_dependencies: bool,
    pub include_optional_dependencies: bool,
    pub include_peer_dependencies: bool,
    pub discover_project_requirements: bool,
    pub save_manifest_dependency: bool,
    pub save_dependency_kind: ManifestDependencyKind,
    pub enforce_local_source_verdicts: bool,
    /// Project/global default minimum release age in seconds (a supply-chain
    /// freshness floor): a package version younger than this is rejected at
    /// resolution. Resolved from `omc.toml`/`~/.omc/omc.toml` `[policy]
    /// min-release-age`. `omc.policy` per-package `min-age` rules layer on top
    /// via `policy_document`. `None` = no project/global floor.
    pub min_release_age_secs: Option<i64>,
    /// The parsed `omc.policy` DSL document, when present, for per-package
    /// `min-age` (and used elsewhere for the per-package capability policy).
    pub policy_document: Option<omc_policy::PolicyDocument>,
}

impl LinkOptions {
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            record_blocked: false,
            allowed_capabilities: Vec::new(),
            allowed_flows: Vec::new(),
            constraints: BTreeMap::new(),
            npm_overrides: BTreeMap::new(),
            hashes: BTreeMap::new(),
            npm_integrities: BTreeMap::new(),
            npm_resolved: BTreeMap::new(),
            npm_registry_url: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            pypi_binary_all: None,
            pypi_binary_packages: BTreeMap::new(),
            pypi_index_url: None,
            pypi_extra_index_urls: Vec::new(),
            pypi_find_links: Vec::new(),
            pypi_no_index: false,
            pypi_require_hashes: false,
            pypi_include_dependencies: true,
            pypi_allow_prereleases: false,
            pypi_release_controls: PypiReleaseControls::default(),
            pypi_uploaded_prior_to: None,
            pypi_target_python: None,
            pypi_target_implementation: None,
            pypi_target_platforms: Vec::new(),
            pypi_target_abis: Vec::new(),
            pypi_environment_base_dir: None,
            python_target_dir: None,
            python_bin_dir: None,
            python_target_overwrite_existing: true,
            npm_local_paths: Vec::new(),
            npm_discovered_local_paths: Vec::new(),
            python_local_paths: Vec::new(),
            python_local_requirements: Vec::new(),
            python_vcs_requirements: Vec::new(),
            python_vcs_locks: Vec::new(),
            requirement_files: Vec::new(),
            constraint_files: Vec::new(),
            project_extras: BTreeSet::new(),
            include_dev_dependencies: true,
            include_optional_dependencies: true,
            include_peer_dependencies: true,
            discover_project_requirements: true,
            save_manifest_dependency: true,
            save_dependency_kind: ManifestDependencyKind::Production,
            enforce_local_source_verdicts: true,
            min_release_age_secs: None,
            policy_document: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PypiBinaryMode {
    Binary,
    Source,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PypiReleaseControl {
    pub all: bool,
    pub packages: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PypiReleaseControls {
    pub all_releases: PypiReleaseControl,
    pub only_final: PypiReleaseControl,
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
    pub local_source_artifacts: usize,
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
    pub npm_overrides: BTreeMap<String, String>,
    pub hashes: BTreeMap<String, BTreeSet<String>>,
    pub npm_integrities: BTreeMap<String, BTreeSet<String>>,
    pub npm_resolved: BTreeMap<String, String>,
    pub npm_local_paths: Vec<PathBuf>,
    pub pypi_binary_all: Option<PypiBinaryMode>,
    pub pypi_binary_packages: BTreeMap<String, PypiBinaryMode>,
    pub pypi_index_url: Option<String>,
    pub pypi_extra_index_urls: Vec<String>,
    pub pypi_find_links: Vec<String>,
    pub pypi_no_index: bool,
    pub pypi_require_hashes: bool,
    pub pypi_no_deps: bool,
    pub pypi_allow_prereleases: bool,
    pub pypi_release_controls: PypiReleaseControls,
    pub pypi_uploaded_prior_to: Option<String>,
    pub python_local_paths: Vec<PathBuf>,
    pub python_local_requirements: Vec<PythonLocalRequirement>,
    pub python_local_directory_requirements: Vec<PythonLocalRequirement>,
    pub python_vcs_requirements: Vec<PythonVcsRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PythonLocalRequirement {
    pub path: PathBuf,
    pub extras: BTreeSet<String>,
}

impl PythonLocalRequirement {
    pub fn new(path: PathBuf, extras: BTreeSet<String>) -> Self {
        Self { path, extras }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PythonVcsRequirement {
    pub name: String,
    pub url: String,
    pub reference: Option<String>,
    pub subdirectory: Option<PathBuf>,
    pub extras: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct GlobalConfig {
    #[serde(default)]
    pub(crate) policy: ManifestPolicy,
}
