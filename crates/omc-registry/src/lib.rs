use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::OnceLock;
use std::{env, fmt};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};
use flate2::read::GzDecoder;
use omc_cap::{Capability, FlowRule, LabelMatcher, Policy, Sink};
use omc_format::{BehaviorType, CapOp, Function, HttpRequest, Module, Op, Value, VirtualPath};
use omc_verify::{verify_module, VerifyFinding};
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Certificate, Identity};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use tar::Archive;
use walkdir::{DirEntry, WalkDir};


mod error;
pub use error::{OmcRegistryError, Result};

pub(crate) mod manifest;
pub use manifest::{
    add_manifest_npm_local_paths, add_manifest_policy_flows, add_manifest_policy_grants,
    init_project, read_manifest, write_global_package_trust,
};

pub(crate) mod types;
pub use types::{
    ArtifactPackage, ArtifactSignature, Behavior, CapabilityFinding, CapabilityKind,
    CompileSourceOptions, CompileSourceReport, Ecosystem, InstallReport, LinkOptions, LinkReport,
    LockedLocalSource, LockedPackage, LockedPythonVcsDependency, ManifestDependencyKind,
    ManifestPolicy, ManifestRegistries, OmcArtifact, OmcLock, OmcManifest, PackageSpec, ProjectInfo,
    ProjectRequirements, PypiBinaryMode, PypiCheckIssue, PypiReleaseControl, PypiReleaseControls,
    PythonLocalRequirement, PythonVcsRequirement, Verdict,
};
use types::{parse_npm_spec, GlobalConfig};

pub(crate) mod lockfile;
pub use lockfile::read_lockfile;
use lockfile::{
    locked_package_key, locked_reachable_package_keys, prune_lockfile, sync_python_vcs_lockfile,
};

pub(crate) mod http_client;
use http_client::{artifact_path_for, cache_archive, download_artifact, write_artifact};

pub(crate) mod npm_resolve;
use npm_resolve::{
    NpmPackageManifest, NpmPeerDependencyMeta, NpmRoot, NpmSearchResponse, NpmStringList, NpmVersion,
};
#[cfg(test)]
use npm_resolve::NpmDist;

pub(crate) mod npm_install;
use npm_install::{
    collect_npm_local_dependency_links, install_nested_npm_dependencies, install_npm_direct_local_links,
    install_npm_package, install_npm_project_links, npm_project_package_jsons,
};
#[cfg(test)]
use npm_install::install_npm_package_to;

pub(crate) mod npm_config;
pub use npm_config::{
    read_npm_config_snapshot, read_npm_config_snapshot_with_globalconfig, NpmConfigSnapshot,
};
use npm_config::{
    ensure_trailing_slash, npm_registry_package_url, npm_registry_package_version_url,
    read_npm_config, read_npm_config_for_options, strip_npmrc_comment, NpmConfig,
};
#[cfg(test)]
use npm_config::{
    apply_npm_environment_values, parse_npmrc_content, read_npm_user_config, read_npmrc_into,
    NpmAuthToken,
};

pub(crate) mod npm_metadata;
pub use npm_metadata::{
    add_npm_dist_tag, add_npm_team_user, create_npm_team, create_npm_token, create_npm_trust,
    deprecate_npm_package, destroy_npm_team, download_npm_package_tarball, grant_npm_access,
    mutate_npm_package_owner, mutate_npm_package_star, publish_npm_package,
    read_npm_access_collaborators, read_npm_access_packages, read_npm_access_status,
    read_npm_org_users, read_npm_package_metadata, read_npm_package_metadata_with_userconfig,
    read_npm_package_owners, read_npm_ping, read_npm_ping_with_userconfig, read_npm_profile,
    read_npm_stars, read_npm_team_users, read_npm_teams, read_npm_token_list, read_npm_trust,
    read_npm_whoami, remove_npm_dist_tag, remove_npm_org_user, remove_npm_team_user,
    revoke_npm_access, revoke_npm_token, revoke_npm_trust, set_npm_access_mfa, set_npm_access_status,
    set_npm_org_user, set_npm_profile_property, unpublish_npm_package,
};

pub(crate) mod pypi_resolve;
pub use pypi_resolve::{parse_pypi_vcs_requirement, pypi_marker_applies};
pub(crate) use pypi_resolve::parse_pypi_name_and_extras;
#[cfg(test)]
use pypi_resolve::{evaluate_pypi_marker, PypiMarkerEnvironment};
use pypi_resolve::{
    collect_pypi_project_requirement, is_pypi_archive_filename, is_pypi_archive_reference,
    normalize_pypi_extra, normalize_pypi_find_links_source, normalize_pypi_name,
    normalize_pypi_simple_index_url, normalize_requirements_editable_path,
    parse_pypi_direct_archive_url_reference, parse_pypi_direct_requirement,
    parse_pypi_local_archive_requirement, parse_pypi_local_direct_path_requirement,
    parse_pypi_local_direct_requirement, parse_pypi_local_path_requirement, parse_pypi_requirement,
    parse_pypi_requirement_with_extras, parse_pypi_vcs_direct_requirement,
    parse_python_vcs_requirement, parse_requirements_all_releases,
    parse_requirements_allow_prereleases, parse_requirements_bare_vcs_requirement,
    parse_requirements_binary_option, parse_requirements_compatible_global_option,
    parse_requirements_editable_value, parse_requirements_editable_vcs_requirement,
    parse_requirements_extra_index_url, parse_requirements_find_links, parse_requirements_include,
    parse_requirements_index_url, parse_requirements_no_deps, parse_requirements_no_index,
    parse_requirements_only_final, parse_requirements_require_hashes,
    parse_requirements_uploaded_prior_to, pypi_direct_file_url_local_directory,
    pypi_direct_reference_applies, python_vcs_table_reference, PypiProjectRequirement,
};

pub(crate) mod pypi_config;
pub use pypi_config::{read_pip_config_snapshot, PipConfigSnapshot};
use pypi_config::{
    apply_pip_config_files, dedupe_pypi_extra_index_urls, env_truthy, pypi_index_url_values,
    pypi_path_values,
};
#[cfg(test)]
use pypi_config::{parse_pip_config_content, read_pip_config, PipConfig};
pub(crate) mod pypi_install;
use pypi_install::{
    folded_metadata_lines, install_pypi_package, install_python_entry_point_scripts,
    is_ignorable_archive_metadata_path, pypi_sdist_dependencies, pypi_wheel_dependencies,
    read_python_local_entry_points,
};
#[cfg(test)]
use pypi_install::{
    is_python_startup_hook_path, parse_python_entry_points, parse_setup_py_entry_points,
    python_dist_info_component, python_entry_point_script, should_copy_python_sdist_path,
};
pub(crate) mod profiler;
use profiler::{hash_profiled_directory, profile_archive, profile_source_directory};
#[cfg(test)]
use profiler::{ArchiveProfile, SourceProfiler};

pub(crate) mod signature;
pub use signature::verify_artifact_signature;
use signature::{artifact_payload_sha256, ensure_lock_signing_key, sign_artifact};
#[cfg(test)]
use signature::project_signing_public_key;
#[cfg(test)]
use ed25519_dalek::{Signer, SigningKey};
#[cfg(test)]
use rand_core::OsRng;

pub(crate) const LOCKFILE: &str = "omc.lock";
pub(crate) const MANIFEST: &str = "omc.toml";
/// Optional per-package capability policy DSL, layered on top of the flat
/// `[policy]` grants in `omc.toml`. When absent, behaviour is exactly as before.
const POLICY_FILE: &str = "omc.policy";
const ARTIFACT_SCHEMA: u32 = 1;
pub(crate) const ARTIFACT_SIGNING_KEY: &str = "artifact-ed25519.key";
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_PUBLIC_ENV_READS: &[&str] = &["NODE_DEBUG"];
const NPM_DIRECT_TARBALL_PLACEHOLDER: &str = "__omc_direct_tarball__";
const NPM_PROFILE_WRITABLE_KEYS: &[&str] = &[
    "email", "password", "fullname", "homepage", "freenode", "twitter", "github",
];




#[derive(Debug, Clone, Copy)]
struct DependencySelection {
    dev: bool,
    optional: bool,
    peer: bool,
}

impl DependencySelection {
    fn with_dev(dev: bool) -> Self {
        Self {
            dev,
            optional: true,
            peer: true,
        }
    }

    fn from_options(options: &LinkOptions) -> Self {
        Self {
            dev: options.include_dev_dependencies,
            optional: options.include_optional_dependencies,
            peer: options.include_peer_dependencies,
        }
    }
}



pub fn apply_pypi_binary_option(
    all: &mut Option<PypiBinaryMode>,
    packages: &mut BTreeMap<String, PypiBinaryMode>,
    mode: PypiBinaryMode,
    value: &str,
) {
    for raw in value.split(',') {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        match value {
            ":all:" => *all = Some(mode),
            ":none:" => {
                if *all == Some(mode) {
                    *all = None;
                }
                packages.retain(|_, existing| *existing != mode);
            }
            package => {
                packages.insert(normalize_pypi_name(package), mode);
            }
        }
    }
}


pub fn apply_pypi_release_control(control: &mut PypiReleaseControl, value: &str) {
    for raw in value.split(',') {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        match value {
            ":all:" => control.all = true,
            ":none:" => {
                control.all = false;
                control.packages.clear();
            }
            package => {
                control.packages.insert(normalize_pypi_name(package));
            }
        }
    }
}

fn merge_pypi_release_control(target: &mut PypiReleaseControl, source: PypiReleaseControl) {
    target.all |= source.all;
    target.packages.extend(source.packages);
}

fn merge_pypi_release_controls(target: &mut PypiReleaseControls, source: PypiReleaseControls) {
    merge_pypi_release_control(&mut target.all_releases, source.all_releases);
    merge_pypi_release_control(&mut target.only_final, source.only_final);
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
    target.npm_overrides.extend(requirements.npm_overrides);
    target.hashes.extend(requirements.hashes);
    target.npm_integrities.extend(requirements.npm_integrities);
    target.npm_resolved.extend(requirements.npm_resolved);
    target.npm_local_paths.extend(requirements.npm_local_paths);
    if requirements.pypi_binary_all.is_some() {
        target.pypi_binary_all = requirements.pypi_binary_all;
    }
    target
        .pypi_binary_packages
        .extend(requirements.pypi_binary_packages);
    if requirements.pypi_index_url.is_some() {
        target.pypi_index_url = requirements.pypi_index_url;
    }
    target
        .pypi_extra_index_urls
        .extend(requirements.pypi_extra_index_urls);
    target.pypi_find_links.extend(requirements.pypi_find_links);
    target.pypi_no_index |= requirements.pypi_no_index;
    target.pypi_require_hashes |= requirements.pypi_require_hashes;
    target.pypi_no_deps |= requirements.pypi_no_deps;
    target.pypi_allow_prereleases |= requirements.pypi_allow_prereleases;
    merge_pypi_release_controls(
        &mut target.pypi_release_controls,
        requirements.pypi_release_controls,
    );
    if requirements.pypi_uploaded_prior_to.is_some() {
        target.pypi_uploaded_prior_to = requirements.pypi_uploaded_prior_to;
    }
    target
        .python_local_paths
        .extend(requirements.python_local_paths);
    target
        .python_local_requirements
        .extend(requirements.python_local_requirements);
    target
        .python_local_directory_requirements
        .extend(requirements.python_local_directory_requirements);
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
    options.npm_overrides.extend(requirements.npm_overrides);
    options.hashes.extend(requirements.hashes);
    options.npm_integrities.extend(requirements.npm_integrities);
    options.npm_resolved.extend(requirements.npm_resolved);
    options
        .npm_discovered_local_paths
        .extend(requirements.npm_local_paths);
    if requirements.pypi_binary_all.is_some() {
        options.pypi_binary_all = requirements.pypi_binary_all;
    }
    options
        .pypi_binary_packages
        .extend(requirements.pypi_binary_packages);
    if requirements.pypi_index_url.is_some() {
        options.pypi_index_url = requirements.pypi_index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(requirements.pypi_extra_index_urls);
    options.pypi_find_links.extend(requirements.pypi_find_links);
    options.pypi_no_index |= requirements.pypi_no_index;
    options.pypi_require_hashes |= requirements.pypi_require_hashes;
    options.pypi_allow_prereleases |= requirements.pypi_allow_prereleases;
    merge_pypi_release_controls(
        &mut options.pypi_release_controls,
        requirements.pypi_release_controls,
    );
    if requirements.pypi_uploaded_prior_to.is_some() {
        options.pypi_uploaded_prior_to = requirements.pypi_uploaded_prior_to;
    }
    if requirements.pypi_no_deps {
        options.pypi_include_dependencies = false;
    }
    options
        .python_local_paths
        .extend(requirements.python_local_paths);
    options
        .python_local_requirements
        .extend(requirements.python_local_requirements);
    for requirement in requirements.python_local_directory_requirements {
        if !options.python_local_paths.contains(&requirement.path) {
            options.python_local_paths.push(requirement.path.clone());
        }
        options.python_local_requirements.push(requirement);
    }
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
pub(crate) struct PackageDependency {
    pub(crate) spec: PackageSpec,
    pub(crate) optional: bool,
    pub(crate) peer: bool,
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

pub fn remove_locked_packages(
    project_dir: impl AsRef<Path>,
    specs: &[PackageSpec],
) -> Result<Vec<String>> {
    let project_dir = project_dir.as_ref();
    let lockfile = project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    let mut removed = Vec::new();
    let mut removed_locked_pypi_names = BTreeSet::new();
    // F6 hygiene: collect the (ecosystem, name, version) of removed entries so we
    // can also prune their on-disk artifact + cache directories (the lock edit
    // alone would orphan `.omc/artifacts/<eco>/<pkg>/` and `.omc/cache/<eco>/<pkg>/`).
    let mut pruned_artifacts: Vec<(Ecosystem, String, String)> = Vec::new();
    lock.packages.retain(|package| {
        let should_remove = specs
            .iter()
            .any(|spec| locked_package_matches_spec(package, spec));
        if should_remove {
            if package.ecosystem == Ecosystem::Pypi {
                removed_locked_pypi_names.insert(normalize_pypi_name(&package.name));
            }
            pruned_artifacts.push((
                package.ecosystem,
                package.name.clone(),
                package.version.clone(),
            ));
            removed.push(locked_package_key(package));
            false
        } else {
            true
        }
    });

    let removed_pypi_names = specs
        .iter()
        .filter(|spec| spec.ecosystem == Ecosystem::Pypi)
        .map(|spec| normalize_pypi_name(&spec.name))
        .collect::<BTreeSet<_>>();
    let mut removed_vcs = Vec::new();
    if !removed_pypi_names.is_empty() {
        lock.python_vcs.retain(|dependency| {
            let name = normalize_pypi_name(&dependency.name);
            let should_remove = removed_pypi_names.contains(&name);
            if should_remove {
                if !removed_locked_pypi_names.contains(&name) {
                    removed_vcs.push(format!("pypi:{}", dependency.name));
                }
                false
            } else {
                true
            }
        });
    }

    if !removed.is_empty() || !removed_vcs.is_empty() {
        fs::write(lockfile, toml::to_string_pretty(&lock)?)?;
    }

    // F6 hygiene: prune orphaned artifact + cache directories for removed
    // packages, and an emptied node_modules/.bin. Best-effort: failures here must
    // not fail the uninstall (the lock — the source of truth — is already updated).
    for (ecosystem, name, version) in &pruned_artifacts {
        prune_removed_package_artifacts(project_dir, *ecosystem, name, version);
    }
    prune_empty_npm_bin_dir(project_dir);

    removed.extend(removed_vcs);
    Ok(removed)
}

/// F6 — remove the artifact + cache directories left behind by an uninstalled
/// package. Best-effort: removes the version dir and, if it becomes empty, the
/// package dir. Paths are built from the package coordinates (same scheme as
/// `artifact_path_for` / `cache_archive`).
fn prune_removed_package_artifacts(
    project_dir: &Path,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) {
    let omc = project_dir.join(".omc");
    for root in ["artifacts", "cache"] {
        let package_dir = omc
            .join(root)
            .join(ecosystem.to_string())
            .join(safe_name(name));
        let version_dir = package_dir.join(version);
        let _ = remove_path_if_exists(&version_dir);
        // Remove the now-empty package directory if no other versions remain.
        if let Ok(mut entries) = fs::read_dir(&package_dir) {
            if entries.next().is_none() {
                let _ = fs::remove_dir(&package_dir);
            }
        }
    }
}

/// F6 — remove `node_modules/.bin` if it is now empty after an uninstall (it is
/// otherwise left dangling). Best-effort.
fn prune_empty_npm_bin_dir(project_dir: &Path) {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    if let Ok(mut entries) = fs::read_dir(&bin_dir) {
        if entries.next().is_none() {
            let _ = fs::remove_dir(&bin_dir);
        }
    }
}

pub fn prune_locked_package_versions(
    project_dir: impl AsRef<Path>,
    keep_packages: &[LockedPackage],
) -> Result<Vec<String>> {
    let project_dir = project_dir.as_ref();
    let lockfile = project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    let keep_keys = keep_packages
        .iter()
        .map(locked_package_key)
        .collect::<BTreeSet<_>>();
    let affected_names = keep_packages
        .iter()
        .map(locked_package_name_key)
        .collect::<BTreeSet<_>>();
    let mut removed = Vec::new();
    lock.packages.retain(|package| {
        let affected = affected_names.contains(&locked_package_name_key(package));
        let keep = keep_keys.contains(&locked_package_key(package));
        if affected && !keep {
            removed.push(locked_package_key(package));
            false
        } else {
            true
        }
    });
    if !removed.is_empty() {
        fs::write(lockfile, toml::to_string_pretty(&lock)?)?;
    }
    Ok(removed)
}

fn locked_package_matches_spec(package: &LockedPackage, spec: &PackageSpec) -> bool {
    if package.ecosystem != spec.ecosystem {
        return false;
    }
    match spec.ecosystem {
        Ecosystem::Npm => package.name == spec.name,
        Ecosystem::Pypi => normalize_pypi_name(&package.name) == normalize_pypi_name(&spec.name),
    }
}

pub fn check_pypi_lock(lock: &OmcLock) -> Vec<PypiCheckIssue> {
    let constraints = BTreeMap::new();
    let hashes = BTreeMap::new();
    let mut issues = Vec::new();
    for package in lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
    {
        for dependency in &package.dependencies {
            let Ok(spec) = PackageSpec::parse(dependency) else {
                continue;
            };
            if spec.ecosystem != Ecosystem::Pypi {
                continue;
            }
            if find_locked_package_for_spec(lock, &spec, &constraints, &BTreeMap::new(), &hashes)
                .is_some()
            {
                continue;
            }

            let requirement = pypi_requirement_label(&spec);
            if let Some(installed) = lock.packages.iter().find(|installed| {
                installed.ecosystem == Ecosystem::Pypi
                    && normalize_pypi_name(&installed.name) == spec.name
            }) {
                issues.push(PypiCheckIssue::Incompatible {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    requirement,
                    installed_name: installed.name.clone(),
                    installed_version: installed.version.clone(),
                });
            } else {
                issues.push(PypiCheckIssue::Missing {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    requirement,
                });
            }
        }
    }
    issues
}

fn pypi_requirement_label(spec: &PackageSpec) -> String {
    let mut name = spec.name.clone();
    if !spec.extras.is_empty() {
        name.push('[');
        name.push_str(&spec.extras.iter().cloned().collect::<Vec<_>>().join(","));
        name.push(']');
    }
    if let Some(url) = &spec.direct_url {
        format!("{name} @ {url}")
    } else if let Some(version) = &spec.version {
        format!("{name}{version}")
    } else {
        name
    }
}

pub fn install_project(options: &LinkOptions) -> Result<InstallReport> {
    init_project(&options.project_dir, None)?;

    let mut options = options.clone();
    lock_project_options(&mut options)?;
    let lock = read_lockfile(options.project_dir.join(LOCKFILE))?;
    let local_source_artifacts = compile_local_source_artifacts(&options, false)?;
    let mut report = install_lock_with_python_target(
        &options.project_dir,
        &lock,
        options.python_target_dir.as_deref(),
        options.python_bin_dir.as_deref(),
        options.python_target_overwrite_existing,
    )?;
    report.local_source_artifacts += local_source_artifacts;
    report.npm_bins += install_npm_project_links(
        &options.project_dir,
        &report.node_modules,
        &report.npm_bin_dir,
        DependencySelection::from_options(&options),
    )?;
    report.npm_bins += install_npm_direct_local_links(
        &options.npm_discovered_local_paths,
        &report.node_modules,
        &report.npm_bin_dir,
    )?;
    report.npm_bins += install_npm_direct_local_links(
        &options.npm_local_paths,
        &report.node_modules,
        &report.npm_bin_dir,
    )?;
    report.python_scripts += install_python_local_paths(
        &python_install_local_paths(&options),
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
    let local_source_artifacts = compile_local_source_artifacts(&options, true)?;

    let mut report = install_lock_with_python_target(
        &options.project_dir,
        &selected,
        options.python_target_dir.as_deref(),
        options.python_bin_dir.as_deref(),
        options.python_target_overwrite_existing,
    )?;
    report.local_source_artifacts += local_source_artifacts;
    report.npm_bins += install_npm_project_links(
        &options.project_dir,
        &report.node_modules,
        &report.npm_bin_dir,
        DependencySelection::from_options(&options),
    )?;
    report.npm_bins += install_npm_direct_local_links(
        &options.npm_discovered_local_paths,
        &report.node_modules,
        &report.npm_bin_dir,
    )?;
    report.npm_bins += install_npm_direct_local_links(
        &options.npm_local_paths,
        &report.node_modules,
        &report.npm_bin_dir,
    )?;
    report.python_scripts += install_python_local_paths(
        &python_install_local_paths(&options),
        &report.python_site_packages,
        &report.python_bin_dir,
    )?;
    Ok(report)
}

fn python_install_local_paths(options: &LinkOptions) -> Vec<PathBuf> {
    let mut paths = options.python_local_paths.clone();
    paths.extend(
        options
            .python_local_requirements
            .iter()
            .map(|requirement| requirement.path.clone()),
    );
    paths
}

#[derive(Debug, Clone)]
struct LocalSourceCompileInput {
    ecosystem: Ecosystem,
    source_path: PathBuf,
    name: String,
    version: String,
}

fn compile_local_source_artifacts(options: &LinkOptions, locked: bool) -> Result<usize> {
    let mut inputs = npm_local_source_compile_inputs(
        &options.project_dir,
        &npm_source_compile_paths(options),
        DependencySelection::from_options(options),
    )?;
    inputs.extend(python_local_source_compile_inputs(
        &python_install_local_paths(options),
    )?);

    let mut count = 0;
    let mut locked_sources = Vec::new();
    let mut seen = BTreeSet::new();
    let canonical_project_dir =
        fs::canonicalize(&options.project_dir).unwrap_or_else(|_| options.project_dir.clone());
    for input in inputs {
        let key = format!(
            "{}:{}@{}:{}",
            input.ecosystem,
            input.name,
            input.version,
            input.source_path.display()
        );
        if !seen.insert(key) {
            continue;
        }

        let report = compile_source_path(CompileSourceOptions {
            project_dir: options.project_dir.clone(),
            source_path: input.source_path.clone(),
            ecosystem: input.ecosystem,
            name: input.name.clone(),
            version: input.version.clone(),
            allowed_capabilities: options.allowed_capabilities.clone(),
            allowed_flows: options.allowed_flows.clone(),
            write_artifact: !locked,
        })?;
        if report.artifact.verdict == Verdict::Blocked
            && options.enforce_local_source_verdicts
            && !options.record_blocked
        {
            return Err(OmcRegistryError::BlockedPackage {
                spec: format!(
                    "{}:{}@{} local source `{}`",
                    input.ecosystem,
                    input.name,
                    input.version,
                    input.source_path.display()
                ),
                guidance: Some(render_block_guidance(
                    input.ecosystem,
                    &input.name,
                    &input.version,
                    &report.artifact.verifier_findings,
                )),
            });
        }
        let artifact_path = if locked {
            artifact_path_for(
                &options.project_dir,
                input.ecosystem,
                &input.name,
                &input.version,
            )
        } else {
            report.artifact_path.as_ref().cloned().ok_or_else(|| {
                OmcRegistryError::UnsupportedInstallArtifact(format!(
                    "local source artifact for {}:{}@{} was not stored",
                    input.ecosystem, input.name, input.version
                ))
            })?
        };
        let canonical_artifact_path =
            fs::canonicalize(&artifact_path).unwrap_or_else(|_| artifact_path.clone());
        locked_sources.push(LockedLocalSource {
            ecosystem: input.ecosystem,
            name: input.name,
            version: input.version,
            source_url: report.artifact.source_url.clone(),
            source_path: relative_path(&canonical_project_dir, &input.source_path),
            artifact: relative_path(&canonical_project_dir, &canonical_artifact_path),
            sha256: report.artifact.source_sha256.clone(),
            behavior: report.artifact.behavior,
            verdict: report.artifact.verdict,
            grants: report.artifact.grants.clone(),
            capabilities: report.artifact.capabilities.clone(),
            verifier_findings: report.artifact.verifier_findings.clone(),
        });
        count += 1;
    }
    sync_local_source_lockfile(&options.project_dir, locked_sources, locked)?;

    Ok(count)
}

fn npm_source_compile_paths(options: &LinkOptions) -> Vec<PathBuf> {
    let mut paths = options.npm_local_paths.clone();
    paths.extend(options.npm_discovered_local_paths.clone());
    paths
}

fn sync_local_source_lockfile(
    project_dir: &Path,
    sources: Vec<LockedLocalSource>,
    locked: bool,
) -> Result<()> {
    let lockfile = project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    if locked {
        validate_locked_local_sources(project_dir, &lock, &sources)?;
        return Ok(());
    }

    ensure_lock_signing_key(project_dir, &mut lock)?;
    lock.replace_local_sources(sources);
    fs::write(lockfile, toml::to_string_pretty(&lock)?)?;
    Ok(())
}

fn validate_locked_local_sources(
    project_dir: &Path,
    lock: &OmcLock,
    sources: &[LockedLocalSource],
) -> Result<()> {
    for source in sources {
        let key = locked_local_source_request_key(source);
        let Some(locked) = lock
            .local_sources
            .iter()
            .find(|locked| locked_local_source_request_key(locked) == key)
        else {
            return Err(OmcRegistryError::LockfileOutOfDate(format!(
                "{}:{} local source `{}`",
                source.ecosystem, source.name, source.source_path
            )));
        };
        if locked.version != source.version
            || locked.sha256 != source.sha256
            || locked.artifact != source.artifact
            || locked.behavior != source.behavior
            || locked.verdict != source.verdict
            || locked.grants != source.grants
            || locked.capabilities != source.capabilities
            || locked.verifier_findings != source.verifier_findings
        {
            return Err(OmcRegistryError::LockfileOutOfDate(format!(
                "{}:{} local source `{}`",
                source.ecosystem, source.name, source.source_path
            )));
        }
        verify_locked_local_source_artifact(project_dir, locked, lock.signing_key.as_deref())?;
    }
    Ok(())
}

fn verify_locked_local_source_artifact(
    project_dir: &Path,
    source: &LockedLocalSource,
    pinned_key: Option<&str>,
) -> Result<()> {
    let artifact_path = checked_join(project_dir, Path::new(&source.artifact))?;
    let artifact = serde_json::from_str::<OmcArtifact>(&fs::read_to_string(&artifact_path)?)?;
    verify_artifact_signature(&artifact)?;
    // F3 trust anchor (local sources): require the project's pinned signing key.
    // The full field-by-field cross-check below already binds verdict/grants/
    // capabilities to the lock, so a payload pin is redundant here; the key pin
    // closes the re-signing gap.
    if let Some(pinned_key) = pinned_key.filter(|key| !key.is_empty()) {
        if artifact.signature.as_ref().map(|s| s.public_key.as_str()) != Some(pinned_key) {
            return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
                "local source artifact `{}` for {}:{}@{} is not signed by the project key \
                 pinned in omc.lock — refusing to trust a re-signed artifact",
                source.artifact, source.ecosystem, source.name, source.version
            )));
        }
    }
    if artifact.package.ecosystem != source.ecosystem
        || artifact.package.name != source.name
        || artifact.package.version != source.version
        || artifact.source_url != source.source_url
        || artifact.source_sha256 != source.sha256
        || artifact.behavior != source.behavior
        || artifact.verdict != source.verdict
        || artifact.grants != source.grants
        || artifact.capabilities != source.capabilities
        || artifact.verifier_findings != source.verifier_findings
    {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
            "local source artifact `{}` does not match lock entry for {}:{}@{}",
            source.artifact, source.ecosystem, source.name, source.version
        )));
    }
    Ok(())
}

fn locked_local_source_request_key(source: &LockedLocalSource) -> (Ecosystem, String, String) {
    let name = match source.ecosystem {
        Ecosystem::Npm => source.name.clone(),
        Ecosystem::Pypi => normalize_pypi_name(&source.name),
    };
    (source.ecosystem, name, source.source_path.clone())
}

fn locked_local_source_sort_key(
    source: &LockedLocalSource,
) -> (Ecosystem, String, String, String, String) {
    let (ecosystem, name, source_path) = locked_local_source_request_key(source);
    (
        ecosystem,
        name,
        source_path,
        source.version.clone(),
        source.sha256.clone(),
    )
}

fn npm_local_source_compile_inputs(
    project_dir: &Path,
    direct_paths: &[PathBuf],
    selection: DependencySelection,
) -> Result<Vec<LocalSourceCompileInput>> {
    let mut inputs = Vec::new();
    for path in direct_paths {
        push_npm_local_source_compile_input(&mut inputs, path, None)?;
    }

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        let root = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        if let Some(workspaces) = root.workspaces {
            for package_json in workspace_package_json_paths(project_dir, &workspaces) {
                if let Some(package_dir) = package_json.parent() {
                    push_npm_local_source_compile_input(&mut inputs, package_dir, None)?;
                }
            }
        }
    }

    for package_json in npm_project_package_jsons(project_dir)? {
        let base_dir = package_json.parent().unwrap_or(project_dir);
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let mut links = Vec::new();
        collect_npm_local_dependency_links(&package, selection, base_dir, &mut links)?;
        for link in links {
            push_npm_local_source_compile_input(&mut inputs, &link.path, Some(&link.name))?;
        }
    }

    Ok(inputs)
}

fn push_npm_local_source_compile_input(
    inputs: &mut Vec<LocalSourceCompileInput>,
    path: &Path,
    install_name: Option<&str>,
) -> Result<()> {
    let source_path = fs::canonicalize(path).map_err(|error| {
        OmcRegistryError::UnsupportedRequirement(format!(
            "local npm path `{}` could not be resolved: {error}",
            path.display()
        ))
    })?;
    if !source_path.is_dir() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "local npm path `{}` must point to an existing directory",
            source_path.display()
        )));
    }
    let package_json = source_path.join("package.json");
    if !package_json.exists() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "local npm path `{}` must contain package.json",
            source_path.display()
        )));
    }
    let package = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
    let name = install_name
        .map(str::to_owned)
        .or(package.name)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` package.json must declare name",
                source_path.display()
            ))
        })?;
    let version = package
        .version
        .filter(|version| !version.trim().is_empty())
        .unwrap_or_else(|| "0.0.0".to_owned());

    inputs.push(LocalSourceCompileInput {
        ecosystem: Ecosystem::Npm,
        source_path,
        name,
        version,
    });
    Ok(())
}

fn python_local_source_compile_inputs(
    local_paths: &[PathBuf],
) -> Result<Vec<LocalSourceCompileInput>> {
    let mut inputs = Vec::new();
    for path in local_paths {
        let source_path = fs::canonicalize(path).map_err(|error| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` could not be resolved: {error}",
                path.display()
            ))
        })?;
        if !source_path.is_dir() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` must be a directory",
                source_path.display()
            )));
        }
        let (name, version) = python_local_source_name_version(&source_path)?;
        inputs.push(LocalSourceCompileInput {
            ecosystem: Ecosystem::Pypi,
            source_path,
            name,
            version,
        });
    }
    Ok(inputs)
}

fn python_local_source_name_version(package_dir: &Path) -> Result<(String, String)> {
    if let Some((name, version)) = python_local_pyproject_name_version(package_dir)? {
        return Ok((name, version));
    }
    if let Some((name, version)) = python_local_setup_cfg_name_version(package_dir)? {
        return Ok((name, version));
    }
    if let Some((name, version)) = python_local_setup_py_name_version(package_dir)? {
        return Ok((name, version));
    }

    let name = package_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(normalize_pypi_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "local-source".to_owned());
    Ok((name, "0.0.0".to_owned()))
}

fn python_local_pyproject_name_version(package_dir: &Path) -> Result<Option<(String, String)>> {
    let pyproject = package_dir.join("pyproject.toml");
    if !pyproject.exists() {
        return Ok(None);
    }
    let pyproject = toml::from_str::<PyProjectToml>(&fs::read_to_string(pyproject)?)?;
    if let Some(project) = pyproject.project {
        if let Some(name) = project.name.filter(|name| !name.trim().is_empty()) {
            let version = project
                .version
                .filter(|version| !version.trim().is_empty())
                .unwrap_or_else(|| "0.0.0".to_owned());
            return Ok(Some((normalize_pypi_name(&name), version)));
        }
    }
    if let Some(poetry) = pyproject.tool.and_then(|tool| tool.poetry) {
        if let Some(name) = poetry.name.filter(|name| !name.trim().is_empty()) {
            let version = poetry
                .version
                .filter(|version| !version.trim().is_empty())
                .unwrap_or_else(|| "0.0.0".to_owned());
            return Ok(Some((normalize_pypi_name(&name), version)));
        }
    }
    Ok(None)
}

fn python_local_setup_cfg_name_version(package_dir: &Path) -> Result<Option<(String, String)>> {
    let setup_cfg = package_dir.join("setup.cfg");
    if !setup_cfg.exists() {
        return Ok(None);
    }
    let sections = parse_setup_cfg_sections(&fs::read_to_string(setup_cfg)?);
    let Some(metadata) = sections.get("metadata") else {
        return Ok(None);
    };
    let Some(name) = metadata
        .get("name")
        .and_then(|values| values.iter().find(|value| !value.trim().is_empty()))
    else {
        return Ok(None);
    };
    let version = metadata
        .get("version")
        .and_then(|values| values.iter().find(|value| !value.trim().is_empty()))
        .cloned()
        .unwrap_or_else(|| "0.0.0".to_owned());
    Ok(Some((normalize_pypi_name(name), version)))
}

fn python_local_setup_py_name_version(package_dir: &Path) -> Result<Option<(String, String)>> {
    let setup_py = package_dir.join("setup.py");
    if !setup_py.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(setup_py)?;
    let name = python_keyword_assignment_values(&content, "name")
        .into_iter()
        .flat_map(python_string_literals)
        .find(|value| !value.trim().is_empty());
    let Some(name) = name else {
        return Ok(None);
    };
    let version = python_keyword_assignment_values(&content, "version")
        .into_iter()
        .flat_map(python_string_literals)
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "0.0.0".to_owned());
    Ok(Some((normalize_pypi_name(&name), version)))
}

fn project_requested_specs(options: &mut LinkOptions, locked: bool) -> Result<Vec<PackageSpec>> {
    let manifest = read_manifest(options.project_dir.join(MANIFEST))?;
    apply_manifest_config(&manifest, options)?;
    let mut specs = Vec::new();
    for (key, requirement) in manifest.dependencies {
        specs.push(parse_manifest_dependency(&key, &requirement)?);
    }
    if options.include_optional_dependencies {
        for (key, requirement) in manifest.optional_dependencies {
            specs.push(parse_manifest_dependency(&key, &requirement)?);
        }
    }
    if options.include_peer_dependencies {
        for (key, requirement) in manifest.peer_dependencies {
            specs.push(parse_manifest_dependency(&key, &requirement)?);
        }
    }
    if options.include_dev_dependencies {
        for (key, requirement) in manifest.dev_dependencies {
            specs.push(parse_manifest_dependency(&key, &requirement)?);
        }
    }
    if options.discover_project_requirements {
        let discovered = discover_project_requirements_with_selection(
            &options.project_dir,
            &options.project_extras,
            DependencySelection::from_options(options),
        )?;
        apply_project_requirements_to_options(options, &mut specs, discovered);
    }
    if !options.npm_discovered_local_paths.is_empty() {
        specs.extend(resolve_npm_discovered_local_path_requirements(options)?);
    }
    if !options.npm_local_paths.is_empty() {
        specs.extend(resolve_npm_local_path_requirements(options)?);
    }

    if !options.requirement_files.is_empty() {
        let requirements = read_requirements_files(&options.requirement_files)?;
        apply_project_requirements_to_options(options, &mut specs, requirements);
    }
    if !options.constraint_files.is_empty() {
        let requirements = read_constraint_files(&options.constraint_files)?;
        apply_project_requirements_to_options(options, &mut specs, requirements);
    }

    if !options.python_local_requirements.is_empty() {
        let requirements = resolve_python_local_requirements(
            &options.python_local_requirements,
            options.pypi_include_dependencies,
        )?;
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

fn resolve_npm_local_path_requirements(options: &mut LinkOptions) -> Result<Vec<PackageSpec>> {
    let (specs, paths) = resolve_npm_local_path_requirements_inner(
        &options.npm_local_paths.clone(),
        DependencySelection {
            dev: false,
            optional: options.include_optional_dependencies,
            peer: options.include_peer_dependencies,
        },
        options,
    )?;
    options.npm_local_paths = paths;
    Ok(specs)
}

fn resolve_npm_discovered_local_path_requirements(
    options: &mut LinkOptions,
) -> Result<Vec<PackageSpec>> {
    let (specs, paths) = resolve_npm_local_path_requirements_inner(
        &options.npm_discovered_local_paths.clone(),
        DependencySelection {
            dev: false,
            optional: options.include_optional_dependencies,
            peer: options.include_peer_dependencies,
        },
        options,
    )?;
    options.npm_discovered_local_paths = paths;
    Ok(specs)
}

fn resolve_npm_local_path_requirements_inner(
    local_paths: &[PathBuf],
    selection: DependencySelection,
    options: &mut LinkOptions,
) -> Result<(Vec<PackageSpec>, Vec<PathBuf>)> {
    let mut specs = Vec::new();
    let mut queue = local_paths.to_vec();
    let mut seen = BTreeSet::new();
    let mut resolved_paths = Vec::new();

    while let Some(path) = queue.pop() {
        let path = fs::canonicalize(&path).map_err(|error| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "local npm path `{}` could not be resolved: {error}",
                path.display()
            ))
        })?;
        if !path.is_dir() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` must point to an existing directory",
                path.display()
            )));
        }
        if !seen.insert(path.clone()) {
            continue;
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
        collect_package_json_overrides(&package, &mut options.npm_overrides);
        specs.extend(package_json_dependency_specs(
            package.clone(),
            selection,
            &path,
        )?);
        let mut links = Vec::new();
        collect_npm_local_dependency_links(&package, selection, &path, &mut links)?;
        for link in links {
            queue.push(link.path);
        }
        resolved_paths.push(path);
    }

    Ok((specs, resolved_paths))
}

fn resolve_python_local_requirements(
    requirements: &[PythonLocalRequirement],
    include_dependencies: bool,
) -> Result<ProjectRequirements> {
    let mut resolved = ProjectRequirements::default();
    let mut queue = requirements.to_vec();
    let mut seen = BTreeSet::new();

    while let Some(requirement) = queue.pop() {
        let path = fs::canonicalize(&requirement.path).map_err(|error| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` could not be resolved: {error}",
                requirement.path.display()
            ))
        })?;
        if !path.is_dir() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` must be a directory",
                path.display()
            )));
        }
        let requirement = PythonLocalRequirement::new(path.clone(), requirement.extras);
        if !seen.insert(requirement.clone()) {
            continue;
        }

        if include_dependencies {
            let mut source_requirements =
                read_python_source_requirements(&path, &requirement.extras)?;
            queue.extend(source_requirements.python_local_requirements.clone());
            source_requirements.python_local_requirements.clear();
            extend_project_requirements(&mut resolved, source_requirements);
        }
        push_python_local_path(&mut resolved, path);
    }

    Ok(resolved)
}

fn parse_manifest_dependency(key: &str, requirement: &str) -> Result<PackageSpec> {
    if is_direct_dependency_requirement(requirement)
        || npm_github_dependency_parts(requirement)?.is_some()
    {
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

pub(crate) fn should_follow_locked_dependencies(
    package: &LockedPackage,
    options: &LinkOptions,
) -> bool {
    package.ecosystem != Ecosystem::Pypi || options.pypi_include_dependencies
}

pub(crate) fn find_locked_package_for_spec<'a>(
    lock: &'a OmcLock,
    spec: &PackageSpec,
    constraints: &BTreeMap<String, String>,
    npm_overrides: &BTreeMap<String, String>,
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
        .filter(|package| locked_package_version_matches(package, spec, constraints, npm_overrides))
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
    npm_overrides: &BTreeMap<String, String>,
) -> bool {
    match spec.ecosystem {
        Ecosystem::Npm => {
            let Ok((_, requirement)) = npm_registry_name_and_requirement(spec) else {
                return false;
            };
            effective_npm_requirement(spec, requirement.as_deref(), constraints, npm_overrides)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmWorkspacePackage {
    pub name: Option<String>,
    pub path: PathBuf,
}

pub fn read_npm_workspace_packages(
    project_dir: impl AsRef<Path>,
) -> Result<Vec<NpmWorkspacePackage>> {
    let project_dir = project_dir.as_ref();
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(Vec::new());
    }
    let root = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
    let Some(workspaces) = root.workspaces else {
        return Ok(Vec::new());
    };
    let mut packages = Vec::new();
    for package_json in workspace_package_json_paths(project_dir, &workspaces) {
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let path = package_json.parent().unwrap_or(project_dir).to_path_buf();
        packages.push(NpmWorkspacePackage {
            name: package.name,
            path,
        });
    }
    packages.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(packages)
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
    discover_project_requirements_with_selection(
        project_dir,
        project_extras,
        DependencySelection::with_dev(include_dev_dependencies),
    )
}

fn discover_project_requirements_with_selection(
    project_dir: impl AsRef<Path>,
    project_extras: &BTreeSet<String>,
    selection: DependencySelection,
) -> Result<ProjectRequirements> {
    let project_dir = project_dir.as_ref();
    let mut project = ProjectRequirements::default();

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        let requirements = read_package_json_requirements(&package_json, selection)?;
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
        let lock_requirements = read_pnpm_lock_requirements(&pnpm_lock, selection)?;
        extend_project_requirements(&mut project, lock_requirements);
    }

    let requirements_files = project_requirements_files(project_dir, selection.dev);
    if !requirements_files.is_empty() {
        let requirements = read_requirements_files(&requirements_files)?;
        extend_project_requirements(&mut project, requirements);
    }

    let pipfile_lock = project_dir.join("Pipfile.lock");
    if pipfile_lock.exists() {
        let requirements = read_pipfile_lock_requirements(&pipfile_lock, selection.dev)?;
        extend_project_requirements(&mut project, requirements);
    }

    let pipfile = project_dir.join("Pipfile");
    if pipfile.exists() && !pipfile_lock.exists() {
        let requirements = read_pipfile_requirements(&pipfile, selection.dev)?;
        extend_project_requirements(&mut project, requirements);
    }

    let uv_lock = project_dir.join("uv.lock");
    if uv_lock.exists() {
        let requirements = read_uv_lock_requirements(&uv_lock, selection.dev)?;
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
            read_pyproject_requirements(&pyproject_toml, project_extras, selection.dev)?;
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
            add_package_graph_inner(
                client,
                &dependency.spec,
                dependency.optional,
                options,
                seen,
                reports,
            )?;
        }
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
            guidance: Some(render_block_guidance(
                locked.ecosystem,
                &locked.name,
                &locked.version,
                &locked.verifier_findings,
            )),
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
    let mut lock = read_lockfile(&lockfile)?;
    ensure_lock_signing_key(&options.project_dir, &mut lock)?;
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

fn manifest_spec_for_locked_root(spec: &PackageSpec, locked: &LockedPackage) -> PackageSpec {
    if spec.direct_url.is_none() || spec.name == locked.name {
        return spec.clone();
    }
    let mut spec = spec.clone();
    spec.name = locked.name.clone();
    spec
}

fn options_with_manifest_policy(options: &LinkOptions) -> Result<LinkOptions> {
    let mut options = options.clone();
    let manifest = read_manifest(options.project_dir.join(MANIFEST))?;
    apply_manifest_config(&manifest, &mut options)?;
    Ok(options)
}

fn policy_from_link_options(options: &LinkOptions) -> Policy {
    default_public_capabilities()
        .into_iter()
        .chain(options.allowed_capabilities.iter().cloned())
        .fold(Policy::pure(), Policy::allow_capability)
}

fn default_public_capabilities() -> Vec<Capability> {
    DEFAULT_PUBLIC_ENV_READS
        .iter()
        .map(|name| Capability::EnvRead((*name).to_owned()))
        .collect()
}

/// Map a registry [`Ecosystem`] onto the policy DSL's own ecosystem enum.
fn policy_ecosystem(ecosystem: Ecosystem) -> omc_policy::Ecosystem {
    match ecosystem {
        Ecosystem::Npm => omc_policy::Ecosystem::Npm,
        Ecosystem::Pypi => omc_policy::Ecosystem::Pypi,
    }
}

/// Load and parse the optional `omc.policy` DSL file from a project directory.
///
/// Returns `Ok(None)` when the file is absent (full back-compat: behaviour is
/// exactly as before). A present-but-malformed file is a hard, clearly-reported
/// error — the policy layer is deny-by-default and never fails open.
pub fn load_policy_document(project_dir: &Path) -> Result<Option<omc_policy::PolicyDocument>> {
    let path = project_dir.join(POLICY_FILE);
    if !path.exists() {
        return Ok(None);
    }
    // batou:ignore file_read -- `omc.policy` is a fixed, project-local config
    // file name joined onto the operator-chosen project dir; reading it is the
    // explicit purpose, identical to how `read_manifest` loads `omc.toml`.
    let source = fs::read_to_string(&path)?;
    Ok(Some(omc_policy::parse(&source)?))
}

/// Merge the DSL-compiled per-package [`Policy`] into a base policy built from
/// the flat `omc.toml [policy]` / CLI grants.
///
/// The existing flat grants are treated as additional `default` grants (they
/// stay in `base`); the DSL `default` block plus every matching `package` block
/// are layered on top. Capabilities and flows are unioned (deduped); the
/// sensitive-read guard is lifted if either side lifted it.
fn merge_dsl_policy(base: Policy, dsl: &Policy) -> Policy {
    let mut merged = base;
    for capability in &dsl.allowed_capabilities {
        if !merged.allowed_capabilities.contains(capability) {
            merged = merged.allow_capability(capability.clone());
        }
    }
    for flow in &dsl.allowed_flows {
        if !merged.allowed_flows.contains(flow) {
            merged = merged.allow_flow_rule(flow.clone());
        }
    }
    if dsl.sensitive_reads_allowed() {
        merged = merged.allow_sensitive_reads();
    }
    merged
}

/// Build the effective verification [`Policy`] for one concrete package.
///
/// `base` is the policy assembled from the flat `omc.toml [policy]` / CLI grants
/// (the historical global allow-list). When an `omc.policy` DSL file is present,
/// the package's compiled per-package policy is layered on top so each
/// dependency is checked against ITS block, not just the one global list. When
/// no `omc.policy` exists, `base` is returned unchanged.
pub fn effective_package_policy(
    project_dir: &Path,
    base: Policy,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<Policy> {
    let eco = policy_ecosystem(ecosystem);
    let mut policy = base;
    // Project `omc.policy` (committable, project-scoped).
    if let Some(document) = load_policy_document(project_dir)? {
        policy = merge_dsl_policy(policy, &document.compile_for(eco, name, version));
    }
    // Global drop-in trust store `~/.omc/policy.d/*.omc.policy` (personal,
    // per-package, version-pinned). Each block only grants for its exact package,
    // so it composes as a baseline under every project without leaking to other
    // packages or transitive dependencies.
    for document in load_global_policy_documents()? {
        policy = merge_dsl_policy(policy, &document.compile_for(eco, name, version));
    }
    Ok(policy)
}

/// Load every drop-in per-package policy from the global trust directory
/// `$OMC_HOME/policy.d/` (default `~/.omc/policy.d/`). Each `*.omc.policy` /
/// `*.policy` file is parsed independently (a parse error in any file fails
/// closed); files are read in sorted order for determinism. Missing dir → empty.
fn load_global_policy_documents() -> Result<Vec<omc_policy::PolicyDocument>> {
    let Some(dir) = global_omc_home().map(|home| home.join("policy.d")) else {
        return Ok(Vec::new());
    };
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        let is_policy = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".omc.policy") || name.ends_with(".policy"));
        if path.is_file() && is_policy {
            paths.push(path);
        }
    }
    paths.sort();
    let mut documents = Vec::new();
    for path in paths {
        // batou:ignore file_read -- drop-in policy files in the operator's own
        // $OMC_HOME/policy.d trust dir; reading them is the explicit purpose.
        let source = fs::read_to_string(&path)?;
        documents.push(omc_policy::parse(&source)?);
    }
    Ok(documents)
}

/// Auto-accept a package's BENIGN runtime capabilities at the install gate.
///
/// Installing runs none of the package's source, so the capabilities a library
/// uses only when later called — network, DNS, env reads, file reads, the clock,
/// randomness — are not install-time risks. We grant them here so they don't
/// block the install (they remain recorded on the artifact as the runtime
/// profile). We deliberately do NOT grant: `ProcSpawn` (also represents npm
/// lifecycle scripts), `DynamicEval` (eval / unresolved obfuscation), or
/// `FsWrite` (persistence/backdoor) — those stay deny-by-default. Reads of
/// SENSITIVE files remain denied even though `FsRead("*")` is granted, because
/// the sensitive-read guard ignores wildcard grants. Data FLOWS are unaffected
/// (no flow is granted here), so a package that combines a secret read with a
/// sink still needs an explicit flow grant.
fn allow_benign_runtime_capabilities(policy: Policy) -> Policy {
    policy
        .allow_capability(Capability::EnvRead("*".to_owned()))
        .allow_capability(Capability::FsRead("*".to_owned()))
        .allow_capability(Capability::HttpHost("*".to_owned()))
        .allow_capability(Capability::DnsHost("*".to_owned()))
        .allow_capability(Capability::TimeNow)
        .allow_capability(Capability::RandomBytes)
}

/// Resolve the global OMC home directory: `$OMC_HOME` when set (it points at the
/// directory holding the global config — handy for tests/CI), otherwise
/// `$HOME/.omc` (or `%USERPROFILE%\.omc` on Windows).
pub(crate) fn global_omc_home() -> Option<PathBuf> {
    if let Some(dir) = env::var_os("OMC_HOME") {
        return Some(PathBuf::from(dir));
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".omc"))
}

/// The global `~/.omc/omc.toml` is a policy-only baseline: unlike a project
/// manifest it has no `[project]` (no name/version) and lists no dependencies —
/// it exists purely to set an org-wide `[policy]` floor. It therefore parses into
/// this lenient struct rather than the full [`OmcManifest`]. Unknown tables (e.g.
/// a `[project]` left over from copying a project file) are ignored.

/// Load the optional global user policy at `~/.omc/omc.toml`. Returns
/// `Ok(None)` when absent; a present-but-malformed file is a hard error.
fn load_global_manifest() -> Result<Option<GlobalConfig>> {
    let Some(path) = global_omc_home().map(|home| home.join("omc.toml")) else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(toml::from_str(&fs::read_to_string(path)?)?))
}

/// Parse a `min-release-age` duration string into seconds. A present-but-invalid
/// value fails closed (a typo never silently disables the freshness floor).
fn parse_min_release_age(value: Option<&str>) -> Result<Option<i64>> {
    match value {
        None => Ok(None),
        Some(raw) => omc_policy::parse_duration_secs(raw).map(Some).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "invalid min-release-age `{raw}`; use e.g. \"14d\", \"12h\", \"2w\", or \"7\" (days)"
            ))
        }),
    }
}

/// The effective minimum release age (seconds) for a package by name: the
/// `omc.policy` DSL's `min-age` for the package (most specific, and able to
/// relax to 0) when stated, otherwise the project/global `min-release-age`
/// floor. `None`/`Some(0)` means no age requirement.
fn effective_min_age_secs(options: &LinkOptions, ecosystem: Ecosystem, name: &str) -> Option<i64> {
    let dsl = options
        .policy_document
        .as_ref()
        .and_then(|doc| doc.min_age_for_name(policy_ecosystem(ecosystem), name));
    dsl.or(options.min_release_age_secs)
        .filter(|secs| *secs > 0)
}

/// The "published before" cutoff string to use when resolving an npm package:
/// the earlier (more restrictive) of any explicit `--before`/`npm_before` and
/// the `now - effective_min_age` freshness cutoff for this package.
fn effective_npm_before(options: &LinkOptions, name: &str) -> Result<Option<String>> {
    let explicit = options
        .npm_before
        .as_deref()
        .map(parse_npm_before)
        .transpose()?;
    let age_cutoff = effective_min_age_secs(options, Ecosystem::Npm, name)
        .map(|secs| Utc::now() - Duration::seconds(secs));
    let cutoff = match (explicit, age_cutoff) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    Ok(cutoff.map(|dt| dt.to_rfc3339()))
}

/// The "uploaded prior to" cutoff string for resolving a PyPI package: the
/// earlier of any explicit `--uploaded-prior-to` and the `now - min_age`
/// freshness cutoff for this package. RFC3339, re-parseable by
/// `parse_pypi_uploaded_prior_to`.
fn effective_pypi_uploaded_prior_to(options: &LinkOptions, name: &str) -> Result<Option<String>> {
    let explicit = options
        .pypi_uploaded_prior_to
        .as_deref()
        .map(parse_pypi_uploaded_prior_to)
        .transpose()?;
    let age_cutoff = effective_min_age_secs(options, Ecosystem::Pypi, name)
        .map(|secs| Utc::now() - Duration::seconds(secs));
    let cutoff = match (explicit, age_cutoff) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    Ok(cutoff.map(|dt| dt.to_rfc3339()))
}

fn apply_manifest_config(manifest: &OmcManifest, options: &mut LinkOptions) -> Result<()> {
    // Global user policy at `~/.omc/omc.toml` is a baseline applied to every
    // project: its grants are unioned UNDER the project's, and its
    // min-release-age is the fallback floor the project can override.
    let global = load_global_manifest()?;
    if let Some(global) = &global {
        for grant in &global.policy.allow {
            options
                .allowed_capabilities
                .push(parse_capability_grant(grant)?);
        }
        for flow in &global.policy.allow_flow {
            options.allowed_flows.push(parse_flow_rule(flow)?);
        }
    }

    for grant in &manifest.policy.allow {
        options
            .allowed_capabilities
            .push(parse_capability_grant(grant)?);
    }
    for flow in &manifest.policy.allow_flow {
        options.allowed_flows.push(parse_flow_rule(flow)?);
    }

    // Minimum release age: the project value overrides the global one
    // (most-specific wins). A present-but-malformed duration fails closed.
    let project_age = parse_min_release_age(manifest.policy.min_release_age.as_deref())?;
    let global_age = parse_min_release_age(
        global
            .as_ref()
            .and_then(|g| g.policy.min_release_age.as_deref()),
    )?;
    if let Some(secs) = project_age.or(global_age) {
        options.min_release_age_secs = Some(secs);
    }

    // The per-package `omc.policy` DSL (for per-package `min-age`, and the
    // per-package capability policy applied at verify time).
    if options.policy_document.is_none() {
        options.policy_document = load_policy_document(&options.project_dir)?;
    }

    let project_dir = options.project_dir.clone();
    for path in &manifest.npm_local_paths {
        options
            .npm_local_paths
            .push(resolve_manifest_path(&project_dir, path));
    }
    if options.include_optional_dependencies {
        for path in &manifest.npm_optional_local_paths {
            options
                .npm_local_paths
                .push(resolve_manifest_path(&project_dir, path));
        }
    }
    if options.include_peer_dependencies {
        for path in &manifest.npm_peer_local_paths {
            options
                .npm_local_paths
                .push(resolve_manifest_path(&project_dir, path));
        }
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
    let requirement_files = env::var("PIP_REQUIREMENT").ok();
    let constraint_files = env::var("PIP_CONSTRAINT").ok();
    let no_binary = env::var("PIP_NO_BINARY").ok();
    let only_binary = env::var("PIP_ONLY_BINARY").ok();
    let all_releases = env::var("PIP_ALL_RELEASES").ok();
    let only_final = env::var("PIP_ONLY_FINAL").ok();
    let uploaded_prior_to = env::var("PIP_UPLOADED_PRIOR_TO").ok();
    let no_index = env_truthy("PIP_NO_INDEX");
    let allow_prereleases = env_truthy("PIP_PRE");
    let base_dir = options
        .pypi_environment_base_dir
        .clone()
        .unwrap_or_else(|| options.project_dir.clone());
    apply_pypi_environment_values(
        options,
        &base_dir,
        PypiEnvironmentValues {
            index_url: index_url.as_deref(),
            extra_index_urls: extra_index_urls.as_deref(),
            find_links: find_links.as_deref(),
            requirement_files: requirement_files.as_deref(),
            constraint_files: constraint_files.as_deref(),
            no_binary: no_binary.as_deref(),
            only_binary: only_binary.as_deref(),
            all_releases: all_releases.as_deref(),
            only_final: only_final.as_deref(),
            uploaded_prior_to: uploaded_prior_to.as_deref(),
            no_index,
            allow_prereleases,
            override_index,
        },
    );
}

pub fn apply_pypi_environment_defaults(options: &mut LinkOptions, override_index: bool) {
    apply_pypi_environment_config(options, override_index);
}

#[derive(Debug, Clone, Copy, Default)]
struct PypiEnvironmentValues<'a> {
    index_url: Option<&'a str>,
    extra_index_urls: Option<&'a str>,
    find_links: Option<&'a str>,
    requirement_files: Option<&'a str>,
    constraint_files: Option<&'a str>,
    no_binary: Option<&'a str>,
    only_binary: Option<&'a str>,
    all_releases: Option<&'a str>,
    only_final: Option<&'a str>,
    uploaded_prior_to: Option<&'a str>,
    no_index: bool,
    allow_prereleases: bool,
    override_index: bool,
}

fn apply_pypi_environment_values(
    options: &mut LinkOptions,
    base_dir: &Path,
    values: PypiEnvironmentValues<'_>,
) {
    if values.override_index || options.pypi_index_url.is_none() {
        if let Some(index_url) = values.index_url.and_then(normalize_pypi_simple_index_url) {
            options.pypi_index_url = Some(index_url);
        }
    }
    if let Some(extra_index_urls) = values.extra_index_urls {
        options.pypi_extra_index_urls.extend(
            pypi_index_url_values(extra_index_urls)
                .into_iter()
                .filter_map(|index_url| normalize_pypi_simple_index_url(&index_url)),
        );
    }
    if let Some(find_links) = values.find_links {
        options.pypi_find_links.extend(
            pypi_index_url_values(find_links)
                .into_iter()
                .filter_map(|find_links| normalize_pypi_find_links_source(&find_links, base_dir)),
        );
    }
    if let Some(requirement_files) = values.requirement_files {
        options
            .requirement_files
            .extend(pypi_path_values(requirement_files, base_dir));
    }
    if let Some(constraint_files) = values.constraint_files {
        options
            .constraint_files
            .extend(pypi_path_values(constraint_files, base_dir));
    }
    if let Some(no_binary) = values.no_binary {
        apply_pypi_binary_option(
            &mut options.pypi_binary_all,
            &mut options.pypi_binary_packages,
            PypiBinaryMode::Source,
            no_binary,
        );
    }
    if let Some(only_binary) = values.only_binary {
        apply_pypi_binary_option(
            &mut options.pypi_binary_all,
            &mut options.pypi_binary_packages,
            PypiBinaryMode::Binary,
            only_binary,
        );
    }
    if let Some(all_releases) = values.all_releases {
        apply_pypi_release_control(
            &mut options.pypi_release_controls.all_releases,
            all_releases,
        );
    }
    if let Some(only_final) = values.only_final {
        apply_pypi_release_control(&mut options.pypi_release_controls.only_final, only_final);
    }
    if let Some(uploaded_prior_to) = values
        .uploaded_prior_to
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        options.pypi_uploaded_prior_to = Some(uploaded_prior_to.to_owned());
    }
    options.pypi_no_index |= values.no_index;
    options.pypi_allow_prereleases |= values.allow_prereleases;
    dedupe_pypi_find_links(options);
    dedupe_pypi_extra_index_urls(options);
    dedupe_paths(&mut options.requirement_files);
    dedupe_paths(&mut options.constraint_files);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PypiVersionListing {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PypiAvailableVersionsOptions {
    pub index_url: Option<String>,
    pub extra_index_urls: Vec<String>,
    pub find_links: Vec<String>,
    pub no_index: bool,
    pub allow_prereleases: bool,
    pub release_controls: PypiReleaseControls,
    pub uploaded_prior_to: Option<String>,
    pub target_python: Option<String>,
    pub target_implementation: Option<String>,
    pub target_platforms: Vec<String>,
    pub target_abis: Vec<String>,
}

pub fn read_pypi_available_versions(
    project_dir: &Path,
    package: &str,
    query: PypiAvailableVersionsOptions,
) -> Result<PypiVersionListing> {
    let mut options = LinkOptions::new(project_dir);
    options.pypi_index_url = query
        .index_url
        .and_then(|url| normalize_pypi_simple_index_url(&url));
    options.pypi_extra_index_urls = query
        .extra_index_urls
        .into_iter()
        .filter_map(|url| normalize_pypi_simple_index_url(&url))
        .collect();
    options.pypi_find_links = query
        .find_links
        .into_iter()
        .filter_map(|source| normalize_pypi_find_links_source(&source, project_dir))
        .collect();
    options.pypi_no_index = query.no_index;
    options.pypi_allow_prereleases = query.allow_prereleases;
    options.pypi_release_controls = query.release_controls;
    options.pypi_uploaded_prior_to = query.uploaded_prior_to;
    options.pypi_target_python = query.target_python;
    options.pypi_target_implementation = query.target_implementation;
    options.pypi_target_platforms = query.target_platforms;
    options.pypi_target_abis = query.target_abis;
    let options = options_with_manifest_policy(&options)?;
    let spec = PackageSpec::parse(&format!("pypi:{package}"))?;
    let client = Client::builder().user_agent("omc-prototype/0.1").build()?;
    let target_python = pypi_target_python(&options);
    let wheel_compatibility = pypi_wheel_compatibility(&options);
    let uploaded_prior_to = options
        .pypi_uploaded_prior_to
        .as_deref()
        .map(parse_pypi_uploaded_prior_to)
        .transpose()?;
    let mut versions = BTreeSet::new();

    insert_pypi_available_candidate_versions(
        &mut versions,
        pypi_find_link_candidates(
            &client,
            &spec,
            &options,
            target_python.as_deref(),
            wheel_compatibility.as_ref(),
        )?,
        uploaded_prior_to.as_ref(),
        &spec.name,
    )?;

    if !options.pypi_no_index {
        let simple_indexes = pypi_simple_index_urls(&options);
        let indexes = if simple_indexes.is_empty() {
            vec!["https://pypi.org/simple/".to_owned()]
        } else {
            simple_indexes
        };
        insert_pypi_available_candidate_versions(
            &mut versions,
            pypi_simple_index_candidates_from_indexes(
                &client,
                &spec,
                &indexes,
                target_python.as_deref(),
                wheel_compatibility.as_ref(),
                options.pypi_uploaded_prior_to.as_deref(),
            )?,
            uploaded_prior_to.as_ref(),
            &spec.name,
        )?;
    }

    if versions.is_empty() {
        return Err(OmcRegistryError::PackageNotFound(spec.requested()));
    }

    let mut versions = versions.into_iter().collect::<Vec<_>>();
    match pypi_prerelease_policy_for_name(&options, &spec.name) {
        PypiPrereleasePolicy::Allow => {}
        PypiPrereleasePolicy::OnlyFinal => {
            versions.retain(|version| !pypi_version_is_prerelease(version));
        }
        PypiPrereleasePolicy::Default => {
            if versions
                .iter()
                .any(|version| !pypi_version_is_prerelease(version))
            {
                versions.retain(|version| !pypi_version_is_prerelease(version));
            }
        }
    }
    versions.sort_by(|left, right| compare_pypi_versions(right, left));
    Ok(PypiVersionListing {
        name: spec.name,
        versions,
    })
}

fn insert_pypi_available_candidate_versions(
    versions: &mut BTreeSet<String>,
    candidates: Vec<PypiSimpleCandidate>,
    uploaded_prior_to: Option<&DateTime<Utc>>,
    package: &str,
) -> Result<()> {
    let candidates = if let Some(cutoff) = uploaded_prior_to {
        filter_pypi_candidates_uploaded_prior_to(candidates, cutoff.to_owned(), package)?
    } else {
        candidates
    };
    for candidate in candidates {
        versions.insert(candidate.version);
    }
    Ok(())
}


fn dedupe_pypi_find_links(options: &mut LinkOptions) {
    let mut seen = BTreeSet::new();
    options
        .pypi_find_links
        .retain(|find_links| seen.insert(find_links.clone()));
}

fn dedupe_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = BTreeSet::new();
    paths.retain(|path| seen.insert(path.clone()));
}

fn locked_package_name_key(package: &LockedPackage) -> (Ecosystem, String) {
    match package.ecosystem {
        Ecosystem::Npm => (package.ecosystem, package.name.clone()),
        Ecosystem::Pypi => (package.ecosystem, normalize_pypi_name(&package.name)),
    }
}

#[cfg(test)]
fn read_package_json_specs(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<Vec<PackageSpec>> {
    Ok(read_package_json_requirements(
        path,
        DependencySelection::with_dev(include_dev_dependencies),
    )?
    .specs)
}

fn read_package_json_requirements(
    path: &Path,
    selection: DependencySelection,
) -> Result<ProjectRequirements> {
    let package = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(path)?)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let workspaces = package.workspaces.clone();
    let mut requirements = ProjectRequirements::default();
    collect_package_json_overrides(&package, &mut requirements.npm_overrides);
    requirements.specs.extend(package_json_dependency_specs(
        package.clone(),
        selection,
        base_dir,
    )?);
    collect_package_json_local_dependency_paths(
        &package,
        selection,
        base_dir,
        &mut requirements.npm_local_paths,
    )?;

    if let Some(workspaces) = workspaces {
        for package_json in workspace_package_json_paths(base_dir, &workspaces) {
            let workspace_base_dir = package_json.parent().unwrap_or(base_dir);
            let package =
                serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
            collect_package_json_overrides(&package, &mut requirements.npm_overrides);
            requirements.specs.extend(package_json_dependency_specs(
                package.clone(),
                selection,
                workspace_base_dir,
            )?);
            collect_package_json_local_dependency_paths(
                &package,
                selection,
                workspace_base_dir,
                &mut requirements.npm_local_paths,
            )?;
        }
    }

    Ok(requirements)
}

fn collect_package_json_local_dependency_paths(
    package: &ProjectPackageJson,
    selection: DependencySelection,
    base_dir: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut links = Vec::new();
    collect_npm_local_dependency_links(package, selection, base_dir, &mut links)?;
    for link in links {
        if !paths.contains(&link.path) {
            paths.push(link.path);
        }
    }
    Ok(())
}

fn package_json_dependency_specs(
    package: ProjectPackageJson,
    selection: DependencySelection,
    base_dir: &Path,
) -> Result<Vec<PackageSpec>> {
    let mut specs = Vec::new();
    let dev_dependencies = if selection.dev {
        package.dev_dependencies
    } else {
        BTreeMap::new()
    };
    let optional_dependencies = if selection.optional {
        package.optional_dependencies
    } else {
        BTreeMap::new()
    };
    let peer_dependencies = if selection.peer {
        required_peer_dependencies(package.peer_dependencies, package.peer_dependencies_meta)
    } else {
        BTreeMap::new()
    };

    for dependencies in [
        package.dependencies,
        dev_dependencies,
        optional_dependencies,
        peer_dependencies,
    ] {
        for (name, requirement) in dependencies {
            if let Some(spec) = npm_package_json_dependency_spec(name, requirement, base_dir)? {
                specs.push(spec);
            }
        }
    }

    Ok(specs)
}

fn collect_package_json_overrides(
    package: &ProjectPackageJson,
    overrides: &mut BTreeMap<String, String>,
) {
    collect_npm_override_constraints(&package.overrides, overrides);
    collect_npm_resolution_constraints(&package.resolutions, overrides);
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
    let requirement = requirement.trim();
    if let Some(url) = npm_github_archive_url(requirement)? {
        return Ok(Some(url));
    }

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

fn npm_github_archive_url(requirement: &str) -> Result<Option<String>> {
    let Some((owner, repo, reference)) = npm_github_dependency_parts(requirement)? else {
        return Ok(None);
    };
    if reference
        .as_deref()
        .is_some_and(|reference| reference.starts_with("semver:"))
    {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm GitHub dependency `{requirement}` uses semver refs, which OMC does not resolve yet"
        )));
    }
    let reference = reference.as_deref().unwrap_or("HEAD");
    let owner = npm_github_path_segment(owner);
    let repo = npm_github_path_segment(repo);
    let reference = npm_github_ref_path(reference);
    Ok(Some(format!(
        "https://github.com/{owner}/{repo}/archive/{reference}.tar.gz"
    )))
}

fn npm_github_dependency_parts(
    requirement: &str,
) -> Result<Option<(String, String, Option<String>)>> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return Ok(None);
    }

    if let Some(rest) = requirement.strip_prefix("github:") {
        return npm_github_shorthand_parts(rest, requirement);
    }
    if let Some(rest) = requirement.strip_prefix("git@github.com:") {
        return npm_github_shorthand_parts(rest, requirement);
    }

    let (source, reference) = split_npm_git_reference(requirement);
    let source = source.strip_prefix("git+").unwrap_or(source);
    if source.starts_with("git@github.com:") {
        return npm_github_shorthand_parts(&source["git@github.com:".len()..], requirement);
    }
    if let Ok(url) = reqwest::Url::parse(source) {
        let Some(host) = url.host_str() else {
            return Ok(None);
        };
        if !host.eq_ignore_ascii_case("github.com") {
            return Ok(None);
        }
        if !matches!(url.scheme(), "https" | "ssh") {
            return Ok(None);
        }
        let segments = url
            .path_segments()
            .map(|segments| {
                segments
                    .filter(|segment| !segment.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if segments.len() != 2 {
            return Ok(None);
        }
        let Some(owner) = segments.first() else {
            return Ok(None);
        };
        let Some(repo) = segments.get(1) else {
            return Ok(None);
        };
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        return Ok(Some(npm_valid_github_parts(
            owner,
            repo,
            reference.map(str::to_owned),
            requirement,
        )?));
    }

    if npm_bare_github_shorthand(requirement) {
        return npm_github_shorthand_parts(requirement, requirement);
    }

    Ok(None)
}

fn split_npm_git_reference(value: &str) -> (&str, Option<&str>) {
    value
        .split_once('#')
        .map(|(source, reference)| {
            (
                source,
                (!reference.trim().is_empty()).then_some(reference.trim()),
            )
        })
        .unwrap_or((value, None))
}

fn npm_github_shorthand_parts(
    value: &str,
    original: &str,
) -> Result<Option<(String, String, Option<String>)>> {
    let (path, reference) = split_npm_git_reference(value.trim());
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    let Some(owner) = segments.next() else {
        return Ok(None);
    };
    let Some(repo) = segments.next() else {
        return Ok(None);
    };
    if segments.next().is_some() {
        return Ok(None);
    }
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    Ok(Some(npm_valid_github_parts(
        owner,
        repo,
        reference.map(str::to_owned),
        original,
    )?))
}

fn npm_valid_github_parts(
    owner: &str,
    repo: &str,
    reference: Option<String>,
    original: &str,
) -> Result<(String, String, Option<String>)> {
    if owner.is_empty() || repo.is_empty() || owner.starts_with('.') || repo.starts_with('.') {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm GitHub dependency `{original}`"
        )));
    }
    Ok((owner.to_owned(), repo.to_owned(), reference))
}

fn npm_bare_github_shorthand(requirement: &str) -> bool {
    if requirement.starts_with('@')
        || requirement.starts_with('.')
        || requirement.starts_with('/')
        || requirement.starts_with("~/")
        || requirement.contains("://")
        || requirement.starts_with("git+")
        || requirement.starts_with("file:")
        || requirement.starts_with("link:")
    {
        return false;
    }
    let (path, _) = split_npm_git_reference(requirement);
    let segments = path.split('/').collect::<Vec<_>>();
    segments.len() == 2
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && !segment.starts_with('.'))
}

fn npm_github_path_segment(value: String) -> String {
    urlencoding::encode(&value).into_owned()
}

fn npm_github_ref_path(value: &str) -> String {
    value
        .split('/')
        .map(|segment| urlencoding::encode(segment).into_owned())
        .collect::<Vec<_>>()
        .join("/")
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
    selection: DependencySelection,
) -> Result<ProjectRequirements> {
    let lock = serde_yaml::from_str::<PnpmLock>(&fs::read_to_string(path)?)
        .map_err(|error| OmcRegistryError::UnsupportedRequirement(error.to_string()))?;
    let mut requirements = ProjectRequirements::default();
    let mut versions = BTreeMap::<String, BTreeSet<String>>::new();
    let mut integrities = BTreeMap::<String, BTreeSet<String>>::new();
    let mut resolved = BTreeMap::<String, BTreeSet<String>>::new();

    for importer in lock.importers.into_values() {
        collect_pnpm_importer_dependencies(importer.dependencies, &mut requirements, &mut versions);
        if selection.optional {
            collect_pnpm_importer_dependencies(
                importer.optional_dependencies,
                &mut requirements,
                &mut versions,
            );
        }
        if selection.dev {
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
        npm_overrides: BTreeMap::new(),
        hashes: BTreeMap::new(),
        npm_integrities,
        npm_resolved,
        npm_local_paths: Vec::new(),
        pypi_binary_all: None,
        pypi_binary_packages: BTreeMap::new(),
        pypi_index_url: None,
        pypi_extra_index_urls: Vec::new(),
        pypi_find_links: Vec::new(),
        pypi_no_index: false,
        pypi_require_hashes: false,
        pypi_no_deps: false,
        pypi_allow_prereleases: false,
        pypi_release_controls: PypiReleaseControls::default(),
        pypi_uploaded_prior_to: None,
        python_local_paths: Vec::new(),
        python_local_requirements: Vec::new(),
        python_local_directory_requirements: Vec::new(),
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

pub fn read_requirements_files(paths: &[PathBuf]) -> Result<ProjectRequirements> {
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

pub fn read_constraint_files(paths: &[PathBuf]) -> Result<ProjectRequirements> {
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

pub fn read_script_requirement_files(paths: &[PathBuf]) -> Result<ProjectRequirements> {
    let mut discovered = ProjectRequirements::default();
    for path in paths {
        extend_project_requirements(&mut discovered, read_script_requirements(path)?);
    }
    Ok(discovered)
}

fn read_script_requirements(path: &Path) -> Result<ProjectRequirements> {
    let content = fs::read_to_string(path)?;
    let Some(metadata) = inline_script_metadata(&content)? else {
        return Ok(ProjectRequirements::default());
    };
    let metadata = toml::from_str::<InlineScriptMetadata>(&metadata)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut requirements = ProjectRequirements::default();
    let local_sources = BTreeMap::new();
    for dependency in metadata.dependencies {
        collect_pypi_project_requirement(
            &mut requirements,
            &dependency,
            &BTreeSet::new(),
            base_dir,
            &local_sources,
        )?;
    }
    Ok(requirements)
}

fn inline_script_metadata(content: &str) -> Result<Option<String>> {
    let mut script_metadata = None;
    let mut lines = content.lines();

    while let Some(line) = lines.next() {
        if line != "# /// script" {
            continue;
        }
        let mut block = String::new();
        let mut closed = false;
        for line in lines.by_ref() {
            if line == "# ///" {
                closed = true;
                break;
            }
            if let Some(content) = line.strip_prefix("# ") {
                block.push_str(content);
                block.push('\n');
            } else if line == "#" {
                block.push('\n');
            } else {
                break;
            }
        }
        if !closed {
            continue;
        }
        if script_metadata.replace(block).is_some() {
            return Err(OmcRegistryError::UnsupportedRequirement(
                "multiple inline script metadata blocks found".to_owned(),
            ));
        }
    }

    Ok(script_metadata)
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
                PypiProjectRequirement::LocalPath(requirement) => {
                    push_python_local_requirement(requirements, requirement);
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
            return Ok(Some(PypiProjectRequirement::LocalPath(
                PythonLocalRequirement::new(path, normalized_pypi_extras(table.extras)),
            )));
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

fn push_python_local_requirement(
    requirements: &mut ProjectRequirements,
    requirement: PythonLocalRequirement,
) {
    push_python_local_path(requirements, requirement.path.clone());
    if !requirements
        .python_local_requirements
        .contains(&requirement)
    {
        requirements.python_local_requirements.push(requirement);
    }
}

fn push_python_local_directory_requirement(
    requirements: &mut ProjectRequirements,
    requirement: PythonLocalRequirement,
) {
    if !requirements
        .python_local_directory_requirements
        .contains(&requirement)
    {
        requirements
            .python_local_directory_requirements
            .push(requirement);
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
        let spec = pylock_package_spec(&package, &name);
        requirements.specs.push(spec);
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

fn pylock_package_spec(package: &PylockPackage, name: &str) -> PackageSpec {
    let direct_url = package
        .wheels
        .first()
        .and_then(|dist| dist.url.clone())
        .or_else(|| package.sdist.as_ref().and_then(|dist| dist.url.clone()))
        .or_else(|| package.archive.as_ref().and_then(|dist| dist.url.clone()));
    if let Some(url) = direct_url {
        PackageSpec::with_direct_url(Ecosystem::Pypi, name.to_owned(), url, BTreeSet::new())
    } else {
        PackageSpec::new(
            Ecosystem::Pypi,
            name.to_owned(),
            Some(package.version.clone()),
        )
    }
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

pub(crate) fn setup_cfg_key_value(trimmed: &str) -> Option<(String, &str)> {
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

pub(crate) fn python_keyword_assignment_values<'a>(content: &'a str, keyword: &str) -> Vec<&'a str> {
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

pub(crate) fn python_string_literals(content: &str) -> Vec<String> {
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

pub(crate) fn python_string_dict_values(content: &str, selected_keys: &BTreeSet<String>) -> Vec<String> {
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

fn strip_relative_local_path_scheme(path: &str) -> &str {
    if path.contains("://") {
        return path;
    }
    path.strip_prefix("file:")
        .or_else(|| path.strip_prefix("link:"))
        .unwrap_or(path)
}

fn local_file_url_path(value: &str) -> Result<Option<PathBuf>> {
    if !value.contains("://") {
        return Ok(None);
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return Ok(None);
    };
    if url.scheme() != "file" {
        return Ok(None);
    }
    url.to_file_path()
        .map(Some)
        .map_err(|_| OmcRegistryError::UnsupportedRequirement(value.to_owned()))
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

    if is_pylock_requirements_file(path) {
        if mode == RequirementsMode::Constraint {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "pylock requirements file `{}` cannot be used as a constraint file",
                path.display()
            )));
        }
        extend_project_requirements(discovered, read_pylock_requirements(path)?);
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

        if parse_requirements_no_deps(line) {
            if mode == RequirementsMode::Install {
                discovered.pypi_no_deps = true;
            }
            continue;
        }

        if parse_requirements_allow_prereleases(line) {
            if mode == RequirementsMode::Install {
                discovered.pypi_allow_prereleases = true;
            }
            continue;
        }

        if let Some(all_releases) = parse_requirements_all_releases(line) {
            if mode == RequirementsMode::Install {
                apply_pypi_release_control(
                    &mut discovered.pypi_release_controls.all_releases,
                    &all_releases,
                );
            }
            continue;
        }

        if let Some(only_final) = parse_requirements_only_final(line) {
            if mode == RequirementsMode::Install {
                apply_pypi_release_control(
                    &mut discovered.pypi_release_controls.only_final,
                    &only_final,
                );
            }
            continue;
        }

        if let Some(uploaded_prior_to) = parse_requirements_uploaded_prior_to(line) {
            if mode == RequirementsMode::Install {
                discovered.pypi_uploaded_prior_to = Some(uploaded_prior_to);
            }
            continue;
        }

        if let Some(value) = parse_requirements_binary_option(line, PypiBinaryMode::Binary) {
            if mode == RequirementsMode::Install {
                apply_pypi_binary_option(
                    &mut discovered.pypi_binary_all,
                    &mut discovered.pypi_binary_packages,
                    PypiBinaryMode::Binary,
                    &value,
                );
            }
            continue;
        }

        if let Some(value) = parse_requirements_binary_option(line, PypiBinaryMode::Source) {
            if mode == RequirementsMode::Install {
                apply_pypi_binary_option(
                    &mut discovered.pypi_binary_all,
                    &mut discovered.pypi_binary_packages,
                    PypiBinaryMode::Source,
                    &value,
                );
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
                .python_local_requirements
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
                push_python_local_directory_requirement(
                    discovered,
                    PythonLocalRequirement::new(path, spec.extras),
                );
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

        if let Some(requirement) = parse_pypi_local_direct_path_requirement(
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
            push_python_local_directory_requirement(discovered, requirement);
            continue;
        }

        if let Some(requirement) =
            parse_pypi_local_path_requirement(&parsed.requirement, &BTreeSet::new(), base_dir)?
        {
            if mode == RequirementsMode::Constraint {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            if !parsed.hashes.is_empty() {
                return Err(OmcRegistryError::UnsupportedRequirement(line.to_owned()));
            }
            push_python_local_directory_requirement(discovered, requirement);
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

        if let Some((spec, hashes)) = parse_pypi_direct_archive_url_reference(&parsed.requirement)?
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

fn is_pylock_requirements_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "pylock.toml" || (name.starts_with("pylock.") && name.ends_with(".toml"))
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
            lines.push(expand_requirement_env_variables(&std::mem::take(
                &mut current,
            )));
        }
    }

    if !current.trim().is_empty() {
        lines.push(expand_requirement_env_variables(&current));
    }

    lines
}

fn expand_requirement_env_variables(line: &str) -> String {
    let mut expanded = String::new();
    let mut rest = line;

    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            expanded.push_str(&rest[start..]);
            return expanded;
        };
        let name = &after_start[..end];
        let token = &rest[start..start + 3 + name.len()];
        if requirement_env_var_name_is_valid(name) {
            if let Ok(value) = env::var(name) {
                if !value.is_empty() {
                    expanded.push_str(&value);
                } else {
                    expanded.push_str(token);
                }
            } else {
                expanded.push_str(token);
            }
        } else {
            expanded.push_str(token);
        }
        rest = &after_start[end + 1..];
    }

    expanded.push_str(rest);
    expanded
}

fn requirement_env_var_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
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
    report.npm_bins += install_npm_project_links(
        project_dir,
        &report.node_modules,
        &report.npm_bin_dir,
        DependencySelection::with_dev(true),
    )?;
    report.python_scripts += install_python_local_paths(
        &project.python_local_paths,
        &report.python_site_packages,
        &report.python_bin_dir,
    )?;
    Ok(report)
}

pub fn install_locked_packages_with_python_target(
    project_dir: impl AsRef<Path>,
    python_target_dir: impl AsRef<Path>,
) -> Result<InstallReport> {
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
    let mut report = install_lock_with_python_target(
        project_dir,
        &lock,
        Some(python_target_dir.as_ref()),
        None,
        true,
    )?;
    report.npm_bins += install_npm_project_links(
        project_dir,
        &report.node_modules,
        &report.npm_bin_dir,
        DependencySelection::with_dev(true),
    )?;
    report.python_scripts += install_python_local_paths(
        &project.python_local_paths,
        &report.python_site_packages,
        &report.python_bin_dir,
    )?;
    Ok(report)
}

fn install_lock(project_dir: &Path, lock: &OmcLock) -> Result<InstallReport> {
    install_lock_with_python_target(project_dir, lock, None, None, true)
}

fn install_lock_with_python_target(
    project_dir: &Path,
    lock: &OmcLock,
    python_target_dir: Option<&Path>,
    python_bin_dir: Option<&Path>,
    overwrite_existing: bool,
) -> Result<InstallReport> {
    let node_modules = project_dir.join("node_modules");
    let npm_bin_dir = node_modules.join(".bin");
    let default_python_site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let python_site_packages = match python_target_dir {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => project_dir.join(path),
        None => default_python_site_packages,
    };
    let python_bin_dir = match python_bin_dir {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => project_dir.join(path),
        None => match python_target_dir {
            Some(_) => python_site_packages.join("bin"),
            None => project_dir.join(".omc").join("python").join("bin"),
        },
    };
    let python_sdists_dir = project_dir.join(".omc").join("python").join("sdists");
    let python_local_paths = python_local_paths_file_for_site_packages(&python_site_packages)?;

    remove_path_if_exists(&node_modules)?;
    if python_target_dir.is_none() {
        remove_path_if_exists(&python_site_packages)?;
        remove_path_if_exists(&python_bin_dir)?;
    }
    remove_path_if_exists(&python_sdists_dir)?;
    remove_path_if_exists(&python_local_paths)?;
    let python_bin_dir_existed = python_bin_dir.exists();

    fs::create_dir_all(&node_modules)?;
    fs::create_dir_all(&npm_bin_dir)?;
    fs::create_dir_all(&python_site_packages)?;
    fs::create_dir_all(&python_bin_dir)?;
    fs::create_dir_all(&python_sdists_dir)?;

    let mut report = InstallReport {
        npm_packages: 0,
        pypi_packages: 0,
        local_source_artifacts: 0,
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
        verify_locked_artifact(project_dir, package, lock.signing_key.as_deref())?;

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
                    overwrite_existing,
                    python_bin_dir_existed,
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

    let local_paths_file = python_local_paths_file_for_site_packages(site_packages)?;
    fs::write(
        local_paths_file,
        format!("{}\n", lines.into_iter().collect::<Vec<_>>().join("\n")),
    )?;
    install_python_entry_point_scripts(&entry_points, bin_dir, true, false)
}

pub fn install_python_project_local_import_paths(
    project_dir: impl AsRef<Path>,
    import_paths: &[PathBuf],
) -> Result<usize> {
    if import_paths.is_empty() {
        return Ok(0);
    }

    let python_dir = project_dir.as_ref().join(".omc").join("python");
    let site_packages = python_dir.join("site-packages");
    let bin_dir = python_dir.join("bin");
    fs::create_dir_all(&site_packages)?;
    fs::create_dir_all(&bin_dir)?;
    let project_roots = import_paths
        .iter()
        .map(|path| python_local_import_project_root(path))
        .collect::<Vec<_>>();
    install_python_local_paths(&project_roots, &site_packages, &bin_dir)
}

fn python_local_import_project_root(import_path: &Path) -> PathBuf {
    if import_path.file_name().and_then(|name| name.to_str()) == Some("src") {
        if let Some(parent) = import_path.parent() {
            if parent.join("pyproject.toml").exists()
                || parent.join("setup.cfg").exists()
                || parent.join("setup.py").exists()
            {
                return parent.to_path_buf();
            }
        }
    }
    import_path.to_path_buf()
}

fn python_local_paths_file_for_site_packages(site_packages: &Path) -> Result<PathBuf> {
    let parent = site_packages.parent().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("missing python install directory".to_owned())
    })?;
    if site_packages.file_name().and_then(|name| name.to_str()) == Some("site-packages") {
        Ok(parent.join("local-paths"))
    } else {
        Ok(site_packages.join(".omc-local-paths"))
    }
}

pub(crate) fn read_locked_archive(project_dir: &Path, package: &LockedPackage) -> Result<Vec<u8>> {
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

/// The entry source of a locked package, extracted from its cached archive.
///
/// `module_id` is the canonical `eco:name@version` id (matching `Module.id`),
/// and `source` is the UTF-8 text of the package's entry source file. This is
/// the REAL package source — it is handed to a language front end for in-cell
/// lowering, never executed on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedEntrySource {
    pub module_id: String,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub source: String,
}

/// Minimal view of a package.json used only to locate the npm entry file.
#[derive(Debug, Default, Deserialize)]
struct NpmEntryManifest {
    #[serde(default)]
    main: Option<String>,
}

/// Read the entry source file for a locked package out of its cached archive.
///
/// The archive is verified against the lock's sha256 (via [`read_locked_archive`])
/// before any bytes are interpreted. For npm the entry file is the `main` field
/// of package.json (defaulting to `index.js`); for PyPI it is the package's
/// top-level module — `{name}/__init__.py` or `{name}.py` (dashes normalized to
/// underscores). Deny-by-default: if no entry source can be located, this fails
/// with [`OmcRegistryError::MissingEntrySource`] rather than guessing.
pub fn read_locked_package_entry_source(
    project_dir: impl AsRef<Path>,
    package: &LockedPackage,
) -> Result<LockedEntrySource> {
    let project_dir = project_dir.as_ref();
    let bytes = read_locked_archive(project_dir, package)?;
    let files = read_archive_text_files(&bytes)?;

    let source = match package.ecosystem {
        Ecosystem::Npm => locate_npm_entry_source(&files),
        Ecosystem::Pypi => locate_pypi_entry_source(&package.name, &files),
    }
    .ok_or_else(|| OmcRegistryError::MissingEntrySource(locked_package_key(package)))?;

    Ok(LockedEntrySource {
        module_id: locked_package_key(package),
        ecosystem: package.ecosystem,
        name: package.name.clone(),
        version: package.version.clone(),
        source,
    })
}

/// Decode a gzip tarball into a map of archive-relative path -> UTF-8 contents.
/// The leading distribution directory (`package/`, `name-version/`) is stripped
/// so callers index by the in-package path (e.g. `package.json`, `index.js`).
/// Binary (non-UTF-8) entries are skipped — only text sources are surfaced.
fn read_archive_text_files(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut files = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let raw_path = entry.path()?.to_string_lossy().into_owned();
        if is_ignorable_archive_metadata_path(&raw_path) {
            continue;
        }
        let Some(stripped) = strip_first_path_component(Path::new(&raw_path)) else {
            continue;
        };
        let mut contents = String::new();
        if entry.read_to_string(&mut contents).is_err() {
            // Non-UTF-8 (binary) entry; not a lowerable text source.
            continue;
        }
        files.insert(stripped.to_string_lossy().replace('\\', "/"), contents);
    }
    Ok(files)
}

/// Pick the npm entry source: package.json `main` (defaulting to `index.js`).
fn locate_npm_entry_source(files: &BTreeMap<String, String>) -> Option<String> {
    let main = files
        .get("package.json")
        .and_then(|raw| serde_json::from_str::<NpmEntryManifest>(raw).ok())
        .and_then(|manifest| manifest.main)
        .filter(|main| !main.trim().is_empty())
        .unwrap_or_else(|| "index.js".to_owned());

    let candidates = [
        normalize_archive_rel_path(&main),
        format!(
            "{}.js",
            normalize_archive_rel_path(&main).trim_end_matches('/')
        ),
        format!(
            "{}/index.js",
            normalize_archive_rel_path(&main).trim_end_matches('/')
        ),
        "index.js".to_owned(),
    ];
    for candidate in candidates {
        if let Some(source) = files.get(&candidate) {
            return Some(source.clone());
        }
    }
    None
}

/// Pick the PyPI entry source: the package's top-level module. Tries
/// `{name}/__init__.py` (package layout) then `{name}.py` (single-module), with
/// dashes normalized to underscores per the import-name convention.
fn locate_pypi_entry_source(name: &str, files: &BTreeMap<String, String>) -> Option<String> {
    let module = name.replace('-', "_");
    let candidates = [
        format!("{module}/__init__.py"),
        format!("{module}.py"),
        format!("src/{module}/__init__.py"),
        format!("src/{module}.py"),
    ];
    for candidate in candidates {
        if let Some(source) = files.get(&candidate) {
            return Some(source.clone());
        }
    }
    None
}

/// Normalize an archive-relative path: strip a leading `./`, collapse backslashes.
fn normalize_archive_rel_path(path: &str) -> String {
    path.trim_start_matches("./").replace('\\', "/")
}

fn verify_locked_artifact(
    project_dir: &Path,
    package: &LockedPackage,
    pinned_key: Option<&str>,
) -> Result<()> {
    let artifact_path = checked_join(project_dir, Path::new(&package.artifact))?;
    let artifact = serde_json::from_str::<OmcArtifact>(&fs::read_to_string(&artifact_path)?)?;
    verify_artifact_signature(&artifact)?;

    // F3 trust anchor: the artifact must be signed by the PROJECT's pinned key
    // (not just self-consistently signed by some key) AND its payload hash must
    // match the value pinned in the lock. This defeats an attacker who tampers a
    // cached artifact (e.g. Blocked -> Accepted) and re-signs it with their own
    // key, since both the embedded public key and the payload hash will differ.
    enforce_artifact_trust_anchor(&artifact, package, pinned_key)?;

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

/// F3 — bind a locked artifact to the project's trust anchor: its embedded
/// signing public key must equal the lock's pinned `signing-key`, and its
/// payload sha256 must equal the lock entry's `artifact-sha256`. Both anchors
/// are required; a missing pin (pre-F3 lockfile) is rejected so an untrusted
/// lock cannot silently bypass the check by simply omitting the fields.
fn enforce_artifact_trust_anchor(
    artifact: &OmcArtifact,
    package: &LockedPackage,
    pinned_key: Option<&str>,
) -> Result<()> {
    let Some(pinned_key) = pinned_key.filter(|key| !key.is_empty()) else {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
            "lockfile has no pinned artifact signing key (`signing-key`); \
             re-run `omc install` to re-lock and pin the trust anchor before \
             `--locked`/`ci` for {}:{}@{}",
            package.ecosystem, package.name, package.version
        )));
    };

    let signature = artifact.signature.as_ref().ok_or_else(|| {
        OmcRegistryError::UnsupportedInstallArtifact("artifact is unsigned".to_owned())
    })?;
    if signature.public_key != pinned_key {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
            "artifact `{}` for {}:{}@{} is signed by an unpinned key `{}` (expected the \
             project key pinned in omc.lock) — refusing to trust a re-signed artifact",
            package.artifact, package.ecosystem, package.name, package.version, signature.key_id
        )));
    }

    if package.artifact_sha256.is_empty() {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
            "lock entry for {}:{}@{} has no pinned `artifact-sha256`; re-lock to pin it",
            package.ecosystem, package.name, package.version
        )));
    }
    let actual = artifact_payload_sha256(artifact)?;
    if !actual.eq_ignore_ascii_case(&package.artifact_sha256) {
        return Err(OmcRegistryError::DigestMismatch {
            name: format!(
                "{}:{}@{} artifact",
                package.ecosystem, package.name, package.version
            ),
            expected: format!("sha256:{}", package.artifact_sha256),
            actual: format!("sha256:{actual}"),
        });
    }
    Ok(())
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

fn npm_manifest_engine_compatible(manifest: &NpmPackageManifest, options: &LinkOptions) -> bool {
    npm_engine_compatible(manifest.engines.as_ref(), options.npm_engine_strict)
}


pub(crate) fn is_safe_script_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains(std::path::MAIN_SEPARATOR)
        && name != "."
        && name != ".."
}

pub(crate) fn remove_path_if_exists(path: &Path) -> Result<()> {
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
    fs::write(
        target,
        // batou:ignore BATOU-RUST-AST-002 -- not SQL: format! builds a POSIX shell bin-shim; the interpolated path is shell-quoted via shell_single_quote
        format!(
            "#!/bin/sh\n# OMC npm bin shim\nNODE_OPTIONS='--preserve-symlinks --preserve-symlinks-main'\nexport NODE_OPTIONS\nexec {} \"$@\"\n",
            shell_single_quote(&source.to_string_lossy())
        ),
    )?;
    make_executable(target)?;
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

#[cfg(unix)]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
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
pub(crate) fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn strip_first_path_component(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    components.next()?;
    let stripped = components.as_path();
    (!stripped.as_os_str().is_empty()).then(|| stripped.to_path_buf())
}

pub(crate) fn checked_join(base: &Path, relative: &Path) -> Result<PathBuf> {
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

pub fn parse_flow_rule(value: &str) -> Result<FlowRule> {
    let (from, to) = value
        .split_once("->")
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    Ok(FlowRule::new(
        parse_flow_label_matcher(from.trim())?,
        parse_flow_sink(to.trim())?,
    ))
}

fn parse_flow_label_matcher(value: &str) -> Result<LabelMatcher> {
    if matches!(value, "*" | "any") {
        return Ok(LabelMatcher::Any);
    }
    let (kind, target) = value
        .split_once(':')
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    let target = target.to_owned();
    match kind {
        "env" | "env.read" | "env-read" => Ok(LabelMatcher::Env(target)),
        "file" | "fs.read" | "fs-read" => Ok(LabelMatcher::File(target)),
        "secret" => Ok(LabelMatcher::Secret(target)),
        _ => Err(OmcRegistryError::UnsupportedSpec(value.to_owned())),
    }
}

fn parse_flow_sink(value: &str) -> Result<Sink> {
    if matches!(value, "eval" | "dynamic_eval" | "dynamic.eval") {
        return Ok(Sink::Eval);
    }
    let (kind, target) = value
        .split_once(':')
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    let target = target.to_owned();
    match kind {
        "network" | "http" => Ok(Sink::Network(target)),
        "file" | "fs.write" | "fs-write" => Ok(Sink::File(target)),
        "process" | "proc" | "proc.spawn" | "proc-spawn" => Ok(Sink::Process(target)),
        _ => Err(OmcRegistryError::UnsupportedSpec(value.to_owned())),
    }
}

/// One blocked verifier finding, reduced to everything the CLI needs to explain
/// it and offer an EXACT, minimal grant. The raw machine token is always carried
/// verbatim (`raw`) so the audit trail is never replaced, only annotated.
#[derive(Debug, Clone)]
pub struct GrantNeed {
    /// The raw machine token, e.g. `env:NPM_TOKEN may not flow to network:evil.com`.
    pub raw: String,
    /// Consequence-first plain English describing what granting this permits.
    pub human: String,
    /// An exfiltration/backdoor warning for dangerous shapes (secret->sink,
    /// proc-spawn, eval, fs-write, sensitive read); `None` for benign reads.
    pub risk: Option<String>,
    /// The exact one-run CLI flag, e.g. `--allow-flow env:NPM_TOKEN->network:evil.com`.
    pub cli_flag: String,
    /// The equivalent `omc.policy` statement, e.g. `flow env "NPM_TOKEN" -> net "evil.com"`.
    pub policy_stmt: String,
    /// True for the deny-by-default classes that must never be one-keystroke
    /// granted (flows, proc-spawn, eval, fs-write, sensitive read).
    pub dangerous: bool,
}

/// Strip the `<function>[<instruction>]: ` prefix off a verifier finding.
fn finding_message(finding: &str) -> &str {
    finding.split_once("]: ").map(|(_, m)| m).unwrap_or(finding)
}

/// Render a `<kind>:<target>` capability token as its `omc.policy` `allow` clause.
pub(crate) fn dsl_allow_clause(token: &str) -> Option<String> {
    match token {
        "dynamic.eval" | "dynamic-eval" | "eval" => return Some("allow eval".to_owned()),
        "time.now" | "time" => return Some("allow time".to_owned()),
        "random.bytes" | "random" => return Some("allow random".to_owned()),
        _ => {}
    }
    let (kind, target) = token.split_once(':')?;
    let keyword = match kind {
        "env" | "env.read" | "env-read" => "env",
        "fs.read" | "fs-read" => "read",
        "fs.write" | "fs-write" => "write",
        "http" | "network" => "net",
        "dns" => "dns",
        "proc" | "proc.spawn" | "proc-spawn" => "spawn",
        _ => return None,
    };
    Some(format!("allow {keyword} {target:?}"))
}

/// Render a flow source token (`env:X` / `file:X` / `secret:X` / `*`) as its DSL form.
pub(crate) fn dsl_flow_src(token: &str) -> Option<String> {
    if token == "*" || token == "any" {
        return Some("any".to_owned());
    }
    let (kind, target) = token.split_once(':')?;
    let keyword = match kind {
        "env" | "env.read" | "env-read" => "env",
        "file" | "fs.read" | "fs-read" => "file",
        "secret" => "secret",
        _ => return None,
    };
    Some(format!("{keyword} {target:?}"))
}

/// Render a flow sink token (`network:Y` / `process:Y` / `file:Y` / `eval`) as its DSL form.
pub(crate) fn dsl_flow_sink(token: &str) -> Option<String> {
    if matches!(token, "eval" | "dynamic_eval" | "dynamic.eval") {
        return Some("eval".to_owned());
    }
    let (kind, target) = token.split_once(':')?;
    let keyword = match kind {
        "network" | "http" => "net",
        "process" | "proc" | "proc.spawn" | "proc-spawn" => "spawn",
        "file" | "fs.write" | "fs-write" => "write",
        _ => return None,
    };
    Some(format!("{keyword} {target:?}"))
}

/// Plain-English description of a flow source token (for the human line).
fn describe_flow_src(token: &str) -> String {
    match token.split_once(':') {
        Some(("env" | "env.read" | "env-read", "*")) => "your environment variables".to_owned(),
        Some(("env" | "env.read" | "env-read", t)) => {
            format!("the value of environment variable {t}")
        }
        Some(("file" | "fs.read" | "fs-read", "*")) => "files it reads".to_owned(),
        Some(("file" | "fs.read" | "fs-read", t)) => format!("the contents of file {t}"),
        Some(("secret", t)) => format!("the secret {t}"),
        _ => "a secret it read".to_owned(),
    }
}

/// Plain-English description of a flow sink token (for the human line).
fn describe_flow_sink(token: &str) -> String {
    if matches!(token, "eval" | "dynamic_eval" | "dynamic.eval") {
        return "dynamically evaluated code".to_owned();
    }
    match token.split_once(':') {
        Some(("network" | "http", "*")) => "the network (any host)".to_owned(),
        Some(("network" | "http", t)) => format!("the network host {t}"),
        Some(("process" | "proc" | "proc.spawn" | "proc-spawn", _)) => {
            "a spawned process".to_owned()
        }
        Some(("file" | "fs.write" | "fs-write", _)) => "a file it writes".to_owned(),
        _ => "an external sink".to_owned(),
    }
}

/// (human phrase, risk line, dangerous?) for a capability token.
fn describe_capability_token(token: &str) -> (String, Option<String>, bool) {
    match token {
        "dynamic.eval" | "dynamic-eval" | "eval" => (
            "run dynamically generated or loaded code (eval / exec / dynamic import)".to_owned(),
            Some("can hide arbitrary behavior from static analysis".to_owned()),
            true,
        ),
        "time.now" | "time" => ("read the current time".to_owned(), None, false),
        "random.bytes" | "random" => ("read secure random bytes".to_owned(), None, false),
        _ => {
            let (kind, target) = match token.split_once(':') {
                Some(kt) => kt,
                None => return (token.to_owned(), None, true),
            };
            match kind {
                "proc" | "proc.spawn" | "proc-spawn" => {
                    let human = if let Some(script) = target.strip_prefix("npm-script:") {
                        format!("run the npm lifecycle script `{script}` during install")
                    } else if target == "*" {
                        "spawn arbitrary processes".to_owned()
                    } else {
                        format!("spawn the process `{target}`")
                    };
                    (
                        human,
                        Some("install-time / arbitrary code execution".to_owned()),
                        true,
                    )
                }
                "fs.write" | "fs-write" => (
                    if target == "*" {
                        "write arbitrary files".to_owned()
                    } else {
                        format!("write the file {target}")
                    },
                    Some("could install a persistent backdoor".to_owned()),
                    true,
                ),
                "env" | "env.read" | "env-read" => {
                    (format!("read environment variable {target}"), None, false)
                }
                "fs.read" | "fs-read" => (
                    format!("read the file {target}"),
                    Some(
                        "reading a sensitive file (keys/credentials) stays blocked even here"
                            .to_owned(),
                    ),
                    true,
                ),
                "http" | "network" => (
                    if target == "*" {
                        "make network requests to any host".to_owned()
                    } else {
                        format!("make network requests to {target}")
                    },
                    None,
                    false,
                ),
                "dns" => (format!("resolve DNS for {target}"), None, false),
                _ => (token.to_owned(), None, true),
            }
        }
    }
}

/// Parse one verifier finding into a [`GrantNeed`] with a minimal grant. Returns
/// `None` only if the finding shape is unrecognized (the caller still shows the
/// raw line so nothing is silently dropped).
fn parse_block_finding(finding: &str) -> Option<GrantNeed> {
    let message = finding_message(finding);

    // Flow: `<source> may not flow to <sink>`.
    if let Some((src, sink)) = message.split_once(" may not flow to ") {
        let (src, sink) = (src.trim(), sink.trim());
        let human = format!(
            "send {} to {}",
            describe_flow_src(src),
            describe_flow_sink(sink)
        );
        let risk = Some(
            "this is the shape used to exfiltrate credentials/data — only allow it if you trust this package"
                .to_owned(),
        );
        let cli_flag = format!("--allow-flow {src}->{sink}");
        let policy_stmt = match (dsl_flow_src(src), dsl_flow_sink(sink)) {
            (Some(s), Some(d)) => format!("flow {s} -> {d}"),
            _ => return None,
        };
        return Some(GrantNeed {
            raw: message.to_owned(),
            human,
            risk,
            cli_flag,
            policy_stmt,
            dangerous: true,
        });
    }

    // Capability: `capability <kind>:<target> not granted`.
    let token = message
        .strip_prefix("capability ")
        .and_then(|s| s.strip_suffix(" not granted"))?
        .trim();
    let policy_stmt = dsl_allow_clause(token)?;
    let (human, risk, dangerous) = describe_capability_token(token);
    Some(GrantNeed {
        raw: message.to_owned(),
        human,
        risk,
        cli_flag: format!("--allow {token}"),
        policy_stmt,
        dangerous,
    })
}

/// Build the actionable, plain-language guidance shown when a package is blocked:
/// what it wants to do (human + raw token + risk), the exact one-run `--allow`
/// command, and a per-package, version-pinned `omc.policy` block to persist it.
/// All output is advisory text — it never grants anything.
fn render_block_guidance(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    findings: &[String],
) -> String {
    let mut needs: Vec<GrantNeed> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for finding in findings {
        match parse_block_finding(finding) {
            Some(need) if !needs.iter().any(|n| n.cli_flag == need.cli_flag) => needs.push(need),
            Some(_) => {}
            None => {
                let raw = finding_message(finding).to_owned();
                if !unknown.contains(&raw) {
                    unknown.push(raw);
                }
            }
        }
    }

    let mut out = String::new();
    out.push_str(&format!("  {name} was blocked. It wants to:\n"));
    for need in &needs {
        let marker = if need.dangerous { "!" } else { " " };
        out.push_str(&format!("    {marker} {}   ({})\n", need.human, need.raw));
        if let Some(risk) = &need.risk {
            out.push_str(&format!("      \u{2514} {risk}\n"));
        }
    }
    for raw in &unknown {
        out.push_str(&format!("    ! {raw}\n"));
    }

    if needs.is_empty() {
        return out;
    }

    let flags: Vec<&str> = needs.iter().map(|n| n.cli_flag.as_str()).collect();
    out.push_str("\n  To allow it for THIS run only:\n");
    out.push_str(&format!(
        "      omc add {ecosystem}:{name}@{version} \\\n        {}\n",
        flags.join(" \\\n        ")
    ));
    out.push_str(&format!(
        "\n  To trust {name} {version} everywhere (writes ~/.omc/policy.d/):\n"
    ));
    out.push_str(&format!(
        "      omc trust {ecosystem}:{name}@{version} {}\n",
        flags.join(" ")
    ));
    out.push_str(&format!(
        "\n  ...or add this version-pinned block to ./omc.policy (project) or\n  ~/.omc/policy.d/{name}.omc.policy (personal, applies everywhere):\n"
    ));
    out.push_str(&format!(
        "      {ecosystem} package {name:?} =={version} {{\n"
    ));
    for need in &needs {
        out.push_str(&format!("        {}\n", need.policy_stmt));
    }
    out.push_str("      }\n");
    out
}

/// Sanitize a package name into a safe `policy.d` file stem (scoped names like
/// `@scope/pkg` become `@scope_pkg`).
#[derive(Debug, Clone)]
pub struct NpmPingResult {
    pub registry: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct NpmWhoamiResult {
    pub registry: String,
    pub username: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmProfileResult {
    pub registry: String,
    pub profile: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmProfileMutationResult {
    pub registry: String,
    pub property: String,
    pub value: serde_json::Value,
    pub status: u16,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmTokenListResult {
    pub registry: String,
    pub tokens: Vec<NpmAccessToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub urls: BTreeMap<String, String>,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NpmTokenCreateOptions {
    pub password: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub expires: Option<u64>,
    pub packages: Vec<String>,
    pub packages_all: bool,
    pub scopes: Vec<String>,
    pub orgs: Vec<String>,
    pub packages_and_scopes_permission: Option<String>,
    pub orgs_permission: Option<String>,
    pub cidr: Vec<String>,
    pub bypass_2fa: bool,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmTokenCreateResult {
    pub registry: String,
    pub status: u16,
    pub token: NpmAccessToken,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmTokenRevokeResult {
    pub registry: String,
    pub token: String,
    pub status: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmTrustResult {
    pub registry: String,
    pub package: String,
    pub configs: Vec<serde_json::Value>,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmTrustMutationResult {
    pub registry: String,
    pub package: String,
    pub status: u16,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmDistTagMutationResult {
    pub registry: String,
    pub package: String,
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub status: u16,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmOwnerListResult {
    pub registry: String,
    pub package: String,
    pub owners: Vec<NpmSearchUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmOwnerMutationResult {
    pub registry: String,
    pub package: String,
    pub user: String,
    pub added: bool,
    pub changed: bool,
    pub owners: Vec<NpmSearchUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmAccessMapResult {
    pub registry: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    pub items: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmAccessStatusResult {
    pub registry: String,
    pub package: String,
    pub status: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmAccessMutationResult {
    pub registry: String,
    pub package: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_team: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    pub status: u16,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmOrgListResult {
    pub registry: String,
    pub org: String,
    pub users: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmOrgMutationResult {
    pub registry: String,
    pub action: String,
    pub org: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_count: Option<usize>,
    pub status: u16,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmTeamListResult {
    pub registry: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmTeamMutationResult {
    pub registry: String,
    pub action: String,
    pub scope: String,
    pub team: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub status: u16,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmStarMutationResult {
    pub registry: String,
    pub package: String,
    pub user: String,
    pub starred: bool,
    pub status: u16,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmStarsResult {
    pub registry: String,
    pub user: String,
    pub packages: Vec<String>,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmDeprecateResult {
    pub registry: String,
    pub package: String,
    pub requirement: String,
    pub message: String,
    pub versions: Vec<String>,
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmUnpublishResult {
    pub registry: String,
    pub package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub removed_versions: Vec<String>,
    pub dry_run: bool,
    pub force: bool,
    pub whole_package: bool,
    pub changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tarball_status: Option<u16>,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmPublishPackage {
    pub name: String,
    pub version: String,
    pub manifest: serde_json::Value,
    pub filename: String,
    pub tarball: Vec<u8>,
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<NpmProvenanceBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmProvenanceBundle {
    pub media_type: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmPublishResult {
    pub registry: String,
    pub name: String,
    pub version: String,
    pub filename: String,
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    pub status: u16,
    pub shasum: String,
    pub integrity: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PypiUploadResult {
    pub repository_url: String,
    pub filename: String,
    pub name: String,
    pub version: String,
    pub filetype: String,
    pub pyversion: String,
    pub status: u16,
    pub sha256_digest: String,
    pub skipped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PypiDistributionCheckResult {
    pub filename: String,
    pub name: String,
    pub version: String,
    pub strict: bool,
    pub passed: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PypiUploadOptions<'a> {
    pub skip_existing: bool,
    pub comment: Option<&'a str>,
    pub cert: Option<&'a Path>,
    pub client_cert: Option<&'a Path>,
    pub signature: Option<PypiUploadSignature<'a>>,
    pub attestations: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct PypiUploadSignature<'a> {
    pub filename: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PypiUploadDistribution {
    filename: String,
    name: String,
    version: String,
    filetype: String,
    pyversion: String,
    metadata: BTreeMap<String, Vec<String>>,
    description: Option<String>,
    sha256_digest: String,
    bytes: Vec<u8>,
}

type PypiUploadMetadata = (BTreeMap<String, Vec<String>>, Option<String>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmAccessToken {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        default,
        alias = "token_description",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
    #[serde(
        default,
        alias = "cidr_whitelist",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed: Option<String>,
    #[serde(default, alias = "expires", skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass_2fa: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmPackageMetadata {
    pub name: String,
    pub version: String,
    pub dist_tags: BTreeMap<String, String>,
    pub versions: Vec<String>,
    pub root: serde_json::Value,
    pub manifest: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmPackageTarball {
    pub metadata: NpmPackageMetadata,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NpmSearchPackage {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitized_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<NpmSearchUser>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub maintainers: Vec<NpmSearchUser>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NpmSearchUser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, alias = "name", skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

pub(crate) fn npm_get(client: &Client, url: &str, config: &NpmConfig) -> reqwest::blocking::RequestBuilder {
    let request = client.get(url);
    if let Some(token) = config.auth_token_for_url(url) {
        request.bearer_auth(token)
    } else {
        request
    }
}

fn npm_delete(client: &Client, url: &str, config: &NpmConfig) -> reqwest::blocking::RequestBuilder {
    let request = client.delete(url);
    if let Some(token) = config.auth_token_for_url(url) {
        request.bearer_auth(token)
    } else {
        request
    }
}

fn npm_put(client: &Client, url: &str, config: &NpmConfig) -> reqwest::blocking::RequestBuilder {
    let request = client.put(url);
    if let Some(token) = config.auth_token_for_url(url) {
        request.bearer_auth(token)
    } else {
        request
    }
}

fn npm_post(client: &Client, url: &str, config: &NpmConfig) -> reqwest::blocking::RequestBuilder {
    let request = client.post(url);
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
    let constrained_requirement = effective_npm_requirement(
        spec,
        version_requirement.as_deref(),
        &options.constraints,
        &options.npm_overrides,
    );
    if options.npm_offline {
        return resolve_npm_offline_locked_package(
            spec,
            &install_name,
            constrained_requirement.as_deref(),
            options,
        )?
        .ok_or_else(|| npm_offline_missing_lock_error(spec));
    }
    // The effective "published before" cutoff for this package: any explicit
    // --before plus the project/global/DSL minimum-release-age freshness floor.
    let npm_before_owned = effective_npm_before(options, &install_name)?;
    if npm_before_owned.is_none() {
        // Only take the lockfile-tarball fast path when no time cutoff applies;
        // a locked tarball bypasses the publish-time check.
        if let Some(resolved) = resolve_npm_lockfile_tarball(
            spec,
            &install_name,
            version_requirement.as_deref(),
            options,
        )? {
            return Ok(resolved);
        }
    }

    let npm_config = read_npm_config_for_options(&options.project_dir, options)?;
    let registry = npm_config.registry_for(&registry_name);
    let encoded = urlencoding::encode(&registry_name);
    let npm_before = npm_before_owned.as_deref();
    let version = match constrained_requirement.as_deref() {
        Some(requirement) if is_exact_npm_version(requirement) && npm_before.is_none() => {
            requirement.to_owned()
        }
        Some(requirement) => {
            let url = npm_registry_package_url(registry, &encoded);
            let root = npm_get(client, &url, &npm_config)
                .send()?
                .error_for_status()?
                .json::<NpmRoot>()?;
            choose_npm_version(&registry_name, requirement, &root, npm_before)?
        }
        None => {
            let url = npm_registry_package_url(registry, &encoded);
            let root = npm_get(client, &url, &npm_config)
                .send()?
                .error_for_status()?
                .json::<NpmRoot>()?;
            choose_npm_version(&registry_name, "latest", &root, npm_before)?
        }
    };
    let url = npm_registry_package_version_url(registry, &encoded, &version);
    let response = npm_get(client, &url, &npm_config).send()?;
    if response.status().as_u16() == 404 {
        return Err(OmcRegistryError::PackageNotFound(spec.requested()));
    }
    let version_doc = response.error_for_status()?.json::<NpmVersion>()?;
    let platform_compatible = npm_platform_compatible(&version_doc)
        && npm_version_engine_compatible(&version_doc, options);
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

pub fn upload_pypi_distribution(
    repository_url: &str,
    username: &str,
    password: &str,
    path: &Path,
    options: PypiUploadOptions<'_>,
) -> Result<PypiUploadResult> {
    let repository_url = repository_url.trim();
    if repository_url.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine upload needs a repository URL".to_owned(),
        ));
    }
    if username.trim().is_empty() && password.is_empty() && options.client_cert.is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine upload needs authentication; pass --username/--password, set TWINE_USERNAME/TWINE_PASSWORD, configure .pypirc, or pass --client-cert".to_owned(),
        ));
    }

    let distribution = prepare_pypi_upload_distribution(path)?;
    let form = pypi_upload_form(
        &distribution,
        options.comment,
        options.signature,
        options.attestations,
    )?;
    let client = pypi_upload_client(options.cert, options.client_cert)?;
    let mut request = client.post(repository_url);
    if !username.trim().is_empty() || !password.is_empty() {
        request = request.basic_auth(username, Some(password));
    }
    let response = request.multipart(form).send()?;
    let status = response.status();
    let status_code = status.as_u16();
    let text = response.text()?;
    let skipped = options.skip_existing && pypi_upload_response_is_existing(status_code, &text);
    if !status.is_success() && !skipped {
        let detail = text.trim();
        let message = if detail.is_empty() {
            format!(
                "twine upload failed for {}: HTTP {status_code}",
                distribution.filename
            )
        } else {
            format!(
                "twine upload failed for {}: HTTP {status_code}: {detail}",
                distribution.filename
            )
        };
        return Err(OmcRegistryError::UnsupportedSpec(message));
    }

    Ok(PypiUploadResult {
        repository_url: repository_url.to_owned(),
        filename: distribution.filename,
        name: distribution.name,
        version: distribution.version,
        filetype: distribution.filetype,
        pyversion: distribution.pyversion,
        status: status_code,
        sha256_digest: distribution.sha256_digest,
        skipped,
        response_text: (!text.trim().is_empty()).then_some(text),
    })
}

pub fn check_pypi_distribution(path: &Path, strict: bool) -> Result<PypiDistributionCheckResult> {
    let distribution = prepare_pypi_upload_distribution(path)?;
    let warnings = pypi_distribution_check_warnings(&distribution);
    let passed = warnings.is_empty() || !strict;
    Ok(PypiDistributionCheckResult {
        filename: distribution.filename,
        name: distribution.name,
        version: distribution.version,
        strict,
        passed,
        warnings,
    })
}

fn pypi_distribution_check_warnings(distribution: &PypiUploadDistribution) -> Vec<String> {
    let mut warnings = Vec::new();
    let content_type =
        pypi_upload_metadata_value(&distribution.metadata, "description_content_type")
            .map(str::trim)
            .filter(|value| !value.is_empty());
    if content_type.is_none() {
        warnings.push(
            "`long_description_content_type` missing. defaulting to `text/x-rst`.".to_owned(),
        );
    }

    let description = distribution
        .description
        .as_deref()
        .or_else(|| pypi_upload_metadata_value(&distribution.metadata, "description"))
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if description
        .map(|value| value.eq_ignore_ascii_case("UNKNOWN"))
        .unwrap_or(true)
    {
        warnings.push("`long_description` missing.".to_owned());
    }

    if let Some(content_type) = content_type {
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase();
        if !matches!(
            media_type.as_str(),
            "text/plain" | "text/x-rst" | "text/markdown"
        ) {
            warnings.push(format!(
                "`long_description_content_type` `{content_type}` is not one of text/plain, text/x-rst, or text/markdown."
            ));
        }
    }

    warnings
}

fn pypi_upload_client(cert: Option<&Path>, client_cert: Option<&Path>) -> Result<Client> {
    let mut builder = Client::builder().user_agent("omc-prototype/0.1");
    if let Some(cert) = cert {
        let bytes = fs::read(cert)?;
        for cert in Certificate::from_pem_bundle(&bytes)? {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(client_cert) = client_cert {
        let bytes = fs::read(client_cert)?;
        builder = builder.identity(Identity::from_pem(&bytes)?);
    }
    Ok(builder.build()?)
}

fn prepare_pypi_upload_distribution(path: &Path) -> Result<PypiUploadDistribution> {
    let bytes = fs::read(path)?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload path `{}` does not have a valid UTF-8 filename",
                path.display()
            ))
        })?
        .to_owned();
    let (filetype, pyversion, fallback_name, fallback_version) =
        pypi_upload_filename_parts(&filename)?;
    let (metadata, description) = pypi_upload_metadata_from_archive(&bytes, &filename)?;
    let name = pypi_upload_metadata_value(&metadata, "name")
        .unwrap_or(&fallback_name)
        .trim()
        .to_owned();
    let version = pypi_upload_metadata_value(&metadata, "version")
        .unwrap_or(&fallback_version)
        .trim()
        .to_owned();
    if name.is_empty() || version.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "twine upload could not determine name and version for `{filename}`"
        )));
    }

    Ok(PypiUploadDistribution {
        filename,
        name,
        version,
        filetype,
        pyversion,
        metadata,
        description,
        sha256_digest: sha256_hex(&bytes),
        bytes,
    })
}

fn pypi_upload_filename_parts(filename: &str) -> Result<(String, String, String, String)> {
    if filename.ends_with(".whl") {
        let (name, version) = parse_wheel_name_and_version(filename).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload could not parse wheel filename `{filename}`"
            ))
        })?;
        let pyversion = pypi_wheel_pyversion(filename).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload could not parse wheel Python tag `{filename}`"
            ))
        })?;
        Ok((
            "bdist_wheel".to_owned(),
            pyversion,
            name.replace('-', "_"),
            version,
        ))
    } else if is_python_sdist_filename(filename) {
        let (name, version) = parse_sdist_name_and_version(filename).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload could not parse sdist filename `{filename}`"
            ))
        })?;
        Ok(("sdist".to_owned(), "source".to_owned(), name, version))
    } else {
        Err(OmcRegistryError::UnsupportedSpec(format!(
            "twine upload supports .whl, .tar.gz, .tgz, and .zip distributions; unsupported `{filename}`"
        )))
    }
}

fn pypi_wheel_pyversion(filename: &str) -> Option<String> {
    let filename = filename.strip_suffix(".whl")?;
    let parts = filename.split('-').collect::<Vec<_>>();
    (parts.len() >= 5).then(|| parts[parts.len() - 3].to_owned())
}

fn pypi_upload_metadata_from_archive(bytes: &[u8], filename: &str) -> Result<PypiUploadMetadata> {
    if filename.ends_with(".whl") {
        return pypi_upload_zip_metadata(bytes, ".dist-info/METADATA");
    }
    if filename.to_ascii_lowercase().ends_with(".zip") {
        return pypi_upload_zip_metadata(bytes, "/PKG-INFO");
    }
    pypi_upload_tar_metadata(bytes)
}

fn pypi_upload_zip_metadata(bytes: &[u8], suffix: &str) -> Result<PypiUploadMetadata> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if file.is_dir() || file.size() > MAX_FILE_BYTES {
            continue;
        }
        let path = file.name().to_owned();
        if is_ignorable_archive_metadata_path(&path) || !path.ends_with(suffix) {
            continue;
        }
        let mut metadata = String::new();
        file.read_to_string(&mut metadata)?;
        return Ok(parse_pypi_upload_metadata(&metadata));
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "twine upload distribution did not contain package metadata".to_owned(),
    ))
}

fn pypi_upload_tar_metadata(bytes: &[u8]) -> Result<PypiUploadMetadata> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
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
        return Ok(parse_pypi_upload_metadata(&metadata));
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "twine upload distribution did not contain package metadata".to_owned(),
    ))
}

fn parse_pypi_upload_metadata(metadata: &str) -> (BTreeMap<String, Vec<String>>, Option<String>) {
    let (headers, body) = split_metadata_headers_and_body(metadata);
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    for line in folded_metadata_lines(headers) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = pypi_upload_metadata_key(key);
        let value = value.trim();
        if !key.is_empty() && !value.is_empty() {
            fields.entry(key).or_default().push(value.to_owned());
        }
    }
    let trimmed_body = body.trim();
    let description = (!trimmed_body.is_empty()).then(|| trimmed_body.to_owned());
    (fields, description)
}

fn split_metadata_headers_and_body(metadata: &str) -> (&str, &str) {
    metadata
        .split_once("\r\n\r\n")
        .or_else(|| metadata.split_once("\n\n"))
        .unwrap_or((metadata, ""))
}

fn pypi_upload_metadata_key(key: &str) -> String {
    key.trim()
        .chars()
        .map(|ch| if ch == '-' { '_' } else { ch })
        .collect::<String>()
        .to_ascii_lowercase()
}

fn pypi_upload_metadata_value<'a>(
    metadata: &'a BTreeMap<String, Vec<String>>,
    key: &str,
) -> Option<&'a str> {
    metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn pypi_upload_form(
    distribution: &PypiUploadDistribution,
    comment: Option<&str>,
    signature: Option<PypiUploadSignature<'_>>,
    attestations: Option<&str>,
) -> Result<Form> {
    let metadata_version = pypi_upload_metadata_value(&distribution.metadata, "metadata_version")
        .unwrap_or("2.1")
        .to_owned();
    let mut form = Form::new()
        .text(":action", "file_upload")
        .text("protocol_version", "1")
        .text("metadata_version", metadata_version)
        .text("name", distribution.name.clone())
        .text("version", distribution.version.clone())
        .text("filetype", distribution.filetype.clone())
        .text("pyversion", distribution.pyversion.clone())
        .text("sha256_digest", distribution.sha256_digest.clone());

    for (key, values) in &distribution.metadata {
        if matches!(
            key.as_str(),
            "metadata_version" | "name" | "version" | "filetype" | "pyversion" | "sha256_digest"
        ) {
            continue;
        }
        for value in values {
            form = form.text(key.clone(), value.clone());
        }
    }
    if let Some(description) = distribution
        .description
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        form = form.text("description", description.to_owned());
    }
    if let Some(comment) = comment.map(str::trim).filter(|value| !value.is_empty()) {
        form = form.text("comment", comment.to_owned());
    }
    if let Some(attestations) = attestations
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        form = form.text("attestations", attestations.to_owned());
    }

    let content = Part::bytes(distribution.bytes.clone())
        .file_name(distribution.filename.clone())
        .mime_str("application/octet-stream")?;
    let mut form = form.part("content", content);
    if let Some(signature) = signature {
        let signature_part = Part::bytes(signature.bytes.to_vec())
            .file_name(signature.filename.to_owned())
            .mime_str("application/octet-stream")?;
        form = form.part("gpg_signature", signature_part);
    }
    Ok(form)
}

fn pypi_upload_response_is_existing(status: u16, text: &str) -> bool {
    if status == 409 {
        return true;
    }
    if status != 400 {
        return false;
    }
    let text = text.to_ascii_lowercase();
    text.contains("already exist")
        || text.contains("already been uploaded")
        || text.contains("file already exists")
        || text.contains("filename has already been used")
}

fn npm_publish_integrity(bytes: &[u8]) -> String {
    let mut digest = Sha512::new();
    digest.update(bytes);
    format!("sha512-{}", STANDARD.encode(digest.finalize()))
}

fn npm_publish_document(
    registry: &str,
    package: &NpmPublishPackage,
    shasum: &str,
    integrity: &str,
) -> Result<serde_json::Value> {
    let mut root = serde_json::Map::new();
    root.insert("_id".to_owned(), serde_json::json!(package.name));
    root.insert("name".to_owned(), serde_json::json!(package.name));
    if let Some(description) = package
        .manifest
        .get("description")
        .and_then(serde_json::Value::as_str)
    {
        root.insert("description".to_owned(), serde_json::json!(description));
    }
    let mut dist_tags = serde_json::Map::new();
    dist_tags.insert(
        package.tag.clone(),
        serde_json::Value::String(package.version.clone()),
    );
    root.insert("dist-tags".to_owned(), serde_json::Value::Object(dist_tags));
    if let Some(access) = &package.access {
        root.insert("access".to_owned(), serde_json::json!(access));
    }

    let mut version = package.manifest.clone();
    let Some(version_object) = version.as_object_mut() else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm publish package manifest must be a JSON object".to_owned(),
        ));
    };
    version_object.insert(
        "_id".to_owned(),
        serde_json::json!(format!("{}@{}", package.name, package.version)),
    );
    version_object.insert("name".to_owned(), serde_json::json!(package.name));
    version_object.insert("version".to_owned(), serde_json::json!(package.version));
    version_object.insert(
        "dist".to_owned(),
        serde_json::json!({
            "shasum": shasum,
            "integrity": integrity,
            "tarball": npm_publish_tarball_url(registry, &package.name, &package.filename),
        }),
    );

    let mut versions = serde_json::Map::new();
    versions.insert(package.version.clone(), version);
    root.insert("versions".to_owned(), serde_json::Value::Object(versions));

    let mut attachment = serde_json::Map::new();
    attachment.insert(
        "content_type".to_owned(),
        serde_json::Value::String("application/octet-stream".to_owned()),
    );
    attachment.insert(
        "data".to_owned(),
        serde_json::Value::String(STANDARD.encode(&package.tarball)),
    );
    attachment.insert(
        "length".to_owned(),
        serde_json::json!(package.tarball.len()),
    );
    let mut attachments = serde_json::Map::new();
    attachments.insert(
        package.filename.clone(),
        serde_json::Value::Object(attachment),
    );
    if let Some(provenance) = &package.provenance {
        let mut attachment = serde_json::Map::new();
        attachment.insert(
            "content_type".to_owned(),
            serde_json::Value::String(provenance.media_type.clone()),
        );
        attachment.insert(
            "data".to_owned(),
            serde_json::Value::String(provenance.data.clone()),
        );
        attachment.insert(
            "length".to_owned(),
            serde_json::json!(provenance.data.len()),
        );
        attachments.insert(
            format!("{}-{}.sigstore", package.name, package.version),
            serde_json::Value::Object(attachment),
        );
    }
    root.insert(
        "_attachments".to_owned(),
        serde_json::Value::Object(attachments),
    );
    Ok(serde_json::Value::Object(root))
}

fn npm_publish_tarball_url(registry: &str, name: &str, filename: &str) -> String {
    let encoded = urlencoding::encode(name);
    format!("{}{encoded}/-/{filename}", ensure_trailing_slash(registry))
}

pub fn read_npm_search(
    project_dir: &Path,
    query: &str,
    limit: usize,
    registry_override: Option<&str>,
) -> Result<Vec<NpmSearchPackage>> {
    let query = query.trim();
    if query.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm search needs search terms".to_owned(),
        ));
    }

    let client = Client::new();
    let mut options = LinkOptions::new(project_dir);
    options.npm_registry_url = registry_override.map(str::to_owned);
    let npm_config = read_npm_config_for_options(project_dir, &options)?;
    let url = format!(
        "{}-/v1/search?text={}&size={}",
        ensure_trailing_slash(&npm_config.registry),
        urlencoding::encode(query),
        limit
    );
    let response = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<NpmSearchResponse>()?;
    Ok(response
        .objects
        .into_iter()
        .map(|object| object.package)
        .collect())
}

fn resolve_npm_direct_tarball(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<ResolvedPackage> {
    let fallback_source_url = spec
        .direct_url
        .clone()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(spec.requested()))?;
    let source_url = locked_npm_direct_url_for_spec(spec, options)?.unwrap_or(fallback_source_url);
    let source_url = npm_github_archive_url(&source_url)?.unwrap_or(source_url);
    let (local_path, filename) = npm_direct_tarball_source(&source_url, &spec.name)?;
    if options.npm_offline && local_path.is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm --offline cannot download direct tarball `{source_url}`"
        )));
    }
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

fn locked_npm_direct_url_for_spec(
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<Option<String>> {
    if spec.ecosystem != Ecosystem::Npm || spec.direct_url.is_none() {
        return Ok(None);
    }
    let key = spec.constraint_key();
    for candidate in [
        options.npm_resolved.get(&key),
        options.constraints.get(&key),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(url) = npm_direct_tarball_url(candidate, &options.project_dir)? {
            return Ok(Some(url));
        }
    }
    Ok(None)
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
    let source_url = npm_github_archive_url(source_url)?.unwrap_or_else(|| source_url.to_owned());
    if version_requirement
        .map(|requirement| npm_version_satisfies(version, requirement))
        .unwrap_or(true)
    {
        return Ok(Some(npm_direct_tarball_package(
            install_name,
            version,
            &source_url,
        )?));
    }
    Ok(None)
}

fn resolve_npm_offline_locked_package(
    spec: &PackageSpec,
    install_name: &str,
    version_requirement: Option<&str>,
    options: &LinkOptions,
) -> Result<Option<ResolvedPackage>> {
    let lockfile = options.project_dir.join(LOCKFILE);
    if !lockfile.exists() {
        return Ok(None);
    }
    let lock = read_lockfile(&lockfile)?;
    let Some(locked) = lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
        .filter(|package| package.name == install_name)
        .filter(|package| {
            npm_locked_package_matches_requirement(&package.version, version_requirement)
        })
        .max_by(|left, right| compare_npm_versions(&left.version, &right.version))
    else {
        return Ok(None);
    };
    let archive_path = options.project_dir.join(&locked.archive);
    if !archive_path.exists() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm --offline requires cached archive `{}` for {}",
            locked.archive,
            spec.requested()
        )));
    }
    let filename = Path::new(&locked.archive)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package.tgz")
        .to_owned();

    Ok(Some(ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: install_name.to_owned(),
        version: locked.version.clone(),
        source_url: locked.source_url.clone(),
        download_url: None,
        local_path: Some(archive_path),
        filename,
        expected_sha256: Some(locked.sha256.clone()),
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: true,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    }))
}

fn npm_locked_package_matches_requirement(version: &str, requirement: Option<&str>) -> bool {
    let Some(requirement) = requirement.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    if npm_version_satisfies(version, requirement) {
        return true;
    }
    Version::parse(requirement).is_err()
        && !requirement.starts_with(['^', '~', '>', '<', '='])
        && !requirement.contains(' ')
        && !requirement.contains(',')
}

fn npm_offline_missing_lock_error(spec: &PackageSpec) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!(
        "npm --offline requires {} to already be locked in omc.lock with a cached archive",
        spec.requested()
    ))
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
            .map(|(name, requirement)| npm_dependency(name, requirement, false, false)),
    );
    dependencies.extend(
        optional_dependencies_field
            .unwrap_or_default()
            .into_iter()
            .filter(|(name, _)| !bundled.contains(name))
            .map(|(name, requirement)| npm_dependency(name, requirement, true, false)),
    );
    dependencies.extend(
        required_peer_dependencies(
            peer_dependencies.unwrap_or_default(),
            peer_dependencies_meta.unwrap_or_default(),
        )
        .into_iter()
        .filter(|(name, _)| !bundled.contains(name))
        .map(|(name, requirement)| npm_dependency(name, requirement, false, true)),
    );

    dependencies.sort_by(|left, right| {
        left.spec
            .name
            .cmp(&right.spec.name)
            .then_with(|| left.spec.version.cmp(&right.spec.version))
            .then_with(|| left.optional.cmp(&right.optional))
            .then_with(|| left.peer.cmp(&right.peer))
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

fn npm_dependency(
    name: String,
    requirement: String,
    optional: bool,
    peer: bool,
) -> PackageDependency {
    PackageDependency {
        spec: PackageSpec::new(Ecosystem::Npm, name, Some(requirement)),
        optional,
        peer,
    }
}

fn npm_platform_compatible(version_doc: &NpmVersion) -> bool {
    npm_platform_fields(
        version_doc.os.as_ref(),
        version_doc.cpu.as_ref(),
        version_doc.libc.as_ref(),
    )
}

fn npm_version_engine_compatible(version_doc: &NpmVersion, options: &LinkOptions) -> bool {
    npm_engine_compatible(version_doc.engines.as_ref(), options.npm_engine_strict)
}

fn npm_engine_compatible(engines: Option<&BTreeMap<String, String>>, strict: bool) -> bool {
    if !strict {
        return true;
    }
    let Some(node_requirement) = engines.and_then(|engines| engines.get("node")) else {
        return true;
    };
    let Some(node_version) = current_node_version() else {
        return true;
    };
    npm_engine_requirement_satisfied(&node_version, node_requirement)
}

fn current_node_version() -> Option<Version> {
    static CURRENT_NODE_VERSION: OnceLock<Option<Version>> = OnceLock::new();
    CURRENT_NODE_VERSION
        .get_or_init(|| {
            let output = Command::new("node").arg("--version").output().ok()?;
            if !output.status.success() {
                return None;
            }
            let version = String::from_utf8_lossy(&output.stdout);
            Version::parse(version.trim().trim_start_matches('v')).ok()
        })
        .clone()
}

fn npm_engine_requirement_satisfied(version: &Version, requirement: &str) -> bool {
    let version = version.to_string();
    requirement
        .split("||")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .any(|part| npm_version_satisfies(&version, &normalize_npm_engine_requirement(part)))
}

fn normalize_npm_engine_requirement(requirement: &str) -> String {
    let mut normalized = String::new();
    let mut previous_was_operator = false;
    for token in requirement.split_whitespace() {
        if previous_was_operator {
            normalized.push_str(token);
            previous_was_operator = false;
            continue;
        }
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(token);
        previous_was_operator = matches!(token, ">" | ">=" | "<" | "<=" | "=");
    }
    normalized
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
        return resolve_pypi_direct_wheel(spec, options);
    }
    // Tighten the effective "uploaded prior to" cutoff for this package with the
    // project/global/DSL minimum-release-age floor, then resolve against it.
    let effective_prior_to = effective_pypi_uploaded_prior_to(options, &spec.name)?;
    let mut local_options;
    let options = if effective_prior_to != options.pypi_uploaded_prior_to {
        local_options = options.clone();
        local_options.pypi_uploaded_prior_to = effective_prior_to;
        &local_options
    } else {
        options
    };
    let target_python = pypi_target_python(options);
    let wheel_compatibility = pypi_wheel_compatibility(options);
    let binary_mode = pypi_binary_mode_for_spec(options, spec);
    let prerelease_policy = pypi_prerelease_policy_for_name(options, &spec.name);
    let mut candidates = pypi_find_link_candidates(
        client,
        spec,
        options,
        target_python.as_deref(),
        wheel_compatibility.as_ref(),
    )?;
    let simple_indexes = pypi_simple_index_urls(options);
    if !candidates.is_empty() || options.pypi_no_index || options.pypi_uploaded_prior_to.is_some() {
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
                wheel_compatibility.as_ref(),
                options.pypi_uploaded_prior_to.as_deref(),
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
            wheel_compatibility.as_ref(),
            options.pypi_uploaded_prior_to.as_deref(),
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
            choose_pypi_version(
                &spec.name,
                requirement,
                &root,
                target_python.as_deref(),
                wheel_compatibility.as_ref(),
                binary_mode,
                prerelease_policy,
            )?
        }
        None => {
            let url = format!("https://pypi.org/pypi/{encoded}/json");
            let root = client
                .get(url)
                .send()?
                .error_for_status()?
                .json::<PypiRoot>()?;
            choose_pypi_version(
                &spec.name,
                "*",
                &root,
                target_python.as_deref(),
                wheel_compatibility.as_ref(),
                binary_mode,
                prerelease_policy,
            )?
        }
    };
    let url = format!("https://pypi.org/pypi/{encoded}/{version}/json");
    let response = client.get(url).send()?;
    if response.status().as_u16() == 404 {
        return Err(OmcRegistryError::PackageNotFound(spec.requested()));
    }
    let doc = response.error_for_status()?.json::<PypiResponse>()?;
    let file = choose_pypi_file(
        &doc,
        target_python.as_deref(),
        wheel_compatibility.as_ref(),
        binary_mode,
    )
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
            peer: false,
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
    wheel_compatibility: Option<&PythonWheelCompatibility>,
    uploaded_prior_to: Option<&str>,
) -> Result<Vec<PypiSimpleCandidate>> {
    let mut candidates = Vec::new();
    for index in indexes {
        let url = pypi_simple_package_url(index, &spec.name)?;
        let mut request = client.get(url);
        if uploaded_prior_to.is_some() {
            request = request.header(
                ACCEPT,
                "application/vnd.pypi.simple.v1+json, text/html;q=0.2",
            );
        }
        let response = request.send()?;
        if response.status().as_u16() == 404 {
            continue;
        }
        let base_url = response.url().clone();
        let is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.contains("json"))
            .unwrap_or(false);
        let body = response.error_for_status()?.text()?;
        if is_json || body.trim_start().starts_with('{') {
            candidates.extend(pypi_simple_json_candidates(
                &base_url,
                &body,
                &spec.name,
                target_python,
                wheel_compatibility,
            )?);
        } else {
            candidates.extend(pypi_simple_index_candidates(
                &base_url,
                &body,
                &spec.name,
                target_python,
                wheel_compatibility,
                uploaded_prior_to.is_some(),
            ));
        }
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
    let binary_mode = pypi_binary_mode_for_spec(options, spec);
    let uploaded_prior_to = options
        .pypi_uploaded_prior_to
        .as_deref()
        .map(parse_pypi_uploaded_prior_to)
        .transpose()?;
    let mut candidates = candidates
        .into_iter()
        .filter(|candidate| pypi_version_satisfies(&candidate.version, &requirement))
        .filter(|candidate| pypi_candidate_matches_binary_mode(candidate, binary_mode))
        .collect::<Vec<_>>();
    if let Some(cutoff) = uploaded_prior_to {
        candidates = filter_pypi_candidates_uploaded_prior_to(candidates, cutoff, &spec.name)?;
    }
    let prerelease_policy = pypi_prerelease_policy_for_name(options, &spec.name);
    if prerelease_policy == PypiPrereleasePolicy::OnlyFinal {
        candidates.retain(|candidate| !pypi_version_is_prerelease(&candidate.version));
    } else if !pypi_prereleases_allowed(
        &requirement,
        prerelease_policy == PypiPrereleasePolicy::Allow,
        candidates
            .iter()
            .map(|candidate| candidate.version.as_str()),
    ) {
        candidates.retain(|candidate| !pypi_version_is_prerelease(&candidate.version));
    }

    let candidate = candidates
        .into_iter()
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

fn pypi_binary_mode_for_spec(options: &LinkOptions, spec: &PackageSpec) -> Option<PypiBinaryMode> {
    options
        .pypi_binary_packages
        .get(&normalize_pypi_name(&spec.name))
        .copied()
        .or(options.pypi_binary_all)
}

fn pypi_candidate_matches_binary_mode(
    candidate: &PypiSimpleCandidate,
    mode: Option<PypiBinaryMode>,
) -> bool {
    match mode {
        None => true,
        Some(PypiBinaryMode::Binary) => !candidate.sdist,
        Some(PypiBinaryMode::Source) => candidate.sdist,
    }
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
    upload_time: Option<String>,
    upload_time_required: bool,
}

fn filter_pypi_candidates_uploaded_prior_to(
    candidates: Vec<PypiSimpleCandidate>,
    cutoff: DateTime<Utc>,
    package: &str,
) -> Result<Vec<PypiSimpleCandidate>> {
    let mut filtered = Vec::new();
    for candidate in candidates {
        if !candidate.upload_time_required {
            filtered.push(candidate);
            continue;
        }
        let Some(upload_time) = candidate.upload_time.as_deref() else {
            return Err(pypi_missing_upload_time_error(package));
        };
        let Some(upload_time) = parse_pypi_upload_time(upload_time) else {
            return Err(pypi_missing_upload_time_error(package));
        };
        if upload_time < cutoff {
            filtered.push(candidate);
        }
    }
    Ok(filtered)
}

fn pypi_missing_upload_time_error(package: &str) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!(
        "pip --uploaded-prior-to requires upload-time metadata for pypi:{package}"
    ))
}

fn parse_pypi_uploaded_prior_to(value: &str) -> Result<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip --uploaded-prior-to needs a datetime or PnD duration".to_owned(),
        ));
    }
    if let Some(days) = parse_pypi_duration_days(value) {
        return Ok(Utc::now() - Duration::days(days));
    }
    if let Some(timestamp) = parse_pypi_upload_time(value) {
        return Ok(timestamp);
    }
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let Some(naive) = date.and_hms_opt(0, 0, 0) else {
            return Err(OmcRegistryError::UnsupportedSpec(value.to_owned()));
        };
        return Ok(local_naive_to_utc(naive));
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Ok(local_naive_to_utc(naive));
        }
    }
    Err(OmcRegistryError::UnsupportedSpec(format!(
        "unsupported pip --uploaded-prior-to value `{value}`"
    )))
}

fn parse_pypi_duration_days(value: &str) -> Option<i64> {
    let value = value.strip_prefix('P')?.strip_suffix('D')?;
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn parse_pypi_upload_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn local_naive_to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    if let Some(local) = Local.from_local_datetime(&naive).earliest() {
        local.with_timezone(&Utc)
    } else {
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
    }
}

fn pypi_find_link_candidates(
    client: &Client,
    spec: &PackageSpec,
    options: &LinkOptions,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
) -> Result<Vec<PypiSimpleCandidate>> {
    let mut candidates = Vec::new();
    for source in &options.pypi_find_links {
        candidates.extend(pypi_find_link_source_candidates(
            client,
            source,
            &spec.name,
            target_python,
            wheel_compatibility,
        )?);
    }
    Ok(candidates)
}

fn pypi_find_link_source_candidates(
    client: &Client,
    source: &str,
    package: &str,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
) -> Result<Vec<PypiSimpleCandidate>> {
    if let Ok(url) = reqwest::Url::parse(source) {
        return match url.scheme() {
            "http" | "https" => pypi_http_find_link_candidates(
                client,
                url,
                package,
                target_python,
                wheel_compatibility,
            ),
            "file" => {
                let Ok(path) = url.to_file_path() else {
                    return Ok(Vec::new());
                };
                pypi_local_find_link_candidates(&path, package, target_python, wheel_compatibility)
            }
            _ => Ok(Vec::new()),
        };
    }
    pypi_local_find_link_candidates(
        Path::new(source),
        package,
        target_python,
        wheel_compatibility,
    )
}

fn pypi_http_find_link_candidates(
    client: &Client,
    url: reqwest::Url,
    package: &str,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
) -> Result<Vec<PypiSimpleCandidate>> {
    if url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .map(|filename| filename.ends_with(".whl") || is_python_sdist_filename(filename))
        .unwrap_or(false)
    {
        return Ok(pypi_candidate_from_url(
            url,
            package,
            None,
            target_python,
            wheel_compatibility,
            None,
            None,
            None,
            false,
        )
        .into_iter()
        .collect());
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
        wheel_compatibility,
        false,
    ))
}

fn pypi_local_find_link_candidates(
    source: &Path,
    package: &str,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
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
                    wheel_compatibility,
                )?);
            }
        }
        return Ok(candidates);
    }
    if !source.is_file() {
        return Ok(Vec::new());
    }
    if source.extension().and_then(|ext| ext.to_str()) == Some("whl") {
        return Ok(pypi_local_archive_candidate(
            source,
            package,
            target_python,
            wheel_compatibility,
        )
        .into_iter()
        .collect());
    }
    if source
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_python_sdist_filename)
        .unwrap_or(false)
    {
        return Ok(pypi_local_archive_candidate(
            source,
            package,
            target_python,
            wheel_compatibility,
        )
        .into_iter()
        .collect());
    }

    let html = fs::read_to_string(source)?;
    let Ok(base_url) = reqwest::Url::from_file_path(source) else {
        return Ok(Vec::new());
    };
    let mut candidates = pypi_simple_index_candidates(
        &base_url,
        &html,
        package,
        target_python,
        wheel_compatibility,
        false,
    );
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
    wheel_compatibility: Option<&PythonWheelCompatibility>,
) -> Option<PypiSimpleCandidate> {
    let url = reqwest::Url::from_file_path(path).ok()?;
    pypi_candidate_from_url(
        url,
        package,
        None,
        target_python,
        wheel_compatibility,
        Some(path.to_path_buf()),
        None,
        None,
        false,
    )
}

fn pypi_simple_index_candidates(
    base_url: &reqwest::Url,
    html: &str,
    package: &str,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
    upload_time_required: bool,
) -> Vec<PypiSimpleCandidate> {
    simple_index_links(base_url, html)
        .into_iter()
        .filter_map(|link| {
            pypi_candidate_from_url(
                link.url,
                package,
                link.requires_python.as_deref(),
                target_python,
                wheel_compatibility,
                None,
                None,
                link.upload_time,
                upload_time_required,
            )
        })
        .collect()
}

fn pypi_simple_json_candidates(
    base_url: &reqwest::Url,
    body: &str,
    package: &str,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
) -> Result<Vec<PypiSimpleCandidate>> {
    let page = serde_json::from_str::<PypiSimpleJsonPage>(body)?;
    let mut candidates = Vec::new();
    for file in page.files {
        let Ok(mut url) = base_url.join(&file.url) else {
            continue;
        };
        inherit_url_credentials(base_url, &mut url);
        let sha256 = file
            .hashes
            .get("sha256")
            .and_then(|hash| normalize_sha256_hash(&format!("sha256:{hash}")));
        if let Some(candidate) = pypi_candidate_from_url(
            url,
            package,
            file.requires_python.as_deref(),
            target_python,
            wheel_compatibility,
            None,
            sha256,
            file.upload_time,
            true,
        ) {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

#[derive(Debug, Deserialize)]
struct PypiSimpleJsonPage {
    files: Vec<PypiSimpleJsonFile>,
}

#[derive(Debug, Deserialize)]
struct PypiSimpleJsonFile {
    url: String,
    #[serde(default)]
    hashes: BTreeMap<String, String>,
    #[serde(default, rename = "requires-python")]
    requires_python: Option<String>,
    #[serde(default, rename = "upload-time")]
    upload_time: Option<String>,
}

fn pypi_candidate_from_url(
    mut url: reqwest::Url,
    package: &str,
    requires_python: Option<&str>,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
    local_path: Option<PathBuf>,
    sha256_override: Option<String>,
    upload_time: Option<String>,
    upload_time_required: bool,
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
    if !sdist {
        let compatible = if let Some(compatibility) = wheel_compatibility {
            wheel_tag_compatible(&filename, compatibility)
        } else {
            current_python_wheel_compatibility()
                .as_ref()
                .map(|compatibility| wheel_tag_compatible(&filename, compatibility))
                .unwrap_or(true)
        };
        if !compatible {
            return None;
        }
    }
    let sha256 = sha256_override.or_else(|| url.fragment().and_then(simple_index_sha256_fragment));
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
        upload_time,
        upload_time_required,
    })
}

#[derive(Debug, Clone)]
struct SimpleIndexLink {
    url: reqwest::Url,
    requires_python: Option<String>,
    upload_time: Option<String>,
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
            upload_time: html_attr(tag, "data-upload-time").map(|value| html_unescape(&value)),
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

fn resolve_pypi_direct_wheel(spec: &PackageSpec, options: &LinkOptions) -> Result<ResolvedPackage> {
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
    if !pypi_sdist {
        let compatible = pypi_wheel_compatibility(options)
            .as_ref()
            .map(|compatibility| wheel_tag_compatible(&filename, compatibility))
            .unwrap_or(true);
        if !compatible {
            return Err(OmcRegistryError::MissingCompatibleWheel(spec.requested()));
        }
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

fn effective_npm_requirement(
    spec: &PackageSpec,
    requirement: Option<&str>,
    constraints: &BTreeMap<String, String>,
    npm_overrides: &BTreeMap<String, String>,
) -> Option<String> {
    npm_overrides
        .get(&spec.constraint_key())
        .cloned()
        .or_else(|| constrained_npm_requirement(spec, requirement, constraints))
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
    wheel_compatibility: Option<&PythonWheelCompatibility>,
    binary_mode: Option<PypiBinaryMode>,
) -> Option<&'a PypiFile> {
    if binary_mode == Some(PypiBinaryMode::Source) {
        return doc
            .urls
            .iter()
            .filter(|file| {
                pypi_file_compatible_for_binary_mode(
                    file,
                    target_python,
                    wheel_compatibility,
                    binary_mode,
                )
            })
            .find(|file| file.packagetype == "sdist" && is_python_sdist_filename(&file.filename));
    }

    doc.urls
        .iter()
        .filter(|file| {
            pypi_file_compatible_for_binary_mode(
                file,
                target_python,
                wheel_compatibility,
                binary_mode,
            )
        })
        .find(|file| file.packagetype == "bdist_wheel" && file.filename.contains("py3-none-any"))
        .or_else(|| {
            doc.urls
                .iter()
                .filter(|file| {
                    pypi_file_compatible_for_binary_mode(
                        file,
                        target_python,
                        wheel_compatibility,
                        binary_mode,
                    )
                })
                .find(|file| file.packagetype == "bdist_wheel")
        })
        .or_else(|| {
            if binary_mode == Some(PypiBinaryMode::Binary) {
                return None;
            }
            doc.urls
                .iter()
                .filter(|file| {
                    pypi_file_compatible_for_binary_mode(
                        file,
                        target_python,
                        wheel_compatibility,
                        binary_mode,
                    )
                })
                .find(|file| {
                    file.packagetype == "sdist" && is_python_sdist_filename(&file.filename)
                })
        })
}

fn pypi_file_compatible_for_binary_mode(
    file: &PypiFile,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
    binary_mode: Option<PypiBinaryMode>,
) -> bool {
    pypi_file_python_compatible(file, target_python, wheel_compatibility)
        && pypi_file_matches_binary_mode(file, binary_mode)
}

fn pypi_file_matches_binary_mode(file: &PypiFile, binary_mode: Option<PypiBinaryMode>) -> bool {
    match binary_mode {
        None => true,
        Some(PypiBinaryMode::Binary) => file.packagetype == "bdist_wheel",
        Some(PypiBinaryMode::Source) => {
            file.packagetype == "sdist" && is_python_sdist_filename(&file.filename)
        }
    }
}

fn is_python_sdist_filename(filename: &str) -> bool {
    let filename = filename.to_ascii_lowercase();
    filename.ends_with(".tar.gz") || filename.ends_with(".tgz") || filename.ends_with(".zip")
}

fn choose_npm_version(
    name: &str,
    requirement: &str,
    root: &NpmRoot,
    before: Option<&str>,
) -> Result<String> {
    let cutoff = before.map(parse_npm_before).transpose()?;
    if let Some(version) = root.dist_tags.get(requirement) {
        if npm_version_published_before(root, version, cutoff.as_ref())? {
            return Ok(version.to_owned());
        }
    }

    root.versions
        .keys()
        .filter(|version| npm_version_satisfies(version, requirement))
        .filter_map(
            |version| match npm_version_published_before(root, version, cutoff.as_ref()) {
                Ok(true) => Some(Ok(version)),
                Ok(false) => None,
                Err(err) => Some(Err(err)),
            },
        )
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max_by(|left, right| compare_npm_versions(left, right))
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsatisfiedRequirement {
            name: name.to_owned(),
            requirement: requirement.to_owned(),
        })
}

fn npm_version_published_before(
    root: &NpmRoot,
    version: &str,
    cutoff: Option<&DateTime<Utc>>,
) -> Result<bool> {
    let Some(cutoff) = cutoff else {
        return Ok(true);
    };
    let Some(published) = root.time.get(version) else {
        return Err(npm_missing_publish_time_error(version));
    };
    let Some(published) = parse_npm_publish_time(published) else {
        return Err(npm_missing_publish_time_error(version));
    };
    Ok(published <= *cutoff)
}

fn npm_missing_publish_time_error(version: &str) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!(
        "npm --before requires publish-time metadata for npm version {version}"
    ))
}

fn parse_npm_before(value: &str) -> Result<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm --before needs a datetime or YYYY-MM-DD date".to_owned(),
        ));
    }
    if let Some(timestamp) = parse_npm_publish_time(value) {
        return Ok(timestamp);
    }
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let Some(naive) = date.and_hms_opt(0, 0, 0) else {
            return Err(OmcRegistryError::UnsupportedSpec(value.to_owned()));
        };
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Ok(local_naive_to_utc(naive));
        }
    }
    Err(OmcRegistryError::UnsupportedSpec(format!(
        "unsupported npm --before value `{value}`"
    )))
}

fn parse_npm_publish_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
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

pub fn compare_npm_versions(left: &str, right: &str) -> std::cmp::Ordering {
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
    wheel_compatibility: Option<&PythonWheelCompatibility>,
    binary_mode: Option<PypiBinaryMode>,
    prerelease_policy: PypiPrereleasePolicy,
) -> Result<String> {
    let mut versions = root
        .releases
        .iter()
        .filter(|(_, files)| {
            files.iter().any(|file| {
                pypi_file_compatible_for_binary_mode(
                    file,
                    target_python,
                    wheel_compatibility,
                    binary_mode,
                )
            })
        })
        .map(|(version, _)| version)
        .filter(|version| pypi_version_satisfies(version, requirement))
        .cloned()
        .collect::<Vec<_>>();
    if prerelease_policy == PypiPrereleasePolicy::OnlyFinal {
        versions.retain(|version| !pypi_version_is_prerelease(version));
    } else if !pypi_prereleases_allowed(
        requirement,
        prerelease_policy == PypiPrereleasePolicy::Allow,
        versions.iter().map(String::as_str),
    ) {
        versions.retain(|version| !pypi_version_is_prerelease(version));
    }

    versions
        .into_iter()
        .max_by(|left, right| compare_pypi_versions(left, right))
        .ok_or_else(|| OmcRegistryError::UnsatisfiedRequirement {
            name: name.to_owned(),
            requirement: requirement.to_owned(),
        })
}

fn pypi_prereleases_allowed<'a>(
    requirement: &str,
    allow_prereleases: bool,
    versions: impl IntoIterator<Item = &'a str>,
) -> bool {
    allow_prereleases
        || pypi_requirement_mentions_prerelease(requirement)
        || !versions
            .into_iter()
            .any(|version| !pypi_version_is_prerelease(version))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PypiPrereleasePolicy {
    Default,
    Allow,
    OnlyFinal,
}

fn pypi_prerelease_policy_for_name(options: &LinkOptions, package: &str) -> PypiPrereleasePolicy {
    let package = normalize_pypi_name(package);
    if options.pypi_release_controls.only_final.all
        || options
            .pypi_release_controls
            .only_final
            .packages
            .contains(&package)
    {
        PypiPrereleasePolicy::OnlyFinal
    } else if options.pypi_allow_prereleases
        || options.pypi_release_controls.all_releases.all
        || options
            .pypi_release_controls
            .all_releases
            .packages
            .contains(&package)
    {
        PypiPrereleasePolicy::Allow
    } else {
        PypiPrereleasePolicy::Default
    }
}

fn pypi_requirement_mentions_prerelease(requirement: &str) -> bool {
    requirement
        .trim_matches(|ch| ch == '(' || ch == ')')
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter_map(pypi_comparator_version)
        .any(pypi_version_is_prerelease)
}

fn pypi_comparator_version(comparator: &str) -> Option<&str> {
    for op in [">=", "<=", "===", "==", "!=", "~=", ">", "<"] {
        if let Some(required) = comparator.strip_prefix(op) {
            return Some(required.trim());
        }
    }
    Some(comparator.trim())
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

fn pypi_file_python_compatible(
    file: &PypiFile,
    target_python: Option<&str>,
    wheel_compatibility: Option<&PythonWheelCompatibility>,
) -> bool {
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

    if let Some(compatibility) = wheel_compatibility {
        wheel_tag_compatible(&file.filename, compatibility)
    } else {
        current_python_wheel_compatibility()
            .as_ref()
            .map(|compatibility| wheel_tag_compatible(&file.filename, compatibility))
            .unwrap_or(true)
    }
}

fn pypi_target_python(options: &LinkOptions) -> Option<String> {
    options
        .pypi_target_python
        .as_deref()
        .and_then(parse_target_python_version)
        .map(|(major, minor)| format!("{major}.{minor}.0"))
        .or_else(|| options.pypi_target_python.clone())
        .or_else(current_python_version)
}

fn pypi_wheel_compatibility(options: &LinkOptions) -> Option<PythonWheelCompatibility> {
    PythonWheelCompatibility::from_target_options(
        options.pypi_target_python.as_deref(),
        options.pypi_target_implementation.as_deref(),
        &options.pypi_target_abis,
        &options.pypi_target_platforms,
    )
    .or_else(current_python_wheel_compatibility)
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
    fn from_target_options(
        python_version: Option<&str>,
        implementation: Option<&str>,
        abis: &[String],
        platforms: &[String],
    ) -> Option<Self> {
        if python_version.is_none()
            && implementation.is_none()
            && abis.is_empty()
            && platforms.is_empty()
        {
            return None;
        }

        let current = current_python_wheel_compatibility();
        let current_python = current_python_version();
        let (major, minor) = python_version
            .and_then(parse_target_python_version)
            .or_else(|| {
                current_python
                    .as_deref()
                    .and_then(parse_target_python_version)
            })
            .unwrap_or((3, 0));
        let implementation = implementation
            .map(normalize_python_implementation_tag)
            .unwrap_or_else(|| "cpython".to_owned());

        let mut python_tags = BTreeSet::from([format!("py{major}"), format!("py{major}{minor}")]);
        if implementation == "cpython" {
            python_tags.insert(format!("cp{major}{minor}"));
        }

        let mut abi_tags = BTreeSet::from(["none".to_owned(), "abi3".to_owned()]);
        if abis.is_empty() {
            if implementation == "cpython" {
                abi_tags.insert(format!("cp{major}{minor}"));
            } else if let Some(current) = current.as_ref() {
                abi_tags.extend(current.abi_tags.iter().cloned());
            }
        } else {
            abi_tags.extend(abis.iter().map(|abi| normalize_wheel_platform(abi)));
        }

        let mut platform_tags = BTreeSet::from(["any".to_owned()]);
        if platforms.is_empty() {
            if let Some(current) = current.as_ref() {
                platform_tags.extend(current.platform_tags.iter().cloned());
            }
        } else {
            platform_tags.extend(
                platforms
                    .iter()
                    .map(|platform| normalize_wheel_platform(platform)),
            );
        }

        Some(Self {
            python_tags,
            abi_tags,
            platform_tags,
        })
    }

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

fn parse_target_python_version(value: &str) -> Option<(u64, u64)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some((major, rest)) = value.split_once('.') {
        return Some((major.parse().ok()?, rest.split('.').next()?.parse().ok()?));
    }
    if value.len() >= 2 {
        let (major, minor) = value.split_at(1);
        return Some((major.parse().ok()?, minor.parse().ok()?));
    }
    Some((value.parse().ok()?, 0))
}

fn normalize_python_implementation_tag(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "cp" | "cpython" => "cpython".to_owned(),
        other => other.to_owned(),
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

pub fn compare_pypi_versions(left: &str, right: &str) -> std::cmp::Ordering {
    comparable_pypi_version(left).cmp(&comparable_pypi_version(right))
}

fn pypi_version_is_prerelease(version: &str) -> bool {
    comparable_pypi_version(version).phase != PypiReleasePhase::Final
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PypiVersionKey {
    epoch: u64,
    release: Vec<u64>,
    phase: PypiReleasePhase,
    post: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PypiReleasePhase {
    Dev(u64),
    Alpha(u64),
    Beta(u64),
    Rc(u64),
    Final,
}

fn comparable_pypi_version(version: &str) -> PypiVersionKey {
    let lower = version.trim().trim_start_matches('v').to_ascii_lowercase();
    let public = lower
        .split_once('+')
        .map(|(public, _)| public)
        .unwrap_or(&lower);
    let (epoch, rest) = public
        .split_once('!')
        .map(|(epoch, rest)| (epoch.parse().unwrap_or(0), rest))
        .unwrap_or((0, public));
    let (release, rest) = pypi_release_segments(rest);
    let suffix = rest.trim_matches(|ch: char| matches!(ch, '.' | '-' | '_'));
    let phase = pypi_release_phase(suffix);
    let post = pypi_post_release(suffix);
    PypiVersionKey {
        epoch,
        release,
        phase,
        post,
    }
}

fn pypi_release_segments(version: &str) -> (Vec<u64>, &str) {
    let mut release = Vec::new();
    let mut index = 0;
    let bytes = version.as_bytes();
    loop {
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if start == index {
            break;
        }
        release.push(version[start..index].parse().unwrap_or(0));
        if index >= bytes.len() || bytes[index] != b'.' {
            break;
        }
        index += 1;
    }
    while release.last() == Some(&0) {
        release.pop();
    }
    if release.is_empty() {
        release.push(0);
    }
    (release, &version[index..])
}

fn pypi_release_phase(suffix: &str) -> PypiReleasePhase {
    if let Some(number) = pypi_suffix_number(suffix, &["dev"]) {
        return PypiReleasePhase::Dev(number);
    }
    if let Some(number) = pypi_suffix_number(suffix, &["alpha", "a"]) {
        return PypiReleasePhase::Alpha(number);
    }
    if let Some(number) = pypi_suffix_number(suffix, &["beta", "b"]) {
        return PypiReleasePhase::Beta(number);
    }
    if let Some(number) = pypi_suffix_number(suffix, &["preview", "pre", "rc", "c"]) {
        return PypiReleasePhase::Rc(number);
    }
    PypiReleasePhase::Final
}

fn pypi_post_release(suffix: &str) -> Option<u64> {
    pypi_suffix_number(suffix, &["post", "rev", "r"])
}

fn pypi_suffix_number(suffix: &str, labels: &[&str]) -> Option<u64> {
    let normalized = suffix.replace(['-', '_'], ".");
    let bytes = normalized.as_bytes();
    let mut index = 0;
    while index < normalized.len() {
        if matches!(bytes[index], b'.') {
            index += 1;
            continue;
        }
        for label in labels {
            if !normalized[index..].starts_with(label) {
                continue;
            }
            let after = index + label.len();
            if after < normalized.len() && normalized.as_bytes()[after].is_ascii_alphabetic() {
                continue;
            }
            return Some(pypi_suffix_numeric_value(&normalized[after..]));
        }
        index += 1;
    }
    None
}

fn pypi_suffix_numeric_value(rest: &str) -> u64 {
    let rest = rest.trim_start_matches('.');
    let digits = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse().unwrap_or(0)
}


fn grants_all_host_capabilities(capabilities: &[Capability]) -> bool {
    capabilities
        .iter()
        .any(|capability| matches!(capability, Capability::EnvRead(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::FsRead(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::FsWrite(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::HttpHost(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::DnsHost(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::ProcSpawn(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::DynamicEval))
}

pub fn compile_source_path(options: CompileSourceOptions) -> Result<CompileSourceReport> {
    let source_path = fs::canonicalize(&options.source_path)?;
    let source_url = file_url_from_path(&source_path, "compile source path")?;
    let filename = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source")
        .to_owned();
    let package = ResolvedPackage {
        ecosystem: options.ecosystem,
        name: options.name.clone(),
        version: options.version.clone(),
        source_url: source_url.clone(),
        download_url: None,
        local_path: Some(source_path.clone()),
        filename,
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let (source_sha256, profile) = if source_path.is_dir() {
        (
            hash_profiled_directory(&source_path)?,
            profile_source_directory(&source_path)?,
        )
    } else {
        let bytes = fs::read(&source_path)?;
        (sha256_hex(&bytes), profile_archive(&package, &bytes)?)
    };
    let module = module_from_profile(&package, &profile.capabilities);
    let explicit_grants_all_host = grants_all_host_capabilities(&options.allowed_capabilities);
    let policy = default_public_capabilities()
        .into_iter()
        .chain(options.allowed_capabilities.iter().cloned())
        .fold(Policy::pure(), Policy::allow_capability);
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
    // Layer the optional `omc.policy` DSL for this compiled local source too, so
    // a locally-compiled package is held to the same per-package block an
    // installed one would be.
    let policy = effective_package_policy(
        &options.project_dir,
        policy,
        package.ecosystem,
        &package.name,
        &package.version,
    )?;
    let verifier_findings = verify_module(&module, &policy)
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
            ecosystem: options.ecosystem,
            name: options.name,
            version: options.version,
        },
        source_url,
        source_sha256,
        compiler: "omc-prototype-source-profiler".to_owned(),
        microcode: module,
        behavior,
        verdict,
        grants: options
            .allowed_capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
        dependencies: Vec::new(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        files_scanned: profile.files_scanned,
        capabilities: profile.capabilities,
        verifier_findings,
        signature: None,
    };
    sign_artifact(&options.project_dir, &mut artifact)?;
    let artifact_path = if options.write_artifact {
        Some(write_artifact(&options.project_dir, &package, &artifact)?)
    } else {
        None
    };

    Ok(CompileSourceReport {
        artifact,
        artifact_path,
    })
}

fn file_url_from_path(path: &Path, description: &str) -> Result<String> {
    reqwest::Url::from_file_path(path)
        .map(|url| url.to_string())
        .map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "{description} `{}` could not be converted to a file URL",
                path.display()
            ))
        })
}



fn module_from_profile(package: &ResolvedPackage, capabilities: &[CapabilityFinding]) -> Module {
    let capabilities = unique_capability_findings(capabilities);
    let behavior = if capabilities.is_empty() {
        BehaviorType::Pure
    } else {
        BehaviorType::HostCapability
    };
    // F2: model a tainted DATA FLOW from EVERY sensitive source (env/file read)
    // to EVERY sink (network, process spawn, fs write, dynamic eval) so the
    // verifier's `check_flows` evaluates each source->sink pair. Previously only
    // the env-read x http pairing was wired (`body_from_stack`), so fs-read->net,
    // env->proc, env->eval and env->fs-write were silently Accepted at install
    // time even though the identical env->http pattern was Blocked. We emit, for
    // each (source, sink) pair, a self-contained `push source; consume in sink`
    // sequence; the sink's *_from_stack flag makes the verifier pop the tainted
    // label and run the flow check, requiring a covering flow grant to pass.
    let mut code = Vec::new();
    let is_source = |finding: &&CapabilityFinding| {
        matches!(
            finding.kind,
            CapabilityKind::EnvRead | CapabilityKind::FsRead
        )
    };
    let is_sink = |finding: &&CapabilityFinding| {
        matches!(
            finding.kind,
            CapabilityKind::HttpRequest
                | CapabilityKind::ProcSpawn
                | CapabilityKind::FsWrite
                | CapabilityKind::DynamicEval
        )
    };
    let sources = capabilities.iter().filter(is_source).collect::<Vec<_>>();
    let sinks = capabilities.iter().filter(is_sink).collect::<Vec<_>>();

    if sources.is_empty() || sinks.is_empty() {
        // No source->sink edge to model; emit each capability once so the
        // per-capability grant check (and the F1 DynamicEval deny) still runs.
        for finding in &capabilities {
            code.push(Op::Cap(cap_op_from_finding(finding)));
        }
    } else {
        for source in &sources {
            for sink in &sinks {
                code.push(Op::Cap(cap_op_from_finding(source)));
                code.push(Op::Cap(sink_cap_op_consuming_stack(sink)));
            }
        }
        // Emit sources/sinks once more standalone is unnecessary: every source
        // and every sink already appears in at least one pair above, so their
        // capability grant is checked. Nothing else to add.
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

fn unique_capability_findings(capabilities: &[CapabilityFinding]) -> Vec<CapabilityFinding> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for finding in capabilities {
        if seen.insert((finding.kind, finding.target.clone())) {
            unique.push(finding.clone());
        }
    }
    unique
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
            args_from_stack: 0,
        },
        CapabilityKind::DynamicEval => CapOp::DynamicEval {
            source_from_stack: false,
        },
    }
}

/// Build the sink CapOp for a finding with its from-stack flag set, so the
/// verifier pops the tainted source label pushed immediately before it and runs
/// `check_flows` for the source->sink pair (F2). Non-sink findings fall back to
/// the plain op.
fn sink_cap_op_consuming_stack(finding: &CapabilityFinding) -> CapOp {
    match finding.kind {
        CapabilityKind::HttpRequest => CapOp::HttpRequest {
            request: HttpRequest {
                method: "POST".to_owned(),
                url: "omc://observed-network".to_owned(),
                host: finding.target.clone(),
                body_from_stack: true,
            },
        },
        CapabilityKind::ProcSpawn => CapOp::ProcSpawn {
            command: finding.target.clone(),
            args: Vec::new(),
            args_from_stack: 1,
        },
        CapabilityKind::FsWrite => CapOp::FsWrite {
            path: VirtualPath(finding.target.clone()),
            value_from_stack: true,
        },
        CapabilityKind::DynamicEval => CapOp::DynamicEval {
            source_from_stack: true,
        },
        // Not a sink: emit the plain op (no stack consumption).
        CapabilityKind::EnvRead | CapabilityKind::FsRead => cap_op_from_finding(finding),
    }
}

fn render_verify_finding(finding: VerifyFinding) -> String {
    format!(
        "{}[{}]: {}",
        finding.function, finding.instruction, finding.message
    )
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

pub(crate) fn safe_name(name: &str) -> String {
    name.replace('/', "__")
}

fn relative_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[derive(Debug, Clone, Deserialize)]
struct ProjectPackageJson {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
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
pub(crate) struct PyProjectToml {
    pub(crate) project: Option<PyProjectProject>,
    #[serde(default, rename = "dependency-groups")]
    dependency_groups: BTreeMap<String, Vec<PyProjectDependencyGroupItem>>,
    pub(crate) tool: Option<PyProjectTool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PyProjectProject {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub(crate) scripts: BTreeMap<String, String>,
    #[serde(default, rename = "gui-scripts")]
    pub(crate) gui_scripts: BTreeMap<String, String>,
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

#[derive(Debug, Default, Deserialize)]
struct InlineScriptMetadata {
    #[serde(default)]
    dependencies: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PyProjectTool {
    pub(crate) poetry: Option<PoetryProject>,
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
pub(crate) struct PoetryProject {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, PoetryDependency>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: BTreeMap<String, PoetryDependency>,
    #[serde(default)]
    extras: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub(crate) scripts: BTreeMap<String, PoetryScript>,
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
pub(crate) enum PoetryScript {
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
    url: Option<String>,
    #[serde(default)]
    hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonEntryPoint {
    pub(crate) name: String,
    pub(crate) module: String,
    pub(crate) function: String,
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
mod policy_dsl_tests;
#[cfg(test)]
mod redteam_capability_evasion;
#[cfg(test)]
mod tests;
