//! uv.lock parsing and local source resolution.
//!
//! Extracted from `lib.rs`: the `uv_*` / `Uv*` cluster that parses `uv.lock`
//! and `pyproject.toml` `[tool.uv]` tables and resolves local (path/workspace)
//! sources.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use walkdir::WalkDir;

use crate::*;

pub(crate) fn uv_local_sources(lock: &UvLock, base_dir: &Path) -> BTreeMap<String, PathBuf> {
    lock.package
        .iter()
        .filter_map(|package| {
            let source = package.source.as_ref()?;
            let path = uv_source_local_path(source, base_dir);
            path.map(|path| (normalize_pypi_name(&package.name), path))
        })
        .collect()
}

pub(crate) fn uv_local_source_map_with_workspace(
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

pub(crate) fn collect_uv_dist_hash(
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

pub(crate) enum PythonDependencyRequirement {
    Spec(PackageSpec),
    LocalPath(PathBuf),
}

pub(crate) fn uv_dependency_requirement(
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

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvProject {
    #[serde(default)]
    pub(crate) sources: BTreeMap<String, UvProjectSource>,
    pub(crate) workspace: Option<UvWorkspace>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvProjectSource {
    path: Option<String>,
    #[serde(default)]
    workspace: bool,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvWorkspace {
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvLock {
    #[serde(default)]
    pub(crate) package: Vec<UvLockedPackage>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvLockedPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: Option<UvPackageSource>,
    pub(crate) sdist: Option<UvDistribution>,
    #[serde(default)]
    pub(crate) wheels: Vec<UvDistribution>,
    pub(crate) metadata: Option<UvPackageMetadata>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvPackageSource {
    pub(crate) registry: Option<String>,
    editable: Option<String>,
    directory: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvDistribution {
    hash: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvPackageMetadata {
    #[serde(default, rename = "requires-dist")]
    pub(crate) requires_dist: Vec<UvRequirement>,
    #[serde(default, rename = "requires-dev")]
    pub(crate) requires_dev: BTreeMap<String, Vec<UvRequirement>>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UvRequirement {
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
