//! Pipfile / Pipfile.lock parsing.
//!
//! Deserializes `Pipfile` (TOML) and `Pipfile.lock` (JSON) into the shared
//! `ProjectRequirements`, translating each package/source entry into the
//! ecosystem-neutral requirement types. Extracted verbatim from lib.rs.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::pypi_resolve::{
    is_pypi_archive_filename, is_pypi_archive_reference, normalize_pypi_extra, normalize_pypi_name,
    normalize_pypi_simple_index_url, parse_pypi_requirement_with_extras,
    parse_python_vcs_requirement, pypi_marker_applies, python_vcs_table_reference,
    PypiProjectRequirement,
};

pub(crate) fn collect_pipfile_sources(
    sources: &[PipfileSource],
    requirements: &mut ProjectRequirements,
) {
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

pub(crate) fn collect_pipfile_packages(
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

pub(crate) fn collect_pipfile_lock_sources(
    metadata: &PipfileLockMetadata,
    requirements: &mut ProjectRequirements,
) {
    collect_pipfile_sources(&metadata.sources, requirements);
}

pub(crate) fn collect_pipfile_locked_packages(
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

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Pipfile {
    #[serde(default)]
    pub(crate) source: Vec<PipfileSource>,
    #[serde(default)]
    pub(crate) packages: BTreeMap<String, PipfilePackage>,
    #[serde(default, rename = "dev-packages")]
    pub(crate) dev_packages: BTreeMap<String, PipfilePackage>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PipfileScripts {
    #[serde(default)]
    pub(crate) scripts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum PipfilePackage {
    Version(String),
    Table(Box<PipfilePackageTable>),
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PipfilePackageTable {
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
pub(crate) struct PipfileLock {
    #[serde(default, rename = "_meta")]
    pub(crate) metadata: PipfileLockMetadata,
    #[serde(default)]
    pub(crate) default: BTreeMap<String, PipfileLockedPackage>,
    #[serde(default)]
    pub(crate) develop: BTreeMap<String, PipfileLockedPackage>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PipfileLockMetadata {
    #[serde(default)]
    sources: Vec<PipfileSource>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PipfileSource {
    url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PipfileLockedPackage {
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
