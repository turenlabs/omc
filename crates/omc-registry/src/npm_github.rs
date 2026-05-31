//! npm GitHub / direct-tarball dependency resolution.
//!
//! Extracted verbatim from `lib.rs`: helpers that translate GitHub shorthand
//! and direct (https/file) tarball references into resolvable npm packages,
//! plus the offline/lockfile direct-tarball resolution paths.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use reqwest::blocking::Client;
use semver::Version;

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

pub(crate) fn npm_direct_tarball_url(requirement: &str, base_dir: &Path) -> Result<Option<String>> {
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

pub(crate) fn npm_github_archive_url(requirement: &str) -> Result<Option<String>> {
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

pub(crate) fn npm_github_dependency_parts(
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

pub(crate) fn is_npm_tarball_path(path: &str) -> bool {
    let lower = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    lower.ends_with(".tgz") || lower.ends_with(".tar.gz")
}

pub(crate) fn resolve_npm_direct_tarball(
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

pub(crate) fn locked_npm_direct_url_for_spec(
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

pub(crate) fn resolve_npm_lockfile_tarball(
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

pub(crate) fn resolve_npm_offline_locked_package(
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

pub(crate) fn npm_offline_missing_lock_error(spec: &PackageSpec) -> OmcRegistryError {
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
