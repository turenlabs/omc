//! PyPI spec + requirements/pyproject/markers resolution.
//!
//! Extracted from lib.rs (refactor/split-lib-modules).

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) fn parse_pypi_requirement(requirement: &str) -> Option<PackageSpec> {
    parse_pypi_requirement_with_extras(requirement, &BTreeSet::new())
}

pub(crate) fn parse_pypi_direct_requirement(
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

pub(crate) fn parse_pypi_local_direct_requirement(
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

pub(crate) enum PypiProjectRequirement {
    Spec(PackageSpec, BTreeSet<String>),
    LocalPath(PythonLocalRequirement),
    Vcs(PythonVcsRequirement),
}

pub(crate) fn collect_pypi_project_requirement(
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
        PypiProjectRequirement::LocalPath(requirement) => {
            push_python_local_requirement(requirements, requirement);
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
            return Ok(Some(PypiProjectRequirement::LocalPath(
                PythonLocalRequirement::new(path, spec.extras.clone()),
            )));
        }
        return Ok(Some(PypiProjectRequirement::Spec(spec, hashes)));
    }

    if let Some(requirement) =
        parse_pypi_local_direct_path_requirement(requirement, active_extras, base_dir)?
    {
        return Ok(Some(PypiProjectRequirement::LocalPath(requirement)));
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
        return Ok(Some(PypiProjectRequirement::LocalPath(
            PythonLocalRequirement::new(path.clone(), spec.extras.clone()),
        )));
    }

    Ok(Some(PypiProjectRequirement::Spec(spec, BTreeSet::new())))
}

pub(crate) fn pypi_direct_file_url_local_directory(
    direct_url: Option<&str>,
) -> Result<Option<PathBuf>> {
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

pub(crate) fn parse_pypi_vcs_direct_requirement(
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

pub fn parse_pypi_vcs_requirement(value: &str) -> Result<Option<PythonVcsRequirement>> {
    if let Some(requirement) = parse_pypi_vcs_direct_requirement(value, &BTreeSet::new())? {
        return Ok(Some(requirement));
    }
    parse_requirements_bare_vcs_requirement(value, &BTreeSet::new())
}

pub(crate) fn parse_requirements_editable_vcs_requirement(
    value: &str,
) -> Result<Option<PythonVcsRequirement>> {
    parse_python_vcs_requirement(None, value, None, false)
}

pub(crate) fn parse_requirements_bare_vcs_requirement(
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

pub(crate) fn parse_python_vcs_requirement(
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

pub(crate) fn python_vcs_table_reference(
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

pub(crate) fn parse_pypi_local_direct_path_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<Option<PythonLocalRequirement>> {
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
    let (name, extras) = parse_pypi_name_and_extras(name.trim());
    if name.is_empty() {
        return Ok(None);
    }
    let (path, _) = direct_requirement_url_and_hashes(path.trim());
    if path.contains("://") || is_pypi_archive_reference(&path) {
        return Ok(None);
    }
    let path = strip_relative_local_path_scheme(&path);
    let path = resolved_local_path(&path, base_dir);
    Ok(path
        .is_dir()
        .then(|| PythonLocalRequirement::new(path, extras)))
}

pub(crate) fn parse_pypi_local_path_requirement(
    requirement: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<Option<PythonLocalRequirement>> {
    let mut parts = requirement.splitn(2, ';');
    let requirement_body = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(None);
        }
    }

    let (path, _) = split_python_local_path_extras(requirement_body);
    let local_file_url = path.starts_with("file://");
    if (!looks_like_local_path_requirement(requirement_body) && !local_file_url)
        || (requirement_body.contains("://") && !local_file_url)
        || is_pypi_archive_reference(requirement_body)
    {
        return Ok(None);
    }

    let local = normalize_requirements_editable_path(requirement_body, base_dir)?;
    if !local.path.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(
            requirement.to_owned(),
        ));
    }
    Ok(Some(local))
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

pub(crate) fn pypi_direct_reference_applies(
    requirement: &str,
    active_extras: &BTreeSet<String>,
) -> bool {
    let mut parts = requirement.splitn(2, ';');
    let requirement = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return false;
        }
    }
    requirement.contains(" @ ")
}

pub(crate) fn parse_pypi_local_archive_requirement(
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

pub(crate) fn parse_pypi_direct_archive_url_reference(
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

    let path = strip_relative_local_path_scheme(&path);
    let path = Path::new(&path);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    };
    let path = if path.is_absolute() {
        path
    } else {
        env::current_dir()?.join(path)
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

pub(crate) fn is_pypi_archive_reference(value: &str) -> bool {
    let (value, _) = direct_requirement_url_and_hashes(value.trim());
    let filename = value
        .rsplit_once('/')
        .map(|(_, filename)| filename)
        .unwrap_or(&value);
    is_pypi_archive_filename(filename)
}

pub(crate) fn is_pypi_archive_filename(filename: &str) -> bool {
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

pub(crate) fn parse_pypi_requirement_with_extras(
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

pub(crate) fn parse_pypi_name_and_extras(name: &str) -> (String, BTreeSet<String>) {
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

pub(crate) fn normalize_pypi_name(name: &str) -> String {
    name.replace('_', "-").to_ascii_lowercase()
}

pub(crate) fn normalize_pypi_extra(extra: &str) -> String {
    extra.trim().replace('_', "-").to_ascii_lowercase()
}

pub(crate) fn parse_requirements_include(line: &str) -> Option<RequirementsInclude> {
    for (prefixes, mode) in [
        (
            &["--requirement=", "--requirement", "-r"][..],
            RequirementsMode::Install,
        ),
        (
            &["--constraint=", "--constraint", "-c"][..],
            RequirementsMode::Constraint,
        ),
    ] {
        if let Some(path) = parse_requirements_option_value(line, prefixes) {
            if !path.is_empty() {
                return Some(RequirementsInclude { path, mode });
            }
        }
    }

    None
}

pub(crate) fn parse_requirements_index_url(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--index-url=", "--index-url", "-i"])
        .and_then(|index_url| normalize_pypi_simple_index_url(&index_url))
}

pub(crate) fn parse_requirements_extra_index_url(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--extra-index-url=", "--extra-index-url"])
        .and_then(|index_url| normalize_pypi_simple_index_url(&index_url))
}

pub(crate) fn parse_requirements_find_links(line: &str, base_dir: &Path) -> Option<String> {
    parse_requirements_option_value(line, &["--find-links=", "--find-links", "-f"])
        .and_then(|find_links| normalize_pypi_find_links_source(&find_links, base_dir))
}

pub(crate) fn parse_requirements_no_index(line: &str) -> bool {
    line == "--no-index"
}

pub(crate) fn parse_requirements_require_hashes(line: &str) -> bool {
    line == "--require-hashes"
}

pub(crate) fn parse_requirements_no_deps(line: &str) -> bool {
    line == "--no-deps"
}

pub(crate) fn parse_requirements_allow_prereleases(line: &str) -> bool {
    line == "--pre"
}

pub(crate) fn parse_requirements_all_releases(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--all-releases=", "--all-releases"])
}

pub(crate) fn parse_requirements_only_final(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--only-final=", "--only-final"])
}

pub(crate) fn parse_requirements_uploaded_prior_to(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--uploaded-prior-to=", "--uploaded-prior-to"])
}

pub(crate) fn parse_requirements_binary_option(line: &str, mode: PypiBinaryMode) -> Option<String> {
    match mode {
        PypiBinaryMode::Binary => {
            parse_requirements_option_value(line, &["--only-binary=", "--only-binary"])
        }
        PypiBinaryMode::Source => {
            parse_requirements_option_value(line, &["--no-binary=", "--no-binary"])
        }
    }
}

pub(crate) fn parse_requirements_compatible_global_option(line: &str) -> bool {
    line == "--prefer-binary"
        || parse_requirements_option_value(line, &["--trusted-host=", "--trusted-host"]).is_some()
        || parse_requirements_option_value(line, &["--use-feature=", "--use-feature"]).is_some()
        || parse_requirements_option_value(line, &["--use-deprecated=", "--use-deprecated"])
            .is_some()
}

pub(crate) fn parse_requirements_editable_value(line: &str) -> Option<String> {
    parse_requirements_option_value(line, &["--editable=", "--editable", "-e"])
}

pub(crate) fn normalize_requirements_editable_path(
    value: &str,
    base_dir: &Path,
) -> Result<PythonLocalRequirement> {
    let (path, extras) = split_python_local_path_extras(value);
    if let Some(path) = local_file_url_path(path)? {
        return Ok(PythonLocalRequirement::new(path, extras));
    }
    if path.contains("://") || path.starts_with("git+") {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "editable requirement `{value}` must be a local path"
        )));
    }
    let path = strip_relative_local_path_scheme(path);
    let path = PathBuf::from(path);
    let path = if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    };
    Ok(PythonLocalRequirement::new(path, extras))
}

fn split_python_local_path_extras(value: &str) -> (&str, BTreeSet<String>) {
    let Some((path, extras)) = value.split_once('[') else {
        return (value, BTreeSet::new());
    };
    let extras = extras
        .trim_end_matches(']')
        .split(',')
        .map(normalize_pypi_extra)
        .filter(|extra| !extra.is_empty())
        .collect();
    (path, extras)
}

fn parse_requirements_option_value(line: &str, prefixes: &[&str]) -> Option<String> {
    for prefix in prefixes {
        if prefix.ends_with('=') {
            let Some(value) = line.strip_prefix(prefix) else {
                continue;
            };
            return first_shell_like_token(value);
        } else if line == *prefix || line.starts_with(&format!("{prefix} ")) {
            return shell_like_tokens(line)
                .get(1)
                .filter(|value| !value.is_empty())
                .cloned();
        } else if let Some(value) = short_option_attached_value(line, prefix) {
            return Some(value.to_owned());
        }
    }
    None
}

fn short_option_attached_value<'a>(arg: &'a str, prefix: &str) -> Option<&'a str> {
    if !prefix.starts_with('-') || prefix.starts_with("--") || prefix.len() != 2 {
        return None;
    }
    let value = arg.strip_prefix(prefix)?;
    if value.is_empty() || value.starts_with(char::is_whitespace) {
        return None;
    }
    Some(value)
}

fn first_shell_like_token(value: &str) -> Option<String> {
    shell_like_tokens(value)
        .into_iter()
        .find(|value| !value.is_empty())
}

pub(crate) fn normalize_pypi_find_links_source(value: &str, base_dir: &Path) -> Option<String> {
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

pub(crate) fn normalize_pypi_simple_index_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(ensure_trailing_slash(value))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PypiMarkerEnvironment {
    pub(crate) python_full_version: Option<String>,
    pub(crate) os_name: String,
    pub(crate) sys_platform: String,
    pub(crate) platform_system: String,
    pub(crate) platform_machine: String,
    pub(crate) implementation_name: String,
    pub(crate) platform_python_implementation: String,
    pub(crate) extra: String,
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

pub fn pypi_marker_applies(marker: &str, active_extras: &BTreeSet<String>) -> bool {
    let mut env = PypiMarkerEnvironment::current();
    if active_extras.is_empty() {
        return evaluate_pypi_marker(marker.trim(), &env).unwrap_or(true);
    }

    active_extras.iter().any(|extra| {
        env.extra.clone_from(extra);
        evaluate_pypi_marker(marker.trim(), &env).unwrap_or(true)
    })
}

pub(crate) fn evaluate_pypi_marker(marker: &str, env: &PypiMarkerEnvironment) -> Option<bool> {
    evaluate_pypi_marker_expression(marker.trim(), env)
}

fn evaluate_pypi_marker_expression(marker: &str, env: &PypiMarkerEnvironment) -> Option<bool> {
    let marker = strip_enclosing_marker_parentheses(marker.trim());

    let or_parts = split_marker_keyword(marker, "or");
    if or_parts.len() > 1 {
        let mut saw_unknown_true_path = false;

        for part in or_parts {
            match evaluate_pypi_marker_expression(part, env) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => saw_unknown_true_path = true,
            }
        }

        return if saw_unknown_true_path {
            None
        } else {
            Some(false)
        };
    }

    let and_parts = split_marker_keyword(marker, "and");
    if and_parts.len() > 1 {
        let mut group_unknown = false;

        for part in and_parts {
            match evaluate_pypi_marker_expression(part, env) {
                Some(true) => {}
                Some(false) => return Some(false),
                None => group_unknown = true,
            }
        }

        return if group_unknown { None } else { Some(true) };
    }

    evaluate_pypi_marker_atom(marker, env)
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
    let mut depth = 0usize;
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

        if quote.is_none() {
            match ch {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }

        if quote.is_none()
            && depth == 0
            && marker[index..].to_ascii_lowercase().starts_with(&separator)
        {
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

fn strip_enclosing_marker_parentheses(mut marker: &str) -> &str {
    loop {
        let trimmed = marker.trim();
        if !marker_has_enclosing_parentheses(trimmed) {
            return trimmed;
        }
        marker = &trimmed[1..trimmed.len() - 1];
    }
}

fn marker_has_enclosing_parentheses(marker: &str) -> bool {
    if !marker.starts_with('(') || !marker.ends_with(')') {
        return false;
    }

    let mut quote = None;
    let mut depth = 0usize;
    for (index, ch) in marker.char_indices() {
        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
            continue;
        }
        if quote.is_some() {
            continue;
        }

        match ch {
            '(' => depth += 1,
            ')' => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
                if depth == 0 && index + ch.len_utf8() != marker.len() {
                    return false;
                }
            }
            _ => {}
        }
    }

    depth == 0
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
