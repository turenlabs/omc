//! PyPI `requirements.txt` parsing: logical-line folding, comment/env-var
//! handling, per-line option parsing (`--hash`, `--editable`, index/find-links
//! directives), and the recursive requirements-file reader that turns a
//! `requirements.txt` / constraint file into a [`ProjectRequirements`].
//!
//! Extracted verbatim from the monolithic `lib.rs`. The resolution and install
//! orchestration that drives these parsers still lives at the crate root.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::*;

use crate::pypi_resolve::{
    normalize_requirements_editable_path, parse_pypi_direct_archive_url_reference,
    parse_pypi_direct_requirement, parse_pypi_local_archive_requirement,
    parse_pypi_local_direct_path_requirement, parse_pypi_local_direct_requirement,
    parse_pypi_local_path_requirement, parse_pypi_requirement, parse_pypi_vcs_direct_requirement,
    parse_requirements_all_releases, parse_requirements_allow_prereleases,
    parse_requirements_bare_vcs_requirement, parse_requirements_binary_option,
    parse_requirements_compatible_global_option, parse_requirements_editable_value,
    parse_requirements_editable_vcs_requirement, parse_requirements_extra_index_url,
    parse_requirements_find_links, parse_requirements_include, parse_requirements_index_url,
    parse_requirements_no_deps, parse_requirements_no_index, parse_requirements_only_final,
    parse_requirements_require_hashes, parse_requirements_uploaded_prior_to,
    pypi_direct_file_url_local_directory, pypi_direct_reference_applies,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RequirementsMode {
    Install,
    Constraint,
}

#[derive(Debug, Clone)]
pub(crate) struct RequirementsInclude {
    pub(crate) path: String,
    pub(crate) mode: RequirementsMode,
}

pub(crate) fn read_requirements_file_inner(
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

pub(crate) fn requirement_logical_lines(content: &str) -> Vec<String> {
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
pub(crate) struct ParsedRequirementLine {
    pub(crate) requirement: String,
    pub(crate) hashes: BTreeSet<String>,
}

pub(crate) fn parse_requirement_line(line: &str) -> ParsedRequirementLine {
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

pub(crate) fn shell_like_tokens(value: &str) -> Vec<String> {
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

pub(crate) fn normalize_sha256_hash(value: &str) -> Option<String> {
    let hash = value.strip_prefix("sha256:")?.to_ascii_lowercase();
    (hash.len() == 64 && hash.chars().all(|ch| ch.is_ascii_hexdigit())).then_some(hash)
}

pub(crate) fn enforce_requirements_hashes(requirements: &ProjectRequirements) -> Result<()> {
    enforce_pypi_hashes_for_specs(
        &requirements.specs,
        &requirements.hashes,
        &requirements.constraints,
    )
}

pub(crate) fn enforce_pypi_hashes_for_specs(
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
