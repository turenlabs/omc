//! Python source-file parsing: `pyproject.toml`, `setup.cfg`, `setup.py`, and
//! `Pipfile`/`Pipfile.lock`.
//!
//! Reads project requirements out of Python packaging source files and the
//! small hand-rolled Python literal scanner used to extract `install_requires`
//! and `extras_require` values from `setup.py`. Also hosts the
//! `push_python_local_*` helpers that record local-path requirements on a
//! `ProjectRequirements`. Pure code movement out of `lib.rs`; behaviour is
//! unchanged.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::pipfile::{
    collect_pipfile_lock_sources, collect_pipfile_locked_packages, collect_pipfile_packages,
    collect_pipfile_sources, Pipfile, PipfileLock, PipfileScripts,
};
use crate::uv_lock::uv_local_source_map_with_workspace;

pub(crate) fn read_python_source_requirements(
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

pub(crate) fn read_pipfile_lock_requirements(
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

pub(crate) fn read_pipfile_requirements(
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

pub(crate) fn read_pipfile_scripts(path: &Path) -> Result<BTreeMap<String, String>> {
    Ok(toml::from_str::<PipfileScripts>(&fs::read_to_string(path)?)?.scripts)
}

pub(crate) fn push_python_local_path(requirements: &mut ProjectRequirements, path: PathBuf) {
    if !requirements.python_local_paths.contains(&path) {
        requirements.python_local_paths.push(path);
    }
}

pub(crate) fn push_python_local_requirement(
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

pub(crate) fn push_python_local_directory_requirement(
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

pub(crate) fn read_setup_cfg_requirements(
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

pub(crate) fn parse_setup_cfg_sections(
    content: &str,
) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
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

pub(crate) fn read_setup_py_requirements(
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

pub(crate) fn root_python_project_has_metadata(project_dir: &Path) -> Result<bool> {
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

pub(crate) fn python_keyword_assignment_values<'a>(
    content: &'a str,
    keyword: &str,
) -> Vec<&'a str> {
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

pub(crate) fn python_string_dict_values(
    content: &str,
    selected_keys: &BTreeSet<String>,
) -> Vec<String> {
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

pub(crate) fn read_pyproject_requirements(
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
