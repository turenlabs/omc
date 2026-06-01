//! pip config edit support: reading, listing, getting, setting, unsetting, and
//! editing pip config (`pip.conf`/`pip.ini`) for the `omc pip config` compat
//! surface (`run_pip_config_edit`, `print_pip_config`, and the section/line helpers).

use crate::*;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) fn print_pip_config(project_dir: &Path, action: PipConfigAction) -> Result<(), OmcRegistryError> {
    match action {
        PipConfigAction::Set {
            assignments,
            location,
        } => {
            write_pip_config_assignments(project_dir, location, &assignments)?;
            return Ok(());
        }
        PipConfigAction::Unset { keys, location } => {
            unset_pip_config_keys(project_dir, location, &keys)?;
            return Ok(());
        }
        PipConfigAction::Get { .. } | PipConfigAction::List { .. } | PipConfigAction::Debug => {}
    }

    let values = pip_config_values(project_dir)?;
    match action {
        PipConfigAction::Get { keys, json } => {
            if json {
                if keys.len() == 1 {
                    let value = pip_config_value_for_key(&values, &keys[0])?;
                    println!("{}", serde_json::to_string_pretty(&value)?);
                } else {
                    let mut selected = BTreeMap::new();
                    for key in keys {
                        selected.insert(key.clone(), pip_config_value_for_key(&values, &key)?);
                    }
                    println!("{}", serde_json::to_string_pretty(&selected)?);
                }
            } else {
                for key in keys {
                    println!("{}", pip_config_value_for_key(&values, &key)?);
                }
            }
        }
        PipConfigAction::List { json } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&values)?);
            } else {
                for (key, value) in values {
                    println!("{key}={}", pip_config_list_value(&key, &value));
                }
            }
        }
        PipConfigAction::Debug => print_pip_config_debug(project_dir, &values)?,
        PipConfigAction::Set { .. } | PipConfigAction::Unset { .. } => unreachable!(),
    }
    Ok(())
}

fn print_pip_config_debug(
    project_dir: &Path,
    values: &BTreeMap<String, String>,
) -> Result<(), OmcRegistryError> {
    print!("{}", pip_config_debug_report(project_dir, values)?);
    Ok(())
}

pub(crate) fn pip_config_debug_report(
    project_dir: &Path,
    values: &BTreeMap<String, String>,
) -> Result<String, OmcRegistryError> {
    let mut output = String::from("env_var:\n");
    let mut env_values = pip_env_values();
    if env_values.is_empty() {
        output.push_str("  <none>\n");
    } else {
        for (key, value) in env_values.drain(..) {
            output.push_str(&format!("  {key}={value}\n"));
        }
    }

    output.push_str("config_file:\n");
    for (label, path) in [
        (
            "global",
            pip_config_write_path(project_dir, PipConfigLocation::Global)?,
        ),
        (
            "user",
            pip_config_write_path(project_dir, PipConfigLocation::User)?,
        ),
        (
            "site",
            pip_config_write_path(project_dir, PipConfigLocation::Site)?,
        ),
        (
            "env",
            pip_config_write_path(project_dir, PipConfigLocation::Auto)?,
        ),
    ] {
        output.push_str(&format!(
            "  {label}: {} ({})",
            path.display(),
            if path.exists() { "exists" } else { "missing" }
        ));
        output.push('\n');
    }

    output.push_str("config_value:\n");
    if values.is_empty() {
        output.push_str("  <none>\n");
    } else {
        for (key, value) in values {
            output.push_str(&format!("  {key}={value}\n"));
        }
    }
    Ok(output)
}

pub(crate) fn pip_config_values(project_dir: &Path) -> Result<BTreeMap<String, String>, OmcRegistryError> {
    let snapshot = read_pip_config_snapshot(project_dir)?;
    let mut values = BTreeMap::from([
        ("global.index-url".to_owned(), snapshot.index_url),
        ("global.no-index".to_owned(), snapshot.no_index.to_string()),
        (
            "global.pre".to_owned(),
            snapshot.allow_prereleases.to_string(),
        ),
    ]);
    if !snapshot.extra_index_urls.is_empty() {
        values.insert(
            "global.extra-index-url".to_owned(),
            snapshot.extra_index_urls.join(" "),
        );
    }
    if !snapshot.find_links.is_empty() {
        values.insert(
            "global.find-links".to_owned(),
            snapshot.find_links.join(" "),
        );
    }
    if let Some(uploaded_prior_to) = snapshot.uploaded_prior_to {
        values.insert("global.uploaded-prior-to".to_owned(), uploaded_prior_to);
    }
    if let Some(value) = pypi_release_control_config_value(&snapshot.release_controls.all_releases)
    {
        values.insert("global.all-releases".to_owned(), value);
    }
    if let Some(value) = pypi_release_control_config_value(&snapshot.release_controls.only_final) {
        values.insert("global.only-final".to_owned(), value);
    }
    if let Some(value) = pip_binary_config_value(snapshot.binary_all, PypiBinaryMode::Source) {
        values.insert("global.no-binary".to_owned(), value);
    }
    if let Some(value) = pip_binary_config_value(snapshot.binary_all, PypiBinaryMode::Binary) {
        values.insert("global.only-binary".to_owned(), value);
    }
    for (package, mode) in snapshot.binary_packages {
        match mode {
            PypiBinaryMode::Source => values
                .entry("global.no-binary".to_owned())
                .and_modify(|value| {
                    if !value.is_empty() {
                        value.push(',');
                    }
                    value.push_str(&package);
                })
                .or_insert(package),
            PypiBinaryMode::Binary => values
                .entry("global.only-binary".to_owned())
                .and_modify(|value| {
                    if !value.is_empty() {
                        value.push(',');
                    }
                    value.push_str(&package);
                })
                .or_insert(package),
        };
    }
    insert_pip_env_config_values(&mut values);
    Ok(values)
}

fn insert_pip_env_config_values(values: &mut BTreeMap<String, String>) {
    for (env_key, value) in pip_env_values() {
        if let Some(config_key) = pip_env_config_key(&env_key) {
            values.insert(config_key, value);
        }
    }
}

pub(crate) fn pip_env_values() -> Vec<(String, String)> {
    let mut values = Vec::new();
    for (key, value) in env::vars_os() {
        let Some(key) = key.to_str() else {
            continue;
        };
        if !key.starts_with("PIP_") || value.is_empty() {
            continue;
        }
        values.push((key.to_owned(), value.to_string_lossy().to_string()));
    }
    values.sort_by(|(left, _), (right, _)| left.cmp(right));
    values
}

fn pip_env_config_key(env_key: &str) -> Option<String> {
    env_key
        .strip_prefix("PIP_")
        .filter(|suffix| !suffix.is_empty())
        .map(|suffix| format!(":env:.{}", suffix.to_ascii_lowercase().replace('_', "-")))
}

pub(crate) fn pip_config_list_value(key: &str, value: &str) -> String {
    if key.starts_with(":env:") {
        format!("'{value}'")
    } else {
        value.to_owned()
    }
}

fn pypi_release_control_config_value(control: &PypiReleaseControl) -> Option<String> {
    let mut values = Vec::new();
    if control.all {
        values.push(":all:".to_owned());
    }
    values.extend(control.packages.iter().cloned());
    (!values.is_empty()).then(|| values.join(","))
}

fn pip_binary_config_value(mode: Option<PypiBinaryMode>, target: PypiBinaryMode) -> Option<String> {
    (mode == Some(target)).then(|| ":all:".to_owned())
}

pub(crate) fn pip_config_value_for_key(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<String, OmcRegistryError> {
    pip_config_key_aliases(key)
        .into_iter()
        .find_map(|key| values.get(&key).cloned())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("pip config key `{key}` is not set"))
        })
}

fn pip_config_key_aliases(key: &str) -> Vec<String> {
    let normalized = key.trim().to_ascii_lowercase().replace('_', "-");
    if let Some((section, name)) = normalized.split_once('.') {
        if matches!(section, "global" | "install") {
            return vec![normalized.clone(), format!("global.{name}")];
        }
        return vec![normalized];
    }
    vec![
        format!("global.{normalized}"),
        format!("install.{normalized}"),
    ]
}

fn write_pip_config_assignments(
    project_dir: &Path,
    location: PipConfigLocation,
    assignments: &[(String, String)],
) -> Result<(), OmcRegistryError> {
    let path = pip_config_write_path(project_dir, location)?;
    let mut lines = read_pip_config_lines(&path)?;
    for (key, value) in assignments {
        let (section, key) = normalize_pip_config_key(key)?;
        upsert_pip_config_line(&mut lines, &section, &key, value);
    }
    write_pip_config_lines(&path, &lines)
}

fn unset_pip_config_keys(
    project_dir: &Path,
    location: PipConfigLocation,
    keys: &[String],
) -> Result<(), OmcRegistryError> {
    let path = pip_config_write_path(project_dir, location)?;
    let mut lines = read_pip_config_lines(&path)?;
    for key in keys {
        for (section, key) in pip_config_unset_targets(key)? {
            remove_pip_config_line(&mut lines, &section, &key);
        }
    }
    write_pip_config_lines(&path, &lines)
}

pub(crate) fn run_pip_config_edit(
    project_dir: &Path,
    invocation_cwd: &Path,
    location: PipConfigLocation,
    editor: Option<String>,
) -> Result<ExitCode, OmcRegistryError> {
    let path = pip_config_write_path(project_dir, location)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        fs::write(&path, "")?;
    }

    let editor = pip_config_editor(editor);
    let mut command = package_script_command(&editor);
    command.current_dir(invocation_cwd).arg(&path);
    let status = command.status()?;
    Ok(exit_code(status.code()))
}

fn pip_config_editor(editor: Option<String>) -> String {
    editor
        .or_else(|| env::var("VISUAL").ok())
        .or_else(|| env::var("EDITOR").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "vi".to_owned())
}

pub(crate) fn pip_config_write_path(
    project_dir: &Path,
    location: PipConfigLocation,
) -> Result<PathBuf, OmcRegistryError> {
    match location {
        PipConfigLocation::Auto => {
            Ok(pip_config_file_override(project_dir)
                .unwrap_or_else(|| project_dir.join("pip.conf")))
        }
        PipConfigLocation::Site => Ok(project_dir.join("pip.conf")),
        PipConfigLocation::User => Ok(pip_user_config_path(project_dir)),
        PipConfigLocation::Global => Ok(pip_global_config_path(project_dir)),
    }
}

fn pip_config_file_override(project_dir: &Path) -> Option<PathBuf> {
    env::var_os("PIP_CONFIG_FILE")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| absolutize_path(project_dir, path))
}

fn pip_user_config_path(project_dir: &Path) -> PathBuf {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return path.join("pip").join("pip.conf");
    }
    if let Some(home) = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return home.join(".config").join("pip").join("pip.conf");
    }
    project_dir.join("pip.conf")
}

fn pip_global_config_path(project_dir: &Path) -> PathBuf {
    if let Some(path) = pip_config_file_override(project_dir) {
        return path;
    }
    #[cfg(test)]
    if let Some(path) = env::var_os("OMC_TEST_PIP_GLOBAL_CONFIG_FILE")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return absolutize_path(project_dir, path);
    }
    pip_global_config_default_path(project_dir)
}

#[cfg(target_os = "macos")]
pub(crate) fn pip_global_config_default_path(_project_dir: &Path) -> PathBuf {
    PathBuf::from("/Library/Application Support/pip/pip.conf")
}

#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn pip_global_config_default_path(_project_dir: &Path) -> PathBuf {
    PathBuf::from("/etc/pip.conf")
}

#[cfg(windows)]
pub(crate) fn pip_global_config_default_path(project_dir: &Path) -> PathBuf {
    env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join("pip").join("pip.ini"))
        .unwrap_or_else(|| project_dir.join("pip.ini"))
}

fn read_pip_config_lines(path: &Path) -> Result<Vec<String>, OmcRegistryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::to_owned)
        .collect())
}

fn write_pip_config_lines(path: &Path, lines: &[String]) -> Result<(), OmcRegistryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

fn normalize_pip_config_key(key: &str) -> Result<(String, String), OmcRegistryError> {
    let normalized = key.trim().to_ascii_lowercase().replace('_', "-");
    let (section, key) = normalized
        .split_once('.')
        .map(|(section, key)| (section.trim(), key.trim()))
        .unwrap_or(("global", normalized.trim()));
    if section.is_empty() || key.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid pip config key `{key}`"
        )));
    }
    Ok((section.to_owned(), key.to_owned()))
}

fn pip_config_unset_targets(key: &str) -> Result<Vec<(String, String)>, OmcRegistryError> {
    let normalized = key.trim().to_ascii_lowercase().replace('_', "-");
    if normalized.contains('.') {
        return normalize_pip_config_key(&normalized).map(|target| vec![target]);
    }
    if normalized.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config key cannot be empty".to_owned(),
        ));
    }
    Ok(vec![
        ("global".to_owned(), normalized.clone()),
        ("install".to_owned(), normalized),
    ])
}

fn upsert_pip_config_line(lines: &mut Vec<String>, section: &str, key: &str, value: &str) {
    if let Some((start, end)) = pip_config_section_range(lines, section) {
        if let Some(line) = lines[start..end]
            .iter_mut()
            .find(|line| pip_config_line_key_matches(line, key))
        {
            *line = format!("{key} = {value}");
            return;
        }
        let insert_at = pip_config_section_insert_index(lines, start, end);
        lines.insert(insert_at, format!("{key} = {value}"));
        return;
    }

    if !lines.is_empty() && lines.last().is_some_and(|line| !line.trim().is_empty()) {
        lines.push(String::new());
    }
    lines.push(format!("[{section}]"));
    lines.push(format!("{key} = {value}"));
}

fn remove_pip_config_line(lines: &mut Vec<String>, section: &str, key: &str) {
    let Some((start, end)) = pip_config_section_range(lines, section) else {
        return;
    };
    let mut index = start;
    while index < end && index < lines.len() {
        if pip_config_line_key_matches(&lines[index], key) {
            lines.remove(index);
        } else {
            index += 1;
        }
    }
}

fn pip_config_section_insert_index(lines: &[String], start: usize, end: usize) -> usize {
    let mut index = end;
    while index > start && lines[index - 1].trim().is_empty() {
        index -= 1;
    }
    index
}

fn pip_config_section_range(lines: &[String], section: &str) -> Option<(usize, usize)> {
    let mut start = None;
    for (index, line) in lines.iter().enumerate() {
        let Some(found) = pip_config_section_name(line) else {
            continue;
        };
        if let Some(start) = start {
            return Some((start, index));
        }
        if found == section {
            start = Some(index + 1);
        }
    }
    start.map(|start| (start, lines.len()))
}

fn pip_config_section_name(line: &str) -> Option<String> {
    let line = strip_pip_config_comment(line).trim();
    line.strip_prefix('[')
        .and_then(|line| line.strip_suffix(']'))
        .map(str::trim)
        .filter(|section| !section.is_empty())
        .map(|section| section.to_ascii_lowercase())
}

fn pip_config_line_key_matches(line: &str, key: &str) -> bool {
    let line = strip_pip_config_comment(line).trim();
    let Some((found, _)) = line.split_once('=') else {
        return false;
    };
    found.trim().to_ascii_lowercase().replace('_', "-") == key
}

pub(crate) fn strip_pip_config_comment(line: &str) -> &str {
    strip_npm_config_comment(line)
}
