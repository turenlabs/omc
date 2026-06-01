//! npm config edit support: editing and writing `.npmrc`-style config files
//! (`run_npm_config_*` and the line read/write/upsert helpers).

use crate::*;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) fn run_npm_config_edit(
    project_dir: &Path,
    invocation_cwd: &Path,
    userconfig: Option<&Path>,
    globalconfig: Option<&Path>,
    location: NpmConfigLocation,
    editor: Option<String>,
) -> Result<ExitCode, OmcRegistryError> {
    let path = npm_config_write_path(project_dir, userconfig, globalconfig, location);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        fs::write(&path, "")?;
    }

    let editor = npm_config_editor(editor);
    let mut command = package_script_command(&editor);
    command.current_dir(invocation_cwd).arg(&path);
    let status = command.status()?;
    Ok(exit_code(status.code()))
}

pub(crate) fn npm_config_editor(editor: Option<String>) -> String {
    editor
        .or_else(|| env::var("VISUAL").ok())
        .or_else(|| env::var("EDITOR").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "vi".to_owned())
}

pub(crate) fn npm_config_write_path(
    project_dir: &Path,
    userconfig: Option<&Path>,
    globalconfig: Option<&Path>,
    location: NpmConfigLocation,
) -> PathBuf {
    match location {
        NpmConfigLocation::User => npm_userconfig_path(project_dir, userconfig),
        NpmConfigLocation::Project => project_dir.join(".npmrc"),
        NpmConfigLocation::Global => npm_globalconfig_path(project_dir, globalconfig),
    }
}

pub(crate) fn read_npm_config_lines(path: &Path) -> Result<Vec<String>, OmcRegistryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    // batou:ignore file_read -- CLI tool intentionally reads the user-selected .npmrc config path (npm config edit); code moved verbatim from lib.rs
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::to_owned)
        .collect())
}

pub(crate) fn write_npm_config_lines(
    path: &Path,
    lines: &[String],
) -> Result<(), OmcRegistryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    // batou:ignore file_write -- CLI tool intentionally writes the user-selected .npmrc config path (npm config edit); code moved verbatim from lib.rs
    fs::write(path, content)?;
    Ok(())
}

pub(crate) fn upsert_npm_config_line(lines: &mut Vec<String>, key: &str, value: &str) {
    if let Some(line) = lines
        .iter_mut()
        .find(|line| npm_config_line_key(line).is_some_and(|existing| existing == key))
    {
        *line = format!("{key}={value}");
        return;
    }
    lines.push(format!("{key}={value}"));
}

pub(crate) fn npm_config_line_key(line: &str) -> Option<&str> {
    let line = strip_npm_config_comment(line).trim();
    if line.is_empty() {
        return None;
    }
    line.split_once('=')
        .map(|(key, _)| key.trim())
        .filter(|key| !key.is_empty())
}

pub(crate) fn strip_npm_config_comment(line: &str) -> &str {
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
