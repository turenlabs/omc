//! `.npmrc` parsing + registry URL resolution.

use crate::*;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct NpmConfig {
    pub(crate) registry: String,
    pub(crate) scoped_registries: BTreeMap<String, String>,
    pub(crate) auth_tokens: Vec<NpmAuthToken>,
}

#[derive(Debug, Clone)]
pub(crate) struct NpmAuthToken {
    pub(crate) scope: String,
    pub(crate) token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmConfigSnapshot {
    pub registry: String,
    pub scoped_registries: BTreeMap<String, String>,
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            registry: "https://registry.npmjs.org/".to_owned(),
            scoped_registries: BTreeMap::new(),
            auth_tokens: Vec::new(),
        }
    }
}

impl NpmConfig {
    pub(crate) fn registry_for(&self, package: &str) -> &str {
        let Some((scope, _)) = package.split_once('/') else {
            return &self.registry;
        };
        self.scoped_registries
            .get(scope)
            .map(String::as_str)
            .unwrap_or(&self.registry)
    }

    pub(crate) fn auth_token_for_url(&self, url: &str) -> Option<&str> {
        let url = reqwest::Url::parse(url).ok()?;
        let host = url.host_str()?;
        let authority = url
            .port()
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned());
        let target = format!("{authority}{}", url.path());
        self.auth_tokens
            .iter()
            .filter(|token| target.starts_with(&token.scope))
            .max_by_key(|token| token.scope.len())
            .map(|token| token.token.as_str())
    }
}

pub(crate) fn read_npm_config(project_dir: &Path) -> Result<NpmConfig> {
    read_npm_config_with_overrides(project_dir, None, None)
}

pub(crate) fn read_npm_config_with_overrides(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmConfig> {
    read_npm_config_with_config_paths(project_dir, registry_override, userconfig_override, None)
}

fn read_npm_config_with_config_paths(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    globalconfig_override: Option<&Path>,
) -> Result<NpmConfig> {
    let mut config = NpmConfig::default();
    read_npm_global_config(project_dir, globalconfig_override, &mut config)?;
    let user_config = userconfig_override
        .map(Path::to_path_buf)
        .or_else(npm_userconfig_env_path);
    read_npm_user_config(project_dir, user_config.as_deref(), &mut config)?;
    read_npmrc_into(&project_dir.join(".npmrc"), &mut config)?;
    apply_npm_environment_config(&mut config);
    if let Some(registry) = registry_override {
        config.registry = normalize_npm_registry(registry).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("invalid npm registry `{registry}`"))
        })?;
    }
    Ok(config)
}

pub fn read_npm_config_snapshot(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmConfigSnapshot> {
    read_npm_config_snapshot_with_globalconfig(
        project_dir,
        registry_override,
        userconfig_override,
        None,
    )
}

pub fn read_npm_config_snapshot_with_globalconfig(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    globalconfig_override: Option<&Path>,
) -> Result<NpmConfigSnapshot> {
    let config = read_npm_config_with_config_paths(
        project_dir,
        registry_override,
        userconfig_override,
        globalconfig_override,
    )?;
    Ok(NpmConfigSnapshot {
        registry: config.registry,
        scoped_registries: config.scoped_registries,
    })
}

pub(crate) fn read_npm_config_for_options(
    project_dir: &Path,
    options: &LinkOptions,
) -> Result<NpmConfig> {
    read_npm_config_with_overrides(project_dir, options.npm_registry_url.as_deref(), None)
}

fn apply_npm_environment_config(config: &mut NpmConfig) {
    let registry = env::var("npm_config_registry")
        .ok()
        .or_else(|| env::var("NPM_CONFIG_REGISTRY").ok());
    apply_npm_environment_values(config, registry.as_deref());
}

pub(crate) fn apply_npm_environment_values(config: &mut NpmConfig, registry: Option<&str>) {
    if let Some(registry) = registry.and_then(normalize_npm_registry) {
        config.registry = registry;
    }
}

fn npm_userconfig_env_path() -> Option<PathBuf> {
    env::var_os("npm_config_userconfig")
        .or_else(|| env::var_os("NPM_CONFIG_USERCONFIG"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn npm_globalconfig_env_path() -> Option<PathBuf> {
    env::var_os("npm_config_globalconfig")
        .or_else(|| env::var_os("NPM_CONFIG_GLOBALCONFIG"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn read_npm_global_config(
    project_dir: &Path,
    global_config: Option<&Path>,
    config: &mut NpmConfig,
) -> Result<()> {
    let path = global_config
        .map(Path::to_path_buf)
        .or_else(npm_globalconfig_env_path)
        .map(|path| resolve_npm_config_path(project_dir, &path))
        .unwrap_or_else(npm_globalconfig_default_path);
    read_npmrc_into(&path, config)
}

pub(crate) fn read_npm_user_config(
    project_dir: &Path,
    user_config: Option<&Path>,
    config: &mut NpmConfig,
) -> Result<()> {
    if let Some(user_config) = user_config {
        return read_npmrc_into(&resolve_npm_config_path(project_dir, user_config), config);
    }
    if let Some(home) = env::var_os("HOME") {
        read_npmrc_into(&PathBuf::from(home).join(".npmrc"), config)?;
    }
    Ok(())
}

fn resolve_npm_config_path(project_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_dir.join(path)
    }
}

fn npm_globalconfig_default_path() -> PathBuf {
    npm_global_prefix_path().join("etc").join("npmrc")
}

fn npm_global_prefix_path() -> PathBuf {
    if let Some(prefix) = env::var_os("npm_config_prefix")
        .or_else(|| env::var_os("NPM_CONFIG_PREFIX"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return prefix;
    }
    npm_default_global_prefix_path()
}

#[cfg(target_os = "macos")]
fn npm_default_global_prefix_path() -> PathBuf {
    let homebrew = PathBuf::from("/opt/homebrew");
    if homebrew.exists() {
        homebrew
    } else {
        PathBuf::from("/usr/local")
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn npm_default_global_prefix_path() -> PathBuf {
    PathBuf::from("/usr/local")
}

#[cfg(windows)]
fn npm_default_global_prefix_path() -> PathBuf {
    env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join("npm"))
        .unwrap_or_else(|| PathBuf::from("npm"))
}

pub(crate) fn read_npmrc_into(path: &Path, config: &mut NpmConfig) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    // batou:ignore file_read -- reads npm's own .npmrc config files from standard project/home/global config locations (npm config resolution), not attacker-supplied web input; verbatim code-movement refactor, behavior unchanged from lib.rs
    parse_npmrc_content(&fs::read_to_string(path)?, config);
    Ok(())
}

pub(crate) fn parse_npmrc_content(content: &str, config: &mut NpmConfig) {
    for raw_line in content.lines() {
        let line = strip_npmrc_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Some(value) = expand_npmrc_value(value.trim()) else {
            continue;
        };

        if key == "registry" {
            if let Some(registry) = normalize_npm_registry(&value) {
                config.registry = registry;
            }
        } else if key.starts_with('@') && key.ends_with(":registry") {
            if let Some(registry) = normalize_npm_registry(&value) {
                let scope = key.trim_end_matches(":registry").to_owned();
                config.scoped_registries.insert(scope, registry);
            }
        } else if key.starts_with("//") && key.ends_with(":_authToken") {
            let scope = key
                .trim_start_matches("//")
                .trim_end_matches(":_authToken")
                .trim_start_matches('/')
                .to_owned();
            if !scope.is_empty() && !value.is_empty() {
                config.auth_tokens.push(NpmAuthToken {
                    scope: ensure_trailing_slash(&scope),
                    token: value,
                });
            }
        }
    }
}

pub(crate) fn strip_npmrc_comment(line: &str) -> &str {
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

pub(crate) fn normalize_npm_registry(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(ensure_trailing_slash(value))
    }
}

pub(crate) fn ensure_trailing_slash(value: &str) -> String {
    if value.ends_with('/') {
        value.to_owned()
    } else {
        format!("{value}/")
    }
}

fn expand_npmrc_value(value: &str) -> Option<String> {
    let mut expanded = String::new();
    let mut rest = value.trim().trim_matches('"');
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let end = after_start.find('}')?;
        let key = &after_start[..end];
        expanded.push_str(&env::var(key).ok()?);
        rest = &after_start[end + 1..];
    }
    expanded.push_str(rest);
    Some(expanded)
}

pub(crate) fn npm_registry_package_url(registry: &str, encoded: &str) -> String {
    format!("{}{}", ensure_trailing_slash(registry), encoded)
}

pub(crate) fn npm_registry_package_version_url(registry: &str, encoded: &str, version: &str) -> String {
    format!("{}{encoded}/{version}", ensure_trailing_slash(registry))
}
