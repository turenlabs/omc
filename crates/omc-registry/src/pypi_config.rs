use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PipConfig {
    pub(crate) index_url: Option<String>,
    pub(crate) extra_index_urls: Vec<String>,
    pub(crate) find_links: Vec<String>,
    pub(crate) requirement_files: Vec<PathBuf>,
    pub(crate) constraint_files: Vec<PathBuf>,
    pub(crate) binary_all: Option<PypiBinaryMode>,
    pub(crate) binary_packages: BTreeMap<String, PypiBinaryMode>,
    pub(crate) no_index: bool,
    pub(crate) allow_prereleases: bool,
    pub(crate) release_controls: PypiReleaseControls,
    pub(crate) uploaded_prior_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipConfigSnapshot {
    pub index_url: String,
    pub extra_index_urls: Vec<String>,
    pub find_links: Vec<String>,
    pub binary_all: Option<PypiBinaryMode>,
    pub binary_packages: BTreeMap<String, PypiBinaryMode>,
    pub no_index: bool,
    pub allow_prereleases: bool,
    pub release_controls: PypiReleaseControls,
    pub uploaded_prior_to: Option<String>,
}

pub(crate) fn apply_pip_config_files(project_dir: &Path, options: &mut LinkOptions) -> Result<()> {
    let config = read_pip_config(project_dir)?;
    if options.pypi_index_url.is_none() {
        options.pypi_index_url = config.index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(config.extra_index_urls);
    options.pypi_find_links.extend(config.find_links);
    options.requirement_files.extend(config.requirement_files);
    options.constraint_files.extend(config.constraint_files);
    if config.binary_all.is_some() {
        options.pypi_binary_all = config.binary_all;
    }
    options.pypi_binary_packages.extend(config.binary_packages);
    options.pypi_no_index |= config.no_index;
    options.pypi_allow_prereleases |= config.allow_prereleases;
    merge_pypi_release_controls(&mut options.pypi_release_controls, config.release_controls);
    if config.uploaded_prior_to.is_some() {
        options.pypi_uploaded_prior_to = config.uploaded_prior_to;
    }
    dedupe_pypi_find_links(options);
    dedupe_pypi_extra_index_urls(options);
    dedupe_paths(&mut options.requirement_files);
    dedupe_paths(&mut options.constraint_files);
    Ok(())
}

pub(crate) fn read_pip_config(project_dir: &Path) -> Result<PipConfig> {
    let mut config = PipConfig::default();
    read_pip_config_into(&pip_global_config_path(), &mut config)?;
    if let Some(home) = env::var_os("HOME") {
        let home = PathBuf::from(home);
        read_pip_config_into(&home.join(".pip").join("pip.conf"), &mut config)?;
        read_pip_config_into(
            &home.join(".config").join("pip").join("pip.conf"),
            &mut config,
        )?;
    }
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        read_pip_config_into(
            &PathBuf::from(xdg).join("pip").join("pip.conf"),
            &mut config,
        )?;
    }
    read_pip_config_into(&project_dir.join("pip.conf"), &mut config)?;
    if let Some(path) = env::var_os("PIP_CONFIG_FILE") {
        read_pip_config_into(
            &resolve_pip_config_file_path(project_dir, PathBuf::from(path)),
            &mut config,
        )?;
    }
    Ok(config)
}

fn resolve_pip_config_file_path(project_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        project_dir.join(path)
    }
}

#[cfg(target_os = "macos")]
fn pip_global_config_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/pip/pip.conf")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn pip_global_config_path() -> PathBuf {
    PathBuf::from("/etc/pip.conf")
}

#[cfg(windows)]
fn pip_global_config_path() -> PathBuf {
    env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join("pip").join("pip.ini"))
        .unwrap_or_else(|| PathBuf::from("pip.ini"))
}

pub fn read_pip_config_snapshot(project_dir: &Path) -> Result<PipConfigSnapshot> {
    let config = read_pip_config(project_dir)?;
    let mut options = LinkOptions::new(project_dir);
    options.pypi_index_url = config.index_url;
    options
        .pypi_extra_index_urls
        .extend(config.extra_index_urls);
    options.pypi_find_links.extend(config.find_links);
    options.pypi_binary_all = config.binary_all;
    options.pypi_binary_packages = config.binary_packages;
    options.pypi_no_index = config.no_index;
    options.pypi_allow_prereleases = config.allow_prereleases;
    options.pypi_release_controls = config.release_controls;
    options.pypi_uploaded_prior_to = config.uploaded_prior_to;
    apply_pypi_environment_config(&mut options, true);
    Ok(PipConfigSnapshot {
        index_url: options
            .pypi_index_url
            .unwrap_or_else(|| "https://pypi.org/simple/".to_owned()),
        extra_index_urls: options.pypi_extra_index_urls,
        find_links: options.pypi_find_links,
        binary_all: options.pypi_binary_all,
        binary_packages: options.pypi_binary_packages,
        no_index: options.pypi_no_index,
        allow_prereleases: options.pypi_allow_prereleases,
        release_controls: options.pypi_release_controls,
        uploaded_prior_to: options.pypi_uploaded_prior_to,
    })
}

fn read_pip_config_into(path: &Path, config: &mut PipConfig) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    parse_pip_config_content(&fs::read_to_string(path)?, base_dir, config);
    Ok(())
}

pub(crate) fn parse_pip_config_content(content: &str, base_dir: &Path, config: &mut PipConfig) {
    let mut section = String::new();
    let mut multiline_key: Option<String> = None;
    for raw_line in content.lines() {
        let line = strip_npmrc_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_ascii_lowercase();
            multiline_key = None;
            continue;
        }
        let indented = raw_line
            .chars()
            .next()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if indented && multiline_key.is_some() && !trimmed.contains('=') {
            if let Some(key) = multiline_key.as_deref() {
                apply_pip_config_value(&section, key, trimmed, base_dir, config);
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            multiline_key = None;
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        apply_pip_config_value(&section, &key, value, base_dir, config);
        multiline_key = value.is_empty().then_some(key);
    }
}

fn apply_pip_config_value(
    section: &str,
    key: &str,
    value: &str,
    base_dir: &Path,
    config: &mut PipConfig,
) {
    if !matches!(section, "global" | "install") {
        return;
    }
    match key {
        "index-url" => {
            if let Some(index_url) = normalize_pypi_simple_index_url(value) {
                config.index_url = Some(index_url);
            }
        }
        "extra-index-url" => {
            config.extra_index_urls.extend(
                pypi_index_url_values(value)
                    .into_iter()
                    .filter_map(|index_url| normalize_pypi_simple_index_url(&index_url)),
            );
        }
        "find-links" => {
            config.find_links.extend(
                pypi_index_url_values(value)
                    .into_iter()
                    .filter_map(|find_links| {
                        normalize_pypi_find_links_source(&find_links, base_dir)
                    }),
            );
        }
        "requirement" => {
            config
                .requirement_files
                .extend(pypi_path_values(value, base_dir));
        }
        "constraint" => {
            config
                .constraint_files
                .extend(pypi_path_values(value, base_dir));
        }
        "no-index" => {
            config.no_index |= pip_config_bool(value);
        }
        "pre" => {
            config.allow_prereleases |= pip_config_bool(value);
        }
        "all-releases" => {
            apply_pypi_release_control(&mut config.release_controls.all_releases, value);
        }
        "only-final" => {
            apply_pypi_release_control(&mut config.release_controls.only_final, value);
        }
        "uploaded-prior-to" => {
            if !value.trim().is_empty() {
                config.uploaded_prior_to = Some(value.trim().to_owned());
            }
        }
        "no-binary" => {
            apply_pypi_binary_option(
                &mut config.binary_all,
                &mut config.binary_packages,
                PypiBinaryMode::Source,
                value,
            );
        }
        "only-binary" => {
            apply_pypi_binary_option(
                &mut config.binary_all,
                &mut config.binary_packages,
                PypiBinaryMode::Binary,
                value,
            );
        }
        _ => {}
    }
    let mut seen = BTreeSet::new();
    config
        .extra_index_urls
        .retain(|index_url| seen.insert(index_url.clone()));
    let mut seen = BTreeSet::new();
    config
        .find_links
        .retain(|find_links| seen.insert(find_links.clone()));
    dedupe_paths(&mut config.requirement_files);
    dedupe_paths(&mut config.constraint_files);
}

pub(crate) fn pypi_index_url_values(value: &str) -> Vec<String> {
    shell_like_tokens(value)
}

pub(crate) fn pypi_path_values(value: &str, base_dir: &Path) -> Vec<PathBuf> {
    shell_like_tokens(value)
        .into_iter()
        .map(|path| resolve_manifest_path(base_dir, &path))
        .collect()
}

fn pip_config_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "on"
    )
}

pub(crate) fn env_truthy(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| pip_config_bool(&value))
        .unwrap_or(false)
}

pub(crate) fn dedupe_pypi_extra_index_urls(options: &mut LinkOptions) {
    let mut seen = BTreeSet::new();
    options
        .pypi_extra_index_urls
        .retain(|index_url| seen.insert(index_url.clone()));
}
