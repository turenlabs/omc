//! pip-compat argument/file parsing: `parse_pip_*` / `expand_pip_*` argument
//! parsers, their flag helpers, and the pip-local path/archive argument
//! classifiers. Extracted from pip_cli.rs (module split).

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use omc_registry::{OmcRegistryError, PypiBinaryMode, PypiReleaseControls, PythonLocalRequirement};

pub(crate) fn parse_pip_help_request(args: &[String]) -> Option<PipCompatAction> {
    let command = args.first()?;
    if pip_help_flag(command) {
        return Some(PipCompatAction::Help { topic: None });
    }
    if command == "help" {
        let topic = args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned();
        return Some(PipCompatAction::Help { topic });
    }
    if args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| pip_help_flag(arg))
    {
        return Some(PipCompatAction::Help {
            topic: Some(command.clone()),
        });
    }
    None
}

pub(crate) fn pip_help_flag(arg: &str) -> bool {
    matches!(arg, "--help" | "-h")
}

pub(crate) fn parse_pip_completion_args(
    args: &[String],
) -> Result<PipCompatAction, OmcRegistryError> {
    let mut shell = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--bash" {
            shell = Some(PipCompletionShell::Bash);
        } else if arg == "--zsh" {
            shell = Some(PipCompletionShell::Zsh);
        } else if arg == "--fish" {
            shell = Some(PipCompletionShell::Fish);
        } else if matches!(
            arg.as_str(),
            "--disable-pip-version-check" | "--no-color" | "--no-input" | "--isolated"
        ) {
        } else if matches!(
            arg.as_str(),
            "--log" | "--proxy" | "--retries" | "--timeout"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_completion_ignored_equals_flag(arg) {
        } else {
            return Err(unsupported_compat_arg("pip completion", arg));
        }
        index += 1;
    }
    Ok(PipCompatAction::Completion { shell })
}

pub(crate) fn pip_completion_ignored_equals_flag(arg: &str) -> bool {
    ["--log=", "--proxy=", "--retries=", "--timeout="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn normalize_pip_global_args(args: &[String]) -> Result<Vec<String>, OmcRegistryError> {
    let mut cache_dir_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--version" | "-V") {
            return Ok(vec![arg.clone()]);
        } else if arg == "--cache-dir" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--cache-dir needs a path".to_owned(),
                ));
            };
            cache_dir_args.push(arg.clone());
            cache_dir_args.push(value.clone());
        } else if arg.starts_with("--cache-dir=") {
            cache_dir_args.push(arg.clone());
        } else if pip_global_ignored_bool_flag(arg) || pip_global_ignored_equals_flag(arg) {
        } else if pip_global_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with('-') {
            return Ok(args[index..].to_vec());
        } else if index == 0 {
            return Ok(args.to_vec());
        } else if arg == "cache" && !cache_dir_args.is_empty() {
            let mut normalized = Vec::with_capacity(args.len());
            normalized.push(arg.clone());
            normalized.extend(cache_dir_args);
            normalized.extend(args[index + 1..].iter().cloned());
            return Ok(normalized);
        } else {
            return Ok(args[index..].to_vec());
        }
        index += 1;
    }
    Ok(Vec::new())
}

pub(crate) fn pip_global_ignored_bool_flag(arg: &str) -> bool {
    pip_ignored_verbosity_flag(arg)
        || matches!(
            arg,
            "--disable-pip-version-check"
                | "--no-cache-dir"
                | "--isolated"
                | "--require-virtualenv"
                | "--no-color"
                | "--no-input"
                | "--no-python-version-warning"
        )
}

pub(crate) fn pip_ignored_verbosity_flag(arg: &str) -> bool {
    matches!(arg, "-q" | "--quiet" | "-v" | "--verbose")
        || pip_repeated_short_flag(arg, 'q')
        || pip_repeated_short_flag(arg, 'v')
}

pub(crate) fn pip_verbose_flag(arg: &str) -> bool {
    matches!(arg, "-v" | "--verbose") || pip_repeated_short_flag(arg, 'v')
}

pub(crate) fn pip_repeated_short_flag(arg: &str, flag: char) -> bool {
    let Some(rest) = arg.strip_prefix('-') else {
        return false;
    };
    rest.len() > 1 && !rest.starts_with('-') && rest.chars().all(|ch| ch == flag)
}

pub(crate) fn pip_global_ignored_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--log"
            | "--proxy"
            | "--retries"
            | "--timeout"
            | "--exists-action"
            | "--trusted-host"
            | "--cert"
            | "--client-cert"
            | "--cache-dir"
            | "--use-feature"
            | "--use-deprecated"
    )
}

pub(crate) fn pip_global_ignored_equals_flag(arg: &str) -> bool {
    [
        "--log=",
        "--proxy=",
        "--retries=",
        "--timeout=",
        "--exists-action=",
        "--trusted-host=",
        "--cert=",
        "--client-cert=",
        "--cache-dir=",
        "--use-feature=",
        "--use-deprecated=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn parse_pip_index_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let PipIndexArgs {
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        allow_prereleases,
        release_controls,
        uploaded_prior_to,
        compatibility,
        json,
        mut positionals,
    } = parse_pip_index_common_args(args)?;
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip index needs a command such as versions".to_owned(),
        ));
    }
    let command = positionals.remove(0);
    match command.as_str() {
        "versions" => {
            if positionals.len() != 1 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip index versions needs exactly one package".to_owned(),
                ));
            }
            Ok(PipCompatAction::IndexVersions {
                package: positionals.remove(0),
                index_url,
                extra_index_urls,
                find_links,
                no_index,
                allow_prereleases,
                release_controls,
                uploaded_prior_to,
                compatibility,
                json,
            })
        }
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip index command `{other}`"
        ))),
    }
}

#[derive(Debug)]
pub(crate) struct PipIndexArgs {
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    allow_prereleases: bool,
    release_controls: PypiReleaseControls,
    uploaded_prior_to: Option<String>,
    compatibility: PipCompatibilityTarget,
    json: bool,
    positionals: Vec<String>,
}

pub(crate) fn parse_pip_index_common_args(
    args: &[String],
) -> Result<PipIndexArgs, OmcRegistryError> {
    let mut parsed = PipIndexArgs {
        index_url: None,
        extra_index_urls: Vec::new(),
        find_links: Vec::new(),
        no_index: false,
        allow_prereleases: false,
        release_controls: PypiReleaseControls::default(),
        uploaded_prior_to: None,
        compatibility: PipCompatibilityTarget::default(),
        json: false,
        positionals: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            parsed.json = true;
        } else if arg == "-i" || arg == "--index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            parsed.index_url = Some(url.clone());
        } else if let Some(url) = arg.strip_prefix("--index-url=") {
            parsed.index_url = Some(url.to_owned());
        } else if let Some(url) = pip_attached_short_value(arg, 'i') {
            parsed.index_url = Some(url.to_owned());
        } else if arg == "--extra-index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            parsed.extra_index_urls.push(url.clone());
        } else if let Some(url) = arg.strip_prefix("--extra-index-url=") {
            parsed.extra_index_urls.push(url.to_owned());
        } else if arg == "-f" || arg == "--find-links" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path or URL"
                )));
            };
            parsed.find_links.push(value.clone());
        } else if let Some(value) = arg.strip_prefix("--find-links=") {
            parsed.find_links.push(value.to_owned());
        } else if let Some(value) = pip_attached_short_value(arg, 'f') {
            parsed.find_links.push(value.to_owned());
        } else if let Some(value) = pip_bool_flag_value(arg, "--no-index") {
            parsed.no_index = value;
        } else if let Some(value) = pip_bool_flag_value(arg, "--pre") {
            parsed.allow_prereleases = value;
        } else if arg == "--all-releases" {
            let value = pip_target_flag_value(args, &mut index, arg)?;
            apply_pypi_release_control(&mut parsed.release_controls.all_releases, &value);
        } else if let Some(value) = arg.strip_prefix("--all-releases=") {
            apply_pypi_release_control(&mut parsed.release_controls.all_releases, value);
        } else if arg == "--only-final" {
            let value = pip_target_flag_value(args, &mut index, arg)?;
            apply_pypi_release_control(&mut parsed.release_controls.only_final, &value);
        } else if let Some(value) = arg.strip_prefix("--only-final=") {
            apply_pypi_release_control(&mut parsed.release_controls.only_final, value);
        } else if arg == "--uploaded-prior-to" {
            parsed.uploaded_prior_to = Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--uploaded-prior-to=") {
            parsed.uploaded_prior_to = Some(value.to_owned());
        } else if arg == "--platform" {
            parsed
                .compatibility
                .platforms
                .push(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--platform=") {
            parsed.compatibility.platforms.push(value.to_owned());
        } else if arg == "--python-version" {
            parsed.compatibility.python_version =
                Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--python-version=") {
            parsed.compatibility.python_version = Some(value.to_owned());
        } else if arg == "--implementation" {
            parsed.compatibility.implementation =
                Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--implementation=") {
            parsed.compatibility.implementation = Some(value.to_owned());
        } else if arg == "--abi" {
            parsed
                .compatibility
                .abis
                .push(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--abi=") {
            parsed.compatibility.abis.push(value.to_owned());
        } else if matches!(
            arg.as_str(),
            "--disable-pip-version-check"
                | "--isolated"
                | "--no-cache-dir"
                | "--ignore-requires-python"
        ) || pip_ignored_verbosity_flag(arg)
        {
        } else if pip_index_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_index_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip index", arg));
        } else {
            parsed.positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(parsed)
}

pub(crate) fn pip_index_ignored_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--trusted-host"
            | "--timeout"
            | "--retries"
            | "--cert"
            | "--client-cert"
            | "--proxy"
            | "--cache-dir"
            | "--log"
    )
}

pub(crate) fn pip_index_ignored_equals_flag(arg: &str) -> bool {
    [
        "--trusted-host=",
        "--timeout=",
        "--retries=",
        "--cert=",
        "--client-cert=",
        "--proxy=",
        "--cache-dir=",
        "--log=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn parse_pip_search_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut query = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "--isolated"
                | "--disable-pip-version-check"
                | "--no-cache-dir"
                | "--no-color"
                | "--no-input"
                | "--no-python-version-warning"
        ) || pip_ignored_verbosity_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "-i" | "--index"
                | "--log"
                | "--proxy"
                | "--retries"
                | "--timeout"
                | "--exists-action"
                | "--trusted-host"
                | "--cert"
                | "--client-cert"
                | "--cache-dir"
                | "--use-feature"
                | "--use-deprecated"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_search_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip search", arg));
        } else {
            query.push(arg.clone());
        }
        index += 1;
    }
    Ok(PipCompatAction::Search { query })
}

pub(crate) fn pip_search_ignored_equals_flag(arg: &str) -> bool {
    [
        "--index=",
        "--log=",
        "--proxy=",
        "--retries=",
        "--timeout=",
        "--exists-action=",
        "--trusted-host=",
        "--cert=",
        "--client-cert=",
        "--cache-dir=",
        "--use-feature=",
        "--use-deprecated=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn parse_pip_config_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let PipConfigArgs {
        editor,
        json,
        location,
        mut positionals,
    } = parse_pip_config_common_args(args)?;
    let command = if positionals.is_empty() {
        "list".to_owned()
    } else {
        positionals.remove(0)
    };
    match command.as_str() {
        "get" => {
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip config get needs at least one key".to_owned(),
                ));
            }
            Ok(PipCompatAction::Config {
                action: PipConfigAction::Get {
                    keys: positionals,
                    json,
                },
            })
        }
        "list" => {
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("pip config list", &positionals[0]));
            }
            Ok(PipCompatAction::Config {
                action: PipConfigAction::List { json },
            })
        }
        "debug" => {
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("pip config debug", &positionals[0]));
            }
            Ok(PipCompatAction::Config {
                action: PipConfigAction::Debug,
            })
        }
        "edit" => {
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("pip config edit", &positionals[0]));
            }
            Ok(PipCompatAction::ConfigEdit { location, editor })
        }
        "set" => {
            let assignments = parse_pip_config_assignments(positionals)?;
            Ok(PipCompatAction::Config {
                action: PipConfigAction::Set {
                    assignments,
                    location,
                },
            })
        }
        "unset" | "delete" | "del" | "remove" | "rm" => {
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip config unset needs at least one key".to_owned(),
                ));
            }
            Ok(PipCompatAction::Config {
                action: PipConfigAction::Unset {
                    keys: positionals,
                    location,
                },
            })
        }
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip config command `{other}`"
        ))),
    }
}

#[derive(Debug)]
pub(crate) struct PipConfigArgs {
    editor: Option<String>,
    json: bool,
    location: PipConfigLocation,
    positionals: Vec<String>,
}

pub(crate) fn parse_pip_config_common_args(
    args: &[String],
) -> Result<PipConfigArgs, OmcRegistryError> {
    let mut editor = None;
    let mut json = false;
    let mut location = PipConfigLocation::Auto;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--user" {
            location = PipConfigLocation::User;
        } else if arg == "--site" {
            location = PipConfigLocation::Site;
        } else if arg == "--global" {
            location = PipConfigLocation::Global;
        } else if arg == "--isolated" || pip_ignored_verbosity_flag(arg) {
        } else if arg == "--editor" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--editor needs a value".to_owned(),
                ));
            };
            editor = Some(value.clone());
        } else if arg.starts_with("--editor=") {
            editor = Some(arg["--editor=".len()..].to_owned());
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip config", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(PipConfigArgs {
        editor,
        json,
        location,
        positionals,
    })
}

pub(crate) fn parse_pip_config_assignments(
    positionals: Vec<String>,
) -> Result<Vec<(String, String)>, OmcRegistryError> {
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config set needs a key and value".to_owned(),
        ));
    }
    if positionals.iter().any(|value| value.contains('=')) {
        return positionals
            .into_iter()
            .map(|assignment| {
                let Some((key, value)) = assignment.split_once('=') else {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "pip config set mixed assignment formats at `{assignment}`"
                    )));
                };
                pip_config_assignment(key, value)
            })
            .collect();
    }
    if positionals.len() != 2 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config set needs either KEY VALUE or KEY=VALUE".to_owned(),
        ));
    }
    pip_config_assignment(&positionals[0], &positionals[1]).map(|assignment| vec![assignment])
}

pub(crate) fn pip_config_assignment(
    key: &str,
    value: &str,
) -> Result<(String, String), OmcRegistryError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config key cannot be empty".to_owned(),
        ));
    }
    Ok((key.to_owned(), value.trim().to_owned()))
}

pub(crate) fn parse_pip_uninstall_args(
    args: &[String],
) -> Result<PipCompatAction, OmcRegistryError> {
    let expanded_short_clusters = expand_pip_uninstall_short_clusters(args);
    let args = expanded_short_clusters.as_slice();
    let mut requirements = Vec::new();
    let mut user = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-r" || arg == "--requirement" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--requirement=") {
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = pip_attached_short_value(arg, 'r') {
            requirements.push(PathBuf::from(path));
        } else if matches!(arg.as_str(), "--user" | "--user=true") {
            user = true;
        } else if arg == "--user=false" {
            user = false;
        } else if matches!(arg.as_str(), "-y" | "--yes" | "--break-system-packages")
            || pip_global_ignored_bool_flag(arg)
        {
        } else if pip_global_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_global_ignored_equals_flag(arg) {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        allow,
        allow_flow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, false)?;
    if positionals.is_empty() && requirements.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip uninstall needs at least one package or requirement file".to_owned(),
        ));
    }
    Ok(PipCompatAction::Uninstall {
        specs: positionals,
        requirements,
        user,
        allow,
        allow_flow,
        allow_all_host,
    })
}

pub(crate) fn expand_pip_uninstall_short_clusters(args: &[String]) -> Vec<String> {
    args.iter()
        .flat_map(|arg| {
            expand_pip_short_cluster(arg, &['y'], &['r']).unwrap_or_else(|| vec![arg.clone()])
        })
        .collect()
}

pub(crate) fn parse_pip_show_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let expanded_short_clusters = expand_pip_show_short_clusters(args);
    let args = expanded_short_clusters.as_slice();
    let mut specs = Vec::new();
    let mut files = false;
    let mut user = false;
    for arg in args {
        if arg == "--disable-pip-version-check" || pip_ignored_verbosity_flag(arg) {
            continue;
        }
        if matches!(arg.as_str(), "-f" | "--files") {
            files = true;
            continue;
        }
        if matches!(arg.as_str(), "--user" | "--user=true") {
            user = true;
            continue;
        }
        if arg == "--user=false" {
            user = false;
            continue;
        }
        if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip show", arg));
        }
        specs.push(arg.clone());
    }
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip show needs at least one package".to_owned(),
        ));
    }
    Ok(PipCompatAction::Show { specs, files, user })
}

pub(crate) fn expand_pip_show_short_clusters(args: &[String]) -> Vec<String> {
    args.iter()
        .flat_map(|arg| {
            expand_pip_short_cluster(arg, &['f'], &[]).unwrap_or_else(|| vec![arg.clone()])
        })
        .collect()
}

pub(crate) fn parse_pip_hash_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut algorithm = PipHashAlgorithm::Sha256;
    let mut paths = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-a" || arg == "--algorithm" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            algorithm = parse_pip_hash_algorithm(value)?;
        } else if let Some(value) = arg.strip_prefix("--algorithm=") {
            algorithm = parse_pip_hash_algorithm(value)?;
        } else if let Some(value) = pip_attached_short_value(arg, 'a') {
            algorithm = parse_pip_hash_algorithm(value)?;
        } else if arg == "--disable-pip-version-check" || pip_ignored_verbosity_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip hash", arg));
        } else {
            paths.push(PathBuf::from(arg));
        }
        index += 1;
    }
    if paths.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip hash needs at least one file".to_owned(),
        ));
    }
    Ok(PipCompatAction::Hash { algorithm, paths })
}

pub(crate) fn parse_pip_hash_algorithm(value: &str) -> Result<PipHashAlgorithm, OmcRegistryError> {
    match value.to_ascii_lowercase().as_str() {
        "sha256" => Ok(PipHashAlgorithm::Sha256),
        "sha384" => Ok(PipHashAlgorithm::Sha384),
        "sha512" => Ok(PipHashAlgorithm::Sha512),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip hash algorithm `{other}`"
        ))),
    }
}

pub(crate) fn parse_pip_cache_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut filtered = Vec::new();
    let mut format = PipCacheListFormat::Human;
    let mut cache_dir = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--disable-pip-version-check" || pip_ignored_verbosity_flag(arg) {
        } else if arg == "--cache-dir" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--cache-dir needs a path".to_owned(),
                ));
            };
            cache_dir = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--cache-dir=") {
            cache_dir = Some(PathBuf::from(value));
        } else if arg == "--format" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip cache --format needs a value".to_owned(),
                ));
            };
            format = parse_pip_cache_list_format(value)?;
        } else if let Some(value) = arg.strip_prefix("--format=") {
            format = parse_pip_cache_list_format(value)?;
        } else if pip_global_ignored_bool_flag(arg) || pip_global_ignored_equals_flag(arg) {
        } else if pip_global_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip cache", arg));
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }
    let Some(command) = filtered.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip cache needs a command such as dir, list, remove, or purge".to_owned(),
        ));
    };
    let rest = &filtered[1..];
    let action = match command {
        "dir" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("pip cache dir", &rest[0]));
            }
            PipCacheAction::Dir
        }
        "info" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("pip cache info", &rest[0]));
            }
            PipCacheAction::Info
        }
        "list" => {
            if rest.len() > 1 {
                return Err(unsupported_compat_arg("pip cache list", &rest[1]));
            }
            PipCacheAction::List {
                pattern: rest.first().cloned(),
                format,
            }
        }
        "remove" | "rm" => {
            if rest.len() != 1 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip cache remove needs exactly one pattern".to_owned(),
                ));
            }
            PipCacheAction::Remove {
                pattern: rest[0].clone(),
            }
        }
        "purge" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("pip cache purge", &rest[0]));
            }
            PipCacheAction::Purge
        }
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported pip cache command `{other}`"
            )))
        }
    };
    Ok(PipCompatAction::Cache { action, cache_dir })
}

pub(crate) fn parse_pip_cache_list_format(
    value: &str,
) -> Result<PipCacheListFormat, OmcRegistryError> {
    match value {
        "human" => Ok(PipCacheListFormat::Human),
        "abspath" => Ok(PipCacheListFormat::Abspath),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip cache list format `{other}`"
        ))),
    }
}

pub(crate) fn parse_pip_check_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut user = false;
    for arg in args {
        if matches!(arg.as_str(), "--user" | "--user=true") {
            user = true;
            continue;
        }
        if arg == "--user=false" {
            user = false;
            continue;
        }
        if arg == "--disable-pip-version-check" || pip_ignored_verbosity_flag(arg) {
            continue;
        }
        return Err(unsupported_compat_arg("pip check", arg));
    }
    Ok(PipCompatAction::Check { user })
}

pub(crate) fn parse_pip_debug_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut action = PipDebugAction {
        verbose: false,
        platform: None,
        python_version: None,
        implementation: None,
        abis: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--debug" | "--disable-pip-version-check")
            || pip_ignored_verbosity_flag(arg)
        {
            if pip_verbose_flag(arg) {
                action.verbose = true;
            }
        } else if arg == "--platform" {
            action.platform = Some(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--platform=") {
            action.platform = Some(value.to_owned());
        } else if arg == "--python-version" {
            action.python_version = Some(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--python-version=") {
            action.python_version = Some(value.to_owned());
        } else if arg == "--implementation" {
            action.implementation = Some(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--implementation=") {
            action.implementation = Some(value.to_owned());
        } else if arg == "--abi" {
            action
                .abis
                .push(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--abi=") {
            action.abis.push(value.to_owned());
        } else if matches!(
            arg.as_str(),
            "--cert" | "--client-cert" | "--cache-dir" | "--log" | "--proxy" | "--timeout"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_debug_ignored_equals_flag(arg) {
        } else {
            return Err(unsupported_compat_arg("pip debug", arg));
        }
        index += 1;
    }
    Ok(PipCompatAction::Debug { action })
}

pub(crate) fn pip_debug_flag_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

pub(crate) fn pip_debug_ignored_equals_flag(arg: &str) -> bool {
    [
        "--cert=",
        "--client-cert=",
        "--cache-dir=",
        "--log=",
        "--proxy=",
        "--timeout=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn parse_pip_inspect_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut paths = Vec::new();
    let mut user = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--user" {
            user = true;
        } else if matches!(arg.as_str(), "--local" | "--disable-pip-version-check")
            || pip_ignored_verbosity_flag(arg)
        {
        } else if arg == "--path" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            paths.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--path=") {
            paths.push(PathBuf::from(path));
        } else {
            return Err(unsupported_compat_arg("pip inspect", arg));
        }
        index += 1;
    }
    Ok(PipCompatAction::Inspect { paths, user })
}

pub(crate) fn parse_pip_freeze_args(args: &[String]) -> Result<PipFreezeAction, OmcRegistryError> {
    let expanded_short_clusters = expand_pip_freeze_short_clusters(args);
    let args = expanded_short_clusters.as_slice();
    let mut action = PipFreezeAction::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--user" {
            action.user = true;
        } else if matches!(
            arg.as_str(),
            "--all" | "--local" | "-l" | "--exclude-editable" | "--disable-pip-version-check"
        ) || pip_ignored_verbosity_flag(arg)
        {
            if arg == "--exclude-editable" {
                action.exclude_editable = true;
            }
        } else if matches!(
            arg.as_str(),
            "-r" | "--requirement" | "--path" | "--exclude"
        ) {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            if arg == "--path" {
                action.paths.push(PathBuf::from(value));
            } else if arg == "--exclude" {
                action.exclude.push(value.clone());
            } else {
                action.requirements.push(PathBuf::from(value));
            }
        } else if let Some(path) = arg.strip_prefix("--path=") {
            action.paths.push(PathBuf::from(path));
        } else if let Some(exclude) = arg.strip_prefix("--exclude=") {
            action.exclude.push(exclude.to_owned());
        } else if let Some(requirement) = arg.strip_prefix("--requirement=") {
            action.requirements.push(PathBuf::from(requirement));
        } else if let Some(requirement) = pip_attached_short_value(arg, 'r') {
            action.requirements.push(PathBuf::from(requirement));
        } else {
            return Err(unsupported_compat_arg("pip freeze", arg));
        }
        index += 1;
    }
    Ok(action)
}

pub(crate) fn parse_pip_install_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let expanded_short_clusters = expand_pip_install_short_clusters(args);
    let args = expanded_short_clusters.as_slice();
    let mut requirements = Vec::new();
    let mut constraints = Vec::new();
    let mut script_requirements = Vec::new();
    let mut report = None;
    let mut dry_run = false;
    let mut index_url = None;
    let mut extra_index_urls = Vec::new();
    let mut find_links = Vec::new();
    let mut no_index = false;
    let mut binary_all = None;
    let mut binary_packages = BTreeMap::new();
    let mut require_hashes = false;
    let mut no_deps = false;
    let mut allow_prereleases = false;
    let mut release_controls = PypiReleaseControls::default();
    let mut uploaded_prior_to = None;
    let mut upgrade = false;
    let mut force_reinstall = false;
    let mut compatibility = PipCompatibilityTarget::default();
    let mut target = None;
    let mut prefix = None;
    let mut root = None;
    let mut user = false;
    let mut groups = Vec::new();
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    let mut local_directories = Vec::new();
    let mut vcs_requirements = Vec::new();
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-r" || arg == "--requirement" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--requirement=") {
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = pip_attached_short_value(arg, 'r') {
            requirements.push(PathBuf::from(path));
        } else if arg == "-c" || arg == "--constraint" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            constraints.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--constraint=") {
            constraints.push(PathBuf::from(path));
        } else if let Some(path) = pip_attached_short_value(arg, 'c') {
            constraints.push(PathBuf::from(path));
        } else if arg == "--requirements-from-script" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            script_requirements.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--requirements-from-script=") {
            script_requirements.push(PathBuf::from(path));
        } else if arg == "--report" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            report = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--report=") {
            report = Some(PathBuf::from(path));
        } else if let Some(value) = pip_bool_flag_value(arg, "--dry-run") {
            dry_run = value;
        } else if arg == "-i" || arg == "--index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            index_url = Some(url.clone());
        } else if let Some(url) = arg.strip_prefix("--index-url=") {
            index_url = Some(url.to_owned());
        } else if let Some(url) = pip_attached_short_value(arg, 'i') {
            index_url = Some(url.to_owned());
        } else if arg == "--extra-index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            extra_index_urls.push(url.clone());
        } else if let Some(url) = arg.strip_prefix("--extra-index-url=") {
            extra_index_urls.push(url.to_owned());
        } else if arg == "-f" || arg == "--find-links" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path or URL"
                )));
            };
            find_links.push(value.clone());
        } else if let Some(value) = arg.strip_prefix("--find-links=") {
            find_links.push(value.to_owned());
        } else if let Some(value) = pip_attached_short_value(arg, 'f') {
            find_links.push(value.to_owned());
        } else if let Some(value) = pip_bool_flag_value(arg, "--no-index") {
            no_index = value;
        } else if let Some(value) = pip_bool_flag_value(arg, "--require-hashes") {
            require_hashes = value;
        } else if let Some(value) = pip_bool_flag_value(arg, "--no-deps") {
            no_deps = value;
        } else if let Some(value) = pip_bool_flag_value(arg, "--pre") {
            allow_prereleases = value;
        } else if arg == "--all-releases" {
            let value = pip_target_flag_value(args, &mut index, arg)?;
            apply_pypi_release_control(&mut release_controls.all_releases, &value);
        } else if let Some(value) = arg.strip_prefix("--all-releases=") {
            apply_pypi_release_control(&mut release_controls.all_releases, value);
        } else if arg == "--only-final" {
            let value = pip_target_flag_value(args, &mut index, arg)?;
            apply_pypi_release_control(&mut release_controls.only_final, &value);
        } else if let Some(value) = arg.strip_prefix("--only-final=") {
            apply_pypi_release_control(&mut release_controls.only_final, value);
        } else if arg == "--uploaded-prior-to" {
            uploaded_prior_to = Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--uploaded-prior-to=") {
            uploaded_prior_to = Some(value.to_owned());
        } else if arg == "--platform" {
            compatibility
                .platforms
                .push(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--platform=") {
            compatibility.platforms.push(value.to_owned());
        } else if arg == "--python-version" {
            compatibility.python_version = Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--python-version=") {
            compatibility.python_version = Some(value.to_owned());
        } else if arg == "--implementation" {
            compatibility.implementation = Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--implementation=") {
            compatibility.implementation = Some(value.to_owned());
        } else if arg == "--abi" {
            compatibility
                .abis
                .push(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--abi=") {
            compatibility.abis.push(value.to_owned());
        } else if arg == "-t" || arg == "--target" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            target = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--target=") {
            target = Some(PathBuf::from(path));
        } else if let Some(path) = pip_attached_short_value(arg, 't') {
            target = Some(PathBuf::from(path));
        } else if arg == "--prefix" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            prefix = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--prefix=") {
            prefix = Some(PathBuf::from(path));
        } else if arg == "--root" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            root = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--root=") {
            root = Some(PathBuf::from(path));
        } else if matches!(arg.as_str(), "--user" | "--user=true") {
            user = true;
        } else if arg == "--user=false" {
            user = false;
        } else if arg == "--group" {
            index += 1;
            let Some(group) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a group"
                )));
            };
            match pip_project_group_arg(group)? {
                PipProjectGroupArg::Current(group) => groups.push(group),
                PipProjectGroupArg::Local(requirement) => local_paths.push(requirement),
            }
        } else if let Some(group) = arg.strip_prefix("--group=") {
            match pip_project_group_arg(group)? {
                PipProjectGroupArg::Current(group) => groups.push(group),
                PipProjectGroupArg::Local(requirement) => local_paths.push(requirement),
            }
        } else if arg == "--prefer-binary" {
        } else if arg == "--only-binary" || arg == "--no-binary" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            let mode = if arg == "--only-binary" {
                PypiBinaryMode::Binary
            } else {
                PypiBinaryMode::Source
            };
            apply_pypi_binary_option(&mut binary_all, &mut binary_packages, mode, value);
        } else if let Some(value) = arg.strip_prefix("--only-binary=") {
            apply_pypi_binary_option(
                &mut binary_all,
                &mut binary_packages,
                PypiBinaryMode::Binary,
                value,
            );
        } else if let Some(value) = arg.strip_prefix("--no-binary=") {
            apply_pypi_binary_option(
                &mut binary_all,
                &mut binary_packages,
                PypiBinaryMode::Source,
                value,
            );
        } else if arg == "--trusted-host" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with("--trusted-host=") {
        } else if arg == "-e" || arg == "--editable" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            if let Some(requirement) = parse_pypi_vcs_requirement(path)? {
                vcs_requirements.push(requirement);
            } else {
                local_paths.push(pip_local_path_arg(path)?);
            }
        } else if let Some(path) = arg.strip_prefix("--editable=") {
            if let Some(requirement) = parse_pypi_vcs_requirement(path)? {
                vcs_requirements.push(requirement);
            } else {
                local_paths.push(pip_local_path_arg(path)?);
            }
        } else if let Some(path) = pip_attached_short_value(arg, 'e') {
            if let Some(requirement) = parse_pypi_vcs_requirement(path)? {
                vcs_requirements.push(requirement);
            } else {
                local_paths.push(pip_local_path_arg(path)?);
            }
        } else if matches!(arg.as_str(), "--upgrade" | "-U") {
            upgrade = true;
        } else if arg == "--upgrade=false" {
            upgrade = false;
        } else if matches!(
            arg.as_str(),
            "--force-reinstall" | "--ignore-installed" | "-I"
        ) {
            force_reinstall = true;
        } else if matches!(
            arg.as_str(),
            "--break-system-packages"
                | "--disable-pip-version-check"
                | "--no-cache-dir"
                | "--isolated"
                | "--require-virtualenv"
                | "--ignore-requires-python"
                | "--no-build-isolation"
                | "--check-build-dependencies"
                | "--use-pep517"
                | "--no-use-pep517"
                | "--compile"
                | "--no-compile"
                | "--no-color"
                | "--no-input"
                | "--no-python-version-warning"
                | "--no-warn-script-location"
                | "--no-warn-conflicts"
                | "--no-clean"
        ) || pip_ignored_verbosity_flag(arg)
        {
        } else if pip_ignored_install_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_ignored_install_equals_flag(arg) {
        } else if is_pip_archive_arg(arg) {
            archive_references.push(arg.clone());
        } else if let Some(requirement) = parse_pypi_vcs_requirement(arg)? {
            vcs_requirements.push(requirement);
        } else if is_pip_pylock_requirements_arg(arg) {
            requirements.push(PathBuf::from(arg));
        } else if is_pip_local_directory_arg(arg) {
            local_directories.push(pip_local_path_arg(arg)?);
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        allow,
        allow_flow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, false)?;

    // batou:ignore-start http_header -- false positives across the pip-compat
    // action builders below: these are PipInstallAction/PipLockAction struct
    // literals over paths and specs. There is no lettre/Mailbox/email or
    // HTTP-header sink anywhere in this module; the taint engine misattributes
    // a CRLF-injection sink to plain struct construction.
    Ok(PipCompatAction::Install(Box::new(PipInstallAction {
        specs: positionals.into_iter().filter(|spec| spec != ".").collect(),
        requirements,
        constraints,
        script_requirements,
        groups,
        report,
        dry_run,
        archive_references,
        local_paths,
        local_directories,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        binary_all,
        binary_packages,
        require_hashes,
        no_deps,
        allow_prereleases,
        release_controls,
        uploaded_prior_to,
        upgrade,
        force_reinstall,
        compatibility,
        target,
        prefix,
        root,
        user,
        vcs_requirements,
        allow,
        allow_flow,
        allow_all_host,
    })))
}

pub(crate) fn parse_pip_lock_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut output = PathBuf::from("pylock.toml");
    let mut install_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-o" || arg == "--output" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            output = PathBuf::from(path);
        } else if let Some(path) = arg.strip_prefix("--output=") {
            output = PathBuf::from(path);
        } else if arg == "--build-constraint" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            }
        } else if arg.starts_with("--build-constraint=") {
        } else {
            install_args.push(arg.clone());
        }
        index += 1;
    }

    let PipCompatAction::Install(action) = parse_pip_install_args(&install_args)? else {
        unreachable!("parse_pip_install_args returns install actions")
    };
    Ok(PipCompatAction::Lock(Box::new(PipLockAction {
        install: *action,
        output,
    })))
}

pub(crate) fn expand_pip_install_short_clusters(args: &[String]) -> Vec<String> {
    args.iter()
        .flat_map(|arg| {
            expand_pip_short_cluster(arg, &['U', 'I'], &['r', 'c', 'i', 'f', 't', 'e', 'C'])
                .unwrap_or_else(|| vec![arg.clone()])
        })
        .collect()
}

pub(crate) fn expand_pip_freeze_short_clusters(args: &[String]) -> Vec<String> {
    args.iter()
        .flat_map(|arg| {
            expand_pip_short_cluster(arg, &['l'], &['r']).unwrap_or_else(|| vec![arg.clone()])
        })
        .collect()
}

pub(crate) fn parse_pip_download_args(
    args: &[String],
) -> Result<PipCompatAction, OmcRegistryError> {
    parse_pip_artifact_args(args, PipArtifactCommand::Download)
}

pub(crate) fn parse_pip_wheel_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    parse_pip_artifact_args(args, PipArtifactCommand::Wheel)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipArtifactCommand {
    Download,
    Wheel,
}

pub(crate) fn parse_pip_artifact_args(
    args: &[String],
    command: PipArtifactCommand,
) -> Result<PipCompatAction, OmcRegistryError> {
    let expanded_short_clusters = expand_pip_artifact_short_clusters(args, command);
    let args = expanded_short_clusters.as_slice();
    let mut requirements = Vec::new();
    let mut constraints = Vec::new();
    let mut index_url = None;
    let mut extra_index_urls = Vec::new();
    let mut find_links = Vec::new();
    let mut no_index = false;
    let mut binary_all = None;
    let mut binary_packages = BTreeMap::new();
    let mut require_hashes = false;
    let mut no_deps = false;
    let mut allow_prereleases = false;
    let mut release_controls = PypiReleaseControls::default();
    let mut uploaded_prior_to = None;
    let mut compatibility = PipCompatibilityTarget::default();
    let mut destination = PathBuf::from(".");
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-r" || arg == "--requirement" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--requirement=") {
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = pip_attached_short_value(arg, 'r') {
            requirements.push(PathBuf::from(path));
        } else if arg == "-c" || arg == "--constraint" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            constraints.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--constraint=") {
            constraints.push(PathBuf::from(path));
        } else if let Some(path) = pip_attached_short_value(arg, 'c') {
            constraints.push(PathBuf::from(path));
        } else if command == PipArtifactCommand::Download
            && (arg == "-d" || arg == "--dest" || arg == "--destination-dir")
        {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Download
            && arg
                .strip_prefix("--dest=")
                .or_else(|| arg.strip_prefix("--destination-dir="))
                .is_some()
        {
            let path = arg
                .strip_prefix("--dest=")
                .or_else(|| arg.strip_prefix("--destination-dir="))
                .expect("checked path option");
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Download
            && pip_attached_short_value(arg, 'd').is_some()
        {
            let path = pip_attached_short_value(arg, 'd').expect("checked download dest");
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Wheel && (arg == "-w" || arg == "--wheel-dir") {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Wheel && arg.starts_with("--wheel-dir=") {
            let path = arg
                .strip_prefix("--wheel-dir=")
                .expect("checked wheel-dir option");
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Wheel
            && pip_attached_short_value(arg, 'w').is_some()
        {
            let path = pip_attached_short_value(arg, 'w').expect("checked wheel dir");
            destination = PathBuf::from(path);
        } else if arg == "-i" || arg == "--index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            index_url = Some(url.clone());
        } else if let Some(url) = arg.strip_prefix("--index-url=") {
            index_url = Some(url.to_owned());
        } else if let Some(url) = pip_attached_short_value(arg, 'i') {
            index_url = Some(url.to_owned());
        } else if arg == "--extra-index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            extra_index_urls.push(url.clone());
        } else if let Some(url) = arg.strip_prefix("--extra-index-url=") {
            extra_index_urls.push(url.to_owned());
        } else if arg == "-f" || arg == "--find-links" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path or URL"
                )));
            };
            find_links.push(value.clone());
        } else if let Some(value) = arg.strip_prefix("--find-links=") {
            find_links.push(value.to_owned());
        } else if let Some(value) = pip_attached_short_value(arg, 'f') {
            find_links.push(value.to_owned());
        } else if let Some(value) = pip_bool_flag_value(arg, "--no-index") {
            no_index = value;
        } else if let Some(value) = pip_bool_flag_value(arg, "--require-hashes") {
            require_hashes = value;
        } else if let Some(value) = pip_bool_flag_value(arg, "--no-deps") {
            no_deps = value;
        } else if let Some(value) = pip_bool_flag_value(arg, "--pre") {
            allow_prereleases = value;
        } else if arg == "--all-releases" {
            let value = pip_target_flag_value(args, &mut index, arg)?;
            apply_pypi_release_control(&mut release_controls.all_releases, &value);
        } else if let Some(value) = arg.strip_prefix("--all-releases=") {
            apply_pypi_release_control(&mut release_controls.all_releases, value);
        } else if arg == "--only-final" {
            let value = pip_target_flag_value(args, &mut index, arg)?;
            apply_pypi_release_control(&mut release_controls.only_final, &value);
        } else if let Some(value) = arg.strip_prefix("--only-final=") {
            apply_pypi_release_control(&mut release_controls.only_final, value);
        } else if arg == "--uploaded-prior-to" {
            uploaded_prior_to = Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--uploaded-prior-to=") {
            uploaded_prior_to = Some(value.to_owned());
        } else if arg == "--platform" {
            compatibility
                .platforms
                .push(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--platform=") {
            compatibility.platforms.push(value.to_owned());
        } else if arg == "--python-version" {
            compatibility.python_version = Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--python-version=") {
            compatibility.python_version = Some(value.to_owned());
        } else if arg == "--implementation" {
            compatibility.implementation = Some(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--implementation=") {
            compatibility.implementation = Some(value.to_owned());
        } else if arg == "--abi" {
            compatibility
                .abis
                .push(pip_target_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--abi=") {
            compatibility.abis.push(value.to_owned());
        } else if arg == "--prefer-binary" {
        } else if arg == "--only-binary" || arg == "--no-binary" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            let mode = if arg == "--only-binary" {
                PypiBinaryMode::Binary
            } else {
                PypiBinaryMode::Source
            };
            apply_pypi_binary_option(&mut binary_all, &mut binary_packages, mode, value);
        } else if let Some(value) = arg.strip_prefix("--only-binary=") {
            apply_pypi_binary_option(
                &mut binary_all,
                &mut binary_packages,
                PypiBinaryMode::Binary,
                value,
            );
        } else if let Some(value) = arg.strip_prefix("--no-binary=") {
            apply_pypi_binary_option(
                &mut binary_all,
                &mut binary_packages,
                PypiBinaryMode::Source,
                value,
            );
        } else if arg == "--trusted-host" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if (command == PipArtifactCommand::Wheel && arg == "--no-verify")
            || matches!(
                arg.as_str(),
                "--ignore-requires-python"
                    | "--no-build-isolation"
                    | "--check-build-dependencies"
                    | "--use-pep517"
                    | "--no-use-pep517"
                    | "--no-clean"
            )
            || pip_global_ignored_bool_flag(arg)
            || arg.starts_with("--trusted-host=")
        {
        } else if command == PipArtifactCommand::Wheel && (arg == "-e" || arg == "--editable") {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            local_paths.push(pip_local_path_arg(path)?);
        } else if command == PipArtifactCommand::Wheel && arg.starts_with("--editable=") {
            let path = arg
                .strip_prefix("--editable=")
                .expect("checked editable option");
            local_paths.push(pip_local_path_arg(path)?);
        } else if command == PipArtifactCommand::Wheel
            && pip_attached_short_value(arg, 'e').is_some()
        {
            let path = pip_attached_short_value(arg, 'e').expect("checked editable option");
            local_paths.push(pip_local_path_arg(path)?);
        } else if command == PipArtifactCommand::Wheel && pip_ignored_wheel_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if command == PipArtifactCommand::Wheel && pip_ignored_wheel_equals_flag(arg) {
        } else if pip_ignored_download_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_ignored_download_equals_flag(arg) {
        } else if is_pip_archive_arg(arg) {
            archive_references.push(arg.clone());
        } else if is_pip_pylock_requirements_arg(arg) {
            requirements.push(PathBuf::from(arg));
        } else if is_pip_local_directory_arg(arg) {
            local_paths.push(pip_local_path_arg(arg)?);
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        allow,
        allow_flow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, false)?;

    let action = PipDownloadAction {
        specs: positionals.into_iter().filter(|spec| spec != ".").collect(),
        requirements,
        constraints,
        archive_references,
        local_paths,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        binary_all,
        binary_packages,
        require_hashes,
        no_deps,
        allow_prereleases,
        release_controls,
        uploaded_prior_to,
        compatibility,
        destination,
        allow,
        allow_flow,
        allow_all_host,
    };
    Ok(match command {
        PipArtifactCommand::Download => PipCompatAction::Download(Box::new(action)),
        PipArtifactCommand::Wheel => PipCompatAction::Wheel(Box::new(action)),
    })
}
// batou:ignore-end http_header

pub(crate) fn expand_pip_artifact_short_clusters(
    args: &[String],
    command: PipArtifactCommand,
) -> Vec<String> {
    let value_flags = match command {
        PipArtifactCommand::Download => &['r', 'c', 'd', 'i', 'f'][..],
        PipArtifactCommand::Wheel => &['r', 'c', 'w', 'i', 'f', 'e', 'C'][..],
    };
    args.iter()
        .flat_map(|arg| {
            expand_pip_short_cluster(arg, &[], value_flags).unwrap_or_else(|| vec![arg.clone()])
        })
        .collect()
}

pub(crate) fn pip_ignored_install_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--progress-bar"
            | "--build-constraint"
            | "--upgrade-strategy"
            | "--src"
            | "-C"
            | "--config-settings"
            | "--global-option"
            | "--install-option"
            | "--root-user-action"
            | "--log"
            | "--proxy"
            | "--retries"
            | "--timeout"
            | "--exists-action"
            | "--keyring-provider"
            | "--cert"
            | "--client-cert"
            | "--cache-dir"
            | "--use-feature"
            | "--use-deprecated"
    )
}

pub(crate) fn pip_ignored_install_equals_flag(arg: &str) -> bool {
    [
        "--progress-bar=",
        "--build-constraint=",
        "--upgrade-strategy=",
        "--src=",
        "-C=",
        "--config-settings=",
        "--global-option=",
        "--install-option=",
        "--root-user-action=",
        "--log=",
        "--proxy=",
        "--retries=",
        "--timeout=",
        "--exists-action=",
        "--keyring-provider=",
        "--cert=",
        "--client-cert=",
        "--cache-dir=",
        "--use-feature=",
        "--use-deprecated=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn pip_bool_flag_value(arg: &str, flag: &str) -> Option<bool> {
    if arg == flag {
        return Some(true);
    }
    let value = arg.strip_prefix(flag)?.strip_prefix('=')?;
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

pub(crate) fn pip_attached_short_value(arg: &str, flag: char) -> Option<&str> {
    if arg.starts_with("--") {
        return None;
    }
    let rest = arg.strip_prefix('-')?;
    let value = rest.strip_prefix(flag)?;
    (!value.is_empty()).then_some(value)
}

pub(crate) fn expand_pip_short_cluster(
    arg: &str,
    bool_flags: &[char],
    value_flags: &[char],
) -> Option<Vec<String>> {
    if arg.starts_with("--") {
        return None;
    }
    let body = arg.strip_prefix('-')?;
    if body.chars().count() <= 1 {
        return None;
    }

    let chars = body.chars().collect::<Vec<_>>();
    if value_flags.contains(&chars[0]) {
        return (chars[0] == 'C' && chars.len() > 1)
            .then(|| vec!["-C".to_owned(), chars[1..].iter().collect::<String>()]);
    }

    let mut expanded = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let flag = chars[index];
        if matches!(flag, 'q' | 'v') || bool_flags.contains(&flag) {
            expanded.push(format!("-{flag}"));
            index += 1;
        } else if value_flags.contains(&flag) {
            let value = chars[index + 1..].iter().collect::<String>();
            if value.is_empty() {
                expanded.push(format!("-{flag}"));
            } else if flag == 'C' {
                expanded.push("-C".to_owned());
                expanded.push(value);
            } else {
                expanded.push(format!("-{flag}{value}"));
            }
            return Some(expanded);
        } else {
            return None;
        }
    }
    Some(expanded)
}

pub(crate) fn pip_target_flag_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

pub(crate) enum PipProjectGroupArg {
    Current(String),
    Local(PythonLocalRequirement),
}

pub(crate) fn pip_project_group_arg(value: &str) -> Result<PipProjectGroupArg, OmcRegistryError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --group needs a non-empty group".to_owned(),
        ));
    }
    if let Some((path, group)) = value.rsplit_once(':') {
        let path = path.trim();
        let group = normalize_extra(group);
        if group.is_empty() {
            return Err(OmcRegistryError::UnsupportedSpec(
                "pip install --group needs a non-empty group".to_owned(),
            ));
        }
        if matches!(path, "" | "pyproject.toml" | "./pyproject.toml") {
            return Ok(PipProjectGroupArg::Current(group));
        }
        return Ok(PipProjectGroupArg::Local(PythonLocalRequirement::new(
            pip_project_group_path(path)?,
            BTreeSet::from([group]),
        )));
    }
    Ok(PipProjectGroupArg::Current(normalize_extra(value)))
}

pub(crate) fn pip_project_group_path(path: &str) -> Result<PathBuf, OmcRegistryError> {
    if path.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --group needs a non-empty pyproject path".to_owned(),
        ));
    }
    let path = PathBuf::from(path);
    if path.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
        return Ok(path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")));
    }
    Ok(path)
}

pub(crate) fn pip_ignored_wheel_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "-C" | "--config-settings" | "--build-option" | "--global-option"
    )
}

pub(crate) fn pip_ignored_wheel_equals_flag(arg: &str) -> bool {
    [
        "-C=",
        "--config-settings=",
        "--build-option=",
        "--global-option=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn pip_ignored_download_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--progress-bar"
            | "--build-constraint"
            | "--retries"
            | "--timeout"
            | "--exists-action"
            | "--keyring-provider"
            | "--cert"
            | "--client-cert"
            | "--proxy"
            | "--cache-dir"
            | "--log"
            | "--use-feature"
            | "--use-deprecated"
    )
}

pub(crate) fn pip_ignored_download_equals_flag(arg: &str) -> bool {
    [
        "--progress-bar=",
        "--build-constraint=",
        "--retries=",
        "--timeout=",
        "--exists-action=",
        "--keyring-provider=",
        "--cert=",
        "--client-cert=",
        "--proxy=",
        "--cache-dir=",
        "--log=",
        "--use-feature=",
        "--use-deprecated=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn pip_local_path_arg(value: &str) -> Result<PythonLocalRequirement, OmcRegistryError> {
    if value.starts_with("git+") || is_pip_archive_arg(value) {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "pip editable path `{value}` must be a local directory"
        )));
    }
    let (path, extras) = pip_local_path_and_extras(value);
    let path = if let Some(path) = pip_local_file_url_path(path)? {
        return Ok(PythonLocalRequirement::new(path, extras));
    } else {
        path
    };
    let path = path
        .strip_prefix("file:")
        .or_else(|| path.strip_prefix("link:"))
        .unwrap_or(path);
    if path.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip editable path cannot be empty".to_owned(),
        ));
    }
    Ok(PythonLocalRequirement::new(PathBuf::from(path), extras))
}

pub(crate) fn is_pip_local_directory_arg(value: &str) -> bool {
    if value.starts_with("git+") || is_pip_archive_arg(value) {
        return false;
    }
    let (path, _) = pip_local_path_and_extras(value);
    if path.contains("://") {
        return path.starts_with("file://");
    }
    let path = path
        .strip_prefix("file:")
        .or_else(|| path.strip_prefix("link:"))
        .unwrap_or(path);
    path == "."
        || path.starts_with("./")
        || path.starts_with("../")
        || path.starts_with('/')
        || path.starts_with("~/")
        || path.contains('/')
        || path.contains('\\')
}

pub(crate) fn pip_local_file_url_path(value: &str) -> Result<Option<PathBuf>, OmcRegistryError> {
    if !value.contains("://") {
        return Ok(None);
    }
    let url = reqwest::Url::parse(value)
        .map_err(|_| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    if url.scheme() != "file" {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "pip local directory URL `{value}` must use file://"
        )));
    }
    url.to_file_path().map(Some).map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!(
            "pip local directory URL `{value}` must use a valid file URL"
        ))
    })
}

pub(crate) fn is_pip_pylock_requirements_arg(value: &str) -> bool {
    if value.contains("://") || value.starts_with("git+") {
        return false;
    }
    let path = Path::new(value);
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "pylock.toml" || (name.starts_with("pylock.") && name.ends_with(".toml"))
}

pub(crate) fn pip_local_path_and_extras(value: &str) -> (&str, BTreeSet<String>) {
    let Some((path, extras)) = value.split_once('[') else {
        return (value, BTreeSet::new());
    };
    let extras = extras
        .trim_end_matches(']')
        .split(',')
        .map(normalize_extra)
        .filter(|extra| !extra.is_empty())
        .collect();
    (path, extras)
}

pub(crate) fn is_pip_archive_arg(value: &str) -> bool {
    let value = value.split_once('#').map(|(path, _)| path).unwrap_or(value);
    let filename = value
        .rsplit_once('/')
        .map(|(_, filename)| filename)
        .unwrap_or(value);
    filename.ends_with(".whl")
        || filename.ends_with(".zip")
        || filename.ends_with(".tgz")
        || filename.ends_with(".tar.gz")
}

pub(crate) fn parse_pip_list_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let expanded_short_clusters = expand_pip_list_short_clusters(args);
    let args = expanded_short_clusters.as_slice();
    let mut format = PipListFormat::Columns;
    let mut verbose = false;
    let mut outdated = false;
    let mut uptodate = false;
    let mut index_url = None;
    let mut extra_index_urls = Vec::new();
    let mut find_links = Vec::new();
    let mut no_index = false;
    let mut allow_prereleases = false;
    let mut paths = Vec::new();
    let mut user = false;
    let mut exclude = Vec::new();
    let mut editable = PipEditableMode::Include;
    let mut not_required = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--format" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip list --format needs a value".to_owned(),
                ));
            };
            format = parse_pip_list_format_value(value)?;
        } else if let Some(value) = arg.strip_prefix("--format=") {
            format = parse_pip_list_format_value(value)?;
        } else if arg == "-o" || arg == "--outdated" {
            outdated = true;
        } else if arg == "-u" || arg == "--uptodate" {
            uptodate = true;
        } else if arg == "-i" || arg == "--index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            index_url = Some(url.clone());
        } else if let Some(url) = arg.strip_prefix("--index-url=") {
            index_url = Some(url.to_owned());
        } else if let Some(url) = pip_attached_short_value(arg, 'i') {
            index_url = Some(url.to_owned());
        } else if arg == "--extra-index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            extra_index_urls.push(url.clone());
        } else if let Some(url) = arg.strip_prefix("--extra-index-url=") {
            extra_index_urls.push(url.to_owned());
        } else if arg == "-f" || arg == "--find-links" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path or URL"
                )));
            };
            find_links.push(value.clone());
        } else if let Some(value) = arg.strip_prefix("--find-links=") {
            find_links.push(value.to_owned());
        } else if let Some(value) = pip_attached_short_value(arg, 'f') {
            find_links.push(value.to_owned());
        } else if arg == "--no-index" {
            no_index = true;
        } else if arg == "--pre" {
            allow_prereleases = true;
        } else if arg == "--user" {
            user = true;
        } else if pip_verbose_flag(arg) {
            verbose = true;
        } else if matches!(
            arg.as_str(),
            "--local" | "-l" | "--disable-pip-version-check" | "--ignore-requires-python"
        ) || pip_ignored_verbosity_flag(arg)
        {
        } else if arg == "-e" || arg == "--editable" {
            editable = PipEditableMode::Only;
        } else if arg == "--include-editable" {
            editable = PipEditableMode::Include;
        } else if arg == "--exclude-editable" {
            editable = PipEditableMode::Exclude;
        } else if arg == "--not-required" {
            not_required = true;
        } else if matches!(arg.as_str(), "--path" | "--exclude") {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            if arg == "--path" {
                paths.push(PathBuf::from(value));
            } else {
                exclude.push(value.clone());
            }
        } else if let Some(path) = arg.strip_prefix("--path=") {
            paths.push(PathBuf::from(path));
        } else if let Some(name) = arg.strip_prefix("--exclude=") {
            exclude.push(name.to_owned());
        } else if pip_index_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_index_ignored_equals_flag(arg) {
        } else {
            return Err(unsupported_compat_arg("pip list", arg));
        }
        index += 1;
    }
    if outdated && uptodate {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip list cannot combine --outdated and --uptodate".to_owned(),
        ));
    }
    Ok(PipCompatAction::List {
        format,
        verbose,
        outdated,
        uptodate,
        paths,
        user,
        exclude,
        editable,
        not_required,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        allow_prereleases,
    })
}

pub(crate) fn expand_pip_list_short_clusters(args: &[String]) -> Vec<String> {
    args.iter()
        .flat_map(|arg| {
            expand_pip_short_cluster(arg, &['o', 'u', 'e', 'l'], &['i', 'f'])
                .unwrap_or_else(|| vec![arg.clone()])
        })
        .collect()
}

pub(crate) fn parse_pip_list_format_value(value: &str) -> Result<PipListFormat, OmcRegistryError> {
    match value {
        "columns" => Ok(PipListFormat::Columns),
        "freeze" => Ok(PipListFormat::Freeze),
        "json" => Ok(PipListFormat::Json),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip list format `{other}`"
        ))),
    }
}
