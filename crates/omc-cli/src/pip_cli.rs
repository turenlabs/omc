//! pip CLI compat: command-action parsing, help/completion, config defaults,
//! install/freeze/list/show/check/outdated/cache/debug output, local-wheel build,
//! and the `run_pip_compat` dispatcher. Moved out of lib.rs (module split).

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs};

use sha2::{Digest, Sha256, Sha384, Sha512};

use omc_registry::{
    add_package_graph, install_locked_packages, install_project, read_constraint_files,
    read_lockfile, read_requirements_files, read_script_requirement_files, Ecosystem, LinkOptions,
    LockedPackage, OmcLock, OmcRegistryError, PackageSpec,
    PypiCheckIssue, PythonLocalRequirement,
};

pub(crate) fn run_pip_lock(project_dir: &Path, action: PipLockAction) -> Result<ExitCode, OmcRegistryError> {
    let PipInstallAction {
        specs,
        requirements,
        constraints,
        script_requirements,
        groups,
        report: _,
        dry_run: _,
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
        upgrade: _,
        force_reinstall: _,
        compatibility,
        target,
        prefix,
        root,
        user,
        vcs_requirements,
        allow,
        allow_flow,
        allow_all_host,
    } = action.install;

    if user {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip lock does not support --user".to_owned(),
        ));
    }
    if target.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip lock does not support --target".to_owned(),
        ));
    }
    if prefix.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip lock does not support --prefix".to_owned(),
        ));
    }
    if root.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip lock does not support --root".to_owned(),
        ));
    }

    let temp_project = TempOmcProject::empty("pip-lock")?;
    let mut options = LinkOptions::new(temp_project.path());
    options.save_manifest_dependency = false;
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    options.requirement_files = absolutize_paths(project_dir, requirements);
    options.constraint_files = absolutize_paths(project_dir, constraints);
    options.python_local_requirements =
        absolutize_python_local_requirements(project_dir, local_paths);
    let local_directories = absolutize_python_local_requirements(project_dir, local_directories);
    if !groups.is_empty() {
        options
            .python_local_requirements
            .push(PythonLocalRequirement::new(
                project_dir.to_path_buf(),
                groups.into_iter().collect(),
            ));
    }
    apply_pip_compat_index_options(
        &mut options,
        project_dir,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
    );
    apply_pip_environment_defaults_for_project(&mut options, project_dir);
    options.pypi_require_hashes = require_hashes;
    options.pypi_include_dependencies = !no_deps;
    options.pypi_allow_prereleases = allow_prereleases;
    options.pypi_release_controls = release_controls;
    options.pypi_uploaded_prior_to = uploaded_prior_to;
    options.pypi_binary_all = binary_all;
    options.pypi_binary_packages = binary_packages;
    apply_pip_compatibility_target(&mut options, compatibility);
    options.python_vcs_requirements = vcs_requirements;
    apply_pip_constraint_files_for_explicit_specs(&mut options)?;

    let mut resolved_specs = parse_package_specs(&specs, Some(Ecosystem::Pypi))?;
    resolved_specs.extend(parse_pip_archive_references(
        project_dir,
        &archive_references,
        &mut options,
    )?);
    resolved_specs.extend(prepare_pip_local_directory_archive_specs(
        project_dir,
        project_dir,
        local_directories,
        &mut options,
    )?);
    apply_pypi_requirement_files_with_local_directories(
        &mut options,
        &mut resolved_specs,
        project_dir,
        project_dir,
    )?;
    if !script_requirements.is_empty() {
        let requirements =
            read_script_requirement_files(&absolutize_paths(project_dir, script_requirements))?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            requirements,
            project_dir,
            project_dir,
        )?;
    }

    let has_project_inputs = !options.requirement_files.is_empty()
        || !options.python_local_requirements.is_empty()
        || !options.python_vcs_requirements.is_empty();
    if resolved_specs.is_empty() && !has_project_inputs {
        options
            .python_local_requirements
            .push(PythonLocalRequirement::new(
                project_dir.to_path_buf(),
                BTreeSet::new(),
            ));
    }

    let mut all_reports = Vec::new();
    if !options.requirement_files.is_empty()
        || !options.python_local_requirements.is_empty()
        || !options.python_vcs_requirements.is_empty()
    {
        all_reports.extend(lock_project(&options)?);
    }

    for spec in &resolved_specs {
        all_reports.extend(add_package_graph(spec, &options)?);
    }
    if !all_reports.is_empty() {
        print_link_reports(&all_reports);
    }

    let lock = read_lockfile(temp_project.path().join("omc.lock"))?;
    let output = pylock_toml_from_omc_lock(&lock);
    if action.output == Path::new("-") {
        print!("{output}");
    } else {
        let output_path = absolutize_path(project_dir, action.output);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&output_path, output)?;
        println!("wrote {}", output_path.display());
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn pip_args_with_config_defaults(
    project_dir: &Path,
    args: &[String],
) -> Result<Vec<String>, OmcRegistryError> {
    if pip_isolated_requested(args) {
        return Ok(args.to_vec());
    }

    let normalized = normalize_pip_global_args(args)?;
    let Some(command) = normalized.first().map(String::as_str) else {
        return Ok(args.to_vec());
    };

    let mut defaults = pip_config_file_default_args(project_dir, command)?;
    defaults.extend(pip_environment_default_args(command));
    if defaults.is_empty() {
        return Ok(args.to_vec());
    }

    let mut merged = Vec::with_capacity(normalized.len() + defaults.len());
    merged.push(command.to_owned());
    merged.extend(defaults);
    merged.extend(normalized.iter().skip(1).cloned());
    Ok(merged)
}

#[cfg(test)]
pub(crate) fn pip_args_with_environment_defaults(args: &[String]) -> Result<Vec<String>, OmcRegistryError> {
    if pip_isolated_requested(args) {
        return Ok(args.to_vec());
    }

    let normalized = normalize_pip_global_args(args)?;
    let Some(command) = normalized.first().map(String::as_str) else {
        return Ok(args.to_vec());
    };

    let defaults = pip_environment_default_args(command);
    if defaults.is_empty() {
        return Ok(args.to_vec());
    }

    let mut merged = Vec::with_capacity(normalized.len() + defaults.len());
    merged.push(command.to_owned());
    merged.extend(defaults);
    merged.extend(normalized.iter().skip(1).cloned());
    Ok(merged)
}

pub(crate) fn pip_isolated_requested(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--isolated") || pip_config_env_bool("isolated")
}

#[derive(Debug, Default)]
pub(crate) struct PipCliConfigDefaults {
    entries: Vec<(String, String)>,
    values: BTreeMap<String, Vec<String>>,
}

impl PipCliConfigDefaults {
    fn push(&mut self, key: String, value: String) {
        self.entries.push((key.clone(), value.clone()));
        self.values.entry(key).or_default().push(value);
    }

    fn last(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find_map(|(entry_key, value)| (entry_key == key).then_some(value.as_str()))
            .filter(|value| !value.trim().is_empty())
    }

    fn last_any(&self, keys: &[&str]) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find_map(|(entry_key, value)| {
                keys.contains(&entry_key.as_str()).then_some(value.as_str())
            })
            .filter(|value| !value.trim().is_empty())
    }

    fn tokens(&self, key: &str) -> Vec<String> {
        self.values
            .get(key)
            .into_iter()
            .flat_map(|values| values.iter())
            .flat_map(|value| shell_like_tokens(value))
            .collect()
    }
}

pub(crate) fn pip_config_file_default_args(
    project_dir: &Path,
    command: &str,
) -> Result<Vec<String>, OmcRegistryError> {
    let values = read_pip_cli_config_defaults(project_dir, command)?;
    let mut args = Vec::new();
    append_pip_default_args_from_config(&values, command, &mut args);
    Ok(args)
}

pub(crate) fn read_pip_cli_config_defaults(
    project_dir: &Path,
    command: &str,
) -> Result<PipCliConfigDefaults, OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let mut values = PipCliConfigDefaults::default();
    for path in pip_cli_config_default_paths(&project_dir) {
        read_pip_cli_config_defaults_file(&path, command, &mut values)?;
    }
    Ok(values)
}

pub(crate) fn pip_cli_config_default_paths(project_dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(test)]
    if let Some(path) = env::var_os("OMC_TEST_PIP_GLOBAL_CONFIG_FILE")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        paths.push(absolutize_path(project_dir, path));
    }
    #[cfg(not(test))]
    paths.push(pip_global_config_default_path(project_dir));

    if let Some(home) = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        paths.push(home.join(".pip").join("pip.conf"));
        paths.push(home.join(".config").join("pip").join("pip.conf"));
    }
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        paths.push(xdg.join("pip").join("pip.conf"));
    }
    paths.push(project_dir.join("pip.conf"));
    if let Some(path) = env::var_os("PIP_CONFIG_FILE")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        paths.push(absolutize_path(project_dir, path));
    }
    paths
}

pub(crate) fn read_pip_cli_config_defaults_file(
    path: &Path,
    command: &str,
    values: &mut PipCliConfigDefaults,
) -> Result<(), OmcRegistryError> {
    if !path.exists() {
        return Ok(());
    }
    parse_pip_cli_config_defaults_content(&fs::read_to_string(path)?, command, values);
    Ok(())
}

pub(crate) fn parse_pip_cli_config_defaults_content(
    content: &str,
    command: &str,
    values: &mut PipCliConfigDefaults,
) {
    let mut section = String::new();
    let mut multiline_key: Option<String> = None;
    for raw_line in content.lines() {
        let line = strip_pip_config_comment(raw_line);
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
                push_pip_cli_config_default(&section, key, trimmed, command, values);
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            multiline_key = None;
            continue;
        };
        let key = key.trim().to_ascii_lowercase().replace('_', "-");
        let value = value.trim();
        push_pip_cli_config_default(&section, &key, value, command, values);
        multiline_key = value.is_empty().then_some(key);
    }
}

pub(crate) fn push_pip_cli_config_default(
    section: &str,
    key: &str,
    value: &str,
    command: &str,
    values: &mut PipCliConfigDefaults,
) {
    if !pip_cli_config_section_applies(section, command) || !pip_cli_default_config_key(key) {
        return;
    }
    values.push(key.to_owned(), value.trim().to_owned());
}

pub(crate) fn pip_cli_config_section_applies(section: &str, command: &str) -> bool {
    section == "global"
        || section == command
        || (command == "lock" && section == "install")
        || (command == "index" && section == "index")
}

pub(crate) fn pip_cli_default_config_key(key: &str) -> bool {
    matches!(
        key,
        "target"
            | "prefix"
            | "root"
            | "user"
            | "dry-run"
            | "upgrade"
            | "report"
            | "requirement"
            | "constraint"
            | "build-constraint"
            | "no-deps"
            | "require-hashes"
            | "no-binary"
            | "only-binary"
            | "pre"
            | "all-releases"
            | "only-final"
            | "uploaded-prior-to"
            | "platform"
            | "python-version"
            | "implementation"
            | "abi"
            | "dest"
            | "destination-dir"
            | "wheel-dir"
    )
}

pub(crate) fn append_pip_default_args_from_config(
    values: &PipCliConfigDefaults,
    command: &str,
    args: &mut Vec<String>,
) {
    let install_like = matches!(command, "install" | "lock");
    let artifact_like = matches!(command, "download" | "wheel");
    let index_like = command == "index";

    if install_like {
        append_pip_value_arg_from_config(values, args, "target", "--target");
        append_pip_value_arg_from_config(values, args, "prefix", "--prefix");
        append_pip_value_arg_from_config(values, args, "root", "--root");
        append_pip_bool_arg_from_config(values, args, "user", "--user", "--user=false");
        append_pip_bool_arg_from_config(values, args, "dry-run", "--dry-run", "--dry-run=false");
        append_pip_bool_arg_from_config(values, args, "upgrade", "--upgrade", "--upgrade=false");
        append_pip_value_arg_from_config(values, args, "report", "--report");
    }

    if install_like || artifact_like {
        append_pip_token_args_from_config(values, args, "requirement", "--requirement");
        append_pip_token_args_from_config(values, args, "constraint", "--constraint");
        append_pip_token_args_from_config(values, args, "build-constraint", "--build-constraint");
        append_pip_bool_arg_from_config(values, args, "no-deps", "--no-deps", "--no-deps=false");
        append_pip_bool_arg_from_config(
            values,
            args,
            "require-hashes",
            "--require-hashes",
            "--require-hashes=false",
        );
        append_pip_repeated_value_args_from_config(values, args, "no-binary", "--no-binary");
        append_pip_repeated_value_args_from_config(values, args, "only-binary", "--only-binary");
    }

    if install_like || artifact_like || index_like {
        append_pip_bool_arg_from_config(values, args, "pre", "--pre", "--pre=false");
        append_pip_value_arg_from_config(values, args, "all-releases", "--all-releases");
        append_pip_value_arg_from_config(values, args, "only-final", "--only-final");
        append_pip_value_arg_from_config(values, args, "uploaded-prior-to", "--uploaded-prior-to");
        append_pip_token_args_from_config(values, args, "platform", "--platform");
        append_pip_value_arg_from_config(values, args, "python-version", "--python-version");
        append_pip_value_arg_from_config(values, args, "implementation", "--implementation");
        append_pip_token_args_from_config(values, args, "abi", "--abi");
    }

    if command == "download" {
        append_pip_value_arg_from_config_aliases(
            values,
            args,
            &["dest", "destination-dir"],
            "--dest",
        );
    }

    if command == "wheel" {
        append_pip_value_arg_from_config(values, args, "wheel-dir", "--wheel-dir");
    }
}

pub(crate) fn append_pip_value_arg_from_config(
    values: &PipCliConfigDefaults,
    args: &mut Vec<String>,
    key: &str,
    flag: &str,
) {
    if let Some(value) = values.last(key) {
        args.push(format!("{flag}={value}"));
    }
}

pub(crate) fn append_pip_value_arg_from_config_aliases(
    values: &PipCliConfigDefaults,
    args: &mut Vec<String>,
    keys: &[&str],
    flag: &str,
) {
    if let Some(value) = values.last_any(keys) {
        args.push(format!("{flag}={value}"));
    }
}

pub(crate) fn append_pip_repeated_value_args_from_config(
    values: &PipCliConfigDefaults,
    args: &mut Vec<String>,
    key: &str,
    flag: &str,
) {
    if let Some(repeated) = values.values.get(key) {
        for value in repeated {
            if !value.trim().is_empty() {
                args.push(format!("{flag}={value}"));
            }
        }
    }
}

pub(crate) fn append_pip_token_args_from_config(
    values: &PipCliConfigDefaults,
    args: &mut Vec<String>,
    key: &str,
    flag: &str,
) {
    for value in values.tokens(key) {
        args.push(format!("{flag}={value}"));
    }
}

pub(crate) fn append_pip_bool_arg_from_config(
    values: &PipCliConfigDefaults,
    args: &mut Vec<String>,
    key: &str,
    true_arg: &str,
    false_arg: &str,
) {
    if let Some(value) = values.last(key) {
        if config_bool(value) {
            args.push(true_arg.to_owned());
        } else if config_false(value) {
            args.push(false_arg.to_owned());
        }
    }
}

pub(crate) fn pip_environment_default_args(command: &str) -> Vec<String> {
    let mut args = Vec::new();
    let install_like = matches!(command, "install" | "lock");
    let artifact_like = matches!(command, "download" | "wheel");
    let index_like = command == "index";

    if install_like {
        if let Some(target) = pip_config_env("target") {
            args.push(format!("--target={target}"));
        }
        if let Some(prefix) = pip_config_env("prefix") {
            args.push(format!("--prefix={prefix}"));
        }
        if let Some(root) = pip_config_env("root") {
            args.push(format!("--root={root}"));
        }
        if let Some(user) = pip_config_env("user") {
            if config_bool(&user) {
                args.push("--user".to_owned());
            } else if config_false(&user) {
                args.push("--user=false".to_owned());
            }
        }
        append_pip_bool_arg_from_env(&mut args, "dry-run", "--dry-run", "--dry-run=false");
        append_pip_bool_arg_from_env(&mut args, "upgrade", "--upgrade", "--upgrade=false");
        if let Some(report) = pip_config_env("report") {
            args.push(format!("--report={report}"));
        }
    }

    if install_like || artifact_like {
        for requirement in pip_config_env_tokens("requirement") {
            args.push(format!("--requirement={requirement}"));
        }
        for constraint in pip_config_env_tokens("constraint") {
            args.push(format!("--constraint={constraint}"));
        }
        for constraint in pip_config_env_tokens("build-constraint") {
            args.push(format!("--build-constraint={constraint}"));
        }
        append_pip_bool_arg_from_env(&mut args, "no-deps", "--no-deps", "--no-deps=false");
        append_pip_bool_arg_from_env(
            &mut args,
            "require-hashes",
            "--require-hashes",
            "--require-hashes=false",
        );
        if let Some(no_binary) = pip_config_env("no-binary") {
            args.push(format!("--no-binary={no_binary}"));
        }
        if let Some(only_binary) = pip_config_env("only-binary") {
            args.push(format!("--only-binary={only_binary}"));
        }
    }

    if install_like || artifact_like || index_like {
        append_pip_bool_arg_from_env(&mut args, "pre", "--pre", "--pre=false");
        if let Some(all_releases) = pip_config_env("all-releases") {
            args.push(format!("--all-releases={all_releases}"));
        }
        if let Some(only_final) = pip_config_env("only-final") {
            args.push(format!("--only-final={only_final}"));
        }
        if let Some(uploaded_prior_to) = pip_config_env("uploaded-prior-to") {
            args.push(format!("--uploaded-prior-to={uploaded_prior_to}"));
        }
        for platform in pip_config_env_tokens("platform") {
            args.push(format!("--platform={platform}"));
        }
        if let Some(version) = pip_config_env("python-version") {
            args.push(format!("--python-version={version}"));
        }
        if let Some(implementation) = pip_config_env("implementation") {
            args.push(format!("--implementation={implementation}"));
        }
        for abi in pip_config_env_tokens("abi") {
            args.push(format!("--abi={abi}"));
        }
    }

    if command == "download" {
        if let Some(dest) = pip_config_env("dest").or_else(|| pip_config_env("destination-dir")) {
            args.push(format!("--dest={dest}"));
        }
    }

    if command == "wheel" {
        if let Some(wheel_dir) = pip_config_env("wheel-dir") {
            args.push(format!("--wheel-dir={wheel_dir}"));
        }
    }

    args
}

pub(crate) fn append_pip_bool_arg_from_env(
    args: &mut Vec<String>,
    key: &str,
    true_arg: &str,
    false_arg: &str,
) {
    if let Some(value) = pip_config_env(key) {
        if config_bool(&value) {
            args.push(true_arg.to_owned());
        } else if config_false(&value) {
            args.push(false_arg.to_owned());
        }
    }
}

pub(crate) fn pip_config_env_bool(name: &str) -> bool {
    pip_config_env(name)
        .map(|value| config_bool(&value))
        .unwrap_or(false)
}

pub(crate) fn pip_config_env(name: &str) -> Option<String> {
    let env_name = name.replace('-', "_");
    let upper = format!("PIP_{}", env_name.to_ascii_uppercase());
    env::var(upper)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(crate) fn pip_config_env_tokens(name: &str) -> Vec<String> {
    pip_config_env(name)
        .map(|value| shell_like_tokens(&value))
        .unwrap_or_default()
}

pub(crate) fn run_pip_compat(
    project_dir: &Path,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    run_pip_compat_with_cwd(project_dir, args, project_dir)
}

pub(crate) fn run_pip_compat_with_cwd(
    project_dir: &Path,
    args: &[String],
    invocation_cwd: &Path,
) -> Result<ExitCode, OmcRegistryError> {
    let _pip_config_file = scoped_relative_env_path("PIP_CONFIG_FILE", invocation_cwd);
    if pip_auto_complete_requested() {
        print_pip_auto_completion(project_dir)?;
        return Ok(ExitCode::SUCCESS);
    }

    let args = pip_args_with_config_defaults(project_dir, args)?;
    match parse_pip_compat_action(&args)? {
        PipCompatAction::Help { topic } => print_pip_help(topic.as_deref()),
        PipCompatAction::Version => println!("pip {} from OMC", env!("CARGO_PKG_VERSION")),
        PipCompatAction::Completion { shell } => print_pip_completion(shell),
        PipCompatAction::Lock(mut action) => {
            absolutize_pip_lock_action_paths(invocation_cwd, &mut action);
            return run_pip_lock(project_dir, *action);
        }
        PipCompatAction::Install(mut action) => {
            absolutize_pip_install_action_paths(invocation_cwd, &mut action);
            let action = *action;
            if action.user && action.target.is_some() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip install cannot combine --user and --target".to_owned(),
                ));
            }
            if action.user && action.prefix.is_some() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip install cannot combine --user and --prefix".to_owned(),
                ));
            }
            if action.target.is_some() && action.prefix.is_some() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip install cannot combine --target and --prefix".to_owned(),
                ));
            }
            if action.dry_run {
                return run_pip_install_dry_run(project_dir, action);
            }
            if action.user {
                return run_pip_install_user(project_dir, action);
            }
            if action.target.is_some() {
                return run_pip_install_target(project_dir, action);
            }
            if action.prefix.is_some() {
                return run_pip_install_prefix(project_dir, action);
            }
            if action.root.is_some() {
                return run_pip_install_root(project_dir, action);
            }
            let PipInstallAction {
                specs,
                requirements,
                constraints,
                script_requirements,
                groups,
                report,
                dry_run: _,
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
                upgrade: _,
                force_reinstall: _,
                compatibility,
                target,
                prefix: _,
                root: _,
                user: _,
                vcs_requirements,
                allow,
                allow_flow,
                allow_all_host,
            } = action;
            let report_stdout = pip_install_report_to_stdout(report.as_deref());
            let requested_count = specs.len()
                + requirements.len()
                + script_requirements.len()
                + archive_references.len()
                + local_paths.len()
                + local_directories.len()
                + groups.len()
                + vcs_requirements.len();
            if requested_count == 0 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip install needs at least one package, archive, local path, VCS requirement, or requirement file"
                        .to_owned(),
                ));
            }
            if specs.is_empty()
                && archive_references.is_empty()
                && local_directories.is_empty()
                && script_requirements.is_empty()
            {
                let mut options = LinkOptions::new(project_dir);
                options.discover_project_requirements = !groups.is_empty();
                apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
                options.requirement_files = absolutize_paths(project_dir, requirements);
                options.constraint_files = absolutize_paths(project_dir, constraints);
                options.python_local_requirements =
                    absolutize_python_local_requirements(project_dir, local_paths);
                options.project_extras = groups.into_iter().collect();
                apply_pip_compat_index_options(
                    &mut options,
                    project_dir,
                    index_url,
                    extra_index_urls,
                    find_links,
                    no_index,
                );
                options.pypi_require_hashes = require_hashes;
                options.pypi_include_dependencies = !no_deps;
                options.pypi_allow_prereleases = allow_prereleases;
                options.pypi_release_controls = release_controls.clone();
                options.pypi_uploaded_prior_to = uploaded_prior_to.clone();
                options.pypi_binary_all = binary_all;
                options.pypi_binary_packages = binary_packages;
                apply_pip_compatibility_target(&mut options, compatibility);
                options.python_target_dir = target.map(|path| absolutize_path(project_dir, path));
                options.python_vcs_requirements = vcs_requirements;
                let mut specs = Vec::new();
                if apply_pypi_requirement_files_with_local_directories(
                    &mut options,
                    &mut specs,
                    project_dir,
                    project_dir,
                )? {
                    let mut all_reports = Vec::new();
                    for spec in &specs {
                        all_reports.extend(add_package_graph(spec, &options)?);
                    }
                    prune_locked_package_versions(
                        project_dir,
                        &locked_packages_from_reports(&all_reports),
                    )?;
                    if !report_stdout {
                        print_link_reports(&all_reports);
                    }
                }
                let install = install_project(&options)?;
                if !report_stdout {
                    print_install_report(&install);
                }
                write_pip_install_report(project_dir, report.as_deref(), &install)?;
            } else {
                let mut options = LinkOptions::new(project_dir);
                options.discover_project_requirements = !groups.is_empty();
                let local_directories =
                    absolutize_python_local_requirements(project_dir, local_directories);
                apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
                options.requirement_files = absolutize_paths(project_dir, requirements);
                options.constraint_files = absolutize_paths(project_dir, constraints);
                options.python_local_requirements =
                    absolutize_python_local_requirements(project_dir, local_paths);
                options.project_extras = groups.into_iter().collect();
                apply_pip_compat_index_options(
                    &mut options,
                    project_dir,
                    index_url,
                    extra_index_urls,
                    find_links,
                    no_index,
                );
                options.pypi_require_hashes = require_hashes;
                options.pypi_include_dependencies = !no_deps;
                options.pypi_allow_prereleases = allow_prereleases;
                options.pypi_release_controls = release_controls;
                options.pypi_uploaded_prior_to = uploaded_prior_to;
                options.pypi_binary_all = binary_all;
                options.pypi_binary_packages = binary_packages;
                apply_pip_compatibility_target(&mut options, compatibility);
                options.python_target_dir = target.map(|path| absolutize_path(project_dir, path));
                options.python_vcs_requirements = vcs_requirements;
                apply_pip_environment_defaults_for_project(&mut options, project_dir);
                apply_pip_constraint_files_for_explicit_specs(&mut options)?;
                let mut specs = parse_package_specs(&specs, Some(Ecosystem::Pypi))?;
                specs.extend(parse_pip_archive_references(
                    project_dir,
                    &archive_references,
                    &mut options,
                )?);
                specs.extend(prepare_pip_local_directory_archive_specs(
                    project_dir,
                    project_dir,
                    local_directories,
                    &mut options,
                )?);
                apply_pypi_requirement_files_with_local_directories(
                    &mut options,
                    &mut specs,
                    project_dir,
                    project_dir,
                )?;
                if !script_requirements.is_empty() {
                    let requirements = read_script_requirement_files(&absolutize_paths(
                        project_dir,
                        script_requirements,
                    ))?;
                    apply_pypi_install_requirements(
                        &mut options,
                        &mut specs,
                        requirements,
                        project_dir,
                        project_dir,
                    )?;
                }
                let mut all_reports = Vec::new();
                for spec in &specs {
                    all_reports.extend(add_package_graph(spec, &options)?);
                }
                prune_locked_package_versions(
                    project_dir,
                    &locked_packages_from_reports(&all_reports),
                )?;
                if !report_stdout {
                    print_link_reports(&all_reports);
                }
                let install = if options.requirement_files.is_empty()
                    && options.constraint_files.is_empty()
                    && options.python_local_paths.is_empty()
                    && options.python_local_requirements.is_empty()
                    && options.python_target_dir.is_none()
                    && options.project_extras.is_empty()
                    && options.pypi_include_dependencies
                {
                    install_locked_packages(project_dir)?
                } else if options.requirement_files.is_empty()
                    && options.constraint_files.is_empty()
                    && options.python_local_paths.is_empty()
                    && options.python_local_requirements.is_empty()
                {
                    install_locked_project(&options)?
                } else {
                    install_project(&options)?
                };
                if !report_stdout {
                    println!();
                    print_install_report(&install);
                }
                write_pip_install_report(project_dir, report.as_deref(), &install)?;
            }
        }
        PipCompatAction::Download(mut action) => {
            absolutize_pip_download_action_paths(invocation_cwd, &mut action);
            download_pip_packages(project_dir, *action)?;
        }
        PipCompatAction::Wheel(mut action) => {
            absolutize_pip_download_action_paths(invocation_cwd, &mut action);
            download_pip_packages(project_dir, *action)?;
        }
        PipCompatAction::Uninstall {
            mut specs,
            requirements,
            user,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            specs.extend(pip_uninstall_specs_from_requirements(
                invocation_cwd,
                requirements,
            )?);
            if specs.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip uninstall needs at least one package or non-empty requirement file"
                        .to_owned(),
                ));
            }
            if user {
                return run_pip_uninstall_user(&specs, &allow, &allow_flow, allow_all_host);
            }
            let _ = remove_specs(
                project_dir,
                &specs,
                Some(Ecosystem::Pypi),
                CliPolicyArgs::new(&allow, &allow_flow, allow_all_host),
                false,
                true,
                false,
                true,
                true,
                true,
            )?;
        }
        PipCompatAction::Show { specs, files, user } => {
            if user {
                let paths = pip_effective_scope_paths(invocation_cwd, &[], true)?;
                return print_pip_path_show(project_dir, &paths, &specs, files);
            }
            return print_locked_pip_show(project_dir, &specs, files);
        }
        PipCompatAction::Hash { algorithm, paths } => {
            print_pip_hash(invocation_cwd, algorithm, paths)?
        }
        PipCompatAction::Cache { action, cache_dir } => {
            let cache_dir = pip_cache_arg_or_env(invocation_cwd, cache_dir);
            return print_pip_cache(project_dir, action, cache_dir.as_deref());
        }
        PipCompatAction::Check { user } => {
            if user {
                let paths = pip_effective_scope_paths(invocation_cwd, &[], true)?;
                return print_pip_path_check(project_dir, &paths);
            }
            return print_locked_pip_check(project_dir);
        }
        PipCompatAction::Debug { action } => print_pip_debug(project_dir, invocation_cwd, action)?,
        PipCompatAction::Inspect { paths, user } => {
            let paths = pip_effective_scope_paths(invocation_cwd, &paths, user)?;
            if paths.is_empty() {
                print_locked_pip_inspect(project_dir)?
            } else {
                print_pip_path_inspect(project_dir, &paths)?
            }
        }
        PipCompatAction::Freeze { action } => {
            let paths = pip_effective_scope_paths(invocation_cwd, &action.paths, action.user)?;
            let requirements = absolutize_paths(invocation_cwd, action.requirements);
            if paths.is_empty() {
                print_locked_freeze(
                    project_dir,
                    &action.exclude,
                    action.exclude_editable,
                    &requirements,
                )?
            } else {
                print_pip_path_freeze(
                    project_dir,
                    &paths,
                    &action.exclude,
                    action.exclude_editable,
                    &requirements,
                )?
            }
        }
        PipCompatAction::List {
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
        } => {
            let paths = pip_effective_scope_paths(invocation_cwd, &paths, user)?;
            let find_links = absolutize_pip_find_links(invocation_cwd, find_links);
            if outdated || uptodate {
                print_pip_outdated(
                    project_dir,
                    PipOutdatedOptions {
                        format,
                        verbose,
                        paths: &paths,
                        exclude: &exclude,
                        editable,
                        not_required,
                        uptodate,
                        index_url,
                        extra_index_urls,
                        find_links,
                        no_index,
                        allow_prereleases,
                    },
                )?;
            } else if !paths.is_empty() {
                print_pip_path_list(
                    project_dir,
                    format,
                    verbose,
                    &paths,
                    &exclude,
                    editable,
                    not_required,
                )?;
            } else {
                match format {
                    PipListFormat::Columns => print_locked_pip_list(
                        project_dir,
                        PipListFormat::Columns,
                        verbose,
                        &exclude,
                        editable,
                        not_required,
                    )?,
                    PipListFormat::Freeze => {
                        if not_required {
                            print_locked_pip_list(
                                project_dir,
                                PipListFormat::Freeze,
                                verbose,
                                &exclude,
                                editable,
                                true,
                            )?
                        } else {
                            print_locked_pip_list(
                                project_dir,
                                PipListFormat::Freeze,
                                verbose,
                                &exclude,
                                editable,
                                false,
                            )?
                        }
                    }
                    PipListFormat::Json => print_locked_pip_list(
                        project_dir,
                        PipListFormat::Json,
                        verbose,
                        &exclude,
                        editable,
                        not_required,
                    )?,
                }
            }
        }
        PipCompatAction::IndexVersions {
            package,
            index_url,
            extra_index_urls,
            find_links,
            no_index,
            allow_prereleases,
            release_controls,
            uploaded_prior_to,
            compatibility,
            json,
        } => print_pip_index_versions(
            project_dir,
            &package,
            PipIndexSearchOptions {
                index_url,
                extra_index_urls,
                find_links: absolutize_pip_find_links(invocation_cwd, find_links),
                no_index,
                allow_prereleases,
                release_controls,
                uploaded_prior_to,
                compatibility,
            },
            json,
        )?,
        PipCompatAction::Search { query } => return print_pip_search_deprecated(query),
        PipCompatAction::Config { action } => print_pip_config(project_dir, action)?,
        PipCompatAction::ConfigEdit { location, editor } => {
            return run_pip_config_edit(project_dir, invocation_cwd, location, editor);
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn absolutize_pip_lock_action_paths(base_dir: &Path, action: &mut PipLockAction) {
    absolutize_pip_install_action_paths(base_dir, &mut action.install);
    action.output = absolutize_path(base_dir, std::mem::take(&mut action.output));
}

pub(crate) fn absolutize_pip_install_action_paths(base_dir: &Path, action: &mut PipInstallAction) {
    action.requirements = absolutize_paths(base_dir, std::mem::take(&mut action.requirements));
    action.constraints = absolutize_paths(base_dir, std::mem::take(&mut action.constraints));
    action.script_requirements =
        absolutize_paths(base_dir, std::mem::take(&mut action.script_requirements));
    action.report = action.report.take().map(|path| {
        if path == Path::new("-") {
            path
        } else {
            absolutize_path(base_dir, path)
        }
    });
    action.archive_references =
        absolutize_pip_archive_references(base_dir, std::mem::take(&mut action.archive_references));
    action.local_paths =
        absolutize_python_local_requirements(base_dir, std::mem::take(&mut action.local_paths));
    action.find_links = absolutize_pip_find_links(base_dir, std::mem::take(&mut action.find_links));
    action.target = action
        .target
        .take()
        .map(|path| absolutize_path(base_dir, path));
    action.prefix = action
        .prefix
        .take()
        .map(|path| absolutize_path(base_dir, path));
    action.root = action
        .root
        .take()
        .map(|path| absolutize_path(base_dir, path));
}

pub(crate) fn absolutize_pip_download_action_paths(base_dir: &Path, action: &mut PipDownloadAction) {
    action.requirements = absolutize_paths(base_dir, std::mem::take(&mut action.requirements));
    action.constraints = absolutize_paths(base_dir, std::mem::take(&mut action.constraints));
    action.archive_references =
        absolutize_pip_archive_references(base_dir, std::mem::take(&mut action.archive_references));
    action.local_paths =
        absolutize_python_local_requirements(base_dir, std::mem::take(&mut action.local_paths));
    action.find_links = absolutize_pip_find_links(base_dir, std::mem::take(&mut action.find_links));
    action.destination = absolutize_path(base_dir, std::mem::take(&mut action.destination));
}

pub(crate) fn absolutize_pip_archive_references(base_dir: &Path, references: Vec<String>) -> Vec<String> {
    references
        .into_iter()
        .map(|reference| {
            let (source, fragment) = reference
                .split_once('#')
                .map(|(source, fragment)| (source, Some(fragment)))
                .unwrap_or((reference.as_str(), None));
            if source.contains("://") || source.contains(" @ ") || Path::new(source).is_absolute() {
                return reference;
            }
            let mut absolute = absolutize_path(base_dir, PathBuf::from(source))
                .to_string_lossy()
                .into_owned();
            if let Some(fragment) = fragment {
                absolute.push('#');
                absolute.push_str(fragment);
            }
            absolute
        })
        .collect()
}

pub(crate) fn absolutize_pip_find_links(base_dir: &Path, find_links: Vec<String>) -> Vec<String> {
    find_links
        .into_iter()
        .map(|source| normalize_pip_compat_find_links(base_dir, source))
        .collect()
}

pub(crate) fn pip_help_text(topic: Option<&str>) -> String {
    match topic.and_then(pip_help_topic) {
        None => pip_general_help_text(),
        Some("completion") => pip_command_help(
            "pip completion --bash|--zsh|--fish",
            &["Print an OMC pip shell-completion script for bash, zsh, or fish."],
        ),
        Some("install") => pip_command_help(
            "pip install [<requirement>...]",
            &[
                "Resolve, verify, lock, and install PyPI packages with OMC.",
                "Supports requirements/constraints, build constraints, pylock.toml inputs, inline script requirements, indexes, find-links, no-index, hashes, no-deps, install reports, dry-runs, binary policy, target dirs, local archives, local directories, editable paths, and editable VCS requirements.",
            ],
        ),
        Some("lock") => pip_command_help(
            "pip lock [<requirement>...]",
            &[
                "Resolve and verify PyPI requirements with OMC, then write a pylock.toml-style lock file without installing packages.",
                "Supports install-style requirements, constraints, build constraints, inline script requirements, indexes, find-links, hashes, no-deps, local paths, editable VCS requirements, --group, and -o/--output.",
            ],
        ),
        Some("download") => pip_command_help(
            "pip download [<requirement>...]",
            &["Download locked PyPI archives into a destination directory. Shares install-style requirement, build-constraint, and index flags."],
        ),
        Some("wheel") => pip_command_help(
            "pip wheel [<requirement>...]",
            &["Populate a wheelhouse with resolved wheel artifacts, falling back to source distributions when no wheel is available. Shares install-style requirement, build-constraint, and index flags; OMC does not execute source builds."],
        ),
        Some("uninstall") => pip_command_help(
            "pip uninstall <package>...",
            &["Remove OMC-managed PyPI dependencies and reinstall the remaining graph. Supports -r/--requirement and --user for OMC-managed Python user state."],
        ),
        Some("freeze") => pip_command_help(
            "pip freeze",
            &["Print locked PyPI requirements, including local editable and VCS entries where present."],
        ),
        Some("list") => pip_command_help(
            "pip list",
            &["List locked PyPI packages. Supports --format=columns|freeze|json and --outdated."],
        ),
        Some("show") => pip_command_help(
            "pip show <package>...",
            &["Show locked package metadata. Supports -f/--files and --user for OMC-managed Python user state."],
        ),
        Some("check") => pip_command_help(
            "pip check",
            &["Validate locked PyPI dependency requirements. Supports --user for OMC-managed Python user state."],
        ),
        Some("inspect") => pip_command_help(
            "pip inspect",
            &["Print a JSON report for locked PyPI packages or --path target directories in pip inspect shape."],
        ),
        Some("debug") => pip_command_help(
            "pip debug",
            &["Print OMC compatibility diagnostics, including project paths, cache, index config, lockfile status, and optional target platform/Python/ABI args."],
        ),
        Some("hash") => pip_command_help(
            "pip hash <file>...",
            &["Hash local files with sha256, sha384, or sha512."],
        ),
        Some("cache") => pip_command_help(
            "pip cache <dir|info|list|remove|purge>",
            &["Inspect or clear OMC's PyPI cache."],
        ),
        Some("search") => pip_command_help(
            "pip search <query>",
            &[
                "Recognize pip's deprecated PyPI search command and return PyPI's XML-RPC deprecation guidance.",
                "Use pip index versions <package> for package version lookup.",
            ],
        ),
        Some("index") => pip_command_help(
            "pip index versions <package>",
            &["List available package versions from the configured index. Supports --json and index flags."],
        ),
        Some("config") => pip_command_help(
            "pip config <get|set|unset|list|debug|edit> ...",
            &["Read, update, debug, and edit pip config used by OMC. Supports --site, --user, --global, --editor, and --json where relevant."],
        ),
        Some(_) => pip_command_help(
            "pip help [command]",
            &["No focused OMC help is available for that topic yet."],
        ),
    }
}

pub(crate) fn pip_general_help_text() -> String {
    pip_command_help(
        "pip <command>",
        &[
            "OMC pip compatibility runs supported pip workflows through OMC's resolver, verifier, lockfile, cache, and isolated Python site-packages.",
            "Supported commands: install, lock, download, wheel, uninstall, freeze, list, show, check, inspect, debug, hash, cache, search, index versions, config, completion.",
            "Use `pip help <command>` for focused OMC compatibility notes.",
        ],
    )
}

pub(crate) fn pip_command_help(usage: &str, lines: &[&str]) -> String {
    let mut output = format!("OMC pip compatibility\n\nUsage: {usage}\n");
    if !lines.is_empty() {
        output.push('\n');
        for line in lines {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

pub(crate) fn pip_help_topic(topic: &str) -> Option<&'static str> {
    match topic {
        "help" | "--help" | "-h" => None,
        "completion" => Some("completion"),
        "install" => Some("install"),
        "lock" => Some("lock"),
        "download" => Some("download"),
        "wheel" => Some("wheel"),
        "uninstall" | "remove" => Some("uninstall"),
        "freeze" => Some("freeze"),
        "list" => Some("list"),
        "show" => Some("show"),
        "check" => Some("check"),
        "inspect" => Some("inspect"),
        "debug" => Some("debug"),
        "hash" => Some("hash"),
        "cache" => Some("cache"),
        "search" => Some("search"),
        "index" => Some("index"),
        "config" => Some("config"),
        _ => Some("unknown"),
    }
}

pub(crate) const PIP_COMPLETION_COMMANDS: &[&str] = &[
    "cache",
    "check",
    "completion",
    "config",
    "debug",
    "download",
    "freeze",
    "hash",
    "help",
    "index",
    "inspect",
    "install",
    "list",
    "lock",
    "search",
    "show",
    "uninstall",
    "wheel",
];

pub(crate) const PIP_COMPLETION_OPTIONS: &[&str] = &[
    "--help",
    "--isolated",
    "--require-virtualenv",
    "--verbose",
    "--quiet",
    "--log",
    "--proxy",
    "--retries",
    "--timeout",
    "--exists-action",
    "--trusted-host",
    "--cert",
    "--client-cert",
    "--cache-dir",
    "--no-cache-dir",
    "--disable-pip-version-check",
    "--allow",
    "--allow-all-host",
];

pub(crate) const PIP_COMPLETION_PACKAGE_COMMANDS: &[&str] = &["show", "uninstall"];

pub(crate) fn pip_auto_complete_requested() -> bool {
    env::var_os("PIP_AUTO_COMPLETE").is_some()
}

pub(crate) fn pip_completion_words_from_env() -> Vec<String> {
    env::var("COMP_WORDS")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

pub(crate) fn pip_completion_suggestions(project_dir: &Path, words: &[String], cword: usize) -> Vec<String> {
    let original_len = words.len();
    let words = completion_words_without_program(words, &["pip", "pip3"]);
    let adjusted_cword = if words.len() != original_len {
        cword.saturating_sub(1)
    } else {
        cword
    };
    let current = words
        .get(adjusted_cword)
        .or_else(|| {
            (adjusted_cword < words.len())
                .then(|| words.last())
                .flatten()
        })
        .map(String::as_str)
        .unwrap_or("");
    if words.is_empty() || adjusted_cword == 0 {
        return filter_completion_values(PIP_COMPLETION_COMMANDS, current);
    }
    if current.starts_with('-') {
        return filter_completion_values(PIP_COMPLETION_OPTIONS, current);
    }

    let command = words.first().map(String::as_str).unwrap_or("");
    if PIP_COMPLETION_PACKAGE_COMMANDS.contains(&command) {
        return completion_filter_owned(
            completion_locked_package_names(project_dir, Ecosystem::Pypi),
            current,
        );
    }
    Vec::new()
}

pub(crate) fn pip_bash_completion_script() -> &'static str {
    r#"# omc pip bash completion start
_omc_pip_completion()
{
    COMPREPLY=( $( COMP_WORDS="${COMP_WORDS[*]}" \
                   COMP_CWORD=$COMP_CWORD \
                   PIP_AUTO_COMPLETE=1 pip 2>/dev/null ) )
}
complete -o default -F _omc_pip_completion pip pip3
# omc pip bash completion end
"#
}

pub(crate) fn pip_zsh_completion_script() -> &'static str {
    r#"# omc pip zsh completion start
function _omc_pip_completion {
  local words cword
  read -Ac words
  read -cn cword
  reply=( $( COMP_WORDS="$words[*]" \
             COMP_CWORD=$(( cword-1 )) \
             PIP_AUTO_COMPLETE=1 pip 2>/dev/null ))
}
compctl -K _omc_pip_completion pip pip3
# omc pip zsh completion end
"#
}

pub(crate) fn pip_fish_completion_script() -> &'static str {
    r#"# omc pip fish completion start
function __fish_complete_omc_pip
    set -lx COMP_WORDS (commandline -o) ""
    set -lx COMP_CWORD (math (contains -i -- (commandline -t) $COMP_WORDS)-1)
    set -lx PIP_AUTO_COMPLETE 1
    string split \n -- (pip)
end
complete -fa "(__fish_complete_omc_pip)" -c pip
complete -fa "(__fish_complete_omc_pip)" -c pip3
# omc pip fish completion end
"#
}

#[derive(Debug)]
pub(crate) struct PipIndexSearchOptions {
    pub(crate) index_url: Option<String>,
    pub(crate) extra_index_urls: Vec<String>,
    pub(crate) find_links: Vec<String>,
    pub(crate) no_index: bool,
    pub(crate) allow_prereleases: bool,
    pub(crate) release_controls: PypiReleaseControls,
    pub(crate) uploaded_prior_to: Option<String>,
    pub(crate) compatibility: PipCompatibilityTarget,
}

pub(crate) fn pip_hash_digest(algorithm: PipHashAlgorithm, bytes: &[u8]) -> String {
    let digest = match algorithm {
        PipHashAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
        PipHashAlgorithm::Sha384 => Sha384::digest(bytes).to_vec(),
        PipHashAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
    };
    digest
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

pub(crate) fn download_pip_packages(
    project_dir: &Path,
    action: PipDownloadAction,
) -> Result<(), OmcRegistryError> {
    let PipDownloadAction {
        specs,
        requirements,
        constraints,
        archive_references,
        mut local_paths,
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
    } = action;

    let destination = absolutize_path(project_dir, destination);
    fs::create_dir_all(&destination)?;

    let mut options = LinkOptions::new(project_dir);
    options.save_manifest_dependency = false;
    options.discover_project_requirements = false;
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    apply_pip_compat_index_options(
        &mut options,
        project_dir,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
    );
    options.requirement_files = absolutize_paths(project_dir, requirements);
    options.constraint_files = absolutize_paths(project_dir, constraints);
    apply_pip_environment_defaults_for_project(&mut options, project_dir);
    options.pypi_require_hashes = require_hashes;
    options.pypi_include_dependencies = !no_deps;
    options.pypi_allow_prereleases = allow_prereleases;
    options.pypi_release_controls = release_controls;
    options.pypi_uploaded_prior_to = uploaded_prior_to;
    options.pypi_binary_all = binary_all;
    options.pypi_binary_packages = binary_packages;
    apply_pip_compatibility_target(&mut options, compatibility);
    let had_requirement_sources = !options.requirement_files.is_empty();

    let mut resolved_specs = parse_package_specs(&specs, Some(Ecosystem::Pypi))?;
    resolved_specs.extend(parse_pip_archive_references(
        project_dir,
        &archive_references,
        &mut options,
    )?);
    if !options.requirement_files.is_empty() {
        let requirements = read_requirements_files(&options.requirement_files)?;
        apply_pypi_download_requirements(
            &mut options,
            &mut resolved_specs,
            &mut local_paths,
            requirements,
            true,
        )?;
    }
    if !options.constraint_files.is_empty() {
        let constraints = read_constraint_files(&options.constraint_files)?;
        apply_pypi_download_requirements(
            &mut options,
            &mut resolved_specs,
            &mut local_paths,
            constraints,
            false,
        )?;
    }
    if resolved_specs.is_empty() && local_paths.is_empty() {
        if had_requirement_sources {
            return Ok(());
        }
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip download/wheel needs at least one package, archive, or requirement file"
                .to_owned(),
        ));
    }
    if options.pypi_include_dependencies && !local_paths.is_empty() {
        resolved_specs.extend(collect_pip_local_wheel_dependencies(
            project_dir,
            &mut local_paths,
        )?);
    }

    if !resolved_specs.is_empty() {
        let mut reports = Vec::new();
        for spec in &resolved_specs {
            reports.extend(add_package_graph(spec, &options)?);
        }
        copy_downloaded_pypi_archives(project_dir, &destination, &reports)?;
    }
    if !local_paths.is_empty() {
        build_pip_local_wheels(
            project_dir,
            &destination,
            &local_paths,
            options.pypi_include_dependencies,
        )?;
    }
    Ok(())
}

pub(crate) fn prepare_pip_local_directory_archive_specs(
    source_project_dir: &Path,
    wheel_project_dir: &Path,
    mut requirements: Vec<PythonLocalRequirement>,
    options: &mut LinkOptions,
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    if requirements.is_empty() {
        return Ok(Vec::new());
    }

    let wheelhouse = wheel_project_dir
        .join(".omc")
        .join("python")
        .join("local-wheels");
    if wheelhouse.exists() {
        fs::remove_dir_all(&wheelhouse)?;
    }
    fs::create_dir_all(&wheelhouse)?;

    let requested_requirements = requirements.len();
    if options.pypi_include_dependencies {
        let _ = collect_pip_local_wheel_dependencies(source_project_dir, &mut requirements)?;
    }
    build_pip_local_wheels(
        source_project_dir,
        &wheelhouse,
        &requirements,
        options.pypi_include_dependencies,
    )?;

    let wheelhouse_value = wheelhouse.to_string_lossy().into_owned();
    if !options.pypi_find_links.contains(&wheelhouse_value) {
        options.pypi_find_links.push(wheelhouse_value);
    }

    let mut specs = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, requirement) in requirements.into_iter().enumerate() {
        let package_dir = resolve_pip_local_wheel_path(source_project_dir, &requirement)?;
        let metadata = read_pip_local_wheel_metadata(&package_dir, &requirement.extras)?;
        let wheel_path = wheelhouse.join(pip_local_wheel_filename(&metadata));
        let wheel_url = reqwest::Url::from_file_path(&wheel_path).map_err(|_| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "local wheel path `{}` could not be converted to a file URL",
                wheel_path.display()
            ))
        })?;
        let Some((spec, hashes)) =
            parse_pypi_direct_archive_reference(wheel_url.as_str(), wheel_project_dir)?
        else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported generated local wheel `{}`",
                wheel_path.display()
            )));
        };
        if !hashes.is_empty() {
            options
                .hashes
                .entry(spec.package_key())
                .or_default()
                .extend(hashes);
        }
        if index < requested_requirements && seen.insert(spec.requested()) {
            specs.push(spec);
        }
    }

    Ok(specs)
}

pub(crate) fn apply_pip_constraint_files_for_explicit_specs(
    options: &mut LinkOptions,
) -> Result<(), OmcRegistryError> {
    if options.constraint_files.is_empty() {
        return Ok(());
    }

    let constraints = read_constraint_files(&options.constraint_files)?;
    let mut ignored_specs = Vec::new();
    let project_dir = options.project_dir.clone();
    apply_pypi_install_requirements(
        options,
        &mut ignored_specs,
        constraints,
        &project_dir,
        &project_dir,
    )?;
    Ok(())
}

pub(crate) fn pip_debug_report(
    project_dir: &Path,
    invocation_cwd: &Path,
    action: &PipDebugAction,
) -> Result<String, OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let cache_dir =
        pip_cache_arg_or_env(invocation_cwd, None).unwrap_or_else(|| pip_cache_dir(&project_dir));
    let executable = env::current_exe()?;
    let values = pip_config_values(&project_dir)?;
    let lockfile = project_dir.join("omc.lock");
    let packages = if lockfile.exists() {
        read_lockfile(&lockfile)?
            .packages
            .into_iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut lines = vec![
        "WARNING: This command is only meant for OMC compatibility debugging.".to_owned(),
        format!("pip version: omc-pip {}", env!("CARGO_PKG_VERSION")),
        format!("omc executable: {}", executable.display()),
        format!("omc project: {}", project_dir.display()),
        format!("sys.platform: {}", env::consts::OS),
        format!("architecture: {}", env::consts::ARCH),
        format!("python site-packages: {}", site_packages.display()),
        format!("pip cache dir: {}", cache_dir.display()),
        format!(
            "lockfile: {} ({})",
            lockfile.display(),
            if lockfile.exists() {
                "present"
            } else {
                "missing"
            }
        ),
        format!("installed pypi packages: {}", packages.len()),
        format!(
            "global.index-url: {}",
            values
                .get("global.index-url")
                .map(String::as_str)
                .unwrap_or("not configured")
        ),
        format!(
            "global.no-index: {}",
            values
                .get("global.no-index")
                .map(String::as_str)
                .unwrap_or("false")
        ),
        format!(
            "global.extra-index-url: {}",
            values
                .get("global.extra-index-url")
                .map(String::as_str)
                .unwrap_or("not configured")
        ),
        format!(
            "global.find-links: {}",
            values
                .get("global.find-links")
                .map(String::as_str)
                .unwrap_or("not configured")
        ),
        format!(
            "REQUESTS_CA_BUNDLE: {}",
            env::var("REQUESTS_CA_BUNDLE").unwrap_or_else(|_| "None".to_owned())
        ),
        format!(
            "CURL_CA_BUNDLE: {}",
            env::var("CURL_CA_BUNDLE").unwrap_or_else(|_| "None".to_owned())
        ),
    ];

    if action.platform.is_some()
        || action.python_version.is_some()
        || action.implementation.is_some()
        || !action.abis.is_empty()
    {
        lines.push("requested compatibility target:".to_owned());
        lines.push(format!(
            "  platform: {}",
            action.platform.as_deref().unwrap_or("current")
        ));
        lines.push(format!(
            "  python-version: {}",
            action.python_version.as_deref().unwrap_or("current")
        ));
        lines.push(format!(
            "  implementation: {}",
            action.implementation.as_deref().unwrap_or("current")
        ));
        lines.push(format!(
            "  abi: {}",
            if action.abis.is_empty() {
                "current".to_owned()
            } else {
                action.abis.join(", ")
            }
        ));
    }

    lines.push("compatible tags: not computed by OMC compatibility mode".to_owned());

    if action.verbose {
        lines.push("locked pypi packages:".to_owned());
        if packages.is_empty() {
            lines.push("  (none)".to_owned());
        } else {
            for package in packages {
                lines.push(format!(
                    "  {}=={} ({})",
                    package.name,
                    package.version,
                    pip_locked_package_filetype(&package)
                ));
            }
        }
    }

    Ok(format!("{}\n", lines.join("\n")))
}

#[derive(Default)]
pub(crate) struct PipEditableLocalPathRemoval {
    pub(crate) removed_names: BTreeSet<String>,
    pub(crate) remaining_import_paths: Vec<PathBuf>,
}

impl PipEditableLocalPathRemoval {
    pub(crate) fn removed(&self, name: &str) -> bool {
        self.removed_names.contains(&normalize_pip_show_name(name))
    }
}

pub(crate) fn remove_pip_editable_local_paths(
    project_dir: &Path,
    specs: &[PackageSpec],
) -> Result<PipEditableLocalPathRemoval, OmcRegistryError> {
    remove_pip_editable_local_paths_from_file(
        &project_dir.join(".omc").join("python").join("local-paths"),
        specs,
    )
}

pub(crate) fn remove_pip_editable_local_paths_from_file(
    local_paths_file: &Path,
    specs: &[PackageSpec],
) -> Result<PipEditableLocalPathRemoval, OmcRegistryError> {
    let requested_names = specs
        .iter()
        .filter(|spec| spec.ecosystem == Ecosystem::Pypi)
        .map(|spec| normalize_pip_show_name(&spec.name))
        .collect::<BTreeSet<_>>();
    if requested_names.is_empty() {
        return Ok(PipEditableLocalPathRemoval::default());
    }

    let content = match fs::read_to_string(local_paths_file) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PipEditableLocalPathRemoval::default())
        }
        Err(error) => return Err(error.into()),
    };

    let mut removal = PipEditableLocalPathRemoval::default();
    let mut remaining_lines = Vec::new();
    let mut seen_remaining_lines = BTreeSet::new();
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let import_path = PathBuf::from(line);
        let package = pip_local_editable_package(&import_path)?;
        let remove = package
            .as_ref()
            .map(|package| normalize_pip_show_name(&package.name))
            .is_some_and(|name| {
                if requested_names.contains(&name) {
                    removal.removed_names.insert(name);
                    true
                } else {
                    false
                }
            });
        if remove {
            continue;
        }
        if seen_remaining_lines.insert(line.to_owned()) {
            remaining_lines.push(line.to_owned());
            removal.remaining_import_paths.push(import_path);
        }
    }

    if removal.removed_names.is_empty() {
        return Ok(removal);
    }

    if remaining_lines.is_empty() {
        match fs::remove_file(local_paths_file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    } else {
        fs::write(
            local_paths_file,
            format!("{}\n", remaining_lines.join("\n")),
        )?;
    }

    Ok(removal)
}

pub(crate) fn pip_effective_scope_paths(
    base_dir: &Path,
    paths: &[PathBuf],
    user: bool,
) -> Result<Vec<PathBuf>, OmcRegistryError> {
    if user && paths.is_empty() {
        Ok(vec![pip_user_paths()?.site_packages])
    } else {
        Ok(paths
            .iter()
            .cloned()
            .map(|path| absolutize_path(base_dir, path))
            .collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipFrozenRequirement {
    pub(crate) name: Option<String>,
    pub(crate) line: String,
}

pub(crate) fn pip_requirement_line_name(line: &str) -> Option<String> {
    let line = pip_requirement_without_inline_comment(line).trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let requirement = line
        .strip_prefix("-e ")
        .or_else(|| line.strip_prefix("--editable "))
        .unwrap_or(line)
        .trim();
    if requirement.starts_with('-') {
        return None;
    }

    if let Some(egg) = requirement.split_once("#egg=").map(|(_, egg)| egg) {
        let egg = egg
            .split('&')
            .next()
            .unwrap_or(egg)
            .split(';')
            .next()
            .unwrap_or(egg)
            .trim();
        if !egg.is_empty() {
            return Some(normalize_pip_show_name(egg));
        }
    }

    let named_requirement = requirement
        .split_once(" @ ")
        .map(|(name, _)| name.trim())
        .unwrap_or(requirement);
    if named_requirement.contains("://")
        || !named_requirement
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
    {
        return None;
    }
    let name_end = named_requirement
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')))
        .unwrap_or(named_requirement.len());
    if name_end == 0 {
        return None;
    }
    Some(normalize_pip_show_name(&named_requirement[..name_end]))
}

pub(crate) fn pip_requirement_without_inline_comment(line: &str) -> &str {
    let mut previous_was_whitespace = true;
    for (index, ch) in line.char_indices() {
        if ch == '#' && previous_was_whitespace {
            return &line[..index];
        }
        previous_was_whitespace = ch.is_whitespace();
    }
    line
}

pub(crate) fn pip_installed_list_json_output(
    packages: &[InstalledPythonPackage],
    verbose: bool,
) -> Result<String, OmcRegistryError> {
    let packages = packages
        .iter()
        .map(|package| {
            let mut item = serde_json::Map::new();
            item.insert(
                "name".to_owned(),
                serde_json::Value::String(package.name.clone()),
            );
            item.insert(
                "version".to_owned(),
                serde_json::Value::String(package.version.clone()),
            );
            if let Some(location) = &package.editable_project_location {
                item.insert(
                    "editable_project_location".to_owned(),
                    serde_json::Value::String(location.display().to_string()),
                );
            }
            if verbose {
                if let Some(location) = &package.install_location {
                    item.insert(
                        "location".to_owned(),
                        serde_json::Value::String(location.display().to_string()),
                    );
                }
                item.insert(
                    "installer".to_owned(),
                    serde_json::Value::String("omc".to_owned()),
                );
            }
            serde_json::Value::Object(item)
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_string(&packages)?)
}

pub(crate) fn pip_columns_list_output(packages: &[InstalledPythonPackage], verbose: bool) -> Option<String> {
    if packages.is_empty() {
        return None;
    }

    let has_editable_locations = packages
        .iter()
        .any(|package| package.editable_project_location.is_some());
    let headers = if verbose && has_editable_locations {
        vec![
            "Package",
            "Version",
            "Editable project location",
            "Location",
            "Installer",
        ]
    } else if verbose {
        vec!["Package", "Version", "Location", "Installer"]
    } else if has_editable_locations {
        vec!["Package", "Version", "Location"]
    } else {
        vec!["Package", "Version"]
    };
    let rows = packages
        .iter()
        .map(|package| {
            let mut row = vec![package.name.clone(), package.version.clone()];
            if has_editable_locations {
                row.push(
                    package
                        .editable_project_location
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default(),
                );
            }
            if verbose {
                row.push(
                    package
                        .install_location
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default(),
                );
                row.push("omc".to_owned());
            }
            row
        })
        .collect::<Vec<_>>();
    let widths = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            rows.iter()
                .map(|row| row[index].len())
                .chain(std::iter::once(header.len()))
                .max()
                .unwrap_or(header.len())
        })
        .collect::<Vec<_>>();

    let mut output = String::new();
    output.push_str(&pip_columns_join_row(
        &headers
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>(),
        &widths,
    ));
    output.push('\n');
    output.push_str(&pip_columns_join_row(
        &widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>(),
        &widths,
    ));
    output.push('\n');
    for row in rows {
        output.push_str(&pip_columns_join_row(&row, &widths));
        output.push('\n');
    }
    Some(output)
}

pub(crate) fn pip_columns_join_row(row: &[String], widths: &[usize]) -> String {
    row.iter()
        .enumerate()
        .map(|(index, value)| {
            if index + 1 == row.len() {
                value.clone()
            } else {
                format!("{value:<width$}", width = widths[index])
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn read_pip_path_packages(
    project_dir: &Path,
    paths: &[PathBuf],
    exclude: &[String],
    editable: PipEditableMode,
) -> Result<Vec<InstalledPythonPackage>, OmcRegistryError> {
    let excluded = pip_excluded_names(exclude);
    let mut packages = BTreeMap::new();
    for path in paths {
        let site_packages = absolutize_path(project_dir, path.clone());
        if editable.includes_regular() {
            for package in read_site_packages_metadata(&site_packages)? {
                if !pip_name_excluded(&package.name, &excluded) {
                    packages.insert(normalize_pip_show_name(&package.name), package);
                }
            }
        }
        if editable.includes_editables() {
            for package in pip_local_editable_packages_from_file(
                site_packages.join(".omc-local-paths"),
                &excluded,
            )? {
                packages.insert(normalize_pip_show_name(&package.name), package);
            }
        }
    }
    Ok(packages.into_values().collect())
}

pub(crate) fn pip_project_local_path_packages(
    project_dir: &Path,
    exclude: &[String],
) -> Result<Vec<InstalledPythonPackage>, OmcRegistryError> {
    let excluded = pip_excluded_names(exclude);
    pip_local_editable_packages_from_file(
        project_dir.join(".omc").join("python").join("local-paths"),
        &excluded,
    )
}

pub(crate) fn pip_editable_project_root(import_path: &Path) -> PathBuf {
    if import_path.file_name().and_then(|name| name.to_str()) == Some("src") {
        if let Some(parent) = import_path.parent() {
            if python_project_identity_file_exists(parent) {
                return parent.to_path_buf();
            }
        }
    }
    import_path.to_path_buf()
}

pub(crate) fn push_pip_show_requirement(requirement: &str, metadata: &mut PipShowMetadata) {
    if requirement.is_empty() {
        return;
    }
    metadata.requires_dist.push(requirement.to_owned());
    if let Some(name) = pip_installed_dependency_name(requirement) {
        metadata.requires.push(name);
    }
}

pub(crate) fn append_pip_project_editables(
    project_dir: &Path,
    exclude: &[String],
    packages: &mut Vec<InstalledPythonPackage>,
) -> Result<(), OmcRegistryError> {
    packages.extend(pip_project_local_path_packages(project_dir, exclude)?);
    *packages = merge_installed_python_packages(std::mem::take(packages));
    Ok(())
}

pub(crate) fn pip_not_required_packages(packages: Vec<InstalledPythonPackage>) -> Vec<InstalledPythonPackage> {
    let required = packages
        .iter()
        .flat_map(|package| package.dependencies.iter())
        .filter_map(|dependency| pip_installed_dependency_name(dependency))
        .collect::<BTreeSet<_>>();
    packages
        .into_iter()
        .filter(|package| !required.contains(&normalize_pip_show_name(&package.name)))
        .collect()
}

pub(crate) fn pip_installed_dependency_name(dependency: &str) -> Option<String> {
    pip_dependency_name(dependency).or_else(|| pip_requires_dist_name(dependency))
}

pub(crate) fn pip_metadata_lines(metadata: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in metadata.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(previous) = lines.last_mut() {
                previous.push(' ');
                previous.push_str(line.trim());
            }
        } else {
            lines.push(line.to_owned());
        }
    }
    lines
}

pub(crate) fn pip_excluded_names(exclude: &[String]) -> BTreeSet<String> {
    exclude
        .iter()
        .map(|name| normalize_pip_show_name(name))
        .collect()
}

pub(crate) fn pip_name_excluded(name: &str, excluded: &BTreeSet<String>) -> bool {
    excluded.contains(&normalize_pip_show_name(name))
}

pub(crate) fn pip_path_inspect_entries(
    project_dir: &Path,
    paths: &[PathBuf],
) -> Result<Vec<serde_json::Value>, OmcRegistryError> {
    read_pip_path_packages(project_dir, paths, &[], PipEditableMode::Include)?
        .into_iter()
        .map(|package| {
            let metadata_location = package
                .metadata_location
                .as_ref()
                .or(package.editable_project_location.as_ref())
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            let installer = package
                .metadata_location
                .as_deref()
                .map(read_pip_installer)
                .transpose()?
                .unwrap_or_else(|| "omc".to_owned());
            Ok(serde_json::json!({
                "metadata": {
                    "name": package.name,
                    "version": package.version,
                },
                "metadata_location": metadata_location,
                "installer": installer,
                "requested": false,
                "dependencies": package.dependencies,
            }))
        })
        .collect()
}

pub(crate) fn pip_inspect_installed_package(package: InstalledPythonPackage) -> serde_json::Value {
    let metadata_location = package
        .metadata_location
        .as_ref()
        .or(package.editable_project_location.as_ref())
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    serde_json::json!({
        "metadata": {
            "name": package.name,
            "version": package.version,
        },
        "metadata_location": metadata_location,
        "installer": "omc",
        "requested": false,
        "dependencies": package.dependencies,
    })
}

pub(crate) fn read_pip_installer(dist_info: &Path) -> Result<String, OmcRegistryError> {
    let installer = dist_info.join("INSTALLER");
    if !installer.exists() {
        return Ok("omc".to_owned());
    }
    let installer = fs::read_to_string(installer)?;
    let installer = installer.trim();
    if installer.is_empty() {
        Ok("omc".to_owned())
    } else {
        Ok(installer.to_owned())
    }
}

#[derive(Debug)]
pub(crate) struct PipOutdatedPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) latest_version: String,
    pub(crate) latest_filetype: String,
    pub(crate) install_location: Option<PathBuf>,
    pub(crate) installer: String,
}

pub(crate) struct PipOutdatedOptions<'a> {
    pub(crate) format: PipListFormat,
    pub(crate) verbose: bool,
    pub(crate) paths: &'a [PathBuf],
    pub(crate) exclude: &'a [String],
    pub(crate) editable: PipEditableMode,
    pub(crate) not_required: bool,
    pub(crate) uptodate: bool,
    pub(crate) index_url: Option<String>,
    pub(crate) extra_index_urls: Vec<String>,
    pub(crate) find_links: Vec<String>,
    pub(crate) no_index: bool,
    pub(crate) allow_prereleases: bool,
}

pub(crate) fn pip_version_status_matches(latest_version: &str, current_version: &str, uptodate: bool) -> bool {
    let latest_is_newer = compare_pypi_versions(latest_version, current_version).is_gt();
    if uptodate {
        !latest_is_newer
    } else {
        latest_is_newer
    }
}

pub(crate) fn pip_outdated_rows_json_output(
    rows: &[PipOutdatedPackage],
    verbose: bool,
) -> Result<String, OmcRegistryError> {
    let packages = rows
        .iter()
        .map(|row| {
            let mut item = serde_json::Map::new();
            item.insert(
                "name".to_owned(),
                serde_json::Value::String(row.name.clone()),
            );
            item.insert(
                "version".to_owned(),
                serde_json::Value::String(row.version.clone()),
            );
            if verbose {
                if let Some(location) = &row.install_location {
                    item.insert(
                        "location".to_owned(),
                        serde_json::Value::String(location.display().to_string()),
                    );
                }
                item.insert(
                    "installer".to_owned(),
                    serde_json::Value::String(row.installer.clone()),
                );
            }
            item.insert(
                "latest_version".to_owned(),
                serde_json::Value::String(row.latest_version.clone()),
            );
            item.insert(
                "latest_filetype".to_owned(),
                serde_json::Value::String(row.latest_filetype.clone()),
            );
            serde_json::Value::Object(item)
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_string(&packages)?)
}

pub(crate) fn locked_pip_installed_packages(
    project_dir: &Path,
    exclude: &[String],
    editable: PipEditableMode,
) -> Result<Vec<InstalledPythonPackage>, OmcRegistryError> {
    let excluded = pip_excluded_names(exclude);
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let mut packages = Vec::new();
    if editable.includes_regular() {
        for package in lock
            .packages
            .into_iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .filter(|package| !pip_name_excluded(&package.name, &excluded))
        {
            let metadata_location = match_dist_info_dir(&site_packages, &package)?;
            let install_location = metadata_location
                .as_deref()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
                .unwrap_or_else(|| site_packages.clone());
            packages.push(InstalledPythonPackage {
                name: package.name,
                version: package.version,
                dependencies: package.dependencies,
                install_location: Some(install_location),
                metadata_location,
                editable_project_location: None,
            });
        }
    }
    if editable.includes_editables() {
        append_pip_project_editables(project_dir, exclude, &mut packages)?;
    }
    sort_installed_python_packages(&mut packages);
    Ok(packages)
}

pub(crate) fn pip_locked_package_filetype(package: &LockedPackage) -> &'static str {
    let source = if package.source_url.is_empty() {
        package.archive.as_str()
    } else {
        package.source_url.as_str()
    }
    .to_ascii_lowercase();
    if source.ends_with(".tar.gz")
        || source.ends_with(".tar.bz2")
        || source.ends_with(".tar.xz")
        || source.ends_with(".zip")
        || source.ends_with(".tgz")
    {
        "sdist"
    } else {
        "wheel"
    }
}

pub(crate) fn pip_check_installed_packages(
    project_dir: &Path,
    lock: &OmcLock,
) -> Result<Vec<PypiCheckIssue>, OmcRegistryError> {
    let mut packages = lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .map(|package| InstalledPythonPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            dependencies: package.dependencies.clone(),
            install_location: None,
            metadata_location: None,
            editable_project_location: None,
        })
        .collect::<Vec<_>>();
    packages.extend(pip_project_local_path_packages(project_dir, &[])?);
    Ok(pip_check_installed_package_set(&packages))
}

pub(crate) fn pip_check_installed_package_set(packages: &[InstalledPythonPackage]) -> Vec<PypiCheckIssue> {
    let mut issues = Vec::new();
    for package in packages {
        for dependency in &package.dependencies {
            let Ok(spec) = parse_package_spec(dependency, Some(Ecosystem::Pypi)) else {
                continue;
            };
            if spec.ecosystem != Ecosystem::Pypi {
                continue;
            }
            let requirement = pip_check_requirement_label(&spec);
            if let Some(installed) = packages.iter().find(|installed| {
                normalize_pip_show_name(&installed.name) == normalize_pip_show_name(&spec.name)
            }) {
                if pip_check_version_satisfies(&installed.version, spec.version.as_deref()) {
                    continue;
                }
                issues.push(PypiCheckIssue::Incompatible {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    requirement,
                    installed_name: installed.name.clone(),
                    installed_version: installed.version.clone(),
                });
            } else {
                issues.push(PypiCheckIssue::Missing {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    requirement,
                });
            }
        }
    }
    issues
}

pub(crate) fn pip_check_requirement_label(spec: &PackageSpec) -> String {
    let mut name = spec.name.clone();
    if !spec.extras.is_empty() {
        name.push('[');
        name.push_str(&spec.extras.iter().cloned().collect::<Vec<_>>().join(","));
        name.push(']');
    }
    if let Some(version) = &spec.version {
        name.push_str(version);
    }
    name
}

pub(crate) fn pip_check_version_satisfies(version: &str, requirement: Option<&str>) -> bool {
    let Some(requirement) = requirement.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    if requirement == "*" {
        return true;
    }
    requirement
        .trim_matches(|ch| ch == '(' || ch == ')')
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .all(|part| pip_check_comparator_satisfied(version, part))
}

pub(crate) fn pip_check_comparator_satisfied(version: &str, comparator: &str) -> bool {
    for op in [">=", "<=", "==", "!=", "~=", ">", "<"] {
        if let Some(required) = comparator.strip_prefix(op) {
            let ordering = compare_pypi_versions(version, required.trim());
            return match op {
                ">=" => ordering.is_ge(),
                "<=" => ordering.is_le(),
                "==" => ordering.is_eq(),
                "!=" => !ordering.is_eq(),
                ">" => ordering.is_gt(),
                "<" => ordering.is_lt(),
                "~=" => ordering.is_ge(),
                _ => false,
            };
        }
    }
    compare_pypi_versions(version, comparator).is_eq()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PipShowMetadata {
    pub(crate) summary: Option<String>,
    pub(crate) home_page: Option<String>,
    pub(crate) author: Option<String>,
    pub(crate) author_email: Option<String>,
    pub(crate) license: Option<String>,
    pub(crate) requires: Vec<String>,
    pub(crate) requires_dist: Vec<String>,
}

impl PipShowMetadata {
    pub(crate) fn is_empty(&self) -> bool {
        self.summary.is_none()
            && self.home_page.is_none()
            && self.author.is_none()
            && self.author_email.is_none()
            && self.license.is_none()
            && self.requires.is_empty()
            && self.requires_dist.is_empty()
    }
}

pub(crate) fn read_pip_show_metadata(
    site_packages: &Path,
    package: &LockedPackage,
) -> Result<PipShowMetadata, OmcRegistryError> {
    let Some(dist_info) = match_dist_info_dir(site_packages, package)? else {
        return Ok(PipShowMetadata::default());
    };
    read_pip_show_metadata_from_dist_info(&dist_info)
}

pub(crate) fn read_pip_show_metadata_from_dist_info(
    dist_info: &Path,
) -> Result<PipShowMetadata, OmcRegistryError> {
    let metadata = dist_info.join("METADATA");
    if !metadata.exists() {
        return Ok(PipShowMetadata::default());
    }

    let mut output = PipShowMetadata::default();
    for line in pip_metadata_lines(&fs::read_to_string(metadata)?) {
        if let Some(value) = line.strip_prefix("Summary:") {
            output.summary = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("Home-page:") {
            output.home_page = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("Author:") {
            output.author = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("Author-email:") {
            output.author_email = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("License:") {
            output.license = Some(value.trim().to_owned());
        } else if output.license.is_none() {
            if let Some(value) = line.strip_prefix("License-Expression:") {
                output.license = Some(value.trim().to_owned());
            }
        }
        if let Some(value) = line.strip_prefix("Requires-Dist:") {
            output.requires_dist.push(value.trim().to_owned());
            if let Some(name) = pip_requires_dist_name(value.trim()) {
                output.requires.push(name);
            }
        }
    }
    output.requires.sort();
    output.requires.dedup();
    Ok(output)
}

pub(crate) fn pip_dependency_names(package: &LockedPackage) -> Vec<String> {
    package
        .dependencies
        .iter()
        .filter_map(|dependency| pip_dependency_name(dependency))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn pip_required_by_names(package: &LockedPackage, packages: &[LockedPackage]) -> Vec<String> {
    pip_required_by_package_name(&package.name, packages)
}

pub(crate) fn pip_required_by_package_name(name: &str, packages: &[LockedPackage]) -> Vec<String> {
    let target = normalize_pip_show_name(name);
    packages
        .iter()
        .filter(|candidate| normalize_pip_show_name(&candidate.name) != target)
        .filter(|candidate| {
            candidate
                .dependencies
                .iter()
                .filter_map(|dependency| pip_dependency_name(dependency))
                .any(|name| normalize_pip_show_name(&name) == target)
        })
        .map(|candidate| candidate.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn pip_required_by_installed_package_name(
    name: &str,
    packages: &[InstalledPythonPackage],
) -> Vec<String> {
    let target = normalize_pip_show_name(name);
    packages
        .iter()
        .filter(|candidate| normalize_pip_show_name(&candidate.name) != target)
        .filter(|candidate| {
            candidate
                .dependencies
                .iter()
                .filter_map(|dependency| pip_installed_dependency_name(dependency))
                .any(|name| normalize_pip_show_name(&name) == target)
        })
        .map(|candidate| candidate.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn pip_dependency_name(dependency: &str) -> Option<String> {
    PackageSpec::parse(dependency)
        .ok()
        .filter(|spec| spec.ecosystem == Ecosystem::Pypi)
        .map(|spec| spec.name)
}

pub(crate) fn pip_requires_dist_name(requirement: &str) -> Option<String> {
    let requirement = requirement
        .split_once(';')
        .map(|(requirement, _)| requirement)
        .unwrap_or(requirement)
        .trim();
    let name = requirement
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        .collect::<String>();
    (!name.is_empty()).then(|| normalize_pip_show_name(&name))
}

pub(crate) fn pip_installed_files(
    site_packages: &Path,
    package: &LockedPackage,
) -> Result<Vec<String>, OmcRegistryError> {
    let Some(dist_info) = match_dist_info_dir(site_packages, package)? else {
        return Ok(Vec::new());
    };
    pip_installed_files_from_dist_info(&dist_info)
}

pub(crate) fn pip_installed_files_from_dist_info(dist_info: &Path) -> Result<Vec<String>, OmcRegistryError> {
    let record = dist_info.join("RECORD");
    if !record.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for line in fs::read_to_string(record)?.lines() {
        if let Some((file, _)) = line.split_once(',') {
            if !file.is_empty() {
                files.push(file.to_owned());
            }
        }
    }
    files.sort();
    Ok(files)
}

pub(crate) fn pip_editable_project_files(import_path: &Path) -> Result<Vec<String>, OmcRegistryError> {
    if !import_path.is_dir() {
        return Ok(Vec::new());
    }
    let files = pip_local_wheel_source_files(import_path)?
        .into_iter()
        .map(|(relative, _)| relative)
        .collect();
    Ok(files)
}

pub(crate) fn normalize_pip_show_name(name: &str) -> String {
    let name = name
        .strip_prefix("pypi:")
        .or_else(|| name.strip_prefix("py:"))
        .or_else(|| name.strip_prefix("python:"))
        .unwrap_or(name);
    let name = name.split_once('[').map(|(name, _)| name).unwrap_or(name);
    name.chars()
        .map(|ch| match ch {
            '_' | '.' => '-',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

pub(crate) fn apply_pip_compat_index_options(
    options: &mut LinkOptions,
    project_dir: &Path,
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
) {
    if index_url.is_some() {
        options.pypi_index_url = index_url;
    }
    options.pypi_extra_index_urls.extend(extra_index_urls);
    options.pypi_find_links.extend(
        find_links
            .into_iter()
            .map(|source| normalize_pip_compat_find_links(project_dir, source)),
    );
    options.pypi_no_index |= no_index;
}

pub(crate) fn normalize_pip_compat_find_links(project_dir: &Path, source: String) -> String {
    if source.is_empty() || source.contains("://") {
        return source;
    }
    absolutize_path(project_dir, PathBuf::from(source))
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn apply_pip_environment_defaults_for_project(options: &mut LinkOptions, project_dir: &Path) {
    options.pypi_environment_base_dir = Some(project_dir.to_path_buf());
    let override_index = options.pypi_index_url.is_none();
    apply_pypi_environment_defaults(options, override_index);
}

pub(crate) fn pip_uninstall_specs_from_requirements(
    project_dir: &Path,
    requirements: Vec<PathBuf>,
) -> Result<Vec<String>, OmcRegistryError> {
    if requirements.is_empty() {
        return Ok(Vec::new());
    }

    let requirements = read_requirements_files(&absolutize_paths(project_dir, requirements))?;

    let mut specs = requirements
        .specs
        .into_iter()
        .map(|spec| spec.package_key())
        .collect::<Vec<_>>();
    specs.extend(
        requirements
            .python_vcs_requirements
            .into_iter()
            .map(|requirement| format!("pypi:{}", requirement.name)),
    );
    specs.extend(pip_uninstall_local_path_specs(
        requirements.python_local_paths,
        requirements.python_local_requirements,
    )?);
    Ok(specs)
}

pub(crate) fn pip_uninstall_local_path_specs(
    local_paths: Vec<PathBuf>,
    local_requirements: Vec<PythonLocalRequirement>,
) -> Result<Vec<String>, OmcRegistryError> {
    let mut specs = Vec::new();
    let mut seen = BTreeSet::new();
    for path in local_paths.into_iter().chain(
        local_requirements
            .into_iter()
            .map(|requirement| requirement.path),
    ) {
        let Some(package) = pip_local_editable_package(&path)? else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "pip uninstall -r cannot remove unnamed local path requirement `{}`",
                path.display()
            )));
        };
        if seen.insert(normalize_pip_show_name(&package.name)) {
            specs.push(format!("pypi:{}", package.name));
        }
    }
    Ok(specs)
}

