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
    LockedPackage, LockedPythonVcsDependency, OmcLock, OmcRegistryError, PackageSpec,
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




pub(crate) fn print_pip_help(topic: Option<&str>) {
    print!("{}", pip_help_text(topic));
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

pub(crate) fn print_pip_completion(shell: Option<PipCompletionShell>) {
    match shell {
        Some(PipCompletionShell::Bash) => print!("{}", pip_bash_completion_script()),
        Some(PipCompletionShell::Zsh) => print!("{}", pip_zsh_completion_script()),
        Some(PipCompletionShell::Fish) => print!("{}", pip_fish_completion_script()),
        None => println!("ERROR: You must pass --bash or --fish or --zsh"),
    }
}

pub(crate) fn print_pip_auto_completion(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let words = pip_completion_words_from_env();
    let cword = env::var("COMP_CWORD")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| words.len().saturating_sub(1));
    for suggestion in pip_completion_suggestions(project_dir, &words, cword) {
        println!("{suggestion}");
    }
    Ok(())
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


pub(crate) fn print_pip_index_versions(
    project_dir: &Path,
    package: &str,
    options: PipIndexSearchOptions,
    json: bool,
) -> Result<(), OmcRegistryError> {
    let PipIndexSearchOptions {
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        allow_prereleases,
        release_controls,
        uploaded_prior_to,
        compatibility,
    } = options;
    let listing = read_pypi_available_versions(
        project_dir,
        package,
        PypiAvailableVersionsOptions {
            index_url,
            extra_index_urls,
            find_links,
            no_index,
            allow_prereleases,
            release_controls,
            uploaded_prior_to,
            target_python: compatibility.python_version,
            target_implementation: compatibility.implementation,
            target_platforms: compatibility.platforms,
            target_abis: compatibility.abis,
        },
    )?;
    let latest = listing.versions.first().cloned().unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "name": listing.name,
                "latest": latest,
                "versions": listing.versions,
            }))?
        );
    } else {
        println!("{} ({latest})", listing.name);
        println!("Available versions: {}", listing.versions.join(", "));
    }
    Ok(())
}

pub(crate) fn print_pip_search_deprecated(query: Vec<String>) -> Result<ExitCode, OmcRegistryError> {
    if query.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip search needs at least one search term".to_owned(),
        ));
    }
    eprintln!("ERROR: XMLRPC request failed [code: -32500]");
    eprintln!(
        "RuntimeError: PyPI no longer supports 'pip search' (or XML-RPC search). Please use https://pypi.org/search (via a browser) instead. See https://warehouse.pypa.io/api-reference/xml-rpc.html#deprecated-methods for more information."
    );
    Ok(ExitCode::FAILURE)
}

#[derive(Debug)]
pub(crate) struct PipIndexSearchOptions {
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    allow_prereleases: bool,
    release_controls: PypiReleaseControls,
    uploaded_prior_to: Option<String>,
    compatibility: PipCompatibilityTarget,
}

pub(crate) fn print_pip_hash(
    project_dir: &Path,
    algorithm: PipHashAlgorithm,
    paths: Vec<PathBuf>,
) -> Result<(), OmcRegistryError> {
    for path in paths {
        let resolved = absolutize_path(project_dir, path.clone());
        let bytes = fs::read(&resolved)?;
        println!("{}:", path.display());
        println!(
            "--hash={}:{}",
            algorithm.name(),
            pip_hash_digest(algorithm, &bytes)
        );
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipLocalWheelMetadata {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) requires_dist: Vec<String>,
    pub(crate) entry_points: Vec<PipLocalWheelEntryPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipLocalWheelEntryPoint {
    group: String,
    name: String,
    target: String,
}

pub(crate) enum PipLocalWheelDependencySource {
    Local(PythonLocalRequirement),
    Skipped,
    Other,
}

pub(crate) fn build_pip_local_wheels(
    project_dir: &Path,
    destination: &Path,
    requirements: &[PythonLocalRequirement],
    include_dependencies: bool,
) -> Result<(), OmcRegistryError> {
    let mut built = 0usize;
    let mut seen = BTreeSet::new();
    for requirement in requirements {
        let package_dir = resolve_pip_local_wheel_path(project_dir, requirement)?;
        if !seen.insert(package_dir.clone()) {
            continue;
        }

        let mut metadata = read_pip_local_wheel_metadata(&package_dir, &requirement.extras)?;
        if !include_dependencies {
            metadata.requires_dist.clear();
        }
        let filename = pip_local_wheel_filename(&metadata);
        let target = destination.join(filename);
        write_pip_local_wheel(&package_dir, &metadata, &target)?;
        println!("Created {}", target.display());
        built += 1;
    }
    println!("Successfully built {built} local wheel(s)");
    Ok(())
}

pub(crate) fn collect_pip_local_wheel_dependencies(
    project_dir: &Path,
    requirements: &mut Vec<PythonLocalRequirement>,
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    let mut specs = Vec::new();
    let mut seen_paths = BTreeSet::new();
    let mut seen_specs = BTreeSet::new();
    let mut index = 0;
    while index < requirements.len() {
        let requirement = requirements[index].clone();
        index += 1;
        let package_dir = resolve_pip_local_wheel_path(project_dir, &requirement)?;
        if !seen_paths.insert((package_dir.clone(), requirement.extras.clone())) {
            continue;
        }

        let metadata = read_pip_local_wheel_metadata(&package_dir, &requirement.extras)?;
        for dependency in metadata.requires_dist {
            match pip_local_wheel_dependency_source(&dependency, &requirement.extras, &package_dir)?
            {
                PipLocalWheelDependencySource::Local(local_requirement) => {
                    requirements.push(local_requirement);
                }
                PipLocalWheelDependencySource::Skipped => {}
                PipLocalWheelDependencySource::Other => {
                    let spec = parse_package_spec(&dependency, Some(Ecosystem::Pypi))?;
                    if seen_specs.insert(spec.requested()) {
                        specs.push(spec);
                    }
                }
            }
        }
    }
    Ok(specs)
}

pub(crate) fn pip_local_wheel_dependency_source(
    dependency: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<PipLocalWheelDependencySource, OmcRegistryError> {
    let mut parts = dependency.splitn(2, ';');
    let requirement = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(PipLocalWheelDependencySource::Skipped);
        }
    }

    let Some((name, source)) = requirement.split_once(" @ ") else {
        return Ok(PipLocalWheelDependencySource::Other);
    };
    let (_, extras) = pip_local_path_and_extras(name.trim());
    let source = source
        .trim()
        .split_once('#')
        .map(|(source, _)| source)
        .unwrap_or_else(|| source.trim());
    if source.is_empty() || source.starts_with("git+") || is_pip_archive_arg(source) {
        return Ok(PipLocalWheelDependencySource::Other);
    }

    let path = if source.contains("://") {
        let Ok(url) = reqwest::Url::parse(source) else {
            return Ok(PipLocalWheelDependencySource::Other);
        };
        if url.scheme() != "file" {
            return Ok(PipLocalWheelDependencySource::Other);
        }
        url.to_file_path().map_err(|_| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "local wheel dependency `{dependency}` uses an invalid file URL"
            ))
        })?
    } else {
        let source = source
            .strip_prefix("file:")
            .or_else(|| source.strip_prefix("link:"))
            .unwrap_or(source);
        let path = PathBuf::from(source);
        if path.is_absolute() {
            path
        } else {
            base_dir.join(path)
        }
    };

    if !path.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "local wheel dependency `{dependency}` must point to an existing directory"
        )));
    }
    Ok(PipLocalWheelDependencySource::Local(
        PythonLocalRequirement::new(path, extras),
    ))
}

pub(crate) fn resolve_pip_local_wheel_path(
    project_dir: &Path,
    requirement: &PythonLocalRequirement,
) -> Result<PathBuf, OmcRegistryError> {
    let package_dir = absolutize_path(project_dir, requirement.path.clone());
    let package_dir = fs::canonicalize(&package_dir).map_err(|error| {
        OmcRegistryError::UnsupportedRequirement(format!(
            "local wheel path `{}` could not be resolved: {error}",
            requirement.path.display()
        ))
    })?;
    if !package_dir.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "local wheel path `{}` must be a directory",
            package_dir.display()
        )));
    }
    Ok(package_dir)
}

pub(crate) fn read_pip_local_wheel_metadata(
    package_dir: &Path,
    extras: &BTreeSet<String>,
) -> Result<PipLocalWheelMetadata, OmcRegistryError> {
    if let Some(metadata) = read_pyproject_wheel_metadata(package_dir, extras)? {
        return Ok(metadata);
    }
    if let Some(metadata) = read_setup_cfg_wheel_metadata(package_dir, extras)? {
        return Ok(metadata);
    }
    Err(OmcRegistryError::UnsupportedRequirement(format!(
        "local wheel path `{}` must declare static name and version in pyproject.toml or setup.cfg",
        package_dir.display()
    )))
}

pub(crate) fn parse_pip_local_setup_cfg(content: &str) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut sections = BTreeMap::<String, BTreeMap<String, Vec<String>>>::new();
    let mut section = String::new();
    let mut key = None::<String>;
    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            key = None;
            sections.entry(section.clone()).or_default();
            continue;
        }
        if section.is_empty() {
            continue;
        }
        if let Some((parsed_key, value)) = setup_cfg_assignment(trimmed) {
            let parsed_key = parsed_key.to_ascii_lowercase();
            key = Some(parsed_key.clone());
            if !value.trim().is_empty() {
                sections
                    .entry(section.clone())
                    .or_default()
                    .entry(parsed_key)
                    .or_default()
                    .push(value.trim().to_owned());
            } else {
                sections
                    .entry(section.clone())
                    .or_default()
                    .entry(parsed_key)
                    .or_default();
            }
            continue;
        }
        if raw.chars().next().map(char::is_whitespace).unwrap_or(false) {
            if let Some(key) = key.as_ref() {
                sections
                    .entry(section.clone())
                    .or_default()
                    .entry(key.clone())
                    .or_default()
                    .push(trimmed.to_owned());
            }
        }
    }
    sections
}

pub(crate) fn pip_local_entry_point(group: &str, value: &str) -> Option<PipLocalWheelEntryPoint> {
    let (name, target) = value.split_once('=')?;
    pip_local_script_entry(group, name.trim(), target.trim())
}

pub(crate) fn pip_local_script_entry(
    group: &str,
    name: &str,
    target: &str,
) -> Option<PipLocalWheelEntryPoint> {
    (!name.is_empty() && !target.is_empty()).then(|| PipLocalWheelEntryPoint {
        group: group.to_owned(),
        name: name.to_owned(),
        target: target.to_owned(),
    })
}

pub(crate) fn pip_local_wheel_filename(metadata: &PipLocalWheelMetadata) -> String {
    format!(
        "{}-{}-py3-none-any.whl",
        python_wheel_component(&metadata.name),
        python_wheel_version_component(&metadata.version)
    )
}

pub(crate) fn write_pip_local_wheel(
    package_dir: &Path,
    metadata: &PipLocalWheelMetadata,
    target: &Path,
) -> Result<(), OmcRegistryError> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::File::create(target)?;
    let mut archive = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let import_root = pip_local_wheel_import_root(package_dir);
    let mut record_paths = Vec::new();

    for (archive_path, source) in pip_local_wheel_source_files(&import_root)? {
        let bytes = fs::read(source)?;
        write_wheel_file(&mut archive, &archive_path, &bytes, options)?;
        record_paths.push(archive_path);
    }

    let dist_info = format!(
        "{}-{}.dist-info",
        python_wheel_component(&metadata.name),
        python_wheel_version_component(&metadata.version)
    );
    let metadata_path = format!("{dist_info}/METADATA");
    let metadata_content = pip_local_wheel_metadata_content(package_dir, metadata)?;
    write_wheel_file(
        &mut archive,
        &metadata_path,
        metadata_content.as_bytes(),
        options,
    )?;
    record_paths.push(metadata_path);

    let wheel_path = format!("{dist_info}/WHEEL");
    write_wheel_file(
        &mut archive,
        &wheel_path,
        b"Wheel-Version: 1.0\nGenerator: omc\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        options,
    )?;
    record_paths.push(wheel_path);

    if !metadata.entry_points.is_empty() {
        let entry_points_path = format!("{dist_info}/entry_points.txt");
        write_wheel_file(
            &mut archive,
            &entry_points_path,
            pip_local_wheel_entry_points_content(&metadata.entry_points).as_bytes(),
            options,
        )?;
        record_paths.push(entry_points_path);
    }

    let record_path = format!("{dist_info}/RECORD");
    record_paths.sort();
    let mut record = record_paths
        .iter()
        .map(|path| format!("{path},,\n"))
        .collect::<String>();
    record.push_str(&format!("{record_path},,\n"));
    write_wheel_file(&mut archive, &record_path, record.as_bytes(), options)?;
    archive.finish()?;
    Ok(())
}

pub(crate) fn pip_local_wheel_import_root(package_dir: &Path) -> PathBuf {
    let src = package_dir.join("src");
    if src.is_dir() {
        src
    } else {
        package_dir.to_path_buf()
    }
}

pub(crate) fn pip_local_wheel_source_files(
    import_root: &Path,
) -> Result<Vec<(String, PathBuf)>, OmcRegistryError> {
    let mut files = Vec::new();
    collect_pip_local_wheel_source_files(import_root, import_root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

pub(crate) fn collect_pip_local_wheel_source_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), OmcRegistryError> {
    let mut entries = fs::read_dir(current)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if file_type.is_dir() {
            if pip_local_wheel_skip_dir(&name) {
                continue;
            }
            collect_pip_local_wheel_source_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            if !pip_local_wheel_include_file(relative) {
                continue;
            }
            files.push((wheel_archive_path(relative)?, path));
        }
    }
    Ok(())
}

pub(crate) fn pip_local_wheel_skip_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(
            name,
            "__pycache__" | "build" | "dist" | "venv" | ".venv" | ".omc"
        )
        || name.ends_with(".egg-info")
        || name.ends_with(".dist-info")
}

pub(crate) fn pip_local_wheel_include_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name.ends_with(".pyc")
        || name == "pyproject.toml"
        || name == "setup.cfg"
        || name == "setup.py"
    {
        return false;
    }
    true
}

pub(crate) fn pip_local_wheel_metadata_content(
    package_dir: &Path,
    metadata: &PipLocalWheelMetadata,
) -> Result<String, OmcRegistryError> {
    let mut content = format!(
        "Metadata-Version: 2.1\nName: {}\nVersion: {}\n",
        metadata.name, metadata.version
    );
    for requirement in &metadata.requires_dist {
        if let Some(requirement) = pip_local_wheel_metadata_requirement(package_dir, requirement)? {
            content.push_str("Requires-Dist: ");
            content.push_str(&requirement);
            content.push('\n');
        }
    }
    Ok(content)
}

pub(crate) fn pip_local_wheel_metadata_requirement(
    package_dir: &Path,
    requirement: &str,
) -> Result<Option<String>, OmcRegistryError> {
    match pip_local_wheel_dependency_source(requirement, &BTreeSet::new(), package_dir)? {
        PipLocalWheelDependencySource::Skipped => Ok(None),
        PipLocalWheelDependencySource::Other => Ok(Some(requirement.to_owned())),
        PipLocalWheelDependencySource::Local(local_requirement) => {
            let dependency_dir = fs::canonicalize(&local_requirement.path).map_err(|error| {
                OmcRegistryError::UnsupportedRequirement(format!(
                    "local wheel dependency `{}` could not be resolved: {error}",
                    local_requirement.path.display()
                ))
            })?;
            let dependency_metadata =
                read_pip_local_wheel_metadata(&dependency_dir, &local_requirement.extras)?;
            Ok(Some(pip_local_wheel_pinned_requirement(
                &dependency_metadata,
                &local_requirement.extras,
            )))
        }
    }
}

pub(crate) fn pip_local_wheel_pinned_requirement(
    metadata: &PipLocalWheelMetadata,
    extras: &BTreeSet<String>,
) -> String {
    let name = if extras.is_empty() {
        metadata.name.clone()
    } else {
        format!(
            "{}[{}]",
            metadata.name,
            extras.iter().cloned().collect::<Vec<_>>().join(",")
        )
    };
    format!("{name}=={}", metadata.version)
}

pub(crate) fn pip_local_wheel_entry_points_content(entry_points: &[PipLocalWheelEntryPoint]) -> String {
    let mut by_group = BTreeMap::<String, Vec<&PipLocalWheelEntryPoint>>::new();
    for entry in entry_points {
        by_group.entry(entry.group.clone()).or_default().push(entry);
    }
    let mut content = String::new();
    for (group, mut entries) in by_group {
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        content.push('[');
        content.push_str(&group);
        content.push_str("]\n");
        for entry in entries {
            content.push_str(&entry.name);
            content.push_str(" = ");
            content.push_str(&entry.target);
            content.push('\n');
        }
        content.push('\n');
    }
    content
}


pub(crate) fn print_pip_cache(
    project_dir: &Path,
    action: PipCacheAction,
    cache_dir: Option<&Path>,
) -> Result<ExitCode, OmcRegistryError> {
    let cache_dir = cache_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| pip_cache_dir(project_dir));
    match action {
        PipCacheAction::Dir => println!("{}", cache_dir.display()),
        PipCacheAction::Info => {
            for line in pip_cache_info_lines(&cache_dir)? {
                println!("{line}");
            }
        }
        PipCacheAction::List { pattern, format } => {
            for line in pip_cache_list_lines(&cache_dir, pattern.as_deref(), format)? {
                println!("{line}");
            }
        }
        PipCacheAction::Remove { pattern } => {
            let mut files = compat_cache_files(&cache_dir)?;
            files.retain(|path| compat_cache_pattern_matches(path, &cache_dir, &pattern));
            if files.is_empty() {
                eprintln!("ERROR: No matching packages");
                return Ok(ExitCode::FAILURE);
            }
            let count = remove_cache_files(&files)?;
            prune_empty_cache_dirs(&cache_dir)?;
            println!("Files removed: {count}");
        }
        PipCacheAction::Purge => {
            let count = compat_cache_files(&cache_dir)?.len();
            if cache_dir.exists() {
                fs::remove_dir_all(&cache_dir)?;
            }
            println!("Files removed: {count}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_pip_debug(
    project_dir: &Path,
    invocation_cwd: &Path,
    action: PipDebugAction,
) -> Result<(), OmcRegistryError> {
    print!(
        "{}",
        pip_debug_report(project_dir, invocation_cwd, &action)?
    );
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

pub(crate) fn pip_cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".omc").join("cache").join("pypi")
}

pub(crate) fn pip_cache_arg_or_env(invocation_cwd: &Path, cache_dir: Option<PathBuf>) -> Option<PathBuf> {
    cache_dir
        .or_else(pip_cache_dir_env)
        .map(|path| absolutize_path(invocation_cwd, path))
}

pub(crate) fn pip_cache_dir_env() -> Option<PathBuf> {
    env_path_from_any(["PIP_CACHE_DIR"])
}

pub(crate) fn pip_cache_list_lines(
    cache_dir: &Path,
    pattern: Option<&str>,
    format: PipCacheListFormat,
) -> Result<Vec<String>, OmcRegistryError> {
    let mut files = compat_cache_files(cache_dir)?;
    if let Some(pattern) = pattern {
        files.retain(|path| compat_cache_pattern_matches(path, cache_dir, pattern));
    }
    files.sort();
    if files.is_empty() && format == PipCacheListFormat::Human {
        return Ok(vec!["Nothing cached.".to_owned()]);
    }
    Ok(files
        .into_iter()
        .map(|path| pip_cache_list_display_path(&path, cache_dir, format))
        .collect())
}

pub(crate) fn pip_cache_info_lines(cache_dir: &Path) -> Result<Vec<String>, OmcRegistryError> {
    let files = compat_cache_files(cache_dir)?;
    let bytes = cache_files_size(&files)?;
    Ok(vec![
        format!(
            "Package index page cache location: {}",
            cache_dir.join("http").display()
        ),
        "Package index page cache size: 0 bytes".to_owned(),
        "Number of HTTP files: 0".to_owned(),
        format!("Wheels location: {}", cache_dir.display()),
        format!("Wheels size: {bytes} bytes"),
        format!("Number of wheels: {}", files.len()),
    ])
}

pub(crate) fn pip_cache_list_display_path(
    path: &Path,
    cache_dir: &Path,
    format: PipCacheListFormat,
) -> String {
    match format {
        PipCacheListFormat::Human => compat_cache_display_path(path, cache_dir),
        PipCacheListFormat::Abspath => path.display().to_string(),
    }
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

pub(crate) fn print_pip_path_freeze(
    project_dir: &Path,
    paths: &[PathBuf],
    exclude: &[String],
    exclude_editable: bool,
    requirements: &[PathBuf],
) -> Result<(), OmcRegistryError> {
    let excluded = pip_excluded_names(exclude);
    let entries = read_pip_path_packages(project_dir, paths, exclude, PipEditableMode::Exclude)?
        .into_iter()
        .map(|package| PipFrozenRequirement {
            name: Some(normalize_pip_show_name(&package.name)),
            line: format!("{}=={}", package.name, package.version),
        })
        .chain(if exclude_editable {
            Vec::new()
        } else {
            pip_freeze_path_local_entries(project_dir, paths, &excluded)?
        })
        .collect::<Vec<_>>();
    print_pip_freeze_output(pip_freeze_output(project_dir, entries, requirements)?);
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PipFreezeOutput {
    pub(crate) warnings: Vec<String>,
    pub(crate) lines: Vec<String>,
}

pub(crate) fn pip_freeze_output(
    project_dir: &Path,
    entries: Vec<PipFrozenRequirement>,
    requirements: &[PathBuf],
) -> Result<PipFreezeOutput, OmcRegistryError> {
    if requirements.is_empty() {
        return Ok(PipFreezeOutput {
            warnings: Vec::new(),
            lines: entries.into_iter().map(|entry| entry.line).collect(),
        });
    }

    let mut by_name = BTreeMap::new();
    for entry in &entries {
        if let Some(name) = &entry.name {
            by_name.insert(name.clone(), entry.line.clone());
        }
    }

    let mut emitted = BTreeSet::new();
    let mut emitted_lines = BTreeSet::new();
    let mut output = PipFreezeOutput::default();
    for requirement in requirements {
        let path = absolutize_path(project_dir, requirement.clone());
        let content = fs::read_to_string(&path)?;
        for line in content.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                emitted_lines.insert(line.to_owned());
                output.lines.push(line.to_owned());
                continue;
            }

            let Some(name) = pip_requirement_line_name(line) else {
                emitted_lines.insert(line.to_owned());
                output.lines.push(line.to_owned());
                continue;
            };
            if let Some(frozen) = by_name.get(&name) {
                if emitted.insert(name) {
                    emitted_lines.insert(frozen.clone());
                    output.lines.push(frozen.clone());
                }
            } else {
                output.warnings.push(format!(
                    "WARNING: Requirement file [{}] contains {}, but package '{}' is not installed",
                    path.display(),
                    line.trim(),
                    name
                ));
            }
        }
    }

    let remaining = entries
        .into_iter()
        .filter(|entry| {
            if let Some(name) = entry.name.as_deref() {
                !emitted.contains(name) && !emitted_lines.contains(&entry.line)
            } else {
                !emitted_lines.contains(&entry.line)
            }
        })
        .map(|entry| entry.line)
        .collect::<Vec<_>>();
    if !remaining.is_empty() {
        output
            .lines
            .push("## The following requirements were added by pip freeze:".to_owned());
        output.lines.extend(remaining);
    }

    Ok(output)
}

pub(crate) fn print_pip_freeze_output(output: PipFreezeOutput) {
    for warning in output.warnings {
        eprintln!("{warning}");
    }
    for line in output.lines {
        println!("{line}");
    }
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

#[cfg(test)]
pub(crate) fn pip_freeze_local_path_requirements(project_dir: &Path) -> Result<Vec<String>, OmcRegistryError> {
    let local_paths_file = project_dir.join(".omc").join("python").join("local-paths");
    Ok(
        pip_freeze_local_path_entries_from_file(local_paths_file, &BTreeSet::new())?
            .into_iter()
            .map(|entry| entry.line)
            .collect(),
    )
}

pub(crate) fn pip_freeze_local_path_entries(
    project_dir: &Path,
    excluded: &BTreeSet<String>,
) -> Result<Vec<PipFrozenRequirement>, OmcRegistryError> {
    pip_freeze_local_path_entries_from_file(
        project_dir.join(".omc").join("python").join("local-paths"),
        excluded,
    )
}

pub(crate) fn pip_freeze_path_local_entries(
    project_dir: &Path,
    paths: &[PathBuf],
    excluded: &BTreeSet<String>,
) -> Result<Vec<PipFrozenRequirement>, OmcRegistryError> {
    let mut entries = Vec::new();
    for path in paths {
        let site_packages = absolutize_path(project_dir, path.clone());
        entries.extend(pip_freeze_local_path_entries_from_file(
            site_packages.join(".omc-local-paths"),
            excluded,
        )?);
    }
    entries.sort_by(|left, right| left.line.cmp(&right.line));
    entries.dedup_by(|left, right| left.line == right.line);
    Ok(entries)
}

pub(crate) fn pip_freeze_local_path_entries_from_file(
    local_paths_file: PathBuf,
    excluded: &BTreeSet<String>,
) -> Result<Vec<PipFrozenRequirement>, OmcRegistryError> {
    let content = match fs::read_to_string(local_paths_file) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut entries = Vec::new();
    for path in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<BTreeSet<_>>()
    {
        let import_path = Path::new(path);
        if pip_freeze_is_omc_vcs_import_path(import_path) {
            continue;
        }
        let name = pip_local_editable_package(import_path)?
            .map(|package| normalize_pip_show_name(&package.name));
        if name
            .as_ref()
            .is_some_and(|name| excluded.contains(name.as_str()))
        {
            continue;
        }
        entries.push(PipFrozenRequirement {
            name,
            line: format!("-e {path}"),
        });
    }
    Ok(entries)
}

pub(crate) fn pip_freeze_is_omc_vcs_import_path(path: &Path) -> bool {
    let mut state = 0;
    for component in path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
    {
        state = match (state, component) {
            (_, ".omc") => 1,
            (1, "python") => 2,
            (2, "vcs") => return true,
            _ => 0,
        };
    }
    false
}

pub(crate) fn pip_freeze_vcs_requirement(dependency: &LockedPythonVcsDependency) -> String {
    let mut name = dependency.name.clone();
    if !dependency.extras.is_empty() {
        name.push('[');
        name.push_str(&dependency.extras.join(","));
        name.push(']');
    }

    let reference = if dependency.resolved_commit.is_empty() {
        dependency.reference.as_deref().unwrap_or_default()
    } else {
        dependency.resolved_commit.as_str()
    };
    let mut url = format!("git+{}", dependency.url);
    if !reference.is_empty() {
        url.push('@');
        url.push_str(reference);
    }
    if let Some(subdirectory) = &dependency.subdirectory {
        if !subdirectory.is_empty() {
            url.push_str("#subdirectory=");
            url.push_str(subdirectory);
        }
    }

    format!("{name} @ {url}")
}

pub(crate) fn print_locked_pip_list(
    project_dir: &Path,
    format: PipListFormat,
    verbose: bool,
    exclude: &[String],
    editable: PipEditableMode,
    not_required: bool,
) -> Result<(), OmcRegistryError> {
    let mut packages = locked_pip_installed_packages(project_dir, exclude, editable)?;
    if not_required {
        packages = pip_not_required_packages(packages);
    }
    print_pip_installed_list(format, verbose, &packages)
}

pub(crate) fn print_pip_path_list(
    project_dir: &Path,
    format: PipListFormat,
    verbose: bool,
    paths: &[PathBuf],
    exclude: &[String],
    editable: PipEditableMode,
    not_required: bool,
) -> Result<(), OmcRegistryError> {
    let mut packages = read_pip_path_packages(project_dir, paths, exclude, editable)?;
    if not_required {
        packages = pip_not_required_packages(packages);
    }
    print_pip_installed_list(format, verbose, &packages)
}

pub(crate) fn print_pip_installed_list(
    format: PipListFormat,
    verbose: bool,
    packages: &[InstalledPythonPackage],
) -> Result<(), OmcRegistryError> {
    match format {
        PipListFormat::Columns => {
            if let Some(output) = pip_columns_list_output(packages, verbose) {
                print!("{output}");
            }
        }
        PipListFormat::Freeze => {
            for package in packages {
                println!("{}=={}", package.name, package.version);
            }
        }
        PipListFormat::Json => {
            println!("{}", pip_installed_list_json_output(packages, verbose)?);
        }
    }
    Ok(())
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

pub(crate) fn pip_local_editable_packages_from_file(
    local_paths_file: PathBuf,
    excluded: &BTreeSet<String>,
) -> Result<Vec<InstalledPythonPackage>, OmcRegistryError> {
    let content = match fs::read_to_string(&local_paths_file) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut packages = BTreeMap::new();
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let path = PathBuf::from(line);
        let Some(mut package) = pip_local_editable_package(&path)? else {
            continue;
        };
        package.install_location = pip_local_paths_install_location(&local_paths_file);
        if !pip_name_excluded(&package.name, excluded) {
            packages.insert(normalize_pip_show_name(&package.name), package);
        }
    }
    Ok(packages.into_values().collect())
}

pub(crate) fn pip_local_paths_install_location(local_paths_file: &Path) -> Option<PathBuf> {
    let parent = local_paths_file.parent()?;
    if local_paths_file.file_name().and_then(|name| name.to_str()) == Some("local-paths") {
        return Some(parent.join("site-packages"));
    }
    Some(parent.to_path_buf())
}

pub(crate) fn pip_local_editable_package(
    import_path: &Path,
) -> Result<Option<InstalledPythonPackage>, OmcRegistryError> {
    let project_root = pip_editable_project_root(import_path);
    let Some((name, version)) = read_python_project_identity(&project_root)? else {
        return Ok(None);
    };
    let metadata = read_python_project_show_metadata(&project_root)?;
    Ok(Some(InstalledPythonPackage {
        name,
        version,
        dependencies: if metadata.requires_dist.is_empty() {
            metadata.requires.clone()
        } else {
            metadata.requires_dist
        },
        install_location: None,
        metadata_location: None,
        editable_project_location: Some(import_path.to_path_buf()),
    }))
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

pub(crate) fn print_locked_pip_inspect(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let mut installed = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .map(|package| {
            let metadata_location = match_dist_info_dir(&site_packages, &package)?
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| site_packages.display().to_string());
            Ok(serde_json::json!({
                "metadata": {
                    "name": package.name,
                    "version": package.version,
                },
                "metadata_location": metadata_location,
                "installer": "omc",
                "requested": false,
                "dependencies": package.dependencies,
            }))
        })
        .collect::<Result<Vec<_>, OmcRegistryError>>()?;
    installed.extend(
        pip_project_local_path_packages(project_dir, &[])?
            .into_iter()
            .map(pip_inspect_installed_package)
            .collect::<Vec<_>>(),
    );
    let value = serde_json::json!({
        "version": "1",
        "pip_version": format!("omc-{}", env!("CARGO_PKG_VERSION")),
        "installed": installed,
        "environment": {},
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) fn print_pip_path_inspect(project_dir: &Path, paths: &[PathBuf]) -> Result<(), OmcRegistryError> {
    let installed = pip_path_inspect_entries(project_dir, paths)?;
    let value = serde_json::json!({
        "version": "1",
        "pip_version": format!("omc-{}", env!("CARGO_PKG_VERSION")),
        "installed": installed,
        "environment": {},
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
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
    format: PipListFormat,
    verbose: bool,
    paths: &'a [PathBuf],
    exclude: &'a [String],
    editable: PipEditableMode,
    not_required: bool,
    uptodate: bool,
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    allow_prereleases: bool,
}

pub(crate) fn print_pip_outdated(
    project_dir: &Path,
    options: PipOutdatedOptions<'_>,
) -> Result<(), OmcRegistryError> {
    if options.paths.is_empty() {
        return print_locked_pip_outdated(project_dir, options);
    }

    let mut packages = read_pip_path_packages(
        project_dir,
        options.paths,
        options.exclude,
        options.editable,
    )?;
    if options.not_required {
        packages = pip_not_required_packages(packages);
    }
    let mut rows = Vec::new();
    for package in packages {
        let listing = match read_pypi_available_versions(
            project_dir,
            &package.name,
            pypi_available_versions_options(
                options.index_url.clone(),
                options.extra_index_urls.clone(),
                options.find_links.clone(),
                options.no_index,
                options.allow_prereleases,
            ),
        ) {
            Ok(listing) => listing,
            Err(OmcRegistryError::PackageNotFound(_)) => continue,
            Err(error) => return Err(error),
        };
        let Some(latest_version) = listing.versions.first() else {
            continue;
        };
        if pip_version_status_matches(latest_version, &package.version, options.uptodate) {
            rows.push(PipOutdatedPackage {
                name: package.name,
                version: package.version,
                latest_version: latest_version.clone(),
                latest_filetype: "wheel".to_owned(),
                install_location: package.install_location,
                installer: "omc".to_owned(),
            });
        }
    }
    print_pip_outdated_rows(options.format, options.verbose, rows)
}

pub(crate) fn print_locked_pip_outdated(
    project_dir: &Path,
    options: PipOutdatedOptions<'_>,
) -> Result<(), OmcRegistryError> {
    let excluded = pip_excluded_names(options.exclude);
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let required = if options.not_required {
        lock.packages
            .iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .flat_map(|package| package.dependencies.iter())
            .filter_map(|dependency| pip_installed_dependency_name(dependency))
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let mut rows = Vec::new();
    if options.editable.includes_regular() {
        for package in lock
            .packages
            .into_iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .filter(|package| !pip_name_excluded(&package.name, &excluded))
            .filter(|package| {
                !options.not_required || !required.contains(&normalize_pip_show_name(&package.name))
            })
        {
            let listing = match read_pypi_available_versions(
                project_dir,
                &package.name,
                pypi_available_versions_options(
                    options.index_url.clone(),
                    options.extra_index_urls.clone(),
                    options.find_links.clone(),
                    options.no_index,
                    options.allow_prereleases,
                ),
            ) {
                Ok(listing) => listing,
                Err(OmcRegistryError::PackageNotFound(_)) => continue,
                Err(error) => return Err(error),
            };
            let Some(latest_version) = listing.versions.first() else {
                continue;
            };
            if pip_version_status_matches(latest_version, &package.version, options.uptodate) {
                let metadata_location = match_dist_info_dir(&site_packages, &package)?;
                let install_location = metadata_location
                    .as_deref()
                    .and_then(Path::parent)
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| site_packages.clone());
                rows.push(PipOutdatedPackage {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    latest_version: latest_version.clone(),
                    latest_filetype: pip_locked_package_filetype(&package).to_owned(),
                    install_location: Some(install_location),
                    installer: "omc".to_owned(),
                });
            }
        }
    }
    if options.editable.includes_editables() {
        for package in pip_project_local_path_packages(project_dir, options.exclude)? {
            if options.not_required && required.contains(&normalize_pip_show_name(&package.name)) {
                continue;
            }
            let listing = match read_pypi_available_versions(
                project_dir,
                &package.name,
                pypi_available_versions_options(
                    options.index_url.clone(),
                    options.extra_index_urls.clone(),
                    options.find_links.clone(),
                    options.no_index,
                    options.allow_prereleases,
                ),
            ) {
                Ok(listing) => listing,
                Err(OmcRegistryError::PackageNotFound(_)) => continue,
                Err(error) => return Err(error),
            };
            let Some(latest_version) = listing.versions.first() else {
                continue;
            };
            if pip_version_status_matches(latest_version, &package.version, options.uptodate) {
                rows.push(PipOutdatedPackage {
                    name: package.name,
                    version: package.version,
                    latest_version: latest_version.clone(),
                    latest_filetype: "editable".to_owned(),
                    install_location: package.install_location,
                    installer: "omc".to_owned(),
                });
            }
        }
    }
    print_pip_outdated_rows(options.format, options.verbose, rows)
}

pub(crate) fn pip_version_status_matches(latest_version: &str, current_version: &str, uptodate: bool) -> bool {
    let latest_is_newer = compare_pypi_versions(latest_version, current_version).is_gt();
    if uptodate {
        !latest_is_newer
    } else {
        latest_is_newer
    }
}

pub(crate) fn print_pip_outdated_rows(
    format: PipListFormat,
    verbose: bool,
    mut rows: Vec<PipOutdatedPackage>,
) -> Result<(), OmcRegistryError> {
    rows.sort_by(|left, right| left.name.cmp(&right.name));

    match format {
        PipListFormat::Columns => {
            if !rows.is_empty() {
                let headers = if verbose {
                    vec![
                        "Package",
                        "Version",
                        "Latest",
                        "Type",
                        "Location",
                        "Installer",
                    ]
                } else {
                    vec!["Package", "Version", "Latest", "Type"]
                };
                let rows = rows
                    .into_iter()
                    .map(|row| {
                        let mut values = vec![
                            row.name,
                            row.version,
                            row.latest_version,
                            row.latest_filetype,
                        ];
                        if verbose {
                            values.push(
                                row.install_location
                                    .map(|path| path.display().to_string())
                                    .unwrap_or_default(),
                            );
                            values.push(row.installer);
                        }
                        values
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
                println!(
                    "{}",
                    pip_columns_join_row(
                        &headers
                            .iter()
                            .map(|value| value.to_string())
                            .collect::<Vec<_>>(),
                        &widths,
                    )
                );
                println!(
                    "{}",
                    pip_columns_join_row(
                        &widths
                            .iter()
                            .map(|width| "-".repeat(*width))
                            .collect::<Vec<_>>(),
                        &widths,
                    )
                );
                for row in rows {
                    println!("{}", pip_columns_join_row(&row, &widths));
                }
            }
        }
        PipListFormat::Json => {
            println!("{}", pip_outdated_rows_json_output(&rows, verbose)?);
        }
        PipListFormat::Freeze => {
            for row in rows {
                println!("{}=={}", row.name, row.version);
            }
        }
    }
    Ok(())
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

pub(crate) fn print_locked_pip_show(
    project_dir: &Path,
    specs: &[String],
    include_files: bool,
) -> Result<ExitCode, OmcRegistryError> {
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip show needs at least one package".to_owned(),
        ));
    }

    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let packages = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .collect::<Vec<_>>();
    let editable_packages = pip_project_local_path_packages(project_dir, &[])?;
    let mut missing = Vec::new();
    let mut printed = false;
    for spec in specs {
        let normalized = normalize_pip_show_name(spec);
        if let Some(package) = packages
            .iter()
            .find(|package| normalize_pip_show_name(&package.name) == normalized)
        {
            if printed {
                println!("---");
            }
            print_pip_show_package(project_dir, package, &packages, include_files)?;
            printed = true;
            continue;
        }
        if let Some(package) = editable_packages
            .iter()
            .find(|package| normalize_pip_show_name(&package.name) == normalized)
        {
            if printed {
                println!("---");
            }
            print_pip_show_editable_package(package, &packages, include_files)?;
            printed = true;
            continue;
        }
        missing.push(spec.clone());
    }

    if !missing.is_empty() {
        eprintln!("WARNING: Package(s) not found: {}", missing.join(", "));
        return Ok(ExitCode::FAILURE);
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_pip_path_show(
    project_dir: &Path,
    paths: &[PathBuf],
    specs: &[String],
    include_files: bool,
) -> Result<ExitCode, OmcRegistryError> {
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip show needs at least one package".to_owned(),
        ));
    }

    let packages = read_pip_path_packages(project_dir, paths, &[], PipEditableMode::Include)?;
    let mut missing = Vec::new();
    let mut printed = false;
    for spec in specs {
        let normalized = normalize_pip_show_name(spec);
        if let Some(package) = packages
            .iter()
            .find(|package| normalize_pip_show_name(&package.name) == normalized)
        {
            if printed {
                println!("---");
            }
            print_pip_show_installed_package(package, &packages, include_files)?;
            printed = true;
        } else {
            missing.push(spec.clone());
        }
    }

    if !missing.is_empty() {
        eprintln!("WARNING: Package(s) not found: {}", missing.join(", "));
        return Ok(ExitCode::FAILURE);
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_locked_pip_check(project_dir: &Path) -> Result<ExitCode, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let issues = pip_check_installed_packages(project_dir, &lock)?;
    print_pip_check_issues(issues)
}

pub(crate) fn print_pip_path_check(
    project_dir: &Path,
    paths: &[PathBuf],
) -> Result<ExitCode, OmcRegistryError> {
    let packages = read_pip_path_packages(project_dir, paths, &[], PipEditableMode::Include)?;
    let issues = pip_check_installed_package_set(&packages);
    print_pip_check_issues(issues)
}

pub(crate) fn print_pip_check_issues(issues: Vec<PypiCheckIssue>) -> Result<ExitCode, OmcRegistryError> {
    if issues.is_empty() {
        println!("No broken requirements found.");
        return Ok(ExitCode::SUCCESS);
    }

    for issue in issues {
        match issue {
            PypiCheckIssue::Missing {
                package,
                version,
                requirement,
            } => {
                println!("{package} {version} requires {requirement}, which is not installed.");
            }
            PypiCheckIssue::Incompatible {
                package,
                version,
                requirement,
                installed_name,
                installed_version,
            } => {
                println!(
                    "{package} {version} has requirement {requirement}, but you have {installed_name} {installed_version}."
                );
            }
        }
    }
    Ok(ExitCode::FAILURE)
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

pub(crate) fn print_pip_show_package(
    project_dir: &Path,
    package: &LockedPackage,
    packages: &[LockedPackage],
    include_files: bool,
) -> Result<(), OmcRegistryError> {
    let site_packages = absolute_project_dir(project_dir)
        .join(".omc")
        .join("python")
        .join("site-packages");
    let metadata = read_pip_show_metadata(&site_packages, package)?;
    let requires = if metadata.requires.is_empty() {
        pip_dependency_names(package)
    } else {
        metadata.requires
    };
    println!("Name: {}", package.name);
    println!("Version: {}", package.version);
    println!("Summary: {}", metadata.summary.unwrap_or_default());
    println!(
        "Home-page: {}",
        metadata
            .home_page
            .unwrap_or_else(|| package.source_url.clone())
    );
    println!("Author: {}", metadata.author.unwrap_or_default());
    println!(
        "Author-email: {}",
        metadata.author_email.unwrap_or_default()
    );
    println!("License: {}", metadata.license.unwrap_or_default());
    println!("Location: {}", site_packages.display());
    println!("Requires: {}", requires.join(", "));
    println!(
        "Required-by: {}",
        pip_required_by_names(package, packages).join(", ")
    );
    if include_files {
        println!("Files:");
        for file in pip_installed_files(&site_packages, package)? {
            println!("  {file}");
        }
    }
    Ok(())
}

pub(crate) fn print_pip_show_editable_package(
    package: &InstalledPythonPackage,
    packages: &[LockedPackage],
    include_files: bool,
) -> Result<(), OmcRegistryError> {
    let location = package
        .editable_project_location
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let metadata = read_python_project_show_metadata(&pip_editable_project_root(&location))?;
    let requires = if metadata.requires.is_empty() {
        package.dependencies.clone()
    } else {
        metadata.requires
    };
    println!("Name: {}", package.name);
    println!("Version: {}", package.version);
    println!("Summary: {}", metadata.summary.unwrap_or_default());
    println!("Home-page: {}", metadata.home_page.unwrap_or_default());
    println!("Author: {}", metadata.author.unwrap_or_default());
    println!(
        "Author-email: {}",
        metadata.author_email.unwrap_or_default()
    );
    println!("License: {}", metadata.license.unwrap_or_default());
    println!("Location: {}", location.display());
    println!("Requires: {}", requires.join(", "));
    println!(
        "Required-by: {}",
        pip_required_by_package_name(&package.name, packages).join(", ")
    );
    if include_files {
        println!("Files:");
        print_pip_show_files_or_missing(pip_editable_project_files(&location)?);
    }
    Ok(())
}

pub(crate) fn print_pip_show_installed_package(
    package: &InstalledPythonPackage,
    packages: &[InstalledPythonPackage],
    include_files: bool,
) -> Result<(), OmcRegistryError> {
    let metadata = if let Some(dist_info) = &package.metadata_location {
        read_pip_show_metadata_from_dist_info(dist_info)?
    } else if let Some(location) = &package.editable_project_location {
        read_python_project_show_metadata(&pip_editable_project_root(location))?
    } else {
        PipShowMetadata::default()
    };
    let requires = if metadata.requires.is_empty() {
        package
            .dependencies
            .iter()
            .filter_map(|dependency| pip_installed_dependency_name(dependency))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        metadata.requires
    };
    let location = package
        .metadata_location
        .as_ref()
        .and_then(|path| path.parent())
        .or(package.editable_project_location.as_deref())
        .map(Path::to_path_buf)
        .unwrap_or_default();
    println!("Name: {}", package.name);
    println!("Version: {}", package.version);
    println!("Summary: {}", metadata.summary.unwrap_or_default());
    println!("Home-page: {}", metadata.home_page.unwrap_or_default());
    println!("Author: {}", metadata.author.unwrap_or_default());
    println!(
        "Author-email: {}",
        metadata.author_email.unwrap_or_default()
    );
    println!("License: {}", metadata.license.unwrap_or_default());
    println!("Location: {}", location.display());
    println!("Requires: {}", requires.join(", "));
    println!(
        "Required-by: {}",
        pip_required_by_installed_package_name(&package.name, packages).join(", ")
    );
    if include_files {
        println!("Files:");
        if let Some(dist_info) = &package.metadata_location {
            for file in pip_installed_files_from_dist_info(dist_info)? {
                println!("  {file}");
            }
        } else if let Some(location) = &package.editable_project_location {
            print_pip_show_files_or_missing(pip_editable_project_files(location)?);
        } else {
            println!("Cannot locate RECORD or installed-files.txt");
        }
    }
    Ok(())
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

pub(crate) fn print_pip_show_files_or_missing(files: Vec<String>) {
    if files.is_empty() {
        println!("Cannot locate RECORD or installed-files.txt");
        return;
    }
    for file in files {
        println!("  {file}");
    }
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

pub(crate) fn parse_pip_completion_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
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

pub(crate) fn parse_pip_index_common_args(args: &[String]) -> Result<PipIndexArgs, OmcRegistryError> {
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

pub(crate) fn parse_pip_config_common_args(args: &[String]) -> Result<PipConfigArgs, OmcRegistryError> {
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

pub(crate) fn pip_config_assignment(key: &str, value: &str) -> Result<(String, String), OmcRegistryError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config key cannot be empty".to_owned(),
        ));
    }
    Ok((key.to_owned(), value.trim().to_owned()))
}

pub(crate) fn parse_pip_uninstall_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
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

pub(crate) fn parse_pip_cache_list_format(value: &str) -> Result<PipCacheListFormat, OmcRegistryError> {
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

pub(crate) fn parse_pip_download_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
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

pub(crate) fn expand_pip_artifact_short_clusters(args: &[String], command: PipArtifactCommand) -> Vec<String> {
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

