use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, ffi::OsString, fs};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{Duration, SecondsFormat, Utc};
#[cfg(test)]
use flate2::write::GzEncoder;
#[cfg(test)]
use flate2::Compression;
#[cfg(test)]
use clap::Parser;
use omc_cap::Capability;
use omc_registry::{
    add_manifest_npm_local_paths, add_npm_dist_tag, add_package_graph, apply_pypi_binary_option, apply_pypi_environment_defaults, apply_pypi_release_control, compare_npm_versions, compare_pypi_versions, deprecate_npm_package, download_npm_package_tarball, install_locked_packages, install_locked_project, install_project, install_python_project_local_import_paths, lock_project, parse_capability_grant, parse_flow_rule, parse_npm_direct_archive_reference, parse_pypi_direct_archive_reference, parse_pypi_vcs_requirement, prune_locked_package_versions, publish_npm_package, pypi_marker_applies, read_constraint_files, read_lockfile, read_manifest, read_npm_config_snapshot_with_globalconfig, read_npm_package_metadata, read_npm_package_metadata_with_userconfig, read_npm_search, read_npm_workspace_packages, read_pip_config_snapshot, read_pypi_available_versions, read_requirements_files, read_script_requirement_files, remove_locked_packages, remove_manifest_dependency, remove_npm_dist_tag, unpublish_npm_package, Behavior, Ecosystem, InstallReport, LinkOptions, LockedLocalSource, LockedPackage, ManifestDependencyKind, NpmDeprecateResult, NpmPackageTarball, NpmProvenanceBundle, NpmPublishPackage, NpmPublishResult, NpmSearchPackage, NpmTokenCreateOptions, NpmUnpublishResult, NpmWorkspacePackage, OmcLock, OmcRegistryError, PackageSpec, ProjectRequirements, PypiAvailableVersionsOptions, PypiBinaryMode, PypiReleaseControl, PypiReleaseControls, PythonLocalRequirement, PythonVcsRequirement, Verdict,
};
#[cfg(test)]
use omc_registry::{LockedPythonVcsDependency, PypiCheckIssue};
use sha2::{Digest, Sha256};

pub(crate) mod args;
pub(crate) mod compile;
pub(crate) mod direct_compat;
pub(crate) mod dispatch;
pub(crate) mod exec_cell;
pub(crate) mod install;
pub(crate) mod manifest;
pub(crate) mod npm_account;
pub(crate) mod npm_cli_parse;
pub(crate) mod npm_compat;
pub(crate) mod npm_config_cli;
pub(crate) mod npm_exec;
pub(crate) mod npm_publish_cli;
pub(crate) mod npm_query_cli;
pub(crate) mod parse;
pub(crate) mod pip_compat;
pub(crate) mod pip_config_cli;
pub(crate) mod pip_cli;
pub(crate) mod pip_parse;
pub(crate) mod policy;
pub(crate) mod policy_args;
pub(crate) mod render;
pub(crate) mod script;
pub(crate) mod shim;
pub(crate) mod temp_project;
pub(crate) mod twine_compat;

#[cfg(test)]
use compile::{compile_source_default_name, infer_compile_ecosystem};

use manifest::{
    parse_package_spec, parse_package_specs, package_spec_has_ecosystem_prefix,
};
#[cfg(test)]
use direct_compat::{discover_direct_compat_project_dir_from, DirectCompatInvocation};
use parse::{npm_next_version, parse_npm_archive_references, parse_pip_archive_references};
use npm_cli_parse::*;
use render::{
    behavior_label, print_audit_report, print_install_report, print_link_reports,
    print_npm_install_json_report, verdict_label,
};
#[cfg(test)]
use render::pip_install_report_json;
use temp_project::TempOmcProject;
use shim::command_program_for_cwd;
#[cfg(test)]
use shim::{python_pip_module_args, python_twine_module_args};
use crate::twine_compat::run_twine_compat_with_cwd;
#[cfg(test)]
use crate::twine_compat::{
    absolutize_twine_upload_action_paths, parse_twine_compat_action, print_twine_check,
    resolve_twine_upload_settings, twine_attestation_path, twine_upload_attestations_json,
    twine_upload_inputs,
};
use script::{
    print_npm_run_list, run_package_script_with_npm_command_for_workspaces,
};
#[cfg(test)]
use script::{package_script_lifecycle_order, run_package_script_with_npm_command};

use crate::args::*;

pub(crate) use crate::pip_cli::*;
pub(crate) use crate::pip_parse::*;

pub(crate) use npm_query_cli::{
    npm_view_field_value,
    parse_npm_audit_args,
    parse_npm_diff_args,
    parse_npm_fund_args,
    parse_npm_outdated_args,
    parse_npm_query_args,
    parse_npm_search_args,
    parse_npm_view_args,
    print_npm_diff,
    print_npm_fund,
    print_npm_outdated,
    print_npm_query,
    print_npm_search,
    print_npm_view,
};
#[cfg(test)]
pub(crate) use npm_query_cli::{
    NpmQueryItem,
    collect_npm_fund_report,
    normalize_npm_funding,
    npm_diff_changed_files,
    npm_diff_file_patch,
    npm_diff_package_tarball,
    npm_fund_report_json,
    npm_funding_urls,
    npm_query_items,
    npm_query_selector_matches,
    npm_view_metadata_value,
};
use crate::npm_compat::NpmLinkAction;
pub(crate) use crate::npm_account::{
    absolutize_npm_access_action_paths, absolutize_npm_login_action_paths,
    absolutize_npm_logout_action_paths, absolutize_npm_org_action_paths,
    absolutize_npm_owner_action_paths, absolutize_npm_profile_action_paths,
    absolutize_npm_star_action_paths, absolutize_npm_team_action_paths,
    absolutize_npm_token_action_paths, absolutize_npm_trust_action_paths, parse_npm_access_args,
    parse_npm_login_args, parse_npm_logout_args, parse_npm_org_args, parse_npm_owner_args,
    parse_npm_ping_args, parse_npm_profile_args, parse_npm_star_args, parse_npm_stars_args,
    parse_npm_team_args, parse_npm_token_args, parse_npm_trust_args, parse_npm_whoami_args,
    print_npm_access, print_npm_login, print_npm_logout, print_npm_org, print_npm_owner,
    print_npm_ping, print_npm_profile, print_npm_star, print_npm_team, print_npm_token,
    print_npm_trust, print_npm_whoami,
};
pub(crate) use crate::npm_config_cli::{
    npm_config_editor, npm_config_line_key, npm_config_write_path, read_npm_config_lines,
    run_npm_config_edit, strip_npm_config_comment, upsert_npm_config_line, write_npm_config_lines,
};
use crate::pip_config_cli::{
    pip_config_values, print_pip_config, run_pip_config_edit, strip_pip_config_comment,
};
#[cfg(not(test))]
use crate::pip_config_cli::pip_global_config_default_path;
#[cfg(test)]
use crate::pip_config_cli::{
    pip_config_debug_report, pip_config_list_value, pip_config_value_for_key, pip_config_write_path,
};
#[cfg(test)]
use crate::npm_compat::{
    npm_link_store_entry, npm_link_target_from_path, npm_package_json_requirement_for_link_root,
    npm_read_link_store_entry, npm_write_link_store_entry,
};
use crate::npm_exec::{npm_exec_direct_package_arg, run_npm_exec};
#[cfg(test)]
use crate::npm_exec::npm_exec_target_cwds;
pub(crate) use crate::npm_publish_cli::{
    absolutize_npm_deprecate_action_paths, absolutize_npm_pack_action_paths,
    absolutize_npm_publish_action_paths, absolutize_npm_unpublish_action_paths,
    npm_pack_package_for_publish, parse_npm_deprecate_args, parse_npm_pack_args,
    parse_npm_publish_args, parse_npm_unpublish_args, print_npm_deprecate, print_npm_pack,
    print_npm_publish, print_npm_unpublish,
};
#[cfg(test)]
use crate::npm_publish_cli::{collect_npm_pack_files, sha512_hex, write_npm_pack_tarball};
use crate::policy_args::{apply_cli_policy_options, CliPolicyArgs};
#[cfg(test)]
use crate::direct_compat::{
    direct_compat_mode, npx_compat_args, parse_direct_compat_invocation, DirectCompatMode,
};
#[cfg(test)]
use crate::npm_compat::{run_npm_compat, run_npm_compat_with_cwd};
#[cfg(test)]
use crate::policy::run_policy_command;
#[cfg(test)]
use crate::shim::run_python;

const NPM_PROFILE_KNOWN_KEYS: &[&str] = &[
    "name",
    "email",
    "two-factor auth",
    "fullname",
    "homepage",
    "freenode",
    "twitter",
    "github",
    "created",
    "updated",
];
const NPM_PROFILE_WRITABLE_KEYS: &[&str] = &[
    "email", "password", "fullname", "homepage", "freenode", "twitter", "github",
];
const DEFAULT_NPM_SAVE_PREFIX: &str = "^";

pub use dispatch::omc_main;

use crate::install::{
    apply_dependency_omit_flags, apply_pip_compatibility_target,
    install_npm_project_with_complete_lock, lock_npm_project_including_omitted,
    locked_packages_from_reports, npm_lock_options_including_omitted, pip_install_report_to_stdout,
    write_pip_install_report,
};
use crate::pip_compat::{
    parse_pip_compat_action, pip_user_install_local_paths_file,
    pip_user_paths, run_pip_install_dry_run, run_pip_install_prefix, run_pip_install_root,
    run_pip_install_target, run_pip_install_user, run_pip_uninstall_user,
};
#[cfg(test)]
use crate::pip_compat::pip_rooted_project_path;

fn pylock_toml_from_omc_lock(lock: &OmcLock) -> String {
    let mut packages = lock
        .packages
        .iter()
        .filter(|package| {
            package.ecosystem == Ecosystem::Pypi && package.verdict == Verdict::Accepted
        })
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| {
        (
            normalize_pip_show_name(&left.name),
            left.version.as_str(),
            left.source_url.as_str(),
        )
            .cmp(&(
                normalize_pip_show_name(&right.name),
                right.version.as_str(),
                right.source_url.as_str(),
            ))
    });

    let mut output = format!(
        "lock-version = \"1.0\"\ncreated-by = \"omc {}\"\n\n",
        env!("CARGO_PKG_VERSION")
    );
    for package in packages {
        output.push_str("[[packages]]\n");
        output.push_str(&format!("name = {}\n", toml_string(&package.name)));
        output.push_str(&format!("version = {}\n", toml_string(&package.version)));
        append_pylock_distribution(&mut output, package);
        output.push('\n');
    }
    output
}

fn append_pylock_distribution(output: &mut String, package: &LockedPackage) {
    if package.sha256.is_empty() {
        return;
    }
    let source = if package.source_url.is_empty() {
        package.archive.as_str()
    } else {
        package.source_url.as_str()
    };
    if source.is_empty() {
        return;
    }
    let distribution = format!(
        "{{ url = {}, hashes = {{ sha256 = {} }} }}",
        toml_string(source),
        toml_string(&package.sha256)
    );
    if pip_locked_package_filetype(package) == "sdist" {
        output.push_str(&format!("sdist = {distribution}\n"));
    } else {
        output.push_str(&format!("wheels = [\n  {distribution},\n]\n"));
    }
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NpmScriptTargets<'a> {
    pub(crate) workspaces: &'a [String],
    pub(crate) all_workspaces: bool,
    pub(crate) include_workspace_root: bool,
}

pub(crate) fn npm_script_target_dirs(
    project_dir: &Path,
    workspaces: &[String],
    all_workspaces: bool,
    include_workspace_root: bool,
) -> Result<Vec<PathBuf>, OmcRegistryError> {
    if workspaces.is_empty() && !all_workspaces {
        return Ok(vec![project_dir.to_path_buf()]);
    }

    let workspace_packages = read_npm_workspace_packages(project_dir)?;
    let mut targets = Vec::new();
    if include_workspace_root {
        targets.push(project_dir.to_path_buf());
    }
    if all_workspaces {
        targets.extend(
            workspace_packages
                .iter()
                .map(|workspace| workspace.path.clone()),
        );
    }
    for selector in workspaces {
        let workspace = select_npm_workspace(project_dir, &workspace_packages, selector)?;
        targets.push(workspace.path);
    }

    let mut seen = BTreeSet::new();
    targets.retain(|path| seen.insert(absolute_project_dir(path)));
    Ok(targets)
}

fn select_npm_workspace(
    project_dir: &Path,
    workspaces: &[NpmWorkspacePackage],
    selector: &str,
) -> Result<NpmWorkspacePackage, OmcRegistryError> {
    let selector_path = absolutize_path(project_dir, PathBuf::from(selector));
    let selector_path = fs::canonicalize(&selector_path).unwrap_or(selector_path);
    for workspace in workspaces {
        if workspace.name.as_deref() == Some(selector) {
            return Ok(workspace.clone());
        }
        let workspace_path =
            fs::canonicalize(&workspace.path).unwrap_or_else(|_| workspace.path.clone());
        if workspace_path == selector_path {
            return Ok(workspace.clone());
        }
    }

    let available = workspaces
        .iter()
        .map(|workspace| {
            workspace
                .name
                .clone()
                .unwrap_or_else(|| workspace.path.display().to_string())
        })
        .collect::<Vec<_>>()
        .join(", ");
    let detail = if available.is_empty() {
        format!("npm workspace `{selector}` was not found")
    } else {
        format!("npm workspace `{selector}` was not found; available workspaces: {available}")
    };
    Err(OmcRegistryError::UnsupportedSpec(detail))
}

fn run_npm_explore(
    project_dir: &Path,
    action: NpmExploreAction,
) -> Result<ExitCode, OmcRegistryError> {
    let package_dir = npm_installed_package_dir(project_dir, &action.package)?;
    if !package_dir.join("package.json").exists() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm explore package `{}` is not installed under {}",
            action.package,
            project_dir.join("node_modules").display()
        )));
    }

    let mut process = if let Some(command) = action.command {
        ProcessCommand::new(command)
    } else {
        ProcessCommand::new(npm_explore_shell(action.shell))
    };
    apply_project_runtime_env_for_cwd(&mut process, project_dir, &package_dir)?;
    let status = process.args(action.args).status()?;
    Ok(exit_code(status.code()))
}

fn npm_explore_shell(shell: Option<String>) -> String {
    shell
        .or_else(|| env::var("SHELL").ok())
        .filter(|shell| !shell.trim().is_empty())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "cmd".to_owned()
            } else {
                "sh".to_owned()
            }
        })
}

fn run_npm_edit(
    project_dir: &Path,
    invocation_cwd: &Path,
    target: &str,
    editor: Option<String>,
) -> Result<ExitCode, OmcRegistryError> {
    let edit_path = npm_edit_target_path(project_dir, target)?;
    if !edit_path.exists() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm edit target `{target}` is not installed under {}",
            project_dir.join("node_modules").display()
        )));
    }

    let editor = npm_config_editor(editor);
    let mut command = package_script_command(&editor);
    command.current_dir(invocation_cwd).arg(&edit_path);
    let status = command.status()?;
    Ok(exit_code(status.code()))
}

fn npm_edit_target_path(project_dir: &Path, target: &str) -> Result<PathBuf, OmcRegistryError> {
    let (package, subpath) = npm_edit_target_parts(target)?;
    let package_dir = npm_installed_package_dir(project_dir, &package)?;
    if subpath.components().next().is_none() {
        return Ok(package_dir);
    }
    Ok(package_dir.join(subpath))
}

fn npm_edit_target_parts(target: &str) -> Result<(String, PathBuf), OmcRegistryError> {
    let target = target.trim();
    if target.is_empty() || target.starts_with('/') || target.starts_with('\\') {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm edit needs a package".to_owned(),
        ));
    }

    let mut parts = target.split('/').filter(|part| !part.is_empty());
    let first = parts
        .next()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec("npm edit needs a package".to_owned()))?;
    if first.contains('\\') {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm edit target `{target}`"
        )));
    }
    let package = if first.starts_with('@') {
        let second = parts.next().ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("invalid npm edit target `{target}`"))
        })?;
        if second.contains('\\') {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "invalid npm edit target `{target}`"
            )));
        }
        format!("{first}/{second}")
    } else {
        first.to_owned()
    };

    let mut subpath = PathBuf::new();
    for part in parts {
        if matches!(part, "." | "..") || part.contains('\\') {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "invalid npm edit subpath `{target}`"
            )));
        }
        subpath.push(part);
    }
    Ok((package, subpath))
}

fn run_npm_create(cwd: &Path, action: NpmCreateAction) -> Result<ExitCode, OmcRegistryError> {
    let package_spec = npm_create_package_spec(&action.initializer)?;
    let spec = parse_package_spec(&package_spec, Some(Ecosystem::Npm))?;
    let temp_project = TempOmcProject::empty("npm-create")?;

    let mut options = LinkOptions::new(temp_project.path());
    apply_cli_policy_options(
        &mut options,
        &action.allow,
        &action.allow_flow,
        action.allow_all_host,
    )?;
    options.npm_registry_url = action.npm_registry;
    options.discover_project_requirements = false;
    options.save_manifest_dependency = true;

    add_package_graph(&spec, &options)?;
    install_project(&options)?;

    let command = npm_create_bin_name(temp_project.path(), &spec.name)?;
    let mut process = ProcessCommand::new(command_program_for_cwd(&command, cwd));
    apply_project_runtime_env_for_cwd(&mut process, temp_project.path(), cwd)?;
    let status = process.args(action.args).status()?;
    Ok(exit_code(status.code()))
}

fn npm_project_dir_from_prefix_args(
    project_dir: &Path,
    args: &[String],
) -> Result<(PathBuf, Vec<String>), OmcRegistryError> {
    let base_project_dir = absolute_project_dir(project_dir);
    let mut selected_project_dir = base_project_dir.clone();
    let mut stripped = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            stripped.extend(args[index..].iter().cloned());
            break;
        }
        if arg == "--prefix" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--prefix needs a path".to_owned(),
                ));
            };
            selected_project_dir = absolutize_path(&base_project_dir, PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--prefix=") {
            selected_project_dir = absolutize_path(&base_project_dir, PathBuf::from(path));
        } else {
            stripped.push(arg.clone());
        }
        index += 1;
    }
    Ok((selected_project_dir, stripped))
}

fn npm_args_with_config_defaults(
    project_dir: &Path,
    args: &[String],
) -> Result<Vec<String>, OmcRegistryError> {
    let mut defaults = npm_config_file_default_args(project_dir)?;
    defaults.extend(npm_environment_default_args());
    if defaults.is_empty() {
        return Ok(args.to_vec());
    }
    defaults.extend(args.iter().cloned());
    Ok(defaults)
}

fn npm_config_file_default_args(project_dir: &Path) -> Result<Vec<String>, OmcRegistryError> {
    let values = read_npm_cli_config_defaults(project_dir)?;
    let mut args = Vec::new();
    append_npm_default_args_from_config(&values, &mut args);
    Ok(args)
}

#[cfg(test)]
fn npm_args_with_environment_defaults(args: &[String]) -> Vec<String> {
    let mut defaults = npm_environment_default_args();
    if defaults.is_empty() {
        return args.to_vec();
    }
    defaults.extend(args.iter().cloned());
    defaults
}

fn npm_environment_default_args() -> Vec<String> {
    let mut args = Vec::new();
    if npm_env_var("NODE_ENV")
        .map(|value| value == "production")
        .unwrap_or(false)
    {
        args.push("--omit=dev".to_owned());
    }

    if let Some(production) = npm_config_env("production") {
        if config_bool(&production) {
            args.push("--omit=dev".to_owned());
        } else if config_false(&production) {
            args.push("--include=dev".to_owned());
        }
    }

    if let Some(only) = npm_config_env("only") {
        append_npm_only_default_args(&only, &mut args);
    }

    if let Some(optional) = npm_config_env("optional") {
        if config_false(&optional) {
            args.push("--omit=optional".to_owned());
        } else if config_bool(&optional) {
            args.push("--include=optional".to_owned());
        }
    }

    if let Some(also) = npm_config_env("also") {
        append_npm_also_default_args(&also, &mut args);
    }

    if let Some(omit) = npm_config_env("omit") {
        args.push("--include=dev,optional,peer".to_owned());
        args.push(format!("--omit={omit}"));
    }
    if let Some(include) = npm_config_env("include") {
        args.push(format!("--include={include}"));
    }
    append_npm_bool_default_arg(&mut args, "global", "--global", "--global=false");
    append_npm_bool_default_arg(&mut args, "dry-run", "--dry-run", "--dry-run=false");
    append_npm_bool_default_arg(
        &mut args,
        "package-lock-only",
        "--package-lock-only",
        "--package-lock-only=false",
    );
    append_npm_bool_default_arg(
        &mut args,
        "package-lock",
        "--package-lock",
        "--package-lock=false",
    );
    append_npm_bool_default_arg(
        &mut args,
        "engine-strict",
        "--engine-strict",
        "--engine-strict=false",
    );
    append_npm_bool_default_arg(&mut args, "offline", "--offline", "--offline=false");
    append_npm_save_location_default_args_from_env(&mut args);
    if let Some(save_exact) = npm_config_env("save-exact") {
        if config_bool(&save_exact) {
            args.push("--save-exact".to_owned());
        } else if config_false(&save_exact) {
            args.push("--save-exact=false".to_owned());
        }
    }
    append_npm_bool_default_arg(
        &mut args,
        "save-bundle",
        "--save-bundle",
        "--save-bundle=false",
    );
    if let Some(save) = npm_config_env("save") {
        if config_bool(&save) {
            args.push("--save".to_owned());
        } else if config_false(&save) {
            args.push("--no-save".to_owned());
        }
    }
    if let Some(save_prefix) = npm_config_env("save-prefix") {
        args.push(format!("--save-prefix={save_prefix}"));
    }
    if let Some(min_release_age) = npm_config_env("min-release-age") {
        args.push(format!("--min-release-age={min_release_age}"));
    }
    if let Some(before) = npm_config_env("before") {
        args.push(format!("--before={before}"));
    }

    args
}




#[cfg(test)]
thread_local! {
    /// Test-only, thread-scoped override of the npm install-mode environment.
    /// The env-defaults tests use it (via `with_npm_config_overrides`) to
    /// exercise NPM_CONFIG_*/NODE_ENV defaulting WITHOUT mutating the
    /// process-global environment — which would race with the many
    /// `run_npm_compat` reader tests running concurrently on other threads.
    /// Production never sets it; it stays `None`.
    static NPM_ENV_OVERRIDE: std::cell::RefCell<Option<std::collections::HashMap<String, String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Read an environment variable for npm install-mode config. In tests a
/// thread-local override (if set) is authoritative — present keys return their
/// value, absent keys read as unset — so a test sees a clean, deterministic env
/// and never has to touch the shared process environment. In production (and
/// when no override is set) it reads the real process environment.
fn npm_env_var(key: &str) -> Option<String> {
    #[cfg(test)]
    {
        let overridden = NPM_ENV_OVERRIDE.with(|cell| cell.borrow().is_some());
        if overridden {
            return NPM_ENV_OVERRIDE
                .with(|cell| cell.borrow().as_ref().and_then(|map| map.get(key).cloned()));
        }
    }
    env::var(key).ok()
}

fn npm_config_env(name: &str) -> Option<String> {
    let env_name = name.replace('-', "_");
    let lower = format!("npm_config_{env_name}");
    let upper = format!("NPM_CONFIG_{}", env_name.to_ascii_uppercase());
    npm_env_var(&lower)
        .or_else(|| npm_env_var(&upper))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn config_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "yes" | "true" | "on"
    )
}

fn config_false(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "no" | "false" | "off"
    )
}

fn read_npm_cli_config_defaults(
    project_dir: &Path,
) -> Result<BTreeMap<String, String>, OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let mut values = BTreeMap::new();
    let globalconfig = npm_globalconfig_path(project_dir.as_path(), None);
    let userconfig = npm_userconfig_path(project_dir.as_path(), None);
    for path in [globalconfig, userconfig, project_dir.join(".npmrc")] {
        read_npm_cli_config_defaults_file(&path, &mut values)?;
    }
    Ok(values)
}

fn read_npm_cli_config_defaults_file(
    path: &Path,
    values: &mut BTreeMap<String, String>,
) -> Result<(), OmcRegistryError> {
    if !path.exists() {
        return Ok(());
    }
    parse_npm_cli_config_defaults_content(&fs::read_to_string(path)?, values);
    Ok(())
}


fn npm_cli_default_config_key(key: &str) -> bool {
    matches!(
        key,
        "production"
            | "only"
            | "also"
            | "optional"
            | "omit"
            | "include"
            | "global"
            | "dry-run"
            | "package-lock"
            | "package-lock-only"
            | "engine-strict"
            | "offline"
            | "save"
            | "save-prod"
            | "save-dev"
            | "save-optional"
            | "save-peer"
            | "save-exact"
            | "save-bundle"
            | "save-prefix"
            | "min-release-age"
            | "before"
    )
}

fn expand_npm_config_default_value(value: &str) -> Option<String> {
    let mut expanded = String::new();
    let mut rest = value.trim().trim_matches('"').trim_matches('\'');
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let end = after_start.find('}')?;
        let key = &after_start[..end];
        expanded.push_str(&env::var(key).ok()?);
        rest = &after_start[end + 1..];
    }
    expanded.push_str(rest);
    Some(expanded.trim().to_owned())
}







fn shell_like_tokens(value: &str) -> Vec<String> {
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

struct ScopedEnvPath {
    key: &'static str,
    previous: Option<OsString>,
}

impl Drop for ScopedEnvPath {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            env::set_var(self.key, previous);
        } else {
            env::remove_var(self.key);
        }
    }
}

fn scoped_relative_env_path(key: &'static str, base_dir: &Path) -> Option<ScopedEnvPath> {
    let value = env::var_os(key)?;
    if value.is_empty() {
        return None;
    }
    let path = PathBuf::from(&value);
    if path.is_absolute() {
        return None;
    }
    let scoped = ScopedEnvPath {
        key,
        previous: Some(value),
    };
    env::set_var(key, absolutize_path(base_dir, path));
    Some(scoped)
}




pub(crate) fn absolutize_optional_path(base_dir: &Path, path: &mut Option<PathBuf>) {
    *path = path.take().map(|path| absolutize_path(base_dir, path));
}

fn npm_help_search_text(query: &[String], long: bool) -> Result<String, OmcRegistryError> {
    let terms = query
        .iter()
        .map(|term| term.trim())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm help-search needs a search term".to_owned(),
        ));
    }

    let mut topics = NPM_COMPLETION_COMMANDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    topics.extend(["get", "help-search"]);

    let mut hits = Vec::new();
    for topic in topics {
        let help = npm_help_text(Some(topic));
        if help.contains("No focused OMC help is available") {
            continue;
        }
        let topic_lower = topic.to_ascii_lowercase();
        let help_lower = help.to_ascii_lowercase();
        if !terms
            .iter()
            .all(|term| topic_lower.contains(term) || help_lower.contains(term))
        {
            continue;
        }
        let score = terms
            .iter()
            .map(|term| {
                count_substrings(&topic_lower, term) * 5 + count_substrings(&help_lower, term)
            })
            .sum::<usize>();
        let excerpts = if long {
            npm_help_search_excerpts(&help, &terms)
        } else {
            Vec::new()
        };
        hits.push((topic.to_owned(), score, excerpts));
    }
    hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let query_display = query.join(" ");
    let mut output = String::new();
    if hits.is_empty() {
        output.push_str(&format!("No matches for \"{query_display}\"\n"));
        return Ok(output);
    }

    output.push_str(&format!("Top hits for \"{query_display}\"\n"));
    output.push_str("------------------------------------------------------------\n");
    for (topic, _score, excerpts) in hits.into_iter().take(10) {
        output.push_str(&format!("npm help {topic}\n"));
        for excerpt in excerpts {
            output.push_str("  ");
            output.push_str(&excerpt);
            output.push('\n');
        }
    }
    if !long {
        output.push_str("(run with -l or --long to see matching help text)\n");
    }
    Ok(output)
}

fn count_substrings(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.match_indices(needle).count()
}

fn npm_help_search_excerpts(help: &str, terms: &[String]) -> Vec<String> {
    help.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            terms.iter().any(|term| lower.contains(term))
        })
        .take(3)
        .map(str::to_owned)
        .collect()
}

fn npm_help_text(topic: Option<&str>) -> String {
    match topic.and_then(npm_help_topic) {
        None => npm_general_help_text(),
        Some("help-search") => npm_command_help(
            "npm help-search <term...>",
            &[
                "Search OMC's npm compatibility help topics.",
                "Supports -l and --long for matching help excerpts.",
            ],
        ),
        Some("install") => npm_command_help(
            "npm install [<package-spec>...]",
            &[
                "Resolve, verify, lock, and install npm packages with OMC.",
                "Aliases: i, add, update, up, upgrade, udpate.",
                "Common flags: --save, --no-save, --save-dev, --save-optional, --save-peer, --only=prod|dev, --also=dev, --no-optional, --omit=dev|optional|peer, --include=dev|optional|peer, --workspace, --workspaces/--ws, --include-workspace-root, --package-lock-only, --prefer-offline, --prefer-online, --prefer-dedupe, --dry-run, --json, --tag, --before, --min-release-age, --engine-strict, --offline, --install-links, --registry, --allow, --allow-all-host.",
                "Direct local inputs are supported for .tgz archives and local package directories.",
                "Workspace installs save dependencies into selected workspace package.json files and install the root OMC graph.",
            ],
        ),
        Some("link") => npm_command_help(
            "npm link [<package-name>|<local-dir>|<tarball>...]",
            &[
                "Register or install local npm package links through OMC's link store.",
                "`npm link` registers the current package; `npm link ../pkg` registers and links a local directory; `npm link <name>` links a previously registered package; `npm link ./pkg.tgz` installs a local tarball through OMC's archive verifier.",
                "Links are not saved by default. Use --save, --save-dev, --save-optional, or --save-peer to record a local path or tarball dependency.",
                "Supports --dry-run, --offline, --package-lock-only, omit/include flags for dev/optional/peer dependencies, --registry for dependency refreshes, --allow, and --allow-all-host.",
            ],
        ),
        Some("ci") => npm_command_help(
            "npm ci",
            &[
                "Install the exact OMC lockfile state.",
                "Common flags: --dry-run, --json, --only=prod|dev, --also=dev, --no-optional, --prefer-offline, --prefer-online, --omit=dev|optional|peer, --include=dev|optional|peer, --allow, --allow-all-host.",
            ],
        ),
        Some("install-test") => npm_command_help(
            "npm install-test [<package-spec>...] [-- <test-args>...]",
            &[
                "Run OMC npm install, then run the root package's test script.",
                "Alias: it.",
            ],
        ),
        Some("install-ci-test") => npm_command_help(
            "npm install-ci-test [-- <test-args>...]",
            &[
                "Run OMC npm ci, then run the root package's test script.",
                "Supports --dry-run for the ci step.",
                "Alias: cit.",
            ],
        ),
        Some("run") => npm_command_help(
            "npm run [<script>] [-- <args>...]",
            &[
                "Run package.json scripts with OMC npm/Python bins and imports on PATH.",
                "Without a script, lists scripts in text or JSON mode.",
                "Common flags: --if-present, --workspace, --workspaces/--ws, --include-workspace-root, --json, --silent.",
                "Aliases: run-script. Also supports npm test/start/stop/restart.",
            ],
        ),
        Some("exec") => npm_command_help(
            "npm exec <command> [-- <args>...]",
            &[
                "Run a project-local executable with OMC runtime paths.",
                "--package installs verified packages into a temporary OMC project before running the command; --call/-c runs a shell command with the same OMC runtime paths.",
                "Aliases: x, npx. Common flags: --yes, --no-install, --package, --call, --workspace, --workspaces/--ws, --include-workspace-root, --cache, --registry, --allow, --allow-all-host.",
            ],
        ),
        Some("completion") => npm_command_help(
            "npm completion",
            &[
                "Print an OMC npm shell-completion script.",
                "The generated script asks `npm completion -- ...` for command, script, and locked package suggestions.",
            ],
        ),
        Some("explore") => npm_command_help(
            "npm explore <package> [-- <command> [args...]]",
            &[
                "Run a command from an installed package directory with OMC npm/Python bins and imports on PATH.",
                "Without a command, opens the configured shell in the package directory.",
                "Supports --shell for the interactive shell path.",
            ],
        ),
        Some("edit") => npm_command_help(
            "npm edit <package>[/<subpath>]",
            &[
                "Open an installed package directory or safe subpath in an editor.",
                "Supports --editor, VISUAL, and EDITOR. OMC does not run package lifecycle scripts after editing.",
            ],
        ),
        Some("remove") => npm_command_help(
            "npm remove <package-spec>...",
            &[
                "Remove OMC-managed npm dependencies and reinstall the remaining graph.",
                "Aliases: uninstall, unlink, rm, r, un.",
            ],
        ),
        Some("list") => npm_command_help(
            "npm list [<package-spec>...]",
            &[
                "List locked npm packages.",
                "Aliases: ls, ll, la. Common flags: --json, --depth, --omit, --include.",
            ],
        ),
        Some("query") => npm_command_help(
            "npm query <selector>",
            &[
                "Return dependency objects from omc.lock and installed package metadata as JSON.",
                "Supports common selectors: *, :root > *, #name, [name=...], [version=...], .prod, .dev, .optional, .peer, .workspace, :empty, :has(*), :not(...), and :attr(scripts, [name]).",
                "Supports --workspace, --workspaces, --include-workspace-root, --package-lock-only, --expect-results, and --expect-result-count.",
            ],
        ),
        Some("explain") => npm_command_help(
            "npm explain <package-spec>...",
            &[
                "Explain why locked npm packages are present.",
                "Alias: why. Supports --json.",
            ],
        ),
        Some("audit") => npm_command_help(
            "npm audit",
            &["Print OMC verifier and capability findings. Supports --json."],
        ),
        Some("doctor") => npm_command_help(
            "npm doctor [connection] [registry] [versions] [environment] [permissions] [cache]",
            &[
                "Print OMC npm compatibility health checks for the current project.",
                "OMC doctor is offline by design and does not probe the registry network.",
                "Supports --registry.",
            ],
        ),
        Some("outdated") => npm_command_help(
            "npm outdated",
            &["Compare locked npm packages to registry versions. Supports --json and --parseable."],
        ),
        Some("fund") => npm_command_help(
            "npm fund [<package-spec>]",
            &[
                "Show funding metadata from root/workspace package.json and installed packages.",
                "Supports --json, --workspace, --workspaces, and --include-workspace-root.",
            ],
        ),
        Some("rebuild") => npm_command_help(
            "npm rebuild [<package-spec>...]",
            &[
                "Refresh OMC's locked install state without running package lifecycle scripts.",
                "Alias: rb.",
            ],
        ),
        Some("maintenance") => npm_command_help(
            "npm <prune|dedupe>",
            &[
                "Refresh OMC's locked install state for common npm maintenance workflows.",
                "Aliases: ddp, find-dupes.",
            ],
        ),
        Some("pack") => npm_command_help(
            "npm pack [<package-spec>|<local-dir>...]",
            &[
                "Create local package tarballs or download registry tarballs.",
                "Common flags: --pack-destination, --json, --dry-run, --registry.",
            ],
        ),
        Some("publish") => npm_command_help(
            "npm publish [<local-dir>|<tarball>]",
            &[
                "Pack and publish a local npm package through the configured registry.",
                "Supports --dry-run, --json, --registry, --userconfig, --tag, --access, --otp, --provenance-file, and workspace selectors.",
                "Automatic --provenance generation needs trusted publishing/OIDC and is currently limited to dry-run reporting.",
                "Remote package specs and git URLs are not implemented yet.",
            ],
        ),
        Some("unpublish") => npm_command_help(
            "npm unpublish [<package-spec>]",
            &[
                "Remove one published npm package version or, with --force, an entire package.",
                "Supports --dry-run, --force, --json, --registry, --userconfig, --otp, and workspace selectors.",
                "Tags and semver ranges are rejected to match npm's single-version unpublish constraint.",
            ],
        ),
        Some("deprecate") => npm_command_help(
            "npm deprecate <package-spec> <message>",
            &[
                "Set deprecation warnings on all published versions matching a package semver range.",
                "Supports --dry-run, --json, --registry, --userconfig, and --otp.",
                "Use npm undeprecate <package-spec> to clear matching deprecation warnings.",
            ],
        ),
        Some("diff") => npm_command_help(
            "npm diff --diff=<spec-a> --diff=<spec-b> [<paths>...]",
            &[
                "Compare two npm package inputs and print unified patches.",
                "Each --diff input can be a registry package spec, local package directory, or npm tarball.",
                "Supports --diff-name-only, --diff-unified, --diff-ignore-all-space, --diff-no-prefix, --diff-src-prefix, --diff-dst-prefix, --diff-text, --registry, and --userconfig.",
            ],
        ),
        Some("search") => npm_command_help(
            "npm search <terms...>",
            &["Search the configured npm registry. Aliases: s, se, find. Supports --json, --parseable, --searchlimit."],
        ),
        Some("star") => npm_command_help(
            "npm <star|unstar|stars> [<package-spec>|<user>]",
            &[
                "Star or unstar npm registry packages, or list packages starred by a user.",
                "star and unstar accept one or more package specs. stars accepts zero or one username.",
                "Supports --json, --registry, --userconfig, and --otp for star mutations.",
            ],
        ),
        Some("ping") => npm_command_help(
            "npm ping",
            &["Check configured npm registry reachability. Supports --json, --registry, and --userconfig."],
        ),
        Some("whoami") => npm_command_help(
            "npm whoami",
            &[
                "Print the authenticated npm username for the configured registry.",
                "Supports --json, --registry, and --userconfig.",
            ],
        ),
        Some("login") => npm_command_help(
            "npm login",
            &[
                "Write an npm registry auth token to OMC's writable .npmrc.",
                "Supports --json, --registry, --scope, --userconfig, and OMC's --token / --auth-token.",
                "Without --token / --auth-token, OMC reads NODE_AUTH_TOKEN or NPM_TOKEN. Interactive web and legacy prompts are not implemented.",
                "Aliases: adduser, add-user.",
            ],
        ),
        Some("logout") => npm_command_help(
            "npm logout",
            &[
                "Remove npm auth credentials for the configured registry from OMC's writable .npmrc.",
                "Supports --json, --registry, --scope, and --userconfig.",
            ],
        ),
        Some("token") => npm_command_help(
            "npm token <list|create|revoke>",
            &[
                "List redacted npm access tokens for the authenticated registry account.",
                "Create granular npm access tokens with explicit package/scope/org permissions.",
                "Revoke tokens by full token or token id.",
                "Create supports --password, --name, --token-description, --expires, --packages, --packages-all, --scopes, --orgs, permission flags, --cidr, --bypass-2fa, --otp, --registry, and --userconfig.",
                "OMC does not prompt interactively; pass --password or set NPM_CONFIG_PASSWORD.",
            ],
        ),
        Some("trust") => npm_command_help(
            "npm trust <github|gitlab|circleci|list|revoke> ...",
            &[
                "Manage npm trusted publishing relationships through the configured registry.",
                "Supports list [package], revoke [package] --id, github/gitlab create flows, and circleci create flows.",
                "Create/revoke support --dry-run, --json, --registry, --userconfig, --otp, and noninteractive --yes for real mutations.",
            ],
        ),
        Some("profile") => npm_command_help(
            "npm profile <get|set> ...",
            &[
                "Read or update noninteractive npm registry profile fields through the configured registry.",
                "Supports get [key...] and set <email|fullname|homepage|freenode|twitter|github> <value>.",
                "Supports --json, --parseable, --registry, --userconfig, and --otp for set.",
                "Interactive password and 2FA profile commands are reported as unsupported.",
            ],
        ),
        Some("owner") => npm_command_help(
            "npm owner <ls|add|rm> ...",
            &[
                "List, add, or remove owners for an npm registry package.",
                "Supports ls [package], add <user> [package], and rm <user> [package].",
                "Supports --json, --registry, --userconfig, and --otp for owner mutations.",
            ],
        ),
        Some("access") => npm_command_help(
            "npm access <list|get|set|grant|revoke> ...",
            &[
                "Manage npm package visibility, publish MFA, and team package access through the configured registry.",
                "Supports list packages, list collaborators, get status, set status=public|private, set mfa=none|publish|automation, grant, and revoke.",
                "Legacy aliases public, restricted, 2fa-required, 2fa-not-required, ls-packages, and ls-collaborators are accepted.",
                "Supports --json, --registry, --userconfig, and --otp for mutations.",
            ],
        ),
        Some("org") => npm_command_help(
            "npm org <set|rm|ls> ...",
            &[
                "Manage npm organization membership through the configured registry.",
                "Supports set <org> <user> [developer|admin|owner], rm <org> <user>, and ls <org> [user].",
                "Alias: add for set. Supports --json, --parseable, --registry, --userconfig, and --otp for mutations.",
            ],
        ),
        Some("team") => npm_command_help(
            "npm team <create|destroy|add|rm|ls> ...",
            &[
                "Manage npm organization teams and team membership through the configured registry.",
                "Supports create <scope:team>, destroy <scope:team>, add <scope:team> <user>, rm <scope:team> <user>, and ls <scope|scope:team>.",
                "Supports --json, --parseable, --registry, --userconfig, and --otp for mutations.",
            ],
        ),
        Some("dist-tag") => npm_command_help(
            "npm dist-tag <add|rm|ls> ...",
            &[
                "Add, remove, or list npm registry distribution tags for a package.",
                "Supports add <package-spec-with-version> [tag], rm <package-spec> <tag>, and ls [package-spec].",
                "Alias: dist-tags. Supports --registry, --userconfig, --tag, and --otp.",
            ],
        ),
        Some("sbom") => npm_command_help(
            "npm sbom --sbom-format <cyclonedx|spdx>",
            &[
                "Generate a Software Bill of Materials from the verified OMC npm lockfile.",
                "Supports --sbom-format, --sbom-type, --package-lock-only, omit flags, and workspace flags.",
            ],
        ),
        Some("shrinkwrap") => npm_command_help(
            "npm shrinkwrap",
            &[
                "Repurpose package-lock.json as npm-shrinkwrap.json, or create a publishable shrinkwrap from package.json and the OMC lockfile.",
                "This command does not support workspaces.",
            ],
        ),
        Some("view") => npm_command_help(
            "npm view <package-spec> [field...]",
            &["Read package metadata from the configured npm registry. Aliases: info, show, v. Supports --json."],
        ),
        Some("metadata-url") => npm_command_help(
            "npm <docs|repo|bugs|home> [package-spec]",
            &[
                "Print package metadata URLs from the npm registry or current package.json.",
                "Supports --json and --registry. OMC prints URLs instead of launching a browser.",
            ],
        ),
        Some("config") => npm_command_help(
            "npm config <get|set|delete|list|edit> ...",
            &[
                "Read, update, and edit npm registry config used by OMC.",
                "Aliases: c, npm get. Supports --json, --registry, --userconfig, --globalconfig, --global, --location, and --editor where relevant.",
            ],
        ),
        Some("cache") => npm_command_help(
            "npm cache <verify|ls|rm|clean>",
            &["Inspect or clear OMC's npm cache. cache clean requires --force."],
        ),
        Some("pkg") => npm_command_help(
            "npm pkg <get|set|delete> ...",
            &["Read and update package.json fields."],
        ),
        Some("version") => npm_command_help(
            "npm version [<newversion>|major|minor|patch|pre...]",
            &["Read or bump package.json version. Supports --json, --preid, --allow-same-version, and --no-git-tag-version."],
        ),
        Some("init") => npm_command_help(
            "npm init [-y] [<initializer>] [-- <args>...]",
            &[
                "Create or update package.json with npm-compatible defaults.",
                "With an initializer, OMC resolves and installs the matching create-* package in an isolated temp project, then runs its bin with the current project as cwd.",
                "Aliases: create, innit. Supports --registry, --allow, and --allow-all-host for initializer package resolution.",
            ],
        ),
        Some("path") => npm_command_help(
            "npm <bin|root|prefix>",
            &["Print OMC project bin, node_modules, or project prefix paths."],
        ),
        Some(_) => npm_command_help(
            "npm help [command]",
            &["No focused OMC help is available for that topic yet."],
        ),
    }
}

fn npm_general_help_text() -> String {
    npm_command_help(
        "npm <command>",
        &[
            "OMC npm compatibility runs supported npm workflows through OMC's verifier, lockfile, cache, and project-local runtime paths.",
            "Supported commands: install, link, install-test, ci, install-ci-test, remove, uninstall, unlink, run, test, start, stop, restart, exec, explore, edit, completion, help-search, list, query, explain, audit, doctor, outdated, fund, prune, dedupe, rebuild, cache, pkg, version, shrinkwrap, pack, publish, unpublish, deprecate, undeprecate, diff, search, star, unstar, stars, ping, whoami, login, adduser, logout, token, trust, profile, owner, access, org, team, dist-tag, sbom, view, docs, repo, bugs, home, config, get, set, init, create, bin, root, prefix.",
            "Use `npm help <command>` for focused OMC compatibility notes.",
        ],
    )
}

fn npm_command_help(usage: &str, lines: &[&str]) -> String {
    let mut output = format!("OMC npm compatibility\n\nUsage: {usage}\n");
    if !lines.is_empty() {
        output.push('\n');
        for line in lines {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn npm_help_topic(topic: &str) -> Option<&'static str> {
    match topic {
        "help" | "--help" | "-h" => None,
        "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt" | "isnta"
        | "isntal" | "isntall" | "add" | "update" | "up" | "upgrade" | "udpate" => Some("install"),
        "link" | "ln" => Some("link"),
        "install-test" | "it" => Some("install-test"),
        "ci" => Some("ci"),
        "install-ci-test" | "cit" => Some("install-ci-test"),
        "run" | "run-script" | "test" | "start" | "stop" | "restart" => Some("run"),
        "exec" | "x" | "npx" => Some("exec"),
        "completion" => Some("completion"),
        "help-search" => Some("help-search"),
        "explore" => Some("explore"),
        "edit" => Some("edit"),
        "remove" | "uninstall" | "unlink" | "rm" | "r" | "un" => Some("remove"),
        "list" | "ls" | "ll" | "la" => Some("list"),
        "query" => Some("query"),
        "explain" | "why" => Some("explain"),
        "audit" => Some("audit"),
        "doctor" => Some("doctor"),
        "outdated" => Some("outdated"),
        "fund" => Some("fund"),
        "prune" | "dedupe" | "ddp" | "find-dupes" => Some("maintenance"),
        "rebuild" | "rb" => Some("rebuild"),
        "pack" => Some("pack"),
        "publish" => Some("publish"),
        "unpublish" => Some("unpublish"),
        "deprecate" | "undeprecate" => Some("deprecate"),
        "diff" => Some("diff"),
        "search" | "s" | "se" | "find" => Some("search"),
        "star" | "unstar" | "stars" => Some("star"),
        "ping" => Some("ping"),
        "whoami" => Some("whoami"),
        "login" | "adduser" | "add-user" => Some("login"),
        "logout" => Some("logout"),
        "token" => Some("token"),
        "trust" => Some("trust"),
        "profile" => Some("profile"),
        "owner" => Some("owner"),
        "access" => Some("access"),
        "org" => Some("org"),
        "team" => Some("team"),
        "dist-tag" | "dist-tags" => Some("dist-tag"),
        "sbom" => Some("sbom"),
        "shrinkwrap" => Some("shrinkwrap"),
        "view" | "info" | "show" | "v" => Some("view"),
        "docs" | "doc" | "repo" | "repository" | "bugs" | "home" | "homepage" => {
            Some("metadata-url")
        }
        "config" | "c" | "get" | "set" => Some("config"),
        "cache" => Some("cache"),
        "pkg" => Some("pkg"),
        "version" => Some("version"),
        "init" | "create" | "innit" => Some("init"),
        "bin" | "root" | "prefix" => Some("path"),
        _ => Some("unknown"),
    }
}

const NPM_COMPLETION_COMMANDS: &[&str] = &[
    "access",
    "add",
    "adduser",
    "audit",
    "bin",
    "bugs",
    "cache",
    "ci",
    "completion",
    "config",
    "create",
    "dedupe",
    "deprecate",
    "diff",
    "dist-tag",
    "docs",
    "doctor",
    "edit",
    "exec",
    "explain",
    "explore",
    "fund",
    "get",
    "help",
    "help-search",
    "home",
    "init",
    "install",
    "link",
    "list",
    "login",
    "logout",
    "npx",
    "org",
    "outdated",
    "owner",
    "pack",
    "ping",
    "pkg",
    "prefix",
    "profile",
    "publish",
    "query",
    "r",
    "rebuild",
    "remove",
    "repo",
    "rm",
    "root",
    "run",
    "sbom",
    "search",
    "set",
    "shrinkwrap",
    "star",
    "stars",
    "start",
    "stop",
    "team",
    "test",
    "token",
    "trust",
    "un",
    "unlink",
    "uninstall",
    "unpublish",
    "unstar",
    "update",
    "up",
    "upgrade",
    "udpate",
    "version",
    "view",
    "whoami",
];

const NPM_COMPLETION_OPTIONS: &[&str] = &[
    "--help",
    "--json",
    "--registry",
    "--userconfig",
    "--workspace",
    "--workspaces",
    "--ws",
    "--include-workspace-root",
    "--omit",
    "--include",
    "--allow",
    "--allow-all-host",
];

const NPM_COMPLETION_PACKAGE_COMMANDS: &[&str] = &[
    "access",
    "deprecate",
    "diff",
    "edit",
    "explain",
    "explore",
    "fund",
    "outdated",
    "owner",
    "remove",
    "star",
    "uninstall",
    "unpublish",
    "unstar",
    "view",
];


fn npm_completion_script() -> &'static str {
    r#"###-begin-omc-npm-completion-###
if type complete >/dev/null 2>&1; then
  _omc_npm_completion() {
    local words cword
    if type _get_comp_words_by_ref >/dev/null 2>&1; then
      _get_comp_words_by_ref -n = -n @ -n : -w words -i cword
    else
      cword="$COMP_CWORD"
      words=("${COMP_WORDS[@]}")
    fi
    local old_ifs="$IFS"
    IFS=$'\n'
    COMPREPLY=( $(COMP_CWORD="$cword" npm completion -- "${words[@]}" 2>/dev/null) )
    IFS="$old_ifs"
  }
  complete -o default -F _omc_npm_completion npm npx
elif type compdef >/dev/null 2>&1; then
  _omc_npm_completion() {
    local old_ifs="$IFS"
    IFS=$'\n'
    compadd -- $(COMP_CWORD=$((CURRENT-1)) npm completion -- "${words[@]}" 2>/dev/null)
    IFS="$old_ifs"
  }
  compdef _omc_npm_completion npm npx
fi
###-end-omc-npm-completion-###
"#
}

fn npm_completion_suggestions(project_dir: &Path, words: &[String]) -> Vec<String> {
    let original_len = words.len();
    let words = completion_words_without_program(words, &["npm", "npx"]);
    let cword = env::var("COMP_CWORD")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let adjusted_cword = cword.map(|cword| {
        if words.len() != original_len {
            cword.saturating_sub(1)
        } else {
            cword
        }
    });
    let current = adjusted_cword
        .and_then(|index| words.get(index).map(String::as_str))
        .or_else(|| {
            if adjusted_cword.is_some_and(|index| index >= words.len()) {
                Some("")
            } else {
                words.last().map(String::as_str)
            }
        })
        .unwrap_or("");
    if words.is_empty() || adjusted_cword.unwrap_or_else(|| words.len().saturating_sub(1)) == 0 {
        return filter_completion_values(NPM_COMPLETION_COMMANDS, current);
    }
    if current.starts_with('-') {
        return filter_completion_values(NPM_COMPLETION_OPTIONS, current);
    }

    let command = words.first().map(String::as_str).unwrap_or("");
    if command == "run" {
        return completion_filter_owned(npm_completion_script_names(project_dir), current);
    }
    if NPM_COMPLETION_PACKAGE_COMMANDS.contains(&command) {
        return completion_filter_owned(
            completion_locked_package_names(project_dir, Ecosystem::Npm),
            current,
        );
    }
    Vec::new()
}

fn npm_completion_script_names(project_dir: &Path) -> Vec<String> {
    let Ok(package) = read_npm_pkg_json(&project_dir.join("package.json")) else {
        return Vec::new();
    };
    package
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .map(|scripts| scripts.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default()
}

fn completion_words_without_program<'a>(words: &'a [String], programs: &[&str]) -> &'a [String] {
    match words.first().map(String::as_str) {
        Some(program) if programs.iter().any(|name| program.ends_with(name)) => &words[1..],
        _ => words,
    }
}

fn filter_completion_values(values: &[&str], prefix: &str) -> Vec<String> {
    values
        .iter()
        .copied()
        .filter(|value| value.starts_with(prefix))
        .map(str::to_owned)
        .collect()
}

fn completion_filter_owned(mut values: Vec<String>, prefix: &str) -> Vec<String> {
    values.retain(|value| value.starts_with(prefix));
    values.sort();
    values.dedup();
    values
}

fn completion_locked_package_names(project_dir: &Path, ecosystem: Ecosystem) -> Vec<String> {
    let Ok(lock) = read_lockfile(project_dir.join("omc.lock")) else {
        return Vec::new();
    };
    let mut names = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == ecosystem)
        .map(|package| package.name)
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn npm_config_values(
    project_dir: &Path,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
    globalconfig: Option<&Path>,
    location: NpmConfigLocation,
) -> Result<BTreeMap<String, String>, OmcRegistryError> {
    let snapshot = read_npm_config_snapshot_with_globalconfig(
        project_dir,
        npm_registry,
        userconfig,
        globalconfig,
    )?;
    let project_dir = absolute_project_dir(project_dir);
    let mut values = BTreeMap::from([
        ("audit".to_owned(), "true".to_owned()),
        (
            "cache".to_owned(),
            project_dir
                .join(".omc")
                .join("cache")
                .join("npm")
                .to_string_lossy()
                .into_owned(),
        ),
        ("fund".to_owned(), "false".to_owned()),
        (
            "global".to_owned(),
            (location == NpmConfigLocation::Global).to_string(),
        ),
        (
            "globalconfig".to_owned(),
            npm_globalconfig_path(project_dir.as_path(), globalconfig)
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "local-prefix".to_owned(),
            project_dir.to_string_lossy().into_owned(),
        ),
        ("location".to_owned(), location.as_str().to_owned()),
        ("loglevel".to_owned(), "notice".to_owned()),
        ("package-lock".to_owned(), "true".to_owned()),
        (
            "prefix".to_owned(),
            project_dir.to_string_lossy().into_owned(),
        ),
        ("save".to_owned(), "true".to_owned()),
        (
            "userconfig".to_owned(),
            npm_userconfig_path(project_dir.as_path(), userconfig)
                .to_string_lossy()
                .into_owned(),
        ),
    ]);
    extend_npm_config_values_from_files(
        &mut values,
        project_dir.as_path(),
        userconfig,
        globalconfig,
        location,
    )?;
    extend_npm_config_values_from_env(&mut values);
    values.insert("registry".to_owned(), snapshot.registry);
    for (scope, registry) in snapshot.scoped_registries {
        values.insert(format!("{scope}:registry"), registry);
    }
    Ok(values)
}

fn extend_npm_config_values_from_files(
    values: &mut BTreeMap<String, String>,
    project_dir: &Path,
    userconfig: Option<&Path>,
    globalconfig: Option<&Path>,
    location: NpmConfigLocation,
) -> Result<(), OmcRegistryError> {
    let globalconfig = npm_globalconfig_path(project_dir, globalconfig);
    let userconfig = npm_userconfig_path(project_dir, userconfig);
    let project_config = project_dir.join(".npmrc");

    match location {
        NpmConfigLocation::Global => {
            read_npm_config_values_file(&globalconfig, values)?;
        }
        NpmConfigLocation::User | NpmConfigLocation::Project => {
            for path in [globalconfig, userconfig, project_config] {
                read_npm_config_values_file(&path, values)?;
            }
        }
    }

    Ok(())
}

fn read_npm_config_values_file(
    path: &Path,
    values: &mut BTreeMap<String, String>,
) -> Result<(), OmcRegistryError> {
    if !path.exists() {
        return Ok(());
    }
    for line in fs::read_to_string(path)?.lines() {
        let Some((key, value)) = npm_config_line_assignment(line) else {
            continue;
        };
        if npm_config_key_is_secret(&key) {
            continue;
        }
        values.insert(key, value);
    }
    Ok(())
}

fn npm_config_line_assignment(line: &str) -> Option<(String, String)> {
    let line = strip_npm_config_comment(line).trim();
    if line.is_empty() {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    let value = expand_npm_config_default_value(value.trim())?;
    Some((key.to_owned(), value))
}

fn extend_npm_config_values_from_env(values: &mut BTreeMap<String, String>) {
    for (name, value) in env::vars() {
        let Some(key) = npm_config_key_from_env_name(&name) else {
            continue;
        };
        if npm_config_key_is_secret(&key) {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        values.insert(key, value.to_owned());
    }
}

fn npm_config_key_from_env_name(name: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    let key = name.strip_prefix("npm_config_")?;
    if key.is_empty() {
        return None;
    }
    Some(key.replace('_', "-"))
}

fn npm_config_key_is_secret(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "_auth"
        || key == "auth"
        || key.ends_with(":_auth")
        || key.ends_with(":auth")
        || key.ends_with("-auth")
        || key.contains("authtoken")
        || key.contains("password")
}

fn npm_userconfig_path(project_dir: &Path, userconfig: Option<&Path>) -> PathBuf {
    if let Some(userconfig) = userconfig {
        return absolutize_path(project_dir, userconfig.to_path_buf());
    }
    if let Some(userconfig) = env::var_os("npm_config_userconfig")
        .or_else(|| env::var_os("NPM_CONFIG_USERCONFIG"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return absolutize_path(project_dir, userconfig);
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| project_dir.to_path_buf())
        .join(".npmrc")
}

fn npm_globalconfig_path(project_dir: &Path, globalconfig: Option<&Path>) -> PathBuf {
    if let Some(globalconfig) = globalconfig {
        return absolutize_path(project_dir, globalconfig.to_path_buf());
    }
    if let Some(globalconfig) = env::var_os("npm_config_globalconfig")
        .or_else(|| env::var_os("NPM_CONFIG_GLOBALCONFIG"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return absolutize_path(project_dir, globalconfig);
    }
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

#[cfg(windows)]
fn npm_global_project_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.to_path_buf()
}

#[cfg(not(windows))]
fn npm_global_project_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.join("lib")
}

#[cfg(windows)]
fn npm_global_bin_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.to_path_buf()
}

#[cfg(not(windows))]
fn npm_global_bin_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.join("bin")
}

fn sync_npm_global_bins(prefix: &Path, global_project_dir: &Path) -> Result<(), OmcRegistryError> {
    let source_bin = global_project_dir.join("node_modules").join(".bin");
    let target_bin = npm_global_bin_dir_from_prefix(prefix);
    fs::create_dir_all(&target_bin)?;
    remove_stale_npm_global_bins(&target_bin, &source_bin)?;
    if !source_bin.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&source_bin)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| cli_bin_name_is_safe(name)) else {
            continue;
        };
        let source = entry.path();
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            continue;
        }
        let target = target_bin.join(name);
        remove_cli_path_if_exists(&target)?;
        create_npm_global_bin_link(&source, &target)?;
    }
    Ok(())
}

fn remove_stale_npm_global_bins(
    target_bin: &Path,
    source_bin: &Path,
) -> Result<(), OmcRegistryError> {
    if !target_bin.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(target_bin)? {
        let entry = entry?;
        let path = entry.path();
        if npm_global_bin_owned_by_omc(&path, source_bin)? {
            remove_cli_path_if_exists(&path)?;
        }
    }
    Ok(())
}

fn npm_global_bin_owned_by_omc(path: &Path, source_bin: &Path) -> Result<bool, OmcRegistryError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        let target = if target.is_absolute() {
            target
        } else {
            path.parent().unwrap_or_else(|| Path::new("")).join(target)
        };
        return Ok(target.starts_with(source_bin));
    }
    if metadata.is_file() {
        let content = fs::read_to_string(path).unwrap_or_default();
        return Ok(content.contains("OMC global npm shim")
            && content.contains(&source_bin.display().to_string()));
    }
    Ok(false)
}

fn cli_bin_name_is_safe(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\\') && name != "." && name != ".."
}

fn remove_cli_path_if_exists(path: &Path) -> Result<(), OmcRegistryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)?;
        }
        Ok(_) => {
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(OmcRegistryError::Io(error)),
    }
    Ok(())
}

#[cfg(unix)]
fn create_npm_global_bin_link(source: &Path, target: &Path) -> Result<(), OmcRegistryError> {
    std::os::unix::fs::symlink(source, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_npm_global_bin_link(source: &Path, target: &Path) -> Result<(), OmcRegistryError> {
    fs::write(
        target,
        format!(
            "@echo off\r\nREM OMC global npm shim {}\r\n\"{}\" %*\r\n",
            source.parent().unwrap_or_else(|| Path::new("")).display(),
            source.display()
        ),
    )?;
    Ok(())
}



fn split_npm_archive_suffix(value: &str) -> (&str, &str) {
    let suffix_index = [value.find('#'), value.find('?')]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(value.len());
    value.split_at(suffix_index)
}

fn npm_archive_reference_is_local(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with("~/")
        || value.contains('\\')
}

fn expand_cli_local_path(value: &str, base_dir: &Path) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
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

impl NpmConfigLocation {
    fn as_str(self) -> &'static str {
        match self {
            NpmConfigLocation::User => "user",
            NpmConfigLocation::Project => "project",
            NpmConfigLocation::Global => "global",
        }
    }
}

fn npm_config_value_for_key(values: &BTreeMap<String, String>, key: &str) -> String {
    values
        .get(key)
        .cloned()
        .unwrap_or_else(|| "undefined".to_owned())
}

fn write_npm_config_assignments(
    project_dir: &Path,
    userconfig: Option<&Path>,
    globalconfig: Option<&Path>,
    location: NpmConfigLocation,
    assignments: &[(String, String)],
) -> Result<(), OmcRegistryError> {
    let path = npm_config_write_path(project_dir, userconfig, globalconfig, location);
    let mut lines = read_npm_config_lines(&path)?;
    for (key, value) in assignments {
        upsert_npm_config_line(&mut lines, key, value);
    }
    write_npm_config_lines(&path, &lines)
}

fn delete_npm_config_keys(
    project_dir: &Path,
    userconfig: Option<&Path>,
    globalconfig: Option<&Path>,
    location: NpmConfigLocation,
    keys: &[String],
) -> Result<(), OmcRegistryError> {
    let path = npm_config_write_path(project_dir, userconfig, globalconfig, location);
    let mut lines = read_npm_config_lines(&path)?;
    lines.retain(|line| {
        let Some(key) = npm_config_line_key(line) else {
            return true;
        };
        !keys.iter().any(|target| target == key)
    });
    write_npm_config_lines(&path, &lines)
}


fn npm_metadata_url(
    kind: NpmMetadataUrlKind,
    manifest: &serde_json::Value,
    package_name: Option<&str>,
) -> Result<String, OmcRegistryError> {
    let url = match kind {
        NpmMetadataUrlKind::Docs | NpmMetadataUrlKind::Home => {
            npm_manifest_string_field(manifest, "homepage")
                .or_else(|| package_name.map(npmjs_package_url))
        }
        NpmMetadataUrlKind::Repo => npm_repository_url(manifest),
        NpmMetadataUrlKind::Bugs => npm_bugs_url(manifest)
            .or_else(|| npm_repository_url(manifest).and_then(|repo| npm_github_issues_url(&repo))),
    };
    url.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!(
            "package metadata does not define {}",
            npm_metadata_url_label(kind)
        ))
    })
}

fn npm_metadata_url_label(kind: NpmMetadataUrlKind) -> &'static str {
    match kind {
        NpmMetadataUrlKind::Docs => "docs/homepage URL",
        NpmMetadataUrlKind::Repo => "repository URL",
        NpmMetadataUrlKind::Bugs => "bugs URL",
        NpmMetadataUrlKind::Home => "homepage URL",
    }
}

pub(crate) fn npm_manifest_string_field(manifest: &serde_json::Value, field: &str) -> Option<String> {
    manifest
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn npm_repository_url(manifest: &serde_json::Value) -> Option<String> {
    let repository = manifest.get("repository")?;
    let raw = repository
        .as_str()
        .or_else(|| repository.get("url").and_then(serde_json::Value::as_str))?;
    normalize_npm_metadata_url(raw)
}

fn npm_bugs_url(manifest: &serde_json::Value) -> Option<String> {
    let bugs = manifest.get("bugs")?;
    if let Some(url) = bugs.as_str() {
        return normalize_npm_metadata_url(url);
    }
    bugs.get("url")
        .and_then(serde_json::Value::as_str)
        .and_then(normalize_npm_metadata_url)
        .or_else(|| {
            bugs.get("email")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|email| !email.is_empty())
                .map(|email| format!("mailto:{email}"))
        })
}

fn normalize_npm_metadata_url(raw: &str) -> Option<String> {
    let mut url = raw.trim().trim_end_matches('/').to_owned();
    if url.is_empty() {
        return None;
    }
    if let Some(rest) = url.strip_prefix("git+") {
        url = rest.to_owned();
    }
    if let Some(rest) = url.strip_prefix("git://") {
        url = format!("https://{rest}");
    } else if let Some(rest) = url.strip_prefix("ssh://git@github.com/") {
        url = format!("https://github.com/{rest}");
    } else if let Some(rest) = url.strip_prefix("git@github.com:") {
        url = format!("https://github.com/{rest}");
    }
    if url.ends_with(".git") {
        url.truncate(url.len() - 4);
    }
    Some(url)
}

fn npm_github_issues_url(repo: &str) -> Option<String> {
    let repo = repo.trim_end_matches('/');
    repo.strip_prefix("https://github.com/")
        .filter(|path| path.split('/').count() >= 2)
        .map(|_| format!("{repo}/issues"))
}

fn npmjs_package_url(package_name: &str) -> String {
    format!("https://www.npmjs.com/package/{package_name}")
}

#[derive(Debug)]
struct NpmAuthTarget {
    registry: String,
    scope: Option<String>,
}

pub(crate) fn npm_auth_target(
    project_dir: &Path,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
    scope: Option<&str>,
) -> Result<NpmAuthTarget, OmcRegistryError> {
    let values = npm_config_values(
        project_dir,
        npm_registry,
        userconfig,
        None,
        NpmConfigLocation::User,
    )?;
    let scope = scope.map(normalize_npm_scope);
    let registry = if npm_registry.is_some() {
        npm_config_value_for_key(&values, "registry")
    } else if let Some(scope) = &scope {
        let scoped_key = format!("{scope}:registry");
        let scoped_registry = npm_config_value_for_key(&values, &scoped_key);
        if scoped_registry == "undefined" {
            npm_config_value_for_key(&values, "registry")
        } else {
            scoped_registry
        }
    } else {
        npm_config_value_for_key(&values, "registry")
    };
    Ok(NpmAuthTarget { registry, scope })
}

pub(crate) fn npm_registry_auth_key_prefix(registry: &str) -> Option<String> {
    let mut value = registry.trim();
    if value.is_empty() || value == "undefined" {
        return None;
    }
    value = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value);
    value = value.split('#').next().unwrap_or(value);
    value = value.split('?').next().unwrap_or(value);
    let value = value.trim_start_matches('/').trim_end_matches('/');
    if value.is_empty() {
        None
    } else {
        Some(format!("//{value}/:"))
    }
}



fn npm_dist_tag_add_package_version(spec: &str) -> Result<(String, String), OmcRegistryError> {
    let spec = parse_package_spec(spec, Some(Ecosystem::Npm))?;
    let version = spec.version.clone().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(
            "npm dist-tag add needs a package spec with an exact version".to_owned(),
        )
    })?;
    Ok((spec.name, version))
}

fn npm_dist_tag_package_name(spec: &str) -> Result<String, OmcRegistryError> {
    let spec = parse_package_spec(spec, Some(Ecosystem::Npm))?;
    Ok(spec.name)
}

fn npm_dist_tag_package_spec(
    project_dir: &Path,
    spec: Option<&str>,
) -> Result<String, OmcRegistryError> {
    if let Some(spec) = spec {
        return Ok(spec.to_owned());
    }
    let package = read_npm_pkg_json(&project_dir.join("package.json"))?;
    let Some(name) = package.get("name").and_then(serde_json::Value::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm dist-tag ls needs a package or package.json name".to_owned(),
        ));
    };
    Ok(name.to_owned())
}

#[derive(Debug)]
struct NpmSbomContext {
    root: NpmSbomRoot,
    packages: Vec<LockedPackage>,
    root_dependencies: BTreeSet<String>,
    timestamp: String,
    serial_uuid: String,
    sbom_type: NpmSbomType,
}

#[derive(Debug)]
struct NpmSbomRoot {
    name: String,
    version: String,
    license: Option<String>,
    homepage: Option<String>,
    description: Option<String>,
}


fn npm_sbom_context(
    project_dir: &Path,
    sbom_type: NpmSbomType,
) -> Result<NpmSbomContext, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let mut packages = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| {
        (left.name.as_str(), left.version.as_str())
            .cmp(&(right.name.as_str(), right.version.as_str()))
    });
    let root = npm_sbom_root(project_dir)?;
    let serial_uuid = npm_sbom_uuid(&root, &packages);
    Ok(NpmSbomContext {
        root,
        packages,
        root_dependencies: npm_root_dependency_names(project_dir)?,
        timestamp: current_utc_timestamp(),
        serial_uuid,
        sbom_type,
    })
}

fn npm_sbom_root(project_dir: &Path) -> Result<NpmSbomRoot, OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let package = if package_json.exists() {
        read_npm_pkg_json(&package_json)?
    } else {
        serde_json::json!({})
    };
    let name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| npm_outdated_dependent(project_dir));
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| "0.0.0".to_owned());
    Ok(NpmSbomRoot {
        name,
        version,
        license: package
            .get("license")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned),
        homepage: package
            .get("homepage")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned),
        description: package
            .get("description")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned),
    })
}

fn npm_cyclonedx_sbom(context: &NpmSbomContext) -> serde_json::Value {
    let root_ref = npm_root_bom_ref(&context.root);
    serde_json::json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", context.serial_uuid),
        "version": 1,
        "metadata": {
            "timestamp": context.timestamp,
            "lifecycles": [{ "phase": "build" }],
            "tools": [{
                "vendor": "turenio",
                "name": "omc",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "component": npm_cyclonedx_root_component(context, &root_ref),
        },
        "components": context.packages.iter().map(npm_cyclonedx_component).collect::<Vec<_>>(),
        "dependencies": npm_cyclonedx_dependencies(context, &root_ref),
    })
}

fn npm_cyclonedx_root_component(context: &NpmSbomContext, root_ref: &str) -> serde_json::Value {
    let mut component = serde_json::json!({
        "bom-ref": root_ref,
        "type": context.sbom_type.cyclonedx_type(),
        "name": context.root.name,
        "version": context.root.version,
        "scope": "required",
        "purl": npm_purl(&context.root.name, &context.root.version),
        "properties": [{
            "name": "cdx:npm:package:path",
            "value": "",
        }],
        "externalReferences": [],
    });
    if let Some(description) = &context.root.description {
        component["description"] = serde_json::Value::String(description.clone());
    }
    if let Some(homepage) = &context.root.homepage {
        component["externalReferences"] = serde_json::json!([{
            "type": "website",
            "url": homepage,
        }]);
    }
    if let Some(license) = &context.root.license {
        component["licenses"] = serde_json::json!([npm_cyclonedx_license(license)]);
    }
    component
}

fn npm_cyclonedx_component(package: &LockedPackage) -> serde_json::Value {
    let mut component = serde_json::json!({
        "bom-ref": npm_package_bom_ref(package),
        "type": "library",
        "name": package.name,
        "version": package.version,
        "scope": "required",
        "purl": npm_purl(&package.name, &package.version),
        "properties": [
            {
                "name": "cdx:npm:package:path",
                "value": npm_node_modules_path(&package.name),
            },
            {
                "name": "omc:behavior",
                "value": behavior_label(package.behavior),
            },
            {
                "name": "omc:verdict",
                "value": verdict_label(package.verdict),
            },
        ],
        "externalReferences": [{
            "type": "distribution",
            "url": npm_package_download_location(package),
        }],
    });
    if !package.sha256.is_empty() {
        component["hashes"] = serde_json::json!([{
            "alg": "SHA-256",
            "content": package.sha256,
        }]);
    }
    component
}

fn npm_cyclonedx_license(license: &str) -> serde_json::Value {
    if npm_license_id_like(license) {
        serde_json::json!({ "license": { "id": license } })
    } else {
        serde_json::json!({ "license": { "name": license } })
    }
}

fn npm_cyclonedx_dependencies(context: &NpmSbomContext, root_ref: &str) -> Vec<serde_json::Value> {
    let refs_by_name = npm_package_refs_by_name(&context.packages);
    let mut dependencies = Vec::new();
    dependencies.push(serde_json::json!({
        "ref": root_ref,
        "dependsOn": npm_dependency_refs(&context.root_dependencies, &refs_by_name),
    }));
    for package in &context.packages {
        let names = package
            .dependencies
            .iter()
            .chain(package.optional_dependencies.iter())
            .filter_map(|dependency| npm_dependency_name(dependency))
            .collect::<BTreeSet<_>>();
        dependencies.push(serde_json::json!({
            "ref": npm_package_bom_ref(package),
            "dependsOn": npm_dependency_refs(&names, &refs_by_name),
        }));
    }
    dependencies
}

fn npm_spdx_sbom(context: &NpmSbomContext) -> serde_json::Value {
    let root_id = npm_root_spdx_id(&context.root);
    let package_ids = npm_package_spdx_ids(&context.packages);
    let mut packages = Vec::new();
    packages.push(npm_spdx_root_package(context, &root_id));
    packages.extend(
        context
            .packages
            .iter()
            .map(|package| npm_spdx_package(package, &package_ids[&npm_package_key(package)])),
    );
    serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{}@{}", context.root.name, context.root.version),
        "documentNamespace": format!(
            "http://spdx.org/spdxdocs/{}-{}",
            npm_sbom_id_segment(&context.root.name),
            context.serial_uuid
        ),
        "creationInfo": {
            "created": context.timestamp,
            "creators": [format!("Tool: omc/{}", env!("CARGO_PKG_VERSION"))],
        },
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": npm_spdx_relationships(context, &root_id, &package_ids),
    })
}

fn npm_spdx_root_package(context: &NpmSbomContext, spdx_id: &str) -> serde_json::Value {
    let mut package = serde_json::json!({
        "name": context.root.name,
        "SPDXID": spdx_id,
        "versionInfo": context.root.version,
        "packageFileName": "",
        "primaryPackagePurpose": context.sbom_type.spdx_purpose(),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "homepage": context.root.homepage.as_deref().unwrap_or("NOASSERTION"),
        "licenseDeclared": context.root.license.as_deref().unwrap_or("NOASSERTION"),
        "externalRefs": [npm_spdx_purl_ref(&context.root.name, &context.root.version)],
    });
    if let Some(description) = &context.root.description {
        package["description"] = serde_json::Value::String(description.clone());
    }
    package
}

fn npm_spdx_package(package: &LockedPackage, spdx_id: &str) -> serde_json::Value {
    let mut value = serde_json::json!({
        "name": package.name,
        "SPDXID": spdx_id,
        "versionInfo": package.version,
        "packageFileName": npm_node_modules_path(&package.name),
        "downloadLocation": npm_package_download_location(package),
        "filesAnalyzed": false,
        "homepage": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "externalRefs": [npm_spdx_purl_ref(&package.name, &package.version)],
    });
    if !package.sha256.is_empty() {
        value["checksums"] = serde_json::json!([{
            "algorithm": "SHA256",
            "checksumValue": package.sha256,
        }]);
    }
    value
}

fn npm_spdx_purl_ref(name: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": npm_purl(name, version),
    })
}

fn npm_spdx_relationships(
    context: &NpmSbomContext,
    root_id: &str,
    package_ids: &BTreeMap<String, String>,
) -> Vec<serde_json::Value> {
    let refs_by_name = npm_spdx_refs_by_name(&context.packages, package_ids);
    let mut relationships = Vec::new();
    relationships.push(serde_json::json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": root_id,
        "relationshipType": "DESCRIBES",
    }));
    for dependency_id in npm_dependency_refs(&context.root_dependencies, &refs_by_name) {
        relationships.push(serde_json::json!({
            "spdxElementId": root_id,
            "relatedSpdxElement": dependency_id,
            "relationshipType": "DEPENDS_ON",
        }));
    }
    for package in &context.packages {
        let package_id = &package_ids[&npm_package_key(package)];
        let names = package
            .dependencies
            .iter()
            .chain(package.optional_dependencies.iter())
            .filter_map(|dependency| npm_dependency_name(dependency))
            .collect::<BTreeSet<_>>();
        for dependency_id in npm_dependency_refs(&names, &refs_by_name) {
            relationships.push(serde_json::json!({
                "spdxElementId": package_id,
                "relatedSpdxElement": dependency_id,
                "relationshipType": "DEPENDS_ON",
            }));
        }
    }
    relationships
}

fn npm_package_refs_by_name(packages: &[LockedPackage]) -> BTreeMap<String, Vec<String>> {
    let mut refs = BTreeMap::<String, Vec<String>>::new();
    for package in packages {
        refs.entry(package.name.clone())
            .or_default()
            .push(npm_package_bom_ref(package));
    }
    refs
}

fn npm_spdx_refs_by_name(
    packages: &[LockedPackage],
    package_ids: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    let mut refs = BTreeMap::<String, Vec<String>>::new();
    for package in packages {
        refs.entry(package.name.clone())
            .or_default()
            .push(package_ids[&npm_package_key(package)].clone());
    }
    refs
}

fn npm_dependency_refs(
    names: &BTreeSet<String>,
    refs_by_name: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    names
        .iter()
        .flat_map(|name| refs_by_name.get(name).into_iter().flatten().cloned())
        .collect()
}

fn npm_package_spdx_ids(packages: &[LockedPackage]) -> BTreeMap<String, String> {
    packages
        .iter()
        .map(|package| (npm_package_key(package), npm_package_spdx_id(package)))
        .collect()
}

fn npm_package_key(package: &LockedPackage) -> String {
    format!("{}@{}", package.name, package.version)
}

fn npm_root_bom_ref(root: &NpmSbomRoot) -> String {
    format!("{}@{}", root.name, root.version)
}

fn npm_package_bom_ref(package: &LockedPackage) -> String {
    format!("{}@{}", package.name, package.version)
}

fn npm_root_spdx_id(root: &NpmSbomRoot) -> String {
    format!(
        "SPDXRef-Package-{}-{}",
        npm_sbom_id_segment(&root.name),
        npm_sbom_id_segment(&root.version)
    )
}

fn npm_package_spdx_id(package: &LockedPackage) -> String {
    format!(
        "SPDXRef-Package-{}-{}",
        npm_sbom_id_segment(&package.name),
        npm_sbom_id_segment(&package.version)
    )
}

fn npm_sbom_id_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    segment.trim_matches('-').to_owned()
}

fn npm_node_modules_path(name: &str) -> String {
    format!("node_modules/{name}")
}

fn npm_package_name_from_spec(spec: &str) -> String {
    let spec = spec.strip_prefix("npm:").unwrap_or(spec);
    let spec = spec.split_once('#').map(|(base, _)| base).unwrap_or(spec);
    if let Some(index) = spec.rfind('@') {
        if index > 0 {
            return spec[..index].to_owned();
        }
    }
    spec.to_owned()
}

pub(crate) fn npm_installed_package_dir(
    project_dir: &Path,
    package: &str,
) -> Result<PathBuf, OmcRegistryError> {
    let name = npm_package_name_from_spec(package);
    let Some(relative) = npm_package_relative_path(&name) else {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm package name `{package}`"
        )));
    };
    Ok(project_dir.join("node_modules").join(relative))
}

fn npm_package_relative_path(name: &str) -> Option<PathBuf> {
    if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped.split_once('/')?;
        if !npm_package_path_segment_valid(scope)
            || !npm_package_path_segment_valid(package)
            || package.contains('/')
        {
            return None;
        }
        return Some(PathBuf::from(format!("@{scope}")).join(package));
    }
    if name.contains('/') || !npm_package_path_segment_valid(name) {
        return None;
    }
    Some(PathBuf::from(name))
}

fn npm_package_path_segment_valid(segment: &str) -> bool {
    !segment.is_empty() && segment != "." && segment != ".."
}

fn npm_package_download_location(package: &LockedPackage) -> String {
    if package.source_url.is_empty() {
        "NOASSERTION".to_owned()
    } else {
        package.source_url.clone()
    }
}

fn npm_purl(name: &str, version: &str) -> String {
    format!("pkg:npm/{name}@{version}")
}

fn npm_license_id_like(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+'))
}

impl NpmSbomType {
    fn cyclonedx_type(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Application => "application",
            Self::Framework => "framework",
        }
    }

    fn spdx_purpose(self) -> &'static str {
        match self {
            Self::Library => "LIBRARY",
            Self::Application => "APPLICATION",
            Self::Framework => "FRAMEWORK",
        }
    }
}

fn npm_sbom_uuid(root: &NpmSbomRoot, packages: &[LockedPackage]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(root.name.as_bytes());
    hasher.update([0]);
    hasher.update(root.version.as_bytes());
    for package in packages {
        hasher.update([0]);
        hasher.update(package.name.as_bytes());
        hasher.update([0]);
        hasher.update(package.version.as_bytes());
        hasher.update([0]);
        hasher.update(package.sha256.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn current_utc_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs() as i64;
    let millis = duration.subsec_millis();
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

pub(crate) fn npm_json_parseable_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(values) => values
            .iter()
            .map(npm_json_parseable_value)
            .collect::<Vec<_>>()
            .join(","),
        serde_json::Value::Object(_) => value.to_string(),
    }
}

fn npm_outdated_location(project_dir: &Path, package: &str) -> PathBuf {
    project_dir.join("node_modules").join(package)
}

fn npm_outdated_dependent(project_dir: &Path) -> String {
    let package_json = project_dir.join("package.json");
    if let Ok(content) = fs::read_to_string(package_json) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(name) = value.get("name").and_then(serde_json::Value::as_str) {
                if !name.is_empty() {
                    return name.to_owned();
                }
            }
        }
    }
    project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("omc-project")
        .to_owned()
}

#[derive(Debug)]
struct NpmExplainPackage {
    name: String,
    version: String,
    location: PathBuf,
    dependents: Vec<String>,
}


fn npm_explain_requested_name(spec: &str) -> Result<String, OmcRegistryError> {
    parse_package_spec(spec, Some(Ecosystem::Npm)).map(|spec| spec.name)
}

fn npm_root_dependency_names(project_dir: &Path) -> Result<BTreeSet<String>, OmcRegistryError> {
    let mut names = BTreeSet::new();
    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        let package = read_npm_pkg_json(&package_json)?;
        for field in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            if let Some(object) = package.get(field).and_then(serde_json::Value::as_object) {
                names.extend(object.keys().cloned());
            }
        }
    }

    let manifest = read_manifest(project_dir.join("omc.toml"))?;
    for key in manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
    {
        if let Ok(spec) = PackageSpec::parse(key) {
            if spec.ecosystem == Ecosystem::Npm {
                names.insert(spec.name);
            }
        }
    }
    Ok(names)
}

fn npm_lock_package_depends_on(package: &LockedPackage, name: &str) -> bool {
    package
        .dependencies
        .iter()
        .chain(package.optional_dependencies.iter())
        .any(|dependency| npm_dependency_name(dependency).as_deref() == Some(name))
}

fn npm_dependency_name(dependency: &str) -> Option<String> {
    let spec = PackageSpec::parse(dependency).ok()?;
    (spec.ecosystem == Ecosystem::Npm).then_some(spec.name)
}

fn pypi_available_versions_options(
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    allow_prereleases: bool,
) -> PypiAvailableVersionsOptions {
    PypiAvailableVersionsOptions {
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        allow_prereleases,
        ..PypiAvailableVersionsOptions::default()
    }
}

fn apply_pypi_download_requirements(
    options: &mut LinkOptions,
    specs: &mut Vec<PackageSpec>,
    local_paths: &mut Vec<PythonLocalRequirement>,
    requirements: ProjectRequirements,
    allow_local_paths: bool,
) -> Result<(), OmcRegistryError> {
    if !requirements.python_vcs_requirements.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "this OMC compatibility path supports registry requirements and direct wheel/sdist archives; local directories and VCS requirements need a real install"
                .to_owned(),
        ));
    }
    if !requirements.python_local_paths.is_empty()
        || !requirements.python_local_requirements.is_empty()
        || !requirements.python_local_directory_requirements.is_empty()
    {
        if !allow_local_paths {
            return Err(OmcRegistryError::UnsupportedSpec(
                "this OMC compatibility path supports registry requirements and direct wheel/sdist archives; local directories need pip wheel"
                    .to_owned(),
            ));
        }
        local_paths.extend(
            requirements
                .python_local_paths
                .into_iter()
                .map(|path| PythonLocalRequirement::new(path, BTreeSet::new())),
        );
        local_paths.extend(requirements.python_local_requirements);
        local_paths.extend(requirements.python_local_directory_requirements);
    }

    specs.extend(requirements.specs);
    options.constraints.extend(requirements.constraints);
    options.hashes.extend(requirements.hashes);
    if requirements.pypi_binary_all.is_some() {
        options.pypi_binary_all = requirements.pypi_binary_all;
    }
    options
        .pypi_binary_packages
        .extend(requirements.pypi_binary_packages);
    if requirements.pypi_index_url.is_some() {
        options.pypi_index_url = requirements.pypi_index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(requirements.pypi_extra_index_urls);
    options.pypi_find_links.extend(requirements.pypi_find_links);
    options.pypi_no_index |= requirements.pypi_no_index;
    options.pypi_require_hashes |= requirements.pypi_require_hashes;
    options.pypi_allow_prereleases |= requirements.pypi_allow_prereleases;
    merge_pypi_release_controls(
        &mut options.pypi_release_controls,
        requirements.pypi_release_controls,
    );
    if requirements.pypi_uploaded_prior_to.is_some() {
        options.pypi_uploaded_prior_to = requirements.pypi_uploaded_prior_to;
    }
    if requirements.pypi_no_deps {
        options.pypi_include_dependencies = false;
    }
    Ok(())
}

fn apply_pypi_install_requirements(
    options: &mut LinkOptions,
    specs: &mut Vec<PackageSpec>,
    mut requirements: ProjectRequirements,
    source_project_dir: &Path,
    wheel_project_dir: &Path,
) -> Result<(), OmcRegistryError> {
    let local_directories = std::mem::take(&mut requirements.python_local_directory_requirements);
    specs.extend(requirements.specs);
    options.constraints.extend(requirements.constraints);
    options.hashes.extend(requirements.hashes);
    if requirements.pypi_binary_all.is_some() {
        options.pypi_binary_all = requirements.pypi_binary_all;
    }
    options
        .pypi_binary_packages
        .extend(requirements.pypi_binary_packages);
    if requirements.pypi_index_url.is_some() {
        options.pypi_index_url = requirements.pypi_index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(requirements.pypi_extra_index_urls);
    options.pypi_find_links.extend(requirements.pypi_find_links);
    options.pypi_no_index |= requirements.pypi_no_index;
    options.pypi_require_hashes |= requirements.pypi_require_hashes;
    options.pypi_allow_prereleases |= requirements.pypi_allow_prereleases;
    merge_pypi_release_controls(
        &mut options.pypi_release_controls,
        requirements.pypi_release_controls,
    );
    if requirements.pypi_uploaded_prior_to.is_some() {
        options.pypi_uploaded_prior_to = requirements.pypi_uploaded_prior_to;
    }
    if requirements.pypi_no_deps {
        options.pypi_include_dependencies = false;
    }
    options
        .python_local_paths
        .extend(requirements.python_local_paths);
    options
        .python_local_requirements
        .extend(requirements.python_local_requirements);
    options
        .python_vcs_requirements
        .extend(requirements.python_vcs_requirements);
    specs.extend(prepare_pip_local_directory_archive_specs(
        source_project_dir,
        wheel_project_dir,
        local_directories,
        options,
    )?);
    Ok(())
}

fn apply_pypi_requirement_files_with_local_directories(
    options: &mut LinkOptions,
    specs: &mut Vec<PackageSpec>,
    source_project_dir: &Path,
    wheel_project_dir: &Path,
) -> Result<bool, OmcRegistryError> {
    if options.requirement_files.is_empty() {
        return Ok(false);
    }

    let requirements = read_requirements_files(&options.requirement_files)?;
    if requirements.python_local_directory_requirements.is_empty() {
        return Ok(false);
    }

    options.requirement_files.clear();
    apply_pypi_install_requirements(
        options,
        specs,
        requirements,
        source_project_dir,
        wheel_project_dir,
    )?;
    Ok(true)
}

fn merge_pypi_release_controls(target: &mut PypiReleaseControls, source: PypiReleaseControls) {
    target.all_releases.all |= source.all_releases.all;
    target
        .all_releases
        .packages
        .extend(source.all_releases.packages);
    target.only_final.all |= source.only_final.all;
    target
        .only_final
        .packages
        .extend(source.only_final.packages);
}

fn copy_downloaded_pypi_archives(
    project_dir: &Path,
    destination: &Path,
    reports: &[omc_registry::LinkReport],
) -> Result<(), OmcRegistryError> {
    let mut copied = BTreeSet::new();
    for report in reports {
        let package = &report.locked;
        if package.ecosystem != Ecosystem::Pypi {
            continue;
        }
        let key = format!("{}=={}:{}", package.name, package.version, package.sha256);
        if !copied.insert(key) {
            continue;
        }
        let source = project_dir.join(&package.archive);
        let filename = pypi_download_filename(package);
        let target = destination.join(filename);
        fs::copy(&source, &target)?;
        println!("Saved {}", target.display());
    }
    println!("Successfully downloaded {} package(s)", copied.len());
    Ok(())
}

fn pypi_download_filename(package: &LockedPackage) -> String {
    if let Ok(url) = reqwest::Url::parse(&package.source_url) {
        if let Some(filename) = url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
        {
            if !filename.is_empty() {
                return filename.to_owned();
            }
        }
    }
    let without_fragment = package
        .source_url
        .split_once('#')
        .map(|(path, _)| path)
        .unwrap_or(&package.source_url);
    let source = without_fragment
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(without_fragment);
    Path::new(source)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            Path::new(&package.archive)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("{}-{}.archive", package.name, package.version))
}

fn read_pyproject_wheel_metadata(
    package_dir: &Path,
    extras: &BTreeSet<String>,
) -> Result<Option<PipLocalWheelMetadata>, OmcRegistryError> {
    let path = package_dir.join("pyproject.toml");
    if !path.exists() {
        return Ok(None);
    }
    let pyproject = toml::from_str::<toml::Value>(&fs::read_to_string(path)?)?;
    if let Some(project) = pyproject.get("project").and_then(toml::Value::as_table) {
        let Some(name) = toml_table_string(project, "name") else {
            return Ok(None);
        };
        let Some(version) = toml_table_string(project, "version") else {
            return Ok(None);
        };
        let mut requires_dist = toml_string_array(project, "dependencies");
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(toml::Value::as_table)
        {
            for extra in extras {
                if let Some(dependencies) = optional.get(extra).and_then(toml::Value::as_array) {
                    requires_dist.extend(
                        dependencies
                            .iter()
                            .filter_map(toml::Value::as_str)
                            .map(str::to_owned),
                    );
                }
            }
        }
        let mut entry_points = Vec::new();
        collect_toml_script_table(project, "scripts", "console_scripts", &mut entry_points);
        collect_toml_script_table(project, "gui-scripts", "gui_scripts", &mut entry_points);
        return Ok(Some(PipLocalWheelMetadata {
            name,
            version,
            requires_dist,
            entry_points,
        }));
    }

    if let Some(poetry) = pyproject
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(toml::Value::as_table)
    {
        let Some(name) = toml_table_string(poetry, "name") else {
            return Ok(None);
        };
        let Some(version) = toml_table_string(poetry, "version") else {
            return Ok(None);
        };
        let mut requires_dist = Vec::new();
        if let Some(dependencies) = poetry.get("dependencies").and_then(toml::Value::as_table) {
            for (name, dependency) in dependencies {
                if name.eq_ignore_ascii_case("python") {
                    continue;
                }
                if let Some(requirement) = poetry_dependency_requirement(name, dependency) {
                    requires_dist.push(requirement);
                }
            }
        }
        let mut entry_points = Vec::new();
        collect_poetry_script_table(poetry, &mut entry_points);
        return Ok(Some(PipLocalWheelMetadata {
            name,
            version,
            requires_dist,
            entry_points,
        }));
    }

    Ok(None)
}

fn read_setup_cfg_wheel_metadata(
    package_dir: &Path,
    extras: &BTreeSet<String>,
) -> Result<Option<PipLocalWheelMetadata>, OmcRegistryError> {
    let path = package_dir.join("setup.cfg");
    if !path.exists() {
        return Ok(None);
    }
    let sections = parse_pip_local_setup_cfg(&fs::read_to_string(path)?);
    let metadata = sections.get("metadata");
    let Some(name) = metadata.and_then(|section| setup_cfg_first_value(section, "name")) else {
        return Ok(None);
    };
    let Some(version) = metadata.and_then(|section| setup_cfg_first_value(section, "version"))
    else {
        return Ok(None);
    };
    let mut requires_dist = sections
        .get("options")
        .and_then(|section| section.get("install_requires"))
        .cloned()
        .unwrap_or_default();
    if let Some(extra_section) = sections.get("options.extras_require") {
        for extra in extras {
            if let Some(values) = extra_section.get(extra) {
                requires_dist.extend(values.clone());
            }
        }
    }
    let mut entry_points = Vec::new();
    if let Some(section) = sections.get("options.entry_points") {
        for group in ["console_scripts", "gui_scripts"] {
            if let Some(values) = section.get(group) {
                entry_points.extend(
                    values
                        .iter()
                        .filter_map(|value| pip_local_entry_point(group, value)),
                );
            }
        }
    }
    Ok(Some(PipLocalWheelMetadata {
        name,
        version,
        requires_dist,
        entry_points,
    }))
}

fn toml_table_string(table: &toml::value::Table, key: &str) -> Option<String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
}

fn toml_string_array(table: &toml::value::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn collect_toml_script_table(
    table: &toml::value::Table,
    key: &str,
    group: &str,
    entry_points: &mut Vec<PipLocalWheelEntryPoint>,
) {
    let Some(scripts) = table.get(key).and_then(toml::Value::as_table) else {
        return;
    };
    entry_points.extend(scripts.iter().filter_map(|(name, target)| {
        target
            .as_str()
            .and_then(|target| pip_local_script_entry(group, name, target))
    }));
}

fn collect_poetry_script_table(
    table: &toml::value::Table,
    entry_points: &mut Vec<PipLocalWheelEntryPoint>,
) {
    let Some(scripts) = table.get("scripts").and_then(toml::Value::as_table) else {
        return;
    };
    entry_points.extend(scripts.iter().filter_map(|(name, value)| {
        let target = value.as_str().or_else(|| {
            value
                .as_table()
                .and_then(|table| table.get("callable"))
                .and_then(toml::Value::as_str)
        })?;
        pip_local_script_entry("console_scripts", name, target)
    }));
}

fn poetry_dependency_requirement(name: &str, dependency: &toml::Value) -> Option<String> {
    if let Some(version) = dependency.as_str() {
        return Some(python_dependency_requirement(name, version));
    }
    let table = dependency.as_table()?;
    let version = table
        .get("version")
        .and_then(toml::Value::as_str)
        .unwrap_or_default();
    if table.get("optional").and_then(toml::Value::as_bool) == Some(true) {
        return None;
    }
    Some(python_dependency_requirement(name, version))
}

fn python_dependency_requirement(name: &str, version: &str) -> String {
    let version = version.trim();
    if version.is_empty() || version == "*" {
        name.to_owned()
    } else if version.starts_with(['<', '>', '=', '!', '~']) {
        format!("{name}{version}")
    } else {
        format!("{name} {version}")
    }
}

fn setup_cfg_assignment(value: &str) -> Option<(&str, &str)> {
    value
        .split_once('=')
        .or_else(|| value.split_once(':'))
        .map(|(key, value)| (key.trim(), value.trim()))
        .filter(|(key, _)| !key.is_empty())
}

fn setup_cfg_first_value(section: &BTreeMap<String, Vec<String>>, key: &str) -> Option<String> {
    section
        .get(key)
        .and_then(|values| values.iter().find(|value| !value.trim().is_empty()))
        .map(|value| value.trim().to_owned())
}

fn python_wheel_component(value: &str) -> String {
    let mut out = String::new();
    let mut previous_separator = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator {
            out.push('_');
            previous_separator = true;
        }
    }
    out.trim_matches('_').to_owned()
}

fn python_wheel_version_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '!' | '+') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_owned()
}

fn wheel_archive_path(path: &Path) -> Result<String, OmcRegistryError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(OmcRegistryError::UnsafeArchivePath(
                path.to_string_lossy().into_owned(),
            ));
        };
        let Some(part) = part.to_str().filter(|part| !part.is_empty()) else {
            return Err(OmcRegistryError::UnsafeArchivePath(
                path.to_string_lossy().into_owned(),
            ));
        };
        parts.push(part.to_owned());
    }
    if parts.is_empty() {
        return Err(OmcRegistryError::UnsafeArchivePath(
            path.to_string_lossy().into_owned(),
        ));
    }
    Ok(parts.join("/"))
}

fn write_wheel_file<W: io::Write + io::Seek>(
    archive: &mut zip::ZipWriter<W>,
    path: &str,
    bytes: &[u8],
    options: zip::write::SimpleFileOptions,
) -> Result<(), OmcRegistryError> {
    archive.start_file(path, options)?;
    archive.write_all(bytes)?;
    Ok(())
}

fn npm_package_json_version(package: &serde_json::Value) -> Result<String, OmcRegistryError> {
    package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("package.json does not define version".to_owned())
        })
}

fn update_npm_lockfile_root_version(
    project_dir: &Path,
    filename: &str,
    version: &str,
) -> Result<(), OmcRegistryError> {
    let path = project_dir.join(filename);
    if !path.exists() {
        return Ok(());
    }
    let mut value: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "version".to_owned(),
            serde_json::Value::String(version.to_owned()),
        );
    }
    if let Some(root) = value
        .get_mut("packages")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|packages| packages.get_mut(""))
        .and_then(serde_json::Value::as_object_mut)
    {
        root.insert(
            "version".to_owned(),
            serde_json::Value::String(version.to_owned()),
        );
    }
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&value)?))?;
    Ok(())
}

fn sync_npm_package_lock(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(());
    }
    let lockfile = project_dir.join("omc.lock");
    if !lockfile.exists() {
        return Ok(());
    }

    let package = read_npm_pkg_json(&package_json)?;
    let lock = read_lockfile(lockfile)?;
    let package_lock = npm_package_lock_json(&package, &lock);
    fs::write(
        project_dir.join("package-lock.json"),
        format!("{}\n", serde_json::to_string_pretty(&package_lock)?),
    )?;
    Ok(())
}

fn write_npm_shrinkwrap(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let shrinkwrap_path = project_dir.join("npm-shrinkwrap.json");
    if shrinkwrap_path.exists() {
        eprintln!("npm notice npm-shrinkwrap.json up to date");
        return Ok(());
    }

    let package_lock_path = project_dir.join("package-lock.json");
    if package_lock_path.exists() {
        fs::rename(package_lock_path, shrinkwrap_path)?;
        eprintln!("npm notice package-lock.json has been renamed to npm-shrinkwrap.json");
        return Ok(());
    }

    let package_json_path = project_dir.join("package.json");
    let package = if package_json_path.exists() {
        read_npm_pkg_json(&package_json_path)?
    } else {
        serde_json::json!({})
    };
    let lockfile_path = project_dir.join("omc.lock");
    let lock = if lockfile_path.exists() {
        read_lockfile(lockfile_path)?
    } else {
        OmcLock::new()
    };
    let shrinkwrap = npm_package_lock_json(&package, &lock);
    fs::write(
        shrinkwrap_path,
        format!("{}\n", serde_json::to_string_pretty(&shrinkwrap)?),
    )?;
    eprintln!("npm notice created a lockfile as npm-shrinkwrap.json with version 3");
    Ok(())
}

fn npm_package_lock_json(package: &serde_json::Value, lock: &OmcLock) -> serde_json::Value {
    let mut packages = serde_json::Map::new();
    packages.insert(String::new(), npm_package_lock_root_entry(package));
    let package_kinds = npm_package_lock_dependency_kinds(package);

    for locked in lock.packages.iter().filter(|package| {
        package.ecosystem == Ecosystem::Npm && package.verdict == Verdict::Accepted
    }) {
        let kinds = package_kinds.get(&locked.name).copied().unwrap_or_default();
        packages.insert(
            npm_package_lock_path(&locked.name),
            npm_package_lock_package_entry(locked, kinds),
        );
    }
    for source in lock
        .local_sources
        .iter()
        .filter(|source| source.ecosystem == Ecosystem::Npm && source.verdict == Verdict::Accepted)
    {
        let kinds = package_kinds.get(&source.name).copied().unwrap_or_default();
        packages.insert(
            npm_package_lock_path(&source.name),
            npm_package_lock_local_source_entry(source, kinds),
        );
    }

    let mut root = serde_json::Map::new();
    if let Some(name) = package.get("name").and_then(serde_json::Value::as_str) {
        root.insert(
            "name".to_owned(),
            serde_json::Value::String(name.to_owned()),
        );
    }
    if let Some(version) = package.get("version").and_then(serde_json::Value::as_str) {
        root.insert(
            "version".to_owned(),
            serde_json::Value::String(version.to_owned()),
        );
    }
    root.insert(
        "lockfileVersion".to_owned(),
        serde_json::Value::Number(3.into()),
    );
    root.insert("requires".to_owned(), serde_json::Value::Bool(true));
    root.insert("packages".to_owned(), serde_json::Value::Object(packages));
    serde_json::Value::Object(root)
}

#[derive(Debug, Clone, Copy, Default)]
struct NpmPackageLockKinds {
    dev: bool,
    optional: bool,
    peer: bool,
}

fn npm_package_lock_dependency_kinds(
    package: &serde_json::Value,
) -> BTreeMap<String, NpmPackageLockKinds> {
    let mut kinds = BTreeMap::new();
    mark_npm_package_lock_dependency_kind(
        package,
        "devDependencies",
        |kind| {
            kind.dev = true;
        },
        &mut kinds,
    );
    mark_npm_package_lock_dependency_kind(
        package,
        "optionalDependencies",
        |kind| {
            kind.optional = true;
        },
        &mut kinds,
    );
    mark_npm_package_lock_dependency_kind(
        package,
        "peerDependencies",
        |kind| {
            kind.peer = true;
        },
        &mut kinds,
    );
    kinds
}

fn mark_npm_package_lock_dependency_kind(
    package: &serde_json::Value,
    field: &str,
    mark: impl Fn(&mut NpmPackageLockKinds),
    kinds: &mut BTreeMap<String, NpmPackageLockKinds>,
) {
    let Some(dependencies) = package.get(field).and_then(serde_json::Value::as_object) else {
        return;
    };
    for name in dependencies.keys() {
        mark(kinds.entry(name.clone()).or_default());
    }
}

fn npm_package_lock_root_entry(package: &serde_json::Value) -> serde_json::Value {
    let mut root = serde_json::Map::new();
    for field in ["name", "version", "license"] {
        if let Some(value) = package.get(field).and_then(serde_json::Value::as_str) {
            root.insert(
                field.to_owned(),
                serde_json::Value::String(value.to_owned()),
            );
        }
    }
    if let Some(private) = package.get("private").and_then(serde_json::Value::as_bool) {
        root.insert("private".to_owned(), serde_json::Value::Bool(private));
    }
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(dependencies) = package
            .get(field)
            .and_then(serde_json::Value::as_object)
            .filter(|dependencies| !dependencies.is_empty())
        {
            root.insert(
                field.to_owned(),
                serde_json::Value::Object(dependencies.clone()),
            );
        }
    }
    for field in ["bundleDependencies", "bundledDependencies"] {
        if let Some(value) = package.get(field).filter(|value| {
            value.as_bool() == Some(true)
                || value.as_array().is_some_and(|entries| !entries.is_empty())
        }) {
            root.insert(field.to_owned(), value.clone());
        }
    }
    serde_json::Value::Object(root)
}

fn npm_package_lock_package_entry(
    package: &LockedPackage,
    kinds: NpmPackageLockKinds,
) -> serde_json::Value {
    let mut entry = serde_json::Map::new();
    entry.insert(
        "version".to_owned(),
        serde_json::Value::String(package.version.clone()),
    );
    if kinds.dev {
        entry.insert("dev".to_owned(), serde_json::Value::Bool(true));
    }
    if kinds.optional {
        entry.insert("optional".to_owned(), serde_json::Value::Bool(true));
    }
    if kinds.peer {
        entry.insert("peer".to_owned(), serde_json::Value::Bool(true));
    }
    if !package.source_url.is_empty() {
        entry.insert(
            "resolved".to_owned(),
            serde_json::Value::String(package.source_url.clone()),
        );
    }
    if let Some(integrity) = npm_package_lock_integrity(&package.sha256) {
        entry.insert("integrity".to_owned(), serde_json::Value::String(integrity));
    }
    append_npm_package_lock_dependencies(&mut entry, "dependencies", &package.dependencies);
    append_npm_package_lock_dependencies(
        &mut entry,
        "optionalDependencies",
        &package.optional_dependencies,
    );
    append_npm_package_lock_dependencies(
        &mut entry,
        "peerDependencies",
        &package.peer_dependencies,
    );
    serde_json::Value::Object(entry)
}

fn npm_package_lock_local_source_entry(
    source: &LockedLocalSource,
    kinds: NpmPackageLockKinds,
) -> serde_json::Value {
    let mut entry = serde_json::Map::new();
    entry.insert(
        "version".to_owned(),
        serde_json::Value::String(source.version.clone()),
    );
    if kinds.dev {
        entry.insert("dev".to_owned(), serde_json::Value::Bool(true));
    }
    if kinds.optional {
        entry.insert("optional".to_owned(), serde_json::Value::Bool(true));
    }
    if kinds.peer {
        entry.insert("peer".to_owned(), serde_json::Value::Bool(true));
    }
    if !source.source_path.is_empty() {
        entry.insert(
            "resolved".to_owned(),
            serde_json::Value::String(format!("file:{}", source.source_path)),
        );
    }
    serde_json::Value::Object(entry)
}


fn npm_package_lock_dependency_map(
    dependencies: &[String],
) -> serde_json::Map<String, serde_json::Value> {
    let mut sorted = BTreeMap::new();
    for dependency in dependencies {
        let Ok(spec) = PackageSpec::parse(dependency) else {
            continue;
        };
        if spec.ecosystem != Ecosystem::Npm {
            continue;
        }
        let requirement = spec
            .version
            .or(spec.direct_url)
            .unwrap_or_else(|| "*".to_owned());
        sorted.insert(spec.name, serde_json::Value::String(requirement));
    }
    sorted.into_iter().collect()
}

fn npm_package_lock_path(name: &str) -> String {
    format!("node_modules/{name}")
}

fn npm_package_lock_integrity(sha256_hex: &str) -> Option<String> {
    let bytes = hex_bytes(sha256_hex)?;
    Some(format!("sha256-{}", BASE64_STANDARD.encode(bytes)))
}

fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[index..index + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}


fn npm_compat_cache_dir(project_dir: &Path, cache_dir: Option<&Path>) -> PathBuf {
    cache_dir
        .map(|path| path.join("_cacache"))
        .unwrap_or_else(|| npm_cache_dir(project_dir))
}

fn npm_cache_arg_or_env(invocation_cwd: &Path, cache_dir: Option<PathBuf>) -> Option<PathBuf> {
    cache_dir
        .or_else(npm_cache_dir_env)
        .map(|path| absolutize_path(invocation_cwd, path))
}

fn npm_cache_dir_env() -> Option<PathBuf> {
    env_path_from_any(["NPM_CONFIG_CACHE", "npm_config_cache"])
}

fn remove_npm_cache_entries(cache_dir: &Path, pattern: &str) -> Result<usize, OmcRegistryError> {
    let mut files = compat_cache_files(cache_dir)?;
    files.retain(|path| compat_cache_pattern_matches(path, cache_dir, pattern));
    let count = remove_cache_files(&files)?;
    prune_empty_cache_dirs(cache_dir)?;
    Ok(count)
}


fn npm_doctor_report(
    project_dir: &Path,
    action: &NpmDoctorAction,
) -> Result<String, OmcRegistryError> {
    let checks = npm_doctor_checks(&action.checks)?;
    let values = npm_config_values(
        project_dir,
        action.npm_registry.as_deref(),
        None,
        None,
        NpmConfigLocation::User,
    )?;
    let registry = npm_config_value_for_key(&values, "registry");
    let cache_dir = npm_cache_dir(project_dir);
    let mut output = String::from("OMC npm doctor\n");
    for check in checks {
        match check {
            "connection" => {
                output.push_str("\nconnection\n");
                output.push_str("  network probe: skipped (OMC doctor is offline)\n");
                output.push_str(&format!("  registry: {registry}\n"));
            }
            "registry" => {
                output.push_str("\nregistry\n");
                output.push_str(&format!("  registry: {registry}\n"));
            }
            "versions" => {
                output.push_str("\nversions\n");
                output.push_str(&format!("  omc: {}\n", env!("CARGO_PKG_VERSION")));
                output.push_str(&format!(
                    "  omc.lock: {}\n",
                    npm_doctor_file_status(&project_dir.join("omc.lock"))
                ));
                output.push_str(&format!(
                    "  npm lockfile: {}\n",
                    if project_dir.join("npm-shrinkwrap.json").exists() {
                        "npm-shrinkwrap.json"
                    } else if project_dir.join("package-lock.json").exists() {
                        "package-lock.json"
                    } else {
                        "missing"
                    }
                ));
            }
            "environment" => {
                output.push_str("\nenvironment\n");
                output.push_str(&format!("  project: {}\n", project_dir.display()));
                output.push_str(&format!(
                    "  package.json: {}\n",
                    npm_doctor_file_status(&project_dir.join("package.json"))
                ));
                output.push_str(&format!(
                    "  node_modules: {}\n",
                    npm_doctor_file_status(&project_dir.join("node_modules"))
                ));
            }
            "permissions" => {
                output.push_str("\npermissions\n");
                output.push_str(&format!(
                    "  project directory: {}\n",
                    npm_doctor_access_status(project_dir)
                ));
                output.push_str(&format!(
                    "  cache directory: {}\n",
                    npm_doctor_access_status(&cache_dir)
                ));
            }
            "cache" => {
                let files = compat_cache_files(&cache_dir)?;
                let bytes = cache_files_size(&files)?;
                output.push_str("\ncache\n");
                output.push_str(&format!("  path: {}\n", cache_dir.display()));
                output.push_str(&format!("  files: {}\n", files.len()));
                output.push_str(&format!("  bytes: {bytes}\n"));
            }
            _ => unreachable!("npm_doctor_checks only returns known checks"),
        }
    }
    Ok(output)
}

fn npm_doctor_checks(checks: &[String]) -> Result<Vec<&'static str>, OmcRegistryError> {
    const DEFAULT_CHECKS: &[&str] = &[
        "connection",
        "registry",
        "versions",
        "environment",
        "permissions",
        "cache",
    ];
    if checks.is_empty() {
        return Ok(DEFAULT_CHECKS.to_vec());
    }
    let mut selected = Vec::new();
    for check in checks {
        let canonical = match check.as_str() {
            "connection" => "connection",
            "registry" => "registry",
            "versions" => "versions",
            "environment" => "environment",
            "permissions" => "permissions",
            "cache" => "cache",
            other => {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "unsupported npm doctor check `{other}`"
                )));
            }
        };
        selected.push(canonical);
    }
    Ok(selected)
}

fn npm_doctor_file_status(path: &Path) -> &'static str {
    if path.exists() {
        "found"
    } else {
        "missing"
    }
}

fn npm_doctor_access_status(path: &Path) -> &'static str {
    if path.exists() {
        "accessible"
    } else {
        "missing"
    }
}



fn npm_pkg_set_default_string(
    package: &mut serde_json::Value,
    path: &str,
    value: String,
) -> Result<(), OmcRegistryError> {
    if npm_pkg_get_path(package, path).is_none() {
        npm_pkg_set_path(package, path, serde_json::Value::String(value))?;
    }
    Ok(())
}

fn default_npm_package_name(project_dir: &Path, scope: Option<&str>) -> String {
    let base = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(normalize_npm_init_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "omc-project".to_owned());
    if let Some(scope) = scope
        .map(normalize_npm_scope)
        .filter(|scope| !scope.is_empty())
    {
        format!("{scope}/{base}")
    } else {
        base
    }
}

fn normalize_npm_init_name(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn normalize_npm_scope(scope: &str) -> String {
    let scope = scope.trim().trim_start_matches('@');
    if scope.is_empty() {
        String::new()
    } else {
        format!("@{}", normalize_npm_init_name(scope))
    }
}

fn npm_cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".omc").join("cache").join("npm")
}


fn npm_manifest_from_tarball(bytes: &[u8]) -> Result<serde_json::Value, OmcRegistryError> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        if path == "package/package.json" || path == "package.json" {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            let manifest: serde_json::Value = serde_json::from_str(&content)?;
            if manifest.is_object() {
                return Ok(manifest);
            }
            break;
        }
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "npm publish tarball does not contain package/package.json".to_owned(),
    ))
}

pub(crate) fn npm_package_json_name(package: &serde_json::Value) -> Result<String, OmcRegistryError> {
    package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("package.json does not define name".to_owned())
        })
}

pub(crate) fn read_npm_pkg_json(path: &Path) -> Result<serde_json::Value, OmcRegistryError> {
    if !path.exists() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{} does not exist",
            path.display()
        )));
    }
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if !value.is_object() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{} must contain a JSON object",
            path.display()
        )));
    }
    Ok(value)
}

fn write_npm_pkg_json(path: &Path, value: &serde_json::Value) -> Result<(), OmcRegistryError> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn save_npm_package_json_dependency(
    package_dir: &Path,
    name: &str,
    requirement: &str,
    kind: ManifestDependencyKind,
    save_bundle: bool,
) -> Result<(), OmcRegistryError> {
    let package_json = package_dir.join("package.json");
    let mut package = read_npm_pkg_json(&package_json)?;
    remove_npm_package_json_dependency(&mut package, name);
    let field = npm_package_json_dependency_field(kind);
    npm_package_json_dependency_map_mut(&mut package, field)?.insert(
        name.to_owned(),
        serde_json::Value::String(requirement.to_owned()),
    );
    if save_bundle {
        save_npm_package_json_bundle_dependency(&mut package, name)?;
    }
    write_npm_pkg_json(&package_json, &package)
}

fn save_npm_package_json_local_dependency(
    project_dir: &Path,
    package_dir: &Path,
    local_path: &Path,
    kind: ManifestDependencyKind,
    save_bundle: bool,
) -> Result<(), OmcRegistryError> {
    let target = fs::canonicalize(absolutize_path(project_dir, local_path.to_path_buf()))?;
    let package = read_npm_pkg_json(&target.join("package.json"))?;
    let name = npm_package_json_name(&package)?;
    let requirement = format!("file:{}", target.display());
    save_npm_package_json_dependency(package_dir, &name, &requirement, kind, save_bundle)
}

fn npm_package_json_dependency_field(kind: ManifestDependencyKind) -> &'static str {
    match kind {
        ManifestDependencyKind::Production => "dependencies",
        ManifestDependencyKind::Dev => "devDependencies",
        ManifestDependencyKind::Optional => "optionalDependencies",
        ManifestDependencyKind::Peer => "peerDependencies",
    }
}

fn remove_npm_package_json_dependency(package: &mut serde_json::Value, name: &str) {
    let _ = remove_npm_package_json_dependency_entry(package, name);
}

fn save_npm_package_json_bundle_dependency(
    package: &mut serde_json::Value,
    name: &str,
) -> Result<(), OmcRegistryError> {
    if npm_package_json_bundle_field_is_true(package, "bundleDependencies")
        || npm_package_json_bundle_field_is_true(package, "bundledDependencies")
    {
        return Ok(());
    }

    let field = if package.get("bundledDependencies").is_some()
        && package.get("bundleDependencies").is_none()
    {
        "bundledDependencies"
    } else {
        "bundleDependencies"
    };
    let object = package.as_object_mut().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("package.json must contain a JSON object".to_owned())
    })?;
    let value = object
        .entry(field.to_owned())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if !value.is_array() {
        *value = serde_json::Value::Array(Vec::new());
    }
    let entries = value.as_array_mut().expect("bundle field is an array");
    if !entries.iter().any(|entry| entry.as_str() == Some(name)) {
        entries.push(serde_json::Value::String(name.to_owned()));
    }
    entries.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    Ok(())
}

fn npm_package_json_bundle_field_is_true(package: &serde_json::Value, field: &str) -> bool {
    package
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn npm_specs_with_existing_manifest_requirements(
    package_dirs: &[PathBuf],
    specs: Vec<String>,
) -> Result<Vec<String>, OmcRegistryError> {
    specs
        .into_iter()
        .map(|spec| npm_spec_with_existing_manifest_requirement(package_dirs, spec))
        .collect()
}

fn npm_spec_with_existing_manifest_requirement(
    package_dirs: &[PathBuf],
    raw: String,
) -> Result<String, OmcRegistryError> {
    let spec = parse_package_spec(&raw, Some(Ecosystem::Npm))?;
    if spec.ecosystem != Ecosystem::Npm || spec.version.is_some() || spec.direct_url.is_some() {
        return Ok(raw);
    }

    let Some(requirement) = npm_existing_package_json_requirement(package_dirs, &spec.name)? else {
        return Ok(raw);
    };
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return Ok(raw);
    }

    Ok(npm_spec_with_manifest_requirement(&spec.name, requirement))
}

fn npm_existing_package_json_requirement(
    package_dirs: &[PathBuf],
    name: &str,
) -> Result<Option<String>, OmcRegistryError> {
    if package_dirs.is_empty() {
        return Ok(None);
    }

    let mut selected = None;
    for package_dir in package_dirs {
        let Some(requirement) = npm_package_json_dependency_requirement(package_dir, name)? else {
            return Ok(None);
        };
        match selected.as_ref() {
            Some(existing) if existing != &requirement => return Ok(None),
            Some(_) => {}
            None => selected = Some(requirement),
        }
    }
    Ok(selected)
}

fn npm_package_json_dependency_requirement(
    package_dir: &Path,
    name: &str,
) -> Result<Option<String>, OmcRegistryError> {
    let package_json = package_dir.join("package.json");
    if !package_json.exists() {
        return Ok(None);
    }
    let package = read_npm_pkg_json(&package_json)?;
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(requirement) = package
            .get(field)
            .and_then(serde_json::Value::as_object)
            .and_then(|dependencies| dependencies.get(name))
            .and_then(serde_json::Value::as_str)
        {
            return Ok(Some(requirement.to_owned()));
        }
    }
    Ok(None)
}

fn npm_spec_with_manifest_requirement(name: &str, requirement: &str) -> String {
    if npm_manifest_requirement_is_direct_url(requirement) {
        format!("{name} @ {requirement}")
    } else {
        format!("{name}@{requirement}")
    }
}

fn npm_manifest_requirement_is_direct_url(requirement: &str) -> bool {
    requirement.contains("://")
        || requirement.starts_with("file:")
        || requirement.starts_with("git+")
}

fn remove_npm_package_json_dependency_entry(package: &mut serde_json::Value, name: &str) -> bool {
    let mut removed = false;
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(dependencies) = package
            .get_mut(field)
            .and_then(serde_json::Value::as_object_mut)
        {
            removed |= dependencies.remove(name).is_some();
        }
    }
    removed
}

fn remove_npm_package_json_bundle_dependency_entry(
    package: &mut serde_json::Value,
    name: &str,
) -> bool {
    let mut removed = false;
    for field in ["bundleDependencies", "bundledDependencies"] {
        if let Some(entries) = package
            .get_mut(field)
            .and_then(serde_json::Value::as_array_mut)
        {
            let before = entries.len();
            entries.retain(|entry| entry.as_str() != Some(name));
            removed |= entries.len() != before;
        }
    }
    removed
}

fn remove_root_npm_package_json_dependency(
    project_dir: &Path,
    name: &str,
) -> Result<bool, OmcRegistryError> {
    remove_npm_package_json_dependency_from_package_dir(project_dir, name)
}

fn remove_npm_package_json_dependency_from_package_dir(
    package_dir: &Path,
    name: &str,
) -> Result<bool, OmcRegistryError> {
    let package_json = package_dir.join("package.json");
    if !package_json.exists() {
        return Ok(false);
    }
    let mut package = read_npm_pkg_json(&package_json)?;
    let removed = remove_npm_package_json_dependency_entry(&mut package, name);
    let removed_bundle = remove_npm_package_json_bundle_dependency_entry(&mut package, name);
    if removed || removed_bundle {
        write_npm_pkg_json(&package_json, &package)?;
    }
    Ok(removed)
}

fn npm_package_json_dependency_map_mut<'a>(
    package: &'a mut serde_json::Value,
    field: &str,
) -> Result<&'a mut serde_json::Map<String, serde_json::Value>, OmcRegistryError> {
    let object = package.as_object_mut().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("package.json must contain a JSON object".to_owned())
    })?;
    let dependencies = object
        .entry(field.to_owned())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !dependencies.is_object() {
        *dependencies = serde_json::Value::Object(serde_json::Map::new());
    }
    dependencies.as_object_mut().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!("cannot update package.json `{field}`"))
    })
}

fn npm_pkg_get_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in npm_pkg_path_segments(path) {
        current = current.get(segment)?;
    }
    Some(current)
}

fn npm_pkg_set_path(
    value: &mut serde_json::Value,
    path: &str,
    new_value: serde_json::Value,
) -> Result<(), OmcRegistryError> {
    let segments = npm_pkg_path_segments(path);
    if segments.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm pkg set needs a non-empty key".to_owned(),
        ));
    }
    let mut current = value;
    for segment in &segments[..segments.len() - 1] {
        if !current.is_object() {
            *current = serde_json::Value::Object(serde_json::Map::new());
        }
        let object = current.as_object_mut().ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("cannot set npm pkg path `{path}`"))
        })?;
        current = object
            .entry((*segment).to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    let object = current.as_object_mut().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!("cannot set npm pkg path `{path}`"))
    })?;
    object.insert(segments[segments.len() - 1].to_owned(), new_value);
    Ok(())
}

fn npm_pkg_delete_path(value: &mut serde_json::Value, path: &str) -> bool {
    let segments = npm_pkg_path_segments(path);
    if segments.is_empty() {
        return false;
    }
    let mut current = value;
    for segment in &segments[..segments.len() - 1] {
        let Some(next) = current.get_mut(*segment) else {
            return false;
        };
        current = next;
    }
    current
        .as_object_mut()
        .and_then(|object| object.remove(segments[segments.len() - 1]))
        .is_some()
}

fn npm_pkg_path_segments(path: &str) -> Vec<&str> {
    path.split('.')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn verify_npm_locked_cache(project_dir: &Path) -> Result<usize, OmcRegistryError> {
    let lockfile = project_dir.join("omc.lock");
    if !lockfile.exists() {
        return Ok(0);
    }
    let lock = read_lockfile(&lockfile)?;
    let mut verified = 0;
    for package in lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
    {
        let archive_path = absolutize_path(project_dir, PathBuf::from(&package.archive));
        let bytes = fs::read(&archive_path)?;
        let actual = pip_hash_digest(PipHashAlgorithm::Sha256, &bytes);
        if !package.sha256.eq_ignore_ascii_case(&actual) {
            return Err(OmcRegistryError::DigestMismatch {
                name: package.name.clone(),
                expected: format!("sha256:{}", package.sha256),
                actual: format!("sha256:{actual}"),
            });
        }
        verified += 1;
    }
    Ok(verified)
}

fn env_path_from_any<const N: usize>(keys: [&str; N]) -> Option<PathBuf> {
    keys.into_iter().find_map(|key| {
        env::var_os(key)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    })
}

fn compat_cache_files(cache_dir: &Path) -> Result<Vec<PathBuf>, OmcRegistryError> {
    let mut files = Vec::new();
    collect_cache_files(cache_dir, &mut files)?;
    Ok(files)
}

fn collect_cache_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), OmcRegistryError> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_cache_files(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn cache_files_size(files: &[PathBuf]) -> Result<u64, OmcRegistryError> {
    let mut bytes = 0;
    for path in files {
        bytes += fs::metadata(path)?.len();
    }
    Ok(bytes)
}

fn remove_cache_files(files: &[PathBuf]) -> Result<usize, OmcRegistryError> {
    let mut count = 0;
    for path in files {
        fs::remove_file(path)?;
        count += 1;
    }
    Ok(count)
}

fn prune_empty_cache_dirs(root: &Path) -> Result<(), OmcRegistryError> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            prune_empty_cache_dirs(&path)?;
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(path)?;
            }
        }
    }
    Ok(())
}

fn compat_cache_pattern_matches(path: &Path, cache_dir: &Path, pattern: &str) -> bool {
    let display = compat_cache_display_path(path, cache_dir);
    wildcard_match(&display, pattern)
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| wildcard_match(name, pattern))
            .unwrap_or(false)
}

fn compat_cache_display_path(path: &Path, cache_dir: &Path) -> String {
    path.strip_prefix(cache_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .to_owned()
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return value.contains(pattern);
    }
    let mut rest = value;
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return true;
    }
    if !starts_with_wildcard {
        let Some(first) = parts.first() else {
            return true;
        };
        if !rest.starts_with(first) {
            return false;
        }
        rest = &rest[first.len()..];
    }
    for (index, part) in parts.iter().enumerate() {
        if index == 0 && !starts_with_wildcard {
            continue;
        }
        let Some(found) = rest.find(part) else {
            return false;
        };
        rest = &rest[found + part.len()..];
    }
    ends_with_wildcard || rest.is_empty()
}

fn print_lock_only_report(project_dir: &Path) {
    println!("lockfile {}", project_dir.join("omc.lock").display());
}


fn npm_maintenance_command_name(command: NpmMaintenanceCommand) -> &'static str {
    match command {
        NpmMaintenanceCommand::Prune => "prune",
        NpmMaintenanceCommand::Dedupe => "dedupe",
        NpmMaintenanceCommand::Rebuild => "rebuild",
    }
}

fn npm_maintenance_dry_run_report(project_dir: &Path) -> Result<InstallReport, OmcRegistryError> {
    let packages = match read_lockfile(project_dir.join("omc.lock")) {
        Ok(lock) => lock.packages,
        Err(OmcRegistryError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Vec::new()
        }
        Err(error) => return Err(error),
    };
    Ok(InstallReport {
        npm_packages: packages
            .iter()
            .filter(|package| package.ecosystem == Ecosystem::Npm)
            .count(),
        pypi_packages: packages
            .iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .count(),
        local_source_artifacts: 0,
        npm_bins: 0,
        python_scripts: 0,
        node_modules: project_dir.join("node_modules"),
        npm_bin_dir: project_dir.join("node_modules").join(".bin"),
        python_bin_dir: project_dir.join(".omc").join("python").join("bin"),
        python_site_packages: project_dir
            .join(".omc")
            .join("python")
            .join("site-packages"),
    })
}

fn remove_npm_installed_specs(
    project_dir: &Path,
    specs: &[PackageSpec],
) -> Result<Vec<String>, OmcRegistryError> {
    let mut package_names = specs
        .iter()
        .filter(|spec| spec.ecosystem == Ecosystem::Npm)
        .map(|spec| spec.name.clone())
        .collect::<BTreeSet<_>>();
    extend_npm_installed_removal_with_lock_dependencies(project_dir, &mut package_names);

    let mut removed = Vec::new();
    for name in package_names {
        if remove_npm_installed_package(project_dir, &name)? {
            removed.push(format!("npm:{name}"));
        }
    }
    Ok(removed)
}

fn extend_npm_installed_removal_with_lock_dependencies(
    project_dir: &Path,
    package_names: &mut BTreeSet<String>,
) {
    let omc_lock = project_dir.join("omc.lock");
    let dependency_graph = if omc_lock.exists() {
        read_lockfile(omc_lock)
            .ok()
            .map(npm_dependency_graph_from_omc_lock)
    } else {
        None
    }
    .or_else(|| npm_dependency_graph_from_package_lock(project_dir));
    let Some(dependency_graph) = dependency_graph else {
        return;
    };

    let direct_names = package_names.clone();
    let mut queue = package_names.iter().cloned().collect::<VecDeque<_>>();
    while let Some(name) = queue.pop_front() {
        let Some(dependencies) = dependency_graph.get(&name) else {
            continue;
        };
        for dependency_name in dependencies {
            if package_names.insert(dependency_name.clone()) {
                queue.push_back(dependency_name.clone());
            }
        }
    }

    let mut protected = BTreeSet::new();
    for name in npm_project_declared_dependency_names(project_dir) {
        if !direct_names.contains(&name) && protected.insert(name.clone()) {
            collect_npm_dependency_closure(&name, &dependency_graph, &mut protected);
        }
    }
    for name in dependency_graph.keys() {
        if package_names.contains(name) {
            continue;
        }
        collect_npm_dependency_closure(name, &dependency_graph, &mut protected);
    }
    for name in protected {
        if !direct_names.contains(&name) {
            package_names.remove(&name);
        }
    }
}

fn npm_dependency_graph_from_omc_lock(lock: OmcLock) -> BTreeMap<String, BTreeSet<String>> {
    lock.packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
        .map(|package| {
            let dependencies = package
                .dependencies
                .iter()
                .chain(&package.optional_dependencies)
                .filter_map(|dependency| npm_dependency_name_from_key(dependency))
                .collect();
            (package.name, dependencies)
        })
        .collect()
}

fn npm_dependency_graph_from_package_lock(
    project_dir: &Path,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    let package_lock = read_npm_pkg_json(&project_dir.join("package-lock.json")).ok()?;
    let packages = package_lock.get("packages")?.as_object()?;
    let mut graph = BTreeMap::new();
    for (path, entry) in packages {
        let Some(name) = npm_package_name_from_package_lock_path(path) else {
            continue;
        };
        let dependencies = ["dependencies", "optionalDependencies"]
            .into_iter()
            .filter_map(|field| entry.get(field).and_then(serde_json::Value::as_object))
            .flat_map(|dependencies| dependencies.keys().cloned())
            .collect();
        graph.insert(name, dependencies);
    }
    Some(graph)
}

fn npm_package_name_from_package_lock_path(path: &str) -> Option<String> {
    if !path.contains("node_modules/") {
        return None;
    }
    let mut parts = path.rsplit("node_modules/");
    let name = parts.next()?;
    if name.is_empty() || name.contains("/node_modules/") {
        return None;
    }
    if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped.split_once('/')?;
        if package.contains('/') {
            return None;
        }
        return Some(format!("@{scope}/{package}"));
    }
    if name.contains('/') {
        return None;
    }
    Some(name.to_owned())
}

fn npm_project_declared_dependency_names(project_dir: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    extend_npm_package_json_dependency_names(&project_dir.join("package.json"), &mut names);
    if let Ok(workspaces) = read_npm_workspace_packages(project_dir) {
        for workspace in workspaces {
            extend_npm_package_json_dependency_names(
                &workspace.path.join("package.json"),
                &mut names,
            );
        }
    }
    names
}

fn extend_npm_package_json_dependency_names(path: &Path, names: &mut BTreeSet<String>) {
    let Ok(package) = read_npm_pkg_json(path) else {
        return;
    };
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(dependencies) = package.get(field).and_then(serde_json::Value::as_object) {
            names.extend(dependencies.keys().cloned());
        }
    }
}


fn npm_dependency_name_from_key(dependency: &str) -> Option<String> {
    parse_package_specs(&[dependency.to_owned()], Some(Ecosystem::Npm))
        .ok()
        .and_then(|specs| specs.into_iter().next())
        .filter(|spec| spec.ecosystem == Ecosystem::Npm)
        .map(|spec| spec.name)
}

fn remove_npm_installed_package(project_dir: &Path, name: &str) -> Result<bool, OmcRegistryError> {
    let node_modules = project_dir.join("node_modules");
    let package_dir = npm_installed_package_dir(project_dir, name)?;
    if !package_dir.exists() {
        return Ok(false);
    }

    remove_npm_bin_links_for_package(&node_modules, &package_dir, name)?;
    remove_cli_path_if_exists(&package_dir)?;
    if let Some(scope_dir) = package_dir.parent().filter(|path| {
        path.parent() == Some(node_modules.as_path())
            && path
                .file_name()
                .and_then(|part| part.to_str())
                .is_some_and(|part| part.starts_with('@'))
    }) {
        if fs::read_dir(scope_dir)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false)
        {
            fs::remove_dir(scope_dir)?;
        }
    }
    Ok(true)
}

fn remove_npm_bin_links_for_package(
    node_modules: &Path,
    package_dir: &Path,
    package_name: &str,
) -> Result<(), OmcRegistryError> {
    let package_json = package_dir.join("package.json");
    let Ok(package) = read_npm_pkg_json(&package_json) else {
        return Ok(());
    };
    for bin_name in npm_package_bin_names(&package, package_name) {
        if !cli_bin_name_is_safe(&bin_name) {
            continue;
        }
        let bin_path = node_modules.join(".bin").join(bin_name);
        if npm_bin_link_owned_by_package(&bin_path, package_dir)? {
            remove_cli_path_if_exists(&bin_path)?;
        }
    }
    Ok(())
}

fn npm_package_bin_names(package: &serde_json::Value, package_name: &str) -> Vec<String> {
    let Some(bin) = package.get("bin") else {
        return Vec::new();
    };
    if bin.is_string() {
        return vec![npm_default_bin_name(package_name).to_owned()];
    }
    bin.as_object()
        .map(|bins| bins.keys().cloned().collect())
        .unwrap_or_default()
}

fn npm_default_bin_name(package_name: &str) -> &str {
    package_name
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(package_name)
}

fn npm_bin_link_owned_by_package(
    bin_path: &Path,
    package_dir: &Path,
) -> Result<bool, OmcRegistryError> {
    let metadata = match fs::symlink_metadata(bin_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(OmcRegistryError::Io(error)),
    };
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(bin_path)?;
        let target = if target.is_absolute() {
            target
        } else {
            bin_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
        return Ok(target.starts_with(package_dir));
    }
    if metadata.is_file() {
        let content = fs::read_to_string(bin_path).unwrap_or_default();
        return Ok(content.contains(&package_dir.display().to_string()));
    }
    Ok(false)
}

pub(crate) fn remove_specs(
    project_dir: &Path,
    specs: &[String],
    ecosystem_hint: Option<Ecosystem>,
    policy: CliPolicyArgs<'_>,
    update_npm_package_json: bool,
    allow_locked_pypi_removal: bool,
    npm_lock_only: bool,
    npm_package_lock: bool,
    missing_ok: bool,
    warn_missing: bool,
) -> Result<bool, OmcRegistryError> {
    let specs = parse_package_specs(specs, ecosystem_hint)?;
    let update_npm_package_json =
        update_npm_package_json && specs.iter().any(|spec| spec.ecosystem == Ecosystem::Npm);
    let allow_locked_pypi_removal =
        allow_locked_pypi_removal && specs.iter().any(|spec| spec.ecosystem == Ecosystem::Pypi);
    let editable_removal = if allow_locked_pypi_removal {
        remove_pip_editable_local_paths(project_dir, &specs)?
    } else {
        PipEditableLocalPathRemoval::default()
    };
    let mut removed = Vec::new();
    let mut removed_locked = false;
    let mut removed_manifest = false;
    for spec in &specs {
        let removed_from_manifest_dependency =
            if missing_ok && !project_dir.join("omc.toml").exists() {
                false
            } else {
                remove_manifest_dependency(project_dir, spec)?
            };
        let removed_from_manifest_local_path = if spec.ecosystem == Ecosystem::Npm {
            remove_manifest_npm_local_paths_for_package(project_dir, &spec.name)?
        } else {
            false
        };
        let removed_from_manifest =
            removed_from_manifest_dependency || removed_from_manifest_local_path;
        removed_manifest |= removed_from_manifest;
        let removed_from_package_json =
            if update_npm_package_json && spec.ecosystem == Ecosystem::Npm {
                remove_root_npm_package_json_dependency(project_dir, &spec.name)?
            } else {
                false
            };
        let locked_removals = if !removed_from_manifest
            && !removed_from_package_json
            && allow_locked_pypi_removal
            && spec.ecosystem == Ecosystem::Pypi
        {
            remove_locked_packages(project_dir, std::slice::from_ref(spec))?
        } else {
            Vec::new()
        };
        let removed_from_editable =
            editable_removal.removed(&spec.name) && spec.ecosystem == Ecosystem::Pypi;
        removed_locked |= !locked_removals.is_empty();
        if !removed_from_manifest
            && !removed_from_package_json
            && locked_removals.is_empty()
            && !removed_from_editable
        {
            if missing_ok {
                if warn_missing {
                    eprintln!("WARNING: Skipping {} as it is not installed.", spec.name);
                }
                continue;
            }
            let sources = if update_npm_package_json && spec.ecosystem == Ecosystem::Npm {
                "omc.toml or package.json"
            } else if allow_locked_pypi_removal && spec.ecosystem == Ecosystem::Pypi {
                "omc.toml, omc.lock, or OMC editable local paths"
            } else {
                "omc.toml"
            };
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "dependency `{}` is not in {sources}",
                spec.package_key(),
            )));
        }
        removed.push(spec.package_key());
    }
    if removed.is_empty() {
        return Ok(false);
    }

    if npm_lock_only && update_npm_package_json {
        let mut options = LinkOptions::new(project_dir);
        apply_cli_policy_options(
            &mut options,
            policy.allow,
            policy.allow_flow,
            policy.allow_all_host,
        )?;
        options.discover_project_requirements = true;
        let reports = lock_npm_project_including_omitted(&options)?;
        print_link_reports(&reports);
        print_lock_only_report(project_dir);
        if npm_package_lock {
            sync_npm_package_lock(project_dir)?;
        }
        return Ok(true);
    }

    let mut install = if (removed_locked || !editable_removal.removed_names.is_empty())
        && !removed_manifest
        && !update_npm_package_json
    {
        install_locked_packages(project_dir)?
    } else {
        let mut options = LinkOptions::new(project_dir);
        apply_cli_policy_options(
            &mut options,
            policy.allow,
            policy.allow_flow,
            policy.allow_all_host,
        )?;
        options.discover_project_requirements = update_npm_package_json;
        install_project(&options)?
    };
    install.python_scripts += install_python_project_local_import_paths(
        project_dir,
        &editable_removal.remaining_import_paths,
    )?;
    if update_npm_package_json {
        sync_npm_package_lock(project_dir)?;
    }
    println!("removed {}", removed.join(", "));
    print_install_report(&install);
    Ok(true)
}

fn remove_manifest_npm_local_paths_for_package(
    project_dir: &Path,
    name: &str,
) -> Result<bool, OmcRegistryError> {
    let manifest_path = project_dir.join("omc.toml");
    if !manifest_path.exists() {
        return Ok(false);
    }

    let mut manifest = read_manifest(&manifest_path)?;
    let mut removed = false;
    removed |= remove_manifest_npm_local_paths_for_package_from_vec(
        project_dir,
        &mut manifest.npm_local_paths,
        name,
    )?;
    removed |= remove_manifest_npm_local_paths_for_package_from_vec(
        project_dir,
        &mut manifest.npm_dev_local_paths,
        name,
    )?;
    removed |= remove_manifest_npm_local_paths_for_package_from_vec(
        project_dir,
        &mut manifest.npm_optional_local_paths,
        name,
    )?;
    removed |= remove_manifest_npm_local_paths_for_package_from_vec(
        project_dir,
        &mut manifest.npm_peer_local_paths,
        name,
    )?;

    if removed {
        fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    }
    Ok(removed)
}

fn remove_manifest_npm_local_paths_for_package_from_vec(
    project_dir: &Path,
    paths: &mut Vec<String>,
    name: &str,
) -> Result<bool, OmcRegistryError> {
    let mut kept = Vec::with_capacity(paths.len());
    let mut removed = false;
    for path in std::mem::take(paths) {
        if npm_manifest_local_path_has_package_name(project_dir, &path, name)? {
            removed = true;
        } else {
            kept.push(path);
        }
    }
    *paths = kept;
    Ok(removed)
}

fn npm_manifest_local_path_has_package_name(
    project_dir: &Path,
    path: &str,
    name: &str,
) -> Result<bool, OmcRegistryError> {
    let package_json = absolutize_path(project_dir, PathBuf::from(path)).join("package.json");
    if !package_json.exists() {
        return Ok(false);
    }
    let package = read_npm_pkg_json(&package_json)?;
    Ok(package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|package_name| package_name == name))
}

fn print_locked_packages(
    project_dir: &Path,
    ecosystem: Option<Ecosystem>,
    json: bool,
    filters: &[String],
) -> Result<(), OmcRegistryError> {
    let packages = listed_locked_packages(project_dir, ecosystem, filters)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else if packages.is_empty() {
        println!("packages: 0");
    } else {
        for package in packages {
            println!(
                "{}:{}@{} {} {}",
                package.ecosystem,
                package.name,
                package.version,
                verdict_label(package.verdict),
                behavior_label(package.behavior)
            );
        }
    }
    Ok(())
}


fn npm_list_json_tree(
    project_dir: &Path,
    filters: &[String],
    depth: usize,
) -> Result<serde_json::Value, OmcRegistryError> {
    let packages = listed_locked_packages(project_dir, Some(Ecosystem::Npm), &[])?;
    let mut packages_by_name = BTreeMap::new();
    for package in &packages {
        packages_by_name
            .entry(package.name.clone())
            .or_insert(package);
    }

    let filter_names = package_list_filter_names(filters, Some(Ecosystem::Npm))?;
    let mut root_dependencies = if filter_names.is_empty() {
        npm_root_dependency_names(project_dir)?
    } else {
        filter_names
    };
    if root_dependencies.is_empty() && filters.is_empty() {
        root_dependencies.extend(packages.iter().map(|package| package.name.clone()));
    }

    let (name, version) = npm_list_root_metadata(project_dir)?;
    let mut root = serde_json::Map::new();
    root.insert("version".to_owned(), serde_json::Value::String(version));
    root.insert("name".to_owned(), serde_json::Value::String(name));

    let mut dependencies = serde_json::Map::new();
    for dependency in root_dependencies {
        if let Some(package) = packages_by_name.get(&dependency) {
            let mut visiting = BTreeSet::new();
            dependencies.insert(
                dependency,
                npm_list_package_json(package, &packages_by_name, &mut visiting, depth),
            );
        }
    }
    if !dependencies.is_empty() {
        root.insert(
            "dependencies".to_owned(),
            serde_json::Value::Object(dependencies),
        );
    }

    Ok(serde_json::Value::Object(root))
}

fn npm_list_root_metadata(project_dir: &Path) -> Result<(String, String), OmcRegistryError> {
    let fallback_name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("omc-project")
        .to_owned();
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok((fallback_name, "0.0.0".to_owned()));
    }

    let package = read_npm_pkg_json(&package_json)?;
    let name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(&fallback_name)
        .to_owned();
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty())
        .unwrap_or("0.0.0")
        .to_owned();
    Ok((name, version))
}

fn npm_list_package_json(
    package: &LockedPackage,
    packages_by_name: &BTreeMap<String, &LockedPackage>,
    visiting: &mut BTreeSet<(String, String)>,
    remaining_depth: usize,
) -> serde_json::Value {
    let mut item = serde_json::Map::new();
    item.insert(
        "version".to_owned(),
        serde_json::Value::String(package.version.clone()),
    );
    if !package.source_url.is_empty() {
        item.insert(
            "resolved".to_owned(),
            serde_json::Value::String(package.source_url.clone()),
        );
    }
    item.insert("overridden".to_owned(), serde_json::Value::Bool(false));

    let visit_key = (package.name.clone(), package.version.clone());
    if remaining_depth > 0 && visiting.insert(visit_key.clone()) {
        let mut dependencies = serde_json::Map::new();
        for dependency in package
            .dependencies
            .iter()
            .chain(package.optional_dependencies.iter())
            .chain(package.peer_dependencies.iter())
            .filter_map(|dependency| npm_dependency_name(dependency))
        {
            if let Some(dependency_package) = packages_by_name.get(&dependency) {
                dependencies.insert(
                    dependency,
                    npm_list_package_json(
                        dependency_package,
                        packages_by_name,
                        visiting,
                        remaining_depth.saturating_sub(1),
                    ),
                );
            }
        }
        if !dependencies.is_empty() {
            item.insert(
                "dependencies".to_owned(),
                serde_json::Value::Object(dependencies),
            );
        }
        visiting.remove(&visit_key);
    }

    serde_json::Value::Object(item)
}

fn listed_locked_packages(
    project_dir: &Path,
    ecosystem: Option<Ecosystem>,
    filters: &[String],
) -> Result<Vec<LockedPackage>, OmcRegistryError> {
    let filter_names = package_list_filter_names(filters, ecosystem)?;
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let mut packages = lock
        .packages
        .into_iter()
        .filter(|package| {
            ecosystem
                .map(|ecosystem| package.ecosystem == ecosystem)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    if ecosystem
        .map(|ecosystem| ecosystem == Ecosystem::Npm)
        .unwrap_or(true)
    {
        let mut existing = packages
            .iter()
            .map(|package| (package.ecosystem, package.name.clone()))
            .collect::<BTreeSet<_>>();
        for package in npm_local_locked_packages(project_dir)? {
            if existing.insert((package.ecosystem, package.name.clone())) {
                packages.push(package);
            }
        }
    }

    packages.retain(|package| filter_names.is_empty() || filter_names.contains(&package.name));
    packages.sort_by(|left, right| {
        (
            left.ecosystem,
            left.name.as_str(),
            left.version.as_str(),
            left.source_url.as_str(),
        )
            .cmp(&(
                right.ecosystem,
                right.name.as_str(),
                right.version.as_str(),
                right.source_url.as_str(),
            ))
    });
    Ok(packages)
}

fn npm_local_locked_packages(project_dir: &Path) -> Result<Vec<LockedPackage>, OmcRegistryError> {
    let mut paths = npm_manifest_local_package_paths(project_dir)?;
    extend_npm_package_json_local_package_paths(project_dir, &mut paths)?;
    let mut packages = BTreeMap::new();
    let mut queue = VecDeque::from(paths);
    let mut seen = BTreeSet::new();
    while let Some(path) = queue.pop_front() {
        let key = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if !seen.insert(key) {
            continue;
        }
        if let Some((package, nested_paths)) = npm_local_locked_package(&path)? {
            queue.extend(nested_paths);
            packages.insert(package.name.clone(), package);
        }
    }
    Ok(packages.into_values().collect())
}

fn npm_manifest_local_package_paths(project_dir: &Path) -> Result<Vec<PathBuf>, OmcRegistryError> {
    let manifest = match read_manifest(project_dir.join("omc.toml")) {
        Ok(manifest) => manifest,
        Err(OmcRegistryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    Ok(manifest
        .npm_local_paths
        .into_iter()
        .chain(manifest.npm_dev_local_paths)
        .chain(manifest.npm_optional_local_paths)
        .chain(manifest.npm_peer_local_paths)
        .map(PathBuf::from)
        .map(|path| absolutize_path(project_dir, path))
        .collect())
}

fn extend_npm_package_json_local_package_paths(
    project_dir: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), OmcRegistryError> {
    collect_npm_package_json_local_package_paths(project_dir, paths)?;
    for workspace in read_npm_workspace_packages(project_dir)? {
        collect_npm_package_json_local_package_paths(&workspace.path, paths)?;
    }
    Ok(())
}


fn npm_package_json_local_directory_path(
    base_dir: &Path,
    requirement: &str,
) -> Result<Option<PathBuf>, OmcRegistryError> {
    let local = requirement.starts_with("file:")
        || requirement.starts_with("link:")
        || is_npm_local_directory_arg(requirement);
    if !local {
        return Ok(None);
    }
    let path = absolutize_path(base_dir, npm_local_path_arg(requirement)?);
    if path.join("package.json").exists() {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

fn npm_local_locked_package(
    path: &Path,
) -> Result<Option<(LockedPackage, Vec<PathBuf>)>, OmcRegistryError> {
    let package_json = path.join("package.json");
    if !package_json.exists() {
        return Ok(None);
    }
    let manifest = read_npm_pkg_json(&package_json)?;
    let name = npm_package_json_name(&manifest)?;
    let version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0.0.0")
        .to_owned();
    let source_url = reqwest::Url::from_directory_path(path)
        .map(|url| url.to_string())
        .unwrap_or_else(|_| format!("file:{}", path.display()));
    let mut nested_paths = Vec::new();
    collect_npm_package_json_local_package_paths(path, &mut nested_paths)?;
    Ok(Some((
        LockedPackage {
            ecosystem: Ecosystem::Npm,
            name,
            version,
            source_url,
            archive: String::new(),
            artifact: String::new(),
            sha256: String::new(),
            artifact_sha256: String::new(),
            behavior: Behavior::HostCapability,
            verdict: Verdict::Accepted,
            dependencies: npm_package_dependency_specs(&manifest, "dependencies"),
            optional_dependencies: npm_package_dependency_specs(&manifest, "optionalDependencies"),
            peer_dependencies: npm_package_dependency_specs(&manifest, "peerDependencies"),
            grants: Vec::new(),
            capabilities: Vec::new(),
            verifier_findings: Vec::new(),
        },
        nested_paths,
    )))
}

fn npm_package_dependency_specs(package: &serde_json::Value, field: &str) -> Vec<String> {
    package
        .get(field)
        .and_then(serde_json::Value::as_object)
        .map(|dependencies| {
            dependencies
                .iter()
                .map(|(name, requirement)| {
                    let requirement = requirement.as_str().unwrap_or("*");
                    format!("npm:{name}@{requirement}")
                })
                .collect()
        })
        .unwrap_or_default()
}

fn package_list_filter_names(
    filters: &[String],
    ecosystem: Option<Ecosystem>,
) -> Result<BTreeSet<String>, OmcRegistryError> {
    filters
        .iter()
        .map(|filter| parse_package_spec(filter, ecosystem).map(|spec| spec.name))
        .collect()
}

fn print_locked_freeze(
    project_dir: &Path,
    exclude: &[String],
    exclude_editable: bool,
    requirements: &[PathBuf],
) -> Result<(), OmcRegistryError> {
    let excluded = pip_excluded_names(exclude);
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let mut entries = Vec::new();
    for package in lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .filter(|package| !pip_name_excluded(&package.name, &excluded))
    {
        entries.push(PipFrozenRequirement {
            name: Some(normalize_pip_show_name(&package.name)),
            line: format!("{}=={}", package.name, package.version),
        });
    }
    for dependency in lock
        .python_vcs
        .iter()
        .filter(|dependency| !pip_name_excluded(&dependency.name, &excluded))
    {
        entries.push(PipFrozenRequirement {
            name: Some(normalize_pip_show_name(&dependency.name)),
            line: pip_freeze_vcs_requirement(dependency),
        });
    }
    if !exclude_editable {
        entries.extend(pip_freeze_local_path_entries(project_dir, &excluded)?);
    }
    print_pip_freeze_output(pip_freeze_output(project_dir, entries, requirements)?);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledPythonPackage {
    name: String,
    version: String,
    dependencies: Vec<String>,
    install_location: Option<PathBuf>,
    metadata_location: Option<PathBuf>,
    editable_project_location: Option<PathBuf>,
}

fn python_project_identity_file_exists(path: &Path) -> bool {
    path.join("pyproject.toml").exists()
        || path.join("setup.cfg").exists()
        || path.join("setup.py").exists()
}

fn read_python_project_identity(
    project_root: &Path,
) -> Result<Option<(String, String)>, OmcRegistryError> {
    let pyproject = project_root.join("pyproject.toml");
    if pyproject.exists() {
        if let Some(identity) = read_pyproject_identity(&pyproject)? {
            return Ok(Some(identity));
        }
    }

    let setup_cfg = project_root.join("setup.cfg");
    if setup_cfg.exists() {
        if let Some(identity) = read_setup_cfg_identity(&setup_cfg)? {
            return Ok(Some(identity));
        }
    }

    let setup_py = project_root.join("setup.py");
    if setup_py.exists() {
        if let Some(identity) = read_setup_py_identity(&setup_py)? {
            return Ok(Some(identity));
        }
    }

    Ok(None)
}

fn read_python_project_show_metadata(
    project_root: &Path,
) -> Result<PipShowMetadata, OmcRegistryError> {
    let pyproject = project_root.join("pyproject.toml");
    if pyproject.exists() {
        let metadata = read_pyproject_show_metadata(&pyproject)?;
        if !metadata.is_empty() {
            return Ok(metadata);
        }
    }

    let setup_cfg = project_root.join("setup.cfg");
    if setup_cfg.exists() {
        let metadata = read_setup_cfg_show_metadata(&setup_cfg)?;
        if !metadata.is_empty() {
            return Ok(metadata);
        }
    }

    let setup_py = project_root.join("setup.py");
    if setup_py.exists() {
        return read_setup_py_show_metadata(&setup_py);
    }

    Ok(PipShowMetadata::default())
}

fn read_pyproject_identity(path: &Path) -> Result<Option<(String, String)>, OmcRegistryError> {
    let pyproject = fs::read_to_string(path)?;
    let value = toml::from_str::<toml::Value>(&pyproject)?;
    if let Some(project) = value.get("project").and_then(|value| value.as_table()) {
        if let Some(identity) = python_project_identity_from_table(project) {
            return Ok(Some(identity));
        }
    }
    if let Some(poetry) = value
        .get("tool")
        .and_then(|value| value.get("poetry"))
        .and_then(|value| value.as_table())
    {
        if let Some(identity) = python_project_identity_from_table(poetry) {
            return Ok(Some(identity));
        }
    }
    Ok(None)
}

fn python_project_identity_from_table(
    table: &toml::map::Map<String, toml::Value>,
) -> Option<(String, String)> {
    let name = table.get("name").and_then(|value| value.as_str())?;
    let version = table
        .get("version")
        .and_then(|value| value.as_str())
        .unwrap_or("0.0.0");
    Some((name.to_owned(), version.to_owned()))
}

fn read_pyproject_show_metadata(path: &Path) -> Result<PipShowMetadata, OmcRegistryError> {
    let pyproject = fs::read_to_string(path)?;
    let value = toml::from_str::<toml::Value>(&pyproject)?;
    let Some(project) = value.get("project").and_then(|value| value.as_table()) else {
        return Ok(PipShowMetadata::default());
    };
    let requires_dist = project
        .get("dependencies")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let requires = requires_dist
        .iter()
        .filter_map(|requirement| pip_installed_dependency_name(requirement))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(PipShowMetadata {
        summary: project
            .get("description")
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        home_page: project
            .get("urls")
            .and_then(|value| value.as_table())
            .and_then(|urls| {
                urls.get("Homepage")
                    .or_else(|| urls.get("homepage"))
                    .or_else(|| urls.get("Home-page"))
            })
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        author: project
            .get("authors")
            .and_then(|value| value.as_array())
            .and_then(|authors| authors.first())
            .and_then(|author| author.get("name"))
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        author_email: project
            .get("authors")
            .and_then(|value| value.as_array())
            .and_then(|authors| authors.first())
            .and_then(|author| author.get("email"))
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        license: project
            .get("license")
            .and_then(python_project_license_value),
        requires,
        requires_dist,
    })
}

fn python_project_license_value(value: &toml::Value) -> Option<String> {
    if let Some(license) = value.as_str() {
        return Some(license.to_owned());
    }
    value
        .as_table()
        .and_then(|table| table.get("text").or_else(|| table.get("file")))
        .and_then(|value| value.as_str())
        .map(str::to_owned)
}

fn read_setup_cfg_identity(path: &Path) -> Result<Option<(String, String)>, OmcRegistryError> {
    let content = fs::read_to_string(path)?;
    let mut in_metadata = false;
    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_metadata = trimmed.eq_ignore_ascii_case("[metadata]");
            continue;
        }
        if !in_metadata
            || trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with(';')
        {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("name") {
            name = Some(value.to_owned());
        } else if key.eq_ignore_ascii_case("version") {
            version = Some(value.to_owned());
        }
    }
    Ok(name.map(|name| (name, version.unwrap_or_else(|| "0.0.0".to_owned()))))
}

fn read_setup_cfg_show_metadata(path: &Path) -> Result<PipShowMetadata, OmcRegistryError> {
    let content = fs::read_to_string(path)?;
    let mut section = String::new();
    let mut metadata = PipShowMetadata::default();
    let mut install_requires = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase();
            install_requires = false;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if section == "metadata" {
            if let Some((key, value)) = trimmed.split_once('=') {
                match key.trim().to_ascii_lowercase().as_str() {
                    "summary" | "description" => metadata.summary = Some(value.trim().to_owned()),
                    "home_page" | "home-page" | "url" => {
                        metadata.home_page = Some(value.trim().to_owned())
                    }
                    "author" => metadata.author = Some(value.trim().to_owned()),
                    "author_email" | "author-email" => {
                        metadata.author_email = Some(value.trim().to_owned())
                    }
                    "license" | "license_expression" | "license-expression" => {
                        metadata.license = Some(value.trim().to_owned())
                    }
                    _ => {}
                }
            }
        } else if section == "options" {
            if install_requires && (line.starts_with(' ') || line.starts_with('\t')) {
                push_pip_show_requirement(trimmed, &mut metadata);
            } else if let Some((key, value)) = trimmed.split_once('=') {
                install_requires = key.trim().eq_ignore_ascii_case("install_requires");
                if install_requires {
                    push_pip_show_requirement(value.trim(), &mut metadata);
                }
            } else if install_requires {
                push_pip_show_requirement(trimmed, &mut metadata);
            }
        }
    }
    metadata.requires.sort();
    metadata.requires.dedup();
    Ok(metadata)
}

fn read_setup_py_identity(path: &Path) -> Result<Option<(String, String)>, OmcRegistryError> {
    let content = fs::read_to_string(path)?;
    let Some(name) = setup_py_string_arg(&content, "name") else {
        return Ok(None);
    };
    let version = setup_py_string_arg(&content, "version").unwrap_or_else(|| "0.0.0".to_owned());
    Ok(Some((name, version)))
}

fn read_setup_py_show_metadata(path: &Path) -> Result<PipShowMetadata, OmcRegistryError> {
    let content = fs::read_to_string(path)?;
    Ok(PipShowMetadata {
        summary: setup_py_string_arg(&content, "description"),
        home_page: setup_py_string_arg(&content, "url"),
        author: setup_py_string_arg(&content, "author"),
        author_email: setup_py_string_arg(&content, "author_email"),
        license: setup_py_string_arg(&content, "license"),
        requires: setup_py_install_requires(&content)
            .iter()
            .filter_map(|requirement| pip_installed_dependency_name(requirement))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        requires_dist: setup_py_install_requires(&content),
    })
}

fn setup_py_install_requires(content: &str) -> Vec<String> {
    let Some(start) = content.find("install_requires") else {
        return Vec::new();
    };
    let Some(list_start) = content[start..].find('[').map(|offset| start + offset + 1) else {
        return Vec::new();
    };
    let Some(list_end) = content[list_start..]
        .find(']')
        .map(|offset| list_start + offset)
    else {
        return Vec::new();
    };
    let mut requires = Vec::new();
    for item in content[list_start..list_end].split(',') {
        let requirement = item.trim().trim_matches('"').trim_matches('\'');
        if !requirement.is_empty() {
            requires.push(requirement.to_owned());
        }
    }
    requires.sort();
    requires.dedup();
    requires
}

fn setup_py_string_arg(content: &str, arg: &str) -> Option<String> {
    let pattern = format!("{arg}=");
    for (offset, _) in content.match_indices(&pattern) {
        let value = content[offset + pattern.len()..].trim_start();
        let quote = value.chars().next()?;
        if quote != '\'' && quote != '"' {
            continue;
        }
        let mut parsed = String::new();
        let mut escaped = false;
        for ch in value[quote.len_utf8()..].chars() {
            if escaped {
                parsed.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                return Some(parsed);
            } else {
                parsed.push(ch);
            }
        }
    }
    None
}

fn sort_installed_python_packages(packages: &mut [InstalledPythonPackage]) {
    packages.sort_by(|left, right| {
        normalize_pip_show_name(&left.name).cmp(&normalize_pip_show_name(&right.name))
    });
}

fn merge_installed_python_package(
    packages: &mut BTreeMap<String, InstalledPythonPackage>,
    package: InstalledPythonPackage,
) {
    packages.insert(normalize_pip_show_name(&package.name), package);
}

fn merge_installed_python_packages(
    packages: Vec<InstalledPythonPackage>,
) -> Vec<InstalledPythonPackage> {
    let mut merged = BTreeMap::new();
    for package in packages {
        merge_installed_python_package(&mut merged, package);
    }
    merged.into_values().collect()
}

fn read_site_packages_metadata(
    site_packages: &Path,
) -> Result<Vec<InstalledPythonPackage>, OmcRegistryError> {
    if !site_packages.exists() {
        return Ok(Vec::new());
    }
    let mut packages = Vec::new();
    for entry in fs::read_dir(site_packages)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.ends_with(".dist-info") {
            continue;
        }
        if let Some(package) = read_dist_info_metadata(&entry.path(), &name)? {
            packages.push(package);
        }
    }
    packages.sort_by(|left, right| {
        normalize_pip_show_name(&left.name).cmp(&normalize_pip_show_name(&right.name))
    });
    Ok(packages)
}

fn read_dist_info_metadata(
    dist_info: &Path,
    dist_info_name: &str,
) -> Result<Option<InstalledPythonPackage>, OmcRegistryError> {
    let metadata = dist_info.join("METADATA");
    if metadata.exists() {
        let metadata = fs::read_to_string(metadata)?;
        let mut name = None;
        let mut version = None;
        let mut dependencies = Vec::new();
        for line in pip_metadata_lines(&metadata) {
            if let Some(value) = line.strip_prefix("Name:") {
                name = Some(value.trim().to_owned());
            } else if let Some(value) = line.strip_prefix("Version:") {
                version = Some(value.trim().to_owned());
            } else if let Some(value) = line.strip_prefix("Requires-Dist:") {
                dependencies.push(value.trim().to_owned());
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            return Ok(Some(InstalledPythonPackage {
                name,
                version,
                dependencies,
                install_location: dist_info.parent().map(Path::to_path_buf),
                metadata_location: Some(dist_info.to_path_buf()),
                editable_project_location: None,
            }));
        }
    }

    let Some(stem) = dist_info_name.strip_suffix(".dist-info") else {
        return Ok(None);
    };
    let Some((name, version)) = stem.rsplit_once('-') else {
        return Ok(None);
    };
    Ok(Some(InstalledPythonPackage {
        name: name.replace('_', "-"),
        version: version.to_owned(),
        dependencies: Vec::new(),
        install_location: dist_info.parent().map(Path::to_path_buf),
        metadata_location: Some(dist_info.to_path_buf()),
        editable_project_location: None,
    }))
}

fn match_dist_info_dir(
    site_packages: &Path,
    package: &LockedPackage,
) -> Result<Option<PathBuf>, OmcRegistryError> {
    if !site_packages.exists() {
        return Ok(None);
    }
    let prefix = format!(
        "{}-{}",
        normalize_pip_show_name(&package.name),
        normalize_pip_show_name(&package.version)
    );
    for entry in fs::read_dir(site_packages)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.ends_with(".dist-info") && normalize_pip_show_name(&name).starts_with(&prefix) {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn absolutize_paths(project_dir: &Path, paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .map(|path| absolutize_path(project_dir, path))
        .collect()
}

fn absolutize_python_local_requirements(
    project_dir: &Path,
    requirements: Vec<PythonLocalRequirement>,
) -> Vec<PythonLocalRequirement> {
    requirements
        .into_iter()
        .map(|requirement| {
            PythonLocalRequirement::new(
                absolutize_path(project_dir, requirement.path),
                requirement.extras,
            )
        })
        .collect()
}

pub(crate) fn absolutize_path(project_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        project_dir.join(path)
    }
}

fn project_dir_for_user_paths(project_dir: &Path) -> PathBuf {
    if project_dir.is_absolute() {
        project_dir.to_path_buf()
    } else {
        env::current_dir()
            .map(|cwd| cwd.join(project_dir))
            .unwrap_or_else(|_| project_dir.to_path_buf())
    }
}

fn absolute_project_dir(project_dir: &Path) -> PathBuf {
    if let Ok(path) = fs::canonicalize(project_dir) {
        return path;
    }
    if project_dir.is_absolute() {
        return project_dir.to_path_buf();
    }
    env::current_dir()
        .map(|cwd| cwd.join(project_dir))
        .unwrap_or_else(|_| project_dir.to_path_buf())
}

pub(crate) fn apply_project_runtime_env_for_cwd(
    command: &mut ProcessCommand,
    project_dir: &Path,
    cwd: &Path,
) -> Result<(), OmcRegistryError> {
    command
        .current_dir(cwd)
        .env("PATH", project_path_for_cwd(project_dir, cwd)?)
        .env("PYTHONPATH", project_python_path(project_dir)?)
        .env("PYTHONNOUSERSITE", "1")
        .env(
            "NODE_OPTIONS",
            "--preserve-symlinks --preserve-symlinks-main",
        )
        .env_remove("NODE_PATH");
    for key in [
        "PYTHONBREAKPOINT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONSTARTUP",
    ] {
        command.env_remove(key);
    }
    Ok(())
}

pub(crate) fn apply_npm_lifecycle_env(
    command: &mut ProcessCommand,
    project_dir: &Path,
    npm_command: &str,
    script_name: &str,
    script: &str,
) -> Result<(), OmcRegistryError> {
    for (key, value) in npm_lifecycle_env(project_dir, npm_command, script_name, script)? {
        command.env(key, value);
    }
    Ok(())
}

fn npm_lifecycle_env(
    project_dir: &Path,
    npm_command: &str,
    script_name: &str,
    script: &str,
) -> Result<BTreeMap<String, String>, OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let init_cwd = env::current_dir().unwrap_or_else(|_| project_dir.clone());
    let mut vars = BTreeMap::from([
        (
            "INIT_CWD".to_owned(),
            init_cwd.to_string_lossy().into_owned(),
        ),
        ("npm_command".to_owned(), npm_command.to_owned()),
        (
            "npm_config_local_prefix".to_owned(),
            project_dir.to_string_lossy().into_owned(),
        ),
        (
            "npm_config_npm_version".to_owned(),
            env!("CARGO_PKG_VERSION").to_owned(),
        ),
        ("npm_config_user_agent".to_owned(), omc_npm_user_agent()),
        ("npm_lifecycle_event".to_owned(), script_name.to_owned()),
        ("npm_lifecycle_script".to_owned(), script.to_owned()),
    ]);

    if let Ok(exe) = env::current_exe() {
        vars.insert(
            "npm_execpath".to_owned(),
            exe.to_string_lossy().into_owned(),
        );
    }
    if let Some(node) = find_program_on_path("node") {
        vars.insert(
            "npm_node_execpath".to_owned(),
            node.to_string_lossy().into_owned(),
        );
    }

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        vars.insert(
            "npm_package_json".to_owned(),
            package_json.to_string_lossy().into_owned(),
        );
        let package =
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(package_json)?)?;
        if let Some(name) = package.get("name").and_then(serde_json::Value::as_str) {
            vars.insert("npm_package_name".to_owned(), name.to_owned());
        }
        if let Some(version) = package.get("version").and_then(serde_json::Value::as_str) {
            vars.insert("npm_package_version".to_owned(), version.to_owned());
        }
        collect_npm_package_bin_env(&package, &mut vars);
        if let Some(config) = package.get("config") {
            collect_npm_package_config_env("npm_package_config", config, &mut vars);
        }
    }

    Ok(vars)
}

fn omc_npm_user_agent() -> String {
    format!(
        "omc/{} {} {} workspaces/false",
        env!("CARGO_PKG_VERSION"),
        env::consts::OS,
        env::consts::ARCH
    )
}

fn find_program_on_path(program: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn find_program_outside_current_exe_dir(program: &str) -> Option<PathBuf> {
    let current_exe = env::current_exe().ok().and_then(canonicalize_path);
    let current_exe_dir = current_exe
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(program);
        if !candidate.is_file() {
            continue;
        }
        let normalized = canonicalize_path(candidate.clone()).unwrap_or_else(|| candidate.clone());
        if current_exe
            .as_ref()
            .is_some_and(|current| current == &normalized)
        {
            continue;
        }
        if current_exe_dir
            .as_ref()
            .is_some_and(|current_dir| normalized.parent() == Some(current_dir.as_path()))
        {
            continue;
        }
        return Some(candidate);
    }
    None
}

fn canonicalize_path(path: PathBuf) -> Option<PathBuf> {
    path.canonicalize().ok()
}


fn npm_package_bin_name(package_name: &str) -> &str {
    package_name
        .rsplit_once('/')
        .map_or(package_name, |(_, name)| name)
}

fn npm_create_package_spec(initializer: &str) -> Result<String, OmcRegistryError> {
    let initializer = initializer.trim();
    if initializer.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm create needs an initializer package".to_owned(),
        ));
    }

    let (name, version) = npm_create_split_version(initializer)?;
    let package = if let Some(scoped) = name.strip_prefix('@') {
        if scoped.is_empty() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "invalid npm create initializer `{initializer}`"
            )));
        }
        if let Some((scope, package)) = scoped.split_once('/') {
            if scope.is_empty() || package.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "invalid npm create initializer `{initializer}`"
                )));
            }
            format!("@{scope}/create-{package}")
        } else {
            format!("@{scoped}/create")
        }
    } else {
        format!("create-{name}")
    };

    Ok(match version {
        Some(version) => format!("{package}@{version}"),
        None => package,
    })
}

fn npm_create_split_version(initializer: &str) -> Result<(&str, Option<&str>), OmcRegistryError> {
    let version_at = if let Some(scoped) = initializer.strip_prefix('@') {
        if let Some(slash_index) = scoped.find('/') {
            let absolute_slash_index = slash_index + 1;
            initializer
                .rfind('@')
                .filter(|index| *index > absolute_slash_index)
        } else {
            initializer.rfind('@').filter(|index| *index > 0)
        }
    } else {
        initializer.rfind('@').filter(|index| *index > 0)
    };

    let (name, version) = match version_at {
        Some(index) => (&initializer[..index], Some(&initializer[index + 1..])),
        None => (initializer, None),
    };
    if name.is_empty() || version == Some("") {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm create initializer `{initializer}`"
        )));
    }
    Ok((name, version))
}

fn npm_create_bin_name(project_dir: &Path, package_name: &str) -> Result<String, OmcRegistryError> {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    let default = npm_package_bin_name(package_name).to_owned();
    if bin_dir.join(&default).exists() {
        return Ok(default);
    }

    let bins = npm_create_bin_names(&bin_dir)?;
    match bins.as_slice() {
        [bin] => Ok(bin.clone()),
        [] => Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm create initializer `{package_name}` did not install an executable bin"
        ))),
        _ => Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm create initializer `{package_name}` installed multiple bins: {}",
            bins.join(", ")
        ))),
    }
}

fn npm_create_bin_names(bin_dir: &Path) -> Result<Vec<String>, OmcRegistryError> {
    let entries = match fs::read_dir(bin_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.path().is_dir() {
            continue;
        }
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    names.dedup();
    Ok(names)
}


fn npm_package_env_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn project_path_for_cwd(project_dir: &Path, cwd: &Path) -> Result<OsString, OmcRegistryError> {
    let mut paths = vec![
        cwd.join("node_modules").join(".bin"),
        project_dir.join("node_modules").join(".bin"),
        project_dir.join(".omc").join("python").join("bin"),
    ];
    if let Ok(user_paths) = pip_user_paths() {
        let user_source_bin = user_paths.site_packages.join("bin");
        if user_source_bin.exists() {
            paths.push(user_source_bin);
        }
    }
    paths.dedup();
    if let Some(existing) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing));
    }
    env::join_paths(paths).map_err(|error| OmcRegistryError::UnsupportedSpec(error.to_string()))
}

fn project_python_path(project_dir: &Path) -> Result<OsString, OmcRegistryError> {
    let mut paths = vec![project_dir
        .join(".omc")
        .join("python")
        .join("site-packages")];
    extend_python_path_file(
        &mut paths,
        &project_dir.join(".omc").join("python").join("local-paths"),
    )?;
    extend_python_path_env(&mut paths)?;
    if let Ok(user_paths) = pip_user_paths() {
        if user_paths.state_project.exists() {
            paths.push(user_paths.site_packages.clone());
            extend_python_path_file(&mut paths, &pip_user_install_local_paths_file(&user_paths)?)?;
            extend_python_path_file(
                &mut paths,
                &user_paths.site_packages.join(".omc-local-paths"),
            )?;
        }
    }
    dedup_paths(&mut paths);
    env::join_paths(paths).map_err(|error| OmcRegistryError::UnsupportedSpec(error.to_string()))
}

fn extend_python_path_env(paths: &mut Vec<PathBuf>) -> Result<(), OmcRegistryError> {
    let Some(existing) = env::var_os("PYTHONPATH") else {
        return Ok(());
    };
    for path in env::split_paths(&existing) {
        paths.push(path.clone());
        extend_python_path_file(paths, &path.join(".omc-local-paths"))?;
        if path.file_name().and_then(|name| name.to_str()) == Some("site-packages") {
            if let Some(parent) = path.parent() {
                extend_python_path_file(paths, &parent.join("local-paths"))?;
            }
        }
    }
    Ok(())
}

fn extend_python_path_file(
    paths: &mut Vec<PathBuf>,
    local_paths_file: &Path,
) -> Result<(), OmcRegistryError> {
    match fs::read_to_string(local_paths_file) {
        Ok(content) => {
            paths.extend(
                content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(PathBuf::from),
            );
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = BTreeSet::new();
    paths.retain(|path| seen.insert(path.clone()));
}

#[cfg(unix)]
pub(crate) fn package_script_command(script: &str) -> ProcessCommand {
    let mut command = ProcessCommand::new("sh");
    command
        .arg("-c")
        .arg(format!("{script} \"$@\""))
        .arg("omc-script");
    command
}

#[cfg(not(unix))]
pub(crate) fn package_script_command(script: &str) -> ProcessCommand {
    let mut command = ProcessCommand::new("cmd");
    command.arg("/C").arg(script);
    command
}

pub(crate) fn exit_code(code: Option<i32>) -> ExitCode {
    code.and_then(|code| u8::try_from(code).ok())
        .map(ExitCode::from)
        .unwrap_or(ExitCode::FAILURE)
}



fn npm_help_flag(arg: &str) -> bool {
    matches!(arg, "--help" | "-h")
}

fn normalize_npm_global_args(args: &[String]) -> Result<Vec<String>, OmcRegistryError> {
    let mut preserved = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--version" | "-v") {
            return Ok(vec![arg.clone()]);
        } else if npm_global_preserved_bool_flag(arg) {
            preserved.push(arg.clone());
        } else if npm_global_preserved_value_flag(arg) {
            preserved.push(arg.clone());
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            preserved.push(value.clone());
        } else if npm_global_preserved_equals_flag(arg) {
            preserved.push(arg.clone());
        } else if npm_global_ignored_bool_flag(arg) || npm_global_ignored_equals_flag(arg) {
        } else if npm_global_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with('-') {
            return Ok(args[index..].to_vec());
        } else {
            if preserved.is_empty() && index == 0 {
                return Ok(args.to_vec());
            }
            let preserved = npm_preserved_global_args_for_command(arg, preserved);
            let mut normalized = Vec::with_capacity(args.len());
            normalized.push(arg.clone());
            normalized.extend(preserved);
            normalized.extend(args[index + 1..].iter().cloned());
            return Ok(normalized);
        }
        index += 1;
    }

    if preserved.is_empty() {
        Ok(Vec::new())
    } else {
        let preserved = npm_preserved_global_args_for_command("install", preserved);
        let mut normalized = Vec::with_capacity(preserved.len() + 1);
        normalized.push("install".to_owned());
        normalized.extend(preserved);
        Ok(normalized)
    }
}

fn npm_preserved_global_args_for_command(command: &str, args: Vec<String>) -> Vec<String> {
    let mut selected = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let include = npm_global_arg_supported_by_command(command, arg);
        if include {
            selected.push(arg.clone());
        }
        if npm_global_preserved_value_flag(arg) {
            index += 1;
            if include {
                if let Some(value) = args.get(index) {
                    selected.push(value.clone());
                }
            }
        }
        index += 1;
    }
    selected
}

fn npm_global_arg_supported_by_command(command: &str, arg: &str) -> bool {
    if matches!(arg, "--global" | "-g") || arg.starts_with("--global=") {
        return true;
    }
    if matches!(arg, "--location") || arg.starts_with("--location=") {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "link"
                | "ln"
                | "remove"
                | "uninstall"
                | "unlink"
                | "rm"
                | "r"
                | "un"
                | "bin"
                | "root"
                | "prefix"
                | "config"
                | "c"
                | "get"
        );
    }
    if matches!(arg, "--registry") || arg.starts_with("--registry=") {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "link"
                | "ln"
                | "install-test"
                | "it"
                | "exec"
                | "x"
                | "npx"
                | "explore"
                | "edit"
                | "init"
                | "create"
                | "innit"
                | "ci"
                | "doctor"
                | "outdated"
                | "pack"
                | "publish"
                | "unpublish"
                | "deprecate"
                | "undeprecate"
                | "diff"
                | "search"
                | "s"
                | "se"
                | "find"
                | "star"
                | "unstar"
                | "stars"
                | "ping"
                | "whoami"
                | "login"
                | "adduser"
                | "add-user"
                | "logout"
                | "token"
                | "trust"
                | "profile"
                | "owner"
                | "access"
                | "org"
                | "team"
                | "dist-tag"
                | "dist-tags"
                | "sbom"
                | "view"
                | "info"
                | "show"
                | "v"
                | "config"
                | "c"
                | "get"
        );
    }
    if matches!(arg, "--shell") || arg.starts_with("--shell=") {
        return command == "explore";
    }
    if matches!(arg, "--editor") || arg.starts_with("--editor=") {
        return matches!(command, "edit" | "config" | "c");
    }
    if matches!(arg, "--otp") || arg.starts_with("--otp=") {
        return matches!(
            command,
            "login"
                | "adduser"
                | "add-user"
                | "publish"
                | "unpublish"
                | "deprecate"
                | "undeprecate"
                | "diff"
                | "star"
                | "unstar"
                | "trust"
                | "token"
                | "exec"
                | "x"
                | "npx"
                | "profile"
                | "owner"
                | "access"
                | "org"
                | "team"
                | "dist-tag"
                | "dist-tags"
        );
    }
    if matches!(
        arg,
        "--read-only"
            | "--no-read-only"
            | "--packages-all"
            | "--no-packages-all"
            | "--bypass-2fa"
            | "--no-bypass-2fa"
    ) || arg.starts_with("--read-only=")
        || arg.starts_with("--packages-all=")
        || arg.starts_with("--bypass-2fa=")
    {
        return matches!(command, "token");
    }
    if matches!(
        arg,
        "--save"
            | "-S"
            | "--save-prod"
            | "-P"
            | "--no-save-prod"
            | "-D"
            | "--save-dev"
            | "--dev"
            | "--no-save-dev"
            | "--no-dev"
            | "--save-optional"
            | "-O"
            | "--no-save-optional"
            | "--save-peer"
            | "--no-save-peer"
            | "--save-bundle"
            | "--save-bundled"
            | "-B"
            | "--no-save-bundle"
            | "--no-save-bundled"
            | "--no-save"
            | "--save-exact"
            | "-E"
    ) || arg.starts_with("--save-exact=")
        || arg.starts_with("--save-prod=")
        || arg.starts_with("--save-dev=")
        || arg.starts_with("--dev=")
        || arg.starts_with("--save-optional=")
        || arg.starts_with("--save-peer=")
        || arg.starts_with("--save-bundle=")
        || arg.starts_with("--save-bundled=")
    {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "link"
                | "ln"
        );
    }
    if matches!(arg, "--save-prefix") || arg.starts_with("--save-prefix=") {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "link"
                | "ln"
        );
    }
    if matches!(
        arg,
        "--name"
            | "--token-description"
            | "--expires"
            | "--packages"
            | "--scopes"
            | "--orgs"
            | "--packages-and-scopes-permission"
            | "--orgs-permission"
            | "--cidr"
            | "--password"
    ) || arg.starts_with("--name=")
        || arg.starts_with("--token-description=")
        || arg.starts_with("--expires=")
        || arg.starts_with("--packages=")
        || arg.starts_with("--scopes=")
        || arg.starts_with("--orgs=")
        || arg.starts_with("--packages-and-scopes-permission=")
        || arg.starts_with("--orgs-permission=")
        || arg.starts_with("--cidr=")
        || arg.starts_with("--password=")
    {
        return matches!(command, "token");
    }
    if matches!(arg, "--auth-type") || arg.starts_with("--auth-type=") {
        return matches!(command, "login" | "adduser" | "add-user");
    }
    if matches!(arg, "--token" | "--auth-token")
        || arg.starts_with("--token=")
        || arg.starts_with("--auth-token=")
    {
        return matches!(command, "login" | "adduser" | "add-user");
    }
    if matches!(arg, "--scope") || arg.starts_with("--scope=") {
        return matches!(command, "login" | "adduser" | "add-user" | "logout");
    }
    if matches!(arg, "--tag") || arg.starts_with("--tag=") {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "publish"
                | "dist-tag"
                | "dist-tags"
        );
    }
    if matches!(arg, "--before") || arg.starts_with("--before=") {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
        );
    }
    if matches!(arg, "--min-release-age") || arg.starts_with("--min-release-age=") {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
        );
    }
    if matches!(arg, "--engine-strict" | "--no-engine-strict")
        || arg.starts_with("--engine-strict=")
    {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
                | "install-ci-test"
                | "cit"
                | "ci"
        );
    }
    if matches!(arg, "--offline" | "--no-offline") || arg.starts_with("--offline=") {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
                | "install-ci-test"
                | "cit"
                | "ci"
        );
    }
    if matches!(arg, "--access" | "--provenance-file")
        || arg.starts_with("--access=")
        || arg.starts_with("--provenance-file=")
    {
        return matches!(command, "publish" | "dist-tag" | "dist-tags");
    }
    if matches!(arg, "--install-links" | "--no-install-links")
        || arg.starts_with("--install-links=")
    {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "link"
                | "ln"
        );
    }
    if matches!(
        arg,
        "--dry-run" | "--no-dry-run" | "--provenance" | "--no-provenance"
    ) || arg.starts_with("--dry-run=")
        || arg.starts_with("--provenance=")
    {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
                | "ci"
                | "install-ci-test"
                | "cit"
                | "publish"
                | "unpublish"
                | "deprecate"
                | "undeprecate"
                | "link"
                | "ln"
                | "shrinkwrap"
                | "trust"
        );
    }
    if matches!(
        arg,
        "--yes"
            | "-y"
            | "--no-yes"
            | "--file"
            | "--repo"
            | "--repository"
            | "--project"
            | "--env"
            | "--environment"
            | "--org-id"
            | "--project-id"
            | "--pipeline-definition-id"
            | "--vcs-origin"
            | "--context-id"
            | "--id"
    ) || arg.starts_with("--yes=")
        || arg.starts_with("--file=")
        || arg.starts_with("--repo=")
        || arg.starts_with("--repository=")
        || arg.starts_with("--project=")
        || arg.starts_with("--env=")
        || arg.starts_with("--environment=")
        || arg.starts_with("--org-id=")
        || arg.starts_with("--project-id=")
        || arg.starts_with("--pipeline-definition-id=")
        || arg.starts_with("--vcs-origin=")
        || arg.starts_with("--context-id=")
        || arg.starts_with("--id=")
    {
        return matches!(command, "trust");
    }
    if matches!(arg, "--force" | "-f") || arg.starts_with("--force=") {
        return matches!(command, "cache" | "unpublish");
    }
    if matches!(arg, "--cache") || arg.starts_with("--cache=") {
        return command == "cache";
    }
    if matches!(arg, "--long" | "-l") || arg.starts_with("--long=") {
        return matches!(command, "help-search" | "search" | "s" | "se" | "find");
    }
    if matches!(arg, "--sbom-format" | "--sbom-type")
        || arg.starts_with("--sbom-format=")
        || arg.starts_with("--sbom-type=")
    {
        return matches!(command, "sbom");
    }
    if matches!(
        arg,
        "--diff"
            | "--diff-unified"
            | "--diff-src-prefix"
            | "--diff-dst-prefix"
            | "--diff-name-only"
            | "--diff-ignore-all-space"
            | "--diff-no-prefix"
            | "--diff-text"
    ) || arg.starts_with("--diff=")
        || arg.starts_with("--diff-unified=")
        || arg.starts_with("--diff-src-prefix=")
        || arg.starts_with("--diff-dst-prefix=")
        || arg.starts_with("--diff-name-only=")
        || arg.starts_with("--diff-ignore-all-space=")
        || arg.starts_with("--diff-no-prefix=")
        || arg.starts_with("--diff-text=")
    {
        return matches!(command, "diff");
    }
    if matches!(arg, "--package-lock-only") || arg.starts_with("--package-lock-only=") {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
                | "link"
                | "ln"
                | "sbom"
                | "query"
        );
    }
    if matches!(arg, "--expect-results" | "--no-expect-results")
        || arg.starts_with("--expect-results=")
    {
        return matches!(command, "query");
    }
    if matches!(arg, "--expect-result-count") || arg.starts_with("--expect-result-count=") {
        return matches!(command, "query");
    }
    if matches!(arg, "--userconfig") || arg.starts_with("--userconfig=") {
        return matches!(
            command,
            "config"
                | "c"
                | "get"
                | "ping"
                | "whoami"
                | "login"
                | "adduser"
                | "add-user"
                | "publish"
                | "unpublish"
                | "deprecate"
                | "undeprecate"
                | "diff"
                | "star"
                | "unstar"
                | "stars"
                | "logout"
                | "trust"
                | "token"
                | "profile"
                | "owner"
                | "access"
                | "org"
                | "team"
                | "dist-tag"
                | "dist-tags"
        );
    }
    if matches!(arg, "--workspace" | "-w")
        || arg.starts_with("--workspace=")
        || arg.starts_with("-w=")
        || (npm_attached_short_value(arg, 'w').is_some()
            && npm_all_workspaces_flag_value(arg).is_none())
    {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
                | "install-ci-test"
                | "cit"
                | "ci"
                | "run"
                | "run-script"
                | "exec"
                | "x"
                | "npx"
                | "test"
                | "start"
                | "stop"
                | "restart"
                | "fund"
                | "owner"
                | "unpublish"
                | "publish"
                | "dist-tag"
                | "dist-tags"
                | "remove"
                | "uninstall"
                | "unlink"
                | "rm"
                | "r"
                | "un"
                | "sbom"
                | "query"
                | "shrinkwrap"
        );
    }
    if npm_all_workspaces_flag_value(arg).is_some()
        || npm_include_workspace_root_flag_value(arg).is_some()
        || arg.starts_with("--workspaces=")
        || arg.starts_with("--ws=")
        || arg.starts_with("--include-workspace-root=")
    {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "install-test"
                | "it"
                | "install-ci-test"
                | "cit"
                | "ci"
                | "run"
                | "run-script"
                | "exec"
                | "x"
                | "npx"
                | "test"
                | "start"
                | "stop"
                | "restart"
                | "fund"
                | "owner"
                | "unpublish"
                | "publish"
                | "dist-tag"
                | "dist-tags"
                | "remove"
                | "uninstall"
                | "unlink"
                | "rm"
                | "r"
                | "un"
                | "sbom"
                | "query"
                | "shrinkwrap"
        );
    }
    if npm_json_flag_value(arg).is_some() {
        return matches!(
            command,
            "install"
                | "i"
                | "in"
                | "ins"
                | "inst"
                | "insta"
                | "instal"
                | "isnt"
                | "isnta"
                | "isntal"
                | "isntall"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "ci"
                | "version"
                | "run"
                | "run-script"
                | "list"
                | "ls"
                | "ll"
                | "la"
                | "query"
                | "explain"
                | "why"
                | "outdated"
                | "audit"
                | "fund"
                | "pkg"
                | "pack"
                | "publish"
                | "unpublish"
                | "deprecate"
                | "undeprecate"
                | "diff"
                | "search"
                | "s"
                | "se"
                | "find"
                | "star"
                | "unstar"
                | "stars"
                | "ping"
                | "whoami"
                | "login"
                | "adduser"
                | "add-user"
                | "logout"
                | "trust"
                | "token"
                | "profile"
                | "owner"
                | "access"
                | "org"
                | "team"
                | "dist-tag"
                | "dist-tags"
                | "view"
                | "sbom"
                | "info"
                | "show"
                | "v"
                | "config"
                | "c"
                | "get"
        );
    }
    if matches!(arg, "--parseable" | "-p") || arg.starts_with("--parseable=") {
        return matches!(command, "profile" | "org" | "team");
    }
    if matches!(arg, "--depth") || arg.starts_with("--depth=") {
        return matches!(command, "list" | "ls" | "ll" | "la" | "outdated");
    }
    if matches!(arg, "--searchlimit" | "--limit")
        || arg.starts_with("--searchlimit=")
        || arg.starts_with("--limit=")
    {
        return matches!(command, "search" | "s" | "se" | "find");
    }
    if matches!(arg, "--omit" | "--include")
        || arg.starts_with("--omit=")
        || arg.starts_with("--include=")
    {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "udpate"
                | "link"
                | "ln"
                | "install-test"
                | "it"
                | "ci"
                | "install-ci-test"
                | "cit"
                | "prune"
                | "dedupe"
                | "ddp"
                | "find-dupes"
                | "rebuild"
                | "rb"
                | "list"
                | "ls"
                | "ll"
                | "la"
                | "outdated"
                | "sbom"
        );
    }
    false
}

fn npm_global_preserved_bool_flag(arg: &str) -> bool {
    if npm_workspace_scope_ignored_flag(arg) {
        return true;
    }

    matches!(
        arg,
        "--json"
            | "-j"
            | "--no-json"
            | "--global"
            | "-g"
            | "--dry-run"
            | "--no-dry-run"
            | "--force"
            | "-f"
            | "--provenance"
            | "--no-provenance"
            | "--read-only"
            | "--no-read-only"
            | "--save"
            | "-S"
            | "--save-prod"
            | "-P"
            | "--no-save-prod"
            | "--save-dev"
            | "--dev"
            | "--no-save-dev"
            | "--no-dev"
            | "--save-optional"
            | "-O"
            | "--no-save-optional"
            | "--save-peer"
            | "--no-save-peer"
            | "--save-bundle"
            | "--save-bundled"
            | "-B"
            | "--no-save-bundle"
            | "--no-save-bundled"
            | "--no-save"
            | "--save-exact"
            | "-E"
            | "--packages-all"
            | "--no-packages-all"
            | "--bypass-2fa"
            | "--no-bypass-2fa"
            | "--parseable"
            | "-p"
            | "--workspaces"
            | "--include-workspace-root"
            | "--package-lock-only"
            | "--engine-strict"
            | "--no-engine-strict"
            | "--offline"
            | "--no-offline"
            | "--install-links"
            | "--no-install-links"
            | "--long"
            | "-l"
            | "--expect-results"
            | "--no-expect-results"
            | "--diff-name-only"
            | "--diff-ignore-all-space"
            | "--diff-no-prefix"
            | "--diff-text"
    )
}

fn npm_global_preserved_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--registry"
            | "--userconfig"
            | "--depth"
            | "--omit"
            | "--include"
            | "--save-prefix"
            | "--searchlimit"
            | "--limit"
            | "--workspace"
            | "-w"
            | "--otp"
            | "--auth-type"
            | "--shell"
            | "--editor"
            | "--token"
            | "--auth-token"
            | "--tag"
            | "--before"
            | "--min-release-age"
            | "--access"
            | "--provenance-file"
            | "--scope"
            | "--name"
            | "--token-description"
            | "--expires"
            | "--packages"
            | "--scopes"
            | "--orgs"
            | "--packages-and-scopes-permission"
            | "--orgs-permission"
            | "--cidr"
            | "--password"
            | "--sbom-format"
            | "--sbom-type"
            | "--location"
            | "--expect-result-count"
            | "--cache"
            | "--diff"
            | "--diff-unified"
            | "--diff-src-prefix"
            | "--diff-dst-prefix"
            | "--id"
            | "--file"
            | "--repo"
            | "--repository"
            | "--project"
            | "--env"
            | "--environment"
            | "--org-id"
            | "--project-id"
            | "--pipeline-definition-id"
            | "--vcs-origin"
            | "--context-id"
    )
}

fn npm_global_preserved_equals_flag(arg: &str) -> bool {
    if npm_all_workspaces_flag_value(arg).is_some()
        || (npm_attached_short_value(arg, 'w').is_some()
            && npm_all_workspaces_flag_value(arg).is_none())
    {
        return true;
    }

    [
        "--registry=",
        "--json=",
        "--userconfig=",
        "--depth=",
        "--omit=",
        "--include=",
        "--save-exact=",
        "--save-prod=",
        "--save-dev=",
        "--dev=",
        "--save-optional=",
        "--save-peer=",
        "--save-bundle=",
        "--save-bundled=",
        "--save-prefix=",
        "--searchlimit=",
        "--limit=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
        "--install-links=",
        "--engine-strict=",
        "--offline=",
        "--otp=",
        "--auth-type=",
        "--shell=",
        "--editor=",
        "--token=",
        "--auth-token=",
        "--tag=",
        "--before=",
        "--min-release-age=",
        "--access=",
        "--dry-run=",
        "--force=",
        "--long=",
        "--provenance=",
        "--provenance-file=",
        "--scope=",
        "--read-only=",
        "--packages-all=",
        "--bypass-2fa=",
        "--parseable=",
        "--name=",
        "--token-description=",
        "--expires=",
        "--packages=",
        "--scopes=",
        "--orgs=",
        "--packages-and-scopes-permission=",
        "--orgs-permission=",
        "--cidr=",
        "--password=",
        "--sbom-format=",
        "--sbom-type=",
        "--location=",
        "--cache=",
        "--package-lock-only=",
        "--global=",
        "--expect-results=",
        "--expect-result-count=",
        "--diff=",
        "--diff-unified=",
        "--diff-name-only=",
        "--diff-ignore-all-space=",
        "--diff-no-prefix=",
        "--diff-src-prefix=",
        "--diff-dst-prefix=",
        "--diff-text=",
        "--yes=",
        "--id=",
        "--file=",
        "--repo=",
        "--repository=",
        "--project=",
        "--env=",
        "--environment=",
        "--org-id=",
        "--project-id=",
        "--pipeline-definition-id=",
        "--vcs-origin=",
        "--context-id=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_global_ignored_bool_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--silent"
            | "-s"
            | "--quiet"
            | "-q"
            | "--no-progress"
            | "--progress=false"
            | "--no-color"
            | "--color=false"
    ) || ignored_npm_install_preference_flag(arg)
}

fn npm_global_ignored_value_flag(arg: &str) -> bool {
    matches!(arg, "--cache" | "--loglevel")
}

fn npm_global_ignored_equals_flag(arg: &str) -> bool {
    ["--cache=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
        || ignored_npm_install_preference_equals_flag(arg)
}



fn npm_maintenance_equals_value_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_rebuild_equals_value_flag(arg: &str) -> bool {
    [
        "--loglevel=",
        "--cache=",
        "--install-strategy=",
        "--audit=",
        "--fund=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}


fn npm_completion_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_help_search_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_init_flag_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

fn npm_init_ignored_value_flag(arg: &str) -> bool {
    matches!(arg, "--cache" | "--userconfig" | "--loglevel")
}

fn npm_init_ignored_equals_flag(arg: &str) -> bool {
    ["--cache=", "--userconfig=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_version_ignored_equals_flag(arg: &str) -> bool {
    ["--message=", "--tag-version-prefix="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_update_defaults_to_no_save(command: &str) -> bool {
    matches!(command, "update" | "up" | "upgrade" | "udpate")
}

fn normalize_npm_install_tag(tag: &str) -> Result<String, OmcRegistryError> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm install --tag cannot be empty".to_owned(),
        ));
    }
    Ok(tag.to_owned())
}

fn normalize_npm_before(value: &str) -> Result<String, OmcRegistryError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm --before cannot be empty".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn npm_min_release_age_before(value: &str) -> Result<String, OmcRegistryError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm --min-release-age needs a numeric day value".to_owned(),
        ));
    }
    let days = value.parse::<f64>().map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm --min-release-age value `{value}`"
        ))
    })?;
    if !days.is_finite() || days < 0.0 {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm --min-release-age value `{value}`"
        )));
    }
    let millis = (days * 86_400_000.0).round();
    if millis > i64::MAX as f64 {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm --min-release-age value `{value}`"
        )));
    }
    let cutoff = Utc::now() - Duration::milliseconds(millis as i64);
    Ok(cutoff.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn npm_install_specs_with_tag(
    specs: Vec<String>,
    tag: Option<&str>,
) -> Result<Vec<String>, OmcRegistryError> {
    let Some(tag) = tag else {
        return Ok(specs);
    };
    specs
        .into_iter()
        .map(|spec| npm_install_spec_with_tag(spec, tag))
        .collect()
}

fn npm_install_spec_with_tag(spec: String, tag: &str) -> Result<String, OmcRegistryError> {
    let parsed = parse_package_spec(&spec, Some(Ecosystem::Npm))?;
    if parsed.ecosystem != Ecosystem::Npm || parsed.version.is_some() || parsed.direct_url.is_some()
    {
        return Ok(spec);
    }
    if package_spec_has_ecosystem_prefix(&spec) {
        Ok(format!("npm:{}@{tag}", parsed.name))
    } else {
        Ok(format!("{spec}@{tag}"))
    }
}

fn npm_bool_flag_value(arg: &str, flag: &str) -> Option<bool> {
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

fn npm_json_flag_value(arg: &str) -> Option<bool> {
    match arg {
        "-j" => Some(true),
        "--no-json" => Some(false),
        _ => npm_bool_flag_value(arg, "--json"),
    }
}

fn npm_all_workspaces_flag_value(arg: &str) -> Option<bool> {
    match arg {
        "--workspaces" | "--workspaces=true" | "--ws" | "--ws=true" | "-ws" => Some(true),
        "--no-workspaces" | "--workspaces=false" | "--no-ws" | "--ws=false" => Some(false),
        _ => None,
    }
}

fn npm_include_workspace_root_flag_value(arg: &str) -> Option<bool> {
    match arg {
        "--include-workspace-root" | "--include-workspace-root=true" => Some(true),
        "--no-include-workspace-root" | "--include-workspace-root=false" => Some(false),
        _ => None,
    }
}

pub(crate) fn npm_workspace_scope_ignored_flag(arg: &str) -> bool {
    npm_all_workspaces_flag_value(arg).is_some()
        || npm_include_workspace_root_flag_value(arg).is_some()
}

fn npm_attached_short_value(arg: &str, flag: char) -> Option<&str> {
    if arg.starts_with("--") {
        return None;
    }

    let body = arg.strip_prefix('-')?;
    let mut chars = body.chars();
    if chars.next()? != flag {
        return None;
    }

    let value = chars.as_str();
    if value.is_empty() || value.starts_with('=') {
        None
    } else {
        Some(value)
    }
}

fn npm_global_location_flag_value(
    args: &[String],
    index: &mut usize,
    arg: &str,
) -> Result<Option<bool>, OmcRegistryError> {
    if matches!(arg, "--global" | "-g" | "--global=true") {
        return Ok(Some(true));
    }
    if arg == "--global=false" {
        return Ok(Some(false));
    }
    if arg == "--location" {
        *index += 1;
        let Some(value) = args.get(*index) else {
            return Err(OmcRegistryError::UnsupportedSpec(
                "--location needs a value".to_owned(),
            ));
        };
        return npm_location_is_global(value).map(Some);
    }
    if let Some(value) = arg.strip_prefix("--location=") {
        return npm_location_is_global(value).map(Some);
    }
    Ok(None)
}

fn npm_location_is_global(value: &str) -> Result<bool, OmcRegistryError> {
    match value {
        "global" => Ok(true),
        "project" | "user" => Ok(false),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm location `{other}`"
        ))),
    }
}


fn npm_link_explicit_save(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--save"
                | "-S"
                | "--save-prod"
                | "-P"
                | "-D"
                | "--save-dev"
                | "--dev"
                | "--save-optional"
                | "-O"
                | "--save-peer"
                | "--save-bundle"
                | "--save-bundled"
                | "-B"
        )
    })
}



fn npm_doctor_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_cache_equals_value_flag(arg: &str) -> bool {
    ["--loglevel="].iter().any(|prefix| arg.starts_with(prefix))
}


fn npm_pkg_ignored_equals_flag(arg: &str) -> bool {
    ["--workspace=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}



fn npm_dist_tag_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--loglevel=",
        "--parseable=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_dist_tag_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}




fn npm_sbom_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--package-lock-only=",
        "--omit=",
        "--include=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
        "--loglevel=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}


pub(crate) fn npm_registry_identity_equals_value_flag(arg: &str) -> bool {
    ["--loglevel="].iter().any(|prefix| arg.starts_with(prefix))
}


fn npm_explain_ignored_equals_flag(arg: &str) -> bool {
    ["--workspace=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn npm_all_long_short_flag(arg: &str) -> bool {
    let Some(rest) = arg.strip_prefix('-') else {
        return false;
    };
    !rest.is_empty() && !rest.starts_with('-') && rest.chars().all(|ch| matches!(ch, 'a' | 'l'))
}



fn npm_metadata_url_equals_value_flag(arg: &str) -> bool {
    ["--browser=", "--userconfig=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}




fn npm_config_assignment(key: &str, value: &str) -> Result<(String, String), OmcRegistryError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config key cannot be empty".to_owned(),
        ));
    }
    Ok((key.to_owned(), value.trim().to_owned()))
}

#[derive(Debug)]
pub(crate) struct NpmConfigArgs {
    editor: Option<String>,
    json: bool,
    location: NpmConfigLocation,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
    globalconfig: Option<PathBuf>,
    positionals: Vec<String>,
}



#[derive(Debug, PartialEq, Eq)]
struct NpmRunArgs {
    name: Option<String>,
    args: Vec<String>,
    if_present: bool,
    json: bool,
    workspaces: Vec<String>,
    all_workspaces: bool,
    include_workspace_root: bool,
}


fn npm_run_equals_value_flag(arg: &str) -> bool {
    ["--loglevel=", "--include-workspace-root="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


#[cfg(windows)]
fn npm_exec_call_command(call: String) -> (String, Vec<String>) {
    ("cmd".to_owned(), vec!["/C".to_owned(), call])
}

#[cfg(not(windows))]
fn npm_exec_call_command(call: String) -> (String, Vec<String>) {
    ("sh".to_owned(), vec!["-c".to_owned(), call])
}

fn npm_exec_equals_value_flag(arg: &str) -> bool {
    ["--cache=", "--userconfig=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
        || ignored_npm_install_preference_equals_flag(arg)
}

fn npm_exec_should_infer_package(command: &str) -> bool {
    !command.is_empty()
        && !command.starts_with("./")
        && !command.starts_with("../")
        && !Path::new(command).is_absolute()
        && !command.contains('\\')
}

fn npm_exec_inferred_bin_name(package: &str) -> Result<String, OmcRegistryError> {
    let package = package.strip_prefix("npm:").unwrap_or(package);
    let (name, _) = npm_create_split_version(package)?;
    Ok(npm_package_bin_name(name).to_owned())
}


fn npm_explore_equals_value_flag(arg: &str) -> bool {
    ["--shell=", "--loglevel=", "--cache=", "--registry="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_edit_equals_value_flag(arg: &str) -> bool {
    ["--editor=", "--loglevel=", "--cache=", "--registry="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn npm_local_path_arg(value: &str) -> Result<PathBuf, OmcRegistryError> {
    let path = value
        .strip_prefix("file:")
        .or_else(|| value.strip_prefix("link:"))
        .unwrap_or(value);
    if path.starts_with("//") {
        let url = reqwest::Url::parse(value)
            .map_err(|_| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
        return url.to_file_path().map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "local npm dependency `{value}` must use a valid file URL"
            ))
        });
    }
    if path.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "local npm path cannot be empty".to_owned(),
        ));
    }
    Ok(PathBuf::from(path))
}

fn is_npm_local_directory_arg(value: &str) -> bool {
    if is_npm_archive_arg(value) {
        return false;
    }
    let value = value
        .strip_prefix("file:")
        .or_else(|| value.strip_prefix("link:"))
        .unwrap_or(value);
    value == "."
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with("~/")
        || value.contains('\\')
}

fn is_npm_archive_arg(value: &str) -> bool {
    let path = value.strip_prefix("file:").unwrap_or(value);
    let path = path.split_once('#').map(|(path, _)| path).unwrap_or(path);
    let path = path.split_once('?').map(|(path, _)| path).unwrap_or(path);
    let lower = path.to_ascii_lowercase();
    (lower.ends_with(".tgz") || lower.ends_with(".tar.gz"))
        && (path.starts_with("https://")
            || path.starts_with("http://")
            || path.starts_with("./")
            || path.starts_with("../")
            || path.starts_with('/')
            || path.starts_with("~/")
            || path.contains('\\'))
}

fn is_npm_github_dependency_arg(value: &str) -> bool {
    let value = value.trim();
    let source = value
        .split_once('#')
        .map(|(source, _)| source)
        .unwrap_or(value);
    if value.starts_with("github:")
        || value.starts_with("git@github.com:")
        || value.starts_with("git+https://github.com/")
        || value.starts_with("git+ssh://git@github.com/")
        || source.starts_with("https://github.com/") && source.ends_with(".git")
        || value.starts_with("ssh://git@github.com/")
    {
        return true;
    }
    if value.starts_with('@')
        || value.starts_with('-')
        || value.starts_with('.')
        || value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with("file:")
        || value.starts_with("link:")
        || value.contains("://")
        || value.starts_with("git+")
    {
        return false;
    }
    let segments = source.split('/').collect::<Vec<_>>();
    segments.len() == 2
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && !segment.starts_with('.'))
}

#[derive(Debug)]
struct CommonCompatFlags {
    dependency_kind: ManifestDependencyKind,
    omit_dev: bool,
    omit_optional: bool,
    omit_peer: bool,
    save: bool,
    save_explicit: bool,
    save_prefix: String,
    save_bundle: bool,
    package_lock: bool,
    lock_only: bool,
    dry_run: bool,
    json: bool,
    npm_registry: Option<String>,
    npm_engine_strict: bool,
    npm_offline: bool,
    allow: Vec<String>,
    allow_flow: Vec<String>,
    allow_all_host: bool,
    workspaces: Vec<String>,
    all_workspaces: bool,
    include_workspace_root: bool,
    positionals: Vec<String>,
}

impl Default for CommonCompatFlags {
    fn default() -> Self {
        Self {
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            save: true,
            save_explicit: false,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
            positionals: Vec::new(),
        }
    }
}

pub(crate) fn parse_common_compat_flags(
    args: &[String],
    npm_mode: bool,
) -> Result<CommonCompatFlags, OmcRegistryError> {
    let mut parsed = CommonCompatFlags::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            parsed.positionals.extend(args[index + 1..].iter().cloned());
            break;
        } else if arg == "--allow" {
            index += 1;
            let Some(grant) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--allow needs a capability grant".to_owned(),
                ));
            };
            parsed.allow.push(grant.clone());
        } else if let Some(grant) = arg.strip_prefix("--allow=") {
            parsed.allow.push(grant.to_owned());
        } else if arg == "--allow-flow" {
            index += 1;
            let Some(flow) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--allow-flow needs a data-flow grant".to_owned(),
                ));
            };
            parsed.allow_flow.push(flow.clone());
        } else if let Some(flow) = arg.strip_prefix("--allow-flow=") {
            parsed.allow_flow.push(flow.to_owned());
        } else if arg == "--allow-all-host" {
            parsed.allow_all_host = true;
        } else if npm_mode && npm_bool_flag_value(arg, "--dry-run").is_some() {
            parsed.dry_run = npm_bool_flag_value(arg, "--dry-run").unwrap_or(false);
        } else if npm_mode && arg == "--no-dry-run" {
            parsed.dry_run = false;
        } else if npm_mode && npm_json_flag_value(arg).is_some() {
            parsed.json = npm_json_flag_value(arg).unwrap_or(false);
        } else if npm_mode
            && matches!(
                arg.as_str(),
                "--save-bundle"
                    | "--save-bundled"
                    | "-B"
                    | "--save-bundle=true"
                    | "--save-bundled=true"
            )
        {
            parsed.save = true;
            parsed.save_explicit = true;
            parsed.save_bundle = true;
        } else if npm_mode
            && matches!(
                arg.as_str(),
                "--no-save-bundle"
                    | "--no-save-bundled"
                    | "--save-bundle=false"
                    | "--save-bundled=false"
            )
        {
            parsed.save_bundle = false;
        } else if npm_mode && arg == "--no-save" {
            parsed.save = false;
            parsed.save_explicit = true;
        } else if npm_mode && arg == "--save=false" {
            parsed.save = false;
            parsed.save_explicit = true;
        } else if npm_mode {
            if let Some(dependency_kind) = npm_save_location_flag_kind(arg) {
                parsed.dependency_kind = dependency_kind;
                parsed.save = true;
                parsed.save_explicit = true;
                index += 1;
                continue;
            }
            if matches!(arg.as_str(), "--save-exact" | "-E" | "--save-exact=true") {
                parsed.save_prefix.clear();
                index += 1;
                continue;
            }
            if arg == "--save-exact=false" {
                parsed.save_prefix = DEFAULT_NPM_SAVE_PREFIX.to_owned();
                index += 1;
                continue;
            }
            if arg == "--save-prefix" {
                index += 1;
                let Some(prefix) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--save-prefix needs a value".to_owned(),
                    ));
                };
                parsed.save_prefix = prefix.clone();
                index += 1;
                continue;
            }
            if let Some(prefix) = arg.strip_prefix("--save-prefix=") {
                parsed.save_prefix = prefix.to_owned();
                index += 1;
                continue;
            }
            if arg == "--registry" {
                index += 1;
                let Some(registry) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--registry needs a URL".to_owned(),
                    ));
                };
                parsed.npm_registry = Some(registry.clone());
                index += 1;
                continue;
            }
            if let Some(lock_only) = npm_bool_flag_value(arg, "--package-lock-only") {
                parsed.lock_only = lock_only;
                index += 1;
                continue;
            }
            if let Some(package_lock) = npm_bool_flag_value(arg, "--package-lock") {
                parsed.package_lock = package_lock;
                index += 1;
                continue;
            }
            if arg == "--no-package-lock" {
                parsed.package_lock = false;
                index += 1;
                continue;
            }
            if let Some(engine_strict) = npm_bool_flag_value(arg, "--engine-strict") {
                parsed.npm_engine_strict = engine_strict;
                index += 1;
                continue;
            }
            if arg == "--no-engine-strict" {
                parsed.npm_engine_strict = false;
                index += 1;
                continue;
            }
            if let Some(offline) = npm_bool_flag_value(arg, "--offline") {
                parsed.npm_offline = offline;
                index += 1;
                continue;
            }
            if arg == "--no-offline" {
                parsed.npm_offline = false;
                index += 1;
                continue;
            }
            if let Some(registry) = arg.strip_prefix("--registry=") {
                parsed.npm_registry = Some(registry.to_owned());
                index += 1;
                continue;
            }
            if matches!(
                arg.as_str(),
                "--omit-dev" | "--production" | "--prod" | "--only=production"
            ) {
                parsed.omit_dev = true;
            } else if arg == "--only=prod" {
                parsed.omit_dev = true;
            } else if matches!(arg.as_str(), "--only=development" | "--only=dev") {
                parsed.omit_dev = false;
            } else if arg == "--only" {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--only needs a value".to_owned(),
                    ));
                };
                apply_npm_only_value(&mut parsed, value);
            } else if arg == "--also" {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--also needs a value".to_owned(),
                    ));
                };
                apply_npm_also_value(&mut parsed, value);
            } else if let Some(value) = arg.strip_prefix("--also=") {
                apply_npm_also_value(&mut parsed, value);
            } else if matches!(arg.as_str(), "--production=false" | "--prod=false") {
                parsed.omit_dev = false;
            } else if matches!(arg.as_str(), "--no-optional" | "--optional=false") {
                parsed.omit_optional = true;
            } else if matches!(arg.as_str(), "--optional" | "--optional=true") {
                parsed.omit_optional = false;
            } else if let Some(value) = arg.strip_prefix("--omit=") {
                parsed.omit_dev |= npm_dependency_set_contains(value, "dev");
                parsed.omit_optional |= npm_dependency_set_contains(value, "optional");
                parsed.omit_peer |= npm_dependency_set_contains(value, "peer");
            } else if let Some(value) = arg.strip_prefix("--include=") {
                if npm_dependency_set_contains(value, "dev") {
                    parsed.omit_dev = false;
                }
                if npm_dependency_set_contains(value, "optional") {
                    parsed.omit_optional = false;
                }
                if npm_dependency_set_contains(value, "peer") {
                    parsed.omit_peer = false;
                }
            } else if arg == "--omit" {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--omit needs a value".to_owned(),
                    ));
                };
                parsed.omit_dev |= npm_dependency_set_contains(value, "dev");
                parsed.omit_optional |= npm_dependency_set_contains(value, "optional");
                parsed.omit_peer |= npm_dependency_set_contains(value, "peer");
            } else if arg == "--include" {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--include needs a value".to_owned(),
                    ));
                };
                if npm_dependency_set_contains(value, "dev") {
                    parsed.omit_dev = false;
                }
                if npm_dependency_set_contains(value, "optional") {
                    parsed.omit_optional = false;
                }
                if npm_dependency_set_contains(value, "peer") {
                    parsed.omit_peer = false;
                }
            } else if matches!(arg.as_str(), "--workspace" | "-w") {
                index += 1;
                let Some(workspace) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "{arg} needs a workspace"
                    )));
                };
                parsed.workspaces.push(workspace.clone());
            } else if let Some(workspace) = arg
                .strip_prefix("--workspace=")
                .or_else(|| arg.strip_prefix("-w="))
            {
                parsed.workspaces.push(workspace.to_owned());
            } else if let Some(value) = npm_all_workspaces_flag_value(arg) {
                parsed.all_workspaces = value;
            } else if let Some(workspace) = npm_attached_short_value(arg, 'w') {
                parsed.workspaces.push(workspace.to_owned());
            } else if let Some(value) = npm_include_workspace_root_flag_value(arg) {
                parsed.include_workspace_root = value;
            } else if ignored_npm_value_flag(arg) {
                index += 1;
                if args.get(index).is_none() {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "{arg} needs a value"
                    )));
                }
            } else if ignored_compat_flag(npm_mode, arg) {
            } else if arg.starts_with('-') {
                return Err(unsupported_compat_arg("compatibility command", arg));
            } else {
                parsed.positionals.push(arg.clone());
            }
        } else if ignored_compat_flag(npm_mode, arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("compatibility command", arg));
        } else {
            parsed.positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(parsed)
}

fn apply_npm_only_value(parsed: &mut CommonCompatFlags, value: &str) {
    if npm_dependency_set_contains(value, "production")
        || npm_dependency_set_contains(value, "prod")
    {
        parsed.omit_dev = true;
    } else if npm_dependency_set_contains(value, "development")
        || npm_dependency_set_contains(value, "dev")
    {
        parsed.omit_dev = false;
    }
}

fn apply_npm_also_value(parsed: &mut CommonCompatFlags, value: &str) {
    if npm_dependency_set_contains(value, "development")
        || npm_dependency_set_contains(value, "dev")
    {
        parsed.omit_dev = false;
    }
    if npm_dependency_set_contains(value, "optional") {
        parsed.omit_optional = false;
    }
    if npm_dependency_set_contains(value, "peer") {
        parsed.omit_peer = false;
    }
}

fn npm_save_location_flag_kind(arg: &str) -> Option<ManifestDependencyKind> {
    match arg {
        "--save"
        | "-S"
        | "--save=true"
        | "--save-prod"
        | "-P"
        | "--save-prod=true"
        | "--save-prod=false"
        | "--no-save-prod"
        | "--save-dev=false"
        | "--dev=false"
        | "--no-save-dev"
        | "--no-dev"
        | "--save-optional=false"
        | "--no-save-optional"
        | "--save-peer=false"
        | "--no-save-peer" => Some(ManifestDependencyKind::Production),
        "-D" | "--save-dev" | "--dev" | "--save-dev=true" | "--dev=true" => {
            Some(ManifestDependencyKind::Dev)
        }
        "--save-optional" | "-O" | "--save-optional=true" => Some(ManifestDependencyKind::Optional),
        "--save-peer" | "--save-peer=true" => Some(ManifestDependencyKind::Peer),
        _ => None,
    }
}

fn npm_dependency_set_contains(value: &str, target: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|part| part.eq_ignore_ascii_case(target))
}

fn ignored_compat_flag(npm_mode: bool, arg: &str) -> bool {
    if npm_mode {
        matches!(
            arg,
            "--silent"
                | "-s"
                | "--quiet"
                | "-q"
                | "--no-progress"
                | "--progress=false"
                | "--no-color"
                | "--color=false"
                | "--save-exact"
                | "--engine-strict=false"
        ) || ignored_npm_install_preference_flag(arg)
            || ignored_npm_equals_flag(arg)
    } else {
        arg == "-y"
    }
}

fn ignored_npm_install_preference_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--ignore-scripts"
            | "--ignore-scripts=true"
            | "--ignore-scripts=false"
            | "--no-ignore-scripts"
            | "--foreground-scripts"
            | "--foreground-scripts=true"
            | "--foreground-scripts=false"
            | "--no-foreground-scripts"
            | "--fund"
            | "--fund=true"
            | "--fund=false"
            | "--no-fund"
            | "--audit"
            | "--audit=true"
            | "--audit=false"
            | "--no-audit"
            | "--legacy-peer-deps"
            | "--legacy-peer-deps=true"
            | "--legacy-peer-deps=false"
            | "--no-legacy-peer-deps"
            | "--strict-peer-deps"
            | "--strict-peer-deps=true"
            | "--strict-peer-deps=false"
            | "--no-strict-peer-deps"
            | "--prefer-offline"
            | "--prefer-offline=true"
            | "--prefer-offline=false"
            | "--no-prefer-offline"
            | "--prefer-online"
            | "--prefer-online=true"
            | "--prefer-online=false"
            | "--no-prefer-online"
            | "--prefer-dedupe"
            | "--prefer-dedupe=true"
            | "--prefer-dedupe=false"
            | "--no-prefer-dedupe"
            | "--install-links"
            | "--install-links=true"
            | "--install-links=false"
            | "--no-install-links"
            | "--bin-links"
            | "--bin-links=true"
            | "--bin-links=false"
            | "--no-bin-links"
            | "--global-style"
            | "--global-style=true"
            | "--global-style=false"
            | "--no-global-style"
            | "--legacy-bundling"
            | "--legacy-bundling=true"
            | "--legacy-bundling=false"
            | "--no-legacy-bundling"
    )
}

fn ignored_npm_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--install-strategy" | "--cache" | "--registry" | "--loglevel" | "--progress" | "--color"
    )
}

fn ignored_npm_equals_flag(arg: &str) -> bool {
    [
        "--install-strategy=",
        "--cache=",
        "--loglevel=",
        "--progress=",
        "--color=",
        "--install-links=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
        || ignored_npm_install_preference_equals_flag(arg)
}

fn ignored_npm_install_preference_equals_flag(arg: &str) -> bool {
    [
        "--ignore-scripts=",
        "--foreground-scripts=",
        "--fund=",
        "--audit=",
        "--legacy-peer-deps=",
        "--strict-peer-deps=",
        "--prefer-offline=",
        "--prefer-online=",
        "--prefer-dedupe=",
        "--install-links=",
        "--bin-links=",
        "--global-style=",
        "--legacy-bundling=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}


fn npm_list_all_flag_value(arg: &str) -> Option<bool> {
    match arg {
        "--all" | "--all=true" => Some(true),
        "--all=false" | "--no-all" => Some(false),
        _ => None,
    }
}

fn npm_list_short_all_flag_value(arg: &str) -> Option<bool> {
    let rest = arg.strip_prefix('-')?;
    if rest.is_empty() || rest.starts_with('-') {
        return None;
    }
    rest.chars()
        .all(|ch| matches!(ch, 'a' | 'l'))
        .then(|| rest.contains('a'))
}


fn npm_list_ignored_equals_flag(arg: &str) -> bool {
    [
        "--depth=",
        "--omit=",
        "--include=",
        "--loglevel=",
        "--workspace=",
        "--userconfig=",
        "--parseable=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn split_first_position(
    command: &str,
    args: &[String],
) -> Result<(String, Vec<String>), OmcRegistryError> {
    let mut args = args.to_vec();
    if args.first().map(String::as_str) == Some("--") {
        args.remove(0);
    }
    if args.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{command} needs a target"
        )));
    }
    let name = args.remove(0);
    if args.first().map(String::as_str) == Some("--") {
        args.remove(0);
    }
    Ok((name, args))
}

pub(crate) fn unsupported_compat_arg(command: &str, arg: &str) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!(
        "{command} does not support compatibility argument `{arg}`"
    ))
}

pub(crate) fn parse_grants(
    allow: &[String],
    allow_all_host: bool,
) -> Result<Vec<Capability>, OmcRegistryError> {
    let mut grants = allow
        .iter()
        .map(|grant| parse_capability_grant(grant))
        .collect::<Result<Vec<_>, _>>()?;

    if allow_all_host {
        grants.extend([
            Capability::EnvRead("*".to_owned()),
            Capability::FsRead("*".to_owned()),
            Capability::FsWrite("*".to_owned()),
            Capability::HttpHost("*".to_owned()),
            Capability::DnsHost("*".to_owned()),
            Capability::ProcSpawn("*".to_owned()),
            Capability::DynamicEval,
            Capability::TimeNow,
            Capability::RandomBytes,
        ]);
    }

    Ok(grants)
}

pub(crate) fn parse_flow_grants(
    allow_flow: &[String],
) -> Result<Vec<omc_cap::FlowRule>, OmcRegistryError> {
    allow_flow
        .iter()
        .map(|flow| parse_flow_rule(flow))
        .collect()
}

pub(crate) fn normalize_extra(extra: &str) -> String {
    extra.trim().replace('_', "-").to_ascii_lowercase()
}

#[cfg(test)]
mod tests;

