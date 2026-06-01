//! npm exec / npx emulation.

use crate::*;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use omc_registry::{Ecosystem, LinkOptions, OmcRegistryError};

use crate::args::NpmExecAction;
use crate::manifest::parse_package_specs;
use crate::parse::parse_npm_archive_references;
use crate::policy_args::apply_cli_policy_options;
use crate::shim::{
    command_has_path_separator, command_program_for_cwd, run_project_command_in_cwd,
};
use crate::temp_project::TempOmcProject;

pub(crate) fn run_npm_exec(
    project_dir: &Path,
    cwd: &Path,
    mut action: NpmExecAction,
) -> Result<ExitCode, OmcRegistryError> {
    let target_cwds = npm_exec_target_cwds(project_dir, cwd, &action)?;
    infer_npm_exec_direct_package_command(cwd, &mut action)?;
    if action.packages.is_empty() || action.no_install {
        return run_npm_exec_in_project_cwds(project_dir, &target_cwds, &action);
    }
    if action.prefer_project_bin
        && npm_exec_all_project_commands_exist(project_dir, &target_cwds, &action.command)?
    {
        return run_npm_exec_in_project_cwds(project_dir, &target_cwds, &action);
    }

    let temp_project = TempOmcProject::empty("npm-exec")?;
    let (package_specs, archive_references, local_paths) =
        npm_exec_package_inputs(cwd, &action.packages)?;
    let mut specs = parse_package_specs(&package_specs, Some(Ecosystem::Npm))?;
    specs.extend(parse_npm_archive_references(
        temp_project.path(),
        &archive_references,
    )?);

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
    options.npm_local_paths = local_paths;
    options.enforce_local_source_verdicts = false;

    for spec in specs {
        add_package_graph(&spec, &options)?;
    }
    install_project(&options)?;

    for target_cwd in target_cwds {
        if action.prefer_project_bin
            && project_command_exists(project_dir, &target_cwd, &action.command)?
        {
            let status = run_project_command_in_cwd(
                project_dir,
                &target_cwd,
                &action.command,
                &action.args,
            )?;
            if status != ExitCode::SUCCESS {
                return Ok(status);
            }
            continue;
        }

        let mut process =
            ProcessCommand::new(command_program_for_cwd(&action.command, &target_cwd));
        apply_project_runtime_env_for_cwd(&mut process, temp_project.path(), &target_cwd)?;
        // batou:ignore command_exec -- npx/exec compat runs the user's own explicitly-requested
        // executable as a direct argv (no shell); cli_arg -> exec is the intended CLI dispatch.
        let status = process.args(&action.args).status()?;
        let status = exit_code(status.code());
        if status != ExitCode::SUCCESS {
            return Ok(status);
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn infer_npm_exec_direct_package_command(
    cwd: &Path,
    action: &mut NpmExecAction,
) -> Result<(), OmcRegistryError> {
    if !action.prefer_project_bin
        || action.packages.len() != 1
        || action.command != action.packages[0]
        || !npm_exec_direct_package_arg(&action.command)
    {
        return Ok(());
    }
    action.command = npm_exec_direct_package_bin_name(cwd, &action.packages[0])?;
    Ok(())
}

pub(crate) fn npm_exec_direct_package_arg(value: &str) -> bool {
    is_npm_local_directory_arg(value) || is_npm_archive_arg(value)
}

fn npm_exec_direct_package_bin_name(cwd: &Path, package: &str) -> Result<String, OmcRegistryError> {
    let package_json = if is_npm_archive_arg(package) {
        npm_exec_archive_package_json(cwd, package)?
    } else {
        let path = absolutize_path(cwd, npm_local_path_arg(package)?);
        read_npm_pkg_json(&path.join("package.json"))?
    };
    npm_exec_bin_name_from_package_json(&package_json, package)
}

fn npm_exec_archive_package_json(
    cwd: &Path,
    package: &str,
) -> Result<serde_json::Value, OmcRegistryError> {
    let reference = absolutize_npm_archive_reference(cwd, package);
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm exec cannot infer a bin name from remote archive `{package}`; use --package with an explicit command"
        )));
    }
    let reference = reference.strip_prefix("file:").unwrap_or(&reference);
    let (path, _) = split_npm_archive_suffix(reference);
    let bytes = fs::read(path)?;
    npm_exec_package_json_from_tgz(&bytes)
}

fn npm_exec_package_json_from_tgz(bytes: &[u8]) -> Result<serde_json::Value, OmcRegistryError> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().replace('\\', "/");
        if path == "package/package.json" {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            return Ok(serde_json::from_str(&content)?);
        }
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "npm exec archive package is missing package.json".to_owned(),
    ))
}

fn npm_exec_bin_name_from_package_json(
    package: &serde_json::Value,
    label: &str,
) -> Result<String, OmcRegistryError> {
    let package_name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(label);
    let default = npm_package_bin_name(package_name);
    let bins = npm_package_bin_names(package, package_name);
    if bins.iter().any(|bin| bin == default) {
        return Ok(default.to_owned());
    }
    match bins.as_slice() {
        [bin] => Ok(bin.clone()),
        [] => Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm exec package `{label}` did not declare an executable bin"
        ))),
        _ => Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm exec package `{label}` declares multiple bins: {}",
            bins.join(", ")
        ))),
    }
}

fn npm_exec_package_inputs(
    cwd: &Path,
    packages: &[String],
) -> Result<(Vec<String>, Vec<String>, Vec<PathBuf>), OmcRegistryError> {
    let mut specs = Vec::new();
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    for package in packages {
        if is_npm_archive_arg(package) {
            archive_references.push(absolutize_npm_archive_reference(cwd, package));
        } else if is_npm_local_directory_arg(package) {
            local_paths.push(absolutize_path(cwd, npm_local_path_arg(package)?));
        } else {
            specs.push(package.clone());
        }
    }
    Ok((specs, archive_references, local_paths))
}

pub(crate) fn npm_exec_target_cwds(
    project_dir: &Path,
    cwd: &Path,
    action: &NpmExecAction,
) -> Result<Vec<PathBuf>, OmcRegistryError> {
    if action.workspaces.is_empty() && !action.all_workspaces {
        return Ok(vec![cwd.to_path_buf()]);
    }
    npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )
}

fn run_npm_exec_in_project_cwds(
    project_dir: &Path,
    target_cwds: &[PathBuf],
    action: &NpmExecAction,
) -> Result<ExitCode, OmcRegistryError> {
    for target_cwd in target_cwds {
        let status =
            run_project_command_in_cwd(project_dir, target_cwd, &action.command, &action.args)?;
        if status != ExitCode::SUCCESS {
            return Ok(status);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn npm_exec_all_project_commands_exist(
    project_dir: &Path,
    target_cwds: &[PathBuf],
    command: &str,
) -> Result<bool, OmcRegistryError> {
    for target_cwd in target_cwds {
        if !project_command_exists(project_dir, target_cwd, command)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn project_command_exists(
    project_dir: &Path,
    cwd: &Path,
    command: &str,
) -> Result<bool, OmcRegistryError> {
    if command.is_empty() {
        return Ok(false);
    }
    let command_path = Path::new(command);
    if command_path.is_absolute() || command_has_path_separator(command) {
        let candidate = if command_path.is_absolute() {
            command_path.to_path_buf()
        } else {
            cwd.join(command_path)
        };
        return Ok(candidate.exists());
    }
    let path = project_path_for_cwd(project_dir, cwd)?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(command);
        if candidate.is_file() {
            return Ok(true);
        }
        #[cfg(windows)]
        {
            if candidate.with_extension("cmd").is_file()
                || candidate.with_extension("exe").is_file()
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
