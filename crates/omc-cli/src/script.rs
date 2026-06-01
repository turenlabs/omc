//! Package script execution (npm run-script / lifecycle / run-list).

use crate::*;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use omc_registry::{read_package_scripts, OmcRegistryError};

use crate::args::NpmRunListAction;

pub(crate) fn run_package_script(
    project_dir: &Path,
    name: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    run_package_script_with_npm_command(project_dir, "run-script", name, args, false)
}

pub(crate) fn run_package_script_with_npm_command(
    project_dir: &Path,
    npm_command: &str,
    name: &str,
    args: &[String],
    if_present: bool,
) -> Result<ExitCode, OmcRegistryError> {
    run_package_script_in_dir(
        project_dir,
        project_dir,
        npm_command,
        name,
        args,
        if_present,
    )
}

pub(crate) fn run_package_script_with_npm_command_for_workspaces(
    project_dir: &Path,
    npm_command: &str,
    name: &str,
    args: &[String],
    if_present: bool,
    targets: NpmScriptTargets<'_>,
) -> Result<ExitCode, OmcRegistryError> {
    let script_dirs = npm_script_target_dirs(
        project_dir,
        targets.workspaces,
        targets.all_workspaces,
        targets.include_workspace_root,
    )?;
    for script_dir in script_dirs {
        let status = run_package_script_in_dir(
            project_dir,
            &script_dir,
            npm_command,
            name,
            args,
            if_present,
        )?;
        if status != ExitCode::SUCCESS {
            return Ok(status);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_package_script_in_dir(
    project_dir: &Path,
    script_dir: &Path,
    npm_command: &str,
    name: &str,
    args: &[String],
    if_present: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let script_dir = script_dir.to_path_buf();
    let scripts = read_package_scripts(&script_dir)?;
    if if_present && !scripts.contains_key(name) {
        return Ok(ExitCode::SUCCESS);
    }
    let lifecycle = package_script_lifecycle_order(&scripts, name)?;

    for lifecycle_name in lifecycle {
        let script = scripts.get(&lifecycle_name).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("missing project script `{lifecycle_name}`"))
        })?;
        let script_args = if lifecycle_name == name {
            args
        } else {
            &[] as &[String]
        };
        let status = run_single_package_script(
            project_dir,
            &script_dir,
            npm_command,
            &lifecycle_name,
            script,
            script_args,
        )?;
        if status != ExitCode::SUCCESS {
            return Ok(status);
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_npm_run_list(
    project_dir: &Path,
    action: NpmRunListAction,
) -> Result<(), OmcRegistryError> {
    let script_dirs = npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )?;
    let workspace_mode =
        !action.workspaces.is_empty() || action.all_workspaces || action.include_workspace_root;
    let mut entries = Vec::new();
    for script_dir in script_dirs {
        let scripts = read_package_scripts(&script_dir)?;
        let label = npm_run_list_label(project_dir, &script_dir)?;
        entries.push((label, scripts));
    }

    if action.json {
        if workspace_mode {
            let value = entries.into_iter().collect::<BTreeMap<_, _>>();
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            let scripts = entries
                .into_iter()
                .next()
                .map(|(_, scripts)| scripts)
                .unwrap_or_default();
            println!("{}", serde_json::to_string_pretty(&scripts)?);
        }
    } else {
        for (index, (label, scripts)) in entries.iter().enumerate() {
            if index > 0 {
                println!();
            }
            print_npm_run_text_list(label, scripts);
        }
    }

    Ok(())
}

fn npm_run_list_label(project_dir: &Path, script_dir: &Path) -> Result<String, OmcRegistryError> {
    let package_json = script_dir.join("package.json");
    if package_json.exists() {
        let package = read_npm_pkg_json(&package_json)?;
        if let Some(name) = package.get("name").and_then(serde_json::Value::as_str) {
            return Ok(name.to_owned());
        }
    }
    if script_dir == project_dir {
        return Ok("undefined".to_owned());
    }
    Ok(script_dir
        .strip_prefix(project_dir)
        .unwrap_or(script_dir)
        .to_string_lossy()
        .into_owned())
}

fn print_npm_run_text_list(label: &str, scripts: &BTreeMap<String, String>) {
    let lifecycle = ["test", "start", "stop", "restart"];
    let lifecycle_scripts = lifecycle
        .iter()
        .filter_map(|name| scripts.get(*name).map(|script| (*name, script)))
        .collect::<Vec<_>>();
    if !lifecycle_scripts.is_empty() {
        println!("Lifecycle scripts included in {label}:");
        for (name, script) in lifecycle_scripts {
            println!("  {name}");
            println!("    {script}");
        }
    }

    let available = scripts
        .iter()
        .filter(|(name, _)| !lifecycle.contains(&name.as_str()))
        .collect::<Vec<_>>();
    if !available.is_empty() {
        println!("available via `npm run`:");
        for (name, script) in available {
            println!("  {name}");
            println!("    {script}");
        }
    }
    if scripts.is_empty() {
        println!("No scripts found in {label}");
    }
}

pub(crate) fn package_script_lifecycle_order(
    scripts: &BTreeMap<String, String>,
    name: &str,
) -> Result<Vec<String>, OmcRegistryError> {
    if !scripts.contains_key(name) {
        let available = scripts.keys().cloned().collect::<Vec<_>>().join(", ");
        let detail = if available.is_empty() {
            format!("missing project script `{name}`")
        } else {
            format!("missing project script `{name}`; available scripts: {available}")
        };
        return Err(OmcRegistryError::UnsupportedSpec(detail));
    }

    let mut lifecycle = Vec::new();
    let pre = format!("pre{name}");
    if scripts.contains_key(&pre) {
        lifecycle.push(pre);
    }
    lifecycle.push(name.to_owned());
    let post = format!("post{name}");
    if scripts.contains_key(&post) {
        lifecycle.push(post);
    }
    Ok(lifecycle)
}

fn run_single_package_script(
    project_dir: &Path,
    script_dir: &Path,
    npm_command: &str,
    name: &str,
    script: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    let mut command = package_script_command(script);
    apply_project_runtime_env_for_cwd(&mut command, project_dir, script_dir)?;
    apply_npm_lifecycle_env(&mut command, script_dir, npm_command, name, script)?;
    let status = command.args(args).status()?;
    Ok(exit_code(status.code()))
}
