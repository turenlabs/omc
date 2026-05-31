//! Host interpreter shims.
//!
//! Dispatch to the host `node`/`python` interpreters (and project commands),
//! intercepting `python -m pip`/`-m twine` invocations into the OMC compat
//! shims.

use crate::*;

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use omc_registry::OmcRegistryError;

pub(crate) fn run_node(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    run_node_in_cwd(project_dir, project_dir, args)
}

pub(crate) fn run_node_in_cwd(
    project_dir: &Path,
    cwd: &Path,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    let mut command = ProcessCommand::new(host_node_program()?);
    apply_project_runtime_env_for_cwd(&mut command, project_dir, cwd)?;
    let status = command.args(args).status()?;
    Ok(exit_code(status.code()))
}

pub(crate) fn host_node_program() -> Result<PathBuf, OmcRegistryError> {
    host_program("OMC_HOST_NODE", &["node"], "host node")
}

pub(crate) fn run_python(
    project_dir: &Path,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    run_python_in_cwd(project_dir, project_dir, args)
}

pub(crate) fn run_python_in_cwd(
    project_dir: &Path,
    cwd: &Path,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    if let Some(pip_args) = python_pip_module_args(args) {
        return run_pip_compat_with_cwd(project_dir, pip_args, cwd);
    }
    if let Some(twine_args) = python_twine_module_args(args) {
        return run_twine_compat_with_cwd(project_dir, twine_args, cwd);
    }

    let mut command = ProcessCommand::new(host_python_program()?);
    apply_project_runtime_env_for_cwd(&mut command, project_dir, cwd)?;
    let status = command.arg("-S").args(args).status()?;
    Ok(exit_code(status.code()))
}

pub(crate) fn host_python_program() -> Result<PathBuf, OmcRegistryError> {
    host_program("OMC_HOST_PYTHON", &["python3", "python"], "host python3")
}

fn host_program(
    override_var: &str,
    programs: &[&str],
    description: &str,
) -> Result<PathBuf, OmcRegistryError> {
    if let Some(path) = env::var_os(override_var) {
        return Ok(PathBuf::from(path));
    }

    programs
        .iter()
        .find_map(|program| find_program_outside_current_exe_dir(program))
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "could not find a {description} outside the OMC shim directory; set {override_var}"
            ))
        })
}

pub(crate) fn python_pip_module_args(args: &[String]) -> Option<&[String]> {
    python_module_args(args, is_pip_module)
}

pub(crate) fn python_twine_module_args(args: &[String]) -> Option<&[String]> {
    python_module_args(args, is_twine_module)
}

fn python_module_args(args: &[String], is_module: impl Fn(&str) -> bool) -> Option<&[String]> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "-m" {
            let module = args.get(index + 1)?;
            return is_module(module).then_some(&args[index + 2..]);
        }
        if let Some(module) = arg.strip_prefix("-m") {
            if !module.is_empty() {
                return is_module(module).then_some(&args[index + 1..]);
            }
        }

        match arg {
            "-S" | "-s" | "-E" | "-I" | "-B" | "-u" | "-q" | "-O" | "-OO" => index += 1,
            "-W" | "-X" => index += 2,
            _ if arg.starts_with("-W") || arg.starts_with("-X") => index += 1,
            _ => return None,
        }
    }
    None
}

fn is_pip_module(module: &str) -> bool {
    matches!(module, "pip" | "pip3" | "pip.__main__")
}

fn is_twine_module(module: &str) -> bool {
    matches!(module, "twine" | "twine.__main__")
}

pub(crate) fn run_project_command(
    project_dir: &Path,
    command: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    run_project_command_in_cwd(project_dir, project_dir, command, args)
}

pub(crate) fn run_project_command_in_cwd(
    project_dir: &Path,
    cwd: &Path,
    command: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    let mut process = ProcessCommand::new(command_program_for_cwd(command, cwd));
    apply_project_runtime_env_for_cwd(&mut process, project_dir, cwd)?;
    let status = process.args(args).status()?;
    Ok(exit_code(status.code()))
}

pub(crate) fn command_program_for_cwd(command: &str, cwd: &Path) -> PathBuf {
    let path = Path::new(command);
    if path.is_relative() && command_has_path_separator(command) {
        cwd.join(path)
    } else {
        path.to_path_buf()
    }
}

pub(crate) fn command_has_path_separator(command: &str) -> bool {
    command.contains('/') || command.contains('\\')
}
