use crate::*;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use omc_registry::OmcRegistryError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectCompatMode {
    Node,
    Npm,
    Npx,
    Pip,
    Python,
    Twine,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DirectCompatInvocation {
    pub(crate) project_dir: PathBuf,
    pub(crate) cwd: PathBuf,
    pub(crate) args: Vec<String>,
}

pub(crate) fn direct_compat_mode(program: Option<&std::ffi::OsStr>) -> Option<DirectCompatMode> {
    let name = Path::new(program?)
        .file_stem()
        .and_then(|name| name.to_str())?;
    match name {
        "node" => Some(DirectCompatMode::Node),
        "npm" => Some(DirectCompatMode::Npm),
        "npx" => Some(DirectCompatMode::Npx),
        "pip" | "pip3" => Some(DirectCompatMode::Pip),
        "python" | "python3" => Some(DirectCompatMode::Python),
        "twine" => Some(DirectCompatMode::Twine),
        _ => None,
    }
}

pub(crate) fn npx_compat_args(args: Vec<String>) -> Vec<String> {
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "--version" | "-v"))
    {
        return vec![args[0].clone()];
    }
    let mut compat_args = Vec::with_capacity(args.len() + 1);
    compat_args.push("npx".to_owned());
    compat_args.extend(args);
    compat_args
}

pub(crate) fn parse_direct_compat_invocation<I>(
    mode: DirectCompatMode,
    args: I,
) -> Result<DirectCompatInvocation, OmcRegistryError>
where
    I: IntoIterator<Item = OsString>,
{
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let env_project_dir = env::var_os("OMC_PROJECT_DIR").map(PathBuf::from);
    let mut project_dir = env_project_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let mut explicit_project_dir = env_project_dir.is_some();
    let mut compat_args = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = os_arg_to_string(arg)?;
        if arg == "--omc-project-dir"
            || arg == "--project-dir"
            || (direct_compat_uses_npm_prefix(mode) && arg == "--prefix")
        {
            let Some(path) = args.next() else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            project_dir = PathBuf::from(os_arg_to_string(path)?);
            explicit_project_dir = true;
        } else if let Some(path) = arg.strip_prefix("--omc-project-dir=") {
            project_dir = PathBuf::from(path);
            explicit_project_dir = true;
        } else if let Some(path) = arg.strip_prefix("--project-dir=") {
            project_dir = PathBuf::from(path);
            explicit_project_dir = true;
        } else if let Some(path) = direct_compat_uses_npm_prefix(mode)
            .then(|| arg.strip_prefix("--prefix="))
            .flatten()
        {
            project_dir = PathBuf::from(path);
            explicit_project_dir = true;
        } else {
            compat_args.push(arg);
            compat_args.extend(
                args.map(os_arg_to_string)
                    .collect::<Result<Vec<_>, OmcRegistryError>>()?,
            );
            break;
        }
    }
    if !explicit_project_dir {
        project_dir = discover_direct_compat_project_dir(mode, &project_dir);
    }
    Ok(DirectCompatInvocation {
        project_dir,
        cwd,
        args: compat_args,
    })
}

fn discover_direct_compat_project_dir(mode: DirectCompatMode, start: &Path) -> PathBuf {
    let start = absolute_project_dir(start);
    discover_direct_compat_project_dir_from(mode, &start).unwrap_or(start)
}

pub(crate) fn discover_direct_compat_project_dir_from(
    mode: DirectCompatMode,
    start: &Path,
) -> Option<PathBuf> {
    for dir in start.ancestors() {
        if direct_compat_project_markers(mode)
            .iter()
            .any(|marker| dir.join(marker).exists())
        {
            return Some(dir.to_path_buf());
        }
    }
    None
}

fn direct_compat_project_markers(mode: DirectCompatMode) -> &'static [&'static str] {
    match mode {
        DirectCompatMode::Node | DirectCompatMode::Npm | DirectCompatMode::Npx => &[
            "omc.toml",
            "omc.lock",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "node_modules",
        ],
        DirectCompatMode::Pip | DirectCompatMode::Python | DirectCompatMode::Twine => &[
            "omc.toml",
            "omc.lock",
            "pyproject.toml",
            "setup.cfg",
            "setup.py",
            "requirements.txt",
            "Pipfile",
            "poetry.lock",
            "uv.lock",
            "pylock.toml",
            ".pypirc",
        ],
    }
}

fn direct_compat_uses_npm_prefix(mode: DirectCompatMode) -> bool {
    matches!(mode, DirectCompatMode::Npm | DirectCompatMode::Npx)
}

fn os_arg_to_string(arg: OsString) -> Result<String, OmcRegistryError> {
    arg.into_string().map_err(|arg| {
        OmcRegistryError::UnsupportedSpec(format!(
            "argument is not valid UTF-8: {}",
            arg.to_string_lossy()
        ))
    })
}
