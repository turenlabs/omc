//! npm global install/uninstall helpers and global argument normalization.
//!
//! Extracted from `lib.rs` (refactor/split-lib-modules). Pure code movement.

use crate::*;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use omc_registry::OmcRegistryError;

pub(crate) fn npm_global_prefix_path() -> PathBuf {
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
pub(crate) fn npm_global_project_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.to_path_buf()
}

#[cfg(not(windows))]
pub(crate) fn npm_global_project_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.join("lib")
}

#[cfg(windows)]
pub(crate) fn npm_global_bin_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.to_path_buf()
}

#[cfg(not(windows))]
pub(crate) fn npm_global_bin_dir_from_prefix(prefix: &Path) -> PathBuf {
    prefix.join("bin")
}

pub(crate) fn sync_npm_global_bins(prefix: &Path, global_project_dir: &Path) -> Result<(), OmcRegistryError> {
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

pub(crate) fn normalize_npm_global_args(args: &[String]) -> Result<Vec<String>, OmcRegistryError> {
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

pub(crate) fn npm_global_location_flag_value(
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

