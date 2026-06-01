//! npm CLI compat shim: install/ci/link execution and dispatch.

use crate::*;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use omc_registry::{
    add_package_graph, install_locked_packages, install_locked_project, install_project,
    lock_project, remove_manifest_dependency, Ecosystem, LinkOptions, LockedPackage,
    ManifestDependencyKind, OmcRegistryError, PackageSpec,
};

use crate::args::NpmCompatAction;

#[derive(Debug)]
pub(crate) struct NpmInstallCompatRequest {
    specs: Vec<String>,
    archive_references: Vec<String>,
    local_paths: Vec<PathBuf>,
    global: bool,
    save: bool,
    save_prefix: String,
    save_bundle: bool,
    dependency_kind: ManifestDependencyKind,
    omit_dev: bool,
    omit_optional: bool,
    omit_peer: bool,
    package_lock: bool,
    lock_only: bool,
    dry_run: bool,
    json: bool,
    npm_registry: Option<String>,
    npm_before: Option<String>,
    npm_engine_strict: bool,
    npm_offline: bool,
    allow: Vec<String>,
    allow_flow: Vec<String>,
    allow_all_host: bool,
    workspaces: Vec<String>,
    all_workspaces: bool,
    include_workspace_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmLinkAction {
    Register {
        dry_run: bool,
    },
    Install {
        names: Vec<String>,
        archive_references: Vec<String>,
        local_paths: Vec<PathBuf>,
        save: bool,
        save_bundle: bool,
        dependency_kind: ManifestDependencyKind,
        omit_dev: bool,
        omit_optional: bool,
        omit_peer: bool,
        lock_only: bool,
        dry_run: bool,
        npm_registry: Option<String>,
        allow: Vec<String>,
        allow_flow: Vec<String>,
        allow_all_host: bool,
    },
}

fn run_npm_install_compat(
    project_dir: &Path,
    request: NpmInstallCompatRequest,
) -> Result<ExitCode, OmcRegistryError> {
    let NpmInstallCompatRequest {
        specs,
        archive_references,
        local_paths,
        global,
        save,
        save_prefix,
        save_bundle,
        dependency_kind,
        omit_dev,
        omit_optional,
        omit_peer,
        package_lock,
        lock_only,
        dry_run,
        json,
        npm_registry,
        npm_before,
        npm_engine_strict,
        npm_offline,
        allow,
        allow_flow,
        allow_all_host,
        workspaces,
        all_workspaces,
        include_workspace_root,
    } = request;
    if global {
        return run_npm_global_install_compat(
            project_dir,
            NpmInstallCompatRequest {
                specs,
                archive_references,
                local_paths,
                global: false,
                save,
                save_prefix,
                save_bundle,
                dependency_kind,
                omit_dev,
                omit_optional,
                omit_peer,
                package_lock,
                lock_only,
                dry_run,
                json,
                npm_registry,
                npm_before,
                npm_engine_strict,
                npm_offline,
                allow,
                allow_flow,
                allow_all_host,
                workspaces,
                all_workspaces,
                include_workspace_root,
            },
        );
    }
    if dry_run {
        return run_npm_install_dry_run(
            project_dir,
            NpmInstallCompatRequest {
                specs,
                archive_references,
                local_paths,
                global: false,
                save,
                save_prefix,
                save_bundle,
                dependency_kind,
                omit_dev,
                omit_optional,
                omit_peer,
                package_lock,
                lock_only,
                dry_run,
                json,
                npm_registry,
                npm_before,
                npm_engine_strict,
                npm_offline,
                allow,
                allow_flow,
                allow_all_host,
                workspaces,
                all_workspaces,
                include_workspace_root,
            },
        );
    }
    let allowed_capabilities = parse_grants(&allow, allow_all_host)?;
    let allowed_flows = parse_flow_grants(&allow_flow)?;
    let workspace_mode = !workspaces.is_empty() || all_workspaces || include_workspace_root;
    if workspace_mode {
        return run_npm_install_workspace_compat(
            project_dir,
            NpmInstallCompatRequest {
                specs,
                archive_references,
                local_paths,
                global: false,
                save,
                save_prefix,
                save_bundle,
                dependency_kind,
                omit_dev,
                omit_optional,
                omit_peer,
                package_lock,
                lock_only,
                dry_run,
                json,
                npm_registry,
                npm_before,
                npm_engine_strict,
                npm_offline,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces,
                all_workspaces,
                include_workspace_root,
            },
            allowed_capabilities,
            allowed_flows,
        );
    }
    if specs.is_empty() && archive_references.is_empty() {
        let mut options = LinkOptions::new(project_dir);
        options.allowed_capabilities = allowed_capabilities;
        options.allowed_flows = allowed_flows;
        options.npm_registry_url = npm_registry.clone();
        options.npm_before = npm_before.clone();
        options.npm_engine_strict = npm_engine_strict;
        options.npm_offline = npm_offline;
        apply_dependency_omit_flags(&mut options, omit_dev, omit_optional, omit_peer);
        options.npm_local_paths = absolutize_paths(project_dir, local_paths.clone());
        if save && !local_paths.is_empty() {
            add_manifest_npm_local_paths(project_dir, &local_paths, dependency_kind)?;
            save_root_npm_package_json_dependencies(
                project_dir,
                &[],
                &local_paths,
                dependency_kind,
                save_bundle,
            )?;
        }
        if lock_only {
            let reports = lock_npm_project_including_omitted(&options)?;
            if json {
                print_npm_install_json_report(
                    project_dir,
                    &reports,
                    None,
                    false,
                    true,
                    &local_paths,
                )?;
            } else {
                print_link_reports(&reports);
                print_lock_only_report(project_dir);
            }
            if package_lock {
                sync_npm_package_lock(project_dir)?;
            }
        } else {
            let install = install_npm_project_with_complete_lock(&options)?;
            if json {
                print_npm_install_json_report(
                    project_dir,
                    &[],
                    Some(&install),
                    false,
                    false,
                    &local_paths,
                )?;
            } else {
                print_install_report(&install);
            }
            if package_lock {
                sync_npm_package_lock(project_dir)?;
            }
        }
    } else {
        let mut options = LinkOptions::new(project_dir);
        options.allowed_capabilities = allowed_capabilities;
        options.allowed_flows = allowed_flows;
        options.npm_registry_url = npm_registry.clone();
        options.npm_before = npm_before.clone();
        options.npm_engine_strict = npm_engine_strict;
        options.npm_offline = npm_offline;
        options.save_manifest_dependency = save;
        options.save_dependency_kind = dependency_kind;
        apply_dependency_omit_flags(&mut options, omit_dev, omit_optional, omit_peer);
        options.npm_local_paths = absolutize_paths(project_dir, local_paths.clone());
        if save && !local_paths.is_empty() {
            add_manifest_npm_local_paths(project_dir, &local_paths, dependency_kind)?;
        }
        let manifest_dirs = vec![project_dir.to_path_buf()];
        let specs = if save {
            specs
        } else {
            npm_specs_with_existing_manifest_requirements(&manifest_dirs, specs)?
        };
        let mut specs = parse_package_specs(&specs, Some(Ecosystem::Npm))?;
        specs.extend(parse_npm_archive_references(
            project_dir,
            &archive_references,
        )?);
        let graph_options = npm_lock_options_including_omitted(&options);
        let mut all_reports = Vec::new();
        let mut root_dependencies = Vec::new();
        for spec in &specs {
            let reports = add_package_graph(spec, &graph_options)?;
            if let Some(root) = reports.first() {
                root_dependencies.push(npm_package_json_requirement_for_link_root(
                    spec,
                    &root.locked,
                    &save_prefix,
                ));
            }
            all_reports.extend(reports);
        }
        prune_locked_package_versions(project_dir, &locked_packages_from_reports(&all_reports))?;
        if !json {
            print_link_reports(&all_reports);
        }
        if save {
            save_root_npm_package_json_dependencies(
                project_dir,
                &root_dependencies,
                &local_paths,
                dependency_kind,
                save_bundle,
            )?;
        }
        if lock_only {
            if json {
                print_npm_install_json_report(
                    project_dir,
                    &all_reports,
                    None,
                    false,
                    true,
                    &local_paths,
                )?;
            } else {
                print_lock_only_report(project_dir);
            }
            if package_lock {
                sync_npm_package_lock(project_dir)?;
            }
            return Ok(ExitCode::SUCCESS);
        }
        let install = if options.npm_local_paths.is_empty() {
            if save {
                install_locked_project(&options)?
            } else {
                install_locked_packages(project_dir)?
            }
        } else {
            install_npm_project_with_complete_lock(&options)?
        };
        if json {
            print_npm_install_json_report(
                project_dir,
                &all_reports,
                Some(&install),
                false,
                false,
                &local_paths,
            )?;
        } else {
            println!();
            print_install_report(&install);
        }
        if package_lock {
            sync_npm_package_lock(project_dir)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_npm_global_install_compat(
    input_project_dir: &Path,
    mut request: NpmInstallCompatRequest,
) -> Result<ExitCode, OmcRegistryError> {
    if !request.workspaces.is_empty() || request.all_workspaces || request.include_workspace_root {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm global install does not support workspace selection".to_owned(),
        ));
    }
    let prefix = npm_global_prefix_path();
    let global_project_dir = npm_global_project_dir_from_prefix(&prefix);
    request.local_paths = absolutize_paths(input_project_dir, request.local_paths);
    request.archive_references =
        absolutize_npm_archive_references(input_project_dir, request.archive_references);
    request.global = false;
    request.save = true;
    request.workspaces = Vec::new();
    request.all_workspaces = false;
    request.include_workspace_root = false;

    let dry_run = request.dry_run;
    let status = run_npm_install_compat(&global_project_dir, request)?;
    if status == ExitCode::SUCCESS && !dry_run {
        sync_npm_global_bins(&prefix, &global_project_dir)?;
    }
    Ok(status)
}

fn run_npm_global_remove_compat(
    specs: &[String],
    allow: &[String],
    allow_flow: &[String],
    allow_all_host: bool,
) -> Result<(), OmcRegistryError> {
    let prefix = npm_global_prefix_path();
    let global_project_dir = npm_global_project_dir_from_prefix(&prefix);
    let removed = remove_specs(
        &global_project_dir,
        specs,
        Some(Ecosystem::Npm),
        CliPolicyArgs::new(allow, allow_flow, allow_all_host),
        true,
        false,
        false,
        true,
        true,
        false,
    )?;
    if removed {
        sync_npm_global_bins(&prefix, &global_project_dir)?;
    }
    Ok(())
}

pub(crate) fn npm_package_json_requirement_for_link_root(
    spec: &PackageSpec,
    locked: &LockedPackage,
    save_prefix: &str,
) -> (String, String) {
    let requirement = spec.direct_url.clone().unwrap_or_else(|| {
        spec.version
            .as_deref()
            .and_then(npm_alias_requirement_name)
            .map(|name| {
                format!(
                    "npm:{name}@{}",
                    npm_package_json_version_requirement(&locked.version, save_prefix)
                )
            })
            .unwrap_or_else(|| npm_package_json_version_requirement(&locked.version, save_prefix))
    });
    (locked.name.clone(), requirement)
}

fn npm_package_json_version_requirement(version: &str, save_prefix: &str) -> String {
    format!("{save_prefix}{version}")
}

fn npm_alias_requirement_name(requirement: &str) -> Option<&str> {
    let alias = requirement.strip_prefix("npm:")?;
    let version_at = if let Some(stripped) = alias.strip_prefix('@') {
        stripped.rfind('@').map(|index| index + 1)
    } else {
        alias.rfind('@')
    };
    let name = version_at.map_or(alias, |index| &alias[..index]).trim();
    (!name.is_empty()).then_some(name)
}

fn save_root_npm_package_json_dependencies(
    project_dir: &Path,
    dependencies: &[(String, String)],
    local_paths: &[PathBuf],
    dependency_kind: ManifestDependencyKind,
    save_bundle: bool,
) -> Result<(), OmcRegistryError> {
    if !project_dir.join("package.json").exists() {
        return Ok(());
    }
    for (name, requirement) in dependencies {
        save_npm_package_json_dependency(
            project_dir,
            name,
            requirement,
            dependency_kind,
            save_bundle,
        )?;
    }
    for local_path in local_paths {
        save_npm_package_json_local_dependency(
            project_dir,
            project_dir,
            local_path,
            dependency_kind,
            save_bundle,
        )?;
    }
    Ok(())
}

fn run_npm_install_workspace_compat(
    project_dir: &Path,
    request: NpmInstallCompatRequest,
    allowed_capabilities: Vec<Capability>,
    allowed_flows: Vec<omc_cap::FlowRule>,
) -> Result<ExitCode, OmcRegistryError> {
    let NpmInstallCompatRequest {
        specs,
        archive_references,
        local_paths,
        global: _,
        save,
        save_prefix,
        save_bundle,
        dependency_kind,
        omit_dev,
        omit_optional,
        omit_peer,
        package_lock,
        lock_only,
        dry_run: _,
        json,
        npm_registry,
        npm_before,
        npm_engine_strict,
        npm_offline,
        allow: _,
        allow_flow: _,
        allow_all_host: _,
        workspaces,
        all_workspaces,
        include_workspace_root,
    } = request;

    let targets = npm_script_target_dirs(
        project_dir,
        &workspaces,
        all_workspaces,
        include_workspace_root,
    )?;
    if targets.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm install workspace selection did not match any package".to_owned(),
        ));
    }

    let mut options = LinkOptions::new(project_dir);
    options.allowed_capabilities = allowed_capabilities;
    options.allowed_flows = allowed_flows;
    options.npm_registry_url = npm_registry;
    options.npm_before = npm_before;
    options.npm_engine_strict = npm_engine_strict;
    options.npm_offline = npm_offline;
    options.save_manifest_dependency = false;
    apply_dependency_omit_flags(&mut options, omit_dev, omit_optional, omit_peer);
    options.npm_local_paths = absolutize_paths(project_dir, local_paths.clone());

    if specs.is_empty() && archive_references.is_empty() && local_paths.is_empty() {
        let install = if lock_only {
            let reports = lock_npm_project_including_omitted(&options)?;
            if json {
                print_npm_install_json_report(
                    project_dir,
                    &reports,
                    None,
                    false,
                    true,
                    &local_paths,
                )?;
            } else {
                print_link_reports(&reports);
                print_lock_only_report(project_dir);
            }
            if package_lock {
                sync_npm_package_lock(project_dir)?;
            }
            return Ok(ExitCode::SUCCESS);
        } else {
            install_npm_project_with_complete_lock(&options)?
        };
        if json {
            print_npm_install_json_report(
                project_dir,
                &[],
                Some(&install),
                false,
                false,
                &local_paths,
            )?;
        } else {
            print_install_report(&install);
        }
        if package_lock {
            sync_npm_package_lock(project_dir)?;
        }
        return Ok(ExitCode::SUCCESS);
    }

    let specs = if save {
        specs
    } else {
        npm_specs_with_existing_manifest_requirements(&targets, specs)?
    };
    let mut specs = parse_package_specs(&specs, Some(Ecosystem::Npm))?;
    specs.extend(parse_npm_archive_references(
        project_dir,
        &archive_references,
    )?);
    let graph_options = npm_lock_options_including_omitted(&options);

    let mut all_reports = Vec::new();
    let mut root_dependencies = Vec::new();
    for spec in &specs {
        let reports = add_package_graph(spec, &graph_options)?;
        if let Some(root) = reports.first() {
            root_dependencies.push(npm_package_json_requirement_for_link_root(
                spec,
                &root.locked,
                &save_prefix,
            ));
        }
        all_reports.extend(reports);
    }
    prune_locked_package_versions(project_dir, &locked_packages_from_reports(&all_reports))?;
    if !json {
        print_link_reports(&all_reports);
    }

    if save {
        for target in &targets {
            for (name, requirement) in &root_dependencies {
                save_npm_package_json_dependency(
                    target,
                    name,
                    requirement,
                    dependency_kind,
                    save_bundle,
                )?;
            }
            for local_path in &local_paths {
                save_npm_package_json_local_dependency(
                    project_dir,
                    target,
                    local_path,
                    dependency_kind,
                    save_bundle,
                )?;
            }
        }
    }

    if lock_only {
        if json {
            print_npm_install_json_report(
                project_dir,
                &all_reports,
                None,
                false,
                true,
                &local_paths,
            )?;
        } else {
            print_lock_only_report(project_dir);
        }
        if package_lock {
            sync_npm_package_lock(project_dir)?;
        }
        return Ok(ExitCode::SUCCESS);
    }

    let install = install_npm_project_with_complete_lock(&options)?;
    if json {
        print_npm_install_json_report(
            project_dir,
            &all_reports,
            Some(&install),
            false,
            false,
            &local_paths,
        )?;
    } else {
        println!();
        print_install_report(&install);
    }
    if package_lock {
        sync_npm_package_lock(project_dir)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn run_npm_remove_workspace_compat(
    project_dir: &Path,
    specs: &[String],
    policy: CliPolicyArgs<'_>,
    workspaces: &[String],
    all_workspaces: bool,
    include_workspace_root: bool,
    package_lock: bool,
    lock_only: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let targets = npm_script_target_dirs(
        project_dir,
        workspaces,
        all_workspaces,
        include_workspace_root,
    )?;
    if targets.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm remove workspace selection did not match any package".to_owned(),
        ));
    }

    let specs = parse_package_specs(specs, Some(Ecosystem::Npm))?;
    let mut removed = Vec::new();
    for spec in &specs {
        let removed_from_manifest = if !project_dir.join("omc.toml").exists() {
            false
        } else {
            remove_manifest_dependency(project_dir, spec)?
        };
        let mut removed_from_package_json = false;
        for target in &targets {
            removed_from_package_json |=
                remove_npm_package_json_dependency_from_package_dir(target, &spec.name)?;
        }
        if !removed_from_manifest && !removed_from_package_json {
            continue;
        }
        removed.push(spec.package_key());
    }
    if removed.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }

    let mut options = LinkOptions::new(project_dir);
    apply_cli_policy_options(
        &mut options,
        policy.allow,
        policy.allow_flow,
        policy.allow_all_host,
    )?;
    options.discover_project_requirements = true;
    if lock_only {
        let reports = lock_npm_project_including_omitted(&options)?;
        print_link_reports(&reports);
        print_lock_only_report(project_dir);
        if package_lock {
            sync_npm_package_lock(project_dir)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let install = install_project(&options)?;
    println!("removed {}", removed.join(", "));
    print_install_report(&install);
    sync_npm_package_lock(project_dir)?;
    Ok(ExitCode::SUCCESS)
}

fn run_npm_link_compat(
    project_dir: &Path,
    action: NpmLinkAction,
) -> Result<ExitCode, OmcRegistryError> {
    match action {
        NpmLinkAction::Register { dry_run } => {
            let (name, target) = npm_current_link_target(project_dir)?;
            let entry = npm_link_store_entry(&name)?;
            if dry_run {
                println!(
                    "dry-run: would register npm link {} -> {} at {}",
                    name,
                    target.display(),
                    entry.display()
                );
                return Ok(ExitCode::SUCCESS);
            }
            npm_write_link_store_entry(&entry, &target)?;
            println!("linked {name} -> {}", target.display());
            Ok(ExitCode::SUCCESS)
        }
        NpmLinkAction::Install {
            names,
            archive_references,
            mut local_paths,
            save,
            save_bundle,
            dependency_kind,
            omit_dev,
            omit_optional,
            omit_peer,
            lock_only,
            dry_run,
            npm_registry,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            for path in &local_paths {
                let (name, target) = npm_link_target_from_path(project_dir, path)?;
                if dry_run {
                    println!(
                        "dry-run: would register npm link {name} -> {}",
                        target.display()
                    );
                } else {
                    let entry = npm_link_store_entry(&name)?;
                    npm_write_link_store_entry(&entry, &target)?;
                }
            }
            for name in names {
                let target = npm_read_link_store_entry(&name)?;
                local_paths.push(target);
            }
            run_npm_install_compat(
                project_dir,
                NpmInstallCompatRequest {
                    specs: Vec::new(),
                    archive_references,
                    local_paths,
                    global: false,
                    save,
                    save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
                    save_bundle,
                    dependency_kind,
                    omit_dev,
                    omit_optional,
                    omit_peer,
                    package_lock: true,
                    lock_only,
                    dry_run,
                    json: false,
                    npm_registry,
                    npm_before: None,
                    npm_engine_strict: false,
                    npm_offline: false,
                    allow,
                    allow_flow,
                    allow_all_host,
                    workspaces: Vec::new(),
                    all_workspaces: false,
                    include_workspace_root: false,
                },
            )
        }
    }
}

fn npm_current_link_target(project_dir: &Path) -> Result<(String, PathBuf), OmcRegistryError> {
    npm_link_target_from_path(project_dir, &PathBuf::from("."))
}

pub(crate) fn npm_link_target_from_path(
    project_dir: &Path,
    path: &Path,
) -> Result<(String, PathBuf), OmcRegistryError> {
    let target = fs::canonicalize(absolutize_path(project_dir, path.to_path_buf()))?;
    let package = read_npm_pkg_json(&target.join("package.json"))?;
    let name = npm_package_json_name(&package)?;
    npm_link_store_entry(&name)?;
    Ok((name, target))
}

fn npm_link_store_home() -> Result<PathBuf, OmcRegistryError> {
    if let Some(path) = env::var_os("OMC_NPM_LINK_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return Ok(path);
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|home| home.join(".omc").join("npm-links"))
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "npm link needs HOME or OMC_NPM_LINK_HOME for the link store".to_owned(),
            )
        })
}

pub(crate) fn npm_link_store_entry(name: &str) -> Result<PathBuf, OmcRegistryError> {
    let home = npm_link_store_home()?;
    let name = name.trim();
    if name.is_empty() || name.contains('\\') || name.contains("..") {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm link package name `{name}`"
        )));
    }
    if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package)) = scoped.split_once('/') else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "invalid npm link package name `{name}`"
            )));
        };
        if scope.is_empty() || package.is_empty() || package.contains('/') {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "invalid npm link package name `{name}`"
            )));
        }
        Ok(home.join(format!("@{scope}")).join(package))
    } else {
        if name.contains('/') {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "invalid npm link package name `{name}`"
            )));
        }
        Ok(home.join(name))
    }
}

pub(crate) fn npm_write_link_store_entry(
    entry: &Path,
    target: &Path,
) -> Result<(), OmcRegistryError> {
    if let Some(parent) = entry.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(entry, format!("{}\n", target.display()))?;
    Ok(())
}

pub(crate) fn npm_read_link_store_entry(name: &str) -> Result<PathBuf, OmcRegistryError> {
    let entry = npm_link_store_entry(name)?;
    let content = fs::read_to_string(&entry).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm link `{name}` is not registered; run `npm link` in that package or `npm link <path>` first"
            ))
        } else {
            OmcRegistryError::Io(err)
        }
    })?;
    let target = PathBuf::from(content.trim());
    if target.as_os_str().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm link `{name}` has an empty target in {}",
            entry.display()
        )));
    }
    let canonical = fs::canonicalize(&target)?;
    let package = read_npm_pkg_json(&canonical.join("package.json"))?;
    let actual_name = npm_package_json_name(&package)?;
    if actual_name != name {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm link `{name}` points to package `{actual_name}` at {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn copy_npm_offline_state(
    source_project: &Path,
    target_project: &Path,
) -> Result<(), OmcRegistryError> {
    let source_lock = source_project.join("omc.lock");
    if source_lock.exists() {
        fs::copy(&source_lock, target_project.join("omc.lock"))?;
    }

    let source_omc = source_project.join(".omc");
    for name in ["cache", "artifacts"] {
        let source = source_omc.join(name);
        if source.exists() {
            copy_dir_recursive(&source, &target_project.join(".omc").join(name))?;
        }
    }

    Ok(())
}

fn copy_dir_recursive(source: &Path, target: &Path) -> Result<(), OmcRegistryError> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&source_path, &target_path)?;
        } else {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, target_path)?;
        }
    }
    Ok(())
}

fn run_npm_install_dry_run(
    project_dir: &Path,
    request: NpmInstallCompatRequest,
) -> Result<ExitCode, OmcRegistryError> {
    let NpmInstallCompatRequest {
        specs,
        archive_references,
        local_paths,
        global: _,
        save: _,
        save_prefix: _,
        save_bundle: _,
        dependency_kind: _,
        omit_dev,
        omit_optional,
        omit_peer,
        package_lock: _,
        lock_only,
        dry_run: _,
        json,
        npm_registry,
        npm_before,
        npm_engine_strict,
        npm_offline,
        allow,
        allow_flow,
        allow_all_host,
        workspaces: _,
        all_workspaces: _,
        include_workspace_root: _,
    } = request;

    let dry_run_project = TempOmcProject::new("npm-dry-run", project_dir)?;
    if npm_offline {
        copy_npm_offline_state(project_dir, dry_run_project.path())?;
    }
    let mut options = LinkOptions::new(dry_run_project.path());
    options.save_manifest_dependency = false;
    options.discover_project_requirements = specs.is_empty() && archive_references.is_empty();
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    options.npm_registry_url = npm_registry.clone();
    options.npm_before = npm_before;
    options.npm_engine_strict = npm_engine_strict;
    options.npm_offline = npm_offline;
    apply_dependency_omit_flags(&mut options, omit_dev, omit_optional, omit_peer);

    let mut reports = Vec::new();
    if specs.is_empty() && archive_references.is_empty() {
        if options.discover_project_requirements {
            reports.extend(lock_project(&options)?);
        }
    } else {
        let mut specs = parse_package_specs(&specs, Some(Ecosystem::Npm))?;
        specs.extend(parse_npm_archive_references(
            project_dir,
            &archive_references,
        )?);
        for spec in &specs {
            reports.extend(add_package_graph(spec, &options)?);
        }
    }

    if json {
        print_npm_install_json_report(project_dir, &reports, None, true, lock_only, &local_paths)?;
        return Ok(ExitCode::SUCCESS);
    }

    if !reports.is_empty() {
        print_link_reports(&reports);
    }
    if !local_paths.is_empty() {
        if !reports.is_empty() {
            println!();
        }
        println!("dry-run: would link npm local paths:");
        for path in &local_paths {
            println!(
                "  - {}",
                absolutize_path(project_dir, path.clone()).display()
            );
        }
    }

    let npm_packages = reports
        .iter()
        .filter(|report| report.locked.ecosystem == Ecosystem::Npm)
        .count();
    if !reports.is_empty() || !local_paths.is_empty() {
        println!();
    }
    let lock_detail = if lock_only {
        " and update omc.lock"
    } else {
        ""
    };
    println!(
        "dry-run: would install npm={} local_paths={} node_modules={}{}",
        npm_packages,
        local_paths.len(),
        project_dir.join("node_modules").display(),
        lock_detail
    );
    Ok(ExitCode::SUCCESS)
}

fn run_npm_ci_compat(
    project_dir: &Path,
    omit_dev: bool,
    omit_optional: bool,
    omit_peer: bool,
    dry_run: bool,
    json: bool,
    npm_engine_strict: bool,
    npm_offline: bool,
    allow: Vec<String>,
    allow_flow: Vec<String>,
    allow_all_host: bool,
    workspaces: &[String],
    all_workspaces: bool,
    include_workspace_root: bool,
) -> Result<ExitCode, OmcRegistryError> {
    validate_npm_workspace_selection(
        project_dir,
        workspaces,
        all_workspaces,
        include_workspace_root,
        "npm ci",
    )?;
    if dry_run {
        return run_npm_ci_dry_run(
            project_dir,
            omit_dev,
            omit_optional,
            omit_peer,
            json,
            npm_engine_strict,
            npm_offline,
            allow,
            allow_flow,
            allow_all_host,
        );
    }
    let mut options = LinkOptions::new(project_dir);
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    options.npm_engine_strict = npm_engine_strict;
    options.npm_offline = npm_offline;
    apply_dependency_omit_flags(&mut options, omit_dev, omit_optional, omit_peer);
    let install = match npm_ci_lock_source(project_dir)? {
        NpmCiLockSource::OmcLock => install_locked_project(&options)?,
        NpmCiLockSource::ProjectLock => install_npm_project_with_complete_lock(&options)?,
    };
    if json {
        print_npm_install_json_report(project_dir, &[], Some(&install), false, false, &[])?;
    } else {
        print_install_report(&install);
    }
    Ok(ExitCode::SUCCESS)
}

fn validate_npm_workspace_selection(
    project_dir: &Path,
    workspaces: &[String],
    all_workspaces: bool,
    include_workspace_root: bool,
    command: &str,
) -> Result<(), OmcRegistryError> {
    if workspaces.is_empty() && !all_workspaces && !include_workspace_root {
        return Ok(());
    }
    let targets = npm_script_target_dirs(
        project_dir,
        workspaces,
        all_workspaces,
        include_workspace_root,
    )?;
    if targets.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{command} workspace selection did not match any package"
        )));
    }
    Ok(())
}

fn run_npm_ci_dry_run(
    project_dir: &Path,
    omit_dev: bool,
    omit_optional: bool,
    omit_peer: bool,
    json: bool,
    npm_engine_strict: bool,
    npm_offline: bool,
    allow: Vec<String>,
    allow_flow: Vec<String>,
    allow_all_host: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let source = npm_ci_lock_source(project_dir)?;
    let dry_run_project = TempOmcProject::new("npm-ci-dry-run", project_dir)?;
    if npm_offline {
        copy_npm_offline_state(project_dir, dry_run_project.path())?;
    }
    if matches!(source, NpmCiLockSource::OmcLock) {
        fs::copy(
            project_dir.join("omc.lock"),
            dry_run_project.path().join("omc.lock"),
        )?;
    }

    let mut options = LinkOptions::new(dry_run_project.path());
    options.npm_engine_strict = npm_engine_strict;
    options.npm_offline = npm_offline;
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    apply_dependency_omit_flags(&mut options, omit_dev, omit_optional, omit_peer);
    let install = match source {
        NpmCiLockSource::OmcLock => install_locked_project(&options)?,
        NpmCiLockSource::ProjectLock => install_npm_project_with_complete_lock(&options)?,
    };
    if json {
        print_npm_install_json_report(project_dir, &[], Some(&install), true, false, &[])?;
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "dry-run: would install npm={} pypi={} local_artifacts={} npm_bins={} python_scripts={} node_modules={} python_site_packages={}",
        install.npm_packages,
        install.pypi_packages,
        install.local_source_artifacts,
        install.npm_bins,
        install.python_scripts,
        project_dir.join("node_modules").display(),
        project_dir.join(".omc").join("python").join("site-packages").display()
    );
    Ok(ExitCode::SUCCESS)
}

enum NpmCiLockSource {
    OmcLock,
    ProjectLock,
}

fn npm_ci_lock_source(project_dir: &Path) -> Result<NpmCiLockSource, OmcRegistryError> {
    if npm_project_has_npm_lockfile(project_dir) {
        return Ok(NpmCiLockSource::ProjectLock);
    }

    if !project_dir.join("omc.lock").exists() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm ci needs package-lock.json, npm-shrinkwrap.json, or omc.lock".to_owned(),
        ));
    }

    Ok(NpmCiLockSource::OmcLock)
}

fn npm_project_has_npm_lockfile(project_dir: &Path) -> bool {
    ["package-lock.json", "npm-shrinkwrap.json"]
        .iter()
        .any(|name| project_dir.join(name).exists())
}

pub(crate) fn run_npm_compat(
    project_dir: &Path,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    run_npm_compat_with_cwd(project_dir, args, project_dir)
}

pub(crate) fn run_npm_compat_with_cwd(
    project_dir: &Path,
    args: &[String],
    invocation_cwd: &Path,
) -> Result<ExitCode, OmcRegistryError> {
    let (project_dir, args) = npm_project_dir_from_prefix_args(project_dir, args)?;
    let project_dir = project_dir.as_path();
    let args = npm_args_with_config_defaults(project_dir, &args)?;
    match parse_npm_compat_action(&args)? {
        NpmCompatAction::Help { topic } => print_npm_help(topic.as_deref()),
        NpmCompatAction::HelpSearch { query, long } => print_npm_help_search(&query, long)?,
        NpmCompatAction::Version => println!("{}", env!("CARGO_PKG_VERSION")),
        NpmCompatAction::Completion { words } => print_npm_completion(project_dir, words)?,
        NpmCompatAction::Init { action } => print_npm_init(project_dir, action)?,
        NpmCompatAction::Create { action } => return run_npm_create(invocation_cwd, action),
        NpmCompatAction::PackageVersion { action } => print_npm_version(project_dir, action)?,
        NpmCompatAction::Link { mut action } => {
            absolutize_npm_link_action_paths(invocation_cwd, &mut action);
            return run_npm_link_compat(project_dir, action);
        }
        NpmCompatAction::Install {
            specs,
            archive_references,
            local_paths,
            global,
            save,
            save_prefix,
            save_bundle,
            dependency_kind,
            omit_dev,
            omit_optional,
            omit_peer,
            package_lock,
            lock_only,
            dry_run,
            json,
            npm_registry,
            npm_before,
            npm_engine_strict,
            npm_offline,
            allow,
            allow_flow,
            allow_all_host,
            workspaces,
            all_workspaces,
            include_workspace_root,
        } => {
            let mut request = NpmInstallCompatRequest {
                specs,
                archive_references,
                local_paths,
                global,
                save,
                save_prefix,
                save_bundle,
                dependency_kind,
                omit_dev,
                omit_optional,
                omit_peer,
                package_lock,
                lock_only,
                dry_run,
                json,
                npm_registry,
                npm_before,
                npm_engine_strict,
                npm_offline,
                allow,
                allow_flow,
                allow_all_host,
                workspaces,
                all_workspaces,
                include_workspace_root,
            };
            absolutize_npm_install_request_paths(invocation_cwd, &mut request);
            return run_npm_install_compat(project_dir, request);
        }
        NpmCompatAction::InstallTest {
            command,
            use_ci,
            specs,
            archive_references,
            local_paths,
            save,
            save_prefix,
            save_bundle,
            dependency_kind,
            omit_dev,
            omit_optional,
            omit_peer,
            package_lock,
            lock_only,
            dry_run,
            json,
            npm_registry,
            npm_before,
            npm_engine_strict,
            npm_offline,
            allow,
            allow_flow,
            allow_all_host,
            workspaces,
            all_workspaces,
            include_workspace_root,
            test_args,
        } => {
            let script_workspaces = workspaces.clone();
            let script_all_workspaces = all_workspaces;
            let script_include_workspace_root = include_workspace_root;
            let status = if use_ci {
                run_npm_ci_compat(
                    project_dir,
                    omit_dev,
                    omit_optional,
                    omit_peer,
                    dry_run,
                    json,
                    npm_engine_strict,
                    npm_offline,
                    allow,
                    allow_flow,
                    allow_all_host,
                    &script_workspaces,
                    script_all_workspaces,
                    script_include_workspace_root,
                )?
            } else {
                let mut request = NpmInstallCompatRequest {
                    specs,
                    archive_references,
                    local_paths,
                    global: false,
                    save,
                    save_prefix,
                    save_bundle,
                    dependency_kind,
                    omit_dev,
                    omit_optional,
                    omit_peer,
                    package_lock,
                    lock_only,
                    dry_run,
                    json,
                    npm_registry,
                    npm_before,
                    npm_engine_strict,
                    npm_offline,
                    allow,
                    allow_flow,
                    allow_all_host,
                    workspaces,
                    all_workspaces,
                    include_workspace_root,
                };
                absolutize_npm_install_request_paths(invocation_cwd, &mut request);
                run_npm_install_compat(project_dir, request)?
            };
            if status != ExitCode::SUCCESS {
                return Ok(status);
            }
            return run_package_script_with_npm_command_for_workspaces(
                project_dir,
                &command,
                "test",
                &test_args,
                false,
                NpmScriptTargets {
                    workspaces: &script_workspaces,
                    all_workspaces: script_all_workspaces,
                    include_workspace_root: script_include_workspace_root,
                },
            );
        }
        NpmCompatAction::Ci {
            omit_dev,
            omit_optional,
            omit_peer,
            dry_run,
            json,
            npm_engine_strict,
            npm_offline,
            allow,
            allow_flow,
            allow_all_host,
            workspaces,
            all_workspaces,
            include_workspace_root,
        } => {
            return run_npm_ci_compat(
                project_dir,
                omit_dev,
                omit_optional,
                omit_peer,
                dry_run,
                json,
                npm_engine_strict,
                npm_offline,
                allow,
                allow_flow,
                allow_all_host,
                &workspaces,
                all_workspaces,
                include_workspace_root,
            )
        }
        NpmCompatAction::Remove {
            specs,
            global,
            save,
            package_lock,
            lock_only,
            allow,
            allow_flow,
            allow_all_host,
            workspaces,
            all_workspaces,
            include_workspace_root,
        } => {
            if global {
                if lock_only {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "npm global remove cannot generate lockfiles".to_owned(),
                    ));
                }
                if !workspaces.is_empty() || all_workspaces || include_workspace_root {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "npm global remove does not support workspace selection".to_owned(),
                    ));
                }
                run_npm_global_remove_compat(&specs, &allow, &allow_flow, allow_all_host)?;
                return Ok(ExitCode::SUCCESS);
            }
            if !save {
                if lock_only {
                    return Ok(ExitCode::SUCCESS);
                }
                let specs = parse_package_specs(&specs, Some(Ecosystem::Npm))?;
                let removed = remove_npm_installed_specs(project_dir, &specs)?;
                if !removed.is_empty() {
                    println!("removed {}", removed.join(", "));
                }
                return Ok(ExitCode::SUCCESS);
            }
            if !workspaces.is_empty() || all_workspaces || include_workspace_root {
                return run_npm_remove_workspace_compat(
                    project_dir,
                    &specs,
                    CliPolicyArgs::new(&allow, &allow_flow, allow_all_host),
                    &workspaces,
                    all_workspaces,
                    include_workspace_root,
                    package_lock,
                    lock_only,
                );
            }
            let _ = remove_specs(
                project_dir,
                &specs,
                Some(Ecosystem::Npm),
                CliPolicyArgs::new(&allow, &allow_flow, allow_all_host),
                true,
                false,
                lock_only,
                package_lock,
                true,
                false,
            )?;
        }
        NpmCompatAction::Maintenance {
            command,
            packages,
            dry_run,
            json,
            omit_dev,
            omit_optional,
            omit_peer,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            let mut options = LinkOptions::new(project_dir);
            apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
            apply_dependency_omit_flags(&mut options, omit_dev, omit_optional, omit_peer);
            let install = if dry_run {
                npm_maintenance_dry_run_report(project_dir)?
            } else {
                install_locked_project(&options)?
            };
            print_npm_maintenance_report(command, &packages, &install, dry_run, json)?;
        }
        NpmCompatAction::RunScript {
            command,
            name,
            args,
            if_present,
            workspaces,
            all_workspaces,
            include_workspace_root,
        } => {
            return run_package_script_with_npm_command_for_workspaces(
                project_dir,
                &command,
                &name,
                &args,
                if_present,
                NpmScriptTargets {
                    workspaces: &workspaces,
                    all_workspaces,
                    include_workspace_root,
                },
            )
        }
        NpmCompatAction::RunList { action } => {
            print_npm_run_list(project_dir, action)?;
        }
        NpmCompatAction::Exec { action } => {
            return run_npm_exec(project_dir, invocation_cwd, action)
        }
        NpmCompatAction::Explore { action } => return run_npm_explore(project_dir, action),
        NpmCompatAction::Edit { target, editor } => {
            return run_npm_edit(project_dir, invocation_cwd, &target, editor)
        }
        NpmCompatAction::Path { kind, global } => print_npm_path(project_dir, kind, global)?,
        NpmCompatAction::List { action } => print_npm_list(project_dir, &action)?,
        NpmCompatAction::Query { action } => return print_npm_query(project_dir, action),
        NpmCompatAction::Explain { specs, json } => {
            return print_npm_explain(project_dir, &specs, json)
        }
        NpmCompatAction::Outdated {
            json,
            parseable,
            packages,
            npm_registry,
        } => {
            return print_npm_outdated(
                project_dir,
                json,
                parseable,
                &packages,
                npm_registry.as_deref(),
            )
        }
        NpmCompatAction::Doctor { action } => print_npm_doctor(project_dir, action)?,
        NpmCompatAction::Audit { json } => return print_audit_report(project_dir, json),
        NpmCompatAction::Fund { action } => print_npm_fund(project_dir, action)?,
        NpmCompatAction::Cache { action, cache_dir } => {
            let cache_dir = npm_cache_arg_or_env(invocation_cwd, cache_dir);
            print_npm_cache(project_dir, action, cache_dir.as_deref())?
        }
        NpmCompatAction::Pkg { action } => print_npm_pkg(project_dir, action)?,
        NpmCompatAction::Shrinkwrap => write_npm_shrinkwrap(project_dir)?,
        NpmCompatAction::Pack { mut action } => {
            absolutize_npm_pack_action_paths(invocation_cwd, &mut action);
            print_npm_pack(project_dir, action)?
        }
        NpmCompatAction::Publish { mut action } => {
            absolutize_npm_publish_action_paths(invocation_cwd, &mut action);
            print_npm_publish(project_dir, action)?
        }
        NpmCompatAction::Unpublish { mut action } => {
            absolutize_npm_unpublish_action_paths(invocation_cwd, &mut action);
            print_npm_unpublish(project_dir, action)?
        }
        NpmCompatAction::Deprecate { mut action } => {
            absolutize_npm_deprecate_action_paths(invocation_cwd, &mut action);
            print_npm_deprecate(project_dir, action)?
        }
        NpmCompatAction::Diff { mut action } => {
            absolutize_npm_diff_action_paths(invocation_cwd, &mut action)?;
            print_npm_diff(project_dir, action)?
        }
        NpmCompatAction::Search { action } => print_npm_search(project_dir, action)?,
        NpmCompatAction::Star { mut action } => {
            absolutize_npm_star_action_paths(invocation_cwd, &mut action);
            print_npm_star(project_dir, action)?
        }
        NpmCompatAction::Ping {
            json,
            npm_registry,
            mut userconfig,
        } => {
            absolutize_optional_path(invocation_cwd, &mut userconfig);
            print_npm_ping(
                project_dir,
                json,
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?
        }
        NpmCompatAction::Whoami {
            json,
            npm_registry,
            mut userconfig,
        } => {
            absolutize_optional_path(invocation_cwd, &mut userconfig);
            print_npm_whoami(
                project_dir,
                json,
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?
        }
        NpmCompatAction::Login { mut action } => {
            absolutize_npm_login_action_paths(invocation_cwd, &mut action);
            print_npm_login(project_dir, action)?
        }
        NpmCompatAction::Logout { mut action } => {
            absolutize_npm_logout_action_paths(invocation_cwd, &mut action);
            print_npm_logout(project_dir, action)?
        }
        NpmCompatAction::Token { mut action } => {
            absolutize_npm_token_action_paths(invocation_cwd, &mut action);
            print_npm_token(project_dir, action)?
        }
        NpmCompatAction::Trust { mut action } => {
            absolutize_npm_trust_action_paths(invocation_cwd, &mut action);
            print_npm_trust(project_dir, action)?
        }
        NpmCompatAction::Profile { mut action } => {
            absolutize_npm_profile_action_paths(invocation_cwd, &mut action);
            print_npm_profile(project_dir, action)?
        }
        NpmCompatAction::Owner { mut action } => {
            absolutize_npm_owner_action_paths(invocation_cwd, &mut action);
            print_npm_owner(project_dir, action)?
        }
        NpmCompatAction::Access { mut action } => {
            absolutize_npm_access_action_paths(invocation_cwd, &mut action);
            print_npm_access(project_dir, action)?
        }
        NpmCompatAction::Org { mut action } => {
            absolutize_npm_org_action_paths(invocation_cwd, &mut action);
            print_npm_org(project_dir, action)?
        }
        NpmCompatAction::Team { mut action } => {
            absolutize_npm_team_action_paths(invocation_cwd, &mut action);
            print_npm_team(project_dir, action)?
        }
        NpmCompatAction::DistTag { mut action } => {
            absolutize_npm_dist_tag_action_paths(invocation_cwd, &mut action);
            print_npm_dist_tag(project_dir, action)?
        }
        NpmCompatAction::Sbom { action } => print_npm_sbom(project_dir, action)?,
        NpmCompatAction::Config {
            action,
            npm_registry,
            mut userconfig,
            mut globalconfig,
        } => {
            absolutize_optional_path(invocation_cwd, &mut userconfig);
            absolutize_optional_path(invocation_cwd, &mut globalconfig);
            print_npm_config(
                project_dir,
                action,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                globalconfig.as_deref(),
            )?
        }
        NpmCompatAction::ConfigEdit {
            location,
            editor,
            mut userconfig,
            mut globalconfig,
        } => {
            absolutize_optional_path(invocation_cwd, &mut userconfig);
            absolutize_optional_path(invocation_cwd, &mut globalconfig);
            return run_npm_config_edit(
                project_dir,
                invocation_cwd,
                userconfig.as_deref(),
                globalconfig.as_deref(),
                location,
                editor,
            );
        }
        NpmCompatAction::View {
            spec,
            fields,
            json,
            npm_registry,
        } => print_npm_view(project_dir, &spec, &fields, json, npm_registry.as_deref())?,
        NpmCompatAction::MetadataUrl {
            kind,
            spec,
            json,
            npm_registry,
        } => print_npm_metadata_url(
            project_dir,
            kind,
            spec.as_deref(),
            json,
            npm_registry.as_deref(),
        )?,
    }

    Ok(ExitCode::SUCCESS)
}

fn absolutize_npm_install_request_paths(base_dir: &Path, request: &mut NpmInstallCompatRequest) {
    request.archive_references = absolutize_npm_archive_references(
        base_dir,
        std::mem::take(&mut request.archive_references),
    );
    request.local_paths = absolutize_paths(base_dir, std::mem::take(&mut request.local_paths));
}

fn absolutize_npm_link_action_paths(base_dir: &Path, action: &mut NpmLinkAction) {
    let NpmLinkAction::Install {
        archive_references,
        local_paths,
        ..
    } = action
    else {
        return;
    };
    *archive_references =
        absolutize_npm_archive_references(base_dir, std::mem::take(archive_references));
    *local_paths = absolutize_paths(base_dir, std::mem::take(local_paths));
}
