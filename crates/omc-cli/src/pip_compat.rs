//! pip CLI compat shim: install execution (target/user/prefix/root/dry-run),
//! user-site path management, and pip command-action parsing dispatch.

use crate::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use omc_registry::{
    add_package_graph, install_locked_packages_with_python_target, install_project, read_lockfile,
    remove_locked_packages, remove_manifest_dependency, Ecosystem, InstallReport, LinkOptions,
    LockedPackage, OmcLock, OmcRegistryError,
};

use crate::args::{PipCompatAction, PipInstallAction};
use crate::install::{
    apply_pip_compatibility_target, pip_install_report_to_stdout, write_pip_install_report_from,
};
use crate::manifest::parse_package_specs;
use crate::parse::parse_pip_archive_references;
use crate::policy_args::apply_cli_policy_options;
use crate::render::{print_install_report, print_link_reports};
use crate::shim::host_python_program;
use crate::temp_project::TempOmcProject;

pub(crate) fn run_pip_install_dry_run(
    project_dir: &Path,
    action: PipInstallAction,
) -> Result<ExitCode, OmcRegistryError> {
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
        prefix,
        root,
        user,
        vcs_requirements,
        allow,
        allow_flow,
        allow_all_host,
    } = action;
    let report_stdout = pip_install_report_to_stdout(report.as_deref());

    let dry_run_project = TempOmcProject::new("pip-dry-run", project_dir)?;
    let (dry_run_target, dry_run_bin_dir) = if user {
        let paths = pip_user_paths()?;
        (
            Some(pip_apply_root(
                project_dir,
                root.as_deref(),
                paths.site_packages,
            )),
            Some(pip_apply_root(project_dir, root.as_deref(), paths.bin_dir)),
        )
    } else if let Some(prefix) = prefix.as_ref() {
        let paths = pip_prefix_paths(project_dir, prefix.clone());
        (
            Some(pip_apply_root(
                project_dir,
                root.as_deref(),
                paths.site_packages,
            )),
            Some(pip_apply_root(project_dir, root.as_deref(), paths.bin_dir)),
        )
    } else {
        (
            target
                .as_ref()
                .map(|path| pip_rooted_project_path(project_dir, root.as_deref(), path.clone()))
                .or_else(|| {
                    root.as_ref()
                        .map(|root| pip_default_scheme_paths(project_dir, root).site_packages)
                }),
            root.as_ref()
                .map(|root| pip_default_scheme_paths(project_dir, root).bin_dir),
        )
    };
    let mut options = LinkOptions::new(dry_run_project.path());
    options.save_manifest_dependency = false;
    options.discover_project_requirements = !groups.is_empty();
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
    options.python_local_requirements =
        absolutize_python_local_requirements(project_dir, local_paths);
    let local_directories = absolutize_python_local_requirements(project_dir, local_directories);
    options.project_extras = groups.into_iter().collect();
    options.python_vcs_requirements = vcs_requirements;

    let had_requirement_sources =
        !options.requirement_files.is_empty() || !script_requirements.is_empty();
    let mut resolved_specs = parse_package_specs(&specs, Some(Ecosystem::Pypi))?;
    resolved_specs.extend(parse_pip_archive_references(
        project_dir,
        &archive_references,
        &mut options,
    )?);
    resolved_specs.extend(prepare_pip_local_directory_archive_specs(
        project_dir,
        dry_run_project.path(),
        local_directories,
        &mut options,
    )?);
    if !options.requirement_files.is_empty() {
        let requirement_files = std::mem::take(&mut options.requirement_files);
        let requirements = read_requirements_files(&requirement_files)?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            requirements,
            project_dir,
            dry_run_project.path(),
        )?;
    }
    if !options.constraint_files.is_empty() {
        let constraints = read_constraint_files(&options.constraint_files)?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            constraints,
            project_dir,
            dry_run_project.path(),
        )?;
    }
    if !script_requirements.is_empty() {
        let requirements =
            read_script_requirement_files(&absolutize_paths(project_dir, script_requirements))?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            requirements,
            project_dir,
            dry_run_project.path(),
        )?;
    }
    let local_path_count =
        options.python_local_paths.len() + options.python_local_requirements.len();
    let vcs_count = options.python_vcs_requirements.len();
    if resolved_specs.is_empty()
        && local_path_count == 0
        && vcs_count == 0
        && options.project_extras.is_empty()
    {
        if had_requirement_sources {
            let python_site_packages = dry_run_target.unwrap_or_else(|| {
                project_dir
                    .join(".omc")
                    .join("python")
                    .join("site-packages")
            });
            let install = InstallReport {
                npm_packages: 0,
                pypi_packages: 0,
                local_source_artifacts: 0,
                npm_bins: 0,
                python_scripts: 0,
                node_modules: project_dir.join("node_modules"),
                npm_bin_dir: project_dir.join("node_modules").join(".bin"),
                python_bin_dir: dry_run_bin_dir.unwrap_or_else(|| python_site_packages.join("bin")),
                python_site_packages,
            };
            if !report_stdout {
                println!();
                println!(
                    "dry-run: would install pypi=0 python_site_packages={}",
                    install.python_site_packages.display()
                );
            }
            write_pip_install_report_from(
                dry_run_project.path(),
                project_dir,
                report.as_deref(),
                &install,
            )?;
            return Ok(ExitCode::SUCCESS);
        }
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --dry-run needs at least one package, archive, local path, VCS requirement, or requirement file"
                .to_owned(),
        ));
    }

    if !options.project_extras.is_empty() {
        let mut manifest_options = options.clone();
        manifest_options.save_manifest_dependency = true;
        let mut reports = Vec::new();
        for spec in &resolved_specs {
            reports.extend(add_package_graph(spec, &manifest_options)?);
        }
        if !report_stdout {
            print_link_reports(&reports);
        }

        let mut install = install_project(&manifest_options)?;
        rewrite_pip_dry_run_install_paths(
            project_dir,
            dry_run_target.as_deref(),
            dry_run_bin_dir.as_deref(),
            &mut install,
        );
        if !report_stdout {
            println!();
            println!(
                "dry-run: would install pypi={} local_paths={} vcs={} groups={} python_site_packages={}",
                install.pypi_packages,
                local_path_count,
                vcs_count,
                manifest_options.project_extras.len(),
                install.python_site_packages.display()
            );
        }
        write_pip_install_report_from(
            dry_run_project.path(),
            project_dir,
            report.as_deref(),
            &install,
        )?;
        return Ok(ExitCode::SUCCESS);
    }

    if local_path_count > 0 || vcs_count > 0 {
        let mut manifest_options = options.clone();
        manifest_options.save_manifest_dependency = true;
        let mut reports = Vec::new();
        for spec in &resolved_specs {
            reports.extend(add_package_graph(spec, &manifest_options)?);
        }
        if !report_stdout {
            print_link_reports(&reports);
        }

        let mut install = install_project(&options)?;
        rewrite_pip_dry_run_install_paths(
            project_dir,
            dry_run_target.as_deref(),
            dry_run_bin_dir.as_deref(),
            &mut install,
        );
        if !report_stdout {
            println!();
            println!(
                "dry-run: would install pypi={} local_paths={} vcs={} python_site_packages={}",
                install.pypi_packages,
                local_path_count,
                vcs_count,
                install.python_site_packages.display()
            );
        }
        write_pip_install_report_from(
            dry_run_project.path(),
            project_dir,
            report.as_deref(),
            &install,
        )?;
        return Ok(ExitCode::SUCCESS);
    }

    let mut reports = Vec::new();
    for spec in &resolved_specs {
        reports.extend(add_package_graph(spec, &options)?);
    }
    if !report_stdout {
        print_link_reports(&reports);
    }

    let pypi_packages = reports
        .iter()
        .filter(|report| report.locked.ecosystem == Ecosystem::Pypi)
        .count();
    let python_site_packages = dry_run_target.unwrap_or_else(|| {
        project_dir
            .join(".omc")
            .join("python")
            .join("site-packages")
    });
    let install = InstallReport {
        npm_packages: 0,
        pypi_packages,
        local_source_artifacts: 0,
        npm_bins: 0,
        python_scripts: 0,
        node_modules: project_dir.join("node_modules"),
        npm_bin_dir: project_dir.join("node_modules").join(".bin"),
        python_bin_dir: dry_run_bin_dir.unwrap_or_else(|| python_site_packages.join("bin")),
        python_site_packages,
    };
    if !report_stdout {
        println!();
        println!(
            "dry-run: would install pypi={} python_site_packages={}",
            install.pypi_packages,
            install.python_site_packages.display()
        );
    }
    write_pip_install_report_from(
        dry_run_project.path(),
        project_dir,
        report.as_deref(),
        &install,
    )?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_pip_install_target(
    project_dir: &Path,
    action: PipInstallAction,
) -> Result<ExitCode, OmcRegistryError> {
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
        upgrade,
        force_reinstall,
        compatibility,
        target,
        prefix: _,
        root,
        user: _,
        vcs_requirements,
        allow,
        allow_flow,
        allow_all_host,
    } = action;
    let report_stdout = pip_install_report_to_stdout(report.as_deref());
    let target = target.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("pip install --target needs a path".to_owned())
    })?;

    let target_project = TempOmcProject::new("pip-target", project_dir)?;
    let mut options = LinkOptions::new(target_project.path());
    options.discover_project_requirements = !groups.is_empty();
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    options.requirement_files = absolutize_paths(project_dir, requirements);
    options.constraint_files = absolutize_paths(project_dir, constraints);
    options.python_local_requirements =
        absolutize_python_local_requirements(project_dir, local_paths);
    let local_directories = absolutize_python_local_requirements(project_dir, local_directories);
    options.project_extras = groups.into_iter().collect();
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
    options.python_target_overwrite_existing = upgrade || force_reinstall;
    apply_pip_compatibility_target(&mut options, compatibility);
    options.python_target_dir = Some(pip_rooted_project_path(
        project_dir,
        root.as_deref(),
        target,
    ));
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
        target_project.path(),
        local_directories,
        &mut options,
    )?);
    apply_pypi_requirement_files_with_local_directories(
        &mut options,
        &mut resolved_specs,
        project_dir,
        target_project.path(),
    )?;
    if !script_requirements.is_empty() {
        let requirements =
            read_script_requirement_files(&absolutize_paths(project_dir, script_requirements))?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            requirements,
            project_dir,
            target_project.path(),
        )?;
    }
    let requested_count = resolved_specs.len()
        + options.requirement_files.len()
        + options.python_local_paths.len()
        + options.python_local_requirements.len()
        + options.python_vcs_requirements.len()
        + options.project_extras.len();
    if requested_count == 0 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --target needs at least one package, archive, local path, VCS requirement, or requirement file"
                .to_owned(),
        ));
    }

    let mut reports = Vec::new();
    for spec in &resolved_specs {
        reports.extend(add_package_graph(spec, &options)?);
    }
    if !report_stdout {
        print_link_reports(&reports);
    }

    let install = install_project(&options)?;
    if !report_stdout {
        println!();
        print_install_report(&install);
    }
    write_pip_install_report_from(
        target_project.path(),
        project_dir,
        report.as_deref(),
        &install,
    )?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_pip_install_prefix(
    project_dir: &Path,
    action: PipInstallAction,
) -> Result<ExitCode, OmcRegistryError> {
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
        target: _,
        prefix,
        root,
        user: _,
        vcs_requirements,
        allow,
        allow_flow,
        allow_all_host,
    } = action;
    let report_stdout = pip_install_report_to_stdout(report.as_deref());
    let prefix = prefix.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("pip install --prefix needs a path".to_owned())
    })?;
    let mut paths = pip_prefix_paths(project_dir, prefix);
    paths.site_packages = pip_apply_root(project_dir, root.as_deref(), paths.site_packages);
    paths.bin_dir = pip_apply_root(project_dir, root.as_deref(), paths.bin_dir);

    let prefix_project = TempOmcProject::new("pip-prefix", project_dir)?;
    let mut options = LinkOptions::new(prefix_project.path());
    options.discover_project_requirements = !groups.is_empty();
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    options.requirement_files = absolutize_paths(project_dir, requirements);
    options.constraint_files = absolutize_paths(project_dir, constraints);
    options.python_local_requirements =
        absolutize_python_local_requirements(project_dir, local_paths);
    let local_directories = absolutize_python_local_requirements(project_dir, local_directories);
    options.project_extras = groups.into_iter().collect();
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
    options.python_target_dir = Some(paths.site_packages);
    options.python_bin_dir = Some(paths.bin_dir);
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
        prefix_project.path(),
        local_directories,
        &mut options,
    )?);
    apply_pypi_requirement_files_with_local_directories(
        &mut options,
        &mut resolved_specs,
        project_dir,
        prefix_project.path(),
    )?;
    if !script_requirements.is_empty() {
        let requirements =
            read_script_requirement_files(&absolutize_paths(project_dir, script_requirements))?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            requirements,
            project_dir,
            prefix_project.path(),
        )?;
    }
    let requested_count = resolved_specs.len()
        + options.requirement_files.len()
        + options.python_local_paths.len()
        + options.python_local_requirements.len()
        + options.python_vcs_requirements.len()
        + options.project_extras.len();
    if requested_count == 0 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --prefix needs at least one package, archive, local path, VCS requirement, or requirement file"
                .to_owned(),
        ));
    }

    let mut reports = Vec::new();
    for spec in &resolved_specs {
        reports.extend(add_package_graph(spec, &options)?);
    }
    if !report_stdout {
        print_link_reports(&reports);
    }

    let install = install_project(&options)?;
    if !report_stdout {
        println!();
        print_install_report(&install);
    }
    write_pip_install_report_from(
        prefix_project.path(),
        project_dir,
        report.as_deref(),
        &install,
    )?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_pip_install_root(
    project_dir: &Path,
    action: PipInstallAction,
) -> Result<ExitCode, OmcRegistryError> {
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
        target: _,
        prefix: _,
        root,
        user: _,
        vcs_requirements,
        allow,
        allow_flow,
        allow_all_host,
    } = action;
    let report_stdout = pip_install_report_to_stdout(report.as_deref());
    let root = root.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("pip install --root needs a path".to_owned())
    })?;
    let paths = pip_default_scheme_paths(project_dir, &root);

    let root_project = TempOmcProject::new("pip-root", project_dir)?;
    let mut options = LinkOptions::new(root_project.path());
    options.discover_project_requirements = !groups.is_empty();
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    options.requirement_files = absolutize_paths(project_dir, requirements);
    options.constraint_files = absolutize_paths(project_dir, constraints);
    options.python_local_requirements =
        absolutize_python_local_requirements(project_dir, local_paths);
    let local_directories = absolutize_python_local_requirements(project_dir, local_directories);
    options.project_extras = groups.into_iter().collect();
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
    options.python_target_dir = Some(paths.site_packages);
    options.python_bin_dir = Some(paths.bin_dir);
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
        root_project.path(),
        local_directories,
        &mut options,
    )?);
    apply_pypi_requirement_files_with_local_directories(
        &mut options,
        &mut resolved_specs,
        project_dir,
        root_project.path(),
    )?;
    if !script_requirements.is_empty() {
        let requirements =
            read_script_requirement_files(&absolutize_paths(project_dir, script_requirements))?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            requirements,
            project_dir,
            root_project.path(),
        )?;
    }
    let requested_count = resolved_specs.len()
        + options.requirement_files.len()
        + options.python_local_paths.len()
        + options.python_local_requirements.len()
        + options.python_vcs_requirements.len()
        + options.project_extras.len();
    if requested_count == 0 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --root needs at least one package, archive, local path, VCS requirement, or requirement file"
                .to_owned(),
        ));
    }

    let mut reports = Vec::new();
    for spec in &resolved_specs {
        reports.extend(add_package_graph(spec, &options)?);
    }
    if !report_stdout {
        print_link_reports(&reports);
    }

    let install = install_project(&options)?;
    if !report_stdout {
        println!();
        print_install_report(&install);
    }
    write_pip_install_report_from(
        root_project.path(),
        project_dir,
        report.as_deref(),
        &install,
    )?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_pip_install_user(
    project_dir: &Path,
    action: PipInstallAction,
) -> Result<ExitCode, OmcRegistryError> {
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
        target: _,
        prefix: _,
        root,
        user: _,
        vcs_requirements,
        allow,
        allow_flow,
        allow_all_host,
    } = action;
    let report_stdout = pip_install_report_to_stdout(report.as_deref());

    let user_paths = pip_user_paths()?;
    let root_install = root.is_some();
    let root_project = if root_install {
        Some(TempOmcProject::new("pip-user-root", project_dir)?)
    } else {
        None
    };
    let state_project = root_project
        .as_ref()
        .map(|project| project.path().to_path_buf())
        .unwrap_or_else(|| user_paths.state_project.clone());
    let site_packages = pip_apply_root(
        project_dir,
        root.as_deref(),
        user_paths.site_packages.clone(),
    );
    let install_bin_dir = if root_install {
        pip_apply_root(project_dir, root.as_deref(), user_paths.bin_dir.clone())
    } else {
        site_packages.join("bin")
    };
    fs::create_dir_all(&state_project)?;
    let mut options = LinkOptions::new(&state_project);
    apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
    options.requirement_files = absolutize_paths(project_dir, requirements);
    options.constraint_files = absolutize_paths(project_dir, constraints);
    options.python_local_requirements =
        absolutize_python_local_requirements(project_dir, local_paths);
    let local_directories = absolutize_python_local_requirements(project_dir, local_directories);
    options.project_extras = groups.into_iter().collect();
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
    options.python_target_dir = Some(site_packages.clone());
    options.python_bin_dir = Some(install_bin_dir);
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
        &state_project,
        local_directories,
        &mut options,
    )?);
    apply_pypi_requirement_files_with_local_directories(
        &mut options,
        &mut resolved_specs,
        project_dir,
        &state_project,
    )?;
    if !script_requirements.is_empty() {
        let requirements =
            read_script_requirement_files(&absolutize_paths(project_dir, script_requirements))?;
        apply_pypi_install_requirements(
            &mut options,
            &mut resolved_specs,
            requirements,
            project_dir,
            &state_project,
        )?;
    }
    let requested_count = resolved_specs.len()
        + options.requirement_files.len()
        + options.python_local_paths.len()
        + options.python_local_requirements.len()
        + options.python_vcs_requirements.len()
        + options.project_extras.len();
    if requested_count == 0 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --user needs at least one package, archive, local path, VCS requirement, or requirement file"
                .to_owned(),
        ));
    }

    let mut reports = Vec::new();
    for spec in &resolved_specs {
        reports.extend(add_package_graph(spec, &options)?);
    }
    if !report_stdout {
        print_link_reports(&reports);
    }

    let install = install_project(&options)?;
    if !root_install {
        sync_pip_user_script_local_paths(&user_paths)?;
        sync_pip_user_scripts(&user_paths)?;
    }
    if !report_stdout {
        println!();
        print_install_report(&install);
    }
    write_pip_install_report_from(&state_project, project_dir, report.as_deref(), &install)?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_pip_uninstall_user(
    specs: &[String],
    allow: &[String],
    allow_flow: &[String],
    allow_all_host: bool,
) -> Result<ExitCode, OmcRegistryError> {
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip uninstall --user needs at least one package".to_owned(),
        ));
    }

    let user_paths = pip_user_paths()?;
    fs::create_dir_all(&user_paths.state_project)?;
    let specs = parse_package_specs(specs, Some(Ecosystem::Pypi))?;
    let previous_lock = read_lockfile(user_paths.state_project.join("omc.lock")).ok();
    let local_paths_file = pip_user_install_local_paths_file(&user_paths)?;
    let editable_removal = remove_pip_editable_local_paths_from_file(&local_paths_file, &specs)?;
    sync_pip_user_script_local_paths(&user_paths)?;

    let mut removed = Vec::new();
    let mut removed_manifest = false;
    let mut removed_locked = false;
    for spec in &specs {
        let removed_from_manifest = remove_manifest_dependency(&user_paths.state_project, spec)?;
        removed_manifest |= removed_from_manifest;
        let locked_removals = if user_paths.state_project.join("omc.lock").exists() {
            remove_locked_packages(&user_paths.state_project, std::slice::from_ref(spec))?
        } else {
            Vec::new()
        };
        removed_locked |= !locked_removals.is_empty();
        let removed_from_editable =
            editable_removal.removed(&spec.name) && spec.ecosystem == Ecosystem::Pypi;
        if !removed_from_manifest && locked_removals.is_empty() && !removed_from_editable {
            eprintln!("WARNING: Skipping {} as it is not installed.", spec.name);
            continue;
        }
        removed.push(spec.package_key());
    }
    if removed.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }

    clean_pip_user_site_before_reinstall(&user_paths, previous_lock.as_ref())?;
    let install = if removed_manifest || !editable_removal.removed_names.is_empty() {
        let mut options = LinkOptions::new(&user_paths.state_project);
        apply_cli_policy_options(&mut options, allow, allow_flow, allow_all_host)?;
        options.python_target_dir = Some(user_paths.site_packages.clone());
        install_project(&options)?
    } else if removed_locked {
        install_locked_packages_with_python_target(
            &user_paths.state_project,
            &user_paths.site_packages,
        )?
    } else {
        InstallReport {
            npm_packages: 0,
            pypi_packages: 0,
            local_source_artifacts: 0,
            npm_bins: 0,
            python_scripts: 0,
            node_modules: user_paths.state_project.join("node_modules"),
            npm_bin_dir: user_paths.state_project.join("node_modules").join(".bin"),
            python_site_packages: user_paths.site_packages.clone(),
            python_bin_dir: user_paths.site_packages.join("bin"),
        }
    };
    sync_pip_user_script_local_paths(&user_paths)?;
    sync_pip_user_scripts(&user_paths)?;
    println!("removed {}", removed.join(", "));
    print_install_report(&install);
    Ok(ExitCode::SUCCESS)
}

fn clean_pip_user_site_before_reinstall(
    paths: &PipUserPaths,
    previous_lock: Option<&OmcLock>,
) -> Result<(), OmcRegistryError> {
    if let Some(lock) = previous_lock {
        for package in lock
            .packages
            .iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
        {
            remove_pip_installed_package_files(&paths.site_packages, package)?;
        }
    }
    remove_cli_path_if_exists(&paths.site_packages.join("bin"))?;
    Ok(())
}

fn remove_pip_installed_package_files(
    site_packages: &Path,
    package: &LockedPackage,
) -> Result<(), OmcRegistryError> {
    for record_path in pip_installed_files(site_packages, package)? {
        let Some(path) = safe_site_package_record_path(site_packages, &record_path) else {
            continue;
        };
        remove_cli_path_if_exists(&path)?;
    }
    if let Some(dist_info) = match_dist_info_dir(site_packages, package)? {
        remove_cli_path_if_exists(&dist_info)?;
    }
    Ok(())
}

fn safe_site_package_record_path(site_packages: &Path, record_path: &str) -> Option<PathBuf> {
    let relative = Path::new(record_path);
    if relative.is_absolute()
        || relative.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return None;
    }
    Some(site_packages.join(relative))
}

#[derive(Debug, Clone)]
struct PipPrefixPaths {
    site_packages: PathBuf,
    bin_dir: PathBuf,
}

fn pip_prefix_paths(project_dir: &Path, prefix: PathBuf) -> PipPrefixPaths {
    let project_dir = project_dir_for_user_paths(project_dir);
    let prefix = absolutize_path(&project_dir, prefix);
    let python_tag = pip_prefix_python_tag().unwrap_or_else(|| "python".to_owned());
    PipPrefixPaths {
        site_packages: prefix.join("lib").join(python_tag).join("site-packages"),
        bin_dir: pip_prefix_bin_dir(&prefix),
    }
}

fn pip_default_scheme_paths(project_dir: &Path, root: &Path) -> PipPrefixPaths {
    let project_dir = project_dir_for_user_paths(project_dir);
    let paths = pip_default_scheme_paths_from_python().unwrap_or_else(|| PipPrefixPaths {
        site_packages: PathBuf::from("lib").join("python").join("site-packages"),
        bin_dir: PathBuf::from("bin"),
    });
    PipPrefixPaths {
        site_packages: pip_apply_root(&project_dir, Some(root), paths.site_packages),
        bin_dir: pip_apply_root(&project_dir, Some(root), paths.bin_dir),
    }
}

fn pip_default_scheme_paths_from_python() -> Option<PipPrefixPaths> {
    let output = ProcessCommand::new(host_python_program().ok()?)
        .arg("-c")
        .arg(
            "import json, sysconfig; print(json.dumps({'purelib': sysconfig.get_path('purelib'), 'scripts': sysconfig.get_path('scripts')}))",
        )
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = serde_json::from_slice::<serde_json::Value>(&output.stdout).ok()?;
    let site_packages = value
        .get("purelib")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    let bin_dir = value
        .get("scripts")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    Some(PipPrefixPaths {
        site_packages,
        bin_dir,
    })
}

pub(crate) fn pip_rooted_project_path(
    project_dir: &Path,
    root: Option<&Path>,
    path: PathBuf,
) -> PathBuf {
    let project_dir = project_dir_for_user_paths(project_dir);
    let path = absolutize_path(&project_dir, path);
    pip_apply_root(&project_dir, root, path)
}

fn pip_apply_root(project_dir: &Path, root: Option<&Path>, path: PathBuf) -> PathBuf {
    let Some(root) = root else {
        return path;
    };
    let project_dir = project_dir_for_user_paths(project_dir);
    let root = absolutize_path(&project_dir, root.to_path_buf());
    if path.is_absolute() {
        let relative = path
            .components()
            .filter(|component| !matches!(component, std::path::Component::RootDir))
            .collect::<PathBuf>();
        root.join(relative)
    } else {
        root.join(path)
    }
}

fn pip_prefix_python_tag() -> Option<String> {
    let output = ProcessCommand::new(host_python_program().ok()?)
        .arg("-c")
        .arg("import sys; print('python{}.{}'.format(sys.version_info[0], sys.version_info[1]))")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let tag = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!tag.is_empty()).then_some(tag)
}

#[cfg(windows)]
fn pip_prefix_bin_dir(prefix: &Path) -> PathBuf {
    prefix.join("Scripts")
}

#[cfg(not(windows))]
fn pip_prefix_bin_dir(prefix: &Path) -> PathBuf {
    prefix.join("bin")
}

#[derive(Debug, Clone)]
pub(crate) struct PipUserPaths {
    pub(crate) site_packages: PathBuf,
    pub(crate) bin_dir: PathBuf,
    pub(crate) state_project: PathBuf,
}

pub(crate) fn pip_user_paths() -> Result<PipUserPaths, OmcRegistryError> {
    let (base, site_packages) =
        pip_user_paths_from_python().unwrap_or_else(pip_user_paths_fallback);
    let bin_dir = pip_user_bin_dir(&base);
    let state_project = base.join(".omc").join("pip-user");
    Ok(PipUserPaths {
        site_packages,
        bin_dir,
        state_project,
    })
}

fn pip_user_paths_from_python() -> Option<(PathBuf, PathBuf)> {
    let output = ProcessCommand::new(host_python_program().ok()?)
        .arg("-c")
        .arg(
            "import json, site; print(json.dumps({'base': site.USER_BASE, 'site': site.USER_SITE}))",
        )
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = serde_json::from_slice::<serde_json::Value>(&output.stdout).ok()?;
    let base = value
        .get("base")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    let site_packages = value
        .get("site")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    Some((base, site_packages))
}

fn pip_user_paths_fallback() -> (PathBuf, PathBuf) {
    let base = env::var_os("PYTHONUSERBASE")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(pip_default_user_base)
        .unwrap_or_else(|| PathBuf::from(".omc").join("pip-user-base"));
    let site_packages = base.join("lib").join("python").join("site-packages");
    (base, site_packages)
}

#[cfg(windows)]
fn pip_default_user_base() -> Option<PathBuf> {
    env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.join("Python"))
}

#[cfg(not(windows))]
fn pip_default_user_base() -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .map(|home| home.join(".local"))
}

#[cfg(windows)]
fn pip_user_bin_dir(base: &Path) -> PathBuf {
    base.join("Scripts")
}

#[cfg(not(windows))]
fn pip_user_bin_dir(base: &Path) -> PathBuf {
    base.join("bin")
}

fn sync_pip_user_scripts(paths: &PipUserPaths) -> Result<(), OmcRegistryError> {
    let source_bin = paths.site_packages.join("bin");
    fs::create_dir_all(&paths.bin_dir)?;
    remove_stale_pip_user_scripts(&paths.bin_dir, &source_bin)?;
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
        let target = paths.bin_dir.join(name);
        remove_cli_path_if_exists(&target)?;
        create_pip_user_script_link(&source, &target)?;
    }
    Ok(())
}

fn sync_pip_user_script_local_paths(paths: &PipUserPaths) -> Result<(), OmcRegistryError> {
    let script_marker = paths.site_packages.join(".omc-local-paths");
    let install_marker = pip_user_install_local_paths_file(paths)?;
    if install_marker == script_marker {
        return Ok(());
    }
    if install_marker.exists() {
        fs::copy(&install_marker, script_marker)?;
    } else {
        remove_cli_path_if_exists(&script_marker)?;
    }
    Ok(())
}

pub(crate) fn pip_user_install_local_paths_file(
    paths: &PipUserPaths,
) -> Result<PathBuf, OmcRegistryError> {
    if paths
        .site_packages
        .file_name()
        .and_then(|name| name.to_str())
        == Some("site-packages")
    {
        let parent = paths.site_packages.parent().ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("missing python user site directory".to_owned())
        })?;
        Ok(parent.join("local-paths"))
    } else {
        Ok(paths.site_packages.join(".omc-local-paths"))
    }
}

fn remove_stale_pip_user_scripts(
    target_bin: &Path,
    source_bin: &Path,
) -> Result<(), OmcRegistryError> {
    if !target_bin.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(target_bin)? {
        let entry = entry?;
        let path = entry.path();
        if pip_user_script_owned_by_omc(&path, source_bin)? {
            remove_cli_path_if_exists(&path)?;
        }
    }
    Ok(())
}

fn pip_user_script_owned_by_omc(path: &Path, source_bin: &Path) -> Result<bool, OmcRegistryError> {
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
        return Ok(content.contains("OMC pip user script shim")
            && content.contains(&source_bin.display().to_string()));
    }
    Ok(false)
}

#[cfg(unix)]
fn create_pip_user_script_link(source: &Path, target: &Path) -> Result<(), OmcRegistryError> {
    std::os::unix::fs::symlink(source, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_pip_user_script_link(source: &Path, target: &Path) -> Result<(), OmcRegistryError> {
    fs::write(
        target,
        format!(
            "@echo off\r\nREM OMC pip user script shim {}\r\n\"{}\" %*\r\n",
            source.parent().unwrap_or_else(|| Path::new("")).display(),
            source.display()
        ),
    )?;
    Ok(())
}

fn rewrite_pip_dry_run_install_paths(
    project_dir: &Path,
    target: Option<&Path>,
    bin_dir: Option<&Path>,
    install: &mut InstallReport,
) {
    install.node_modules = project_dir.join("node_modules");
    install.npm_bin_dir = install.node_modules.join(".bin");
    install.python_site_packages = target
        .map(|path| absolutize_path(project_dir, path.to_path_buf()))
        .unwrap_or_else(|| {
            project_dir
                .join(".omc")
                .join("python")
                .join("site-packages")
        });
    install.python_bin_dir = bin_dir
        .map(|path| absolutize_path(project_dir, path.to_path_buf()))
        .unwrap_or_else(|| install.python_site_packages.join("bin"));
}

pub(crate) fn parse_pip_compat_action(
    args: &[String],
) -> Result<PipCompatAction, OmcRegistryError> {
    let normalized = normalize_pip_global_args(args)?;
    let args = normalized.as_slice();
    if let Some(action) = parse_pip_help_request(args) {
        return Ok(action);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip compatibility needs a command such as install, uninstall, freeze, or list"
                .to_owned(),
        ));
    };

    match command {
        "--version" | "-V" => Ok(PipCompatAction::Version),
        "completion" => parse_pip_completion_args(&args[1..]),
        "install" => parse_pip_install_args(&args[1..]),
        "lock" => parse_pip_lock_args(&args[1..]),
        "download" => parse_pip_download_args(&args[1..]),
        "wheel" => parse_pip_wheel_args(&args[1..]),
        "uninstall" | "remove" => parse_pip_uninstall_args(&args[1..]),
        "show" => parse_pip_show_args(&args[1..]),
        "hash" => parse_pip_hash_args(&args[1..]),
        "cache" => parse_pip_cache_args(&args[1..]),
        "check" => parse_pip_check_args(&args[1..]),
        "debug" => parse_pip_debug_args(&args[1..]),
        "inspect" => parse_pip_inspect_args(&args[1..]),
        "freeze" => {
            let action = parse_pip_freeze_args(&args[1..])?;
            Ok(PipCompatAction::Freeze { action })
        }
        "list" => parse_pip_list_args(&args[1..]),
        "index" => parse_pip_index_args(&args[1..]),
        "search" => parse_pip_search_args(&args[1..]),
        "config" => parse_pip_config_args(&args[1..]),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip compatibility command `{other}`"
        ))),
    }
}
