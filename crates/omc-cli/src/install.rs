//! Install orchestration + dependency-omit flags.

use crate::*;

use std::fs;
use std::path::{Path, PathBuf};

use omc_registry::{
    install_locked_project, install_project, lock_project, InstallReport, LinkOptions, LinkReport,
    LockedPackage, OmcRegistryError,
};

use crate::args::PipCompatibilityTarget;
use crate::policy_args::{apply_cli_policy_options, CliPolicyArgs};
use crate::render::pip_install_report_json;

pub(crate) fn install_options(
    project_dir: &Path,
    policy: CliPolicyArgs<'_>,
    extra: Vec<String>,
    requirements: Vec<PathBuf>,
    constraints: Vec<PathBuf>,
    omit: DependencyOmit,
) -> Result<LinkOptions, OmcRegistryError> {
    let mut options = LinkOptions::new(project_dir);
    apply_cli_policy_options(
        &mut options,
        policy.allow,
        policy.allow_flow,
        policy.allow_all_host,
    )?;
    options.project_extras = extra
        .into_iter()
        .map(|extra| normalize_extra(&extra))
        .collect();
    options.requirement_files = requirements
        .into_iter()
        .map(|path| absolutize_path(project_dir, path))
        .collect();
    options.constraint_files = constraints
        .into_iter()
        .map(|path| absolutize_path(project_dir, path))
        .collect();
    apply_dependency_omit_flags(&mut options, omit.dev, omit.optional, omit.peer);
    Ok(options)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DependencyOmit {
    pub(crate) dev: bool,
    pub(crate) optional: bool,
    pub(crate) peer: bool,
}

pub(crate) fn apply_dependency_omit_flags(
    options: &mut LinkOptions,
    omit_dev: bool,
    omit_optional: bool,
    omit_peer: bool,
) {
    options.include_dev_dependencies = !omit_dev;
    options.include_optional_dependencies = !omit_optional;
    options.include_peer_dependencies = !omit_peer;
}

pub(crate) fn npm_lock_options_including_omitted(options: &LinkOptions) -> LinkOptions {
    let mut lock_options = options.clone();
    lock_options.include_dev_dependencies = true;
    lock_options.include_optional_dependencies = true;
    lock_options.include_peer_dependencies = true;
    lock_options
}

pub(crate) fn lock_npm_project_including_omitted(
    options: &LinkOptions,
) -> Result<Vec<LinkReport>, OmcRegistryError> {
    let lock_options = npm_lock_options_including_omitted(options);
    lock_project(&lock_options)
}

pub(crate) fn install_npm_project_with_complete_lock(
    options: &LinkOptions,
) -> Result<InstallReport, OmcRegistryError> {
    if options.include_dev_dependencies
        && options.include_optional_dependencies
        && options.include_peer_dependencies
    {
        return install_project(options);
    }

    let lock_options = npm_lock_options_including_omitted(options);
    lock_project(&lock_options)?;
    install_locked_project(options)
}

pub(crate) fn apply_pip_compatibility_target(
    options: &mut LinkOptions,
    target: PipCompatibilityTarget,
) {
    options.pypi_target_platforms = target.platforms;
    options.pypi_target_python = target.python_version;
    options.pypi_target_implementation = target.implementation;
    options.pypi_target_abis = target.abis;
}

pub(crate) fn write_pip_install_report(
    project_dir: &Path,
    report_path: Option<&Path>,
    install: &InstallReport,
) -> Result<(), OmcRegistryError> {
    write_pip_install_report_from(project_dir, project_dir, report_path, install)
}

pub(crate) fn write_pip_install_report_from(
    lock_project_dir: &Path,
    output_project_dir: &Path,
    report_path: Option<&Path>,
    install: &InstallReport,
) -> Result<(), OmcRegistryError> {
    let Some(report_path) = report_path else {
        return Ok(());
    };
    let report = pip_install_report_json(lock_project_dir, install)?;
    let report = serde_json::to_string_pretty(&report)?;
    if pip_install_report_to_stdout(Some(report_path)) {
        println!("{report}");
    } else {
        let report_path = absolutize_path(output_project_dir, report_path.to_path_buf());
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(report_path, format!("{report}\n"))?;
    }
    Ok(())
}

pub(crate) fn pip_install_report_to_stdout(report_path: Option<&Path>) -> bool {
    report_path == Some(Path::new("-"))
}

pub(crate) fn locked_packages_from_reports(reports: &[LinkReport]) -> Vec<LockedPackage> {
    reports.iter().map(|report| report.locked.clone()).collect()
}
