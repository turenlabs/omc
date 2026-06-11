//! `omc scan` — read-only capability scan of an EXISTING project, no migration
//! required. It discovers what the project's own manifests and lockfiles
//! declare (package.json, package-lock.json, requirements.txt, uv.lock, …),
//! resolves and capability-profiles every package through the same
//! deny-by-default engine as `omc install`, and reports the verdicts — without
//! requiring an omc.toml and without writing anything into the project.
//!
//! Resolution state lands in a throwaway scratch directory, exactly like
//! `omc inspect`. Unlike inspect, scan IS a gate: it exits 2 when any scanned
//! package would be blocked, so it can sit directly in CI on a non-OMC project.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use omc_registry::{scan_project_dir, LinkOptions, LinkReport, OmcRegistryError, Verdict};

use crate::policy_args::apply_cli_policy_options;
use crate::render::print_scan_report;
use crate::scratch::ScratchDir;

/// Arguments for `omc scan`.
pub(crate) struct ScanCommand {
    pub(crate) json: bool,
    pub(crate) omit_dev: bool,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
}

/// Manifest and lockfile names scan recognizes, mirroring project discovery in
/// `omc-registry`. Used for the report header and the nothing-to-scan error —
/// discovery itself remains the single source of truth for what gets parsed.
const SCAN_MANIFESTS: &[&str] = &[
    "omc.toml",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "dev-requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "uv.lock",
    "poetry.lock",
    "pylock.omc.toml",
    "pylock.toml",
];

/// Nested requirement files discovery also reads.
const SCAN_NESTED_MANIFESTS: &[&str] = &["requirements/base.txt", "requirements/dev.txt"];

pub(crate) fn detect_scan_manifests(project_dir: &Path) -> Vec<String> {
    SCAN_MANIFESTS
        .iter()
        .chain(SCAN_NESTED_MANIFESTS)
        .filter(|name| project_dir.join(name).exists())
        .map(|name| (*name).to_owned())
        .collect()
}

pub(crate) fn run_scan(
    project_dir: &Path,
    command: ScanCommand,
) -> Result<ExitCode, OmcRegistryError> {
    let manifests = detect_scan_manifests(project_dir);
    if manifests.is_empty() {
        return Err(OmcRegistryError::Usage(format!(
            "nothing to scan: no supported manifest or lockfile found in {}",
            project_dir.display()
        )));
    }

    // All resolution state (lock, manifest, archives, artifacts) lands in a
    // throwaway directory; the scanned project is never written to.
    let scratch = ScratchDir::new("omc-scan")?;
    let mut options = LinkOptions::new(scratch.path());
    // Record (don't throw on) blocked packages so the report covers the whole
    // project instead of stopping at the first denial.
    options.record_blocked = true;
    if command.omit_dev {
        options.include_dev_dependencies = false;
    }
    apply_cli_policy_options(
        &mut options,
        &command.allow,
        &command.allow_flow,
        command.allow_all_host,
    )?;

    let scan = scan_project_dir(project_dir, &options)?;
    let reports = dedupe_reports(scan.reports);
    let blocked = reports
        .iter()
        .filter(|r| r.locked.verdict == Verdict::Blocked)
        .count();

    if command.json {
        let payload = serde_json::json!({
            "project": project_dir.display().to_string(),
            "manifests": manifests,
            "scanned": reports.len(),
            "accepted": reports.len() - blocked,
            "blocked": blocked,
            "skipped_python_vcs": scan.skipped_python_vcs,
            "packages": reports.iter().map(|r| &r.locked).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print_scan_report(project_dir, &manifests, &reports, scan.skipped_python_vcs);
    }

    if blocked > 0 {
        return Err(OmcRegistryError::BlockedPackage {
            spec: format!("{blocked} of {} scanned package(s)", reports.len()),
            suggestion: None,
        });
    }
    Ok(ExitCode::SUCCESS)
}

/// Several scanned roots can resolve overlapping dependency graphs (a lockfile
/// pins every transitive package as its own root), so the same locked package
/// shows up in multiple graphs. Keep the first report per
/// ecosystem:name@version.
pub(crate) fn dedupe_reports(reports: Vec<LinkReport>) -> Vec<LinkReport> {
    let mut seen = BTreeSet::new();
    reports
        .into_iter()
        .filter(|report| {
            seen.insert(format!(
                "{}:{}@{}",
                report.locked.ecosystem, report.locked.name, report.locked.version
            ))
        })
        .collect()
}
