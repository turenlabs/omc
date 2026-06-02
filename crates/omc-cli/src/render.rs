//! JSON/text output formatting for the omc CLI.

use crate::*;

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use omc_registry::{
    read_lockfile, Behavior, CapabilityKind, Ecosystem, InstallReport, LinkReport,
    LockedLocalSource, LockedPackage, OmcRegistryError, Verdict,
};

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once from the global `--verbose` flag at startup. `print_link_reports`
/// reads it (it is called from ~20 deep sites that have no access to the parsed
/// CLI), and `OMC_VERBOSE` in the environment forces it on as well.
static VERBOSE: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub(crate) fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed) || env::var_os("OMC_VERBOSE").is_some()
}

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// ANSI coloring is applied only when stdout is a real terminal and `NO_COLOR`
/// is unset, so piped/redirected output and captured test output stay plain.
fn color_enabled() -> bool {
    env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}
fn paint(text: &str, code: &str) -> String {
    if color_enabled() {
        format!("{code}{text}{RESET}")
    } else {
        text.to_owned()
    }
}
fn bold(text: &str) -> String {
    paint(text, BOLD)
}
fn dim(text: &str) -> String {
    paint(text, DIM)
}

pub(crate) fn print_install_report(install: &InstallReport) {
    if is_verbose() {
        println!(
            "installed npm={} pypi={} local_artifacts={} npm_bins={} python_scripts={} node_modules={} python_site_packages={}",
            install.npm_packages,
            install.pypi_packages,
            install.local_source_artifacts,
            install.npm_bins,
            install.python_scripts,
            install.node_modules.display(),
            install.python_site_packages.display()
        );
        return;
    }

    let total = install.npm_packages + install.pypi_packages + install.local_source_artifacts;
    if total == 0 {
        println!("Nothing to install (already up to date).");
        return;
    }

    // Name only the targets the install actually wrote to, with the count of
    // executables/scripts placed on PATH (the part users act on), instead of the
    // npm=…/pypi=… key dump.
    let mut targets: Vec<String> = Vec::new();
    if install.npm_packages > 0 {
        let bins = if install.npm_bins > 0 {
            format!(" ({} bin{})", install.npm_bins, plural(install.npm_bins))
        } else {
            String::new()
        };
        targets.push(format!("{}{bins}", install.node_modules.display()));
    }
    if install.pypi_packages > 0 {
        let scripts = if install.python_scripts > 0 {
            format!(
                " ({} script{})",
                install.python_scripts,
                plural(install.python_scripts)
            )
        } else {
            String::new()
        };
        targets.push(format!(
            "{}{scripts}",
            install.python_site_packages.display()
        ));
    }
    let arrow = if targets.is_empty() {
        String::new()
    } else {
        format!("  {} {}", dim("→"), targets.join(", "))
    };
    println!(
        "{} Installed {total} package{}{arrow}",
        paint("✓", GREEN),
        plural(total)
    );
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

pub(crate) fn print_npm_install_json_report(
    project_dir: &Path,
    reports: &[LinkReport],
    install: Option<&InstallReport>,
    dry_run: bool,
    lock_only: bool,
    local_paths: &[PathBuf],
) -> Result<(), OmcRegistryError> {
    println!(
        "{}",
        serde_json::to_string_pretty(&npm_install_json_report(
            project_dir,
            reports,
            install,
            dry_run,
            lock_only,
            local_paths,
        ))?
    );
    Ok(())
}

pub(crate) fn npm_install_json_report(
    project_dir: &Path,
    reports: &[LinkReport],
    install: Option<&InstallReport>,
    dry_run: bool,
    lock_only: bool,
    local_paths: &[PathBuf],
) -> serde_json::Value {
    let add = reports
        .iter()
        .filter(|report| report.locked.ecosystem == Ecosystem::Npm)
        .map(|report| {
            let path = npm_installed_package_dir(project_dir, &report.locked.name)
                .unwrap_or_else(|_| project_dir.join("node_modules").join(&report.locked.name));
            serde_json::json!({
                "name": report.locked.name,
                "version": report.locked.version,
                "path": path,
            })
        })
        .collect::<Vec<_>>();
    let added = install
        .map(|install| install.npm_packages)
        .unwrap_or_else(|| add.len())
        .max(add.len());
    let local = local_paths
        .iter()
        .map(|path| serde_json::json!({ "path": path }))
        .collect::<Vec<_>>();
    let install_json = install.map(|install| {
        serde_json::json!({
            "npm": install.npm_packages,
            "pypi": install.pypi_packages,
            "localSourceArtifacts": install.local_source_artifacts,
            "npmBins": install.npm_bins,
            "pythonScripts": install.python_scripts,
            "nodeModules": install.node_modules,
            "npmBinDir": install.npm_bin_dir,
            "pythonBinDir": install.python_bin_dir,
            "pythonSitePackages": install.python_site_packages,
        })
    });
    serde_json::json!({
        "add": add,
        "added": added,
        "audited": 0,
        "change": [],
        "changed": 0,
        "funding": 0,
        "remove": [],
        "removed": 0,
        "dryRun": dry_run,
        "lockOnly": lock_only,
        "omc": {
            "install": install_json,
            "localPaths": local,
        },
    })
}

pub(crate) fn pip_install_report_json(
    project_dir: &Path,
    install: &InstallReport,
) -> Result<serde_json::Value, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let mut install_entries = lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .map(pip_install_report_entry)
        .collect::<Vec<_>>();
    install_entries.extend(
        lock.local_sources
            .iter()
            .filter(|source| {
                source.ecosystem == Ecosystem::Pypi && source.verdict == Verdict::Accepted
            })
            .map(pip_install_report_local_source_entry),
    );
    let local_sources = lock
        .local_sources
        .iter()
        .filter(|source| source.ecosystem == Ecosystem::Pypi)
        .map(pip_install_report_local_source_omc_entry)
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "version": "1",
        "pip_version": format!("omc-{}", env!("CARGO_PKG_VERSION")),
        "install": install_entries,
        "environment": {
            "implementation_name": "omc",
            "implementation_version": env!("CARGO_PKG_VERSION"),
            "os_name": env::consts::OS,
            "platform_machine": env::consts::ARCH,
            "platform_system": env::consts::OS,
        },
        "omc": {
            "python_site_packages": install.python_site_packages,
            "python_bin_dir": install.python_bin_dir,
            "python_scripts": install.python_scripts,
            "local_source_artifacts": install.local_source_artifacts,
            "pypi_packages": install.pypi_packages,
            "local_sources": local_sources,
        },
    }))
}

fn pip_install_report_entry(package: &LockedPackage) -> serde_json::Value {
    serde_json::json!({
        "download_info": {
            "url": &package.source_url,
            "archive_info": {
                "hashes": {
                    "sha256": &package.sha256,
                },
            },
        },
        "is_direct": false,
        "is_yanked": false,
        "requested": true,
        "metadata": {
            "metadata_version": "2.1",
            "name": &package.name,
            "version": &package.version,
        },
    })
}

fn pip_install_report_local_source_entry(source: &LockedLocalSource) -> serde_json::Value {
    serde_json::json!({
        "download_info": {
            "url": &source.source_url,
            "dir_info": {
                "editable": true,
            },
        },
        "is_direct": true,
        "is_yanked": false,
        "requested": true,
        "metadata": {
            "metadata_version": "2.1",
            "name": &source.name,
            "version": &source.version,
        },
        "omc": pip_install_report_local_source_omc_entry(source),
    })
}

fn pip_install_report_local_source_omc_entry(source: &LockedLocalSource) -> serde_json::Value {
    serde_json::json!({
        "name": &source.name,
        "version": &source.version,
        "source_path": &source.source_path,
        "artifact": &source.artifact,
        "sha256": &source.sha256,
        "behavior": source.behavior,
        "verdict": source.verdict,
        "capabilities": &source.capabilities,
        "verifier_findings": &source.verifier_findings,
    })
}

pub(crate) fn print_audit_report(
    project_dir: &Path,
    json: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let blocked_packages = lock
        .packages
        .iter()
        .filter(|package| package.verdict == Verdict::Blocked)
        .count();
    let blocked_local_sources = lock
        .local_sources
        .iter()
        .filter(|source| source.verdict == Verdict::Blocked)
        .count();
    let blocked = blocked_packages + blocked_local_sources;
    if json {
        let audit = serde_json::json!({
            "packages": lock.packages.len(),
            "local_sources": lock.local_sources.len(),
            "blocked": blocked,
            "blocked_packages": blocked_packages,
            "blocked_local_sources": blocked_local_sources,
            "lock": lock,
        });
        println!("{}", serde_json::to_string_pretty(&audit)?);
    } else {
        println!("packages: {}", lock.packages.len());
        println!("local_sources: {}", lock.local_sources.len());
        println!("blocked: {blocked}");
        for package in lock.packages {
            println!(
                "{} {}:{}@{}",
                verdict_label(package.verdict),
                package.ecosystem,
                package.name,
                package.version
            );
        }
        for source in lock.local_sources {
            println!(
                "{} local-source {}:{}@{} {}",
                verdict_label(source.verdict),
                source.ecosystem,
                source.name,
                source.version,
                source.source_path
            );
        }
    }

    if blocked > 0 {
        return Err(OmcRegistryError::BlockedPackage {
            spec: format!("{blocked} locked package(s)"),
            suggestion: None,
        });
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_link_reports(reports: &[LinkReport]) {
    if is_verbose() {
        for report in reports {
            print_link_report_verbose(report);
        }
        return;
    }
    print_link_reports_terse(reports);
}

/// A scannable per-package tree — each package with a plain-language capability
/// summary — followed by a ⚠ callout naming the packages with security-notable
/// capabilities (code OMC could not statically verify, file writes, process
/// spawns). The full per-finding dump with file paths and evidence lives behind
/// `--verbose`. Blocked packages keep an explicit ✗ line plus their verifier
/// findings, so terse never hides a denial reason.
fn print_link_reports_terse(reports: &[LinkReport]) {
    if reports.is_empty() {
        return;
    }
    let width = reports
        .iter()
        .map(|r| r.locked.name.len() + 1 + r.locked.version.len())
        .max()
        .unwrap_or(0)
        .min(32);

    for report in reports {
        if report.locked.verdict == Verdict::Blocked {
            println!(
                "  {} {} {}  {}",
                paint("✗", RED),
                bold(&report.locked.name),
                report.locked.version,
                paint("blocked", RED)
            );
            for finding in &report.artifact.verifier_findings {
                println!("      {finding}");
            }
            continue;
        }
        let raw = format!("{} {}", report.locked.name, report.locked.version);
        let pad = " ".repeat(width.saturating_sub(raw.len()));
        println!(
            "  {} {}{pad}  {}",
            bold(&report.locked.name),
            report.locked.version,
            capability_summary(report)
        );
    }

    print_risk_callout(reports);
}

/// Plain-language, ` · `-joined summary of what a package can do at runtime, or
/// a dimmed "no host access" when it touches nothing. The unverifiable-code
/// capability is flagged inline with ⚠ because it is the one OMC cannot reason
/// about; the rest read as a capability list (the ⚠ callout below names the
/// notable ones across the whole tree).
fn capability_summary(report: &LinkReport) -> String {
    let mut parts: Vec<String> = Vec::new();
    if has_kind(report, CapabilityKind::HttpRequest) {
        parts.push("network".to_owned());
    }
    if has_kind(report, CapabilityKind::EnvRead) {
        parts.push("reads env".to_owned());
    }
    match (
        has_kind(report, CapabilityKind::FsRead),
        has_kind(report, CapabilityKind::FsWrite),
    ) {
        (true, true) => parts.push("reads & writes files".to_owned()),
        (true, false) => parts.push("reads files".to_owned()),
        (false, true) => parts.push("writes files".to_owned()),
        (false, false) => {}
    }
    if has_kind(report, CapabilityKind::ProcSpawn) {
        parts.push("runs programs".to_owned());
    }
    if has_kind(report, CapabilityKind::DynamicEval) {
        parts.push(format!(
            "{} {}",
            paint("⚠", YELLOW),
            paint("runs unverifiable code", RED)
        ));
    }
    if parts.is_empty() {
        dim("no host access")
    } else {
        parts.join(" · ")
    }
}

/// One ⚠ line per security-notable capability class present anywhere in the
/// tree, naming the packages. Nothing prints when the whole install is benign.
fn print_risk_callout(reports: &[LinkReport]) {
    let names_with = |kind: CapabilityKind| -> Vec<String> {
        reports
            .iter()
            .filter(|r| r.locked.verdict == Verdict::Accepted && has_kind(r, kind))
            .map(|r| bold(&r.locked.name))
            .collect()
    };
    let eval = names_with(CapabilityKind::DynamicEval);
    let write = names_with(CapabilityKind::FsWrite);
    let spawn = names_with(CapabilityKind::ProcSpawn);
    if eval.is_empty() && write.is_empty() && spawn.is_empty() {
        return;
    }
    println!();
    if !eval.is_empty() {
        println!(
            "  {} {} can run code OMC couldn't statically verify (dynamic eval)",
            paint("⚠", YELLOW),
            eval.join(", ")
        );
    }
    if !write.is_empty() {
        println!(
            "  {} {} can write files",
            paint("⚠", YELLOW),
            write.join(", ")
        );
    }
    if !spawn.is_empty() {
        println!(
            "  {} {} can run external programs",
            paint("⚠", YELLOW),
            spawn.join(", ")
        );
    }
}

fn has_kind(report: &LinkReport, kind: CapabilityKind) -> bool {
    report
        .artifact
        .capabilities
        .iter()
        .any(|finding| finding.kind == kind)
}

fn print_link_report_verbose(report: &omc_registry::LinkReport) {
    println!(
        "{} {}:{}@{}",
        verdict_label(report.locked.verdict),
        report.locked.ecosystem,
        report.locked.name,
        report.locked.version
    );
    println!("archive  {}", report.locked.archive);
    println!("artifact {}", report.locked.artifact);
    println!("lockfile {}", report.lockfile.display());

    if !report.artifact.dependencies.is_empty() {
        println!("dependencies: {}", report.artifact.dependencies.join(", "));
    }
    if !report.artifact.optional_dependencies.is_empty() {
        println!(
            "optional dependencies: {}",
            report.artifact.optional_dependencies.join(", ")
        );
    }
    if !report.artifact.peer_dependencies.is_empty() {
        println!(
            "peer dependencies: {}",
            report.artifact.peer_dependencies.join(", ")
        );
    }

    if !report.artifact.capabilities.is_empty() {
        println!("capabilities:");
        for finding in &report.artifact.capabilities {
            println!(
                "  - {} {} from {} ({})",
                finding.kind, finding.target, finding.source, finding.evidence
            );
        }
    }

    if !report.artifact.verifier_findings.is_empty() {
        println!("verifier findings:");
        for finding in &report.artifact.verifier_findings {
            println!("  - {finding}");
        }
    }
}

pub(crate) fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accepted => "accepted",
        Verdict::Blocked => "blocked",
    }
}

pub(crate) fn behavior_label(behavior: Behavior) -> &'static str {
    match behavior {
        Behavior::Pure => "pure",
        Behavior::HostCapability => "host-capability",
    }
}
