//! JSON/text output formatting for the omc CLI.

use crate::*;

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use omc_registry::{
    block_needs, read_lockfile, Behavior, CapabilityKind, Ecosystem, GrantNeed, InstallReport,
    LinkReport, LockedLocalSource, LockedPackage, OmcRegistryError, Verdict,
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

/// Raw per-package dump (artifact paths, dependencies, every capability finding
/// with file + evidence, verifier findings). This is the power-user escape hatch
/// behind `omc add -v`; `omc inspect` uses the readable `format_inspect_report`
/// instead. Kept verbatim so `add -v` output never changes.
fn print_link_report_verbose(report: &omc_registry::LinkReport) {
    print!("{}", format_link_report_verbose(report));
}

/// Pure formatter for the verbose per-package report. Kept separate from the
/// `print!` wrapper so it can be unit-tested against constructed `LinkReport`s
/// without capturing global stdout.
pub(crate) fn format_link_report_verbose(report: &omc_registry::LinkReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} {}:{}@{}",
        verdict_label(report.locked.verdict),
        report.locked.ecosystem,
        report.locked.name,
        report.locked.version
    );
    let _ = writeln!(out, "archive  {}", report.locked.archive);
    let _ = writeln!(out, "artifact {}", report.locked.artifact);
    let _ = writeln!(out, "lockfile {}", report.lockfile.display());

    if !report.artifact.dependencies.is_empty() {
        let _ = writeln!(
            out,
            "dependencies: {}",
            report.artifact.dependencies.join(", ")
        );
    }
    if !report.artifact.optional_dependencies.is_empty() {
        let _ = writeln!(
            out,
            "optional dependencies: {}",
            report.artifact.optional_dependencies.join(", ")
        );
    }
    if !report.artifact.peer_dependencies.is_empty() {
        let _ = writeln!(
            out,
            "peer dependencies: {}",
            report.artifact.peer_dependencies.join(", ")
        );
    }

    if !report.artifact.capabilities.is_empty() {
        let _ = writeln!(out, "capabilities:");
        for finding in &report.artifact.capabilities {
            let _ = writeln!(
                out,
                "  - {} {} from {} ({})",
                finding.kind, finding.target, finding.source, finding.evidence
            );
        }
    }

    if !report.artifact.verifier_findings.is_empty() {
        let _ = writeln!(out, "verifier findings:");
        for finding in &report.artifact.verifier_findings {
            let _ = writeln!(out, "  - {finding}");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// `omc inspect` report — a dependency-tree-first skim layer with a one-line
// headline-risk sentence, expanding per-finding detail blocks only for blocked
// packages. Reuses the plain-language capability vocabulary and color helpers
// above, and the real `omc add` grant builders (block_needs / cli_flag) so the
// unblock lines stay in lock-step with what `omc add` would emit. This is the
// inspect-only renderer; `omc add -v` keeps the raw `format_link_report_verbose`
// dump untouched.
// ---------------------------------------------------------------------------

/// Render the inspect report for a resolved package graph and print it. Called
/// from `omc inspect` instead of the raw verbose dump.
pub(crate) fn print_inspect_report(reports: &[LinkReport]) {
    print!("{}", format_inspect_report(reports));
}

/// Pure formatter for the inspect report, kept separate from the `print!`
/// wrapper so it can be unit-tested against constructed `LinkReport`s.
pub(crate) fn format_inspect_report(reports: &[LinkReport]) -> String {
    format_inspect_report_with(reports, is_verbose())
}

/// Inner formatter taking `verbose` explicitly so both the compact default and
/// the full `--verbose` view are unit-testable without touching the
/// process-global verbosity flag.
pub(crate) fn format_inspect_report_with(reports: &[LinkReport], verbose: bool) -> String {
    use std::fmt::Write as _;
    if reports.is_empty() {
        return String::new();
    }

    // The first resolved report is the requested root; the remainder are its
    // resolved dependency set (one-level tree, matching the chosen design).
    let root = &reports[0];
    let deps = &reports[1..];
    let total = reports.len();
    let blocked = reports
        .iter()
        .filter(|r| r.locked.verdict == Verdict::Blocked)
        .count();

    let mut out = String::new();

    // Banner: glyph + ecosystem:name@version + verdict word + dep count.
    let root_blocked = root.locked.verdict == Verdict::Blocked;
    let (glyph, verdict_word) = if root_blocked {
        (paint("✗", RED), paint("BLOCKED", RED))
    } else {
        (paint("✓", GREEN), paint("OK", GREEN))
    };
    let dep_count = deps.len();
    let dep_suffix = if dep_count > 0 {
        format!("   {}", dim(&format!("+{dep_count} deps")))
    } else {
        String::new()
    };
    let _ = writeln!(
        out,
        "{glyph} {}:{}@{}  {verdict_word}{dep_suffix}",
        root.locked.ecosystem, root.locked.name, root.locked.version
    );

    // One-line bottom-line + headline-risk sentence (only when something is
    // blocked — an all-accepted tree leads with a benign one-liner instead).
    if blocked > 0 {
        let _ = writeln!(
            out,
            "  Installing this tree is denied by default. {blocked} of {total} package{} {} blocked.",
            plural(total),
            if blocked == 1 { "is" } else { "are" }
        );
        if let Some(headline) = headline_risk(root) {
            let _ = writeln!(out, "  {headline}");
        }
    } else {
        let _ = writeln!(
            out,
            "  All {total} package{} are accepted under the deny-by-default policy.",
            plural(total)
        );
    }
    let _ = writeln!(
        out,
        "  {} {}",
        dim("Capability surface:"),
        tree_capability_summary(reports)
    );
    let _ = writeln!(out);

    // The dependency tree (aligned): root + one indented row per dependency,
    // each with its pinned version, verdict glyph, and plain-language summary.
    out.push_str(&render_inspect_tree(root, deps));

    // Per-blocked-package detail. Compact by default (one-line reason, grouped
    // capabilities with files, a single trust grant line); the full per-finding
    // reasons + run-once grant lines are behind `--verbose`.
    if blocked > 0 {
        let _ = writeln!(out);
        for report in reports
            .iter()
            .filter(|r| r.locked.verdict == Verdict::Blocked)
        {
            if verbose {
                out.push_str(&format_inspect_detail_block(report, root));
            } else {
                out.push_str(&format_inspect_detail_block_compact(report, root));
            }
            let _ = writeln!(out);
        }
        let hint = if verbose {
            "Each block lists run-once and trust grant lines above. Nothing was installed."
        } else {
            "Re-run with -v for every finding + run-once grant lines. Nothing was installed."
        };
        let _ = writeln!(out, "  {}", dim(hint));
    } else {
        let _ = writeln!(
            out,
            "  {}",
            dim("Nothing was installed — inspect is read-only.")
        );
    }

    out
}

/// The aligned one-level dependency tree: the root, then each dependency, every
/// row padded so the verdict column lines up regardless of the `├─`/`└─`
/// connector or the name/version length.
fn render_inspect_tree(root: &LinkReport, deps: &[LinkReport]) -> String {
    let label_len = |connector: &str, r: &LinkReport| {
        connector.chars().count()
            + r.locked.name.chars().count()
            + 1
            + r.locked.version.chars().count()
    };
    let mut width = label_len("", root);
    for dep in deps {
        width = width.max(label_len("├─ ", dep));
    }
    let mut out = String::new();
    inspect_tree_row(&mut out, "", root, width);
    for (idx, dep) in deps.iter().enumerate() {
        let connector = if idx + 1 == deps.len() {
            "└─ "
        } else {
            "├─ "
        };
        inspect_tree_row(&mut out, connector, dep, width);
    }
    out
}

fn inspect_tree_row(out: &mut String, connector: &str, report: &LinkReport, width: usize) {
    use std::fmt::Write as _;
    let visible = connector.chars().count()
        + report.locked.name.chars().count()
        + 1
        + report.locked.version.chars().count();
    let pad = " ".repeat(width.saturating_sub(visible) + 2);
    let _ = writeln!(
        out,
        "  {connector}{} {}{pad}{}",
        bold(&report.locked.name),
        report.locked.version,
        tree_row_verdict(report)
    );
}

/// Compact per-blocked-package block: relation header, a one-line plain-language
/// reason, the grouped runtime capabilities (with files — inspect's reason to
/// exist), a one-line unverifiable-code site list, and a single `omc trust`
/// grant line. The exhaustive per-finding callouts + run-once grant variant are
/// the `--verbose` block instead.
fn format_inspect_detail_block_compact(report: &LinkReport, root: &LinkReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let locked = &report.locked;
    let relation = if locked.name == root.locked.name && locked.version == root.locked.version {
        "root".to_owned()
    } else {
        format!("dep of {}", root.locked.name)
    };
    let _ = writeln!(
        out,
        "  {} {} {} {} {relation}",
        paint("✗", RED),
        bold(&locked.name),
        locked.version,
        dim("—")
    );

    let (needs, unknown) = block_needs(&locked.verifier_findings);
    let reason = compact_block_reason(&needs, &unknown);
    if !reason.is_empty() {
        let _ = writeln!(out, "    {} {reason}", paint("blocked:", RED));
    }

    // Grouped runtime capabilities, files comma-joined (no truncation).
    let runtime = grouped_runtime_capabilities(report);
    if !runtime.is_empty() {
        let label_width = runtime.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
        for (label, files) in &runtime {
            let _ = writeln!(out, "      {label:<label_width$}  {files}");
        }
    }

    // Unverifiable-code sites condensed to one line (per-site evidence is in -v).
    let mut eval_files: Vec<&str> = Vec::new();
    let mut eval_sites = 0usize;
    for finding in &report.artifact.capabilities {
        if finding.kind == CapabilityKind::DynamicEval {
            eval_sites += 1;
            if !eval_files.contains(&finding.source.as_str()) {
                eval_files.push(finding.source.as_str());
            }
        }
    }
    if eval_sites > 0 {
        let _ = writeln!(
            out,
            "      {} {} — {eval_sites} site{} in {}",
            paint("⚠", YELLOW),
            paint("runs unverifiable code", RED),
            plural(eval_sites),
            eval_files.join(", ")
        );
    }

    // A single grant line (trust), built from the real `omc add` grant tokens.
    let flags: Vec<String> = needs.iter().map(|n| n.cli_flag.clone()).collect();
    if !flags.is_empty() {
        let _ = writeln!(
            out,
            "    {} omc trust {}:{}@{} {}",
            dim("unblock:"),
            locked.ecosystem,
            locked.name,
            locked.version,
            flags.join(" ")
        );
    }

    out
}

/// One short clause per distinct danger (deduped, order-preserving), e.g.
/// "send env vars to the network; run unverifiable code; write files". Falls
/// back to a generic clause if only unrecognized findings are present, so a
/// blocked package never shows an empty reason.
fn compact_block_reason(needs: &[GrantNeed], unknown: &[String]) -> String {
    let mut clauses: Vec<String> = Vec::new();
    for need in needs.iter().filter(|n| n.dangerous) {
        let flag = need.cli_flag.as_str();
        let clause: &str = if flag.contains("--allow-flow") {
            if flag.contains("->network") {
                if flag.contains("env:") {
                    "send env vars to the network"
                } else {
                    "send file contents to the network"
                }
            } else if flag.contains("->dynamic_eval") {
                "feed data to code it can't verify"
            } else if flag.contains("->file") {
                "copy file contents between files"
            } else {
                need.human.as_str()
            }
        } else if flag.contains("dynamic.eval") {
            "run unverifiable code"
        } else if flag.contains("fs.write") {
            "write files"
        } else if flag.contains("proc") {
            "spawn processes"
        } else {
            need.human.as_str()
        };
        if !clauses.iter().any(|c| c == clause) {
            clauses.push(clause.to_owned());
        }
    }
    if clauses.is_empty() && !unknown.is_empty() {
        clauses.push("violate the default policy".to_owned());
    }
    clauses.join("; ")
}

/// The headline-risk sentence: a single human sentence describing the most
/// alarming shape the root package exhibits (env→network exfiltration, then
/// unverifiable code), borrowed from the chosen design. `None` when the root has
/// nothing notable to lead with.
fn headline_risk(root: &LinkReport) -> Option<String> {
    let findings = &root.locked.verifier_findings;
    let has_env_to_net = findings
        .iter()
        .any(|f| f.contains("env:") && f.contains("may not flow to") && f.contains("network:"));
    let has_eval = has_kind(root, CapabilityKind::DynamicEval);
    if has_env_to_net && has_eval {
        return Some(format!(
            "Headline risk: {} can send your environment variables to the network (the classic credential-exfiltration shape) and runs code OMC can't verify.",
            root.locked.name
        ));
    }
    if has_env_to_net {
        return Some(format!(
            "Headline risk: {} can send your environment variables to the network — the classic credential-exfiltration shape.",
            root.locked.name
        ));
    }
    if has_eval {
        return Some(format!(
            "Headline risk: {} runs dynamically generated code OMC could not statically verify.",
            root.locked.name
        ));
    }
    None
}

/// `✗ blocked   <caps>` / `✓ accepted  <caps>` for a tree row, where `<caps>` is
/// the plain-language capability summary (or "no host access" for benign deps).
fn tree_row_verdict(report: &LinkReport) -> String {
    let caps = capability_summary(report);
    if report.locked.verdict == Verdict::Blocked {
        format!("{} {}   {caps}", paint("✗", RED), paint("blocked", RED))
    } else {
        format!("{} {}  {caps}", paint("✓", GREEN), paint("accepted", GREEN))
    }
}

/// The `Capability surface` summary line — the union of every capability class
/// present anywhere in the tree, plain-language and ` · `-joined, with the
/// unverifiable-code class flagged ⚠ (it is the one OMC cannot reason about).
fn tree_capability_summary(reports: &[LinkReport]) -> String {
    let any = |kind: CapabilityKind| reports.iter().any(|r| has_kind(r, kind));
    let mut parts: Vec<String> = Vec::new();
    if any(CapabilityKind::HttpRequest) {
        parts.push("network".to_owned());
    }
    if any(CapabilityKind::EnvRead) {
        parts.push("reads env".to_owned());
    }
    match (any(CapabilityKind::FsRead), any(CapabilityKind::FsWrite)) {
        (true, true) => parts.push("reads & writes files".to_owned()),
        (true, false) => parts.push("reads files".to_owned()),
        (false, true) => parts.push("writes files".to_owned()),
        (false, false) => {}
    }
    if any(CapabilityKind::ProcSpawn) {
        parts.push("runs programs".to_owned());
    }
    if any(CapabilityKind::DynamicEval) {
        parts.push(format!(
            "{} {}",
            paint("⚠", YELLOW),
            paint("runs unverifiable code", RED)
        ));
    }
    if parts.is_empty() {
        dim("no host access")
    } else {
        parts.join(&format!(" {} ", dim("·")))
    }
}

/// One expanded detail block for a blocked package: the relation header, the
/// plain-language "Blocked because it wants to:" reasons (each with its raw
/// token + risk callout), the grouped runtime capability rows, the ⚠
/// unverifiable-code site list, and the exact run-once / trust grant lines built
/// from the real `omc add` grant tokens.
fn format_inspect_detail_block(report: &LinkReport, root: &LinkReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let locked = &report.locked;

    // Relation header: "root" or "dep of <root-name>", computed from whether
    // this report IS the root of the inspected graph.
    let relation = if locked.name == root.locked.name && locked.version == root.locked.version {
        "root".to_owned()
    } else {
        format!("dep of {}", root.locked.name)
    };
    let _ = writeln!(
        out,
        "  {} {} {}   {} {} {relation}",
        paint("✗", RED),
        bold(&locked.name),
        locked.version,
        paint("blocked", RED),
        dim("—")
    );

    // Block reasons — every verifier finding mapped 1:1 to a human line, with
    // the raw token preserved in parens and a risk callout below. Unrecognized
    // findings still print as `! {raw}` so nothing silently vanishes.
    let (needs, unknown) = block_needs(&locked.verifier_findings);
    if !needs.is_empty() || !unknown.is_empty() {
        let _ = writeln!(out, "    Blocked because it wants to:");
        for need in &needs {
            let marker = if need.dangerous {
                paint("!", RED)
            } else {
                " ".to_owned()
            };
            let _ = writeln!(out, "      {marker} {}   ({})", need.human, dim(&need.raw));
            if let Some(risk) = &need.risk {
                let _ = writeln!(out, "        {} {}", dim("└"), dim(risk));
            }
        }
        for raw in &unknown {
            let _ = writeln!(out, "      {} {}", paint("!", RED), raw);
        }
    }

    // Runtime capabilities, grouped by kind, files comma-joined (no truncation,
    // no "*" target dump). DynamicEval is rendered separately below as the ⚠
    // callout, keeping one line per site with its distinctive evidence.
    let runtime = grouped_runtime_capabilities(report);
    if !runtime.is_empty() {
        let _ = writeln!(out, "    Can do at runtime:");
        let label_width = runtime.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
        for (label, files) in &runtime {
            let _ = writeln!(out, "      {label:<label_width$}  {files}");
        }
    }

    // ⚠ unverifiable-code callout: one line per DynamicEval site, source +
    // verbatim distinctive evidence. Never collapsed.
    let eval_sites: Vec<&omc_registry::CapabilityFinding> = report
        .artifact
        .capabilities
        .iter()
        .filter(|f| f.kind == CapabilityKind::DynamicEval)
        .collect();
    if !eval_sites.is_empty() {
        let _ = writeln!(
            out,
            "    {} {} — {} site{} OMC could not statically verify:",
            paint("⚠", YELLOW),
            paint("runs unverifiable code", RED),
            eval_sites.len(),
            plural(eval_sites.len())
        );
        let src_width = eval_sites.iter().map(|f| f.source.len()).max().unwrap_or(0);
        for site in &eval_sites {
            let _ = writeln!(out, "      {:<src_width$}   {}", site.source, site.evidence);
        }
    }

    // Grant hints, built from the REAL `omc add` grant tokens so they match what
    // `omc add` would emit exactly. The flags carry the same `--allow` /
    // `--allow-flow` shapes used by build_block_suggestion.
    let flags: Vec<String> = needs.iter().map(|n| n.cli_flag.clone()).collect();
    if !flags.is_empty() {
        let _ = writeln!(out, "    To allow it for THIS run only:");
        let _ = writeln!(
            out,
            "      omc add {}:{}@{} \\",
            locked.ecosystem, locked.name, locked.version
        );
        let _ = writeln!(out, "        {}", flags.join(" \\\n        "));
        let _ = writeln!(
            out,
            "    To trust {} {} everywhere:",
            locked.name, locked.version
        );
        let _ = writeln!(
            out,
            "      omc trust {}:{}@{} {}",
            locked.ecosystem,
            locked.name,
            locked.version,
            flags.join(" ")
        );
    }

    out
}

/// Group a report's non-eval runtime capability findings by plain-language label,
/// each with its source files comma-joined (deduplicated, order-preserving). The
/// uniform "*" target and uniform evidence are dropped — the label encodes them —
/// but EVERY source file is retained (the design forbids truncation in inspect).
fn grouped_runtime_capabilities(report: &LinkReport) -> Vec<(&'static str, String)> {
    let mut rows: Vec<(&'static str, String)> = Vec::new();
    let mut push = |label: &'static str, kinds: &[CapabilityKind]| {
        let mut files: Vec<&str> = Vec::new();
        for finding in &report.artifact.capabilities {
            if kinds.contains(&finding.kind) && !files.contains(&finding.source.as_str()) {
                files.push(finding.source.as_str());
            }
        }
        if !files.is_empty() {
            rows.push((label, files.join(", ")));
        }
    };
    push("network", &[CapabilityKind::HttpRequest]);
    push("reads env", &[CapabilityKind::EnvRead]);
    let has_read = has_kind(report, CapabilityKind::FsRead);
    let has_write = has_kind(report, CapabilityKind::FsWrite);
    match (has_read, has_write) {
        (true, true) => {
            push("reads files", &[CapabilityKind::FsRead]);
            push("writes files", &[CapabilityKind::FsWrite]);
        }
        (true, false) => push("reads files", &[CapabilityKind::FsRead]),
        (false, true) => push("writes files", &[CapabilityKind::FsWrite]),
        (false, false) => {}
    }
    push("runs programs", &[CapabilityKind::ProcSpawn]);
    rows
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
