//! Tests for `omc scan`: argument parsing, manifest detection, the
//! never-touch-the-scanned-project guarantee, report deduplication, and the
//! scan report renderer. Deterministic and network-free — the renderer is
//! exercised against hand-constructed `LinkReport`s, and the no-write contract
//! is checked on pre-resolution error branches so no live registry is
//! contacted.

use super::*;

use std::path::PathBuf;

use omc_registry::{
    Behavior, CapabilityFinding, CapabilityKind, Ecosystem, LinkReport, LockedPackage, OmcArtifact,
    OmcRegistryError, Verdict,
};

use crate::render::format_scan_report;
use crate::scan::{dedupe_reports, detect_scan_manifests, run_scan, ScanCommand};

fn scan_command() -> ScanCommand {
    ScanCommand {
        json: false,
        omit_dev: false,
        allow: Vec::new(),
        allow_flow: Vec::new(),
        allow_all_host: false,
    }
}

fn cap(kind: CapabilityKind, source: &str) -> CapabilityFinding {
    CapabilityFinding {
        kind,
        target: "*".to_owned(),
        source: source.to_owned(),
        evidence: "test evidence".to_owned(),
    }
}

/// Hand-constructed `LinkReport` (no compile/network), mirroring the inspect
/// test fixture, so the scan renderer can be exercised against a controlled
/// package set.
fn link_report(
    name: &str,
    version: &str,
    verdict: Verdict,
    capabilities: Vec<CapabilityFinding>,
    verifier_findings: Vec<String>,
) -> LinkReport {
    let behavior = if capabilities.is_empty() {
        Behavior::Pure
    } else {
        Behavior::HostCapability
    };
    let artifact = OmcArtifact {
        schema: 1,
        package: omc_registry::ArtifactPackage {
            ecosystem: Ecosystem::Npm,
            name: name.to_owned(),
            version: version.to_owned(),
        },
        source_url: String::new(),
        source_sha256: String::new(),
        compiler: "test".to_owned(),
        microcode: omc_format::Module {
            id: String::new(),
            package: name.to_owned(),
            version: version.to_owned(),
            declared_behavior: omc_format::BehaviorType::Pure,
            functions: Vec::new(),
        },
        behavior,
        verdict,
        grants: Vec::new(),
        dependencies: Vec::new(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        files_scanned: 0,
        capabilities: capabilities.clone(),
        verifier_findings: verifier_findings.clone(),
        signature: None,
    };
    let locked = LockedPackage {
        ecosystem: Ecosystem::Npm,
        name: name.to_owned(),
        version: version.to_owned(),
        source_url: String::new(),
        archive: format!("cache/{name}-{version}.tgz"),
        artifact: format!(".omc/artifacts/{name}-{version}.json"),
        sha256: "0".repeat(64),
        artifact_sha256: String::new(),
        behavior,
        verdict,
        dependencies: Vec::new(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        grants: Vec::new(),
        capabilities,
        verifier_findings,
    };
    LinkReport {
        locked,
        artifact,
        lockfile: PathBuf::from("/scratch/omc.lock"),
        manifest: PathBuf::from("/scratch/omc.toml"),
    }
}

#[test]
fn scan_parses_args() {
    let cli = Cli::try_parse_from(args(&["omc", "scan", "--json", "--omit-dev"])).unwrap();
    match cli.command {
        Command::Scan { json, omit_dev, .. } => {
            assert!(json);
            assert!(omit_dev);
        }
        other => panic!("expected scan command, got {other:?}"),
    }

    let cli = Cli::try_parse_from(args(&["omc", "scan"])).unwrap();
    match cli.command {
        Command::Scan { json, omit_dev, .. } => {
            assert!(!json);
            assert!(!omit_dev);
        }
        other => panic!("expected scan command, got {other:?}"),
    }
}

#[test]
fn detect_scan_manifests_lists_present_files_including_nested() {
    let dir = test_dir("scan-detect");
    fs::write(dir.join("package.json"), "{}").unwrap();
    fs::write(dir.join("requirements.txt"), "").unwrap();
    fs::create_dir_all(dir.join("requirements")).unwrap();
    fs::write(dir.join("requirements").join("base.txt"), "").unwrap();

    let manifests = detect_scan_manifests(&dir);
    assert!(manifests.contains(&"package.json".to_owned()));
    assert!(manifests.contains(&"requirements.txt".to_owned()));
    assert!(manifests.contains(&"requirements/base.txt".to_owned()));
    assert!(!manifests.contains(&"poetry.lock".to_owned()));

    let _ = fs::remove_dir_all(&dir);
}

/// A directory with no recognizable manifests is a usage error, not a silent
/// "scanned 0 packages, all clean" — pointing scan at the wrong directory in CI
/// must not read as success.
#[test]
fn scan_of_empty_dir_is_an_error_and_writes_nothing() {
    let dir = test_dir("scan-empty");
    let result = run_scan(&dir, scan_command());
    assert!(
        matches!(result, Err(OmcRegistryError::Usage(_))),
        "expected usage error, got {result:?}"
    );
    assert!(!dir.join("omc.lock").exists());
    assert!(!dir.join("omc.toml").exists());
    let _ = fs::remove_dir_all(&dir);
}

/// READ-ONLY guarantee: a scan that fails during discovery (unparseable
/// package.json, before any registry resolution) must not create omc.lock,
/// omc.toml, or node_modules in the scanned project.
#[test]
fn scan_never_writes_into_scanned_project_on_error_path() {
    let dir = test_dir("scan-bad-manifest");
    fs::write(dir.join("package.json"), "{ this is not json").unwrap();

    let result = run_scan(&dir, scan_command());
    assert!(result.is_err(), "a broken manifest must error, not resolve");
    assert!(
        !dir.join("omc.lock").exists(),
        "scan must not write omc.lock into the scanned project"
    );
    assert!(
        !dir.join("omc.toml").exists(),
        "scan must not write omc.toml into the scanned project"
    );
    assert!(
        !dir.join("node_modules").exists(),
        "scan must not create node_modules in the scanned project"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn dedupe_reports_keeps_first_per_package_version() {
    let reports = vec![
        link_report("dup", "1.0.0", Verdict::Blocked, Vec::new(), Vec::new()),
        link_report("dup", "1.0.0", Verdict::Accepted, Vec::new(), Vec::new()),
        link_report("dup", "2.0.0", Verdict::Accepted, Vec::new(), Vec::new()),
        link_report("other", "1.0.0", Verdict::Accepted, Vec::new(), Vec::new()),
    ];
    let deduped = dedupe_reports(reports);
    assert_eq!(deduped.len(), 3);
    // The first report for dup@1.0.0 (the blocked one) is the one retained.
    assert_eq!(deduped[0].locked.verdict, Verdict::Blocked);
}

#[test]
fn scan_report_renders_blocked_first_with_details_and_no_relation() {
    let reports = vec![
        link_report(
            "good-pkg",
            "1.0.0",
            Verdict::Accepted,
            Vec::new(),
            Vec::new(),
        ),
        link_report(
            "evil-pkg",
            "6.6.6",
            Verdict::Blocked,
            vec![cap(CapabilityKind::ProcSpawn, "lib/install.js")],
            vec!["package_init[0]: capability proc:* not granted".to_owned()],
        ),
    ];
    let rendered = format_scan_report(
        Path::new("/proj"),
        &["package-lock.json".to_owned()],
        &reports,
        0,
        false,
    );

    assert!(rendered.contains("scan of /proj"), "banner: {rendered}");
    assert!(rendered.contains("BLOCKED"), "verdict word: {rendered}");
    assert!(
        rendered.contains("package-lock.json"),
        "manifest names: {rendered}"
    );
    assert!(
        rendered.contains("1 of 2 packages is blocked"),
        "blocked count: {rendered}"
    );
    assert!(
        rendered.contains("Capability surface:"),
        "surface line: {rendered}"
    );

    // Blocked packages list before accepted ones.
    let evil = rendered.find("evil-pkg").expect("evil-pkg row");
    let good = rendered.find("good-pkg").expect("good-pkg row");
    assert!(evil < good, "blocked rows come first: {rendered}");

    // The inspect-style review block appears, without a tree relation note
    // (scan has no single root).
    assert!(
        rendered.contains("Review") && rendered.contains("evil-pkg"),
        "review block: {rendered}"
    );
    assert!(
        !rendered.contains("(root)") && !rendered.contains("(dep of"),
        "no relation note in scan: {rendered}"
    );
    assert!(
        rendered.contains("lib/install.js"),
        "capability evidence file retained: {rendered}"
    );
    assert!(
        rendered.contains("Read-only scan"),
        "read-only line: {rendered}"
    );
}

#[test]
fn scan_report_all_accepted_shows_risk_callout_and_ok() {
    let reports = vec![
        link_report("benign", "1.0.0", Verdict::Accepted, Vec::new(), Vec::new()),
        link_report(
            "writer",
            "2.0.0",
            Verdict::Accepted,
            vec![cap(CapabilityKind::FsWrite, "lib/out.js")],
            Vec::new(),
        ),
    ];
    let rendered = format_scan_report(
        Path::new("/proj"),
        &["requirements.txt".to_owned()],
        &reports,
        0,
        false,
    );

    assert!(rendered.contains("OK"), "verdict word: {rendered}");
    assert!(
        rendered.contains("All 2 packages are accepted"),
        "summary: {rendered}"
    );
    assert!(
        rendered.contains("can write files"),
        "risk callout names the notable capability: {rendered}"
    );
    assert!(
        !rendered.contains("Review"),
        "no review blocks when nothing is blocked: {rendered}"
    );
    assert!(
        rendered.contains("no host access"),
        "benign row: {rendered}"
    );
}

#[test]
fn scan_report_surfaces_skipped_vcs_requirements() {
    let reports = vec![link_report(
        "benign",
        "1.0.0",
        Verdict::Accepted,
        Vec::new(),
        Vec::new(),
    )];
    let rendered = format_scan_report(
        Path::new("/proj"),
        &["requirements.txt".to_owned()],
        &reports,
        2,
        false,
    );
    assert!(
        rendered.contains("2 git/VCS requirements skipped"),
        "skipped inputs must be named, never silent: {rendered}"
    );
}
