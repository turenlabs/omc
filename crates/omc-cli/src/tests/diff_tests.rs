//! Tests for `omc diff`: argument parsing, the capability/dependency delta
//! computation, the escalation rule, the JSON shape, and the text renderer.
//! Deterministic and network-free — everything is exercised against
//! hand-constructed `LinkReport`s.

use super::*;

use std::path::PathBuf;

use omc_registry::{
    Behavior, CapabilityFinding, CapabilityKind, Ecosystem, LinkReport, LockedPackage, OmcArtifact,
    Verdict,
};

use crate::diff::{diff_json, diff_reports};
use crate::render::format_diff_report;

fn cap(kind: CapabilityKind, target: &str, source: &str) -> CapabilityFinding {
    CapabilityFinding {
        kind,
        target: target.to_owned(),
        source: source.to_owned(),
        evidence: "test evidence".to_owned(),
    }
}

/// Hand-constructed `LinkReport` (no compile/network), mirroring the inspect
/// test fixture.
fn link_report(
    name: &str,
    version: &str,
    verdict: Verdict,
    capabilities: Vec<CapabilityFinding>,
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
        verifier_findings: Vec::new(),
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
        verifier_findings: Vec::new(),
    };
    LinkReport {
        locked,
        artifact,
        lockfile: PathBuf::from("/scratch/omc.lock"),
        manifest: PathBuf::from("/scratch/omc.toml"),
    }
}

/// old: pkg@1.0.0 + helper@1.0.0 (env read) + gone@0.1.0
/// new: pkg@2.0.0 + helper@2.0.0 (env read AND proc spawn) + fresh@1.0.0 (network)
fn escalating_sides() -> (Vec<LinkReport>, Vec<LinkReport>) {
    let old = vec![
        link_report("pkg", "1.0.0", Verdict::Accepted, Vec::new()),
        link_report(
            "helper",
            "1.0.0",
            Verdict::Accepted,
            vec![cap(CapabilityKind::EnvRead, "HOME", "lib/env.js")],
        ),
        link_report("gone", "0.1.0", Verdict::Accepted, Vec::new()),
    ];
    let new = vec![
        link_report("pkg", "2.0.0", Verdict::Accepted, Vec::new()),
        link_report(
            "helper",
            "2.0.0",
            Verdict::Accepted,
            vec![
                cap(CapabilityKind::EnvRead, "HOME", "lib/env.js"),
                cap(CapabilityKind::ProcSpawn, "*", "lib/postinstall.js"),
            ],
        ),
        link_report(
            "fresh",
            "1.0.0",
            Verdict::Accepted,
            vec![cap(
                CapabilityKind::HttpRequest,
                "example.com",
                "lib/net.js",
            )],
        ),
    ];
    (old, new)
}

#[test]
fn diff_parses_args() {
    let cli = Cli::try_parse_from(args(&[
        "omc",
        "diff",
        "npm:lodash@4.17.20",
        "npm:lodash@4.17.21",
        "--json",
    ]))
    .unwrap();
    match cli.command {
        Command::Diff {
            old_spec,
            new_spec,
            json,
            ..
        } => {
            assert_eq!(old_spec, "npm:lodash@4.17.20");
            assert_eq!(new_spec, "npm:lodash@4.17.21");
            assert!(json);
        }
        other => panic!("expected diff command, got {other:?}"),
    }
}

#[test]
fn diff_computes_capability_and_package_deltas() {
    let (old, new) = escalating_sides();
    let diff = diff_reports("npm:pkg@1.0.0", "npm:pkg@2.0.0", &old, &new);

    // Capability additions are keyed by (package, kind, target): helper's
    // pre-existing env read does NOT reappear, its new proc spawn and fresh's
    // network access do.
    assert_eq!(diff.added_capabilities.len(), 2);
    assert!(diff
        .added_capabilities
        .iter()
        .any(|c| c.package == "helper" && c.kind == CapabilityKind::ProcSpawn));
    assert!(diff
        .added_capabilities
        .iter()
        .any(|c| c.package == "fresh" && c.kind == CapabilityKind::HttpRequest));
    assert!(diff.removed_capabilities.is_empty());

    // Package deltas: fresh added, gone removed, helper changed — and the
    // diffed root's own version bump is NOT listed as a dependency change.
    assert_eq!(
        diff.added_packages,
        vec![("fresh".to_owned(), "1.0.0".to_owned())]
    );
    assert_eq!(
        diff.removed_packages,
        vec![("gone".to_owned(), "0.1.0".to_owned())]
    );
    assert_eq!(diff.changed_packages.len(), 1);
    assert_eq!(diff.changed_packages[0].name, "helper");
    assert_eq!(diff.changed_packages[0].old_version, "1.0.0");
    assert_eq!(diff.changed_packages[0].new_version, "2.0.0");

    assert_eq!(diff.old.resolved, "npm:pkg@1.0.0");
    assert_eq!(diff.new.resolved, "npm:pkg@2.0.0");
    assert!(diff.escalates());
}

#[test]
fn diff_version_bump_without_new_capabilities_does_not_escalate() {
    let old = vec![
        link_report("pkg", "1.0.0", Verdict::Accepted, Vec::new()),
        link_report(
            "helper",
            "1.0.0",
            Verdict::Accepted,
            vec![cap(CapabilityKind::EnvRead, "HOME", "lib/env.js")],
        ),
    ];
    let new = vec![
        link_report("pkg", "1.0.1", Verdict::Accepted, Vec::new()),
        link_report(
            "helper",
            "1.0.0",
            Verdict::Accepted,
            vec![cap(CapabilityKind::EnvRead, "HOME", "lib/env.js")],
        ),
    ];
    let diff = diff_reports("npm:pkg@1.0.0", "npm:pkg@1.0.1", &old, &new);

    assert!(diff.added_capabilities.is_empty());
    assert!(diff.removed_capabilities.is_empty());
    assert!(diff.added_packages.is_empty());
    assert!(diff.removed_packages.is_empty());
    assert!(
        diff.changed_packages.is_empty(),
        "root bump is not a dep change"
    );
    assert!(!diff.escalates());

    let rendered = format_diff_report(&diff, &old, &new);
    assert!(
        rendered.contains("No new capabilities"),
        "clean upgrade lead line: {rendered}"
    );
    assert!(
        rendered.contains("npm:pkg@1.0.0") && rendered.contains("npm:pkg@1.0.1"),
        "banner names both resolved sides: {rendered}"
    );
}

#[test]
fn diff_newly_blocked_tree_escalates_even_without_new_capabilities() {
    let old = vec![link_report("pkg", "1.0.0", Verdict::Accepted, Vec::new())];
    let new = vec![link_report("pkg", "2.0.0", Verdict::Blocked, Vec::new())];
    let diff = diff_reports("npm:pkg@1.0.0", "npm:pkg@2.0.0", &old, &new);
    assert!(diff.escalates(), "more blocked packages is an escalation");

    let rendered = format_diff_report(&diff, &old, &new);
    assert!(
        rendered.contains("1 of 1 blocked"),
        "new-side verdict: {rendered}"
    );
    assert!(
        rendered.contains("omc inspect npm:pkg@2.0.0 -v"),
        "pointer to the full report: {rendered}"
    );
}

#[test]
fn diff_report_renders_capability_changes_with_evidence() {
    let (old, new) = escalating_sides();
    let diff = diff_reports("npm:pkg@1.0.0", "npm:pkg@2.0.0", &old, &new);
    let rendered = format_diff_report(&diff, &old, &new);

    assert!(
        rendered.contains("New capabilities (2):"),
        "additions header: {rendered}"
    );
    assert!(
        rendered.contains("runs programs") && rendered.contains("helper"),
        "plain-language addition row: {rendered}"
    );
    assert!(
        rendered.contains("lib/postinstall.js"),
        "evidence file retained: {rendered}"
    );
    assert!(
        rendered.contains("Dependency changes:"),
        "dependency section: {rendered}"
    );
    assert!(rendered.contains("+ fresh 1.0.0"), "added row: {rendered}");
    assert!(rendered.contains("- gone 0.1.0"), "removed row: {rendered}");
    assert!(
        rendered.contains("~ helper 1.0.0 → 2.0.0"),
        "changed row: {rendered}"
    );
    assert!(
        rendered.contains("Read-only diff"),
        "read-only line: {rendered}"
    );
}

#[test]
fn diff_json_carries_the_escalation_signal() {
    let (old, new) = escalating_sides();
    let diff = diff_reports("npm:pkg@1.0.0", "npm:pkg@2.0.0", &old, &new);
    let json = diff_json(&diff);

    assert_eq!(json["escalation"], serde_json::json!(true));
    assert_eq!(json["old"]["resolved"], serde_json::json!("npm:pkg@1.0.0"));
    assert_eq!(json["new"]["resolved"], serde_json::json!("npm:pkg@2.0.0"));
    assert_eq!(json["added_capabilities"].as_array().unwrap().len(), 2);
    assert!(json["added_capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["kind"] == serde_json::json!("proc_spawn")));
    assert_eq!(
        json["changed_packages"],
        serde_json::json!([{"name": "helper", "old_version": "1.0.0", "new_version": "2.0.0"}])
    );
}
