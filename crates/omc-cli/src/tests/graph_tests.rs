//! Tests for `omc graph`: building the directed dependency graph from
//! `LinkReport`s and rendering it to a valid PNG. Deterministic and
//! network-free — reports are built from real LOCAL source compiles
//! (`compile_source_path`, no registry/network) and the renderer is exercised
//! against those hand-wired reports plus a temp output path.

use super::*;

use std::path::PathBuf;

use omc_registry::{
    compile_source_path, CapabilityKind, CompileSourceOptions, Ecosystem, LinkReport, LockedPackage,
};

use crate::args::InspectFormat;
use crate::graph::{render_graph, DependencyGraph, Risk};
use crate::inspect::{run_inspect, InspectCommand};

/// Compile a small source file (local, no network) into a `LinkReport` named
/// `name`, declaring `deps` (already-qualified spec strings) as its production
/// dependencies. `body` controls which capabilities the package exhibits.
fn report(name: &str, body: &str, deps: &[&str]) -> LinkReport {
    let dir = test_dir(&format!("graph-fixture-{name}"));
    let source = dir.join("source");
    fs::create_dir_all(&source).unwrap();
    // batou:ignore file_write -- test fixture: `body` is file CONTENT (not a path) written to a fixed
    // filename inside a freshly-created unique temp dir; no external input reaches the path.
    fs::write(source.join("index.js"), body).unwrap();

    let compiled = compile_source_path(CompileSourceOptions {
        project_dir: dir.clone(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        // Grant everything so capability findings are recorded (and the package
        // is accepted) rather than the source being rejected outright; the graph
        // colors by capability presence regardless of verdict.
        allowed_capabilities: Vec::new(),
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap();
    let mut artifact = compiled.artifact;
    artifact.dependencies = deps.iter().map(|d| (*d).to_owned()).collect();

    let locked = LockedPackage {
        ecosystem: Ecosystem::Npm,
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        source_url: artifact.source_url.clone(),
        archive: format!("cache/{name}-1.0.0.tgz"),
        artifact: format!(".omc/artifacts/{name}-1.0.0.json"),
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
    // batou:ignore file_write -- test cleanup: `dir` is the unique temp dir this helper created
    // via test_dir(); it is not derived from external input.
    let _ = fs::remove_dir_all(&dir);
    link_report
}

/// A root that spawns a process (HIGH risk) depending on a benign leaf (GREY).
fn sample_reports() -> Vec<LinkReport> {
    let root = report(
        "root",
        "const cp = require('child_process');\ncp.execSync('echo hi');\n",
        &["npm:leaf@1.0.0"],
    );
    let leaf = report(
        "leaf",
        "module.exports = function (a) { return a + 1; };\n",
        &[],
    );
    vec![root, leaf]
}

#[test]
fn graph_builds_nodes_and_edges_from_reports() {
    let reports = sample_reports();
    let graph = DependencyGraph::from_reports(&reports);

    assert_eq!(graph.nodes.len(), 2, "one node per package");
    assert_eq!(graph.edges.len(), 1, "root -> leaf edge");

    let root_idx = graph
        .nodes
        .iter()
        .position(|n| n.name == "root")
        .expect("root node present");
    let leaf_idx = graph
        .nodes
        .iter()
        .position(|n| n.name == "leaf")
        .expect("leaf node present");

    assert!(
        graph.edges.contains(&(root_idx, leaf_idx)),
        "edge points from root to its leaf dependency: {:?}",
        graph.edges
    );

    // BFS depth places the dependency one layer to the right of its parent.
    assert_eq!(graph.nodes[root_idx].depth, 0);
    assert_eq!(graph.nodes[leaf_idx].depth, 1);
}

#[test]
fn risk_classification_matches_capabilities() {
    let proc = report(
        "spawner",
        "const cp = require('child_process');\ncp.execSync('id');\n",
        &[],
    );
    assert!(
        proc.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::ProcSpawn),
        "fixture must exhibit proc_spawn"
    );
    assert_eq!(
        crate::graph::classify_risk(&proc),
        Risk::High,
        "proc_spawn is high risk"
    );

    let pure = report(
        "pure",
        "module.exports = function (a) { return a; };\n",
        &[],
    );
    assert_eq!(
        crate::graph::classify_risk(&pure),
        Risk::None,
        "no host access is grey/none risk"
    );
}

#[test]
fn render_writes_a_valid_png() {
    let reports = sample_reports();
    let graph = DependencyGraph::from_reports(&reports);
    let pixmap = render_graph(&graph);

    let out = test_dir("graph-render").join("graph.png");
    pixmap.save_png(&out).unwrap();

    let bytes = fs::read(&out).unwrap();
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    assert_eq!(
        &bytes[..8],
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        "file begins with the PNG magic signature"
    );
    assert!(
        bytes.len() > 1024,
        "rendered PNG is non-trivial in size, got {} bytes",
        bytes.len()
    );

    let _ = fs::remove_dir_all(out.parent().unwrap());
}

/// READ-ONLY guarantee mirror of inspect: a `--format png` invocation (the
/// surface behind the hidden `graph` alias) that fails before any registry
/// resolution (an unparseable spec) must not write into the cwd, and must not
/// contact the network.
#[test]
fn graph_never_writes_into_cwd_on_error_path() {
    let cwd = test_dir("graph-cwd-untouched");
    let result = with_env_lock(|| {
        let previous = env::current_dir().ok();
        env::set_current_dir(&cwd).unwrap();
        let result = run_inspect(InspectCommand {
            npm: false,
            pypi: false,
            specs: vec!["bogus-ecosystem:not-a-real-thing@9.9.9".to_owned()],
            format: InspectFormat::Png,
            output: Some(cwd.join("omc-graph.png")),
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
        !cwd.join("omc-graph.png").exists(),
        "graph must not write the PNG when resolution fails"
    );
    assert!(
        !cwd.join("omc.lock").exists(),
        "graph must not write omc.lock into the cwd"
    );

    let _ = fs::remove_dir_all(&cwd);
}
