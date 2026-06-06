//! `policy` domain tests, extracted from the original monolithic tests.rs.

use super::*;

#[test]
fn adds_manifest_policy_grants() {
    let dir = tempfile::tempdir().unwrap();
    let added = add_manifest_policy_grants(
        dir.path(),
        &[
            "http:api.example.com".to_owned(),
            "env:API_TOKEN".to_owned(),
            "http:api.example.com".to_owned(),
        ],
    )
    .unwrap();
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();

    assert_eq!(
        added,
        vec![
            "http:api.example.com".to_owned(),
            "env.read:API_TOKEN".to_owned()
        ]
    );
    assert_eq!(
        manifest.policy.allow,
        vec![
            "env.read:API_TOKEN".to_owned(),
            "http:api.example.com".to_owned()
        ]
    );
}

#[test]
fn adds_manifest_policy_flows() {
    let dir = tempfile::tempdir().unwrap();
    let added = add_manifest_policy_flows(
        dir.path(),
        &[
            "env:API_TOKEN -> network:api.example.com".to_owned(),
            "env:API_TOKEN->network:api.example.com".to_owned(),
        ],
    )
    .unwrap();
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();

    assert_eq!(
        added,
        vec!["env:API_TOKEN->network:api.example.com".to_owned()]
    );
    assert_eq!(
        manifest.policy.allow_flow,
        vec!["env:API_TOKEN->network:api.example.com".to_owned()]
    );
}

#[test]
fn shipped_global_config_example_parses() {
    let raw = include_str!("../../../../examples/omc.global.toml");
    let config: GlobalConfig =
        toml::from_str(raw).expect("policy-only global config must parse without [project]");
    assert_eq!(
        config.policy.min_release_age.as_deref(),
        Some("14d"),
        "the recommended global config must keep its 14d freshness floor"
    );
    assert_eq!(
        parse_min_release_age(config.policy.min_release_age.as_deref()).unwrap(),
        Some(14 * 24 * 60 * 60),
        "the documented floor must compile to 14 days of seconds"
    );
}

// End-to-end: dropping the shipped example at $OMC_HOME/omc.toml must load as a
// global baseline (no `[project]` required) and surface its freshness floor.

#[test]
fn shipped_global_config_loads_from_omc_home() {
    let raw = include_str!("../../../../examples/omc.global.toml");
    let home = tempfile::tempdir().unwrap();
    fs::write(home.path().join("omc.toml"), raw).unwrap();

    let global = {
        let _guard = OMC_HOME_ENV_LOCK.lock().unwrap();
        env::set_var("OMC_HOME", home.path());
        let loaded = load_global_manifest();
        env::remove_var("OMC_HOME");
        loaded
    }
    .unwrap()
    .expect("global config present at $OMC_HOME must load");
    assert_eq!(global.policy.min_release_age.as_deref(), Some("14d"));
}

// A pinned trust block grants ONLY its exact package + version — never a
// different version, never another package. (Pure pin semantics, no env.)

#[test]
fn pinned_trust_block_grants_only_matching_version() {
    let doc = omc_policy::parse("npm package \"widget\" ==1.0.0 { allow eval }").unwrap();
    let hit = doc.compile_for(omc_policy::Ecosystem::Npm, "widget", "1.0.0");
    let miss_ver = doc.compile_for(omc_policy::Ecosystem::Npm, "widget", "2.0.0");
    let miss_pkg = doc.compile_for(omc_policy::Ecosystem::Npm, "gadget", "1.0.0");
    assert!(hit.allowed_capabilities.contains(&Capability::DynamicEval));
    assert!(!miss_ver
        .allowed_capabilities
        .contains(&Capability::DynamicEval));
    assert!(!miss_pkg
        .allowed_capabilities
        .contains(&Capability::DynamicEval));
}

// End-to-end: `omc policy trust` writes a per-package pinned block to
// $OMC_HOME/policy.d/, the loader picks it up, and effective_package_policy
// grants it for that exact package+version — but NOT a different version.

#[test]
fn global_trust_roundtrips_through_policy_d() {
    let home = tempfile::tempdir().unwrap();
    let (granted, other_version, file_ok) = {
        let _guard = OMC_HOME_ENV_LOCK.lock().unwrap();
        env::set_var("OMC_HOME", home.path());
        let path = write_global_package_trust(
            Ecosystem::Pypi,
            "requests",
            "2.32.5",
            &["dynamic.eval".to_owned()],
            &["env:*->network:*".to_owned()],
        )
        .unwrap();
        let file_ok = path.exists()
            && omc_policy::parse(&fs::read_to_string(&path).unwrap()).is_ok()
            && fs::read_to_string(&path).unwrap().contains("==2.32.5");
        let granted = effective_package_policy(
            home.path(),
            Policy::pure(),
            Ecosystem::Pypi,
            "requests",
            "2.32.5",
        )
        .unwrap();
        let other_version = effective_package_policy(
            home.path(),
            Policy::pure(),
            Ecosystem::Pypi,
            "requests",
            "2.30.0",
        )
        .unwrap();
        env::remove_var("OMC_HOME");
        (granted, other_version, file_ok)
    };
    assert!(file_ok, "trust file must exist, parse, and pin the version");
    assert!(
        granted
            .allowed_capabilities
            .contains(&Capability::DynamicEval),
        "trusted version must receive the grant"
    );
    assert!(
        !granted.allowed_flows.is_empty(),
        "trusted version must receive the flow grant"
    );
    assert!(
        !other_version
            .allowed_capabilities
            .contains(&Capability::DynamicEval),
        "an untrusted version must NOT inherit the grant"
    );
}

// REGRESSION: a packument must still deserialize when ANY version uses a
// legacy `engines` shape — an array (early lodash: ["node","rhino"]) or a bare
// string (early qs: ">=0.10.40"). Before the lenient parser these failed the
// whole `.json::<NpmRoot>()` decode ("error decoding response body"), making
// lodash and qs — two of the most-downloaded npm packages — uninstallable.

#[test]
fn block_guidance_maps_flow_finding_to_minimal_grant() {
    let need =
        parse_block_finding("send[8]: env:NPM_TOKEN may not flow to network:evil.com").unwrap();
    assert!(need.dangerous);
    assert_eq!(
        need.cli_flag,
        "--allow-flow env:NPM_TOKEN->network:evil.com"
    );
    assert_eq!(
        need.policy_stmt,
        "flow env \"NPM_TOKEN\" -> net \"evil.com\""
    );
    assert!(
        need.raw
            .contains("env:NPM_TOKEN may not flow to network:evil.com"),
        "raw machine token must be preserved verbatim"
    );
    assert!(need.risk.is_some(), "secret->sink must carry a risk line");
}

#[test]
fn block_guidance_maps_capability_findings() {
    for (finding, flag, stmt, dangerous) in [
        (
            "p[3]: capability dynamic.eval not granted",
            "--allow dynamic.eval",
            "allow eval",
            true,
        ),
        (
            "p[0]: capability proc.spawn:* not granted",
            "--allow proc.spawn:*",
            "allow spawn \"*\"",
            true,
        ),
        (
            "p[0]: capability fs.write:* not granted",
            "--allow fs.write:*",
            "allow write \"*\"",
            true,
        ),
        (
            "p[1]: capability env.read:TOKEN not granted",
            "--allow env.read:TOKEN",
            "allow env \"TOKEN\"",
            false,
        ),
    ] {
        let need = parse_block_finding(finding).unwrap();
        assert_eq!(need.cli_flag, flag, "{finding}");
        assert_eq!(need.policy_stmt, stmt, "{finding}");
        assert_eq!(need.dangerous, dangerous, "{finding}");
    }
}

// The rendered `omc.policy` block must actually PARSE with the real DSL parser
// and pin the exact version — guards against grammar drift (the `=` vs `==`
// bug class) so a copy-pasted suggestion is never a parse error.

#[test]
fn rendered_policy_block_parses_and_pins_version() {
    let findings = vec![
        "main[1]: env:NPM_TOKEN may not flow to network:evil.com".to_owned(),
        "main[3]: capability dynamic.eval not granted".to_owned(),
        "main[4]: capability proc.spawn:npm-script:postinstall not granted".to_owned(),
    ];
    let g = render_block_guidance(Ecosystem::Npm, "shady", "1.2.3", &findings);
    // raw tokens always shown; one-run command present.
    assert!(g.contains("env:NPM_TOKEN may not flow to network:evil.com"));
    assert!(g.contains("omc add npm:shady@1.2.3"));
    assert!(g.contains("--allow-flow env:NPM_TOKEN->network:evil.com"));

    // Extract the omc.policy block and parse it with the real parser.
    let start = g.find("npm package").expect("policy block present");
    let block = &g[start..];
    let block = &block[..=block.rfind('}').unwrap()];
    assert!(block.contains("==1.2.3"), "version must be pinned with ==");
    omc_policy::parse(block).expect("rendered policy block must parse cleanly");
}

#[test]
fn build_block_suggestion_yields_parseable_grant_tokens() {
    let findings = vec![
        "main[1]: env:NPM_TOKEN may not flow to network:evil.com".to_owned(),
        "main[3]: capability dynamic.eval not granted".to_owned(),
        "main[0]: capability proc.spawn:* not granted".to_owned(),
    ];
    let s = build_block_suggestion(Ecosystem::Npm, "shady", "1.2.3", &findings);
    assert_eq!(s.name, "shady");
    assert_eq!(s.version, "1.2.3");
    // Capability vs flow tokens are split correctly.
    assert!(s.allow.contains(&"dynamic.eval".to_owned()));
    assert!(s.allow.contains(&"proc.spawn:*".to_owned()));
    assert!(s
        .allow_flow
        .contains(&"env:NPM_TOKEN->network:evil.com".to_owned()));
    // Every token must actually parse, so interactive `y`/`a` can never error.
    for grant in &s.allow {
        parse_capability_grant(grant).expect("allow token must parse");
    }
    for flow in &s.allow_flow {
        parse_flow_rule(flow).expect("flow token must parse");
    }
    assert!(s.guidance.contains("shady was blocked"));
}

#[test]
fn locked_reachable_packages_include_transitive_dependencies() {
    let mut root = locked_package_for_test(Ecosystem::Npm, "is-odd", "3.0.1");
    root.dependencies = vec!["npm:is-number@^6.0.0".to_owned()];
    let dependency = locked_package_for_test(Ecosystem::Npm, "is-number", "6.0.0");
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![root, dependency],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    let options = LinkOptions::new(".");
    let retained = locked_reachable_package_keys(
        &lock,
        &[PackageSpec::parse("npm:is-odd@^3.0.0").unwrap()],
        &options,
    )
    .unwrap();

    assert!(retained.contains("npm:is-odd@3.0.1"));
    assert!(retained.contains("npm:is-number@6.0.0"));
}

#[test]
fn locked_reachable_packages_respect_pypi_no_deps() {
    let mut root = locked_package_for_test(Ecosystem::Pypi, "requests", "2.32.3");
    root.dependencies = vec!["pypi:idna>=3".to_owned()];
    let dependency = locked_package_for_test(Ecosystem::Pypi, "idna", "3.7");
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![root, dependency],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    let mut options = LinkOptions::new(".");
    options.pypi_include_dependencies = false;

    let retained = locked_reachable_package_keys(
        &lock,
        &[PackageSpec::parse("pypi:requests==2.32.3").unwrap()],
        &options,
    )
    .unwrap();

    assert!(retained.contains("pypi:requests@2.32.3"));
    assert!(!retained.contains("pypi:idna@3.7"));
}

#[test]
fn locked_reachable_packages_allow_missing_optional_dependencies() {
    let mut root = locked_package_for_test(Ecosystem::Npm, "has-optional", "1.0.0");
    root.optional_dependencies = vec!["npm:optional-platform@1.0.0".to_owned()];
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![root],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    let options = LinkOptions::new(".");
    let retained = locked_reachable_package_keys(
        &lock,
        &[PackageSpec::parse("npm:has-optional@1.0.0").unwrap()],
        &options,
    )
    .unwrap();

    assert_eq!(
        retained,
        BTreeSet::from(["npm:has-optional@1.0.0".to_owned()])
    );
}

#[test]
fn locked_reachable_packages_respect_optional_and_peer_omits() {
    let mut root = locked_package_for_test(Ecosystem::Npm, "root", "1.0.0");
    root.dependencies = vec!["npm:runtime@1.0.0".to_owned()];
    root.optional_dependencies = vec!["npm:optional-runtime@1.0.0".to_owned()];
    root.peer_dependencies = vec!["npm:peer-runtime@1.0.0".to_owned()];
    let runtime = locked_package_for_test(Ecosystem::Npm, "runtime", "1.0.0");
    let optional = locked_package_for_test(Ecosystem::Npm, "optional-runtime", "1.0.0");
    let peer = locked_package_for_test(Ecosystem::Npm, "peer-runtime", "1.0.0");
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![root, runtime, optional, peer],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    let mut options = LinkOptions::new(".");
    options.include_optional_dependencies = false;
    options.include_peer_dependencies = false;

    let retained = locked_reachable_package_keys(
        &lock,
        &[PackageSpec::parse("npm:root@1.0.0").unwrap()],
        &options,
    )
    .unwrap();

    assert!(retained.contains("npm:root@1.0.0"));
    assert!(retained.contains("npm:runtime@1.0.0"));
    assert!(!retained.contains("npm:optional-runtime@1.0.0"));
    assert!(!retained.contains("npm:peer-runtime@1.0.0"));
}

#[test]
fn locked_reachable_packages_reject_stale_lockfiles() {
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![locked_package_for_test(Ecosystem::Npm, "left-pad", "1.1.0")],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    let options = LinkOptions::new(".");
    let error = locked_reachable_package_keys(
        &lock,
        &[PackageSpec::parse("npm:left-pad@1.3.0").unwrap()],
        &options,
    )
    .unwrap_err();

    assert!(matches!(error, OmcRegistryError::LockfileOutOfDate(_)));
}

#[test]
fn parses_capability_grants() {
    assert_eq!(
        parse_capability_grant("http:api.example.com").unwrap(),
        Capability::HttpHost("api.example.com".to_owned())
    );
    assert_eq!(
        parse_capability_grant("env:API_TOKEN").unwrap(),
        Capability::EnvRead("API_TOKEN".to_owned())
    );
    assert_eq!(
        parse_capability_grant("dynamic-eval").unwrap(),
        Capability::DynamicEval
    );
}

#[test]
fn parses_flow_rules() {
    assert_eq!(
        parse_flow_rule("env:API_TOKEN -> network:api.example.com").unwrap(),
        FlowRule::new(
            LabelMatcher::Env("API_TOKEN".to_owned()),
            Sink::Network("api.example.com".to_owned())
        )
    );
    assert_eq!(
        parse_flow_rule("*->dynamic.eval").unwrap(),
        FlowRule::new(LabelMatcher::Any, Sink::Eval)
    );
}

#[test]
fn reads_manifest_policy_grants_and_pypi_indexes() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("omc.toml"),
        r#"
            [project]
            name = "policy-demo"
            version = "0.1.0"

            [policy]
            allow = ["http:api.example.com", "env:API_TOKEN"]
            allow-flow = ["env:API_TOKEN -> network:api.example.com"]

            [registries]
            pypi-index-url = "https://mirror.example/simple"
            pypi-extra-index-urls = ["https://extra.example/simple"]
            "#,
    )
    .unwrap();

    let options = options_with_manifest_policy(&LinkOptions::new(dir.path())).unwrap();
    assert!(options
        .allowed_capabilities
        .contains(&Capability::HttpHost("api.example.com".to_owned())));
    assert!(options
        .allowed_capabilities
        .contains(&Capability::EnvRead("API_TOKEN".to_owned())));
    assert!(options.allowed_flows.contains(&FlowRule::new(
        LabelMatcher::Env("API_TOKEN".to_owned()),
        Sink::Network("api.example.com".to_owned())
    )));
    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://mirror.example/simple/")
    );
    assert_eq!(
        options.pypi_extra_index_urls,
        vec!["https://extra.example/simple/".to_owned()]
    );
}
