use crate::*;
use super::*;

#[test]
fn npm_remove_package_lock_only_does_not_touch_install_state() {
    let project = test_dir("npm-remove-package-lock-only-project");
    fs::create_dir_all(project.join("node_modules").join("left-pad")).unwrap();
    fs::write(
        project
            .join("node_modules")
            .join("left-pad")
            .join("index.js"),
        "module.exports = 42;\n",
    )
    .unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    fs::write(
            project.join("package-lock.json"),
            r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}"#,
        )
        .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["uninstall", "--package-lock-only", "left-pad"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("node_modules").join("left-pad").exists());
    assert!(!project.join(".omc").join("python").exists());
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|dependencies| !dependencies.contains_key("left-pad")));
    let package_lock = read_npm_pkg_json(&project.join("package-lock.json")).unwrap();
    let lock_packages = package_lock
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert!(!lock_packages.contains_key("node_modules/left-pad"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_updates_selected_workspace_package_json_dependencies() {
    let project = test_dir("npm-remove-workspace-package-json-project");
    fs::create_dir_all(project.join("packages/lib")).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        project.join("packages/lib/package.json"),
        r#"{"name":"@demo/lib","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    fs::write(
            project.join("package-lock.json"),
            r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","workspaces":["packages/*"]},"node_modules/left-pad":{"version":"1.3.0"}}}"#,
        )
        .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["remove", "left-pad", "--workspace", "@demo/lib"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let package_json = read_npm_pkg_json(&project.join("packages/lib/package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|dependencies| !dependencies.contains_key("left-pad")));
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock.packages.is_empty());
    let package_lock = read_npm_pkg_json(&project.join("package-lock.json")).unwrap();
    let lock_packages = package_lock
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert!(!lock_packages.contains_key("node_modules/left-pad"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_workspace_package_lock_only_does_not_touch_install_state() {
    let project = test_dir("npm-remove-workspace-package-lock-only-project");
    fs::create_dir_all(project.join("packages/lib")).unwrap();
    fs::create_dir_all(project.join("node_modules").join("left-pad")).unwrap();
    fs::write(
        project
            .join("node_modules")
            .join("left-pad")
            .join("index.js"),
        "module.exports = 42;\n",
    )
    .unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        project.join("packages/lib/package.json"),
        r#"{"name":"@demo/lib","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    fs::write(
            project.join("package-lock.json"),
            r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","workspaces":["packages/*"]},"packages/lib":{"name":"@demo/lib","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}"#,
        )
        .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&[
            "remove",
            "--package-lock-only",
            "left-pad",
            "--workspace",
            "@demo/lib",
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("node_modules").join("left-pad").exists());
    assert!(!project.join(".omc").join("python").exists());
    let package_json = read_npm_pkg_json(&project.join("packages/lib/package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|dependencies| !dependencies.contains_key("left-pad")));
    let package_lock = read_npm_pkg_json(&project.join("package-lock.json")).unwrap();
    let lock_packages = package_lock
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert!(!lock_packages.contains_key("node_modules/left-pad"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_workspace_skips_missing_packages_like_npm() {
    let project = test_dir("npm-remove-workspace-missing-package");
    fs::create_dir_all(project.join("packages/lib")).unwrap();
    let root_package_json = r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#;
    let workspace_package_json = r#"{"name":"@demo/lib","version":"1.0.0"}"#;
    fs::write(project.join("package.json"), root_package_json).unwrap();
    fs::write(
        project.join("packages/lib/package.json"),
        workspace_package_json,
    )
    .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&[
            "remove",
            "definitely-not-installed",
            "--workspace",
            "@demo/lib",
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("package.json")).unwrap(),
        root_package_json
    );
    assert_eq!(
        fs::read_to_string(project.join("packages/lib/package.json")).unwrap(),
        workspace_package_json
    );
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join("package-lock.json").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_maintenance_accepts_package_args_like_npm() {
    for command in ["prune", "dedupe"] {
        let project = test_dir(&format!("npm-maintenance-package-arg-{command}"));
        fs::write(
            project.join("package.json"),
            r#"{"name":"root","version":"1.0.0"}"#,
        )
        .unwrap();

        let status = run_npm_compat(&project, &args(&[command, "left-pad"])).unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        assert!(project.join("omc.toml").exists());
        assert!(project.join("omc.lock").exists());

        let _ = fs::remove_dir_all(project);
    }
}

#[test]
fn npm_maintenance_dry_run_does_not_write_project_state() {
    let project = test_dir("npm-maintenance-dry-run");
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();

    let status = run_npm_compat(&project, &args(&["prune", "--dry-run", "--json"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join("node_modules").exists());
    assert!(!project.join(".omc").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn reports_npm_doctor_project_state() {
    let project = test_dir("npm-doctor");
    fs::create_dir_all(project.join(".omc/cache/npm")).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "doctor-demo", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(project.join(".omc/cache/npm/pkg.tgz"), b"cache").unwrap();

    let report = npm_doctor_report(
        &project,
        &NpmDoctorAction {
            checks: vec![
                "registry".to_owned(),
                "environment".to_owned(),
                "cache".to_owned(),
            ],
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
        },
    )
    .unwrap();

    assert!(report.contains("OMC npm doctor"));
    assert!(report.contains("registry: https://registry.example.invalid/npm"));
    assert!(report.contains("package.json: found"));
    assert!(report.contains(".omc/cache/npm"));
    assert!(report.contains("files: 1"));
}

#[test]
fn selects_npm_view_fields_from_packument_metadata() {
    let metadata = omc_registry::NpmPackageMetadata {
        name: "left-pad".to_owned(),
        version: "1.3.0".to_owned(),
        dist_tags: BTreeMap::from([("latest".to_owned(), "1.3.0".to_owned())]),
        versions: vec!["0.0.0".to_owned(), "1.3.0".to_owned()],
        root: serde_json::json!({
            "time": {
                "modified": "2024-04-16T05:01:57.431Z",
            },
            "maintainers": [
                {"name": "sebmck", "email": "sebmck@gmail.com"},
                {"name": "stevemao", "email": "maochenyan@gmail.com"},
            ],
        }),
        manifest: serde_json::json!({
            "dist": {
                "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            },
            "repository": {
                "url": "git+ssh://git@github.com/stevemao/left-pad.git",
            },
        }),
    };

    assert_eq!(
        npm_view_field_value(&metadata, "time.modified"),
        Some(serde_json::json!("2024-04-16T05:01:57.431Z"))
    );
    assert_eq!(
        npm_view_field_value(&metadata, "versions[0]"),
        Some(serde_json::json!("0.0.0"))
    );
    assert_eq!(
        npm_view_field_value(&metadata, "dist-tags[latest]"),
        Some(serde_json::json!("1.3.0"))
    );
    assert_eq!(
        npm_view_field_value(&metadata, "maintainers.name"),
        Some(serde_json::json!({
            "maintainers[0].name": "sebmck",
            "maintainers[1].name": "stevemao",
        }))
    );
    assert_eq!(
        npm_view_field_value(&metadata, "repository.url"),
        Some(serde_json::json!(
            "git+ssh://git@github.com/stevemao/left-pad.git"
        ))
    );

    let view = npm_view_metadata_value(&metadata);
    assert_eq!(view["name"], serde_json::json!("left-pad"));
    assert_eq!(view["version"], serde_json::json!("1.3.0"));
    assert_eq!(view["versions"], serde_json::json!(["0.0.0", "1.3.0"]));
    assert_eq!(
        view["time"]["modified"],
        serde_json::json!("2024-04-16T05:01:57.431Z")
    );
    assert_eq!(view["dist-tags"]["latest"], serde_json::json!("1.3.0"));
    assert_eq!(
        view["dist"]["tarball"],
        serde_json::json!("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
    );
}

#[test]
fn maps_npm_create_initializers_to_packages() {
    assert_eq!(
        npm_create_package_spec("vite@latest").unwrap(),
        "create-vite@latest"
    );
    assert_eq!(
        npm_create_package_spec("react-app").unwrap(),
        "create-react-app"
    );
    assert_eq!(
        npm_create_package_spec("@vitejs").unwrap(),
        "@vitejs/create"
    );
    assert_eq!(
        npm_create_package_spec("@vitejs@latest").unwrap(),
        "@vitejs/create@latest"
    );
    assert_eq!(
        npm_create_package_spec("@scope/tool@2.0.0").unwrap(),
        "@scope/create-tool@2.0.0"
    );
    assert!(npm_create_package_spec("@scope/").is_err());
    assert!(npm_create_package_spec("vite@").is_err());
}

#[test]
fn selects_npm_create_initializer_bin() {
    let dir = test_dir("npm-create-bin");
    let bin_dir = dir.join("node_modules/.bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("vite"), "#!/bin/sh\n").unwrap();
    assert_eq!(
        npm_create_bin_name(&dir, "create-vite").unwrap(),
        "vite".to_owned()
    );

    let scoped = test_dir("npm-create-bin-scoped");
    let scoped_bin_dir = scoped.join("node_modules/.bin");
    fs::create_dir_all(&scoped_bin_dir).unwrap();
    fs::write(scoped_bin_dir.join("only-bin"), "#!/bin/sh\n").unwrap();
    assert_eq!(
        npm_create_bin_name(&scoped, "@scope/create-tool").unwrap(),
        "only-bin".to_owned()
    );
}

#[test]
fn resolves_npm_installed_package_dirs() {
    let root = Path::new("/tmp/omc-project");
    assert_eq!(
        npm_installed_package_dir(root, "left-pad@1.3.0").unwrap(),
        root.join("node_modules/left-pad")
    );
    assert_eq!(
        npm_installed_package_dir(root, "npm:@scope/pkg@1.2.3#readme").unwrap(),
        root.join("node_modules/@scope/pkg")
    );
    assert!(npm_installed_package_dir(root, "../escape").is_err());
    assert!(npm_installed_package_dir(root, "@scope/../escape").is_err());
}

#[test]
fn completes_npm_and_pip_commands_and_locked_packages() {
    let dir = test_dir("compat-completion");
    fs::write(
        dir.join("package.json"),
        r#"{ "scripts": { "build": "echo build" } }"#,
    )
    .unwrap();
    fs::write(
        dir.join("omc.lock"),
        r#"
version = 1

[[packages]]
ecosystem = "npm"
name = "left-pad"
version = "1.3.0"
source_url = ""
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"

[[packages]]
ecosystem = "pypi"
name = "requests"
version = "2.32.3"
source_url = ""
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"
"#,
    )
    .unwrap();

    assert_eq!(
        npm_completion_suggestions(&dir, &args(&["npm", "explo"])),
        vec!["explore".to_owned()]
    );
    assert_eq!(
        npm_completion_suggestions(&dir, &args(&["npm", "run", "b"])),
        vec!["build".to_owned()]
    );
    assert_eq!(
        npm_completion_suggestions(&dir, &args(&["npm", "explore", "left"])),
        vec!["left-pad".to_owned()]
    );
    assert_eq!(
        pip_completion_suggestions(&dir, &args(&["pip", "sho"]), 1),
        vec!["show".to_owned()]
    );
    assert_eq!(
        pip_completion_suggestions(&dir, &args(&["pip", "show", "req"]), 2),
        vec!["requests".to_owned()]
    );
}

#[test]
fn builds_npm_sbom_documents_from_locked_packages() {
    let context = NpmSbomContext {
        root: NpmSbomRoot {
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            license: Some("MIT".to_owned()),
            homepage: Some("https://example.invalid/demo".to_owned()),
            description: Some("demo app".to_owned()),
        },
        packages: vec![
            locked_npm_package("chalk", "5.0.0", vec!["npm:left-pad@1.3.0".to_owned()]),
            locked_npm_package("left-pad", "1.3.0", Vec::new()),
        ],
        root_dependencies: BTreeSet::from(["chalk".to_owned()]),
        timestamp: "2026-05-23T00:00:00.000Z".to_owned(),
        serial_uuid: "00000000-0000-4000-8000-000000000000".to_owned(),
        sbom_type: NpmSbomType::Application,
    };

    let cyclonedx = npm_cyclonedx_sbom(&context);
    assert_eq!(cyclonedx["bomFormat"], "CycloneDX");
    assert_eq!(cyclonedx["metadata"]["component"]["type"], "application");
    assert_eq!(cyclonedx["components"][0]["name"], "chalk");
    assert_eq!(cyclonedx["components"][0]["hashes"][0]["alg"], "SHA-256");
    assert_eq!(cyclonedx["dependencies"][0]["ref"], "demo@1.0.0");
    assert_eq!(cyclonedx["dependencies"][0]["dependsOn"][0], "chalk@5.0.0");
    assert_eq!(
        cyclonedx["dependencies"][1]["dependsOn"][0],
        "left-pad@1.3.0"
    );

    let spdx = npm_spdx_sbom(&context);
    assert_eq!(spdx["spdxVersion"], "SPDX-2.3");
    assert_eq!(spdx["packages"][0]["primaryPackagePurpose"], "APPLICATION");
    assert_eq!(
        spdx["packages"][1]["externalRefs"][0]["referenceLocator"],
        "pkg:npm/chalk@5.0.0"
    );
    assert!(spdx["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["spdxElementId"] == "SPDXRef-Package-demo-1.0.0"
                && item["relatedSpdxElement"] == "SPDXRef-Package-chalk-5.0.0"
                && item["relationshipType"] == "DEPENDS_ON"
        }));
}

#[test]
fn normalizes_npm_funding_metadata() {
    assert_eq!(
        normalize_npm_funding(&serde_json::Value::String(
            "https://example.com/pkg".to_owned()
        ))
        .unwrap(),
        serde_json::json!({ "url": "https://example.com/pkg" })
    );
    assert_eq!(
        normalize_npm_funding(&serde_json::json!([
            "https://example.com/one",
            { "type": "github", "url": "https://example.com/two" },
            "",
        ]))
        .unwrap(),
        serde_json::json!([
            { "url": "https://example.com/one" },
            { "type": "github", "url": "https://example.com/two" },
        ])
    );
    assert!(normalize_npm_funding(&serde_json::json!({ "type": "github" })).is_none());
    assert_eq!(
        npm_funding_urls(&serde_json::json!([
            { "url": "https://example.com/two" },
            { "url": "https://example.com/one" },
            { "url": "https://example.com/two" },
        ])),
        vec![
            "https://example.com/one".to_owned(),
            "https://example.com/two".to_owned(),
        ]
    );
}

#[test]
fn collects_npm_funding_from_root_and_node_modules() {
    let dir = test_dir("npm-fund");
    fs::write(
        dir.join("package.json"),
        r#"{
              "name": "root",
              "version": "1.0.0",
              "funding": { "type": "github", "url": "https://github.com/sponsors/root" }
            }"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("node_modules/left-pad")).unwrap();
    fs::write(
        dir.join("node_modules/left-pad/package.json"),
        r#"{ "name": "left-pad", "version": "1.3.0", "funding": "https://example.com/left-pad" }"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("node_modules/@scope/scoped")).unwrap();
    fs::write(
        dir.join("node_modules/@scope/scoped/package.json"),
        r#"{
              "name": "@scope/scoped",
              "version": "2.0.0",
              "funding": [{ "type": "opencollective", "url": "https://opencollective.com/scoped" }]
            }"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("node_modules/.bin")).unwrap();

    let report = collect_npm_fund_report(
        &dir,
        &NpmFundAction {
            json: true,
            package: None,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        },
    )
    .unwrap();
    assert_eq!(
        report.root.as_ref().map(|package| package.id()).as_deref(),
        Some("root@1.0.0")
    );
    assert_eq!(
        report
            .dependencies
            .iter()
            .map(|package| package.id())
            .collect::<Vec<_>>(),
        vec![
            "@scope/scoped@2.0.0".to_owned(),
            "left-pad@1.3.0".to_owned()
        ]
    );

    let json = npm_fund_report_json(&report);
    assert_eq!(
        json.get("length").and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        npm_pkg_get_path(&json, "dependencies.left-pad.funding.url")
            .and_then(serde_json::Value::as_str),
        Some("https://example.com/left-pad")
    );

    let filtered = collect_npm_fund_report(
        &dir,
        &NpmFundAction {
            json: true,
            package: Some("@scope/scoped@2.0.0".to_owned()),
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        },
    )
    .unwrap();
    assert!(filtered.root.is_none());
    assert_eq!(filtered.dependencies.len(), 1);
    assert_eq!(filtered.dependencies[0].name, "@scope/scoped");
}

#[test]
fn collects_npm_funding_from_selected_workspaces() {
    let dir = test_dir("npm-fund-workspaces");
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0", "workspaces": ["packages/*"] }"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("packages/lib/node_modules/dep")).unwrap();
    fs::write(
        dir.join("packages/lib/package.json"),
        r#"{
              "name": "@demo/lib",
              "version": "1.0.0",
              "funding": "https://example.com/lib"
            }"#,
    )
    .unwrap();
    fs::write(
        dir.join("packages/lib/node_modules/dep/package.json"),
        r#"{ "name": "dep", "version": "2.0.0", "funding": "https://example.com/dep" }"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("packages/api")).unwrap();
    fs::write(
        dir.join("packages/api/package.json"),
        r#"{ "name": "@demo/api", "version": "1.0.0", "funding": "https://example.com/api" }"#,
    )
    .unwrap();

    let report = collect_npm_fund_report(
        &dir,
        &NpmFundAction {
            json: false,
            package: None,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: false,
        },
    )
    .unwrap();

    assert_eq!(
        report.root.as_ref().map(|package| package.id()).as_deref(),
        Some("@demo/lib@1.0.0")
    );
    assert_eq!(
        report
            .dependencies
            .iter()
            .map(|package| package.id())
            .collect::<Vec<_>>(),
        vec!["dep@2.0.0".to_owned()]
    );
}

#[test]
fn initializes_npm_package_json() {
    let root = test_dir("npm-init");
    let dir = root.join("demo_pkg");
    fs::create_dir_all(&dir).unwrap();
    print_npm_init(
        &dir,
        NpmInitAction {
            name: None,
            version: Some("2.0.0".to_owned()),
            description: Some("demo package".to_owned()),
            main: Some("src/index.js".to_owned()),
            license: Some("MIT".to_owned()),
            scope: Some("@scope".to_owned()),
            private: true,
            package_type: Some("module".to_owned()),
        },
    )
    .unwrap();

    let package = read_npm_pkg_json(&dir.join("package.json")).unwrap();
    assert_eq!(
        package.get("name").and_then(serde_json::Value::as_str),
        Some("@scope/demo_pkg")
    );
    assert_eq!(
        package.get("version").and_then(serde_json::Value::as_str),
        Some("2.0.0")
    );
    assert_eq!(
        package
            .get("description")
            .and_then(serde_json::Value::as_str),
        Some("demo package")
    );
    assert_eq!(
        package.get("main").and_then(serde_json::Value::as_str),
        Some("src/index.js")
    );
    assert_eq!(
        package.get("license").and_then(serde_json::Value::as_str),
        Some("MIT")
    );
    assert_eq!(
        package.get("type").and_then(serde_json::Value::as_str),
        Some("module")
    );
    assert_eq!(
        package.get("private").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        npm_pkg_get_path(&package, "scripts.test").and_then(serde_json::Value::as_str),
        Some("echo \"Error: no test specified\" && exit 1")
    );
}

#[test]
fn packs_local_npm_package_tarball() {
    let dir = test_dir("npm-pack");
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "@scope/demo-pkg", "version": "1.2.3" }"#,
    )
    .unwrap();
    fs::write(dir.join("index.js"), "module.exports = 1\n").unwrap();
    fs::create_dir_all(dir.join("lib")).unwrap();
    fs::write(dir.join("lib/main.js"), "module.exports = 2\n").unwrap();
    fs::create_dir_all(dir.join("node_modules/ignored")).unwrap();
    fs::write(dir.join("node_modules/ignored/index.js"), "ignored\n").unwrap();

    print_npm_pack(
        &dir,
        NpmPackAction {
            packages: Vec::new(),
            destination: PathBuf::from("dist"),
            json: false,
            dry_run: false,
            npm_registry: None,
        },
    )
    .unwrap();

    let tarball = dir.join("dist/scope-demo-pkg-1.2.3.tgz");
    assert!(tarball.exists());
    let decoder = flate2::read::GzDecoder::new(fs::File::open(tarball).unwrap());
    let mut archive = tar::Archive::new(decoder);
    let mut paths = archive
        .entries()
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(
        paths,
        vec![
            "package/index.js".to_owned(),
            "package/lib/main.js".to_owned(),
            "package/package.json".to_owned(),
        ]
    );

    print_npm_pack(
        &dir,
        NpmPackAction {
            packages: Vec::new(),
            destination: PathBuf::from("dry"),
            json: true,
            dry_run: true,
            npm_registry: None,
        },
    )
    .unwrap();
    assert!(!dir.join("dry").exists());
}

#[test]
fn direct_npm_pack_resolves_local_paths_from_invocation_cwd() {
    let project = test_dir("direct-npm-pack-local-project");
    let invocation_cwd = project.join("packages/app/src");
    let local_package = invocation_cwd.join("vendor/packme");
    fs::create_dir_all(&local_package).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        local_package.join("package.json"),
        r#"{ "name": "pack-me", "version": "1.2.3" }"#,
    )
    .unwrap();
    fs::write(local_package.join("index.js"), "module.exports = 1;\n").unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&["pack", "./vendor/packme", "--pack-destination", "packed"]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let tarball = invocation_cwd.join("packed/pack-me-1.2.3.tgz");
    assert!(tarball.exists());
    assert!(!project.join("packed/pack-me-1.2.3.tgz").exists());
    let manifest = npm_manifest_from_tarball(&fs::read(tarball).unwrap()).unwrap();
    assert_eq!(npm_package_json_name(&manifest).unwrap(), "pack-me");
}

#[test]
fn diffs_npm_package_tarballs() {
    fn package_tarball(root: &Path, version: &str) -> NpmPackageTarball {
        let (pack, manifest, bytes) = npm_pack_package_for_publish(root).unwrap();
        NpmPackageTarball {
            metadata: omc_registry::NpmPackageMetadata {
                name: pack.name,
                version: version.to_owned(),
                dist_tags: BTreeMap::new(),
                versions: Vec::new(),
                root: serde_json::Value::Null,
                manifest,
            },
            bytes,
        }
    }

    let root = test_dir("npm-diff");
    let left_dir = root.join("left");
    let right_dir = root.join("right");
    fs::create_dir_all(&left_dir).unwrap();
    fs::create_dir_all(&right_dir).unwrap();
    for dir in [&left_dir, &right_dir] {
        fs::write(
            dir.join("package.json"),
            r#"{ "name": "demo-pkg", "version": "1.0.0" }"#,
        )
        .unwrap();
    }
    fs::write(left_dir.join("index.js"), "module.exports = 1\n").unwrap();
    fs::write(right_dir.join("index.js"), "module.exports = 2\n").unwrap();
    fs::write(left_dir.join("removed.txt"), "remove me\n").unwrap();
    fs::write(right_dir.join("added.txt"), "add me\n").unwrap();

    let left = package_tarball(&left_dir, "1.0.0");
    let right = package_tarball(&right_dir, "1.0.1");
    let action = NpmDiffAction {
        specs: vec!["demo-pkg@1.0.0".to_owned(), "demo-pkg@1.0.1".to_owned()],
        paths: Vec::new(),
        name_only: false,
        unified: 3,
        ignore_all_space: false,
        no_prefix: false,
        src_prefix: "a/".to_owned(),
        dst_prefix: "b/".to_owned(),
        text: false,
        npm_registry: None,
        userconfig: None,
    };

    let files = npm_diff_changed_files(&left, &right, &action).unwrap();
    assert_eq!(
        files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["added.txt", "index.js", "removed.txt"]
    );
    let index_file = files
        .iter()
        .find(|file| file.path == "index.js")
        .expect("changed index.js");
    let patch = npm_diff_file_patch(&left, &right, index_file, &action).unwrap();
    assert!(patch.contains("diff --git a/index.js b/index.js"));
    assert!(patch.contains("-module.exports = 1\n"));
    assert!(patch.contains("+module.exports = 2\n"));

    let filtered_action = NpmDiffAction {
        paths: vec!["index.js".to_owned()],
        ..action
    };
    let filtered = npm_diff_changed_files(&left, &right, &filtered_action).unwrap();
    assert_eq!(
        filtered
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["index.js"]
    );

    let local_action = NpmDiffAction {
        specs: vec!["./left".to_owned(), "./right".to_owned()],
        paths: Vec::new(),
        name_only: true,
        unified: 3,
        ignore_all_space: false,
        no_prefix: false,
        src_prefix: "a/".to_owned(),
        dst_prefix: "b/".to_owned(),
        text: false,
        npm_registry: None,
        userconfig: None,
    };
    let local_left =
        npm_diff_package_tarball(&root, &local_action.specs[0], &local_action).unwrap();
    let local_right =
        npm_diff_package_tarball(&root, &local_action.specs[1], &local_action).unwrap();
    assert_eq!(
        npm_diff_changed_files(&local_left, &local_right, &local_action)
            .unwrap()
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["added.txt", "index.js", "removed.txt"]
    );

    let left_tgz = root.join("left.tgz");
    let right_tgz = root.join("right.tgz");
    fs::write(&left_tgz, &left.bytes).unwrap();
    fs::write(&right_tgz, &right.bytes).unwrap();
    let tarball_action = NpmDiffAction {
        specs: vec![
            left_tgz.to_string_lossy().into_owned(),
            right_tgz.to_string_lossy().into_owned(),
        ],
        ..local_action
    };
    let tarball_left =
        npm_diff_package_tarball(&root, &tarball_action.specs[0], &tarball_action).unwrap();
    let tarball_right =
        npm_diff_package_tarball(&root, &tarball_action.specs[1], &tarball_action).unwrap();
    assert_eq!(
        npm_diff_changed_files(&tarball_left, &tarball_right, &tarball_action)
            .unwrap()
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["added.txt", "index.js", "removed.txt"]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn direct_npm_diff_resolves_local_inputs_from_invocation_cwd() {
    let project = test_dir("direct-npm-diff-local-project");
    let invocation_cwd = project.join("work/release");
    let left_dir = invocation_cwd.join("left");
    let right_dir = invocation_cwd.join("right");
    fs::create_dir_all(&left_dir).unwrap();
    fs::create_dir_all(&right_dir).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        left_dir.join("package.json"),
        r#"{ "name": "diff-demo", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        right_dir.join("package.json"),
        r#"{ "name": "diff-demo", "version": "1.0.1" }"#,
    )
    .unwrap();
    fs::write(left_dir.join("index.js"), "module.exports = 1;\n").unwrap();
    fs::write(right_dir.join("index.js"), "module.exports = 2;\n").unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "diff",
            "--diff",
            "./left",
            "--diff",
            "./right",
            "--diff-name-only",
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
}

#[test]
fn npm_list_includes_manifest_local_paths() {
    let project = test_dir("npm-list-local-paths-project");
    let local = project.join("vendor/local-tool");
    fs::create_dir_all(&local).unwrap();
    fs::write(
        local.join("package.json"),
        r#"{
              "name": "local-tool",
              "version": "1.2.3",
              "dependencies": { "left-pad": "^1.3.0" }
            }"#,
    )
    .unwrap();
    fs::write(
        project.join("omc.toml"),
        format!(
            r#"npm-local-paths = ["{}"]

[project]
name = "root"
version = "0.1.0"
"#,
            local.display()
        ),
    )
    .unwrap();
    fs::write(
        project.join("package.json"),
        format!(
            r#"{{
                  "name": "root",
                  "version": "1.0.0",
                  "dependencies": {{ "local-tool": "file:{}" }}
                }}"#,
            local.display()
        ),
    )
    .unwrap();
    fs::write(project.join("omc.lock"), "version = 1\n").unwrap();

    let packages = listed_locked_packages(&project, Some(Ecosystem::Npm), &[]).unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "local-tool");
    assert_eq!(packages[0].version, "1.2.3");
    assert_eq!(packages[0].verdict, Verdict::Accepted);
    assert_eq!(packages[0].behavior, Behavior::HostCapability);
    assert_eq!(packages[0].dependencies, vec!["npm:left-pad@^1.3.0"]);
    assert!(packages[0].source_url.starts_with("file:"));

    let filtered =
        listed_locked_packages(&project, Some(Ecosystem::Npm), &["local-tool".to_owned()]).unwrap();
    assert_eq!(filtered.len(), 1);
    let missing =
        listed_locked_packages(&project, Some(Ecosystem::Npm), &["missing".to_owned()]).unwrap();
    assert!(missing.is_empty());

    let query = NpmQueryAction {
        selector: ":root > *".to_owned(),
        workspaces: Vec::new(),
        all_workspaces: false,
        include_workspace_root: false,
        package_lock_only: false,
        expect_results: None,
        expect_result_count: None,
    };
    let selected = npm_query_items(&project, &query)
        .unwrap()
        .into_iter()
        .filter(|item| npm_query_selector_matches(item, &query.selector).unwrap())
        .map(|item| item.name)
        .collect::<Vec<_>>();
    assert_eq!(selected, vec!["local-tool"]);

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_list_json_uses_npm_tree_shape() {
    let project = test_dir("npm-list-json-tree-project");
    fs::write(
        project.join("package.json"),
        r#"{
              "name": "root",
              "version": "1.0.0",
              "dependencies": { "left-pad": "1.1.0" }
            }"#,
    )
    .unwrap();
    fs::write(
        project.join("omc.lock"),
        toml::to_string_pretty(&OmcLock {
            version: 1,
            signing_key: None,
            packages: vec![
                locked_npm_package("left-pad", "1.1.0", vec!["npm:dep@1.0.0".to_owned()]),
                locked_npm_package("dep", "1.0.0", Vec::new()),
            ],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();

    let tree = npm_list_json_tree(&project, &[], 0).unwrap();
    assert_eq!(tree["name"], "root");
    assert_eq!(tree["version"], "1.0.0");
    assert_eq!(tree["dependencies"]["left-pad"]["version"], "1.1.0");
    assert_eq!(
        tree["dependencies"]["left-pad"]["resolved"],
        "https://registry.example/left-pad/-/left-pad-1.1.0.tgz"
    );
    assert!(tree["dependencies"]["left-pad"]
        .get("dependencies")
        .is_none());

    let deep_tree = npm_list_json_tree(&project, &[], 1).unwrap();
    assert_eq!(
        deep_tree["dependencies"]["left-pad"]["dependencies"]["dep"]["version"],
        "1.0.0"
    );
    assert!(tree.as_array().is_none());

    let filtered = npm_list_json_tree(&project, &["dep".to_owned()], 0).unwrap();
    assert!(filtered["dependencies"].get("left-pad").is_none());
    assert_eq!(filtered["dependencies"]["dep"]["version"], "1.0.0");

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_list_includes_package_json_local_paths() {
    let project = test_dir("npm-list-package-json-local-paths-project");
    let local = project.join("vendor/local-tool");
    let child = project.join("vendor/child-tool");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&child).unwrap();
    fs::write(
        local.join("package.json"),
        r#"{
              "name": "local-tool",
              "version": "1.2.3",
              "dependencies": { "child-tool": "file:../child-tool" }
            }"#,
    )
    .unwrap();
    fs::write(
        child.join("package.json"),
        r#"{ "name": "child-tool", "version": "0.5.0" }"#,
    )
    .unwrap();
    fs::write(
        project.join("package.json"),
        r#"{
              "name": "root",
              "version": "1.0.0",
              "dependencies": { "local-tool": "file:vendor/local-tool" }
            }"#,
    )
    .unwrap();
    fs::write(project.join("omc.lock"), "version = 1\n").unwrap();

    let packages = listed_locked_packages(&project, Some(Ecosystem::Npm), &[]).unwrap();
    assert_eq!(
        packages
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_str()))
            .collect::<Vec<_>>(),
        vec![("child-tool", "0.5.0"), ("local-tool", "1.2.3")]
    );
    let local_package = packages
        .iter()
        .find(|package| package.name == "local-tool")
        .unwrap();
    assert_eq!(
        local_package.dependencies,
        vec!["npm:child-tool@file:../child-tool"]
    );

    let query = NpmQueryAction {
        selector: ":root > *".to_owned(),
        workspaces: Vec::new(),
        all_workspaces: false,
        include_workspace_root: false,
        package_lock_only: false,
        expect_results: None,
        expect_result_count: None,
    };
    let selected = npm_query_items(&project, &query)
        .unwrap()
        .into_iter()
        .filter(|item| npm_query_selector_matches(item, &query.selector).unwrap())
        .map(|item| item.name)
        .collect::<Vec<_>>();
    assert_eq!(selected, vec!["local-tool"]);

    let _ = fs::remove_dir_all(project);
}

#[test]
fn queries_npm_locked_packages_with_common_selectors() {
    fn query_names(items: &[NpmQueryItem], selector: &str) -> Vec<String> {
        let mut names = items
            .iter()
            .filter(|item| npm_query_selector_matches(item, selector).unwrap())
            .map(|item| item.name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    let dir = test_dir("npm-query");
    fs::write(
        dir.join("package.json"),
        r#"{
              "name": "query-root",
              "version": "1.0.0",
              "dependencies": { "prod-pkg": "1.0.0" },
              "devDependencies": { "dev-pkg": "1.0.0" },
              "optionalDependencies": { "optional-pkg": "1.0.0" }
            }"#,
    )
    .unwrap();

    fs::write(
        dir.join("omc.lock"),
        r#"
version = 1

[[packages]]
ecosystem = "npm"
name = "prod-pkg"
version = "1.0.0"
source_url = "https://registry.example/prod-pkg/-/prod-pkg-1.0.0.tgz"
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"
dependencies = ["npm:leaf-pkg@1.0.0"]

[[packages]]
ecosystem = "npm"
name = "leaf-pkg"
version = "1.0.0"
source_url = "https://registry.example/leaf-pkg/-/leaf-pkg-1.0.0.tgz"
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"

[[packages]]
ecosystem = "npm"
name = "dev-pkg"
version = "1.0.0"
source_url = "https://registry.example/dev-pkg/-/dev-pkg-1.0.0.tgz"
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"

[[packages]]
ecosystem = "npm"
name = "optional-pkg"
version = "1.0.0"
source_url = "https://registry.example/optional-pkg/-/optional-pkg-1.0.0.tgz"
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"
optional_dependencies = ["npm:leaf-optional@1.0.0"]

[[packages]]
ecosystem = "npm"
name = "leaf-optional"
version = "1.0.0"
source_url = "https://registry.example/leaf-optional/-/leaf-optional-1.0.0.tgz"
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"
"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("node_modules/prod-pkg")).unwrap();
    fs::write(
        dir.join("node_modules/prod-pkg/package.json"),
        r#"{
              "name": "prod-pkg",
              "version": "1.0.0",
              "license": "MIT",
              "scripts": { "postinstall": "node postinstall.js" }
            }"#,
    )
    .unwrap();

    let action = NpmQueryAction {
        selector: "*".to_owned(),
        workspaces: Vec::new(),
        all_workspaces: false,
        include_workspace_root: false,
        package_lock_only: false,
        expect_results: None,
        expect_result_count: None,
    };
    let items = npm_query_items(&dir, &action).unwrap();

    assert_eq!(
        query_names(&items, ":root > *"),
        vec![
            "dev-pkg".to_owned(),
            "optional-pkg".to_owned(),
            "prod-pkg".to_owned(),
        ]
    );
    assert_eq!(query_names(&items, ".dev"), vec!["dev-pkg".to_owned()]);
    assert_eq!(
        query_names(&items, ".optional"),
        vec!["leaf-optional".to_owned(), "optional-pkg".to_owned()]
    );
    assert_eq!(
        query_names(&items, "#prod-pkg"),
        vec!["prod-pkg".to_owned()]
    );
    assert_eq!(
        query_names(&items, "[license=MIT]"),
        vec!["prod-pkg".to_owned()]
    );
    assert_eq!(
        query_names(&items, ":attr(scripts, [postinstall])"),
        vec!["prod-pkg".to_owned()]
    );
    assert_eq!(
        query_names(&items, ":has(*)"),
        vec!["optional-pkg".to_owned(), "prod-pkg".to_owned(),]
    );
    assert_eq!(
        query_names(&items, ":empty"),
        vec![
            "dev-pkg".to_owned(),
            "leaf-optional".to_owned(),
            "leaf-pkg".to_owned(),
        ]
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn dry_runs_npm_publish_local_package() {
    let dir = test_dir("npm-publish-dry-run");
    fs::write(
            dir.join("package.json"),
            r#"{ "name": "@scope/publish-demo", "version": "1.2.3", "publishConfig": {"registry": "https://publish.example.invalid/npm"} }"#,
        )
        .unwrap();
    fs::write(dir.join("index.js"), "module.exports = 1\n").unwrap();
    let (_, _, tarball) = npm_pack_package_for_publish(&dir).unwrap();
    let payload = serde_json::json!({
        "subject": [{
            "digest": {
                "sha512": sha512_hex(&tarball)
            }
        }]
    })
    .to_string();
    let provenance_file = dir.with_extension("sigstore");
    fs::write(
        &provenance_file,
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "dsseEnvelope": {
                "payload": BASE64_STANDARD.encode(payload)
            }
        })
        .to_string(),
    )
    .unwrap();

    print_npm_publish(
        &dir,
        NpmPublishAction {
            package: None,
            tag: "beta".to_owned(),
            access: Some("public".to_owned()),
            provenance: NpmPublishProvenance::File(provenance_file),
            dry_run: true,
            json: true,
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
            otp: None,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        },
    )
    .unwrap();
}

#[test]
fn direct_npm_publish_resolves_local_paths_from_invocation_cwd() {
    let project = test_dir("direct-npm-publish-local-project");
    let invocation_cwd = project.join("work/release");
    let package = invocation_cwd.join("pkg");
    fs::create_dir_all(&package).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        package.join("package.json"),
        r#"{ "name": "release-pkg", "version": "1.2.3" }"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 1;\n").unwrap();
    fs::write(
        invocation_cwd.join("ci.npmrc"),
        "registry=https://publish.example.invalid/npm\n",
    )
    .unwrap();

    let (_, _, tarball) = npm_pack_package_for_publish(&package).unwrap();
    let payload = serde_json::json!({
        "subject": [{
            "digest": {
                "sha512": sha512_hex(&tarball)
            }
        }]
    })
    .to_string();
    fs::write(
        invocation_cwd.join("build.sigstore"),
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "dsseEnvelope": {
                "payload": BASE64_STANDARD.encode(payload)
            }
        })
        .to_string(),
    )
    .unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "publish",
            "./pkg",
            "--dry-run",
            "--json",
            "--userconfig",
            "ci.npmrc",
            "--provenance-file",
            "build.sigstore",
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
}

#[test]
fn direct_npm_edit_runs_editor_for_installed_package() {
    let project = test_dir("direct-npm-edit-project");
    let invocation_cwd = project.join("work/release");
    let package_dir = project.join("node_modules/@scope/pkg");
    fs::create_dir_all(&invocation_cwd).unwrap();
    fs::create_dir_all(&package_dir).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        package_dir.join("package.json"),
        r#"{ "name": "@scope/pkg", "version": "1.0.0" }"#,
    )
    .unwrap();
    let editor_script = invocation_cwd.join("edit-package.sh");
    fs::write(
        &editor_script,
        "#!/bin/sh\nprintf 'edited=true\\n' > \"$1\"\n",
    )
    .unwrap();
    let editor = format!("sh {}", editor_script.display());

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "--editor",
            editor.as_str(),
            "edit",
            "@scope/pkg/package.json",
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(package_dir.join("package.json")).unwrap(),
        "edited=true\n"
    );
    assert!(npm_edit_target_parts("left-pad/..").is_err());
}

#[test]
fn npm_trust_create_dry_run_does_not_call_registry() {
    let project = test_dir("npm-trust-dry-run");
    let status = run_npm_compat(
        &project,
        &args(&[
            "trust",
            "github",
            "@demo/pkg",
            "--file",
            "release.yml",
            "--repo",
            "turenio/omc",
            "--dry-run",
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
}

#[test]
fn npm_trust_create_dry_run_infers_github_repository_from_package_json() {
    let project = test_dir("npm-trust-dry-run-infer-repo");
    fs::write(
        project.join("package.json"),
        r#"{
  "name": "@demo/pkg",
  "version": "1.0.0",
  "repository": {
    "url": "git+ssh://git@github.com/turenio/omc.git"
  }
}"#,
    )
    .unwrap();
    let status = run_npm_compat(
        &project,
        &args(&["trust", "github", "--file", "release.yml", "--dry-run"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
}

#[test]
fn builds_npm_lifecycle_env_from_package_json() {
    let dir = test_dir("npm-lifecycle-env");
    fs::write(
        dir.join("package.json"),
        r#"{
              "name": "@scope/env-demo",
              "version": "1.2.3",
              "bin": "cli.js",
              "config": {
                "port": 8080,
                "nested": {"token-name": "DEMO_TOKEN"}
              },
              "scripts": {"show": "node show.js"}
            }"#,
    )
    .unwrap();

    let vars = npm_lifecycle_env(&dir, "run", "show", "node show.js").unwrap();

    assert_eq!(vars.get("npm_command").map(String::as_str), Some("run"));
    assert_eq!(
        vars.get("npm_lifecycle_event").map(String::as_str),
        Some("show")
    );
    assert_eq!(
        vars.get("npm_lifecycle_script").map(String::as_str),
        Some("node show.js")
    );
    assert_eq!(
        vars.get("npm_package_name").map(String::as_str),
        Some("@scope/env-demo")
    );
    assert_eq!(
        vars.get("npm_package_version").map(String::as_str),
        Some("1.2.3")
    );
    assert_eq!(
        vars.get("npm_package_bin_env-demo").map(String::as_str),
        Some("cli.js")
    );
    assert_eq!(
        vars.get("npm_package_config_port").map(String::as_str),
        Some("8080")
    );
    assert_eq!(
        vars.get("npm_package_config_nested_token-name")
            .map(String::as_str),
        Some("DEMO_TOKEN")
    );
    let absolute_dir = absolute_project_dir(&dir);
    let package_json = absolute_dir
        .join("package.json")
        .to_string_lossy()
        .into_owned();
    let local_prefix = absolute_dir.to_string_lossy().into_owned();
    assert_eq!(
        vars.get("npm_package_json").map(String::as_str),
        Some(package_json.as_str())
    );
    assert_eq!(
        vars.get("npm_config_local_prefix").map(String::as_str),
        Some(local_prefix.as_str())
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn orders_npm_pre_and_post_lifecycle_scripts() {
    let scripts = BTreeMap::from([
        ("check".to_owned(), "node check.js".to_owned()),
        ("precheck".to_owned(), "node pre.js".to_owned()),
        ("postcheck".to_owned(), "node post.js".to_owned()),
        ("prepare".to_owned(), "node prepare.js".to_owned()),
    ]);

    assert_eq!(
        package_script_lifecycle_order(&scripts, "check").unwrap(),
        vec![
            "precheck".to_owned(),
            "check".to_owned(),
            "postcheck".to_owned()
        ]
    );
    assert_eq!(
        package_script_lifecycle_order(&scripts, "prepare").unwrap(),
        vec!["prepare".to_owned()]
    );
}

#[test]
fn npm_run_if_present_allows_missing_script() {
    let dir = test_dir("npm-run-if-present");
    fs::write(
        dir.join("package.json"),
        r#"{ "scripts": { "test": "true" } }"#,
    )
    .unwrap();

    let status = run_package_script_with_npm_command(&dir, "run", "build", &[], true).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn resolves_npm_workspace_script_targets() {
    let dir = test_dir("npm-run-workspaces");
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"], "scripts": { "build": "true" } }"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("packages/lib")).unwrap();
    fs::write(
        dir.join("packages/lib/package.json"),
        r#"{ "name": "@demo/lib", "scripts": { "build": "true" } }"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("packages/api")).unwrap();
    fs::write(
        dir.join("packages/api/package.json"),
        r#"{ "name": "@demo/api", "scripts": { "build": "true" } }"#,
    )
    .unwrap();

    assert_eq!(
        npm_script_target_dirs(&dir, &["@demo/lib".to_owned()], false, false).unwrap(),
        vec![dir.join("packages/lib")]
    );
    assert_eq!(
        npm_script_target_dirs(&dir, &["packages/api".to_owned()], false, false).unwrap(),
        vec![dir.join("packages/api")]
    );
    assert_eq!(
        npm_script_target_dirs(&dir, &[], true, true).unwrap(),
        vec![
            dir.clone(),
            dir.join("packages/api"),
            dir.join("packages/lib")
        ]
    );
    assert_eq!(
        npm_exec_target_cwds(
            &dir,
            &dir,
            &NpmExecAction {
                packages: Vec::new(),
                command: "node".to_owned(),
                args: Vec::new(),
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: vec!["@demo/api".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            }
        )
        .unwrap(),
        vec![dir.join("packages/api")]
    );
    assert!(npm_script_target_dirs(&dir, &["missing".to_owned()], false, false).is_err());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn saves_npm_workspace_package_json_dependencies() {
    let dir = test_dir("npm-workspace-save");
    fs::create_dir_all(dir.join("packages/lib")).unwrap();
    fs::write(
            dir.join("packages/lib/package.json"),
            r#"{ "name": "@demo/lib", "dependencies": { "old": "1.0.0" }, "devDependencies": { "left-pad": "0.0.1" } }"#,
        )
        .unwrap();

    save_npm_package_json_dependency(
        &dir.join("packages/lib"),
        "left.pad",
        "1.3.0",
        ManifestDependencyKind::Production,
        false,
    )
    .unwrap();
    let package = read_npm_pkg_json(&dir.join("packages/lib/package.json")).unwrap();
    assert_eq!(
        package
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
            .and_then(|dependencies| dependencies.get("left.pad"))
            .and_then(serde_json::Value::as_str),
        Some("1.3.0")
    );
    assert!(package
        .get("devDependencies")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|dependencies| !dependencies.contains_key("left.pad")));

    fs::create_dir_all(dir.join("vendor/local-pkg")).unwrap();
    fs::write(
        dir.join("vendor/local-pkg/package.json"),
        r#"{ "name": "@demo/local" }"#,
    )
    .unwrap();
    save_npm_package_json_local_dependency(
        &dir,
        &dir.join("packages/lib"),
        &PathBuf::from("vendor/local-pkg"),
        ManifestDependencyKind::Dev,
        false,
    )
    .unwrap();
    let package = read_npm_pkg_json(&dir.join("packages/lib/package.json")).unwrap();
    let saved = package
        .get("devDependencies")
        .and_then(serde_json::Value::as_object)
        .and_then(|dependencies| dependencies.get("@demo/local"))
        .and_then(serde_json::Value::as_str)
        .unwrap();
    assert!(saved.starts_with("file:"));
    assert!(saved.ends_with("vendor/local-pkg"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn saves_npm_alias_requirements_as_aliases() {
    let alias = PackageSpec::parse("npm:string-width-cjs@npm:string-width@^4.2.0").unwrap();
    assert_eq!(
        npm_package_json_requirement_for_link_root(
            &alias,
            &locked_npm_package("string-width-cjs", "4.2.3", Vec::new()),
            DEFAULT_NPM_SAVE_PREFIX,
        ),
        (
            "string-width-cjs".to_owned(),
            "npm:string-width@^4.2.3".to_owned()
        )
    );

    let scoped = PackageSpec::parse("npm:demo-runtime@npm:@scope/runtime@^1.0.0").unwrap();
    assert_eq!(
        npm_package_json_requirement_for_link_root(
            &scoped,
            &locked_npm_package("demo-runtime", "1.2.0", Vec::new()),
            DEFAULT_NPM_SAVE_PREFIX,
        ),
        (
            "demo-runtime".to_owned(),
            "npm:@scope/runtime@^1.2.0".to_owned()
        )
    );

    let exact = PackageSpec::parse("npm:left-pad").unwrap();
    assert_eq!(
        npm_package_json_requirement_for_link_root(
            &exact,
            &locked_npm_package("left-pad", "1.3.0", Vec::new()),
            "",
        ),
        ("left-pad".to_owned(), "1.3.0".to_owned())
    );

    assert_eq!(
        npm_package_json_requirement_for_link_root(
            &exact,
            &locked_npm_package("left-pad", "1.3.0", Vec::new()),
            "~",
        ),
        ("left-pad".to_owned(), "~1.3.0".to_owned())
    );
}

#[test]
fn syncs_npm_package_lock_from_omc_lock() {
    let project = test_dir("npm-package-lock-sync");
    fs::write(
        project.join("package.json"),
        r#"{
                "name": "demo",
                "version": "1.0.0",
                "license": "MIT",
                "dependencies": { "is-odd": "3.0.1" },
                "devDependencies": { "@scope/tool": "^2.0.0" }
            }"#,
    )
    .unwrap();

    let mut is_odd = locked_npm_package("is-odd", "3.0.1", vec!["npm:is-number@^6.0.0".to_owned()]);
    is_odd.sha256 = "13c23b3f1f3a5c146b8906e23c8e674f8e4a6ff44b77720e1d4bddb7b2caf312".to_owned();
    let scoped = locked_npm_package("@scope/tool", "2.1.0", Vec::new());
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![
            locked_pypi_package("idna", "3.7", Vec::new()),
            is_odd,
            scoped,
        ],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    fs::write(project.join("omc.lock"), toml::to_string(&lock).unwrap()).unwrap();

    sync_npm_package_lock(&project).unwrap();

    let package_lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project.join("package-lock.json")).unwrap())
            .unwrap();
    assert_eq!(package_lock["lockfileVersion"], 3);
    assert_eq!(
        package_lock["packages"][""]["dependencies"]["is-odd"],
        "3.0.1"
    );
    assert_eq!(
        package_lock["packages"][""]["devDependencies"]["@scope/tool"],
        "^2.0.0"
    );
    assert_eq!(
        package_lock["packages"]["node_modules/is-odd"]["dependencies"]["is-number"],
        "^6.0.0"
    );
    assert_eq!(
        package_lock["packages"]["node_modules/is-odd"]["integrity"],
        "sha256-E8I7Px86XBRriQbiPI5nT45Kb/RLd3IOHUvdt7LK8xI="
    );
    assert_eq!(
        package_lock["packages"]["node_modules/@scope/tool"]["version"],
        "2.1.0"
    );
    assert!(package_lock["packages"]["node_modules/idna"].is_null());
}

#[test]
fn syncs_npm_package_lock_from_local_source_artifacts() {
    let project = test_dir("npm-package-lock-local-sources");
    fs::write(
        project.join("package.json"),
        r#"{
                "name": "demo",
                "version": "1.0.0",
                "dependencies": { "local-pkg": "file:vendor/local-pkg" },
                "devDependencies": { "dev-pkg": "file:vendor/dev-pkg" }
            }"#,
    )
    .unwrap();
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![locked_pypi_package("idna", "3.7", Vec::new())],
        local_sources: vec![
            locked_local_source(Ecosystem::Npm, "local-pkg", "1.2.3", "vendor/local-pkg"),
            locked_local_source(Ecosystem::Npm, "dev-pkg", "0.4.0", "vendor/dev-pkg"),
            locked_local_source(Ecosystem::Pypi, "local-py", "0.2.0", "vendor/local-py"),
        ],
        python_vcs: Vec::new(),
    };
    fs::write(project.join("omc.lock"), toml::to_string(&lock).unwrap()).unwrap();

    sync_npm_package_lock(&project).unwrap();

    let package_lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project.join("package-lock.json")).unwrap())
            .unwrap();
    assert_eq!(
        package_lock["packages"]["node_modules/local-pkg"]["version"],
        "1.2.3"
    );
    assert_eq!(
        package_lock["packages"]["node_modules/local-pkg"]["resolved"],
        "file:vendor/local-pkg"
    );
    assert_eq!(
        package_lock["packages"]["node_modules/dev-pkg"]["version"],
        "0.4.0"
    );
    assert_eq!(
        package_lock["packages"]["node_modules/dev-pkg"]["resolved"],
        "file:vendor/dev-pkg"
    );
    assert_eq!(
        package_lock["packages"]["node_modules/dev-pkg"]["dev"],
        true
    );
    assert!(package_lock["packages"]["node_modules/local-py"].is_null());
}

#[test]
fn npm_shrinkwrap_renames_package_lock() {
    let project = test_dir("npm-shrinkwrap-rename");
    fs::write(
        project.join("package.json"),
        r#"{ "name": "demo", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        project.join("package-lock.json"),
        r#"{
                "name": "demo",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": true,
                "packages": { "": { "name": "demo", "version": "1.0.0" } }
            }"#,
    )
    .unwrap();

    let status = run_npm_compat(&project, &args(&["shrinkwrap"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("package-lock.json").exists());
    let shrinkwrap: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project.join("npm-shrinkwrap.json")).unwrap())
            .unwrap();
    assert_eq!(shrinkwrap["lockfileVersion"], 3);
    assert_eq!(shrinkwrap["packages"][""]["name"], "demo");
}

#[test]
fn npm_shrinkwrap_creates_from_omc_lock() {
    let project = test_dir("npm-shrinkwrap-from-omc-lock");
    fs::write(
        project.join("package.json"),
        r#"{
                "name": "demo",
                "version": "1.0.0",
                "dependencies": { "left-pad": "1.3.0" }
            }"#,
    )
    .unwrap();
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![locked_npm_package("left-pad", "1.3.0", Vec::new())],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    fs::write(project.join("omc.lock"), toml::to_string(&lock).unwrap()).unwrap();

    let status = run_npm_compat(&project, &args(&["shrinkwrap"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("package-lock.json").exists());
    let shrinkwrap: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project.join("npm-shrinkwrap.json")).unwrap())
            .unwrap();
    assert_eq!(shrinkwrap["lockfileVersion"], 3);
    assert_eq!(
        shrinkwrap["packages"][""]["dependencies"]["left-pad"],
        "1.3.0"
    );
    assert_eq!(
        shrinkwrap["packages"]["node_modules/left-pad"]["version"],
        "1.3.0"
    );
}
