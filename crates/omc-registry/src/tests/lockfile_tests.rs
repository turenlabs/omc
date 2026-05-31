//! `lockfile` domain tests, extracted from the original monolithic tests.rs.

use super::*;

#[test]
fn npm_direct_specs_prefer_locked_github_resolved_url() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = LinkOptions::new(dir.path());
    options.npm_resolved.insert(
        "npm:github-pkg".to_owned(),
        "git+https://github.com/turenio/omc.git#v1.0.0".to_owned(),
    );
    let spec = PackageSpec::parse("npm:github-pkg @ github:turenio/omc#main").unwrap();

    let source_url = locked_npm_direct_url_for_spec(&spec, &options)
        .unwrap()
        .unwrap();

    assert_eq!(
        source_url,
        "https://github.com/turenio/omc/archive/v1.0.0.tar.gz"
    );
}

#[test]
fn npm_lockfile_resolution_converts_github_resolved_url() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = LinkOptions::new(dir.path());
    options
        .constraints
        .insert("npm:github-pkg".to_owned(), "1.2.3".to_owned());
    options.npm_resolved.insert(
        "npm:github-pkg".to_owned(),
        "git+ssh://git@github.com/turenio/omc.git#v1.2.3".to_owned(),
    );
    let spec = PackageSpec::parse("npm:github-pkg@^1.0.0").unwrap();

    let resolved = resolve_npm_lockfile_tarball(&spec, "github-pkg", Some("^1.0.0"), &options)
        .unwrap()
        .unwrap();

    assert_eq!(
        resolved.source_url,
        "https://github.com/turenio/omc/archive/v1.2.3.tar.gz"
    );
    assert!(resolved.npm_direct_tarball);
}

#[test]
fn writes_direct_url_manifest_dependencies() {
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

    add_package_graph(&spec, &LinkOptions::new(dir.path())).unwrap();

    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    let requirement = manifest.dependencies.get("npm:local-pkg").unwrap();
    assert!(requirement.starts_with("file://"));
    assert!(parse_manifest_dependency("npm:local-pkg", requirement)
        .unwrap()
        .direct_url
        .is_some());
}

#[test]
fn skips_manifest_write_when_save_is_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("transient-pkg-1.0.0.tgz");
    fs::write(
        &archive,
        npm_tgz_for_test(r#"{ "name": "transient-pkg", "version": "1.0.0" }"#),
    )
    .unwrap();
    let spec = parse_npm_direct_archive_reference("./transient-pkg-1.0.0.tgz", dir.path())
        .unwrap()
        .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.save_manifest_dependency = false;
    add_package_graph(&spec, &options).unwrap();

    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    assert!(manifest.dependencies.is_empty());
    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "transient-pkg"));
}

#[test]
fn installs_manifest_npm_local_paths() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("vendor/direct-pkg")).unwrap();
    fs::write(
        dir.path().join("vendor/direct-pkg/index.js"),
        "module.exports = 43;\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/direct-pkg/package.json"),
        r#"{ "name": "direct-pkg", "bin": { "direct-tool": "cli.js" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("vendor/direct-pkg/cli.js"),
        "#!/usr/bin/env node\n",
    )
    .unwrap();

    add_manifest_npm_local_paths(
        dir.path(),
        &[PathBuf::from("vendor/direct-pkg")],
        ManifestDependencyKind::Production,
    )
    .unwrap();
    let report = install_project(&LinkOptions::new(dir.path())).unwrap();

    assert_eq!(report.npm_bins, 1);
    assert_eq!(
        fs::read_to_string(dir.path().join("node_modules/direct-pkg/index.js")).unwrap(),
        "module.exports = 43;\n"
    );
    assert!(dir.path().join("node_modules/.bin/direct-tool").exists());
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    assert_eq!(manifest.npm_local_paths, vec!["vendor/direct-pkg"]);
}

#[test]
fn dev_manifest_npm_local_paths_respect_omit_dev() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("vendor/dev-pkg")).unwrap();
    fs::write(
        dir.path().join("vendor/dev-pkg/package.json"),
        r#"{ "name": "dev-pkg" }"#,
    )
    .unwrap();

    add_manifest_npm_local_paths(
        dir.path(),
        &[PathBuf::from("vendor/dev-pkg")],
        ManifestDependencyKind::Dev,
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.include_dev_dependencies = false;
    install_project(&options).unwrap();
    assert!(!dir.path().join("node_modules/dev-pkg").exists());

    options.include_dev_dependencies = true;
    install_project(&options).unwrap();
    assert!(dir.path().join("node_modules/dev-pkg").exists());
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    assert_eq!(manifest.npm_dev_local_paths, vec!["vendor/dev-pkg"]);
}

#[test]
fn manifest_npm_local_paths_preserve_dependency_kinds() {
    let dir = tempfile::tempdir().unwrap();

    add_manifest_npm_local_paths(
        dir.path(),
        &[PathBuf::from("vendor/optional-pkg")],
        ManifestDependencyKind::Optional,
    )
    .unwrap();
    add_manifest_npm_local_paths(
        dir.path(),
        &[PathBuf::from("vendor/peer-pkg")],
        ManifestDependencyKind::Peer,
    )
    .unwrap();
    add_manifest_npm_local_paths(
        dir.path(),
        &[PathBuf::from("vendor/optional-pkg")],
        ManifestDependencyKind::Dev,
    )
    .unwrap();

    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    assert!(manifest.npm_local_paths.is_empty());
    assert_eq!(manifest.npm_dev_local_paths, vec!["vendor/optional-pkg"]);
    assert!(manifest.npm_optional_local_paths.is_empty());
    assert_eq!(manifest.npm_peer_local_paths, vec!["vendor/peer-pkg"]);
}

#[test]
fn lock_project_updates_lock_without_installing_packages() {
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

    let reports = lock_project(&LinkOptions::new(dir.path())).unwrap();

    assert!(reports
        .iter()
        .any(|report| report.locked.name == "local-pkg"));
    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "local-pkg"));
    assert!(!dir.path().join("node_modules").exists());
}

#[test]
fn removes_manifest_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = OmcManifest {
        project: ProjectInfo {
            name: "remove-demo".to_owned(),
            version: "0.1.0".to_owned(),
        },
        dependencies: BTreeMap::from([("npm:left-pad".to_owned(), "1.3.0".to_owned())]),
        dev_dependencies: BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())]),
        optional_dependencies: BTreeMap::from([(
            "npm:optional-left".to_owned(),
            "1.0.0".to_owned(),
        )]),
        peer_dependencies: BTreeMap::from([("npm:react".to_owned(), "18.2.0".to_owned())]),
        npm_local_paths: Vec::new(),
        npm_dev_local_paths: Vec::new(),
        npm_optional_local_paths: Vec::new(),
        npm_peer_local_paths: Vec::new(),
        policy: ManifestPolicy {
            allow: vec!["http:api.example.com".to_owned()],
            allow_flow: Vec::new(),
            min_release_age: None,
        },
        registries: ManifestRegistries::default(),
    };
    fs::write(
        dir.path().join("omc.toml"),
        toml::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let removed =
        remove_manifest_dependency(dir.path(), &PackageSpec::parse("npm:left-pad").unwrap())
            .unwrap();
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();

    assert!(removed);
    assert!(manifest.dependencies.is_empty());
    assert_eq!(
        manifest.dev_dependencies,
        BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
    );
    assert_eq!(
        manifest.optional_dependencies,
        BTreeMap::from([("npm:optional-left".to_owned(), "1.0.0".to_owned())])
    );
    assert_eq!(
        manifest.peer_dependencies,
        BTreeMap::from([("npm:react".to_owned(), "18.2.0".to_owned())])
    );
    assert_eq!(manifest.policy.allow, vec!["http:api.example.com"]);
}

#[test]
fn writes_manifest_dependency_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let spec = PackageSpec::parse("npm:is-odd@3.0.1").unwrap();
    write_manifest_dependency(dir.path(), &spec, "3.0.1", ManifestDependencyKind::Dev).unwrap();
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();

    assert!(manifest.dependencies.is_empty());
    assert_eq!(
        manifest.dev_dependencies,
        BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
    );

    write_manifest_dependency(dir.path(), &spec, "3.0.1", ManifestDependencyKind::Optional)
        .unwrap();
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    assert!(manifest.dependencies.is_empty());
    assert!(manifest.dev_dependencies.is_empty());
    assert_eq!(
        manifest.optional_dependencies,
        BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
    );
    assert!(manifest.peer_dependencies.is_empty());

    write_manifest_dependency(dir.path(), &spec, "3.0.1", ManifestDependencyKind::Peer).unwrap();
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    assert!(manifest.dependencies.is_empty());
    assert!(manifest.dev_dependencies.is_empty());
    assert!(manifest.optional_dependencies.is_empty());
    assert_eq!(
        manifest.peer_dependencies,
        BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
    );

    write_manifest_dependency(
        dir.path(),
        &spec,
        "3.0.1",
        ManifestDependencyKind::Production,
    )
    .unwrap();
    let manifest = read_manifest(dir.path().join("omc.toml")).unwrap();
    assert_eq!(
        manifest.dependencies,
        BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())])
    );
    assert!(manifest.dev_dependencies.is_empty());
    assert!(manifest.optional_dependencies.is_empty());
    assert!(manifest.peer_dependencies.is_empty());
}

#[test]
fn manifest_optional_and_peer_dependencies_are_runtime_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = OmcManifest {
        project: ProjectInfo {
            name: "dependency-kind-demo".to_owned(),
            version: "0.1.0".to_owned(),
        },
        dependencies: BTreeMap::from([("npm:prod-pkg".to_owned(), "1.0.0".to_owned())]),
        dev_dependencies: BTreeMap::from([("npm:dev-pkg".to_owned(), "2.0.0".to_owned())]),
        optional_dependencies: BTreeMap::from([(
            "npm:optional-pkg".to_owned(),
            "3.0.0".to_owned(),
        )]),
        peer_dependencies: BTreeMap::from([("npm:peer-pkg".to_owned(), "4.0.0".to_owned())]),
        npm_local_paths: Vec::new(),
        npm_dev_local_paths: Vec::new(),
        npm_optional_local_paths: Vec::new(),
        npm_peer_local_paths: Vec::new(),
        policy: ManifestPolicy::default(),
        registries: ManifestRegistries::default(),
    };
    fs::write(
        dir.path().join("omc.toml"),
        toml::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let mut production_options = LinkOptions::new(dir.path());
    production_options.include_dev_dependencies = false;
    production_options.discover_project_requirements = false;
    let production_specs = project_requested_specs(&mut production_options, false).unwrap();
    assert!(has_spec(&production_specs, "prod-pkg", "1.0.0"));
    assert!(has_spec(&production_specs, "optional-pkg", "3.0.0"));
    assert!(has_spec(&production_specs, "peer-pkg", "4.0.0"));
    assert!(!has_spec(&production_specs, "dev-pkg", "2.0.0"));

    let mut dev_options = LinkOptions::new(dir.path());
    dev_options.include_dev_dependencies = true;
    dev_options.discover_project_requirements = false;
    let dev_specs = project_requested_specs(&mut dev_options, false).unwrap();
    assert!(has_spec(&dev_specs, "dev-pkg", "2.0.0"));

    let mut omit_options = LinkOptions::new(dir.path());
    omit_options.include_dev_dependencies = false;
    omit_options.include_optional_dependencies = false;
    omit_options.include_peer_dependencies = false;
    omit_options.discover_project_requirements = false;
    let omit_specs = project_requested_specs(&mut omit_options, false).unwrap();
    assert!(has_spec(&omit_specs, "prod-pkg", "1.0.0"));
    assert!(!has_spec(&omit_specs, "optional-pkg", "3.0.0"));
    assert!(!has_spec(&omit_specs, "peer-pkg", "4.0.0"));
}

#[test]
fn reads_package_lock_constraints_for_unique_versions() {
    let dir = tempfile::tempdir().unwrap();
    let package_lock = dir.path().join("package-lock.json");
    fs::write(
        &package_lock,
        r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/is-odd": { "version": "3.0.1" },
                    "node_modules/@scope/pkg": { "version": "1.2.3" },
                    "node_modules/a/node_modules/dup": { "version": "1.0.0" },
                    "node_modules/b/node_modules/dup": { "version": "2.0.0" }
                }
            }"#,
    )
    .unwrap();

    let constraints = read_package_lock_requirements(&package_lock)
        .unwrap()
        .constraints;
    assert_eq!(
        constraints.get("npm:is-odd").map(String::as_str),
        Some("3.0.1")
    );
    assert_eq!(
        constraints.get("npm:@scope/pkg").map(String::as_str),
        Some("1.2.3")
    );
    assert!(!constraints.contains_key("npm:dup"));
}

#[test]
fn reads_package_lock_integrities_for_unique_versions() {
    let dir = tempfile::tempdir().unwrap();
    let package_lock = dir.path().join("package-lock.json");
    fs::write(
            &package_lock,
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/is-odd": {
                        "version": "3.0.1",
                        "integrity": "sha512-FGl0QHAcOIX3yNX6pZ8za0ccqGMyA07/DT/dwC3JsYuDVuhA21SCPI/S8svQkGlpzxMs+Lucc9x2m0/9gXvSPQ=="
                    },
                    "node_modules/a/node_modules/dup": {
                        "version": "1.0.0",
                        "integrity": "sha512-one"
                    },
                    "node_modules/b/node_modules/dup": {
                        "version": "2.0.0",
                        "integrity": "sha512-two"
                    }
                },
                "dependencies": {
                    "legacy": {
                        "version": "4.0.0",
                        "integrity": "sha1-Hl3LtZt1PLHUbiNNj2GAKFuLhq0="
                    }
                }
            }"#,
        )
        .unwrap();

    let requirements = read_package_lock_requirements(&package_lock).unwrap();
    assert_eq!(
            requirements
                .npm_integrities
                .get("npm:is-odd")
                .and_then(|values| values.iter().next())
                .map(String::as_str),
            Some(
                "sha512-FGl0QHAcOIX3yNX6pZ8za0ccqGMyA07/DT/dwC3JsYuDVuhA21SCPI/S8svQkGlpzxMs+Lucc9x2m0/9gXvSPQ=="
            )
        );
    assert_eq!(
        requirements
            .npm_integrities
            .get("npm:legacy")
            .and_then(|values| values.iter().next())
            .map(String::as_str),
        Some("sha1-Hl3LtZt1PLHUbiNNj2GAKFuLhq0=")
    );
    assert!(!requirements.npm_integrities.contains_key("npm:dup"));
}

#[test]
fn reads_package_lock_resolved_urls_for_unique_versions() {
    let dir = tempfile::tempdir().unwrap();
    let package_lock = dir.path().join("package-lock.json");
    fs::write(
        &package_lock,
        r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/is-odd": {
                        "version": "3.0.1",
                        "resolved": "https://registry.example.invalid/is-odd-3.0.1.tgz"
                    },
                    "node_modules/a/node_modules/dup": {
                        "version": "1.0.0",
                        "resolved": "https://registry.example.invalid/dup-1.0.0.tgz"
                    },
                    "node_modules/b/node_modules/dup": {
                        "version": "2.0.0",
                        "resolved": "https://registry.example.invalid/dup-2.0.0.tgz"
                    }
                },
                "dependencies": {
                    "legacy": {
                        "version": "4.0.0",
                        "resolved": "https://registry.example.invalid/legacy-4.0.0.tgz"
                    }
                }
            }"#,
    )
    .unwrap();

    let requirements = read_package_lock_requirements(&package_lock).unwrap();
    assert_eq!(
        requirements
            .npm_resolved
            .get("npm:is-odd")
            .map(String::as_str),
        Some("https://registry.example.invalid/is-odd-3.0.1.tgz")
    );
    assert_eq!(
        requirements
            .npm_resolved
            .get("npm:legacy")
            .map(String::as_str),
        Some("https://registry.example.invalid/legacy-4.0.0.tgz")
    );
    assert!(!requirements.npm_resolved.contains_key("npm:dup"));
}

#[test]
fn reads_yarn_lock_constraints_integrities_and_urls() {
    let dir = tempfile::tempdir().unwrap();
    let yarn_lock = dir.path().join("yarn.lock");
    fs::write(
            &yarn_lock,
            r#"# yarn lockfile v1

left-pad@^1.0.0, "left-pad@~1.1.0":
  version "1.1.3"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz#612f61c0f5c20ba82e3d8f3f211f98d7bc86dca5"
  integrity sha512-leftpad

"@scope/pkg@^1.0.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz"

"alias@npm:real-name@^3.0.0":
  version "3.1.0"

dup@^1.0.0:
  version "1.0.0"

dup@^2.0.0:
  version "2.0.0"
"#,
        )
        .unwrap();

    let requirements = read_yarn_lock_requirements(&yarn_lock).unwrap();
    assert_eq!(
        requirements
            .constraints
            .get("npm:left-pad")
            .map(String::as_str),
        Some("1.1.3")
    );
    assert_eq!(
        requirements
            .constraints
            .get("npm:@scope/pkg")
            .map(String::as_str),
        Some("1.2.3")
    );
    assert_eq!(
        requirements
            .constraints
            .get("npm:alias")
            .map(String::as_str),
        Some("3.1.0")
    );
    assert_eq!(
        requirements
            .npm_integrities
            .get("npm:left-pad")
            .and_then(|values| values.iter().next())
            .map(String::as_str),
        Some("sha512-leftpad")
    );
    assert_eq!(
            requirements
                .npm_resolved
                .get("npm:left-pad")
                .map(String::as_str),
            Some(
                "https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz#612f61c0f5c20ba82e3d8f3f211f98d7bc86dca5"
            )
        );
    assert!(!requirements.constraints.contains_key("npm:dup"));
    assert!(!requirements.npm_resolved.contains_key("npm:dup"));
}

#[test]
fn discovers_yarn_lock_constraints() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{ "dependencies": { "left-pad": "^1.0.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("yarn.lock"),
        r#"left-pad@^1.0.0:
  version "1.1.3"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz"
"#,
    )
    .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(discovered
        .specs
        .iter()
        .any(|spec| spec.name == "left-pad" && spec.version.as_deref() == Some("^1.0.0")));
    assert_eq!(
        discovered
            .constraints
            .get("npm:left-pad")
            .map(String::as_str),
        Some("1.1.3")
    );
    assert_eq!(
        discovered
            .npm_resolved
            .get("npm:left-pad")
            .map(String::as_str),
        Some("https://registry.yarnpkg.com/left-pad/-/left-pad-1.1.3.tgz")
    );
}

#[test]
fn reads_pnpm_lock_constraints_integrities_urls_and_importers() {
    let dir = tempfile::tempdir().unwrap();
    let pnpm_lock = dir.path().join("pnpm-lock.yaml");
    fs::write(
        &pnpm_lock,
        r#"lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: ^1.0.0
        version: 1.1.3
    optionalDependencies:
      is-even:
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      which:
        specifier: ^2.0.0
        version: 2.0.2

packages:
  left-pad@1.1.3:
    resolution:
      integrity: sha512-leftpad
      tarball: https://registry.example.invalid/left-pad-1.1.3.tgz
  is-even@1.0.0:
    resolution:
      integrity: sha512-iseven
  which@2.0.2:
    resolution:
      integrity: sha512-which
  dup@1.0.0:
    resolution:
      integrity: sha512-one
  dup@2.0.0:
    resolution:
      integrity: sha512-two
"#,
    )
    .unwrap();

    let production =
        read_pnpm_lock_requirements(&pnpm_lock, DependencySelection::with_dev(false)).unwrap();
    assert!(has_spec(&production.specs, "left-pad", "1.1.3"));
    assert!(has_spec(&production.specs, "is-even", "1.0.0"));
    assert!(!production.specs.iter().any(|spec| spec.name == "which"));
    assert_eq!(
        production
            .constraints
            .get("npm:left-pad")
            .map(String::as_str),
        Some("1.1.3")
    );
    assert_eq!(
        production
            .npm_integrities
            .get("npm:left-pad")
            .and_then(|integrities| integrities.iter().next())
            .map(String::as_str),
        Some("sha512-leftpad")
    );
    assert_eq!(
        production
            .npm_resolved
            .get("npm:left-pad")
            .map(String::as_str),
        Some("https://registry.example.invalid/left-pad-1.1.3.tgz")
    );
    assert!(!production.constraints.contains_key("npm:dup"));

    let dev = read_pnpm_lock_requirements(&pnpm_lock, DependencySelection::with_dev(true)).unwrap();
    assert!(has_spec(&dev.specs, "which", "2.0.2"));
}

#[test]
fn resolves_npm_from_lockfile_tarball_url() {
    let mut options = LinkOptions::new(".");
    options
        .constraints
        .insert("npm:left-pad".to_owned(), "1.3.0".to_owned());
    options.npm_resolved.insert(
        "npm:left-pad".to_owned(),
        "https://registry.example.invalid/left-pad-1.3.0.tgz?lock=1".to_owned(),
    );
    let spec = PackageSpec::parse("npm:left-pad@^1.0.0").unwrap();
    let resolved = resolve_npm_lockfile_tarball(&spec, "left-pad", Some("^1.0.0"), &options)
        .unwrap()
        .unwrap();

    assert!(resolved.npm_direct_tarball);
    assert_eq!(
        resolved.source_url,
        "https://registry.example.invalid/left-pad-1.3.0.tgz?lock=1"
    );
    assert_eq!(resolved.version, "1.3.0");
}

#[test]
fn resolves_npm_offline_from_cached_omc_lock() {
    let dir = tempfile::tempdir().unwrap();
    let archive_bytes = b"cached npm archive";
    let mut locked = locked_package_for_test(Ecosystem::Npm, "offline-pkg", "1.0.0");
    locked.archive = ".omc/cache/npm/offline-pkg/1.0.0/offline-pkg.tgz".to_owned();
    locked.sha256 = sha256_hex(archive_bytes);
    let archive_path = dir.path().join(&locked.archive);
    fs::create_dir_all(archive_path.parent().unwrap()).unwrap();
    fs::write(&archive_path, archive_bytes).unwrap();
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock {
            version: 1,
            signing_key: None,
            packages: vec![locked.clone()],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.npm_offline = true;
    let spec = PackageSpec::parse("npm:offline-pkg@^1.0.0").unwrap();
    let resolved =
        resolve_npm_offline_locked_package(&spec, "offline-pkg", Some("^1.0.0"), &options)
            .unwrap()
            .unwrap();

    assert!(resolved.npm_direct_tarball);
    assert_eq!(resolved.version, "1.0.0");
    assert_eq!(
        resolved.expected_sha256.as_deref(),
        Some(locked.sha256.as_str())
    );
    assert_eq!(resolved.local_path.as_deref(), Some(archive_path.as_path()));
}

#[test]
fn extracts_npm_manifest_from_tgz() {
    let bytes = npm_tgz_for_test(
        r#"{
                "name": "pkg",
                "version": "1.0.0",
                "scripts": { "postinstall": "node install.js" },
                "dependencies": { "runtime": "^1.0.0" },
                "peerDependencies": { "peer": "^2.0.0" }
            }"#,
    );

    let manifest = npm_manifest_from_tgz(&bytes).unwrap();
    assert_eq!(manifest.version, "1.0.0");
    assert_eq!(
        manifest
            .scripts
            .as_ref()
            .and_then(|scripts| scripts.get("postinstall"))
            .map(String::as_str),
        Some("node install.js")
    );
    let dependencies = npm_manifest_runtime_dependencies(&manifest);
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "runtime"));
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "peer"));
}

#[test]
fn verifies_npm_integrity_hashes() {
    let bytes = b"artifact";
    assert!(verify_npm_integrity(
            "demo",
            "sha512-FGl0QHAcOIX3yNX6pZ8za0ccqGMyA07/DT/dwC3JsYuDVuhA21SCPI/S8svQkGlpzxMs+Lucc9x2m0/9gXvSPQ==",
            bytes,
        )
        .is_ok());
    assert!(verify_npm_integrity("demo", "sha1-Hl3LtZt1PLHUbiNNj2GAKFuLhq0=", bytes).is_ok());

    let error = verify_npm_integrity("demo", "sha512-AAAA", bytes).unwrap_err();
    assert!(matches!(error, OmcRegistryError::DigestMismatch { .. }));

    let error = verify_npm_integrity("demo", "md5-AAAA", bytes).unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported npm integrity digest"));
}

#[test]
fn prunes_lockfile_to_retained_packages() {
    let dir = tempfile::tempdir().unwrap();
    let keep = locked_package_for_test(Ecosystem::Npm, "left-pad", "1.3.0");
    let stale = locked_package_for_test(Ecosystem::Npm, "is-odd", "3.0.1");
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock {
            version: 1,
            signing_key: None,
            packages: vec![keep.clone(), stale],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();

    let removed = prune_lockfile(dir.path(), &BTreeSet::from([locked_package_key(&keep)])).unwrap();

    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert_eq!(removed, 1);
    assert_eq!(lock.packages.len(), 1);
    assert_eq!(lock.packages[0].name, "left-pad");
}

#[test]
fn prunes_replaced_locked_versions_by_package_name() {
    let dir = tempfile::tempdir().unwrap();
    let keep_npm = locked_package_for_test(Ecosystem::Npm, "left-pad", "1.1.3");
    let stale_npm = locked_package_for_test(Ecosystem::Npm, "left-pad", "1.3.0");
    let keep_pypi = locked_package_for_test(Ecosystem::Pypi, "idna", "3.16");
    let stale_pypi = locked_package_for_test(Ecosystem::Pypi, "IDNA", "3.7");
    let unrelated = locked_package_for_test(Ecosystem::Npm, "is-odd", "3.0.1");
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock {
            version: 1,
            signing_key: None,
            packages: vec![
                keep_npm.clone(),
                stale_npm,
                keep_pypi.clone(),
                stale_pypi,
                unrelated.clone(),
            ],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();

    let removed =
        prune_locked_package_versions(dir.path(), &[keep_npm.clone(), keep_pypi.clone()]).unwrap();

    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert_eq!(
        removed,
        vec!["npm:left-pad@1.3.0".to_owned(), "pypi:IDNA@3.7".to_owned()]
    );
    assert_eq!(
        lock.packages
            .iter()
            .map(locked_package_key)
            .collect::<Vec<_>>(),
        vec![
            locked_package_key(&keep_npm),
            locked_package_key(&keep_pypi),
            locked_package_key(&unrelated),
        ]
    );
}

#[test]
fn removes_locked_packages_by_requested_spec() {
    let dir = tempfile::tempdir().unwrap();
    let keep = locked_package_for_test(Ecosystem::Pypi, "idna", "3.7");
    let remove = locked_package_for_test(Ecosystem::Pypi, "Requests", "2.32.3");
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock {
            version: 1,
            signing_key: None,
            packages: vec![keep, remove],
            local_sources: Vec::new(),
            python_vcs: vec![LockedPythonVcsDependency {
                name: "requests".to_owned(),
                url: "https://example.invalid/requests.git".to_owned(),
                reference: None,
                resolved_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                archive: String::new(),
                sha256: String::new(),
                subdirectory: None,
                extras: Vec::new(),
            }],
        })
        .unwrap(),
    )
    .unwrap();

    let removed =
        remove_locked_packages(dir.path(), &[PackageSpec::parse("pypi:requests").unwrap()])
            .unwrap();

    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert_eq!(removed, vec!["pypi:Requests@2.32.3".to_owned()]);
    assert_eq!(lock.packages.len(), 1);
    assert_eq!(lock.packages[0].name, "idna");
    assert!(lock.python_vcs.is_empty());
}

#[test]
fn reads_npm_entry_source_from_locked_archive() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = npm_tgz_with_files(
        r#"{"name":"is-odd","version":"3.0.1","main":"lib/main.js"}"#,
        &[(
            "lib/main.js",
            "module.exports = function isOdd(n){return n%2===1;};",
        )],
    );
    let archive = dir.path().join(".omc/cache/npm/is-odd.tgz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Npm, "is-odd", "3.0.1");
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);

    let entry = read_locked_package_entry_source(dir.path(), &package).unwrap();
    assert_eq!(entry.module_id, "npm:is-odd@3.0.1");
    assert!(entry.source.contains("isOdd"));
}

#[test]
fn npm_entry_source_defaults_to_index_js() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = npm_tgz_with_files(
        r#"{"name":"pkg","version":"1.0.0"}"#,
        &[("index.js", "module.exports = function f(){return 1;};")],
    );
    let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);

    let entry = read_locked_package_entry_source(dir.path(), &package).unwrap();
    assert!(entry.source.contains("function f"));
}

#[test]
fn missing_entry_source_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    // An npm archive whose package.json points at a file that is absent.
    let bytes = npm_tgz_with_files(
        r#"{"name":"pkg","version":"1.0.0","main":"missing.js"}"#,
        &[("other.js", "module.exports = 1;")],
    );
    let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);

    let err = read_locked_package_entry_source(dir.path(), &package).unwrap_err();
    assert!(
        matches!(err, OmcRegistryError::MissingEntrySource(_)),
        "got {err:?}"
    );
}

#[test]
fn discovers_package_lock_constraints() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{ "dependencies": { "left-pad": "^1.1.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("package-lock.json"),
        r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/left-pad": { "version": "1.1.3" }
                }
            }"#,
    )
    .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(discovered
        .specs
        .iter()
        .any(|spec| spec.name == "left-pad" && spec.version.as_deref() == Some("^1.1.0")));
    assert_eq!(
        discovered
            .constraints
            .get("npm:left-pad")
            .map(String::as_str),
        Some("1.1.3")
    );
}

#[test]
fn discovers_npm_shrinkwrap_constraints() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{ "dependencies": { "left-pad": "^1.1.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("npm-shrinkwrap.json"),
        r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "demo", "version": "0.1.0" },
                    "node_modules/left-pad": {
                        "version": "1.1.3",
                        "resolved": "https://registry.example.invalid/left-pad-1.1.3.tgz",
                        "integrity": "sha512-leftpad"
                    }
                }
            }"#,
    )
    .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert_eq!(
        discovered
            .constraints
            .get("npm:left-pad")
            .map(String::as_str),
        Some("1.1.3")
    );
    assert_eq!(
        discovered
            .npm_resolved
            .get("npm:left-pad")
            .map(String::as_str),
        Some("https://registry.example.invalid/left-pad-1.1.3.tgz")
    );
    assert_eq!(
        discovered
            .npm_integrities
            .get("npm:left-pad")
            .and_then(|integrities| integrities.iter().next())
            .map(String::as_str),
        Some("sha512-leftpad")
    );
}

#[test]
fn merges_npm_lock_constraints_into_ranges_and_aliases() {
    let spec = PackageSpec::new(Ecosystem::Npm, "is-odd", Some("^3.0.0".to_owned()));
    let constraints = BTreeMap::from([("npm:is-odd".to_owned(), "3.0.1".to_owned())]);
    assert_eq!(
        constrained_npm_requirement(&spec, spec.version.as_deref(), &constraints).as_deref(),
        Some("^3.0.0,3.0.1")
    );
    let overrides = BTreeMap::from([("npm:is-odd".to_owned(), "4.0.0".to_owned())]);
    assert_eq!(
        effective_npm_requirement(&spec, spec.version.as_deref(), &constraints, &overrides)
            .as_deref(),
        Some("4.0.0")
    );

    let alias = PackageSpec::new(
        Ecosystem::Npm,
        "string-width-cjs",
        Some("npm:string-width@^4.2.0".to_owned()),
    );
    let (_, alias_requirement) = npm_registry_name_and_requirement(&alias).unwrap();
    assert_eq!(
        constrained_npm_requirement(&alias, alias_requirement.as_deref(), &BTreeMap::new())
            .as_deref(),
        Some("^4.2.0")
    );
}
