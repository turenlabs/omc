//! `pypi` domain tests, extracted from the original monolithic tests.rs.

use super::*;
use crate::*;

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
fn evaluates_npm_engine_requirements() {
    let node = Version::new(20, 11, 1);

    assert!(npm_engine_requirement_satisfied(&node, ">=18"));
    assert!(npm_engine_requirement_satisfied(&node, ">= 18 < 21"));
    assert!(npm_engine_requirement_satisfied(&node, "^16 || >=20"));
    assert!(!npm_engine_requirement_satisfied(&node, "<18"));
    assert!(!npm_engine_requirement_satisfied(&node, "^16 || ^18"));
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
