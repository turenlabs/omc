use super::*;
use crate::*;

#[test]
fn parses_pip_install_requirements_and_indexes() {
    let action = parse_pip_compat_action(&args(&[
        "--disable-pip-version-check",
        "--no-input",
        "--quiet",
        "--timeout",
        "5",
        "install",
        "--isolated",
        "--require-virtualenv",
        "--no-python-version-warning",
        "-q",
        "-vv",
        "--no-color",
        "-r",
        "requirements.txt",
        "-c",
        "constraints.txt",
        "--requirements-from-script",
        "tool.py",
        "--index-url",
        "https://mirror.example/simple",
        "--extra-index-url=https://extra.example/simple",
        "--find-links",
        "wheelhouse",
        "--no-index",
        "--pre",
        "--uploaded-prior-to",
        "2026-01-01T00:00:00Z",
        "--require-hashes",
        "--no-deps",
        "--platform",
        "macosx_14_0_arm64",
        "--python-version=3.12",
        "--implementation",
        "cp",
        "--abi=cp312",
        "--all-releases",
        "previewed",
        "--only-final=stable-only",
        "--target",
        "vendor",
        "--no-binary=:all:",
        "--only-binary",
        "idna",
        "--trusted-host",
        "mirror.example",
        "--prefer-binary",
        "-I",
        "--force-reinstall",
        "--ignore-installed",
        "--upgrade",
        "--upgrade-strategy",
        "eager",
        "--src",
        "src",
        "--root-user-action=ignore",
        "--log",
        "pip.log",
        "--proxy=https://proxy.example",
        "--progress-bar",
        "off",
        "--retries",
        "1",
        "--timeout=5",
        "--exists-action",
        "i",
        "--cert",
        "certs/ca.pem",
        "--client-cert=certs/client.pem",
        "--cache-dir",
        ".pip-cache",
        "--use-feature",
        "truststore",
        "--use-deprecated=legacy-resolver",
        "--build-constraint",
        "build-constraints.txt",
        "--ignore-requires-python",
        "--no-build-isolation",
        "--check-build-dependencies",
        "-C",
        "editable_mode=strict",
        "--config-settings=--build-option=build_ext",
        "--global-option",
        "egg_info",
        "--install-option",
        "--install-scripts=/tmp/bin",
        "--no-clean",
        "--group",
        "Dev",
        "--group=pyproject.toml:test",
        "--no-warn-script-location",
        "--no-compile",
        "--report",
        "install-report.json",
        "--dry-run",
        "--allow-all-host",
        "requests==2.32.3",
    ]))
    .unwrap();

    assert_eq!(
        action,
        PipCompatAction::Install(Box::new(PipInstallAction {
            specs: vec!["requests==2.32.3".to_owned()],
            requirements: vec![PathBuf::from("requirements.txt")],
            constraints: vec![PathBuf::from("constraints.txt")],
            script_requirements: vec![PathBuf::from("tool.py")],
            groups: vec!["dev".to_owned(), "test".to_owned()],
            report: Some(PathBuf::from("install-report.json")),
            dry_run: true,
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            local_directories: Vec::new(),
            index_url: Some("https://mirror.example/simple".to_owned()),
            extra_index_urls: vec!["https://extra.example/simple".to_owned()],
            find_links: vec!["wheelhouse".to_owned()],
            no_index: true,
            binary_all: Some(PypiBinaryMode::Source),
            binary_packages: BTreeMap::from([("idna".to_owned(), PypiBinaryMode::Binary)]),
            require_hashes: true,
            no_deps: true,
            allow_prereleases: true,
            release_controls: PypiReleaseControls {
                all_releases: PypiReleaseControl {
                    all: false,
                    packages: BTreeSet::from(["previewed".to_owned()]),
                },
                only_final: PypiReleaseControl {
                    all: false,
                    packages: BTreeSet::from(["stable-only".to_owned()]),
                },
            },
            uploaded_prior_to: Some("2026-01-01T00:00:00Z".to_owned()),
            upgrade: true,
            force_reinstall: true,
            compatibility: PipCompatibilityTarget {
                platforms: vec!["macosx_14_0_arm64".to_owned()],
                python_version: Some("3.12".to_owned()),
                implementation: Some("cp".to_owned()),
                abis: vec!["cp312".to_owned()],
            },
            target: Some(PathBuf::from("vendor")),
            prefix: None,
            root: None,
            user: false,
            vcs_requirements: Vec::new(),
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: true,
        }))
    );

    match parse_pip_compat_action(&args(&[
        "install",
        "--allow=env:API_TOKEN",
        "--allow-flow=env:API_TOKEN->network:api.example.com",
        "requests==2.32.3",
    ]))
    .unwrap()
    {
        PipCompatAction::Install(action) => {
            assert_eq!(action.allow, vec!["env:API_TOKEN".to_owned()]);
            assert_eq!(
                action.allow_flow,
                vec!["env:API_TOKEN->network:api.example.com".to_owned()]
            );
        }
        other => panic!("expected pip install action, got {other:?}"),
    }

    for flag in ["--force-reinstall", "--ignore-installed", "-I"] {
        match parse_pip_compat_action(&args(&[
            "install",
            "--target",
            "vendor",
            flag,
            "requests==2.32.3",
        ]))
        .unwrap()
        {
            PipCompatAction::Install(action) => {
                assert!(action.force_reinstall);
                assert!(!action.upgrade);
            }
            other => panic!("expected pip install action, got {other:?}"),
        }
    }

    match parse_pip_compat_action(&args(&["install", "--user", "requests==2.32.3"])).unwrap() {
        PipCompatAction::Install(action) => {
            assert!(action.user);
            assert_eq!(action.specs, vec!["requests==2.32.3"]);
            assert_eq!(action.target, None);
        }
        other => panic!("expected pip install action, got {other:?}"),
    }
    match parse_pip_compat_action(&args(&[
        "install",
        "--prefix",
        "prefix-dir",
        "requests==2.32.3",
    ]))
    .unwrap()
    {
        PipCompatAction::Install(action) => {
            assert_eq!(action.prefix, Some(PathBuf::from("prefix-dir")));
            assert_eq!(action.target, None);
            assert_eq!(action.root, None);
            assert!(!action.user);
        }
        other => panic!("expected pip install action, got {other:?}"),
    }
    match parse_pip_compat_action(&args(&[
        "install",
        "--root",
        "staging-root",
        "requests==2.32.3",
    ]))
    .unwrap()
    {
        PipCompatAction::Install(action) => {
            assert_eq!(action.root, Some(PathBuf::from("staging-root")));
            assert_eq!(action.prefix, None);
            assert_eq!(action.target, None);
            assert!(!action.user);
        }
        other => panic!("expected pip install action, got {other:?}"),
    }
    match parse_pip_compat_action(&args(&[
        "install",
        "--group",
        "packages/tooling/pyproject.toml:Tools",
    ]))
    .unwrap()
    {
        PipCompatAction::Install(action) => {
            assert_eq!(action.groups, Vec::<String>::new());
            assert_eq!(
                action.local_paths,
                vec![PythonLocalRequirement::new(
                    PathBuf::from("packages/tooling"),
                    BTreeSet::from(["tools".to_owned()])
                )]
            );
            assert!(action.local_directories.is_empty());
        }
        other => panic!("expected pip install action, got {other:?}"),
    }

    let action = parse_pip_compat_action(&args(&[
        "download",
        "--isolated",
        "--no-input",
        "--no-color",
        "--no-python-version-warning",
        "-qq",
        "--verbose",
        "-r",
        "requirements.txt",
        "-c",
        "constraints.txt",
        "--build-constraint",
        "build-constraints.txt",
        "--dest",
        "wheelhouse",
        "--index-url=https://mirror.example/simple",
        "--find-links=vendor",
        "--no-index",
        "--require-hashes",
        "--no-deps",
        "--only-binary=:all:",
        "--uploaded-prior-to=P30D",
        "--platform",
        "manylinux_2_28_aarch64",
        "--python-version=3.11",
        "--implementation",
        "cp",
        "--abi=cp311",
        "--trusted-host",
        "mirror.example",
        "--proxy",
        "https://proxy.example",
        "--cert=certs/ca.pem",
        "--client-cert",
        "certs/client.pem",
        "--cache-dir=.pip-cache",
        "--use-feature",
        "truststore",
        "--use-deprecated=legacy-resolver",
        "--allow",
        "http:files.example",
        "requests==2.32.3",
    ]))
    .unwrap();

    assert_eq!(
        action,
        PipCompatAction::Download(Box::new(PipDownloadAction {
            specs: vec!["requests==2.32.3".to_owned()],
            requirements: vec![PathBuf::from("requirements.txt")],
            constraints: vec![PathBuf::from("constraints.txt")],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            index_url: Some("https://mirror.example/simple".to_owned()),
            extra_index_urls: Vec::new(),
            find_links: vec!["vendor".to_owned()],
            no_index: true,
            binary_all: Some(PypiBinaryMode::Binary),
            binary_packages: BTreeMap::new(),
            require_hashes: true,
            no_deps: true,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: Some("P30D".to_owned()),
            compatibility: PipCompatibilityTarget {
                platforms: vec!["manylinux_2_28_aarch64".to_owned()],
                python_version: Some("3.11".to_owned()),
                implementation: Some("cp".to_owned()),
                abis: vec!["cp311".to_owned()],
            },
            destination: PathBuf::from("wheelhouse"),
            allow: vec!["http:files.example".to_owned()],
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );

    let action = parse_pip_compat_action(&args(&[
        "wheel",
        "--require-virtualenv",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--quiet",
        "-r",
        "requirements.txt",
        "-w",
        "wheelhouse",
        "--index-url=https://mirror.example/simple",
        "--find-links=vendor",
        "--no-index",
        "--require-hashes",
        "--no-deps",
        "--uploaded-prior-to",
        "2025-12-31",
        "--check-build-dependencies",
        "--build-constraint=build-constraints.txt",
        "--no-clean",
        "--no-verify",
        "-C",
        "editable_mode=strict",
        "--config-settings=--build-option=build_ext",
        "--build-option",
        "--plat-name=macosx",
        "--global-option=egg_info",
        "--trusted-host",
        "mirror.example",
        "--proxy=https://proxy.example",
        "--use-feature",
        "truststore",
        "--use-deprecated=legacy-resolver",
        "--allow",
        "http:files.example",
        "requests==2.32.3",
    ]))
    .unwrap();

    assert_eq!(
        action,
        PipCompatAction::Wheel(Box::new(PipDownloadAction {
            specs: vec!["requests==2.32.3".to_owned()],
            requirements: vec![PathBuf::from("requirements.txt")],
            constraints: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            index_url: Some("https://mirror.example/simple".to_owned()),
            extra_index_urls: Vec::new(),
            find_links: vec!["vendor".to_owned()],
            no_index: true,
            binary_all: None,
            binary_packages: BTreeMap::new(),
            require_hashes: true,
            no_deps: true,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: Some("2025-12-31".to_owned()),
            compatibility: PipCompatibilityTarget::default(),
            destination: PathBuf::from("wheelhouse"),
            allow: vec!["http:files.example".to_owned()],
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "wheel",
            "--no-binary=:all:",
            "./dist/source_pkg-1.0.0.tar.gz",
            "-w",
            "wheelhouse",
        ]))
        .unwrap(),
        PipCompatAction::Wheel(Box::new(PipDownloadAction {
            specs: Vec::new(),
            requirements: Vec::new(),
            constraints: Vec::new(),
            archive_references: vec!["./dist/source_pkg-1.0.0.tar.gz".to_owned()],
            local_paths: Vec::new(),
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            binary_all: Some(PypiBinaryMode::Source),
            binary_packages: BTreeMap::new(),
            require_hashes: false,
            no_deps: false,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: None,
            compatibility: PipCompatibilityTarget::default(),
            destination: PathBuf::from("wheelhouse"),
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["wheel", "./local_pkg[dev]", "-w", "wheelhouse",]))
            .unwrap(),
        PipCompatAction::Wheel(Box::new(PipDownloadAction {
            specs: Vec::new(),
            requirements: Vec::new(),
            constraints: Vec::new(),
            archive_references: Vec::new(),
            local_paths: vec![PythonLocalRequirement::new(
                PathBuf::from("./local_pkg"),
                BTreeSet::from(["dev".to_owned()])
            )],
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            binary_all: None,
            binary_packages: BTreeMap::new(),
            require_hashes: false,
            no_deps: false,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: None,
            compatibility: PipCompatibilityTarget::default(),
            destination: PathBuf::from("wheelhouse"),
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "wheel",
            "-e",
            "./local_pkg[dev]",
            "--editable=./another_pkg",
            "-w",
            "wheelhouse",
        ]))
        .unwrap(),
        PipCompatAction::Wheel(Box::new(PipDownloadAction {
            specs: Vec::new(),
            requirements: Vec::new(),
            constraints: Vec::new(),
            archive_references: Vec::new(),
            local_paths: vec![
                PythonLocalRequirement::new(
                    PathBuf::from("./local_pkg"),
                    BTreeSet::from(["dev".to_owned()])
                ),
                PythonLocalRequirement::new(PathBuf::from("./another_pkg"), BTreeSet::new())
            ],
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            binary_all: None,
            binary_packages: BTreeMap::new(),
            require_hashes: false,
            no_deps: false,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: None,
            compatibility: PipCompatibilityTarget::default(),
            destination: PathBuf::from("wheelhouse"),
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["download", "./local_pkg"])).unwrap(),
        PipCompatAction::Download(Box::new(PipDownloadAction {
            specs: Vec::new(),
            requirements: Vec::new(),
            constraints: Vec::new(),
            archive_references: Vec::new(),
            local_paths: vec![PythonLocalRequirement::new(
                PathBuf::from("./local_pkg"),
                BTreeSet::new()
            )],
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            binary_all: None,
            binary_packages: BTreeMap::new(),
            require_hashes: false,
            no_deps: false,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: None,
            compatibility: PipCompatibilityTarget::default(),
            destination: PathBuf::from("."),
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );
    assert!(parse_pip_compat_action(&args(&["download", "-e", "./local_pkg"])).is_err());
}

#[test]
fn parses_direct_pylock_files_as_requirements() {
    let project = test_dir("pip-direct-pylock");
    let pylock = project.join("pylock.toml");
    let named_pylock = project.join("pylock.prod.toml");
    fs::write(&pylock, "lock-version = \"1.0\"\n").unwrap();
    fs::write(&named_pylock, "lock-version = \"1.0\"\n").unwrap();

    match parse_pip_compat_action(&args(&["install", pylock.to_str().unwrap(), "--dry-run"]))
        .unwrap()
    {
        PipCompatAction::Install(action) => {
            assert_eq!(action.specs, Vec::<String>::new());
            assert_eq!(action.requirements, vec![pylock.clone()]);
            assert!(action.local_paths.is_empty());
            assert!(action.dry_run);
        }
        other => panic!("expected pip install action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&["download", named_pylock.to_str().unwrap()])).unwrap() {
        PipCompatAction::Download(action) => {
            assert_eq!(action.specs, Vec::<String>::new());
            assert_eq!(action.requirements, vec![named_pylock]);
            assert!(action.local_paths.is_empty());
        }
        other => panic!("expected pip download action, got {other:?}"),
    }
}

#[test]
fn parses_pip_attached_short_value_options() {
    match parse_pip_compat_action(&args(&[
        "install",
        "-rrequirements.txt",
        "-cconstraints.txt",
        "-ihttps://mirror.example/simple",
        "-fwheelhouse",
        "-tvendor",
        "-e../editable_pkg[dev]",
        "requests==2.32.3",
    ]))
    .unwrap()
    {
        PipCompatAction::Install(action) => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
            assert_eq!(action.constraints, vec![PathBuf::from("constraints.txt")]);
            assert_eq!(
                action.index_url.as_deref(),
                Some("https://mirror.example/simple")
            );
            assert_eq!(action.find_links, vec!["wheelhouse".to_owned()]);
            assert_eq!(action.target, Some(PathBuf::from("vendor")));
            assert_eq!(
                action.local_paths,
                vec![PythonLocalRequirement::new(
                    PathBuf::from("../editable_pkg"),
                    BTreeSet::from(["dev".to_owned()])
                )]
            );
            assert_eq!(action.specs, vec!["requests==2.32.3"]);
        }
        other => panic!("expected pip install action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&[
        "install",
        "-Ur",
        "requirements.txt",
        "-Ue../editable_pkg",
        "-ICeditable_mode=strict",
    ]))
    .unwrap()
    {
        PipCompatAction::Install(action) => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
            assert_eq!(
                action.local_paths,
                vec![PythonLocalRequirement::new(
                    PathBuf::from("../editable_pkg"),
                    BTreeSet::new()
                )]
            );
            assert!(action.upgrade);
            assert!(action.force_reinstall);
        }
        other => panic!("expected pip install action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&[
        "download",
        "-rrequirements.txt",
        "-cconstraints.txt",
        "-dwheelhouse",
        "-ihttps://mirror.example/simple",
        "-fwheels",
    ]))
    .unwrap()
    {
        PipCompatAction::Download(action) => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
            assert_eq!(action.constraints, vec![PathBuf::from("constraints.txt")]);
            assert_eq!(action.destination, PathBuf::from("wheelhouse"));
            assert_eq!(
                action.index_url.as_deref(),
                Some("https://mirror.example/simple")
            );
            assert_eq!(action.find_links, vec!["wheels".to_owned()]);
        }
        other => panic!("expected pip download action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&[
        "download",
        "-qr",
        "requirements.txt",
        "-qdwheelhouse",
    ]))
    .unwrap()
    {
        PipCompatAction::Download(action) => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
            assert_eq!(action.destination, PathBuf::from("wheelhouse"));
        }
        other => panic!("expected pip download action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&[
        "wheel",
        "-rrequirements.txt",
        "-wwheelhouse",
        "-e../editable_pkg",
    ]))
    .unwrap()
    {
        PipCompatAction::Wheel(action) => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
            assert_eq!(action.destination, PathBuf::from("wheelhouse"));
            assert_eq!(
                action.local_paths,
                vec![PythonLocalRequirement::new(
                    PathBuf::from("../editable_pkg"),
                    BTreeSet::new()
                )]
            );
        }
        other => panic!("expected pip wheel action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&[
        "wheel",
        "-qr",
        "requirements.txt",
        "-qwwheelhouse",
        "-qe../editable_pkg",
        "-qCeditable_mode=strict",
    ]))
    .unwrap()
    {
        PipCompatAction::Wheel(action) => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
            assert_eq!(action.destination, PathBuf::from("wheelhouse"));
            assert_eq!(
                action.local_paths,
                vec![PythonLocalRequirement::new(
                    PathBuf::from("../editable_pkg"),
                    BTreeSet::new()
                )]
            );
        }
        other => panic!("expected pip wheel action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&["uninstall", "-rrequirements.txt", "-y"])).unwrap() {
        PipCompatAction::Uninstall { requirements, .. } => {
            assert_eq!(requirements, vec![PathBuf::from("requirements.txt")]);
        }
        other => panic!("expected pip uninstall action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&["uninstall", "-yr", "requirements.txt"])).unwrap() {
        PipCompatAction::Uninstall { requirements, .. } => {
            assert_eq!(requirements, vec![PathBuf::from("requirements.txt")]);
        }
        other => panic!("expected pip uninstall action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&["freeze", "-rrequirements.txt"])).unwrap() {
        PipCompatAction::Freeze { action } => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
        }
        other => panic!("expected pip freeze action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&["freeze", "-qr", "requirements.txt"])).unwrap() {
        PipCompatAction::Freeze { action } => {
            assert_eq!(action.requirements, vec![PathBuf::from("requirements.txt")]);
        }
        other => panic!("expected pip freeze action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&[
        "list",
        "--outdated",
        "-ihttps://mirror.example/simple",
        "-fwheelhouse",
    ]))
    .unwrap()
    {
        PipCompatAction::List {
            index_url,
            find_links,
            ..
        } => {
            assert_eq!(index_url.as_deref(), Some("https://mirror.example/simple"));
            assert_eq!(find_links, vec!["wheelhouse".to_owned()]);
        }
        other => panic!("expected pip list action, got {other:?}"),
    }

    match parse_pip_compat_action(&args(&[
        "index",
        "versions",
        "idna",
        "-ihttps://mirror.example/simple",
        "-fwheelhouse",
    ]))
    .unwrap()
    {
        PipCompatAction::IndexVersions {
            index_url,
            find_links,
            ..
        } => {
            assert_eq!(index_url.as_deref(), Some("https://mirror.example/simple"));
            assert_eq!(find_links, vec!["wheelhouse".to_owned()]);
        }
        other => panic!("expected pip index versions action, got {other:?}"),
    }
}

#[test]
fn parses_pip_install_local_paths() {
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "install",
            "-e",
            "../editable_pkg[dev]",
            "--editable=./another_pkg",
            "./local_pkg",
            "requests==2.32.3",
        ]))
        .unwrap(),
        PipCompatAction::Install(Box::new(PipInstallAction {
            specs: vec!["requests==2.32.3".to_owned()],
            requirements: Vec::new(),
            constraints: Vec::new(),
            script_requirements: Vec::new(),
            groups: Vec::new(),
            report: None,
            dry_run: false,
            archive_references: Vec::new(),
            local_paths: vec![
                PythonLocalRequirement::new(
                    PathBuf::from("../editable_pkg"),
                    BTreeSet::from(["dev".to_owned()]),
                ),
                PythonLocalRequirement::new(PathBuf::from("./another_pkg"), BTreeSet::new()),
            ],
            local_directories: vec![PythonLocalRequirement::new(
                PathBuf::from("./local_pkg"),
                BTreeSet::new()
            ),],
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            binary_all: None,
            binary_packages: BTreeMap::new(),
            require_hashes: false,
            no_deps: false,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: None,
            upgrade: false,
            force_reinstall: false,
            compatibility: PipCompatibilityTarget::default(),
            target: None,
            prefix: None,
            root: None,
            user: false,
            vcs_requirements: Vec::new(),
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );

    assert_eq!(
        parse_pip_compat_action(&args(&[
            "install",
            "-e",
            "git+https://example.invalid/demo.git@main#egg=demo[cli]&subdirectory=src",
            "--editable=other @ git+https://example.invalid/other.git@v1#subdirectory=python",
        ]))
        .unwrap(),
        PipCompatAction::Install(Box::new(PipInstallAction {
            specs: Vec::new(),
            requirements: Vec::new(),
            constraints: Vec::new(),
            script_requirements: Vec::new(),
            groups: Vec::new(),
            report: None,
            dry_run: false,
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            local_directories: Vec::new(),
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            binary_all: None,
            binary_packages: BTreeMap::new(),
            require_hashes: false,
            no_deps: false,
            allow_prereleases: false,
            release_controls: PypiReleaseControls::default(),
            uploaded_prior_to: None,
            upgrade: false,
            force_reinstall: false,
            compatibility: PipCompatibilityTarget::default(),
            target: None,
            prefix: None,
            root: None,
            user: false,
            vcs_requirements: vec![
                PythonVcsRequirement {
                    name: "demo".to_owned(),
                    url: "https://example.invalid/demo.git".to_owned(),
                    reference: Some("main".to_owned()),
                    subdirectory: Some(PathBuf::from("src")),
                    extras: BTreeSet::from(["cli".to_owned()]),
                },
                PythonVcsRequirement {
                    name: "other".to_owned(),
                    url: "https://example.invalid/other.git".to_owned(),
                    reference: Some("v1".to_owned()),
                    subdirectory: Some(PathBuf::from("python")),
                    extras: BTreeSet::new(),
                },
            ],
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }))
    );
}

#[test]
fn parses_pip_install_archive_references() {
    assert_eq!(
            parse_pip_compat_action(&args(&[
                "install",
                "./wheelhouse/demo_pkg-1.0.0-py3-none-any.whl",
                "https://files.example/source_pkg-2.0.0.tar.gz#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]))
            .unwrap(),
            PipCompatAction::Install(Box::new(PipInstallAction {
                specs: Vec::new(),
                requirements: Vec::new(),
                constraints: Vec::new(),
                script_requirements: Vec::new(),
                groups: Vec::new(),
                report: None,
                dry_run: false,
                archive_references: vec![
                    "./wheelhouse/demo_pkg-1.0.0-py3-none-any.whl".to_owned(),
                    "https://files.example/source_pkg-2.0.0.tar.gz#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                ],
                local_paths: Vec::new(),
                local_directories: Vec::new(),
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: Vec::new(),
                no_index: false,
                binary_all: None,
                binary_packages: BTreeMap::new(),
                require_hashes: false,
                no_deps: false,
                allow_prereleases: false,
                release_controls: PypiReleaseControls::default(),
                uploaded_prior_to: None,
                upgrade: false,
                force_reinstall: false,
                compatibility: PipCompatibilityTarget::default(),
                target: None,
                prefix: None,
                root: None,
                user: false,
                vcs_requirements: Vec::new(),
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            }))
        );
}

#[test]
fn detects_python_module_pip_invocations() {
    let command = args(&["-m", "pip", "install", "requests==2.32.3"]);
    assert_eq!(
        python_pip_module_args(&command),
        Some(args(&["install", "requests==2.32.3"]).as_slice())
    );

    let isolated = args(&["-I", "-S", "-m", "pip3", "--version"]);
    assert_eq!(
        python_pip_module_args(&isolated),
        Some(args(&["--version"]).as_slice())
    );

    let compact = args(&["-mpip", "freeze"]);
    assert_eq!(
        python_pip_module_args(&compact),
        Some(args(&["freeze"]).as_slice())
    );

    let script = args(&["script.py", "-m", "pip"]);
    assert_eq!(python_pip_module_args(&script), None);

    let twine = args(&["-m", "twine", "upload", "dist/pkg.whl"]);
    assert_eq!(
        python_twine_module_args(&twine),
        Some(args(&["upload", "dist/pkg.whl"]).as_slice())
    );

    let compact_twine = args(&["-mtwine", "--version"]);
    assert_eq!(
        python_twine_module_args(&compact_twine),
        Some(args(&["--version"]).as_slice())
    );
}

#[test]
fn parses_pip_uninstall_and_freeze() {
    assert_eq!(
        parse_pip_compat_action(&args(&["--version"])).unwrap(),
        PipCompatAction::Version
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["--quiet", "--version"])).unwrap(),
        PipCompatAction::Version
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["--help"])).unwrap(),
        PipCompatAction::Help { topic: None }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["help", "install"])).unwrap(),
        PipCompatAction::Help {
            topic: Some("install".to_owned()),
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["install", "--help"])).unwrap(),
        PipCompatAction::Help {
            topic: Some("install".to_owned()),
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["completion", "--bash"])).unwrap(),
        PipCompatAction::Completion {
            shell: Some(PipCompletionShell::Bash),
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["completion"])).unwrap(),
        PipCompatAction::Completion { shell: None }
    );
    assert!(pip_help_text(None).contains("Supported commands: install"));
    assert!(pip_help_text(Some("debug")).contains("pip debug"));
    assert!(pip_help_text(Some("search")).contains("pip search"));
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "search",
            "--index",
            "https://pypi.example.invalid/pypi",
            "requests",
        ]))
        .unwrap(),
        PipCompatAction::Search {
            query: vec!["requests".to_owned()],
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["uninstall", "-y", "requests"])).unwrap(),
        PipCompatAction::Uninstall {
            specs: vec!["requests".to_owned()],
            requirements: Vec::new(),
            user: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "uninstall",
            "--yes",
            "-r",
            "requirements.txt",
            "--requirement=dev-requirements.txt",
            "--disable-pip-version-check",
            "--no-input",
            "--no-color",
            "--no-cache-dir",
            "--no-python-version-warning",
            "--log",
            "pip.log",
            "--proxy=http://proxy.invalid",
            "--retries",
            "1",
            "--timeout=5",
            "--exists-action",
            "i",
            "--trusted-host=mirror.example",
            "--cert",
            "cert.pem",
            "--client-cert=client.pem",
            "--cache-dir",
            ".pip-cache",
            "--use-feature",
            "fast-deps",
            "--use-deprecated=legacy-resolver",
            "--break-system-packages",
            "pytest",
        ]))
        .unwrap(),
        PipCompatAction::Uninstall {
            specs: vec!["pytest".to_owned()],
            requirements: vec![
                PathBuf::from("requirements.txt"),
                PathBuf::from("dev-requirements.txt"),
            ],
            user: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["uninstall", "--user", "-y", "demoedit"])).unwrap(),
        PipCompatAction::Uninstall {
            specs: vec!["demoedit".to_owned()],
            requirements: Vec::new(),
            user: true,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["freeze"])).unwrap(),
        PipCompatAction::Freeze {
            action: PipFreezeAction::default(),
        }
    );
    assert_eq!(
            pip_freeze_vcs_requirement(&LockedPythonVcsDependency {
                name: "demo".to_owned(),
                url: "https://example.invalid/demo.git".to_owned(),
                reference: Some("main".to_owned()),
                resolved_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                archive: String::new(),
                sha256: String::new(),
                subdirectory: Some("src".to_owned()),
                extras: vec!["cli".to_owned(), "test".to_owned()],
            }),
            "demo[cli,test] @ git+https://example.invalid/demo.git@0123456789abcdef0123456789abcdef01234567#subdirectory=src"
        );
    assert_eq!(
        parse_pip_compat_action(&args(&["check", "--disable-pip-version-check"])).unwrap(),
        PipCompatAction::Check { user: false }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["check", "--user"])).unwrap(),
        PipCompatAction::Check { user: true }
    );
    match parse_pip_compat_action(&args(&[
        "lock",
        "-r",
        "requirements.txt",
        "--group",
        "pyproject.toml:Dev",
        "-o",
        "locks/pylock.toml",
    ]))
    .unwrap()
    {
        PipCompatAction::Lock(action) => {
            assert_eq!(action.output, PathBuf::from("locks/pylock.toml"));
            assert_eq!(
                action.install.requirements,
                vec![PathBuf::from("requirements.txt")]
            );
            assert_eq!(action.install.groups, vec!["dev".to_owned()]);
        }
        other => panic!("expected pip lock action, got {other:?}"),
    }
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "debug",
            "-vv",
            "--platform",
            "macosx_14_0_arm64",
            "--python-version=3.12",
            "--implementation",
            "cp",
            "--abi=cp312",
            "--disable-pip-version-check",
        ]))
        .unwrap(),
        PipCompatAction::Debug {
            action: PipDebugAction {
                verbose: true,
                platform: Some("macosx_14_0_arm64".to_owned()),
                python_version: Some("3.12".to_owned()),
                implementation: Some("cp".to_owned()),
                abis: vec!["cp312".to_owned()],
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "inspect",
            "--local",
            "--path",
            ".omc/python/site-packages",
            "--disable-pip-version-check",
        ]))
        .unwrap(),
        PipCompatAction::Inspect {
            paths: vec![PathBuf::from(".omc/python/site-packages")],
            user: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["inspect", "--user"])).unwrap(),
        PipCompatAction::Inspect {
            paths: Vec::new(),
            user: true,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["show", "-f", "requests"])).unwrap(),
        PipCompatAction::Show {
            specs: vec!["requests".to_owned()],
            files: true,
            user: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["show", "-fv", "requests"])).unwrap(),
        PipCompatAction::Show {
            specs: vec!["requests".to_owned()],
            files: true,
            user: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["show", "--user", "demoedit"])).unwrap(),
        PipCompatAction::Show {
            specs: vec!["demoedit".to_owned()],
            files: false,
            user: true,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "hash",
            "--algorithm",
            "sha512",
            "--disable-pip-version-check",
            "dist/pkg.whl",
        ]))
        .unwrap(),
        PipCompatAction::Hash {
            algorithm: PipHashAlgorithm::Sha512,
            paths: vec![PathBuf::from("dist/pkg.whl")],
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["hash", "-asha384", "dist/pkg.whl"])).unwrap(),
        PipCompatAction::Hash {
            algorithm: PipHashAlgorithm::Sha384,
            paths: vec![PathBuf::from("dist/pkg.whl")],
        }
    );
    assert!(parse_pip_compat_action(&args(&["hash", "--algorithm", "md5", "pkg.whl"])).is_err());
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "dir"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::Dir,
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["--cache-dir", ".pip-cache", "cache", "dir"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::Dir,
            cache_dir: Some(PathBuf::from(".pip-cache")),
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "list", "idna"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::List {
                pattern: Some("idna".to_owned()),
                format: PipCacheListFormat::Human,
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "--format=abspath", "list", "idna"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::List {
                pattern: Some("idna".to_owned()),
                format: PipCacheListFormat::Abspath,
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "list", "--format", "human"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::List {
                pattern: None,
                format: PipCacheListFormat::Human,
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "--cache-dir", ".pip-cache", "list"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::List {
                pattern: None,
                format: PipCacheListFormat::Human,
            },
            cache_dir: Some(PathBuf::from(".pip-cache")),
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "list", "--cache-dir=.pip-cache"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::List {
                pattern: None,
                format: PipCacheListFormat::Human,
            },
            cache_dir: Some(PathBuf::from(".pip-cache")),
        }
    );
    assert!(parse_pip_compat_action(&args(&["cache", "dir", "--format=bad"])).is_err());
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "remove", "idna"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::Remove {
                pattern: "idna".to_owned(),
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["cache", "purge", "--disable-pip-version-check"])).unwrap(),
        PipCompatAction::Cache {
            action: PipCacheAction::Purge,
            cache_dir: None,
        }
    );
}

#[test]
fn parses_npm_and_pip_machine_readable_lists() {
    assert_eq!(
        parse_npm_compat_action(&args(&["list", "--json"])).unwrap(),
        NpmCompatAction::List {
            action: NpmListAction {
                json: true,
                depth: 0,
                packages: Vec::new(),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["ls", "-al", "--json"])).unwrap(),
        NpmCompatAction::List {
            action: NpmListAction {
                json: true,
                depth: usize::MAX,
                packages: Vec::new(),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["ls", "-j"])).unwrap(),
        NpmCompatAction::List {
            action: NpmListAction {
                json: true,
                depth: 0,
                packages: Vec::new(),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["ls", "--depth", "1", "--json"])).unwrap(),
        NpmCompatAction::List {
            action: NpmListAction {
                json: true,
                depth: 1,
                packages: Vec::new(),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--depth=0",
            "ls",
            "--omit",
            "dev",
            "--loglevel",
            "silent",
            "left-pad@1.3.0",
            "@scope/pkg",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::List {
            action: NpmListAction {
                json: true,
                depth: 0,
                packages: vec!["left-pad@1.3.0".to_owned(), "@scope/pkg".to_owned()],
            },
        }
    );
    assert_eq!(
        package_list_filter_names(
            &args(&["left-pad@1.3.0", "@scope/pkg"]),
            Some(Ecosystem::Npm),
        )
        .unwrap(),
        BTreeSet::from(["@scope/pkg".to_owned(), "left-pad".to_owned()])
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--ws",
            "--include-workspace-root=false",
            "--package-lock-only",
            "--expect-results=false",
            "--expect-result-count=0",
            "query",
            ":root > *",
        ]))
        .unwrap(),
        NpmCompatAction::Query {
            action: NpmQueryAction {
                selector: ":root > *".to_owned(),
                workspaces: Vec::new(),
                all_workspaces: true,
                include_workspace_root: false,
                package_lock_only: true,
                expect_results: Some(false),
                expect_result_count: Some(0),
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "freeze",
            "--all",
            "--local",
            "--path",
            "vendor",
            "--exclude=requests",
            "-r",
            "requirements.txt",
        ]))
        .unwrap(),
        PipCompatAction::Freeze {
            action: PipFreezeAction {
                requirements: vec![PathBuf::from("requirements.txt")],
                paths: vec![PathBuf::from("vendor")],
                user: false,
                exclude: vec!["requests".to_owned()],
                exclude_editable: false,
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["freeze", "--user", "--exclude-editable"])).unwrap(),
        PipCompatAction::Freeze {
            action: PipFreezeAction {
                requirements: Vec::new(),
                paths: Vec::new(),
                user: true,
                exclude: Vec::new(),
                exclude_editable: true,
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["freeze", "-lr", "requirements.txt"])).unwrap(),
        PipCompatAction::Freeze {
            action: PipFreezeAction {
                requirements: vec![PathBuf::from("requirements.txt")],
                paths: Vec::new(),
                user: false,
                exclude: Vec::new(),
                exclude_editable: false,
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["list", "-qq", "--format=freeze"])).unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Freeze,
            verbose: false,
            outdated: false,
            uptodate: false,
            paths: Vec::new(),
            user: false,
            exclude: Vec::new(),
            editable: PipEditableMode::Include,
            not_required: false,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            allow_prereleases: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "list",
            "-oel",
            "-ihttps://mirror.example/simple",
            "-fwheelhouse",
            "--format=json",
        ]))
        .unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Json,
            verbose: false,
            outdated: true,
            uptodate: false,
            paths: Vec::new(),
            user: false,
            exclude: Vec::new(),
            editable: PipEditableMode::Only,
            not_required: false,
            index_url: Some("https://mirror.example/simple".to_owned()),
            extra_index_urls: Vec::new(),
            find_links: vec!["wheelhouse".to_owned()],
            no_index: false,
            allow_prereleases: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["list", "--format", "json", "--not-required"])).unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Json,
            verbose: false,
            outdated: false,
            uptodate: false,
            paths: Vec::new(),
            user: false,
            exclude: Vec::new(),
            editable: PipEditableMode::Include,
            not_required: true,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            allow_prereleases: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "list",
            "--format=json",
            "--local",
            "--path",
            "vendor",
            "--exclude=requests",
            "--exclude-editable",
        ]))
        .unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Json,
            verbose: false,
            outdated: false,
            uptodate: false,
            paths: vec![PathBuf::from("vendor")],
            user: false,
            exclude: vec!["requests".to_owned()],
            editable: PipEditableMode::Exclude,
            not_required: false,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            allow_prereleases: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["list", "--editable", "--format=columns"])).unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Columns,
            verbose: false,
            outdated: false,
            uptodate: false,
            paths: Vec::new(),
            user: false,
            exclude: Vec::new(),
            editable: PipEditableMode::Only,
            not_required: false,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            allow_prereleases: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "list",
            "--uptodate",
            "--format=json",
            "--no-index",
            "--find-links=wheelhouse",
            "--timeout",
            "5",
        ]))
        .unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Json,
            verbose: false,
            outdated: false,
            uptodate: true,
            paths: Vec::new(),
            user: false,
            exclude: Vec::new(),
            editable: PipEditableMode::Include,
            not_required: false,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: vec!["wheelhouse".to_owned()],
            no_index: true,
            allow_prereleases: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["list", "--outdated", "--pre", "--format=freeze"]))
            .unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Freeze,
            verbose: false,
            outdated: true,
            uptodate: false,
            paths: Vec::new(),
            user: false,
            exclude: Vec::new(),
            editable: PipEditableMode::Include,
            not_required: false,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            allow_prereleases: true,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["list", "--user", "--format=json"])).unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Json,
            verbose: false,
            outdated: false,
            uptodate: false,
            paths: Vec::new(),
            user: true,
            exclude: Vec::new(),
            editable: PipEditableMode::Include,
            not_required: false,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            allow_prereleases: false,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["list", "-v", "--format=json"])).unwrap(),
        PipCompatAction::List {
            format: PipListFormat::Json,
            verbose: true,
            outdated: false,
            uptodate: false,
            paths: Vec::new(),
            user: false,
            exclude: Vec::new(),
            editable: PipEditableMode::Include,
            not_required: false,
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: Vec::new(),
            no_index: false,
            allow_prereleases: false,
        }
    );
    assert!(parse_pip_compat_action(&args(&["list", "--outdated", "--uptodate"])).is_err());
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "index",
            "versions",
            "idna",
            "--json",
            "--no-index",
            "--find-links",
            "wheelhouse",
            "--pre",
            "--all-releases",
            "previewed",
            "--only-final=stable-only",
            "--uploaded-prior-to=P14D",
            "--platform",
            "macosx_14_0_arm64",
            "--python-version=3.12",
            "--implementation",
            "cp",
            "--abi=cp312",
            "--disable-pip-version-check",
        ]))
        .unwrap(),
        PipCompatAction::IndexVersions {
            package: "idna".to_owned(),
            index_url: None,
            extra_index_urls: Vec::new(),
            find_links: vec!["wheelhouse".to_owned()],
            no_index: true,
            allow_prereleases: true,
            release_controls: PypiReleaseControls {
                all_releases: PypiReleaseControl {
                    all: false,
                    packages: BTreeSet::from(["previewed".to_owned()]),
                },
                only_final: PypiReleaseControl {
                    all: false,
                    packages: BTreeSet::from(["stable-only".to_owned()]),
                },
            },
            uploaded_prior_to: Some("P14D".to_owned()),
            compatibility: PipCompatibilityTarget {
                platforms: vec!["macosx_14_0_arm64".to_owned()],
                python_version: Some("3.12".to_owned()),
                implementation: Some("cp".to_owned()),
                abis: vec!["cp312".to_owned()],
            },
            json: true,
        }
    );
    assert!(parse_pip_compat_action(&args(&["index", "foo", "requests"])).is_err());
    assert!(
        parse_pip_compat_action(&args(&["index", "versions", "idna", "--bogus", "value"])).is_err()
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "config",
            "--user",
            "get",
            "global.index-url",
            "--json",
        ]))
        .unwrap(),
        PipCompatAction::Config {
            action: PipConfigAction::Get {
                keys: vec!["global.index-url".to_owned()],
                json: true,
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["config", "list", "-vv"])).unwrap(),
        PipCompatAction::Config {
            action: PipConfigAction::List { json: false },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["config", "debug"])).unwrap(),
        PipCompatAction::Config {
            action: PipConfigAction::Debug,
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["config", "--user", "--editor", "true", "edit",])).unwrap(),
        PipCompatAction::ConfigEdit {
            location: PipConfigLocation::User,
            editor: Some("true".to_owned()),
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["config", "set", "global.index-url", "x"])).unwrap(),
        PipCompatAction::Config {
            action: PipConfigAction::Set {
                assignments: vec![("global.index-url".to_owned(), "x".to_owned())],
                location: PipConfigLocation::Auto,
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "config",
            "--global",
            "set",
            "global.index-url",
            "https://global.example.invalid/simple",
        ]))
        .unwrap(),
        PipCompatAction::Config {
            action: PipConfigAction::Set {
                assignments: vec![(
                    "global.index-url".to_owned(),
                    "https://global.example.invalid/simple".to_owned(),
                )],
                location: PipConfigLocation::Global,
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&[
            "config",
            "--site",
            "set",
            "global.extra-index-url=https://extra.example.invalid/simple",
        ]))
        .unwrap(),
        PipCompatAction::Config {
            action: PipConfigAction::Set {
                assignments: vec![(
                    "global.extra-index-url".to_owned(),
                    "https://extra.example.invalid/simple".to_owned(),
                )],
                location: PipConfigLocation::Site,
            },
        }
    );
    assert_eq!(
        parse_pip_compat_action(&args(&["config", "--user", "unset", "global.index-url"])).unwrap(),
        PipCompatAction::Config {
            action: PipConfigAction::Unset {
                keys: vec!["global.index-url".to_owned()],
                location: PipConfigLocation::User,
            },
        }
    );
}
