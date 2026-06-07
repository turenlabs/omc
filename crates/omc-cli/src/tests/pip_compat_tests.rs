use super::*;

#[test]
fn pip_environment_defaults_behave_like_command_flags() {
    with_env_values(
        &[
            ("PIP_ISOLATED", None),
            ("PIP_TARGET", Some("vendor")),
            ("PIP_PREFIX", None),
            ("PIP_ROOT", Some("staging-root")),
            ("PIP_USER", Some("true")),
            ("PIP_DRY_RUN", Some("true")),
            ("PIP_UPGRADE", Some("yes")),
            ("PIP_REPORT", Some("report.json")),
            (
                "PIP_REQUIREMENT",
                Some("requirements/base.txt 'requirements/dev requirements.txt'"),
            ),
            ("PIP_CONSTRAINT", Some("constraints/base.txt")),
            ("PIP_BUILD_CONSTRAINT", Some("build-constraints/base.txt")),
            ("PIP_NO_DEPS", Some("1")),
            ("PIP_REQUIRE_HASHES", Some("yes")),
            ("PIP_NO_BINARY", Some(":all:")),
            ("PIP_ONLY_BINARY", Some("idna")),
            ("PIP_PRE", Some("on")),
            ("PIP_ALL_RELEASES", Some("previewed")),
            ("PIP_ONLY_FINAL", Some("stable-only")),
            ("PIP_UPLOADED_PRIOR_TO", Some("P7D")),
            (
                "PIP_PLATFORM",
                Some("macosx_14_0_arm64 manylinux_2_28_x86_64"),
            ),
            ("PIP_PYTHON_VERSION", Some("3.12")),
            ("PIP_IMPLEMENTATION", Some("cp")),
            ("PIP_ABI", Some("cp312 abi3")),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let merged =
                pip_args_with_environment_defaults(&args(&["install", "requests==2.32.3"]))
                    .unwrap();
            assert_eq!(
                merged,
                args(&[
                    "install",
                    "--target=vendor",
                    "--root=staging-root",
                    "--user",
                    "--dry-run",
                    "--upgrade",
                    "--report=report.json",
                    "--requirement=requirements/base.txt",
                    "--requirement=requirements/dev requirements.txt",
                    "--constraint=constraints/base.txt",
                    "--build-constraint=build-constraints/base.txt",
                    "--no-deps",
                    "--require-hashes",
                    "--no-binary=:all:",
                    "--only-binary=idna",
                    "--pre",
                    "--all-releases=previewed",
                    "--only-final=stable-only",
                    "--uploaded-prior-to=P7D",
                    "--platform=macosx_14_0_arm64",
                    "--platform=manylinux_2_28_x86_64",
                    "--python-version=3.12",
                    "--implementation=cp",
                    "--abi=cp312",
                    "--abi=abi3",
                    "requests==2.32.3",
                ])
            );

            let action = parse_pip_compat_action(&merged).unwrap();
            let PipCompatAction::Install(action) = action else {
                panic!("expected pip install action");
            };
            assert_eq!(action.target, Some(PathBuf::from("vendor")));
            assert_eq!(action.prefix, None);
            assert_eq!(action.root, Some(PathBuf::from("staging-root")));
            assert!(action.user);
            assert!(action.dry_run);
            assert!(action.upgrade);
            assert_eq!(action.report, Some(PathBuf::from("report.json")));
            assert_eq!(
                action.requirements,
                vec![
                    PathBuf::from("requirements/base.txt"),
                    PathBuf::from("requirements/dev requirements.txt")
                ]
            );
            assert_eq!(
                action.constraints,
                vec![PathBuf::from("constraints/base.txt")]
            );
            assert!(action.no_deps);
            assert!(action.require_hashes);
            assert!(action.allow_prereleases);
            assert!(action
                .release_controls
                .all_releases
                .packages
                .contains("previewed"));
            assert!(action
                .release_controls
                .only_final
                .packages
                .contains("stable-only"));
            assert_eq!(action.uploaded_prior_to.as_deref(), Some("P7D"));
            assert_eq!(action.binary_all, Some(PypiBinaryMode::Source));
            assert_eq!(
                action.binary_packages.get("idna"),
                Some(&PypiBinaryMode::Binary)
            );
            assert_eq!(
                action.compatibility,
                PipCompatibilityTarget {
                    platforms: vec![
                        "macosx_14_0_arm64".to_owned(),
                        "manylinux_2_28_x86_64".to_owned()
                    ],
                    python_version: Some("3.12".to_owned()),
                    implementation: Some("cp".to_owned()),
                    abis: vec!["cp312".to_owned(), "abi3".to_owned()],
                }
            );
        },
    );

    with_env_values(
        &[
            ("PIP_ISOLATED", None),
            ("PIP_TARGET", Some("vendor")),
            ("PIP_PREFIX", None),
            ("PIP_ROOT", None),
            ("PIP_USER", Some("true")),
            ("PIP_DRY_RUN", None),
            ("PIP_UPGRADE", None),
            ("PIP_REPORT", None),
            ("PIP_REQUIREMENT", None),
            ("PIP_CONSTRAINT", None),
            ("PIP_BUILD_CONSTRAINT", None),
            ("PIP_NO_DEPS", None),
            ("PIP_REQUIRE_HASHES", None),
            ("PIP_NO_BINARY", None),
            ("PIP_ONLY_BINARY", None),
            ("PIP_PRE", None),
            ("PIP_ALL_RELEASES", None),
            ("PIP_ONLY_FINAL", None),
            ("PIP_UPLOADED_PRIOR_TO", None),
            ("PIP_PLATFORM", None),
            ("PIP_PYTHON_VERSION", None),
            ("PIP_IMPLEMENTATION", None),
            ("PIP_ABI", None),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let action = parse_pip_compat_action(
                &pip_args_with_environment_defaults(&args(&[
                    "install",
                    "--target",
                    "override",
                    "--user=false",
                    "requests",
                ]))
                .unwrap(),
            )
            .unwrap();
            let PipCompatAction::Install(action) = action else {
                panic!("expected pip install action");
            };
            assert_eq!(action.target, Some(PathBuf::from("override")));
            assert_eq!(action.prefix, None);
            assert_eq!(action.root, None);
            assert!(!action.user);
        },
    );

    with_env_values(
        &[
            ("PIP_ISOLATED", None),
            ("PIP_TARGET", None),
            ("PIP_PREFIX", Some("prefix-dir")),
            ("PIP_ROOT", None),
            ("PIP_USER", None),
            ("PIP_DRY_RUN", None),
            ("PIP_UPGRADE", None),
            ("PIP_REPORT", None),
            ("PIP_REQUIREMENT", None),
            ("PIP_CONSTRAINT", None),
            ("PIP_BUILD_CONSTRAINT", None),
            ("PIP_NO_DEPS", None),
            ("PIP_REQUIRE_HASHES", None),
            ("PIP_NO_BINARY", None),
            ("PIP_ONLY_BINARY", None),
            ("PIP_PRE", None),
            ("PIP_ALL_RELEASES", None),
            ("PIP_ONLY_FINAL", None),
            ("PIP_UPLOADED_PRIOR_TO", None),
            ("PIP_PLATFORM", None),
            ("PIP_PYTHON_VERSION", None),
            ("PIP_IMPLEMENTATION", None),
            ("PIP_ABI", None),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let merged =
                pip_args_with_environment_defaults(&args(&["install", "requests"])).unwrap();
            assert_eq!(
                merged,
                args(&["install", "--prefix=prefix-dir", "requests"])
            );
            let action = parse_pip_compat_action(&merged).unwrap();
            let PipCompatAction::Install(action) = action else {
                panic!("expected pip install action");
            };
            assert_eq!(action.target, None);
            assert_eq!(action.prefix, Some(PathBuf::from("prefix-dir")));
            assert_eq!(action.root, None);
            assert!(!action.user);
        },
    );

    with_env_values(
        &[
            ("PIP_ISOLATED", None),
            ("PIP_TARGET", None),
            ("PIP_PREFIX", None),
            ("PIP_ROOT", Some("stage")),
            ("PIP_USER", None),
            ("PIP_DRY_RUN", None),
            ("PIP_UPGRADE", None),
            ("PIP_REPORT", None),
            ("PIP_REQUIREMENT", None),
            ("PIP_CONSTRAINT", None),
            ("PIP_BUILD_CONSTRAINT", None),
            ("PIP_NO_DEPS", None),
            ("PIP_REQUIRE_HASHES", None),
            ("PIP_NO_BINARY", None),
            ("PIP_ONLY_BINARY", None),
            ("PIP_PRE", None),
            ("PIP_ALL_RELEASES", None),
            ("PIP_ONLY_FINAL", None),
            ("PIP_UPLOADED_PRIOR_TO", None),
            ("PIP_PLATFORM", None),
            ("PIP_PYTHON_VERSION", None),
            ("PIP_IMPLEMENTATION", None),
            ("PIP_ABI", None),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let merged =
                pip_args_with_environment_defaults(&args(&["install", "requests"])).unwrap();
            assert_eq!(merged, args(&["install", "--root=stage", "requests"]));
            let action = parse_pip_compat_action(&merged).unwrap();
            let PipCompatAction::Install(action) = action else {
                panic!("expected pip install action");
            };
            assert_eq!(action.target, None);
            assert_eq!(action.prefix, None);
            assert_eq!(action.root, Some(PathBuf::from("stage")));
            assert!(!action.user);
        },
    );

    with_env_values(
        &[
            ("PIP_ISOLATED", None),
            ("PIP_TARGET", None),
            ("PIP_PREFIX", None),
            ("PIP_ROOT", None),
            ("PIP_USER", None),
            ("PIP_DRY_RUN", None),
            ("PIP_UPGRADE", None),
            ("PIP_REPORT", None),
            ("PIP_REQUIREMENT", None),
            ("PIP_CONSTRAINT", None),
            ("PIP_BUILD_CONSTRAINT", None),
            ("PIP_NO_DEPS", Some("true")),
            ("PIP_REQUIRE_HASHES", None),
            ("PIP_NO_BINARY", None),
            ("PIP_ONLY_BINARY", None),
            ("PIP_PRE", Some("true")),
            ("PIP_ALL_RELEASES", None),
            ("PIP_ONLY_FINAL", None),
            ("PIP_UPLOADED_PRIOR_TO", Some("2026-01-01T00:00:00Z")),
            ("PIP_PLATFORM", Some("manylinux_2_28_aarch64")),
            ("PIP_PYTHON_VERSION", None),
            ("PIP_IMPLEMENTATION", None),
            ("PIP_ABI", None),
            ("PIP_DEST", Some("wheelhouse")),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let action = parse_pip_compat_action(
                &pip_args_with_environment_defaults(&args(&["download", "idna"])).unwrap(),
            )
            .unwrap();
            let PipCompatAction::Download(action) = action else {
                panic!("expected pip download action");
            };
            assert!(action.no_deps);
            assert!(action.allow_prereleases);
            assert_eq!(
                action.uploaded_prior_to.as_deref(),
                Some("2026-01-01T00:00:00Z")
            );
            assert_eq!(
                action.compatibility.platforms,
                vec!["manylinux_2_28_aarch64".to_owned()]
            );
            assert_eq!(action.destination, PathBuf::from("wheelhouse"));
        },
    );

    with_env_values(
        &[
            ("PIP_ISOLATED", None),
            ("PIP_TARGET", None),
            ("PIP_PREFIX", None),
            ("PIP_ROOT", None),
            ("PIP_USER", None),
            ("PIP_DRY_RUN", None),
            ("PIP_UPGRADE", None),
            ("PIP_REPORT", None),
            ("PIP_REQUIREMENT", None),
            ("PIP_CONSTRAINT", None),
            ("PIP_BUILD_CONSTRAINT", None),
            ("PIP_NO_DEPS", None),
            ("PIP_REQUIRE_HASHES", None),
            ("PIP_NO_BINARY", None),
            ("PIP_ONLY_BINARY", None),
            ("PIP_PRE", None),
            ("PIP_ALL_RELEASES", None),
            ("PIP_ONLY_FINAL", None),
            ("PIP_UPLOADED_PRIOR_TO", None),
            ("PIP_PLATFORM", None),
            ("PIP_PYTHON_VERSION", None),
            ("PIP_IMPLEMENTATION", None),
            ("PIP_ABI", None),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", Some("wheels")),
        ],
        || {
            let action = parse_pip_compat_action(
                &pip_args_with_environment_defaults(&args(&["wheel", "idna"])).unwrap(),
            )
            .unwrap();
            let PipCompatAction::Wheel(action) = action else {
                panic!("expected pip wheel action");
            };
            assert_eq!(action.destination, PathBuf::from("wheels"));
        },
    );

    with_env_values(
        &[
            ("PIP_ISOLATED", Some("true")),
            ("PIP_TARGET", Some("vendor")),
            ("PIP_PREFIX", Some("prefix-dir")),
            ("PIP_ROOT", Some("stage")),
            ("PIP_USER", Some("true")),
            ("PIP_DRY_RUN", Some("true")),
            ("PIP_UPGRADE", Some("true")),
            ("PIP_REPORT", Some("report.json")),
            ("PIP_REQUIREMENT", Some("requirements.txt")),
            ("PIP_CONSTRAINT", Some("constraints.txt")),
            ("PIP_BUILD_CONSTRAINT", Some("build-constraints.txt")),
            ("PIP_NO_DEPS", Some("true")),
            ("PIP_REQUIRE_HASHES", Some("true")),
            ("PIP_NO_BINARY", Some(":all:")),
            ("PIP_ONLY_BINARY", Some("idna")),
            ("PIP_PRE", Some("true")),
            ("PIP_ALL_RELEASES", None),
            ("PIP_ONLY_FINAL", None),
            ("PIP_UPLOADED_PRIOR_TO", Some("P30D")),
            ("PIP_PLATFORM", Some("macosx_14_0_arm64")),
            ("PIP_PYTHON_VERSION", Some("3.12")),
            ("PIP_IMPLEMENTATION", Some("cp")),
            ("PIP_ABI", Some("cp312")),
            ("PIP_DEST", Some("wheelhouse")),
            ("PIP_DESTINATION_DIR", Some("dist")),
            ("PIP_WHEEL_DIR", Some("wheels")),
        ],
        || {
            assert_eq!(
                pip_args_with_environment_defaults(&args(&["--isolated", "install", "requests",]))
                    .unwrap(),
                args(&["--isolated", "install", "requests"])
            );
            assert_eq!(
                pip_args_with_environment_defaults(&args(&["install", "requests"])).unwrap(),
                args(&["install", "requests"])
            );
        },
    );
}

#[test]
fn direct_pip_hash_resolves_relative_paths_from_invocation_cwd() {
    let project = test_dir("direct-pip-hash-project");
    let invocation_cwd = project.join("nested").join("work");
    fs::create_dir_all(&invocation_cwd).unwrap();
    fs::write(
        invocation_cwd.join("demo-1.0.0-py3-none-any.whl"),
        b"wheel bytes",
    )
    .unwrap();

    let status = run_pip_compat_with_cwd(
        &project,
        &args(&["hash", "demo-1.0.0-py3-none-any.whl"]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_wheel_accepts_editable_local_directory() {
    let project = test_dir("pip-wheel-editable-local-project");
    let local = test_dir("pip-wheel-editable-local-package");
    fs::create_dir_all(local.join("src").join("editable_wheel")).unwrap();
    fs::write(
        local.join("src").join("editable_wheel").join("__init__.py"),
        "VALUE = 5\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "editable-wheel"
version = "0.1.0"
"#,
    )
    .unwrap();

    with_env_values(
        &[
            ("PIP_CONFIG_FILE", None),
            ("PIP_INDEX_URL", None),
            ("PIP_EXTRA_INDEX_URL", None),
            ("PIP_FIND_LINKS", None),
            ("PIP_NO_INDEX", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let status = run_pip_compat(
                &project,
                &args(&[
                    "wheel",
                    "-e",
                    local.to_str().unwrap(),
                    "-w",
                    "wheelhouse",
                    "--no-deps",
                ]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
            assert!(project
                .join("wheelhouse")
                .join("editable_wheel-0.1.0-py3-none-any.whl")
                .exists());
        },
    );

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(local);
}

#[test]
fn pip_download_builds_local_directory_wheel() {
    let project = test_dir("pip-download-local-project");
    let local = test_dir("pip-download-local-package");
    fs::create_dir_all(local.join("src").join("local_download")).unwrap();
    fs::write(
        local.join("src").join("local_download").join("__init__.py"),
        "VALUE = 9\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "local-download"
version = "0.1.0"
"#,
    )
    .unwrap();

    with_env_values(
        &[
            ("PIP_CONFIG_FILE", None),
            ("PIP_INDEX_URL", None),
            ("PIP_EXTRA_INDEX_URL", None),
            ("PIP_FIND_LINKS", None),
            ("PIP_NO_INDEX", None),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
        ],
        || {
            let status = run_pip_compat(
                &project,
                &args(&[
                    "download",
                    local.to_str().unwrap(),
                    "-d",
                    "downloads",
                    "--no-deps",
                ]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
            assert!(project
                .join("downloads")
                .join("local_download-0.1.0-py3-none-any.whl")
                .exists());
        },
    );

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(local);
}

#[test]
fn pip_wheel_builds_and_installs_local_directory_wheel() {
    let project = test_dir("pip-wheel-local-project");
    let local = test_dir("pip-wheel-local-package");
    let vendor = project.join("vendor");
    let idna_src = test_dir("pip-wheel-local-idna-source");
    fs::create_dir_all(local.join("src").join("local_pkg")).unwrap();
    fs::create_dir_all(idna_src.join("src").join("idna")).unwrap();
    fs::write(
        local.join("src").join("local_pkg").join("__init__.py"),
        "VALUE = 7\n\ndef main():\n    print(VALUE)\n",
    )
    .unwrap();
    fs::write(idna_src.join("src").join("idna").join("__init__.py"), "").unwrap();
    write_pip_local_wheel(
        &idna_src,
        &PipLocalWheelMetadata {
            name: "idna".to_owned(),
            version: "3.7".to_owned(),
            requires_dist: Vec::new(),
            entry_points: Vec::new(),
        },
        &vendor.join("idna-3.7-py3-none-any.whl"),
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "local-pkg"
version = "0.1.0"
dependencies = ["idna==3.7"]

[project.scripts]
local-cli = "local_pkg:main"
"#,
    )
    .unwrap();

    with_env_values(
        &[
            ("PIP_CONFIG_FILE", None),
            ("PIP_INDEX_URL", None),
            ("PIP_EXTRA_INDEX_URL", None),
            ("PIP_FIND_LINKS", None),
            ("PIP_NO_INDEX", None),
            ("PIP_TARGET", None),
            ("PIP_PREFIX", None),
            ("PIP_ROOT", None),
            ("PIP_USER", None),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let status = run_pip_compat(
                &project,
                &args(&[
                    "wheel",
                    local.to_str().unwrap(),
                    "-w",
                    "wheelhouse",
                    "--no-index",
                    "--find-links",
                    "vendor",
                ]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
            assert!(project
                .join("wheelhouse")
                .join("local_pkg-0.1.0-py3-none-any.whl")
                .exists());
            assert!(project
                .join("wheelhouse")
                .join("idna-3.7-py3-none-any.whl")
                .exists());

            let status = run_pip_compat(
                &project,
                &args(&[
                    "install",
                    "--no-index",
                    "--find-links",
                    "wheelhouse",
                    "local-pkg==0.1.0",
                ]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
        },
    );

    assert!(project
        .join(".omc")
        .join("python")
        .join("site-packages")
        .join("local_pkg")
        .join("__init__.py")
        .exists());
    assert!(project
        .join(".omc")
        .join("python")
        .join("site-packages")
        .join("idna")
        .join("__init__.py")
        .exists());
    assert!(project
        .join(".omc")
        .join("python")
        .join("bin")
        .join("local-cli")
        .exists());

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(local);
    let _ = fs::remove_dir_all(idna_src);
}

#[test]
fn pip_install_local_directory_installs_wheel_not_editable() {
    let project = test_dir("pip-install-direct-local-project");
    let local = test_dir("pip-install-direct-local-package");
    fs::create_dir_all(local.join("src").join("direct_local")).unwrap();
    fs::write(
        local.join("src").join("direct_local").join("__init__.py"),
        "VALUE = 11\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "direct-local"
version = "0.1.0"
"#,
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&["install", local.to_str().unwrap(), "--no-deps"]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let site_packages = project.join(".omc").join("python").join("site-packages");
    assert!(site_packages
        .join("direct_local")
        .join("__init__.py")
        .exists());
    assert!(site_packages
        .join("direct_local-0.1.0.dist-info")
        .join("METADATA")
        .exists());
    assert!(pip_freeze_local_path_requirements(&project)
        .unwrap()
        .is_empty());

    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "direct-local" && package.version == "0.1.0"));

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(local);
}

#[test]
fn pip_install_file_url_local_directory_installs_wheel_not_editable() {
    let project = test_dir("pip-install-file-url-local-project");
    let local = test_dir("pip-install-file-url-local-package");
    fs::create_dir_all(local.join("src").join("file_url_local")).unwrap();
    fs::write(
        local.join("src").join("file_url_local").join("__init__.py"),
        "VALUE = 23\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "file-url-local"
version = "0.1.0"
"#,
    )
    .unwrap();
    let local_url = reqwest::Url::from_directory_path(&local)
        .unwrap()
        .to_string();

    let status = with_clean_pip_env(|| {
        run_pip_compat(&project, &args(&["install", &local_url, "--no-deps"]))
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let site_packages = project.join(".omc").join("python").join("site-packages");
    assert!(site_packages
        .join("file_url_local")
        .join("__init__.py")
        .exists());
    assert!(site_packages
        .join("file_url_local-0.1.0.dist-info")
        .join("METADATA")
        .exists());
    assert!(pip_freeze_local_path_requirements(&project)
        .unwrap()
        .is_empty());

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(local);
}

#[test]
fn pip_install_requirements_local_directory_installs_wheel_not_editable() {
    let project = test_dir("pip-install-requirements-local-project");
    let local = project.join("localpkg");
    fs::create_dir_all(local.join("src").join("requirements_local")).unwrap();
    fs::write(
        local
            .join("src")
            .join("requirements_local")
            .join("__init__.py"),
        "VALUE = 17\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "requirements-local"
version = "0.1.0"
"#,
    )
    .unwrap();
    fs::write(project.join("requirements.txt"), "./localpkg\n").unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&["install", "-r", "requirements.txt", "--no-deps"]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let site_packages = project.join(".omc").join("python").join("site-packages");
    assert!(site_packages
        .join("requirements_local")
        .join("__init__.py")
        .exists());
    assert!(site_packages
        .join("requirements_local-0.1.0.dist-info")
        .join("METADATA")
        .exists());
    assert!(pip_freeze_local_path_requirements(&project)
        .unwrap()
        .is_empty());

    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "requirements-local" && package.version == "0.1.0"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_install_editable_file_url_local_directory_adds_local_path() {
    let project = test_dir("pip-install-editable-file-url-local-project");
    let local = test_dir("pip-install-editable-file-url-local-package");
    fs::create_dir_all(local.join("src").join("fileurledit")).unwrap();
    fs::write(
        local.join("src").join("fileurledit").join("__init__.py"),
        "VALUE = 29\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "fileurledit"
version = "0.1.0"
"#,
    )
    .unwrap();
    let local_url = reqwest::Url::from_directory_path(&local)
        .unwrap()
        .to_string();

    let status =
        with_clean_pip_env(|| run_pip_compat(&project, &args(&["install", "-e", &local_url])))
            .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let local_src = fs::canonicalize(local.join("src")).unwrap();
    assert_eq!(
        pip_freeze_local_path_requirements(&project).unwrap(),
        vec![format!("-e {}", local_src.display())]
    );
    assert_eq!(
        run_python(&project, &args(&["-c", "import fileurledit"])).unwrap(),
        ExitCode::SUCCESS
    );

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(local);
}

#[test]
fn pip_install_local_directory_extra_no_deps_skips_extra_dependencies() {
    let project = test_dir("pip-install-local-extra-no-deps-project");
    fs::create_dir_all(project.join("src").join("rootpkg")).unwrap();
    fs::create_dir_all(project.join("dep").join("src").join("deppkg")).unwrap();
    fs::write(
        project.join("src").join("rootpkg").join("__init__.py"),
        "VALUE = 'root'\n",
    )
    .unwrap();
    fs::write(
        project
            .join("dep")
            .join("src")
            .join("deppkg")
            .join("__init__.py"),
        "VALUE = 'dep'\n",
    )
    .unwrap();
    fs::write(
        project.join("dep").join("pyproject.toml"),
        r#"
[project]
name = "deppkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    fs::write(
        project.join("pyproject.toml"),
        r#"
[project]
name = "rootpkg"
version = "0.1.0"

[project.optional-dependencies]
dev = ["deppkg @ file:./dep"]
"#,
    )
    .unwrap();

    let status =
        with_clean_pip_env(|| run_pip_compat(&project, &args(&["install", ".[dev]", "--no-deps"])))
            .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let site_packages = project.join(".omc").join("python").join("site-packages");
    assert!(site_packages.join("rootpkg").join("__init__.py").exists());
    assert!(site_packages.join("rootpkg-0.1.0.dist-info").exists());
    assert!(!site_packages.join("deppkg").exists());
    assert!(!site_packages.join("deppkg-0.1.0.dist-info").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_install_editable_file_extra_dependency_adds_local_path() {
    let project = test_dir("pip-install-editable-file-extra-project");
    fs::create_dir_all(project.join("src").join("rootpkg")).unwrap();
    fs::create_dir_all(project.join("dep").join("src").join("deppkg")).unwrap();
    fs::write(
        project.join("src").join("rootpkg").join("__init__.py"),
        "VALUE = 'root'\n",
    )
    .unwrap();
    fs::write(
        project
            .join("dep")
            .join("src")
            .join("deppkg")
            .join("__init__.py"),
        "VALUE = 'dep'\n",
    )
    .unwrap();
    fs::write(
        project.join("dep").join("pyproject.toml"),
        r#"
[project]
name = "deppkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    fs::write(
        project.join("pyproject.toml"),
        r#"
[project]
name = "rootpkg"
version = "0.1.0"

[project.optional-dependencies]
dev = ["deppkg @ file:./dep"]
"#,
    )
    .unwrap();

    let status =
        with_clean_pip_env(|| run_pip_compat(&project, &args(&["install", "-e", ".[dev]"])))
            .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let root_src = fs::canonicalize(project.join("src")).unwrap();
    let dep_src = fs::canonicalize(project.join("dep").join("src")).unwrap();
    assert_eq!(
        pip_freeze_local_path_requirements(&project).unwrap(),
        vec![
            format!("-e {}", dep_src.display()),
            format!("-e {}", root_src.display())
        ]
    );
    assert_eq!(
        run_python(&project, &args(&["-c", "import rootpkg, deppkg"])).unwrap(),
        ExitCode::SUCCESS
    );

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_install_local_directory_file_dependency_builds_recursive_wheels() {
    let project = test_dir("pip-install-local-file-dependency-project");
    let package = project.join("pkg");
    let dependency = package.join("dep");
    fs::create_dir_all(package.join("src").join("rootpkg")).unwrap();
    fs::create_dir_all(dependency.join("src").join("deppkg")).unwrap();
    fs::write(
        package.join("src").join("rootpkg").join("__init__.py"),
        "VALUE = 'root'\n",
    )
    .unwrap();
    fs::write(
        dependency.join("src").join("deppkg").join("__init__.py"),
        "VALUE = 'dep'\n",
    )
    .unwrap();
    fs::write(
        dependency.join("pyproject.toml"),
        r#"
[project]
name = "deppkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    fs::write(
        package.join("pyproject.toml"),
        r#"
[project]
name = "rootpkg"
version = "0.1.0"
dependencies = ["deppkg @ file:./dep"]
"#,
    )
    .unwrap();

    let status =
        with_clean_pip_env(|| run_pip_compat(&project, &args(&["install", "./pkg"]))).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let site_packages = project.join(".omc").join("python").join("site-packages");
    assert!(site_packages.join("rootpkg").join("__init__.py").exists());
    assert!(site_packages.join("deppkg").join("__init__.py").exists());
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "rootpkg" && package.version == "0.1.0"));
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "deppkg" && package.version == "0.1.0"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_wheel_builds_recursive_local_directory_dependencies() {
    let project = test_dir("pip-wheel-local-dependencies-project");
    let parent = test_dir("pip-wheel-local-parent-package");
    let child = parent.join("child");
    let vendor = project.join("vendor");
    let idna_src = test_dir("pip-wheel-local-child-idna-source");
    fs::create_dir_all(parent.join("src").join("parent_pkg")).unwrap();
    fs::create_dir_all(child.join("src").join("child_pkg")).unwrap();
    fs::create_dir_all(idna_src.join("src").join("idna")).unwrap();
    fs::write(
        parent.join("src").join("parent_pkg").join("__init__.py"),
        "VALUE = 'parent'\n",
    )
    .unwrap();
    fs::write(
        child.join("src").join("child_pkg").join("__init__.py"),
        "VALUE = 'child'\n",
    )
    .unwrap();
    fs::write(idna_src.join("src").join("idna").join("__init__.py"), "").unwrap();
    write_pip_local_wheel(
        &idna_src,
        &PipLocalWheelMetadata {
            name: "idna".to_owned(),
            version: "3.7".to_owned(),
            requires_dist: Vec::new(),
            entry_points: Vec::new(),
        },
        &vendor.join("idna-3.7-py3-none-any.whl"),
    )
    .unwrap();
    fs::write(
        parent.join("pyproject.toml"),
        r#"
[project]
name = "parent-pkg"
version = "0.1.0"
dependencies = ["child-pkg @ ./child"]
"#,
    )
    .unwrap();
    fs::write(
        child.join("pyproject.toml"),
        r#"
[project]
name = "child-pkg"
version = "0.1.0"
dependencies = ["idna==3.7"]
"#,
    )
    .unwrap();

    with_env_values(
        &[
            ("PIP_CONFIG_FILE", None),
            ("PIP_INDEX_URL", None),
            ("PIP_EXTRA_INDEX_URL", None),
            ("PIP_FIND_LINKS", None),
            ("PIP_NO_INDEX", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let status = run_pip_compat(
                &project,
                &args(&[
                    "wheel",
                    parent.to_str().unwrap(),
                    "-w",
                    "wheelhouse",
                    "--no-index",
                    "--find-links",
                    "vendor",
                ]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
            for filename in [
                "parent_pkg-0.1.0-py3-none-any.whl",
                "child_pkg-0.1.0-py3-none-any.whl",
                "idna-3.7-py3-none-any.whl",
            ] {
                assert!(project.join("wheelhouse").join(filename).exists());
            }

            let status = run_pip_compat(
                &project,
                &args(&[
                    "install",
                    "--no-index",
                    "--find-links",
                    "wheelhouse",
                    "parent-pkg==0.1.0",
                ]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
        },
    );

    for package in ["parent_pkg", "child_pkg", "idna"] {
        assert!(project
            .join(".omc")
            .join("python")
            .join("site-packages")
            .join(package)
            .join("__init__.py")
            .exists());
    }

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(parent);
    let _ = fs::remove_dir_all(idna_src);
}

#[test]
fn pip_install_dry_run_accepts_local_paths_without_project_writes() {
    let project = test_dir("pip-dry-run-local-project");
    let local = test_dir("pip-dry-run-local-package");
    fs::create_dir_all(local.join("src").join("localpkg")).unwrap();
    fs::write(local.join("src").join("localpkg").join("__init__.py"), "").unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "localpkg"
version = "0.1.0"
"#,
    )
    .unwrap();

    run_pip_install_dry_run(
        &project,
        PipInstallAction {
            specs: Vec::new(),
            requirements: Vec::new(),
            constraints: Vec::new(),
            script_requirements: Vec::new(),
            groups: Vec::new(),
            report: None,
            dry_run: true,
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            local_directories: vec![PythonLocalRequirement::new(local, BTreeSet::new())],
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
        },
    )
    .unwrap();

    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join(".omc").exists());
}

#[test]
fn pip_install_requires_requested_input_like_pip() {
    for (name, command, setup) in [
        (
            "pip-install-empty-request",
            vec!["install"],
            None::<(&str, &str)>,
        ),
        (
            "pip-install-constraint-only",
            vec!["install", "-c", "constraints.txt"],
            Some(("constraints.txt", "")),
        ),
    ] {
        let project = test_dir(name);
        if let Some((path, content)) = setup {
            fs::write(project.join(path), content).unwrap();
        }

        let error = with_clean_pip_env(|| run_pip_compat(&project, &args(&command)))
            .expect_err("pip install without requested input should fail");

        assert!(error.to_string().contains("pip install needs at least one"));
        assert!(!project.join("omc.toml").exists());
        assert!(!project.join("omc.lock").exists());
        assert!(!project.join(".omc").exists());

        let _ = fs::remove_dir_all(project);
    }
}

#[test]
fn pip_install_accepts_explicit_empty_requirement_file() {
    let project = test_dir("pip-install-empty-requirement-file");
    fs::write(project.join("requirements.txt"), "").unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(&project, &args(&["install", "-r", "requirements.txt"]))
    })
    .expect("explicit empty requirement files are valid pip input");

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("omc.toml").exists());
    assert!(project.join("omc.lock").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_install_dry_run_accepts_empty_requirement_file() {
    for (name, content) in [
        ("pip-install-dry-run-empty-requirement-file", ""),
        (
            "pip-install-dry-run-marker-skipped-requirement-file",
            "idna==3.7; python_version < '2'\n",
        ),
    ] {
        let project = test_dir(name);
        fs::write(project.join("requirements.txt"), content).unwrap();

        let status = with_clean_pip_env(|| {
            run_pip_compat(
                &project,
                &args(&["install", "--dry-run", "-r", "requirements.txt"]),
            )
        })
        .expect("explicit empty dry-run requirement files are valid pip input");

        assert_eq!(status, ExitCode::SUCCESS);
        assert!(!project.join("omc.toml").exists());
        assert!(!project.join("omc.lock").exists());
        assert!(!project.join(".omc").exists());

        let _ = fs::remove_dir_all(project);
    }
}

#[test]
fn pip_install_dry_run_report_dash_does_not_write_literal_dash_file() {
    let project = test_dir("pip-install-dry-run-report-dash");
    let source = test_dir("pip-install-dry-run-report-dash-source");
    let vendor = project.join("vendor");
    fs::create_dir_all(source.join("src").join("idna")).unwrap();
    fs::write(source.join("src").join("idna").join("__init__.py"), "").unwrap();
    write_pip_local_wheel(
        &source,
        &PipLocalWheelMetadata {
            name: "idna".to_owned(),
            version: "3.7".to_owned(),
            requires_dist: Vec::new(),
            entry_points: Vec::new(),
        },
        &vendor.join("idna-3.7-py3-none-any.whl"),
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--dry-run",
                "--report",
                "-",
                "--no-index",
                "--find-links",
                "vendor",
                "idna==3.7",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("-").exists());
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join(".omc").exists());

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(source);
}

#[test]
fn pip_download_accepts_explicit_empty_requirement_file() {
    let project = test_dir("pip-download-empty-requirement-file");
    fs::write(project.join("requirements.txt"), "").unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&["download", "-r", "requirements.txt", "-d", "wheelhouse"]),
        )
    })
    .expect("explicit empty download requirement files are valid pip input");

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("wheelhouse").exists());
    assert_eq!(fs::read_dir(project.join("wheelhouse")).unwrap().count(), 0);

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_install_group_uses_pyproject_dependency_group() {
    let project = test_dir("pip-install-group-project");
    fs::create_dir_all(project.join("src").join("rootpkg")).unwrap();
    fs::create_dir_all(project.join("groupdep").join("src").join("groupdep")).unwrap();
    fs::write(project.join("src").join("rootpkg").join("__init__.py"), "").unwrap();
    fs::write(
        project
            .join("groupdep")
            .join("src")
            .join("groupdep")
            .join("__init__.py"),
        "",
    )
    .unwrap();
    fs::write(
        project.join("pyproject.toml"),
        r#"
[project]
name = "rootpkg"
version = "0.1.0"

[dependency-groups]
tools = ["groupdep @ ./groupdep"]
"#,
    )
    .unwrap();
    fs::write(
        project.join("groupdep").join("pyproject.toml"),
        r#"
[project]
name = "groupdep"
version = "0.1.0"
"#,
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&["install", "--group", "Tools", "--no-index"]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let local_paths =
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap();
    assert!(local_paths.contains("groupdep/src"));
    assert!(local_paths.contains("src"));
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_group_accepts_pyproject_path() {
    let project = test_dir("pip-install-path-group-project");
    fs::create_dir_all(
        project
            .join("packages")
            .join("tooling")
            .join("src")
            .join("tooling"),
    )
    .unwrap();
    fs::create_dir_all(
        project
            .join("packages")
            .join("tooling")
            .join("tooldep")
            .join("src")
            .join("tooldep"),
    )
    .unwrap();
    fs::write(
        project
            .join("packages")
            .join("tooling")
            .join("src")
            .join("tooling")
            .join("__init__.py"),
        "",
    )
    .unwrap();
    fs::write(
        project
            .join("packages")
            .join("tooling")
            .join("tooldep")
            .join("src")
            .join("tooldep")
            .join("__init__.py"),
        "",
    )
    .unwrap();
    fs::write(
        project
            .join("packages")
            .join("tooling")
            .join("pyproject.toml"),
        r#"
[project]
name = "tooling"
version = "0.1.0"

[dependency-groups]
tools = ["tooldep @ ./tooldep"]
"#,
    )
    .unwrap();
    fs::write(
        project
            .join("packages")
            .join("tooling")
            .join("tooldep")
            .join("pyproject.toml"),
        r#"
[project]
name = "tooldep"
version = "0.1.0"
"#,
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--group",
                "packages/tooling/pyproject.toml:Tools",
                "--no-index",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let local_paths =
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap();
    assert!(local_paths.contains("packages/tooling/src"));
    assert!(local_paths.contains("packages/tooling/tooldep/src"));
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_lock_writes_pylock_without_installing_project() {
    let project = test_dir("pip-lock-local-project");
    fs::create_dir_all(project.join("src").join("localpkg")).unwrap();
    fs::write(project.join("src").join("localpkg").join("__init__.py"), "").unwrap();
    fs::write(
        project.join("pyproject.toml"),
        r#"
[project]
name = "localpkg"
version = "0.1.0"
"#,
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(&project, &args(&["lock", "-o", "locks/pylock.toml"]))
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let pylock = fs::read_to_string(project.join("locks").join("pylock.toml")).unwrap();
    assert!(pylock.contains("lock-version = \"1.0\""));
    assert!(pylock.contains("created-by = \"omc "));
    assert!(!project.join("omc.lock").exists());
    assert!(!project
        .join(".omc")
        .join("python")
        .join("site-packages")
        .exists());
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_lock_requirements_local_directory_writes_live_wheel_url() {
    let project = test_dir("pip-lock-requirements-local-project");
    let local = project.join("localpkg");
    fs::create_dir_all(local.join("src").join("localpkg")).unwrap();
    fs::write(local.join("src").join("localpkg").join("__init__.py"), "").unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "localpkg"
version = "0.1.0"
"#,
    )
    .unwrap();
    fs::write(project.join("requirements.txt"), "./localpkg\n").unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "lock",
                "-r",
                "requirements.txt",
                "-o",
                "locks/pylock.toml",
                "--no-deps",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let pylock = fs::read_to_string(project.join("locks").join("pylock.toml")).unwrap();
    let wheel_url = pylock
        .lines()
        .find_map(|line| {
            line.split_once("url = ")
                .and_then(|(_, value)| value.split('"').nth(1))
        })
        .expect("pylock should contain a wheel URL");
    let wheel_path = reqwest::Url::parse(wheel_url)
        .unwrap()
        .to_file_path()
        .unwrap();

    assert!(wheel_path.exists());
    assert!(wheel_path.starts_with(project.join(".omc").join("python").join("local-wheels")));
    assert!(!project.join("omc.lock").exists());
    assert!(!project
        .join(".omc")
        .join("python")
        .join("site-packages")
        .exists());

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&["install", "-r", "locks/pylock.toml", "--no-deps"]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let site_packages = project.join(".omc").join("python").join("site-packages");
    assert!(site_packages.join("localpkg").join("__init__.py").exists());
    assert!(site_packages
        .join("localpkg-0.1.0.dist-info")
        .join("METADATA")
        .exists());

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_requirements_from_script_uses_inline_metadata() {
    let project = test_dir("pip-install-script-req-project");
    let local = project.join("vendor").join("scriptdep");
    fs::create_dir_all(local.join("src").join("scriptdep")).unwrap();
    fs::write(local.join("src").join("scriptdep").join("__init__.py"), "").unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
[project]
name = "scriptdep"
version = "0.1.0"
"#,
    )
    .unwrap();
    fs::write(
        project.join("tool.py"),
        r#"
# /// script
# dependencies = [
#   "scriptdep @ ./vendor/scriptdep",
# ]
# ///
print("ok")
"#,
    )
    .unwrap();

    let status = run_pip_compat(
        &project,
        &args(&[
            "install",
            "--requirements-from-script",
            "tool.py",
            "--no-index",
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let local_paths =
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap();
    assert!(local_paths.contains("vendor/scriptdep/src"));
    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_explicit_spec_applies_constraint_file_before_resolution() {
    let project = test_dir("pip-install-explicit-constraint-project");
    let dist = project.join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(
        dist.join("constraint_pkg-1.0.0.tar.gz"),
        pypi_sdist_for_test(
            "constraint_pkg-1.0.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: constraint-pkg\nVersion: 1.0.0\n",
                ),
                ("constraint_pkg/__init__.py", "VALUE = 'constrained'\n"),
            ],
        ),
    )
    .unwrap();
    fs::write(
        dist.join("constraint_pkg-2.0.0.tar.gz"),
        pypi_sdist_for_test(
            "constraint_pkg-2.0.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: constraint-pkg\nVersion: 2.0.0\n",
                ),
                ("constraint_pkg/__init__.py", "VALUE = 'latest'\n"),
            ],
        ),
    )
    .unwrap();
    fs::write(project.join("constraints.txt"), "constraint-pkg==1.0.0\n").unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--no-index",
                "--find-links",
                "dist",
                "--no-deps",
                "-c",
                "constraints.txt",
                "constraint-pkg>=1",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join(".omc/python/site-packages/constraint_pkg/__init__.py"))
            .unwrap(),
        "VALUE = 'constrained'\n"
    );
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "constraint-pkg" && package.version == "1.0.0"));
    assert!(!lock
        .packages
        .iter()
        .any(|package| package.name == "constraint-pkg" && package.version == "2.0.0"));

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_explicit_spec_uses_pip_conf_constraint_before_resolution() {
    let project = test_dir("pip-install-config-constraint-project");
    let home = test_dir("pip-install-config-constraint-home");
    let xdg = test_dir("pip-install-config-constraint-xdg");
    let global = test_dir("pip-install-config-constraint-global");
    let global_config = global.join("pip.conf");
    let dist = project.join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(
        dist.join("constraint_pkg-1.0.0.tar.gz"),
        pypi_sdist_for_test(
            "constraint_pkg-1.0.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: constraint-pkg\nVersion: 1.0.0\n",
                ),
                ("constraint_pkg/__init__.py", "VALUE = 'constrained'\n"),
            ],
        ),
    )
    .unwrap();
    fs::write(
        dist.join("constraint_pkg-2.0.0.tar.gz"),
        pypi_sdist_for_test(
            "constraint_pkg-2.0.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: constraint-pkg\nVersion: 2.0.0\n",
                ),
                ("constraint_pkg/__init__.py", "VALUE = 'latest'\n"),
            ],
        ),
    )
    .unwrap();
    fs::write(project.join("constraints.txt"), "constraint-pkg==1.0.0\n").unwrap();
    fs::write(
        project.join("pip.conf"),
        "[install]\nconstraint = constraints.txt\n",
    )
    .unwrap();

    let status = with_env_values(
        &[
            ("HOME", Some(home.to_str().unwrap())),
            ("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap())),
            (
                "OMC_TEST_PIP_GLOBAL_CONFIG_FILE",
                Some(global_config.to_str().unwrap()),
            ),
            ("PIP_CONFIG_FILE", None),
            ("PIP_INDEX_URL", None),
            ("PIP_EXTRA_INDEX_URL", None),
            ("PIP_FIND_LINKS", None),
            ("PIP_REQUIREMENT", None),
            ("PIP_CONSTRAINT", None),
            ("PIP_BUILD_CONSTRAINT", None),
            ("PIP_NO_INDEX", None),
            ("PIP_TARGET", None),
            ("PIP_PREFIX", None),
            ("PIP_ROOT", None),
            ("PIP_USER", None),
            ("PIP_DRY_RUN", None),
            ("PIP_UPGRADE", None),
            ("PIP_REPORT", None),
            ("PIP_NO_DEPS", None),
            ("PIP_REQUIRE_HASHES", None),
            ("PIP_NO_BINARY", None),
            ("PIP_ONLY_BINARY", None),
            ("PIP_PRE", None),
            ("PIP_ALL_RELEASES", None),
            ("PIP_ONLY_FINAL", None),
            ("PIP_UPLOADED_PRIOR_TO", None),
            ("PIP_PLATFORM", None),
            ("PIP_PYTHON_VERSION", None),
            ("PIP_IMPLEMENTATION", None),
            ("PIP_ABI", None),
            ("PIP_DEST", None),
            ("PIP_DESTINATION_DIR", None),
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            run_pip_compat(
                &project,
                &args(&[
                    "install",
                    "--no-index",
                    "--find-links",
                    "dist",
                    "--no-deps",
                    "constraint-pkg>=1",
                ]),
            )
        },
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join(".omc/python/site-packages/constraint_pkg/__init__.py"))
            .unwrap(),
        "VALUE = 'constrained'\n"
    );
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "constraint-pkg" && package.version == "1.0.0"));
    assert!(!lock
        .packages
        .iter()
        .any(|package| package.name == "constraint-pkg" && package.version == "2.0.0"));

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(home).unwrap();
    fs::remove_dir_all(xdg).unwrap();
    fs::remove_dir_all(global).unwrap();
}

#[test]
fn pip_install_target_does_not_write_project_state() {
    let project = test_dir("pip-target-project");
    let dist = project.join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(
            dist.join("demo_pkg-1.0.0.tar.gz"),
            pypi_sdist_for_test(
                "demo_pkg-1.0.0",
                &[
                    (
                        "PKG-INFO",
                        "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\nRequires-Dist: idna>=3\n",
                    ),
                    ("demo_pkg/__init__.py", "VALUE = 'target'\n"),
                ],
            ),
        )
        .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--target",
                "vendor",
                "--no-deps",
                "./dist/demo_pkg-1.0.0.tar.gz",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("vendor/demo_pkg/__init__.py")).unwrap(),
        "VALUE = 'target'\n"
    );
    assert!(project
        .join("vendor")
        .join("demo_pkg-1.0.0.dist-info")
        .join("METADATA")
        .exists());
    let installed_files = pip_installed_files(
        &project.join("vendor"),
        &locked_pypi_package("demo-pkg", "1.0.0", Vec::new()),
    )
    .unwrap();
    assert!(installed_files.contains(&"demo_pkg/__init__.py".to_owned()));
    assert!(installed_files.contains(&"demo_pkg-1.0.0.dist-info/METADATA".to_owned()));
    assert!(installed_files.contains(&"demo_pkg-1.0.0.dist-info/RECORD".to_owned()));
    assert_eq!(
        read_pip_path_packages(
            &project,
            &[PathBuf::from("vendor")],
            &[],
            PipEditableMode::Include,
        )
        .unwrap(),
        vec![InstalledPythonPackage {
            name: "demo-pkg".to_owned(),
            version: "1.0.0".to_owned(),
            dependencies: vec!["idna>=3".to_owned()],
            install_location: Some(project.join("vendor")),
            metadata_location: Some(project.join("vendor").join("demo_pkg-1.0.0.dist-info")),
            editable_project_location: None,
        }]
    );
    let inspect = pip_path_inspect_entries(&project, &[PathBuf::from("vendor")]).unwrap();
    assert_eq!(inspect.len(), 1);
    assert_eq!(inspect[0]["metadata"]["name"], "demo-pkg");
    assert_eq!(inspect[0]["metadata"]["version"], "1.0.0");
    assert_eq!(inspect[0]["installer"], "omc");
    assert_eq!(inspect[0]["dependencies"][0], "idna>=3");
    assert!(inspect[0]["metadata_location"]
        .as_str()
        .unwrap()
        .ends_with("vendor/demo_pkg-1.0.0.dist-info"));
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join(".omc").exists());

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_target_preserves_existing_package_without_upgrade() {
    let project = test_dir("pip-target-no-upgrade-project");
    let dist = project.join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(
        dist.join("target_keep_pkg-1.0.0.tar.gz"),
        pypi_sdist_for_test(
            "target_keep_pkg-1.0.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: target-keep-pkg\nVersion: 1.0.0\n",
                ),
                ("target_keep_pkg/__init__.py", "VALUE = 'old'\n"),
            ],
        ),
    )
    .unwrap();
    fs::write(
        dist.join("target_keep_pkg-1.1.0.tar.gz"),
        pypi_sdist_for_test(
            "target_keep_pkg-1.1.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: target-keep-pkg\nVersion: 1.1.0\n",
                ),
                ("target_keep_pkg/__init__.py", "VALUE = 'new'\n"),
                ("target_keep_pkg/extra.py", "EXTRA = True\n"),
            ],
        ),
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--target",
                "vendor",
                "--no-deps",
                "./dist/target_keep_pkg-1.0.0.tar.gz",
            ]),
        )
    })
    .unwrap();
    assert_eq!(status, ExitCode::SUCCESS);
    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--target",
                "vendor",
                "--no-deps",
                "./dist/target_keep_pkg-1.1.0.tar.gz",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("vendor/target_keep_pkg/__init__.py")).unwrap(),
        "VALUE = 'old'\n"
    );
    assert!(!project.join("vendor/target_keep_pkg/extra.py").exists());
    assert!(project
        .join("vendor")
        .join("target_keep_pkg-1.0.0.dist-info")
        .join("METADATA")
        .exists());
    assert!(project
        .join("vendor")
        .join("target_keep_pkg-1.1.0.dist-info")
        .join("METADATA")
        .exists());

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_target_upgrade_replaces_existing_package() {
    let project = test_dir("pip-target-upgrade-project");
    let dist = project.join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(
        dist.join("target_replace_pkg-1.0.0.tar.gz"),
        pypi_sdist_for_test(
            "target_replace_pkg-1.0.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: target-replace-pkg\nVersion: 1.0.0\n",
                ),
                ("target_replace_pkg/__init__.py", "VALUE = 'old'\n"),
                ("target_replace_pkg/extra.py", "EXTRA = True\n"),
            ],
        ),
    )
    .unwrap();
    fs::write(
        dist.join("target_replace_pkg-1.1.0.tar.gz"),
        pypi_sdist_for_test(
            "target_replace_pkg-1.1.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: target-replace-pkg\nVersion: 1.1.0\n",
                ),
                ("target_replace_pkg/__init__.py", "VALUE = 'new'\n"),
            ],
        ),
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--target",
                "vendor",
                "--no-deps",
                "./dist/target_replace_pkg-1.0.0.tar.gz",
            ]),
        )
    })
    .unwrap();
    assert_eq!(status, ExitCode::SUCCESS);
    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--target",
                "vendor",
                "--upgrade",
                "--no-deps",
                "./dist/target_replace_pkg-1.1.0.tar.gz",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("vendor/target_replace_pkg/__init__.py")).unwrap(),
        "VALUE = 'new'\n"
    );
    assert!(!project.join("vendor/target_replace_pkg/extra.py").exists());
    assert!(project
        .join("vendor")
        .join("target_replace_pkg-1.0.0.dist-info")
        .join("METADATA")
        .exists());
    assert!(project
        .join("vendor")
        .join("target_replace_pkg-1.1.0.dist-info")
        .join("METADATA")
        .exists());

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_target_force_reinstall_replaces_existing_package() {
    let project = test_dir("pip-target-force-reinstall-project");
    let dist = project.join("dist");
    fs::create_dir_all(&dist).unwrap();
    fs::write(
        dist.join("target_force_pkg-1.0.0.tar.gz"),
        pypi_sdist_for_test(
            "target_force_pkg-1.0.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: target-force-pkg\nVersion: 1.0.0\n",
                ),
                ("target_force_pkg/__init__.py", "VALUE = 'old'\n"),
                ("target_force_pkg/extra.py", "EXTRA = True\n"),
            ],
        ),
    )
    .unwrap();
    fs::write(
        dist.join("target_force_pkg-1.1.0.tar.gz"),
        pypi_sdist_for_test(
            "target_force_pkg-1.1.0",
            &[
                (
                    "PKG-INFO",
                    "Metadata-Version: 2.1\nName: target-force-pkg\nVersion: 1.1.0\n",
                ),
                ("target_force_pkg/__init__.py", "VALUE = 'forced'\n"),
            ],
        ),
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--target",
                "vendor",
                "--no-deps",
                "./dist/target_force_pkg-1.0.0.tar.gz",
            ]),
        )
    })
    .unwrap();
    assert_eq!(status, ExitCode::SUCCESS);
    let status = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&[
                "install",
                "--target",
                "vendor",
                "--force-reinstall",
                "--no-deps",
                "./dist/target_force_pkg-1.1.0.tar.gz",
            ]),
        )
    })
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("vendor/target_force_pkg/__init__.py")).unwrap(),
        "VALUE = 'forced'\n"
    );
    assert!(!project.join("vendor/target_force_pkg/extra.py").exists());
    assert!(project
        .join("vendor")
        .join("target_force_pkg-1.1.0.dist-info")
        .join("METADATA")
        .exists());

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_install_user_uses_python_user_base() {
    let project = test_dir("pip-user-project");
    let local = test_dir("pip-user-local");
    let user_base = test_dir("pip-user-base");
    let src = local.join("src");
    fs::create_dir_all(src.join("demoedit")).unwrap();
    fs::write(
        src.join("demoedit").join("__init__.py"),
        "def main():\n    print('user-cli-ok')\n",
    )
    .unwrap();
    fs::write(
            local.join("setup.cfg"),
            "[metadata]\nname = demoedit\nversion = 0.1.0\n[options.entry_points]\nconsole_scripts =\n    demo-cli = demoedit:main\n",
        )
        .unwrap();

    with_env_var("PYTHONUSERBASE", &user_base, || {
        let status = run_pip_compat(
            &project,
            &args(&[
                "install",
                "--user",
                "--no-index",
                "-e",
                local.to_str().unwrap(),
            ]),
        )
        .unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        let paths = pip_user_paths().unwrap();
        assert_eq!(paths.state_project, user_base.join(".omc").join("pip-user"));
        assert!(paths.state_project.exists());
        let canonical_src = fs::canonicalize(&src).unwrap();
        let local_paths_file = paths.site_packages.parent().unwrap().join("local-paths");
        let local_paths = fs::read_to_string(&local_paths_file).unwrap();
        assert_eq!(local_paths, format!("{}\n", canonical_src.display()));
        assert_eq!(
            fs::read_to_string(paths.site_packages.join(".omc-local-paths")).unwrap(),
            local_paths
        );

        let source_script = paths.site_packages.join("bin").join("demo-cli");
        let user_script = paths.bin_dir.join("demo-cli");
        assert!(source_script.exists());
        assert!(user_script.exists());

        let scope_paths = pip_effective_scope_paths(&project, &[], true).unwrap();
        assert_eq!(scope_paths, vec![paths.site_packages.clone()]);
        let packages =
            read_pip_path_packages(&project, &scope_paths, &[], PipEditableMode::Include).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "demoedit");
        assert_eq!(packages[0].version, "0.1.0");

        let freeze_entries =
            pip_freeze_path_local_entries(&project, &scope_paths, &BTreeSet::new()).unwrap();
        assert_eq!(freeze_entries.len(), 1);
        assert_eq!(
            freeze_entries[0].line,
            format!("-e {}", canonical_src.display())
        );

        let inspect = pip_path_inspect_entries(&project, &scope_paths).unwrap();
        assert_eq!(inspect.len(), 1);
        assert_eq!(inspect[0]["metadata"]["name"], "demoedit");
        assert_eq!(inspect[0]["metadata"]["version"], "0.1.0");
        assert_eq!(
            run_pip_compat(&project, &args(&["show", "--user", "demoedit"])).unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_pip_compat(&project, &args(&["check", "--user"])).unwrap(),
            ExitCode::SUCCESS
        );
        let runtime_python_paths =
            env::split_paths(&project_python_path(&project).unwrap()).collect::<Vec<_>>();
        assert!(runtime_python_paths.contains(&paths.site_packages));
        assert!(runtime_python_paths.contains(&canonical_src));
        assert_eq!(
            run_python(&project, &args(&["-c", "import demoedit"])).unwrap(),
            ExitCode::SUCCESS
        );
        let mut command = ProcessCommand::new("demo-cli");
        apply_project_runtime_env_for_cwd(&mut command, &project, &project).unwrap();
        let output = command.output().unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "user-cli-ok\n");

        #[cfg(unix)]
        {
            assert_eq!(fs::read_link(&user_script).unwrap(), source_script);
            let output = ProcessCommand::new(&user_script).output().unwrap();
            assert!(output.status.success());
            assert_eq!(String::from_utf8_lossy(&output.stdout), "user-cli-ok\n");
        }

        #[cfg(not(unix))]
        {
            let shim = fs::read_to_string(&user_script).unwrap();
            assert!(shim.contains("OMC pip user script shim"));
            assert!(shim.contains(&source_script.display().to_string()));
        }

        let status =
            run_pip_compat(&project, &args(&["uninstall", "--user", "-y", "demoedit"])).unwrap();
        assert_eq!(status, ExitCode::SUCCESS);
        assert!(!local_paths_file.exists());
        assert!(!paths.site_packages.join(".omc-local-paths").exists());
        assert!(!source_script.exists());
        assert!(!user_script.exists());
        assert!(
            read_pip_path_packages(&project, &scope_paths, &[], PipEditableMode::Include)
                .unwrap()
                .is_empty()
        );
        assert!(!project.join("omc.toml").exists());
        assert!(!project.join("omc.lock").exists());
        assert!(!project.join(".omc").exists());

        fs::write(
            paths.state_project.join("omc.lock"),
            r#"version = 1

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
        fs::create_dir_all(paths.site_packages.join("requests")).unwrap();
        fs::write(
            paths.site_packages.join("requests").join("__init__.py"),
            "VALUE = 'stale'\n",
        )
        .unwrap();
        let dist_info = paths.site_packages.join("requests-2.32.3.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        fs::write(
            dist_info.join("RECORD"),
            "requests/__init__.py,,\nrequests-2.32.3.dist-info/RECORD,,\n",
        )
        .unwrap();
        fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\nRequires-Dist: idna>=3\n",
        )
        .unwrap();
        assert_eq!(
            run_pip_compat(&project, &args(&["show", "--user", "-f", "requests"])).unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_pip_compat(&project, &args(&["check", "--user"])).unwrap(),
            ExitCode::FAILURE
        );

        let status =
            run_pip_compat(&project, &args(&["uninstall", "--user", "-y", "requests"])).unwrap();
        assert_eq!(status, ExitCode::SUCCESS);
        assert!(!paths
            .site_packages
            .join("requests")
            .join("__init__.py")
            .exists());
        assert!(!dist_info.exists());
        assert!(read_lockfile(paths.state_project.join("omc.lock"))
            .unwrap()
            .packages
            .is_empty());
    });

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
    fs::remove_dir_all(user_base).unwrap();
}

#[test]
fn project_python_path_preserves_existing_pythonpath() {
    let project = test_dir("pythonpath-preserve-project");
    let extra_a = test_dir("pythonpath-preserve-extra-a");
    let extra_b = test_dir("pythonpath-preserve-extra-b");
    let editable_src = test_dir("pythonpath-preserve-editable-src");
    let prefix_root = test_dir("pythonpath-preserve-prefix");
    let prefix_site = prefix_root
        .join("lib")
        .join("python3.12")
        .join("site-packages");
    let prefix_editable_src = test_dir("pythonpath-preserve-prefix-editable-src");
    let user_base = test_dir("pythonpath-preserve-user-base");
    fs::create_dir_all(&extra_a).unwrap();
    fs::create_dir_all(&extra_b).unwrap();
    fs::create_dir_all(&editable_src).unwrap();
    fs::create_dir_all(&prefix_site).unwrap();
    fs::create_dir_all(&prefix_editable_src).unwrap();
    fs::write(
        extra_a.join(".omc-local-paths"),
        format!("{}\n", editable_src.display()),
    )
    .unwrap();
    fs::write(
        prefix_site.parent().unwrap().join("local-paths"),
        format!("{}\n", prefix_editable_src.display()),
    )
    .unwrap();
    let existing = env::join_paths([extra_a.as_path(), prefix_site.as_path(), extra_b.as_path()])
        .unwrap()
        .to_string_lossy()
        .into_owned();

    with_env_values(
        &[
            ("PYTHONPATH", Some(existing.as_str())),
            ("PYTHONUSERBASE", Some(user_base.to_str().unwrap())),
        ],
        || {
            let user_paths = pip_user_paths().unwrap();
            fs::create_dir_all(&user_paths.site_packages).unwrap();
            fs::create_dir_all(&user_paths.state_project).unwrap();

            let paths =
                env::split_paths(&project_python_path(&project).unwrap()).collect::<Vec<_>>();
            assert_eq!(
                paths.first(),
                Some(&project.join(".omc").join("python").join("site-packages"))
            );
            assert!(paths.contains(&extra_a));
            assert!(paths.contains(&extra_b));
            assert!(paths.contains(&editable_src));
            assert!(paths.contains(&prefix_site));
            assert!(paths.contains(&prefix_editable_src));
            let extra_position = paths.iter().position(|path| path == &extra_a).unwrap();
            let editable_position = paths.iter().position(|path| path == &editable_src).unwrap();
            assert!(extra_position < editable_position);
            let prefix_position = paths.iter().position(|path| path == &prefix_site).unwrap();
            let prefix_editable_position = paths
                .iter()
                .position(|path| path == &prefix_editable_src)
                .unwrap();
            assert!(prefix_position < prefix_editable_position);
            let user_position = paths
                .iter()
                .position(|path| path == &user_paths.site_packages)
                .unwrap();
            assert!(editable_position < user_position);
            assert!(prefix_editable_position < user_position);
        },
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(extra_a).unwrap();
    fs::remove_dir_all(extra_b).unwrap();
    fs::remove_dir_all(editable_src).unwrap();
    fs::remove_dir_all(prefix_root).unwrap();
    fs::remove_dir_all(prefix_editable_src).unwrap();
    fs::remove_dir_all(user_base).unwrap();
}

#[test]
fn project_python_path_omits_ambient_user_site_without_omc_state() {
    let project = test_dir("pythonpath-no-ambient-user-project");
    let user_base = test_dir("pythonpath-no-ambient-user-base");

    with_env_values(
        &[("PYTHONUSERBASE", Some(user_base.to_str().unwrap()))],
        || {
            let user_paths = pip_user_paths().unwrap();
            fs::create_dir_all(&user_paths.site_packages).unwrap();
            fs::create_dir_all(user_paths.site_packages.join("ambientpkg")).unwrap();

            let paths =
                env::split_paths(&project_python_path(&project).unwrap()).collect::<Vec<_>>();
            assert_eq!(
                paths.first(),
                Some(&project.join(".omc").join("python").join("site-packages"))
            );
            assert!(!paths.contains(&user_paths.site_packages));

            fs::create_dir_all(&user_paths.state_project).unwrap();
            let paths =
                env::split_paths(&project_python_path(&project).unwrap()).collect::<Vec<_>>();
            assert!(paths.contains(&user_paths.site_packages));
        },
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(user_base).unwrap();
}

#[test]
fn project_python_path_starts_with_omc_project_paths() {
    let project = test_dir("pythonpath-project-first");
    let extra = test_dir("pythonpath-project-first-extra");
    fs::create_dir_all(&extra).unwrap();
    let existing = extra.to_string_lossy().into_owned();

    with_env_values(&[("PYTHONPATH", Some(existing.as_str()))], || {
        let paths = env::split_paths(&project_python_path(&project).unwrap()).collect::<Vec<_>>();
        assert_eq!(
            paths.first(),
            Some(&project.join(".omc").join("python").join("site-packages"))
        );
        assert!(paths.contains(&extra));
    });

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(extra).unwrap();
}

#[test]
fn pip_freeze_lists_installed_local_paths() {
    let project = test_dir("pip-freeze-local-paths-project");
    let local_a = test_dir("pip-freeze-local-path-a");
    let local_b = test_dir("pip-freeze-local-path-b");
    let python_dir = project.join(".omc").join("python");
    fs::create_dir_all(&python_dir).unwrap();
    fs::write(
        python_dir.join("local-paths"),
        format!(
            "{}\n\n{}\n{}\n",
            local_b.display(),
            local_a.display(),
            local_b.display()
        ),
    )
    .unwrap();

    assert_eq!(
        pip_freeze_local_path_requirements(&project).unwrap(),
        vec![
            format!("-e {}", local_a.display()),
            format!("-e {}", local_b.display())
        ]
    );
    assert_eq!(
        pip_freeze_local_path_requirements(&test_dir("pip-freeze-no-local-paths")).unwrap(),
        Vec::<String>::new()
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local_a).unwrap();
    fs::remove_dir_all(local_b).unwrap();
}

#[test]
fn pip_install_editable_local_path_does_not_install_project_root() {
    let project = test_dir("pip-install-editable-no-root-project");
    let local = project.join("localpkg");
    fs::create_dir_all(local.join("src").join("localpkg")).unwrap();
    fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"rootpkg\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        "[project]\nname = \"localpkg\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        local.join("src").join("localpkg").join("__init__.py"),
        "VALUE = 'local'\n",
    )
    .unwrap();

    let status = with_clean_pip_env(|| {
        run_pip_compat(&project, &args(&["install", "-e", "localpkg", "--no-deps"]))
    })
    .unwrap();
    assert_eq!(status, ExitCode::SUCCESS);

    let local_src = fs::canonicalize(local.join("src")).unwrap();
    assert_eq!(
        pip_freeze_local_path_requirements(&project).unwrap(),
        vec![format!("-e {}", local_src.display())]
    );

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_freeze_names_and_filters_editable_local_paths() {
    let project = test_dir("pip-freeze-editable-filter-project");
    let local = test_dir("pip-freeze-editable-filter-local");
    let src = local.join("src");
    fs::create_dir_all(src.join("demoedit")).unwrap();
    fs::write(src.join("demoedit").join("__init__.py"), "").unwrap();
    fs::write(
        local.join("setup.cfg"),
        "[metadata]\nname = demoedit\nversion = 0.1.2\n",
    )
    .unwrap();
    fs::create_dir_all(project.join(".omc").join("python")).unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!("{}\n", src.display()),
    )
    .unwrap();

    let entries = pip_freeze_local_path_entries(&project, &BTreeSet::new()).unwrap();
    assert_eq!(
        entries,
        vec![PipFrozenRequirement {
            name: Some("demoedit".to_owned()),
            line: format!("-e {}", src.display()),
        }]
    );
    assert!(
        pip_freeze_local_path_entries(&project, &BTreeSet::from(["demoedit".to_owned()]))
            .unwrap()
            .is_empty()
    );
    let target = project.join("vendor");
    fs::create_dir_all(&target).unwrap();
    fs::write(
        target.join(".omc-local-paths"),
        format!("{}\n", src.display()),
    )
    .unwrap();
    assert_eq!(
        pip_freeze_path_local_entries(&project, &[PathBuf::from("vendor")], &BTreeSet::new())
            .unwrap(),
        vec![PipFrozenRequirement {
            name: Some("demoedit".to_owned()),
            line: format!("-e {}", src.display()),
        }]
    );

    fs::write(
        project.join("requirements.txt"),
        format!("-e {}\n", src.display()),
    )
    .unwrap();
    let output =
        pip_freeze_output(&project, entries, &[PathBuf::from("requirements.txt")]).unwrap();
    assert_eq!(output.lines, vec![format!("-e {}", src.display())]);

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
}

#[test]
fn pip_freeze_hides_omc_managed_vcs_local_paths() {
    let project = test_dir("pip-freeze-vcs-local-paths-project");
    let local = test_dir("pip-freeze-vcs-local-paths-local");
    let local_src = local.join("src");
    let vcs_src = project
        .join(".omc")
        .join("python")
        .join("vcs")
        .join("vcsdemo")
        .join("abcdef")
        .join("src");
    fs::create_dir_all(local_src.join("demoedit")).unwrap();
    fs::create_dir_all(&vcs_src).unwrap();
    fs::write(local_src.join("demoedit").join("__init__.py"), "").unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"[project]
name = "demoedit"
version = "0.1.2"
"#,
    )
    .unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!("{}\n{}\n", vcs_src.display(), local_src.display()),
    )
    .unwrap();

    assert!(pip_freeze_is_omc_vcs_import_path(&vcs_src));
    assert!(!pip_freeze_is_omc_vcs_import_path(&local_src));
    assert_eq!(
        pip_freeze_local_path_entries(&project, &BTreeSet::new()).unwrap(),
        vec![PipFrozenRequirement {
            name: Some("demoedit".to_owned()),
            line: format!("-e {}", local_src.display()),
        }]
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
}

#[test]
fn pip_list_reads_editable_local_path_metadata() {
    let project = test_dir("pip-list-editable-project");
    let local = test_dir("pip-list-editable-local");
    let src = local.join("src");
    fs::create_dir_all(src.join("demoedit")).unwrap();
    fs::write(src.join("demoedit").join("__init__.py"), "").unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"[project]
name = "demoedit"
version = "0.1.2"
"#,
    )
    .unwrap();
    fs::create_dir_all(project.join(".omc").join("python")).unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!("{}\n", src.display()),
    )
    .unwrap();

    assert_eq!(
        pip_project_local_path_packages(&project, &[]).unwrap(),
        vec![InstalledPythonPackage {
            name: "demoedit".to_owned(),
            version: "0.1.2".to_owned(),
            dependencies: Vec::new(),
            install_location: Some(project.join(".omc").join("python").join("site-packages")),
            metadata_location: None,
            editable_project_location: Some(src.clone()),
        }]
    );
    assert!(
        pip_project_local_path_packages(&project, &["demoedit".to_owned()])
            .unwrap()
            .is_empty()
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
}

#[test]
fn pip_uninstall_prunes_editable_local_paths_by_name() {
    let project = test_dir("pip-uninstall-editable-prune-project");
    let local = test_dir("pip-uninstall-editable-prune-local");
    let keep = test_dir("pip-uninstall-editable-prune-keep");
    let src = local.join("src");
    let keep_src = keep.join("src");
    fs::create_dir_all(src.join("demoedit")).unwrap();
    fs::create_dir_all(keep_src.join("keepedit")).unwrap();
    fs::write(
        local.join("setup.cfg"),
        "[metadata]\nname = demo-edit\nversion = 0.1.0\n",
    )
    .unwrap();
    fs::write(
        keep.join("setup.cfg"),
        "[metadata]\nname = keepedit\nversion = 0.2.0\n",
    )
    .unwrap();
    fs::create_dir_all(project.join(".omc").join("python")).unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!(
            "{}\n{}\n{}\n",
            src.display(),
            keep_src.display(),
            src.display()
        ),
    )
    .unwrap();

    let specs = parse_package_specs(&["demo_edit".to_owned()], Some(Ecosystem::Pypi)).unwrap();
    let removal = remove_pip_editable_local_paths(&project, &specs).unwrap();

    assert!(removal.removed("demo-edit"));
    assert_eq!(removal.remaining_import_paths, vec![keep_src.clone()]);
    assert_eq!(
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap(),
        format!("{}\n", keep_src.display())
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
    fs::remove_dir_all(keep).unwrap();
}

#[test]
fn pip_uninstall_removes_editable_and_restores_remaining_scripts() {
    let project = test_dir("pip-uninstall-editable-project");
    let local = test_dir("pip-uninstall-editable-local");
    let keep = test_dir("pip-uninstall-editable-keep");
    let src = local.join("src");
    let keep_src = keep.join("src");
    fs::create_dir_all(src.join("demoedit")).unwrap();
    fs::create_dir_all(keep_src.join("keepedit")).unwrap();
    fs::write(src.join("demoedit").join("__init__.py"), "").unwrap();
    fs::write(keep_src.join("keepedit").join("__init__.py"), "").unwrap();
    fs::write(
        keep_src.join("keepedit").join("cli.py"),
        "def main():\n    print('keep')\n",
    )
    .unwrap();
    fs::write(
            local.join("setup.cfg"),
            "[metadata]\nname = demoedit\nversion = 0.1.0\n[options.entry_points]\nconsole_scripts =\n    demo-cli = demoedit:main\n",
        )
        .unwrap();
    fs::write(
            keep.join("setup.cfg"),
            "[metadata]\nname = keepedit\nversion = 0.2.0\n[options.entry_points]\nconsole_scripts =\n    keep-cli = keepedit.cli:main\n",
        )
        .unwrap();
    fs::create_dir_all(project.join(".omc").join("python").join("bin")).unwrap();
    fs::write(project.join("omc.lock"), "version = 1\n").unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!("{}\n{}\n", src.display(), keep_src.display()),
    )
    .unwrap();
    fs::write(
        project
            .join(".omc")
            .join("python")
            .join("bin")
            .join("demo-cli"),
        "stale",
    )
    .unwrap();

    let status = run_pip_compat(&project, &args(&["uninstall", "-y", "demoedit"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let local_paths =
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(
        local_paths,
        format!("{}\n", fs::canonicalize(&keep_src).unwrap().display())
    );
    assert!(project
        .join(".omc")
        .join("python")
        .join("bin")
        .join("keep-cli")
        .exists());
    assert!(!project
        .join(".omc")
        .join("python")
        .join("bin")
        .join("demo-cli")
        .exists());

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
    fs::remove_dir_all(keep).unwrap();
}

#[test]
fn pip_uninstall_requirement_file_removes_named_editable_paths() {
    let project = test_dir("pip-uninstall-editable-requirements-project");
    let local = test_dir("pip-uninstall-editable-requirements-local");
    let keep = test_dir("pip-uninstall-editable-requirements-keep");
    let src = local.join("src");
    let keep_src = keep.join("src");
    fs::create_dir_all(src.join("demoedit")).unwrap();
    fs::create_dir_all(keep_src.join("keepedit")).unwrap();
    fs::write(src.join("demoedit").join("__init__.py"), "").unwrap();
    fs::write(keep_src.join("keepedit").join("__init__.py"), "").unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"[project]
name = "demoedit"
version = "0.1.0"
"#,
    )
    .unwrap();
    fs::write(
        keep.join("pyproject.toml"),
        r#"[project]
name = "keepedit"
version = "0.2.0"
"#,
    )
    .unwrap();
    fs::create_dir_all(project.join(".omc").join("python")).unwrap();
    fs::write(project.join("omc.lock"), "version = 1\n").unwrap();
    fs::write(
        project.join("requirements.txt"),
        format!("-e {}\n", local.display()),
    )
    .unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!("{}\n{}\n", src.display(), keep_src.display()),
    )
    .unwrap();

    let status = run_pip_compat(
        &project,
        &args(&["uninstall", "-r", "requirements.txt", "-y"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap(),
        format!("{}\n", fs::canonicalize(&keep_src).unwrap().display())
    );
    assert_eq!(
        pip_project_local_path_packages(&project, &[])
            .unwrap()
            .into_iter()
            .map(|package| package.name)
            .collect::<Vec<_>>(),
        vec!["keepedit"]
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
    fs::remove_dir_all(keep).unwrap();
}

#[test]
fn pip_uninstall_requirement_file_rejects_unnamed_local_paths() {
    let project = test_dir("pip-uninstall-unnamed-local-requirement");
    fs::create_dir_all(project.join("unnamed")).unwrap();
    fs::write(project.join("requirements.txt"), "-e ./unnamed\n").unwrap();

    let error =
        pip_uninstall_specs_from_requirements(&project, vec![PathBuf::from("requirements.txt")])
            .unwrap_err()
            .to_string();

    assert!(error.contains("cannot remove unnamed local path requirement"));
    assert!(error.contains("unnamed"));

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn pip_show_and_inspect_read_editable_local_path_metadata() {
    let project = test_dir("pip-show-editable-project");
    let local = test_dir("pip-show-editable-local");
    let src = local.join("src");
    fs::create_dir_all(src.join("demoedit")).unwrap();
    fs::write(src.join("demoedit").join("__init__.py"), "").unwrap();
    fs::write(src.join("demoedit").join("core.py"), "VALUE = 1\n").unwrap();
    fs::create_dir_all(src.join("demoedit").join("__pycache__")).unwrap();
    fs::write(
        src.join("demoedit")
            .join("__pycache__")
            .join("core.cpython-312.pyc"),
        "",
    )
    .unwrap();
    fs::write(
            local.join("setup.cfg"),
            "[metadata]\nname = demoedit\nversion = 0.1.2\nsummary = Demo editable\nhome_page = https://example.invalid/demo\nauthor = Alice\nlicense = MIT\n[options]\ninstall_requires =\n    idna>=3\n",
        )
        .unwrap();
    fs::create_dir_all(project.join(".omc").join("python")).unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!("{}\n", src.display()),
    )
    .unwrap();
    fs::create_dir_all(project.join("vendor")).unwrap();
    fs::write(
        project.join("vendor").join(".omc-local-paths"),
        format!("{}\n", src.display()),
    )
    .unwrap();

    let metadata = read_python_project_show_metadata(&local).unwrap();
    assert_eq!(metadata.summary.as_deref(), Some("Demo editable"));
    assert_eq!(
        metadata.home_page.as_deref(),
        Some("https://example.invalid/demo")
    );
    assert_eq!(metadata.author.as_deref(), Some("Alice"));
    assert_eq!(metadata.license.as_deref(), Some("MIT"));
    assert_eq!(metadata.requires, vec!["idna".to_owned()]);
    assert_eq!(metadata.requires_dist, vec!["idna>=3".to_owned()]);

    assert_eq!(
        pip_project_local_path_packages(&project, &[]).unwrap(),
        vec![InstalledPythonPackage {
            name: "demoedit".to_owned(),
            version: "0.1.2".to_owned(),
            dependencies: vec!["idna>=3".to_owned()],
            install_location: Some(project.join(".omc").join("python").join("site-packages")),
            metadata_location: None,
            editable_project_location: Some(src.clone()),
        }]
    );
    assert_eq!(
        pip_editable_project_files(&src).unwrap(),
        vec![
            "demoedit/__init__.py".to_owned(),
            "demoedit/core.py".to_owned()
        ]
    );
    let inspect = pip_path_inspect_entries(&project, &[PathBuf::from("vendor")]).unwrap();
    assert_eq!(inspect.len(), 1);
    assert_eq!(inspect[0]["metadata"]["name"], "demoedit");
    assert_eq!(inspect[0]["metadata"]["version"], "0.1.2");
    assert_eq!(inspect[0]["dependencies"][0], "idna>=3");
    assert_eq!(inspect[0]["metadata_location"], src.display().to_string());

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
}

#[test]
fn pip_check_includes_editable_local_path_dependencies() {
    let project = test_dir("pip-check-editable-project");
    let local = test_dir("pip-check-editable-local");
    let src = local.join("src");
    fs::create_dir_all(src.join("editdep")).unwrap();
    fs::write(src.join("editdep").join("__init__.py"), "").unwrap();
    fs::write(
            local.join("setup.cfg"),
            "[metadata]\nname = editdep\nversion = 1.5.0\n[options]\ninstall_requires =\n    missing>=1\n",
        )
        .unwrap();
    fs::create_dir_all(project.join(".omc").join("python")).unwrap();
    fs::write(
        project.join(".omc").join("python").join("local-paths"),
        format!("{}\n", src.display()),
    )
    .unwrap();

    let mut root = locked_pypi_package(
        "root",
        "1.0.0",
        vec!["pypi:editdep>=1".to_owned(), "pypi:bad>=2".to_owned()],
    );
    root.source_url.clear();
    let bad = locked_pypi_package("bad", "1.0.0", Vec::new());
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![root, bad],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };

    assert_eq!(
        pip_check_installed_packages(&project, &lock).unwrap(),
        vec![
            PypiCheckIssue::Incompatible {
                package: "root".to_owned(),
                version: "1.0.0".to_owned(),
                requirement: "bad>=2".to_owned(),
                installed_name: "bad".to_owned(),
                installed_version: "1.0.0".to_owned(),
            },
            PypiCheckIssue::Missing {
                package: "editdep".to_owned(),
                version: "1.5.0".to_owned(),
                requirement: "missing>=1".to_owned(),
            },
        ]
    );

    fs::remove_dir_all(project).unwrap();
    fs::remove_dir_all(local).unwrap();
}

#[test]
fn pip_freeze_requirement_files_preserve_order_and_comments() {
    let project = test_dir("pip-freeze-requirement-order");
    fs::write(
            project.join("requirements.txt"),
            "# pinned\nidna>=2 # inline note\n\nnot-installed-demo==1\ncharset-normalizer[unicode]\n-e ../local-package\n--find-links wheelhouse\n",
        )
        .unwrap();

    let output = pip_freeze_output(
        &project,
        vec![
            PipFrozenRequirement {
                name: Some("charset-normalizer".to_owned()),
                line: "charset-normalizer==3.3.2".to_owned(),
            },
            PipFrozenRequirement {
                name: Some("idna".to_owned()),
                line: "idna==3.7".to_owned(),
            },
            PipFrozenRequirement {
                name: Some("requests".to_owned()),
                line: "requests==2.32.3".to_owned(),
            },
            PipFrozenRequirement {
                name: None,
                line: "-e ../local-package".to_owned(),
            },
        ],
        &[PathBuf::from("requirements.txt")],
    )
    .unwrap();

    assert_eq!(
        output.lines,
        vec![
            "# pinned",
            "idna==3.7",
            "",
            "charset-normalizer==3.3.2",
            "-e ../local-package",
            "--find-links wheelhouse",
            "## The following requirements were added by pip freeze:",
            "requests==2.32.3",
        ]
    );
    assert_eq!(output.warnings.len(), 1);
    assert!(output.warnings[0].contains("not-installed-demo==1"));
    assert!(output.warnings[0].contains("not-installed-demo"));

    fs::remove_dir_all(project).unwrap();
}

#[test]
fn filters_pip_list_not_required_packages() {
    let packages = vec![
        InstalledPythonPackage {
            name: "requests".to_owned(),
            version: "2.32.3".to_owned(),
            dependencies: vec![
                "pypi:idna>=3".to_owned(),
                "charset-normalizer>=2".to_owned(),
            ],
            install_location: None,
            metadata_location: None,
            editable_project_location: None,
        },
        InstalledPythonPackage {
            name: "idna".to_owned(),
            version: "3.7".to_owned(),
            dependencies: Vec::new(),
            install_location: None,
            metadata_location: None,
            editable_project_location: None,
        },
        InstalledPythonPackage {
            name: "charset-normalizer".to_owned(),
            version: "3.3.2".to_owned(),
            dependencies: Vec::new(),
            install_location: None,
            metadata_location: None,
            editable_project_location: None,
        },
        InstalledPythonPackage {
            name: "pytest".to_owned(),
            version: "8.0.0".to_owned(),
            dependencies: Vec::new(),
            install_location: None,
            metadata_location: None,
            editable_project_location: None,
        },
    ];

    assert_eq!(
        pip_not_required_packages(packages)
            .into_iter()
            .map(|package| package.name)
            .collect::<Vec<_>>(),
        vec!["requests", "pytest"]
    );
}

#[test]
fn formats_pip_list_columns_like_pip() {
    let packages = vec![
        InstalledPythonPackage {
            name: "idna".to_owned(),
            version: "3.4".to_owned(),
            dependencies: Vec::new(),
            install_location: Some(PathBuf::from("/tmp/site-packages")),
            metadata_location: None,
            editable_project_location: None,
        },
        InstalledPythonPackage {
            name: "setuptools".to_owned(),
            version: "58.0.4".to_owned(),
            dependencies: Vec::new(),
            install_location: Some(PathBuf::from("/tmp/site-packages")),
            metadata_location: None,
            editable_project_location: None,
        },
    ];
    assert_eq!(
        pip_columns_list_output(&packages, false).unwrap(),
        "Package    Version\n---------- -------\nidna       3.4\nsetuptools 58.0.4\n"
    );
    assert_eq!(
            pip_columns_list_output(&packages, true).unwrap(),
            "Package    Version Location           Installer\n---------- ------- ------------------ ---------\nidna       3.4     /tmp/site-packages omc\nsetuptools 58.0.4  /tmp/site-packages omc\n"
        );
    assert_eq!(
        pip_installed_list_json_output(&packages, false).unwrap(),
        r#"[{"name":"idna","version":"3.4"},{"name":"setuptools","version":"58.0.4"}]"#
    );
    assert_eq!(
        pip_installed_list_json_output(&packages, true).unwrap(),
        r#"[{"installer":"omc","location":"/tmp/site-packages","name":"idna","version":"3.4"},{"installer":"omc","location":"/tmp/site-packages","name":"setuptools","version":"58.0.4"}]"#
    );

    let editable = vec![InstalledPythonPackage {
        name: "demoedit".to_owned(),
        version: "0.1.0".to_owned(),
        dependencies: Vec::new(),
        install_location: Some(PathBuf::from("/tmp/site-packages")),
        metadata_location: None,
        editable_project_location: Some(PathBuf::from("/tmp/demoedit")),
    }];
    assert_eq!(
            pip_columns_list_output(&editable, false).unwrap(),
            "Package  Version Location\n-------- ------- -------------\ndemoedit 0.1.0   /tmp/demoedit\n"
        );
    assert_eq!(
        pip_installed_list_json_output(&editable, false).unwrap(),
        r#"[{"editable_project_location":"/tmp/demoedit","name":"demoedit","version":"0.1.0"}]"#
    );
    assert_eq!(
        pip_installed_list_json_output(&editable, true).unwrap(),
        r#"[{"editable_project_location":"/tmp/demoedit","installer":"omc","location":"/tmp/site-packages","name":"demoedit","version":"0.1.0"}]"#
    );
    assert!(pip_columns_list_output(&[], false).is_none());

    let outdated = vec![PipOutdatedPackage {
        name: "idna".to_owned(),
        version: "3.4".to_owned(),
        latest_version: "3.14".to_owned(),
        latest_filetype: "wheel".to_owned(),
        install_location: Some(PathBuf::from("/tmp/site-packages")),
        installer: "omc".to_owned(),
    }];
    assert_eq!(
        pip_outdated_rows_json_output(&outdated, false).unwrap(),
        r#"[{"latest_filetype":"wheel","latest_version":"3.14","name":"idna","version":"3.4"}]"#
    );
    assert_eq!(
        pip_outdated_rows_json_output(&outdated, true).unwrap(),
        r#"[{"installer":"omc","latest_filetype":"wheel","latest_version":"3.14","location":"/tmp/site-packages","name":"idna","version":"3.4"}]"#
    );
}

#[test]
fn detects_pip_list_version_status() {
    assert!(pip_version_status_matches("2.0.0", "1.0.0", false));
    assert!(!pip_version_status_matches("1.0.0", "1.0.0", false));
    assert!(!pip_version_status_matches("2.0.0", "1.0.0", true));
    assert!(pip_version_status_matches("1.0.0", "1.0.0", true));
}

#[test]
fn pip_uninstall_removes_locked_package_without_manifest_dependency() {
    let project = test_dir("pip-uninstall-locked-package");
    fs::write(
        project.join("omc.lock"),
        r#"version = 1

[[packages]]
ecosystem = "pypi"
name = "Requests"
version = "2.32.3"
source_url = ""
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"

[[python_vcs]]
name = "requests"
url = "https://example.invalid/requests.git"
resolved_commit = "0123456789abcdef0123456789abcdef01234567"
"#,
    )
    .unwrap();
    fs::create_dir_all(
        project
            .join(".omc")
            .join("python")
            .join("site-packages")
            .join("requests-2.32.3.dist-info"),
    )
    .unwrap();

    let status = run_pip_compat(&project, &args(&["uninstall", "-y", "requests"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock.packages.is_empty());
    assert!(lock.python_vcs.is_empty());
    assert!(!project
        .join(".omc")
        .join("python")
        .join("site-packages")
        .join("requests-2.32.3.dist-info")
        .exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_uninstall_skips_missing_packages_like_pip() {
    let project = test_dir("pip-uninstall-missing-package");

    let status = run_pip_compat(
        &project,
        &args(&[
            "uninstall",
            "--no-input",
            "--no-color",
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
            "-y",
            "definitely-not-installed",
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join(".omc").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn pip_uninstall_empty_requirement_file_errors_like_pip() {
    let project = test_dir("pip-uninstall-empty-requirement-file");
    fs::write(project.join("requirements.txt"), "\n# no packages\n").unwrap();

    let error = with_clean_pip_env(|| {
        run_pip_compat(
            &project,
            &args(&["uninstall", "-y", "-r", "requirements.txt"]),
        )
    })
    .expect_err("empty uninstall requirement files should fail");

    assert!(error
        .to_string()
        .contains("pip uninstall needs at least one package"));
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join(".omc").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn reports_pip_show_dependency_and_file_metadata() {
    let package = locked_pypi_package(
        "charset-normalizer",
        "3.4.0",
        vec!["pypi:idna@>=3".to_owned()],
    );
    let dependent = locked_pypi_package(
        "requests",
        "2.32.3",
        vec!["pypi:charset-normalizer@>=2".to_owned()],
    );

    assert_eq!(pip_dependency_names(&package), vec!["idna".to_owned()]);
    assert_eq!(
        pip_required_by_names(&package, &[package.clone(), dependent]),
        vec!["requests".to_owned()]
    );

    let site_packages = temp_test_dir().join("site-packages");
    let dist_info = site_packages.join("charset_normalizer-3.4.0.dist-info");
    fs::create_dir_all(&dist_info).unwrap();
    fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: charset-normalizer\nVersion: 3.4.0\nSummary: Character encoding detector\nHome-page: https://example.invalid/charset\nAuthor: Example Maintainers\nAuthor-email: dev@example.invalid\nLicense-Expression: MIT\nRequires-Dist: idna>=3\nRequires-Dist: PySocks>=1.5.6; extra == 'socks'\n",
        )
        .unwrap();
    fs::write(
        dist_info.join("RECORD"),
        "charset_normalizer/__init__.py,,\ncharset_normalizer-3.4.0.dist-info/METADATA,,\n",
    )
    .unwrap();

    assert_eq!(
        pip_installed_files(&site_packages, &package).unwrap(),
        vec![
            "charset_normalizer-3.4.0.dist-info/METADATA".to_owned(),
            "charset_normalizer/__init__.py".to_owned(),
        ]
    );
    assert_eq!(
        read_pip_show_metadata(&site_packages, &package).unwrap(),
        PipShowMetadata {
            summary: Some("Character encoding detector".to_owned()),
            home_page: Some("https://example.invalid/charset".to_owned()),
            author: Some("Example Maintainers".to_owned()),
            author_email: Some("dev@example.invalid".to_owned()),
            license: Some("MIT".to_owned()),
            requires: vec!["idna".to_owned(), "pysocks".to_owned()],
            requires_dist: vec![
                "idna>=3".to_owned(),
                "PySocks>=1.5.6; extra == 'socks'".to_owned(),
            ],
        }
    );
    fs::remove_dir_all(site_packages.parent().unwrap()).unwrap();
}

#[test]
fn pylock_output_contains_pypi_hashes() {
    let mut wheel = locked_pypi_package("idna", "3.7", Vec::new());
    wheel.sha256 = "a".repeat(64);
    let mut sdist = locked_pypi_package("source-pkg", "1.0.0", Vec::new());
    sdist.source_url = "https://files.example/source-pkg-1.0.0.tar.gz".to_owned();
    sdist.sha256 = "b".repeat(64);
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![
            locked_npm_package("left-pad", "1.3.0", Vec::new()),
            sdist,
            wheel,
        ],
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };

    let pylock = pylock_toml_from_omc_lock(&lock);

    assert!(pylock.contains("name = \"idna\""));
    assert!(pylock.contains("wheels = ["));
    assert!(pylock
        .contains("sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
    assert!(pylock.contains("name = \"source-pkg\""));
    assert!(pylock.contains("sdist = { url = \"https://files.example/source-pkg-1.0.0.tar.gz\""));
    assert!(!pylock.contains("left-pad"));
}

#[test]
fn pip_install_report_includes_locked_local_sources() {
    let project = test_dir("pip-install-report-local-sources");
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages: vec![locked_pypi_package("idna", "3.7", Vec::new())],
        local_sources: vec![
            locked_local_source(Ecosystem::Pypi, "local-py", "0.2.0", "vendor/local-py"),
            locked_local_source(Ecosystem::Npm, "local-npm", "1.0.0", "vendor/local-npm"),
        ],
        python_vcs: Vec::new(),
    };
    fs::write(project.join("omc.lock"), toml::to_string(&lock).unwrap()).unwrap();
    let install = InstallReport {
        python_site_packages: project.join(".omc/python/site-packages"),
        python_bin_dir: project.join(".omc/python/bin"),
        pypi_packages: 1,
        local_source_artifacts: 1,
        ..InstallReport::default()
    };

    let report = pip_install_report_json(&project, &install).unwrap();

    let install_entries = report["install"].as_array().unwrap();
    assert_eq!(install_entries.len(), 2);
    let local = install_entries
        .iter()
        .find(|entry| entry["metadata"]["name"] == "local-py")
        .unwrap();
    assert_eq!(local["is_direct"], true);
    assert_eq!(local["download_info"]["url"], "file:///vendor/local-py");
    assert_eq!(local["download_info"]["dir_info"]["editable"], true);
    assert_eq!(local["omc"]["source_path"], "vendor/local-py");
    assert_eq!(
        local["omc"]["artifact"],
        ".omc/artifacts/pypi/local-py/0.2.0/omc.json"
    );
    assert_eq!(report["omc"]["local_source_artifacts"], 1);
    assert_eq!(report["omc"]["local_sources"].as_array().unwrap().len(), 1);
    assert_eq!(report["omc"]["local_sources"][0]["name"], "local-py");
}
