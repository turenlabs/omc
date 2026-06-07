use super::*;

#[test]
fn pip_config_file_defaults_behave_like_command_flags() {
    let project = test_dir("pip-config-file-defaults");
    let home = test_dir("pip-config-file-home");
    let xdg = test_dir("pip-config-file-xdg");
    let global_config = test_dir("pip-config-file-global").join("pip.conf");
    let user_config = home.join(".config").join("pip").join("pip.conf");
    fs::create_dir_all(user_config.parent().unwrap()).unwrap();
    fs::write(
        &global_config,
        "[install]\ntarget = global-target\nno-deps = true\n[global]\npre = true\n",
    )
    .unwrap();
    fs::write(
        &user_config,
        "[install]\ntarget = user-target\nrequire-hashes = true\n",
    )
    .unwrap();
    fs::write(
            project.join("pip.conf"),
            "[install]\ntarget = vendor\ndry-run = true\nupgrade = true\nreport = report.json\nrequirement = requirements/base.txt 'requirements/dev requirements.txt'\nconstraint = constraints/base.txt\nbuild-constraint = build-constraints/base.txt\nonly-binary = idna\n[download]\ndest = wheelhouse\n[wheel]\nwheel-dir = wheels\n[global]\nall-releases = previewed\nonly-final = stable-only\nuploaded-prior-to = P3D\nplatform = macosx_14_0_arm64 manylinux_2_28_x86_64\nabi = cp312 abi3\n",
        )
        .unwrap();

    with_env_values(
        &[
            ("HOME", Some(home.to_str().unwrap())),
            ("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap())),
            (
                "OMC_TEST_PIP_GLOBAL_CONFIG_FILE",
                Some(global_config.to_str().unwrap()),
            ),
            ("PIP_CONFIG_FILE", None),
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
            ("PIP_WHEEL_DIR", None),
        ],
        || {
            let merged =
                pip_args_with_config_defaults(&project, &args(&["install", "requests"])).unwrap();
            assert_eq!(
                merged,
                args(&[
                    "install",
                    "--target=vendor",
                    "--dry-run",
                    "--upgrade",
                    "--report=report.json",
                    "--requirement=requirements/base.txt",
                    "--requirement=requirements/dev requirements.txt",
                    "--constraint=constraints/base.txt",
                    "--build-constraint=build-constraints/base.txt",
                    "--no-deps",
                    "--require-hashes",
                    "--only-binary=idna",
                    "--pre",
                    "--all-releases=previewed",
                    "--only-final=stable-only",
                    "--uploaded-prior-to=P3D",
                    "--platform=macosx_14_0_arm64",
                    "--platform=manylinux_2_28_x86_64",
                    "--abi=cp312",
                    "--abi=abi3",
                    "requests",
                ])
            );
            let action = parse_pip_compat_action(&merged).unwrap();
            let PipCompatAction::Install(action) = action else {
                panic!("expected pip install action");
            };
            assert_eq!(action.target, Some(PathBuf::from("vendor")));
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
            assert_eq!(action.uploaded_prior_to.as_deref(), Some("P3D"));
            assert_eq!(
                action.binary_packages.get("idna"),
                Some(&PypiBinaryMode::Binary)
            );
            assert_eq!(
                action.compatibility.platforms,
                vec![
                    "macosx_14_0_arm64".to_owned(),
                    "manylinux_2_28_x86_64".to_owned()
                ]
            );
            assert_eq!(
                action.compatibility.abis,
                vec!["cp312".to_owned(), "abi3".to_owned()]
            );

            let overridden = pip_args_with_config_defaults(
                &project,
                &args(&[
                    "install",
                    "--target=cli-target",
                    "--dry-run=false",
                    "--upgrade=false",
                    "--no-deps=false",
                    "--require-hashes=false",
                    "--pre=false",
                    "--all-releases=:none:",
                    "--only-final=cli-stable",
                    "--uploaded-prior-to=2026-01-01T00:00:00Z",
                    "requests",
                ]),
            )
            .unwrap();
            let action = parse_pip_compat_action(&overridden).unwrap();
            let PipCompatAction::Install(action) = action else {
                panic!("expected pip install action");
            };
            assert_eq!(action.target, Some(PathBuf::from("cli-target")));
            assert!(!action.dry_run);
            assert!(!action.upgrade);
            assert!(!action.no_deps);
            assert!(!action.require_hashes);
            assert!(!action.allow_prereleases);
            assert!(action.release_controls.all_releases.packages.is_empty());
            assert!(action
                .release_controls
                .only_final
                .packages
                .contains("cli-stable"));
            assert_eq!(
                action.uploaded_prior_to.as_deref(),
                Some("2026-01-01T00:00:00Z")
            );

            let download =
                pip_args_with_config_defaults(&project, &args(&["download", "requests"])).unwrap();
            assert_eq!(
                download,
                args(&[
                    "download",
                    "--pre",
                    "--all-releases=previewed",
                    "--only-final=stable-only",
                    "--uploaded-prior-to=P3D",
                    "--platform=macosx_14_0_arm64",
                    "--platform=manylinux_2_28_x86_64",
                    "--abi=cp312",
                    "--abi=abi3",
                    "--dest=wheelhouse",
                    "requests",
                ])
            );
            let action = parse_pip_compat_action(&download).unwrap();
            let PipCompatAction::Download(action) = action else {
                panic!("expected pip download action");
            };
            assert_eq!(action.destination, PathBuf::from("wheelhouse"));
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
            assert_eq!(action.uploaded_prior_to.as_deref(), Some("P3D"));

            let wheel =
                pip_args_with_config_defaults(&project, &args(&["wheel", "requests"])).unwrap();
            assert_eq!(
                wheel,
                args(&[
                    "wheel",
                    "--pre",
                    "--all-releases=previewed",
                    "--only-final=stable-only",
                    "--uploaded-prior-to=P3D",
                    "--platform=macosx_14_0_arm64",
                    "--platform=manylinux_2_28_x86_64",
                    "--abi=cp312",
                    "--abi=abi3",
                    "--wheel-dir=wheels",
                    "requests",
                ])
            );
            let action = parse_pip_compat_action(&wheel).unwrap();
            let PipCompatAction::Wheel(action) = action else {
                panic!("expected pip wheel action");
            };
            assert_eq!(action.destination, PathBuf::from("wheels"));
            assert_eq!(action.uploaded_prior_to.as_deref(), Some("P3D"));

            let overridden_download = pip_args_with_config_defaults(
                &project,
                &args(&["download", "--dest=cli-wheelhouse", "requests"]),
            )
            .unwrap();
            let action = parse_pip_compat_action(&overridden_download).unwrap();
            let PipCompatAction::Download(action) = action else {
                panic!("expected pip download action");
            };
            assert_eq!(action.destination, PathBuf::from("cli-wheelhouse"));
        },
    );
}

#[test]
fn formats_pip_cache_list_paths() {
    let cache_dir = PathBuf::from("/tmp/omc-cache");
    let path = cache_dir.join("wheels").join("idna-3.4-py3-none-any.whl");
    assert_eq!(
        pip_cache_list_display_path(&path, &cache_dir, PipCacheListFormat::Human),
        "wheels/idna-3.4-py3-none-any.whl"
    );
    assert_eq!(
        pip_cache_list_display_path(&path, &cache_dir, PipCacheListFormat::Abspath),
        "/tmp/omc-cache/wheels/idna-3.4-py3-none-any.whl"
    );
    let empty_cache = test_dir("pip-cache-empty-list").join("cache");
    assert_eq!(
        pip_cache_list_lines(&empty_cache, None, PipCacheListFormat::Human).unwrap(),
        vec!["Nothing cached.".to_owned()]
    );
    assert!(
        pip_cache_list_lines(&empty_cache, None, PipCacheListFormat::Abspath)
            .unwrap()
            .is_empty()
    );

    let info_cache = test_dir("pip-cache-info");
    let info_file = info_cache.join("wheels").join("demo.whl");
    fs::create_dir_all(info_file.parent().unwrap()).unwrap();
    fs::write(&info_file, b"wheel").unwrap();
    let info = pip_cache_info_lines(&info_cache).unwrap();
    assert_eq!(
        info,
        vec![
            format!(
                "Package index page cache location: {}",
                info_cache.join("http").display()
            ),
            "Package index page cache size: 0 bytes".to_owned(),
            "Number of HTTP files: 0".to_owned(),
            format!("Wheels location: {}", info_cache.display()),
            "Wheels size: 5 bytes".to_owned(),
            "Number of wheels: 1".to_owned(),
        ]
    );
}

#[test]
fn pip_cache_dir_prefers_cli_then_env_like_pip() {
    let cwd = test_dir("pip-cache-env-cwd");
    with_env_values(&[("PIP_CACHE_DIR", Some("env-cache"))], || {
        assert_eq!(
            pip_cache_arg_or_env(&cwd, None).unwrap(),
            cwd.join("env-cache")
        );
        assert_eq!(
            pip_cache_arg_or_env(&cwd, Some(PathBuf::from("cli-cache"))).unwrap(),
            cwd.join("cli-cache")
        );
    });
}

#[test]
fn pip_cache_remove_missing_pattern_fails_like_pip() {
    let project = test_dir("pip-cache-remove-missing");
    let cache_file = pip_cache_dir(&project)
        .join("wheels")
        .join("idna")
        .join("idna-3.4-py3-none-any.whl");
    fs::create_dir_all(cache_file.parent().unwrap()).unwrap();
    fs::write(&cache_file, b"wheel").unwrap();

    assert_eq!(
        print_pip_cache(
            &project,
            PipCacheAction::Remove {
                pattern: "definitely-not-a-cache-hit".to_owned(),
            },
            None,
        )
        .unwrap(),
        ExitCode::FAILURE
    );
    assert!(cache_file.exists());

    assert_eq!(
        print_pip_cache(
            &project,
            PipCacheAction::Remove {
                pattern: "idna".to_owned(),
            },
            None,
        )
        .unwrap(),
        ExitCode::SUCCESS
    );
    assert!(!cache_file.exists());
}

#[test]
fn writes_pip_config_set_and_unset() {
    without_env_var("PIP_CONFIG_FILE", || {
        let dir = test_dir("pip-config-set-unset");
        fs::write(
                dir.join("pip.conf"),
                "[global]\nindex-url = https://old.example.invalid/simple\n# keep this\n\n[install]\nno-index = false\n",
            )
            .unwrap();

        print_pip_config(
            &dir,
            PipConfigAction::Set {
                assignments: vec![
                    (
                        "global.index-url".to_owned(),
                        "https://new.example.invalid/simple".to_owned(),
                    ),
                    (
                        "global.extra-index-url".to_owned(),
                        "https://extra.example.invalid/simple".to_owned(),
                    ),
                ],
                location: PipConfigLocation::Auto,
            },
        )
        .unwrap();

        let config = fs::read_to_string(dir.join("pip.conf")).unwrap();
        assert!(config.contains("index-url = https://new.example.invalid/simple\n"));
        assert!(config.contains("extra-index-url = https://extra.example.invalid/simple\n"));
        assert!(config.contains("# keep this\n"));
        let values = pip_config_values(&dir).unwrap();
        assert_eq!(
            values.get("global.index-url").map(String::as_str),
            Some("https://new.example.invalid/simple/")
        );
        assert_eq!(
            values.get("global.extra-index-url").map(String::as_str),
            Some("https://extra.example.invalid/simple/")
        );

        print_pip_config(
            &dir,
            PipConfigAction::Unset {
                keys: vec!["global.index-url".to_owned()],
                location: PipConfigLocation::Auto,
            },
        )
        .unwrap();
        let config = fs::read_to_string(dir.join("pip.conf")).unwrap();
        assert!(!config.contains("index-url = https://new.example.invalid/simple\n"));
        assert!(config.contains("extra-index-url = https://extra.example.invalid/simple\n"));
    });
}

#[test]
fn reports_pip_config_debug() {
    with_clean_pip_env(|| {
        let dir = test_dir("pip-config-debug");
        fs::write(
            dir.join("pip.conf"),
            "[global]\nindex-url = https://debug.example.invalid/simple\n",
        )
        .unwrap();

        let values = pip_config_values(&dir).unwrap();
        let output = pip_config_debug_report(&dir, &values).unwrap();

        assert!(output.contains("env_var:"));
        assert!(output.contains("config_file:"));
        assert!(output.contains("site:"));
        assert!(output.contains("config_value:"));
        assert!(output.contains("global.index-url=https://debug.example.invalid/simple/"));
    });
}

#[test]
fn reports_pip_env_config_values_like_pip_config() {
    let dir = test_dir("pip-config-env-values");
    with_pip_env_values(
        &[
            ("PIP_CACHE_DIR", Some("rel-cache")),
            ("PIP_INDEX_URL", Some("https://mirror.example/simple")),
            (
                "PIP_EXTRA_INDEX_URL",
                Some("https://extra1.example/simple https://extra2.example/simple"),
            ),
            ("PIP_NO_INDEX", Some("1")),
            ("PIP_FIND_LINKS", Some("wheelhouse")),
            ("PIP_UNKNOWN_OPT", Some("kept")),
        ],
        || {
            let values = pip_config_values(&dir).unwrap();
            assert_eq!(
                values.get(":env:.cache-dir").map(String::as_str),
                Some("rel-cache")
            );
            assert_eq!(
                values.get(":env:.index-url").map(String::as_str),
                Some("https://mirror.example/simple")
            );
            assert_eq!(
                values.get(":env:.extra-index-url").map(String::as_str),
                Some("https://extra1.example/simple https://extra2.example/simple")
            );
            assert_eq!(values.get(":env:.no-index").map(String::as_str), Some("1"));
            assert_eq!(
                values.get(":env:.find-links").map(String::as_str),
                Some("wheelhouse")
            );
            assert_eq!(
                values.get(":env:.unknown-opt").map(String::as_str),
                Some("kept")
            );
            assert_eq!(
                pip_config_value_for_key(&values, ":env:.cache-dir").unwrap(),
                "rel-cache"
            );
            assert_eq!(
                pip_config_value_for_key(&values, ":env:.index-url").unwrap(),
                "https://mirror.example/simple"
            );
            assert_eq!(
                pip_config_list_value(":env:.cache-dir", "rel-cache"),
                "'rel-cache'"
            );
            assert_eq!(
                pip_config_list_value(":env:.index-url", "https://mirror.example/simple"),
                "'https://mirror.example/simple'"
            );

            let output = pip_config_debug_report(&dir, &values).unwrap();
            assert!(output.contains("PIP_CACHE_DIR=rel-cache"));
            assert!(output.contains("PIP_INDEX_URL=https://mirror.example/simple"));
            assert!(output.contains(":env:.cache-dir=rel-cache"));
            assert!(output.contains(":env:.index-url=https://mirror.example/simple"));
        },
    );
}

#[test]
fn edits_pip_site_config_with_editor() {
    without_env_var("PIP_CONFIG_FILE", || {
        let dir = test_dir("pip-config-edit");
        let editor_script = dir.join("edit-pip-config.sh");
        fs::write(
                &editor_script,
                "#!/bin/sh\nprintf '[global]\\nindex-url = https://edited.example.invalid/simple\\n' > \"$1\"\n",
            )
            .unwrap();
        let editor = format!("sh {}", editor_script.display());

        let status = run_pip_compat(
            &dir,
            &args(&["config", "--site", "--editor", editor.as_str(), "edit"]),
        )
        .unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        let config = fs::read_to_string(dir.join("pip.conf")).unwrap();
        assert!(config.contains("index-url = https://edited.example.invalid/simple\n"));
    });
}

#[test]
fn direct_pip_config_file_env_resolves_from_invocation_cwd() {
    let project = test_dir("direct-pip-config-file-env-project");
    let invocation_cwd = project.join("work/release");
    fs::create_dir_all(&invocation_cwd).unwrap();
    fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"root\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    with_env_values(&[("PIP_CONFIG_FILE", Some("ci/pip.conf"))], || {
        let status = run_pip_compat_with_cwd(
            &project,
            &args(&[
                "config",
                "set",
                "global.index-url",
                "https://nested-pip-config.example/simple",
            ]),
            &invocation_cwd,
        )
        .unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        let config = fs::read_to_string(invocation_cwd.join("ci/pip.conf")).unwrap();
        assert!(config.contains("index-url = https://nested-pip-config.example/simple\n"));
        assert!(!project.join("ci/pip.conf").exists());
        assert_eq!(env::var("PIP_CONFIG_FILE").unwrap(), "ci/pip.conf");
    });
}

#[test]
fn writes_pip_global_config_set_and_unset() {
    let dir = test_dir("pip-global-config-set-unset");
    let global_config = dir.join("global").join("pip.conf");

    with_env_var("OMC_TEST_PIP_GLOBAL_CONFIG_FILE", &global_config, || {
        assert_eq!(
            pip_config_write_path(&dir, PipConfigLocation::Global).unwrap(),
            global_config
        );

        print_pip_config(
            &dir,
            PipConfigAction::Set {
                assignments: vec![(
                    "global.index-url".to_owned(),
                    "https://global.example.invalid/simple".to_owned(),
                )],
                location: PipConfigLocation::Global,
            },
        )
        .unwrap();

        let config = fs::read_to_string(&global_config).unwrap();
        assert!(config.contains("index-url = https://global.example.invalid/simple\n"));

        print_pip_config(
            &dir,
            PipConfigAction::Unset {
                keys: vec!["global.index-url".to_owned()],
                location: PipConfigLocation::Global,
            },
        )
        .unwrap();

        let config = fs::read_to_string(&global_config).unwrap();
        assert!(!config.contains("index-url = https://global.example.invalid/simple\n"));
    });
}

#[test]
fn reports_pip_debug_project_state() {
    let dir = test_dir("pip-debug");
    fs::write(
        dir.join("pip.conf"),
        "[global]\nindex-url = https://mirror.example.invalid/simple\nno-index = false\n",
    )
    .unwrap();

    with_env_values(&[("PIP_CACHE_DIR", None)], || {
        let report = pip_debug_report(
            &dir,
            &dir,
            &PipDebugAction {
                verbose: true,
                platform: Some("macosx_14_0_arm64".to_owned()),
                python_version: Some("3.12".to_owned()),
                implementation: Some("cp".to_owned()),
                abis: vec!["cp312".to_owned()],
            },
        )
        .unwrap();

        assert!(report.contains("pip version: omc-pip "));
        assert!(report.contains(&format!(
            "omc project: {}",
            absolute_project_dir(&dir).display()
        )));
        assert!(report.contains(".omc/python/site-packages"));
        assert!(report.contains(".omc/cache/pypi"));
        assert!(report.contains("lockfile: "));
        assert!(report.contains("(missing)"));
        assert!(report.contains("global.index-url: https://mirror.example.invalid/simple/"));
        assert!(report.contains("requested compatibility target:"));
        assert!(report.contains("  platform: macosx_14_0_arm64"));
        assert!(report.contains("  abi: cp312"));
        assert!(report.contains("locked pypi packages:\n  (none)"));
    });
}

#[test]
fn reports_pip_debug_effective_env_cache_dir() {
    let dir = test_dir("pip-debug-cache-env");
    with_env_values(&[("PIP_CACHE_DIR", Some("debug-cache"))], || {
        let report = pip_debug_report(
            &dir,
            &dir,
            &PipDebugAction {
                verbose: false,
                platform: None,
                python_version: None,
                implementation: None,
                abis: Vec::new(),
            },
        )
        .unwrap();
        assert!(report.contains(&format!(
            "pip cache dir: {}",
            dir.join("debug-cache").display()
        )));
    });
}
