use super::*;
use crate::*;

#[test]
fn npm_environment_defaults_behave_like_global_config_flags() {
    with_npm_config_overrides(
        &[
            ("NODE_ENV", Some("production")),
            ("NPM_CONFIG_PRODUCTION", None),
            ("npm_config_production", None),
            ("NPM_CONFIG_ONLY", None),
            ("npm_config_only", None),
            ("NPM_CONFIG_ALSO", None),
            ("npm_config_also", None),
            ("NPM_CONFIG_OPTIONAL", None),
            ("npm_config_optional", None),
            ("NPM_CONFIG_OMIT", None),
            ("npm_config_omit", None),
            ("NPM_CONFIG_INCLUDE", None),
            ("npm_config_include", None),
            ("NPM_CONFIG_GLOBAL", None),
            ("npm_config_global", None),
            ("NPM_CONFIG_DRY_RUN", None),
            ("npm_config_dry_run", None),
            ("NPM_CONFIG_PACKAGE_LOCK_ONLY", None),
            ("npm_config_package_lock_only", None),
            ("NPM_CONFIG_PACKAGE_LOCK", None),
            ("npm_config_package_lock", None),
            ("NPM_CONFIG_SAVE", None),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_EXACT", None),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_SAVE_BUNDLE", None),
            ("npm_config_save_bundle", None),
            ("NPM_CONFIG_SAVE_PREFIX", None),
            ("npm_config_save_prefix", None),
            ("NPM_CONFIG_ENGINE_STRICT", None),
            ("npm_config_engine_strict", None),
            ("NPM_CONFIG_OFFLINE", None),
            ("npm_config_offline", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", None),
            ("npm_config_min_release_age", None),
            ("NPM_CONFIG_BEFORE", None),
            ("npm_config_before", None),
        ],
        || {
            assert_eq!(
                npm_args_with_environment_defaults(&args(&["install", "--include=dev"])),
                args(&["--omit=dev", "install", "--include=dev"])
            );
            let action = parse_npm_compat_action(&npm_args_with_environment_defaults(&args(&[
                "install",
                "--include=dev",
            ])))
            .unwrap();
            let NpmCompatAction::Install { omit_dev, .. } = action else {
                panic!("expected npm install action");
            };
            assert!(!omit_dev);
        },
    );

    with_npm_config_overrides(
        &[
            ("NODE_ENV", Some("production")),
            ("NPM_CONFIG_PRODUCTION", Some("false")),
            ("npm_config_production", None),
            ("NPM_CONFIG_ONLY", None),
            ("npm_config_only", None),
            ("NPM_CONFIG_ALSO", None),
            ("npm_config_also", None),
            ("NPM_CONFIG_OPTIONAL", None),
            ("npm_config_optional", None),
            ("NPM_CONFIG_OMIT", None),
            ("npm_config_omit", None),
            ("NPM_CONFIG_INCLUDE", None),
            ("npm_config_include", None),
            ("NPM_CONFIG_GLOBAL", None),
            ("npm_config_global", None),
            ("NPM_CONFIG_DRY_RUN", None),
            ("npm_config_dry_run", None),
            ("NPM_CONFIG_PACKAGE_LOCK_ONLY", None),
            ("npm_config_package_lock_only", None),
            ("NPM_CONFIG_PACKAGE_LOCK", None),
            ("npm_config_package_lock", None),
            ("NPM_CONFIG_SAVE", None),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_EXACT", None),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_SAVE_BUNDLE", None),
            ("npm_config_save_bundle", None),
            ("NPM_CONFIG_SAVE_PREFIX", None),
            ("npm_config_save_prefix", None),
            ("NPM_CONFIG_ENGINE_STRICT", None),
            ("npm_config_engine_strict", None),
            ("NPM_CONFIG_OFFLINE", None),
            ("npm_config_offline", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", None),
            ("npm_config_min_release_age", None),
            ("NPM_CONFIG_BEFORE", None),
            ("npm_config_before", None),
        ],
        || {
            assert_eq!(
                npm_args_with_environment_defaults(&args(&["ci"])),
                args(&["--omit=dev", "--include=dev", "ci"])
            );
            let action =
                parse_npm_compat_action(&npm_args_with_environment_defaults(&args(&["ci"])))
                    .unwrap();
            let NpmCompatAction::Ci { omit_dev, .. } = action else {
                panic!("expected npm ci action");
            };
            assert!(!omit_dev);
        },
    );

    with_npm_config_overrides(
        &[
            ("NODE_ENV", None),
            ("NPM_CONFIG_PRODUCTION", None),
            ("npm_config_production", None),
            ("NPM_CONFIG_ONLY", Some("production")),
            ("npm_config_only", None),
            ("NPM_CONFIG_ALSO", Some("dev")),
            ("npm_config_also", None),
            ("NPM_CONFIG_OPTIONAL", None),
            ("npm_config_optional", None),
            ("NPM_CONFIG_OMIT", None),
            ("npm_config_omit", None),
            ("NPM_CONFIG_INCLUDE", None),
            ("npm_config_include", None),
            ("NPM_CONFIG_GLOBAL", None),
            ("npm_config_global", None),
            ("NPM_CONFIG_DRY_RUN", None),
            ("npm_config_dry_run", None),
            ("NPM_CONFIG_PACKAGE_LOCK_ONLY", None),
            ("npm_config_package_lock_only", None),
            ("NPM_CONFIG_PACKAGE_LOCK", None),
            ("npm_config_package_lock", None),
            ("NPM_CONFIG_SAVE", None),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_EXACT", None),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_SAVE_BUNDLE", None),
            ("npm_config_save_bundle", None),
            ("NPM_CONFIG_SAVE_PREFIX", None),
            ("npm_config_save_prefix", None),
            ("NPM_CONFIG_ENGINE_STRICT", None),
            ("npm_config_engine_strict", None),
            ("NPM_CONFIG_OFFLINE", None),
            ("npm_config_offline", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", None),
            ("npm_config_min_release_age", None),
            ("NPM_CONFIG_BEFORE", None),
            ("npm_config_before", None),
        ],
        || {
            assert_eq!(
                npm_args_with_environment_defaults(&args(&["ci"])),
                args(&["--omit=dev", "--include=dev", "ci"])
            );
            let action =
                parse_npm_compat_action(&npm_args_with_environment_defaults(&args(&["ci"])))
                    .unwrap();
            let NpmCompatAction::Ci { omit_dev, .. } = action else {
                panic!("expected npm ci action");
            };
            assert!(!omit_dev);
        },
    );

    with_npm_config_overrides(
        &[
            ("NODE_ENV", None),
            ("NPM_CONFIG_PRODUCTION", None),
            ("npm_config_production", None),
            ("NPM_CONFIG_ONLY", None),
            ("npm_config_only", None),
            ("NPM_CONFIG_ALSO", None),
            ("npm_config_also", None),
            ("NPM_CONFIG_OPTIONAL", Some("false")),
            ("npm_config_optional", None),
            ("NPM_CONFIG_OMIT", None),
            ("npm_config_omit", None),
            ("NPM_CONFIG_INCLUDE", None),
            ("npm_config_include", None),
            ("NPM_CONFIG_GLOBAL", None),
            ("npm_config_global", None),
            ("NPM_CONFIG_DRY_RUN", None),
            ("npm_config_dry_run", None),
            ("NPM_CONFIG_PACKAGE_LOCK_ONLY", None),
            ("npm_config_package_lock_only", None),
            ("NPM_CONFIG_PACKAGE_LOCK", None),
            ("npm_config_package_lock", None),
            ("NPM_CONFIG_SAVE", None),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_EXACT", None),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_SAVE_BUNDLE", None),
            ("npm_config_save_bundle", None),
            ("NPM_CONFIG_SAVE_PREFIX", None),
            ("npm_config_save_prefix", None),
            ("NPM_CONFIG_ENGINE_STRICT", None),
            ("npm_config_engine_strict", None),
            ("NPM_CONFIG_OFFLINE", None),
            ("npm_config_offline", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", None),
            ("npm_config_min_release_age", None),
            ("NPM_CONFIG_BEFORE", None),
            ("npm_config_before", None),
        ],
        || {
            assert_eq!(
                npm_args_with_environment_defaults(&args(&[
                    "install",
                    "--include=optional",
                    "left-pad",
                ])),
                args(&[
                    "--omit=optional",
                    "install",
                    "--include=optional",
                    "left-pad",
                ])
            );
            let action = parse_npm_compat_action(&npm_args_with_environment_defaults(&args(&[
                "install", "left-pad",
            ])))
            .unwrap();
            let NpmCompatAction::Install { omit_optional, .. } = action else {
                panic!("expected npm install action");
            };
            assert!(omit_optional);
        },
    );

    with_npm_config_overrides(
        &[
            ("NODE_ENV", Some("production")),
            ("NPM_CONFIG_PRODUCTION", None),
            ("npm_config_production", None),
            ("NPM_CONFIG_ONLY", None),
            ("npm_config_only", None),
            ("NPM_CONFIG_ALSO", None),
            ("npm_config_also", None),
            ("NPM_CONFIG_OPTIONAL", None),
            ("npm_config_optional", None),
            ("NPM_CONFIG_OMIT", Some("optional,peer")),
            ("npm_config_omit", None),
            ("NPM_CONFIG_INCLUDE", Some("peer")),
            ("npm_config_include", None),
            ("NPM_CONFIG_GLOBAL", Some("true")),
            ("npm_config_global", None),
            ("NPM_CONFIG_DRY_RUN", Some("true")),
            ("npm_config_dry_run", None),
            ("NPM_CONFIG_PACKAGE_LOCK_ONLY", Some("true")),
            ("npm_config_package_lock_only", None),
            ("NPM_CONFIG_PACKAGE_LOCK", None),
            ("npm_config_package_lock", None),
            ("NPM_CONFIG_SAVE", Some("false")),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_EXACT", Some("true")),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_SAVE_BUNDLE", None),
            ("npm_config_save_bundle", None),
            ("NPM_CONFIG_SAVE_PREFIX", Some("~")),
            ("npm_config_save_prefix", None),
            ("NPM_CONFIG_ENGINE_STRICT", Some("true")),
            ("npm_config_engine_strict", None),
            ("NPM_CONFIG_OFFLINE", Some("true")),
            ("npm_config_offline", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", Some("7")),
            ("npm_config_min_release_age", None),
            ("NPM_CONFIG_BEFORE", Some("2025-01-01")),
            ("npm_config_before", None),
        ],
        || {
            assert_eq!(
                npm_args_with_environment_defaults(&args(&["install", "left-pad"])),
                args(&[
                    "--omit=dev",
                    "--include=dev,optional,peer",
                    "--omit=optional,peer",
                    "--include=peer",
                    "--global",
                    "--dry-run",
                    "--package-lock-only",
                    "--engine-strict",
                    "--offline",
                    "--save-exact",
                    "--no-save",
                    "--save-prefix=~",
                    "--min-release-age=7",
                    "--before=2025-01-01",
                    "install",
                    "left-pad",
                ])
            );
            let action = parse_npm_compat_action(&npm_args_with_environment_defaults(&args(&[
                "install",
                "--save-exact=false",
                "left-pad",
            ])))
            .unwrap();
            let NpmCompatAction::Install {
                omit_dev,
                omit_optional,
                omit_peer,
                global,
                save,
                lock_only,
                dry_run,
                save_prefix,
                npm_before,
                npm_engine_strict,
                npm_offline,
                ..
            } = action
            else {
                panic!("expected npm install action");
            };
            assert!(!omit_dev);
            assert!(omit_optional);
            assert!(!omit_peer);
            assert!(global);
            assert!(!save);
            assert!(lock_only);
            assert!(dry_run);
            assert_eq!(save_prefix, DEFAULT_NPM_SAVE_PREFIX);
            assert_eq!(npm_before.as_deref(), Some("2025-01-01"));
            assert!(npm_engine_strict);
            assert!(npm_offline);
        },
    );

    with_npm_config_overrides(
        &[
            ("NODE_ENV", None),
            ("NPM_CONFIG_PRODUCTION", None),
            ("npm_config_production", None),
            ("NPM_CONFIG_ONLY", None),
            ("npm_config_only", None),
            ("NPM_CONFIG_ALSO", None),
            ("npm_config_also", None),
            ("NPM_CONFIG_OPTIONAL", None),
            ("npm_config_optional", None),
            ("NPM_CONFIG_OMIT", None),
            ("npm_config_omit", None),
            ("NPM_CONFIG_INCLUDE", None),
            ("npm_config_include", None),
            ("NPM_CONFIG_GLOBAL", None),
            ("npm_config_global", None),
            ("NPM_CONFIG_DRY_RUN", None),
            ("npm_config_dry_run", None),
            ("NPM_CONFIG_PACKAGE_LOCK_ONLY", None),
            ("npm_config_package_lock_only", None),
            ("NPM_CONFIG_PACKAGE_LOCK", None),
            ("npm_config_package_lock", None),
            ("NPM_CONFIG_SAVE", None),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_EXACT", None),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_SAVE_BUNDLE", Some("true")),
            ("npm_config_save_bundle", None),
            ("NPM_CONFIG_SAVE_PREFIX", None),
            ("npm_config_save_prefix", None),
            ("NPM_CONFIG_ENGINE_STRICT", None),
            ("npm_config_engine_strict", None),
            ("NPM_CONFIG_OFFLINE", None),
            ("npm_config_offline", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", None),
            ("npm_config_min_release_age", None),
            ("NPM_CONFIG_BEFORE", None),
            ("npm_config_before", None),
        ],
        || {
            assert_eq!(
                npm_args_with_environment_defaults(&args(&["install", "left-pad"])),
                args(&["--save-bundle", "install", "left-pad"])
            );
            let action = parse_npm_compat_action(&npm_args_with_environment_defaults(&args(&[
                "install", "left-pad",
            ])))
            .unwrap();
            let NpmCompatAction::Install {
                save, save_bundle, ..
            } = action
            else {
                panic!("expected npm install action");
            };
            assert!(save);
            assert!(save_bundle);
        },
    );

    with_npm_config_overrides(
        &[
            ("NODE_ENV", None),
            ("NPM_CONFIG_PRODUCTION", None),
            ("npm_config_production", None),
            ("NPM_CONFIG_ONLY", None),
            ("npm_config_only", None),
            ("NPM_CONFIG_ALSO", None),
            ("npm_config_also", None),
            ("NPM_CONFIG_OPTIONAL", None),
            ("npm_config_optional", None),
            ("NPM_CONFIG_OMIT", None),
            ("npm_config_omit", None),
            ("NPM_CONFIG_INCLUDE", None),
            ("npm_config_include", None),
            ("NPM_CONFIG_GLOBAL", None),
            ("npm_config_global", None),
            ("NPM_CONFIG_DRY_RUN", None),
            ("npm_config_dry_run", None),
            ("NPM_CONFIG_PACKAGE_LOCK_ONLY", None),
            ("npm_config_package_lock_only", None),
            ("NPM_CONFIG_PACKAGE_LOCK", None),
            ("npm_config_package_lock", None),
            ("NPM_CONFIG_SAVE", Some("false")),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", Some("true")),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_EXACT", None),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_SAVE_BUNDLE", Some("true")),
            ("npm_config_save_bundle", None),
            ("NPM_CONFIG_SAVE_PREFIX", None),
            ("npm_config_save_prefix", None),
            ("NPM_CONFIG_ENGINE_STRICT", None),
            ("npm_config_engine_strict", None),
            ("NPM_CONFIG_OFFLINE", None),
            ("npm_config_offline", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", None),
            ("npm_config_min_release_age", None),
            ("NPM_CONFIG_BEFORE", None),
            ("npm_config_before", None),
        ],
        || {
            assert_eq!(
                npm_args_with_environment_defaults(&args(&["install", "left-pad"])),
                args(&[
                    "--save-dev",
                    "--save-bundle",
                    "--no-save",
                    "install",
                    "left-pad",
                ])
            );
            let action = parse_npm_compat_action(&npm_args_with_environment_defaults(&args(&[
                "install", "left-pad",
            ])))
            .unwrap();
            let NpmCompatAction::Install {
                save,
                save_bundle,
                dependency_kind,
                ..
            } = action
            else {
                panic!("expected npm install action");
            };
            assert!(!save);
            assert!(save_bundle);
            assert_eq!(dependency_kind, ManifestDependencyKind::Dev);
        },
    );
}

#[test]
fn npm_link_store_round_trips_registered_package() {
    let dir = test_dir("npm-link-store");
    let link_home = dir.join("links");
    let package = dir.join("local-pkg");
    fs::create_dir_all(&package).unwrap();
    fs::write(
        package.join("package.json"),
        r#"{"name":"@scope/local-pkg","version":"1.0.0"}"#,
    )
    .unwrap();

    with_env_var("OMC_NPM_LINK_HOME", &link_home, || {
        let (name, target) = npm_link_target_from_path(&dir, &PathBuf::from("local-pkg")).unwrap();
        assert_eq!(name, "@scope/local-pkg");
        let entry = npm_link_store_entry(&name).unwrap();
        npm_write_link_store_entry(&entry, &target).unwrap();

        assert_eq!(entry, link_home.join("@scope").join("local-pkg"));
        assert_eq!(
            npm_read_link_store_entry("@scope/local-pkg").unwrap(),
            target
        );
    });
}

#[test]
fn npm_link_installs_local_tarball() {
    let project = test_dir("npm-link-tarball-project");
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();

    let package = test_dir("npm-link-tarball-package");
    fs::write(
        package.join("package.json"),
        r#"{"name":"local-tarball","version":"1.2.3","bin":{"local-bin":"cli.js"}}"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 42;\n").unwrap();
    fs::write(package.join("cli.js"), "#!/usr/bin/env node\n").unwrap();

    let tarball = project.join("local-tarball-1.2.3.tgz");
    let files = collect_npm_pack_files(&package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    let status = run_npm_compat(&project, &args(&["link", tarball.to_str().unwrap()])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("node_modules/local-tarball/index.js")).unwrap(),
        "module.exports = 42;\n"
    );
    assert!(project.join("node_modules/.bin/local-bin").exists());

    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock.packages.iter().any(
        |package| package.name == "local-tarball" && package.source_url.starts_with("file://")
    ));
}

#[test]
fn direct_npm_install_resolves_local_paths_from_invocation_cwd() {
    // Hold the env lock: this exercises npm-config-sensitive save behaviour and
    // reads process env, which races (a data race, wrong/empty values) against
    // tests that mutate env via `with_env_var`/`without_env_var` under load.
    with_env_lock(|| {
        let project = test_dir("direct-npm-install-local-path-project");
        let invocation_cwd = project.join("packages/app/src");
        let local_package = invocation_cwd.join("vendor/local-util");
        fs::create_dir_all(&local_package).unwrap();
        fs::write(
            project.join("package.json"),
            r#"{"name":"root","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            local_package.join("package.json"),
            r#"{"name":"local-util","version":"1.2.3"}"#,
        )
        .unwrap();
        fs::write(local_package.join("index.js"), "module.exports = 42;\n").unwrap();

        let status = run_npm_compat_with_cwd(
            &project,
            &args(&["install", "--package-lock=false", "./vendor/local-util"]),
            &invocation_cwd,
        )
        .unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        assert_eq!(
            fs::read_to_string(project.join("node_modules/local-util/index.js")).unwrap(),
            "module.exports = 42;\n"
        );
        let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
        assert_eq!(
            package_json["dependencies"]["local-util"],
            format!(
                "file:{}",
                fs::canonicalize(&local_package).unwrap().display()
            )
        );
        let manifest = read_manifest(project.join("omc.toml")).unwrap();
        let saved_local_path = invocation_cwd
            .join("./vendor/local-util")
            .to_string_lossy()
            .into_owned();
        assert_eq!(manifest.npm_local_paths, vec![saved_local_path]);

        let _ = fs::remove_dir_all(project);
    });
}

#[test]
fn direct_npm_exec_package_resolves_local_paths_from_invocation_cwd() {
    // See the sibling test above: serialize against env-mutating tests.
    with_env_lock(|| {
        let project = test_dir("direct-npm-exec-local-path-project");
        let invocation_cwd = project.join("packages/app/src");
        let local_package = invocation_cwd.join("vendor/local-tool");
        fs::create_dir_all(&local_package).unwrap();
        fs::write(
            local_package.join("package.json"),
            r#"{"name":"local-tool-pkg","version":"1.0.0","bin":{"local-tool":"cli.js"}}"#,
        )
        .unwrap();
        fs::write(
            local_package.join("cli.js"),
            "#!/usr/bin/env node\nconst fs = require('fs'); fs.writeFileSync(process.argv[2], 'local-tool-ok\\n');\n",
        )
        .unwrap();

        let status = run_npm_compat_with_cwd(
            &project,
            &args(&[
                "npx",
                "--package",
                "./vendor/local-tool",
                "local-tool",
                "marker.txt",
            ]),
            &invocation_cwd,
        )
        .unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        assert_eq!(
            fs::read_to_string(invocation_cwd.join("marker.txt")).unwrap(),
            "local-tool-ok\n"
        );
        assert!(!project.join("omc.toml").exists());
        assert!(!project.join("node_modules").exists());

        let _ = fs::remove_dir_all(project);
    });
}

#[test]
fn direct_npm_exec_runs_local_directory_package_arg() {
    let project = test_dir("direct-npm-exec-local-directory-package-project");
    let invocation_cwd = project.join("packages/app/src");
    let local_package = invocation_cwd.join("vendor/direct-tool");
    fs::create_dir_all(&local_package).unwrap();
    fs::write(
        local_package.join("package.json"),
        r#"{"name":"direct-tool-pkg","version":"1.0.0","bin":{"direct-tool":"cli.js"}}"#,
    )
    .unwrap();
    fs::write(
            local_package.join("cli.js"),
            "#!/usr/bin/env node\nconst fs = require('fs'); fs.writeFileSync(process.argv[2], 'direct-tool-ok\\n');\n",
        )
        .unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&["exec", "./vendor/direct-tool", "marker.txt"]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(invocation_cwd.join("marker.txt")).unwrap(),
        "direct-tool-ok\n"
    );
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("node_modules").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn direct_npm_exec_runs_local_tarball_package_arg() {
    let project = test_dir("direct-npm-exec-local-tarball-package-project");
    let invocation_cwd = project.join("packages/app/src");
    let local_package = invocation_cwd.join("tar-tool");
    fs::create_dir_all(&local_package).unwrap();
    fs::write(
        local_package.join("package.json"),
        r#"{"name":"tar-tool-pkg","version":"1.0.0","bin":{"tar-tool":"cli.js"}}"#,
    )
    .unwrap();
    fs::write(
        local_package.join("cli.js"),
        "#!/usr/bin/env node\nprocess.exit(0);\n",
    )
    .unwrap();
    let tarball = invocation_cwd.join("tar-tool-pkg-1.0.0.tgz");
    let files = collect_npm_pack_files(&local_package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&["npx", "./tar-tool-pkg-1.0.0.tgz"]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("node_modules").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn direct_npm_link_resolves_local_paths_from_invocation_cwd() {
    let project = test_dir("direct-npm-link-local-path-project");
    let invocation_cwd = project.join("packages/app/src");
    let local_package = invocation_cwd.join("vendor/local-link");
    fs::create_dir_all(&local_package).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        local_package.join("package.json"),
        r#"{"name":"local-link","version":"1.2.3"}"#,
    )
    .unwrap();
    fs::write(local_package.join("index.js"), "module.exports = 7;\n").unwrap();

    let link_home = project.join("links");
    with_env_var("OMC_NPM_LINK_HOME", &link_home, || {
        let status = run_npm_compat_with_cwd(
            &project,
            &args(&["link", "./vendor/local-link"]),
            &invocation_cwd,
        )
        .unwrap();
        assert_eq!(status, ExitCode::SUCCESS);
    });

    assert_eq!(
        fs::read_to_string(project.join("node_modules/local-link/index.js")).unwrap(),
        "module.exports = 7;\n"
    );
    assert_eq!(
        fs::read_to_string(link_home.join("local-link")).unwrap(),
        format!("{}\n", fs::canonicalize(&local_package).unwrap().display())
    );

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_global_install_uses_prefix_project_and_bins() {
    let project = test_dir("npm-global-install-project");
    let prefix = test_dir("npm-global-prefix");
    let package = test_dir("npm-global-install-package");
    fs::write(
        package.join("package.json"),
        r#"{"name":"global-tarball","version":"1.2.3","bin":{"global-bin":"cli.js"}}"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 42;\n").unwrap();
    fs::write(package.join("cli.js"), "#!/usr/bin/env node\n").unwrap();

    let tarball = project.join("global-tarball-1.2.3.tgz");
    let files = collect_npm_pack_files(&package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    with_env_var("NPM_CONFIG_PREFIX", &prefix, || {
        let status = run_npm_compat(
            &project,
            &args(&["install", "--global", tarball.to_str().unwrap()]),
        )
        .unwrap();
        assert_eq!(status, ExitCode::SUCCESS);

        let global_project = npm_global_project_dir_from_prefix(&prefix);
        assert_eq!(
            fs::read_to_string(global_project.join("node_modules/global-tarball/index.js"))
                .unwrap(),
            "module.exports = 42;\n"
        );
        assert!(global_project.join("omc.toml").exists());
        assert!(prefix.join("bin/global-bin").exists());
        #[cfg(unix)]
        assert_eq!(
            fs::read_link(prefix.join("bin/global-bin")).unwrap(),
            global_project.join("node_modules/.bin/global-bin")
        );

        let status = run_npm_compat(&project, &args(&["remove", "-g", "global-tarball"])).unwrap();
        assert_eq!(status, ExitCode::SUCCESS);
        assert!(!prefix.join("bin/global-bin").exists());
        assert!(!global_project.join("node_modules/global-tarball").exists());
    });

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(prefix);
    let _ = fs::remove_dir_all(package);
}

#[test]
fn npm_global_remove_skips_missing_packages_like_npm() {
    let project = test_dir("npm-global-remove-missing-project");
    let prefix = test_dir("npm-global-remove-missing-prefix");

    with_env_var("NPM_CONFIG_PREFIX", &prefix, || {
        let status = run_npm_compat(
            &project,
            &args(&["uninstall", "--global", "definitely-not-installed"]),
        )
        .unwrap();
        assert_eq!(status, ExitCode::SUCCESS);

        let global_project = npm_global_project_dir_from_prefix(&prefix);
        assert!(!global_project.join("omc.toml").exists());
        assert!(!global_project.join("omc.lock").exists());
        assert!(!prefix.join("bin").exists());
    });

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(prefix);
}

#[test]
fn npm_global_remove_rejects_package_lock_only_like_npm() {
    let project = test_dir("npm-global-remove-package-lock-only-project");
    let prefix = test_dir("npm-global-remove-package-lock-only-prefix");

    with_env_var("NPM_CONFIG_PREFIX", &prefix, || {
        let error = run_npm_compat(
            &project,
            &args(&[
                "uninstall",
                "--global",
                "--package-lock-only",
                "definitely-not-installed",
            ]),
        )
        .expect_err("npm cannot generate global lockfiles");
        assert!(error
            .to_string()
            .contains("global remove cannot generate lockfiles"));
    });

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(prefix);
}

#[test]
fn npm_install_saves_root_package_json_dependencies() {
    let project = test_dir("npm-install-root-package-json-project");
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0","dependencies":{"local-tarball":"0.0.1"}}"#,
    )
    .unwrap();

    let package = test_dir("npm-install-root-package-json-package");
    fs::write(
        package.join("package.json"),
        r#"{"name":"local-tarball","version":"1.2.3"}"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 42;\n").unwrap();

    let tarball = project.join("local-tarball-1.2.3.tgz");
    let files = collect_npm_pack_files(&package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    let status = run_npm_compat(
        &project,
        &args(&[
            "install",
            "--package-lock-only",
            "--save-dev",
            tarball.to_str().unwrap(),
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|dependencies| !dependencies.contains_key("local-tarball")));
    let saved = package_json
        .get("devDependencies")
        .and_then(serde_json::Value::as_object)
        .and_then(|dependencies| dependencies.get("local-tarball"))
        .and_then(serde_json::Value::as_str)
        .unwrap();
    assert!(saved.starts_with("file://"));
    assert!(saved.ends_with("local-tarball-1.2.3.tgz"));

    let manifest = read_manifest(project.join("omc.toml")).unwrap();
    assert!(manifest.dependencies.is_empty());
    assert!(manifest
        .dev_dependencies
        .get("npm:local-tarball")
        .is_some_and(|requirement| requirement.starts_with("file://")));

    let transient = test_dir("npm-install-root-package-json-transient");
    fs::write(
        transient.join("package.json"),
        r#"{"name":"transient-tarball","version":"9.9.9"}"#,
    )
    .unwrap();
    fs::write(transient.join("index.js"), "module.exports = 99;\n").unwrap();
    let transient_tarball = project.join("transient-tarball-9.9.9.tgz");
    let files = collect_npm_pack_files(&transient).unwrap();
    write_npm_pack_tarball(&transient_tarball, &files).unwrap();

    run_npm_compat(
        &project,
        &args(&[
            "install",
            "--package-lock-only",
            "--no-save",
            transient_tarball.to_str().unwrap(),
        ]),
    )
    .unwrap();

    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_none_or(|dependencies| !dependencies.contains_key("transient-tarball")));
    assert!(package_json
        .get("devDependencies")
        .and_then(serde_json::Value::as_object)
        .is_none_or(|dependencies| !dependencies.contains_key("transient-tarball")));

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(package);
    let _ = fs::remove_dir_all(transient);
}

#[test]
fn npm_install_save_bundle_updates_package_json() {
    let project = test_dir("npm-install-save-bundle-project");
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();

    let package = test_dir("npm-install-save-bundle-package");
    fs::write(
        package.join("package.json"),
        r#"{"name":"bundled-tarball","version":"1.2.3"}"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 42;\n").unwrap();

    let tarball = project.join("bundled-tarball-1.2.3.tgz");
    let files = collect_npm_pack_files(&package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    let status = run_npm_compat(
        &project,
        &args(&[
            "install",
            "--package-lock-only",
            "--save-bundle",
            tarball.to_str().unwrap(),
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    let saved = package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .and_then(|dependencies| dependencies.get("bundled-tarball"))
        .and_then(serde_json::Value::as_str)
        .unwrap();
    assert!(saved.starts_with("file://"));
    assert_eq!(
        package_json
            .get("bundleDependencies")
            .and_then(serde_json::Value::as_array)
            .and_then(|entries| entries.first())
            .and_then(serde_json::Value::as_str),
        Some("bundled-tarball")
    );
    let package_lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(project.join("package-lock.json")).unwrap())
            .unwrap();
    assert_eq!(
        package_lock["packages"][""]["bundleDependencies"][0],
        "bundled-tarball"
    );

    let status = run_npm_compat(&project, &args(&["uninstall", "bundled-tarball"])).unwrap();
    assert_eq!(status, ExitCode::SUCCESS);
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_none_or(|dependencies| !dependencies.contains_key("bundled-tarball")));
    assert!(package_json
        .get("bundleDependencies")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|entries| entries
            .iter()
            .all(|entry| entry.as_str() != Some("bundled-tarball"))));

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(package);
}

#[test]
fn npm_install_save_location_defaults_update_package_json() {
    let project = test_dir("npm-install-save-location-default-project");
    let user_config = project.join("user.npmrc");
    let global_config = project.join("global.npmrc");
    fs::write(&user_config, "").unwrap();
    fs::write(&global_config, "").unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(project.join(".npmrc"), "save-dev=true\n").unwrap();

    let package = test_dir("npm-install-save-location-default-package");
    fs::write(
        package.join("package.json"),
        r#"{"name":"dev-default-tarball","version":"1.2.3"}"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 42;\n").unwrap();

    let tarball = project.join("dev-default-tarball-1.2.3.tgz");
    let files = collect_npm_pack_files(&package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    with_env_values(
        &[
            (
                "NPM_CONFIG_GLOBALCONFIG",
                Some(global_config.to_str().unwrap()),
            ),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_USERCONFIG", Some(user_config.to_str().unwrap())),
            ("npm_config_userconfig", None),
            ("NPM_CONFIG_SAVE", None),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_BUNDLE", None),
            ("npm_config_save_bundle", None),
        ],
        || {
            let status = run_npm_compat(
                &project,
                &args(&["install", "--package-lock-only", tarball.to_str().unwrap()]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
        },
    );

    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_none_or(|dependencies| !dependencies.contains_key("dev-default-tarball")));
    let saved = package_json
        .get("devDependencies")
        .and_then(serde_json::Value::as_object)
        .and_then(|dependencies| dependencies.get("dev-default-tarball"))
        .and_then(serde_json::Value::as_str)
        .unwrap();
    assert!(saved.starts_with("file://"));

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(package);
}

#[test]
fn npm_install_save_false_default_overrides_save_bundle() {
    let project = test_dir("npm-install-save-false-bundle-default-project");
    let user_config = project.join("user.npmrc");
    let global_config = project.join("global.npmrc");
    fs::write(&user_config, "").unwrap();
    fs::write(&global_config, "").unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(project.join(".npmrc"), "save=false\nsave-bundle=true\n").unwrap();

    let package = test_dir("npm-install-save-false-bundle-default-package");
    fs::write(
        package.join("package.json"),
        r#"{"name":"unsaved-bundle-default","version":"1.2.3"}"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 42;\n").unwrap();

    let tarball = project.join("unsaved-bundle-default-1.2.3.tgz");
    let files = collect_npm_pack_files(&package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    with_env_values(
        &[
            (
                "NPM_CONFIG_GLOBALCONFIG",
                Some(global_config.to_str().unwrap()),
            ),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_USERCONFIG", Some(user_config.to_str().unwrap())),
            ("npm_config_userconfig", None),
            ("NPM_CONFIG_SAVE", None),
            ("npm_config_save", None),
            ("NPM_CONFIG_SAVE_PROD", None),
            ("npm_config_save_prod", None),
            ("NPM_CONFIG_SAVE_DEV", None),
            ("npm_config_save_dev", None),
            ("NPM_CONFIG_SAVE_OPTIONAL", None),
            ("npm_config_save_optional", None),
            ("NPM_CONFIG_SAVE_PEER", None),
            ("npm_config_save_peer", None),
            ("NPM_CONFIG_SAVE_BUNDLE", None),
            ("npm_config_save_bundle", None),
        ],
        || {
            let status = run_npm_compat(
                &project,
                &args(&["install", "--package-lock-only", tarball.to_str().unwrap()]),
            )
            .unwrap();
            assert_eq!(status, ExitCode::SUCCESS);
        },
    );

    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        assert!(package_json
            .get(field)
            .and_then(serde_json::Value::as_object)
            .is_none_or(|dependencies| !dependencies.contains_key("unsaved-bundle-default")));
    }
    assert!(package_json
        .get("bundleDependencies")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|dependencies| dependencies
            .iter()
            .all(|dependency| dependency.as_str() != Some("unsaved-bundle-default"))));

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(package);
}

#[test]
fn npm_ci_bootstraps_omc_lock_from_package_lock() {
    let project = test_dir("npm-ci-bootstrap-package-lock-project");
    let package = test_dir("npm-ci-bootstrap-package-lock-package");
    fs::write(
        package.join("package.json"),
        r#"{"name":"local-tarball","version":"1.2.3"}"#,
    )
    .unwrap();
    fs::write(package.join("index.js"), "module.exports = 42;\n").unwrap();
    let tarball = project.join("local-tarball-1.2.3.tgz");
    let files = collect_npm_pack_files(&package).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();

    fs::write(
            project.join("package.json"),
            r#"{"name":"root","version":"1.0.0","dependencies":{"local-tarball":"file:local-tarball-1.2.3.tgz"}}"#,
        )
        .unwrap();
    fs::write(
        project.join("package-lock.json"),
        r#"{
                "name": "root",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": true,
                "packages": {
                    "": {
                        "name": "root",
                        "version": "1.0.0",
                        "dependencies": {
                            "local-tarball": "file:local-tarball-1.2.3.tgz"
                        }
                    },
                    "node_modules/local-tarball": {
                        "version": "1.2.3",
                        "resolved": "file:local-tarball-1.2.3.tgz"
                    }
                }
            }"#,
    )
    .unwrap();

    let status = run_npm_compat(&project, &args(&["ci"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("node_modules/local-tarball/index.js")).unwrap(),
        "module.exports = 42;\n"
    );
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "local-tarball"
            && package.version == "1.2.3"
            && package.source_url.starts_with("file://")));

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(package);
}

#[test]
fn npm_ci_validates_workspace_selection() {
    let project = test_dir("npm-ci-workspace-selection");
    fs::create_dir_all(project.join("packages/lib")).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#,
    )
    .unwrap();
    fs::write(
        project.join("packages/lib/package.json"),
        r#"{"name":"@demo/lib","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        project.join("package-lock.json"),
        r#"{
                "name": "root",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": true,
                "packages": {
                    "": {
                        "name": "root",
                        "version": "1.0.0",
                        "workspaces": ["packages/*"]
                    },
                    "packages/lib": {
                        "name": "@demo/lib",
                        "version": "1.0.0"
                    }
                }
            }"#,
    )
    .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["ci", "--workspace", "@demo/lib", "--dry-run"]),
    )
    .unwrap();
    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join("node_modules").exists());

    let error = run_npm_compat(
        &project,
        &args(&["ci", "--workspace", "@demo/missing", "--dry-run"]),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("npm workspace `@demo/missing` was not found"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_ci_package_lock_rehydrates_after_omit_bootstrap() {
    let project = test_dir("npm-ci-omit-dev-bootstrap-project");
    let prod = test_dir("npm-ci-omit-dev-bootstrap-prod");
    fs::write(
        prod.join("package.json"),
        r#"{"name":"prod-tarball","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(prod.join("index.js"), "module.exports = 'prod';\n").unwrap();
    let prod_tarball = project.join("prod-tarball-1.0.0.tgz");
    let files = collect_npm_pack_files(&prod).unwrap();
    write_npm_pack_tarball(&prod_tarball, &files).unwrap();

    let dev = test_dir("npm-ci-omit-dev-bootstrap-dev");
    fs::write(
        dev.join("package.json"),
        r#"{"name":"dev-tarball","version":"2.0.0"}"#,
    )
    .unwrap();
    fs::write(dev.join("index.js"), "module.exports = 'dev';\n").unwrap();
    let dev_tarball = project.join("dev-tarball-2.0.0.tgz");
    let files = collect_npm_pack_files(&dev).unwrap();
    write_npm_pack_tarball(&dev_tarball, &files).unwrap();

    fs::write(
            project.join("package.json"),
            r#"{"name":"root","version":"1.0.0","dependencies":{"prod-tarball":"file:prod-tarball-1.0.0.tgz"},"devDependencies":{"dev-tarball":"file:dev-tarball-2.0.0.tgz"}}"#,
        )
        .unwrap();
    fs::write(
        project.join("package-lock.json"),
        r#"{
                "name": "root",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": true,
                "packages": {
                    "": {
                        "name": "root",
                        "version": "1.0.0",
                        "dependencies": {
                            "prod-tarball": "file:prod-tarball-1.0.0.tgz"
                        },
                        "devDependencies": {
                            "dev-tarball": "file:dev-tarball-2.0.0.tgz"
                        }
                    },
                    "node_modules/prod-tarball": {
                        "version": "1.0.0",
                        "resolved": "file:prod-tarball-1.0.0.tgz"
                    },
                    "node_modules/dev-tarball": {
                        "version": "2.0.0",
                        "resolved": "file:dev-tarball-2.0.0.tgz",
                        "dev": true
                    }
                }
            }"#,
    )
    .unwrap();

    let status = run_npm_compat(&project, &args(&["ci", "--omit=dev"])).unwrap();
    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("node_modules/prod-tarball/index.js").exists());
    assert!(!project.join("node_modules/dev-tarball/index.js").exists());

    let status = run_npm_compat(&project, &args(&["ci"])).unwrap();
    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("node_modules/dev-tarball/index.js")).unwrap(),
        "module.exports = 'dev';\n"
    );
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "dev-tarball" && package.version == "2.0.0"));

    let _ = fs::remove_dir_all(project);
    let _ = fs::remove_dir_all(prod);
    let _ = fs::remove_dir_all(dev);
}

#[test]
fn npm_install_json_report_includes_npm_compatible_counts_and_omc_details() {
    let project = test_dir("npm-install-json-report-shape");
    let install = InstallReport {
        npm_packages: 2,
        pypi_packages: 1,
        local_source_artifacts: 1,
        npm_bins: 1,
        python_scripts: 1,
        node_modules: project.join("node_modules"),
        npm_bin_dir: project.join("node_modules/.bin"),
        python_site_packages: project.join(".omc/python/site-packages"),
        python_bin_dir: project.join(".omc/python/bin"),
    };

    let report = render::npm_install_json_report(
        &project,
        &[],
        Some(&install),
        true,
        false,
        &[PathBuf::from("../local-pkg")],
    );

    assert_eq!(report["added"], 2);
    assert_eq!(report["audited"], 0);
    assert_eq!(report["dryRun"], true);
    assert_eq!(report["lockOnly"], false);
    assert_eq!(report["omc"]["install"]["npm"], 2);
    assert_eq!(report["omc"]["install"]["pypi"], 1);
    assert_eq!(report["omc"]["install"]["localSourceArtifacts"], 1);
    assert_eq!(report["omc"]["install"]["npmBins"], 1);
    assert_eq!(report["omc"]["localPaths"][0]["path"], "../local-pkg");

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_install_json_dry_run_accepts_local_tarball_without_project_writes() {
    let project = test_dir("npm-install-json-dry-run-local-tarball");
    let tarball = write_npm_fixture_tarball(&project, "json-pkg", "1.0.0");

    let status = run_npm_compat(
        &project,
        &args(&["install", "--dry-run", "--json", tarball.to_str().unwrap()]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join("package-lock.json").exists());
    assert!(!project.join("node_modules").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_install_omit_preserves_omitted_packages_in_locks() {
    let project = test_dir("npm-install-omit-preserves-locks");
    write_npm_fixture_tarball(&project, "prod-pkg", "1.0.0");
    write_npm_fixture_tarball(&project, "dev-pkg", "2.0.0");
    write_npm_fixture_tarball(&project, "optional-pkg", "3.0.0");
    write_npm_fixture_tarball(&project, "peer-pkg", "4.0.0");
    fs::write(
        project.join("package.json"),
        r#"{
                "name": "root",
                "version": "1.0.0",
                "dependencies": { "prod-pkg": "file:prod-pkg-1.0.0.tgz" },
                "devDependencies": { "dev-pkg": "file:dev-pkg-2.0.0.tgz" },
                "optionalDependencies": { "optional-pkg": "file:optional-pkg-3.0.0.tgz" },
                "peerDependencies": { "peer-pkg": "file:peer-pkg-4.0.0.tgz" }
            }"#,
    )
    .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["install", "--omit=dev", "--no-optional", "--omit=peer"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("node_modules/prod-pkg/index.js").exists());
    assert!(!project.join("node_modules/dev-pkg/index.js").exists());
    assert!(!project.join("node_modules/optional-pkg/index.js").exists());
    assert!(!project.join("node_modules/peer-pkg/index.js").exists());

    let package_lock = read_npm_pkg_json(&project.join("package-lock.json")).unwrap();
    let packages = package_lock
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    for name in ["prod-pkg", "dev-pkg", "optional-pkg", "peer-pkg"] {
        assert!(packages.contains_key(&format!("node_modules/{name}")));
    }
    assert_eq!(packages["node_modules/dev-pkg"]["dev"], true);
    assert_eq!(packages["node_modules/optional-pkg"]["optional"], true);
    assert_eq!(packages["node_modules/peer-pkg"]["peer"], true);

    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    for name in ["prod-pkg", "dev-pkg", "optional-pkg", "peer-pkg"] {
        assert!(lock.packages.iter().any(|package| package.name == name));
    }

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_package_lock_only_omit_keeps_omitted_packages_in_lock() {
    let project = test_dir("npm-lock-only-omit-preserves-lock");
    write_npm_fixture_tarball(&project, "prod-pkg", "1.0.0");
    write_npm_fixture_tarball(&project, "dev-pkg", "2.0.0");
    fs::write(
        project.join("package.json"),
        r#"{
                "name": "root",
                "version": "1.0.0",
                "dependencies": { "prod-pkg": "file:prod-pkg-1.0.0.tgz" },
                "devDependencies": { "dev-pkg": "file:dev-pkg-2.0.0.tgz" }
            }"#,
    )
    .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["install", "--package-lock-only", "--omit=dev"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("node_modules").exists());
    let package_lock = read_npm_pkg_json(&project.join("package-lock.json")).unwrap();
    let packages = package_lock
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert!(packages.contains_key("node_modules/prod-pkg"));
    assert!(packages.contains_key("node_modules/dev-pkg"));
    assert_eq!(packages["node_modules/dev-pkg"]["dev"], true);

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_install_package_lock_false_skips_package_lock_file() {
    let project = test_dir("npm-install-package-lock-false");
    write_npm_fixture_tarball(&project, "prod-pkg", "1.0.0");
    fs::write(
        project.join("package.json"),
        r#"{
                "name": "root",
                "version": "1.0.0",
                "dependencies": { "prod-pkg": "file:prod-pkg-1.0.0.tgz" }
            }"#,
    )
    .unwrap();

    let status = run_npm_compat(&project, &args(&["install", "--package-lock=false"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("node_modules/prod-pkg/index.js").exists());
    assert!(project.join("omc.lock").exists());
    assert!(!project.join("package-lock.json").exists());

    let status = run_npm_compat(
        &project,
        &args(&["install", "--package-lock-only", "--package-lock=false"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("package-lock.json").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_install_prefix_uses_selected_project_directory() {
    let project = test_dir("npm-install-prefix-project");
    let workspace = project.join("packages").join("app");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        workspace.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();
    write_npm_fixture_tarball(&project, "prod-pkg", "1.0.0");

    let status = run_npm_compat(
        &project,
        &args(&[
            "install",
            "--prefix",
            "packages/app",
            "./prod-pkg-1.0.0.tgz",
        ]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let package_json = read_npm_pkg_json(&workspace.join("package.json")).unwrap();
    let saved = package_json["dependencies"]["prod-pkg"].as_str().unwrap();
    assert!(saved.starts_with("file:"));
    assert!(saved.ends_with("prod-pkg-1.0.0.tgz"));
    assert!(workspace.join("node_modules/prod-pkg/index.js").exists());
    assert!(workspace.join("package-lock.json").exists());
    assert!(workspace.join("omc.lock").exists());
    assert!(!project.join("node_modules").exists());
    assert!(!project.join("package-lock.json").exists());
    assert!(!project.join("omc.lock").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_install_no_save_skips_package_lock_file() {
    with_clean_npm_env(|| {
        let project = test_dir("npm-install-no-save-skips-package-lock");
        let tarball = write_npm_fixture_tarball(&project, "prod-pkg", "1.0.0");
        fs::write(
            project.join("package.json"),
            r#"{
                "name": "root",
                "version": "1.0.0"
            }"#,
        )
        .unwrap();

        let status = run_npm_compat(
            &project,
            &args(&["install", tarball.to_str().unwrap(), "--no-save"]),
        )
        .unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        assert!(project.join("node_modules/prod-pkg/index.js").exists());
        assert!(!project.join("package-lock.json").exists());
        let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
        assert!(package_json
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|dependencies| !dependencies.contains_key("prod-pkg")));

        let _ = fs::remove_dir_all(project);

        let project = test_dir("npm-install-save-false-lock-only");
        let tarball = write_npm_fixture_tarball(&project, "prod-pkg", "1.0.0");
        fs::write(
            project.join("package.json"),
            r#"{
                "name": "root",
                "version": "1.0.0"
            }"#,
        )
        .unwrap();

        let status = run_npm_compat(
            &project,
            &args(&[
                "install",
                tarball.to_str().unwrap(),
                "--save=false",
                "--package-lock-only",
            ]),
        )
        .unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        assert!(!project.join("node_modules").exists());
        assert!(!project.join("package-lock.json").exists());

        let _ = fs::remove_dir_all(project);
    });
}

#[test]
fn npm_no_save_specs_reuse_existing_manifest_requirements() {
    let project = test_dir("npm-no-save-existing-manifest-requirements");
    fs::write(
        project.join("package.json"),
        r#"{
                "name": "root",
                "version": "1.0.0",
                "dependencies": { "left-pad": "1.1.3" },
                "devDependencies": { "@scope/tool": "^2.0.0" }
            }"#,
    )
    .unwrap();

    let package_dirs = vec![project.clone()];
    let specs = npm_specs_with_existing_manifest_requirements(
        &package_dirs,
        vec![
            "left-pad".to_owned(),
            "@scope/tool".to_owned(),
            "new-pkg".to_owned(),
            "left-pad@1.3.0".to_owned(),
        ],
    )
    .unwrap();

    assert_eq!(
        specs,
        vec![
            "left-pad@1.1.3",
            "@scope/tool@^2.0.0",
            "new-pkg",
            "left-pad@1.3.0",
        ]
    );

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_updates_root_package_json_dependencies() {
    let project = test_dir("npm-remove-root-package-json-project");
    fs::write(
            project.join("package.json"),
            r#"{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"},"devDependencies":{"is-odd":"3.0.1"},"optionalDependencies":{"fsevents":"2.0.0"},"peerDependencies":{"react":"18.0.0"}}"#,
        )
        .unwrap();
    fs::write(
            project.join("package-lock.json"),
            r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"},"devDependencies":{"is-odd":"3.0.1"},"optionalDependencies":{"fsevents":"2.0.0"},"peerDependencies":{"react":"18.0.0"}},"node_modules/left-pad":{"version":"1.3.0"},"node_modules/is-odd":{"version":"3.0.1"},"node_modules/fsevents":{"version":"2.0.0"},"node_modules/react":{"version":"18.0.0"}}}"#,
        )
        .unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["remove", "left-pad", "is-odd", "fsevents", "react"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    for (field, name) in [
        ("dependencies", "left-pad"),
        ("devDependencies", "is-odd"),
        ("optionalDependencies", "fsevents"),
        ("peerDependencies", "react"),
    ] {
        assert!(package_json
            .get(field)
            .and_then(serde_json::Value::as_object)
            .is_none_or(|dependencies| !dependencies.contains_key(name)));
    }

    let manifest = read_manifest(project.join("omc.toml")).unwrap();
    assert!(manifest.dependencies.is_empty());
    assert!(manifest.dev_dependencies.is_empty());
    assert!(manifest.optional_dependencies.is_empty());
    assert!(manifest.peer_dependencies.is_empty());
    let package_lock = read_npm_pkg_json(&project.join("package-lock.json")).unwrap();
    let lock_packages = package_lock
        .get("packages")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert!(lock_packages
        .get("")
        .and_then(|root| root.get("dependencies"))
        .is_none());
    for path in [
        "node_modules/left-pad",
        "node_modules/is-odd",
        "node_modules/fsevents",
        "node_modules/react",
    ] {
        assert!(!lock_packages.contains_key(path));
    }

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_prunes_saved_local_directory_links() {
    let project = test_dir("npm-remove-local-directory-link-project");
    let local_package = project.join("pkg");
    fs::create_dir_all(&local_package).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        local_package.join("package.json"),
        r#"{"name":"local-pkg","version":"1.0.0","main":"index.js","bin":{"local-tool":"cli.js"}}"#,
    )
    .unwrap();
    fs::write(local_package.join("index.js"), "module.exports = 61;\n").unwrap();
    fs::write(local_package.join("cli.js"), "#!/usr/bin/env node\n").unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["install", "--package-lock=false", "./pkg"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("node_modules/local-pkg").exists());
    assert!(project.join("node_modules/.bin/local-tool").exists());
    let manifest = read_manifest(project.join("omc.toml")).unwrap();
    assert_eq!(
        manifest.npm_local_paths,
        vec![project.join("./pkg").display().to_string()]
    );
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert_eq!(
        package_json["dependencies"]["local-pkg"],
        format!(
            "file:{}",
            fs::canonicalize(&local_package).unwrap().display()
        )
    );

    let status = run_npm_compat(
        &project,
        &args(&["uninstall", "--package-lock=false", "local-pkg"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("node_modules/local-pkg").exists());
    assert!(!project.join("node_modules/.bin/local-tool").exists());
    let manifest = read_manifest(project.join("omc.toml")).unwrap();
    assert!(manifest.npm_local_paths.is_empty());
    assert!(manifest.npm_dev_local_paths.is_empty());
    assert!(manifest.npm_optional_local_paths.is_empty());
    assert!(manifest.npm_peer_local_paths.is_empty());
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert!(package_json
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .is_none_or(|dependencies| !dependencies.contains_key("local-pkg")));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_skips_missing_packages_like_npm() {
    let project = test_dir("npm-remove-missing-package");
    let package_json = r#"{"name":"root","version":"1.0.0"}"#;
    fs::write(project.join("package.json"), package_json).unwrap();

    let status =
        run_npm_compat(&project, &args(&["uninstall", "definitely-not-installed"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(project.join("package.json")).unwrap(),
        package_json
    );
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());
    assert!(!project.join(".omc").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_no_save_only_updates_install_state() {
    let project = test_dir("npm-remove-no-save-project");
    for package in ["is-odd", "is-number"] {
        fs::create_dir_all(project.join("node_modules").join(package)).unwrap();
        fs::write(
            project.join("node_modules").join(package).join("index.js"),
            "module.exports = 42;\n",
        )
        .unwrap();
    }
    fs::write(
        project.join("package.json"),
        r#"{"name":"root","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}"#,
    )
    .unwrap();
    fs::write(
            project.join("package-lock.json"),
            r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}},"node_modules/is-odd":{"version":"3.0.1","dependencies":{"is-number":"^6.0.0"}},"node_modules/is-number":{"version":"6.0.0"}}}"#,
        )
        .unwrap();
    fs::write(
        project.join("omc.lock"),
        r#"version = 1

[[packages]]
ecosystem = "npm"
name = "is-odd"
version = "3.0.1"
source_url = ""
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"
dependencies = ["npm:is-number@^6.0.0"]

[[packages]]
ecosystem = "npm"
name = "is-number"
version = "6.0.0"
source_url = ""
archive = ""
artifact = ""
sha256 = ""
behavior = "pure"
verdict = "accepted"
"#,
    )
    .unwrap();

    let status = run_npm_compat(&project, &args(&["uninstall", "--no-save", "is-odd"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("node_modules").join("is-odd").exists());
    assert!(!project.join("node_modules").join("is-number").exists());
    let package_json = read_npm_pkg_json(&project.join("package.json")).unwrap();
    assert_eq!(package_json["dependencies"]["is-odd"], "3.0.1");
    let package_lock = fs::read_to_string(project.join("package-lock.json")).unwrap();
    assert!(package_lock.contains("node_modules/is-odd"));
    assert!(package_lock.contains("node_modules/is-number"));
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert!(lock.packages.iter().any(|package| package.name == "is-odd"));
    assert!(lock
        .packages
        .iter()
        .any(|package| package.name == "is-number"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_no_save_uses_package_lock_dependency_graph_without_omc_lock() {
    let project = test_dir("npm-remove-no-save-package-lock-deps-project");
    for package in ["is-odd", "is-number"] {
        fs::create_dir_all(project.join("node_modules").join(package)).unwrap();
        fs::write(
            project.join("node_modules").join(package).join("index.js"),
            "module.exports = 42;\n",
        )
        .unwrap();
    }
    let package_json = r#"{"name":"root","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}"#;
    let package_lock = r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}},"node_modules/is-odd":{"version":"3.0.1","dependencies":{"is-number":"^6.0.0"}},"node_modules/is-number":{"version":"6.0.0"}}}"#;
    fs::write(project.join("package.json"), package_json).unwrap();
    fs::write(project.join("package-lock.json"), package_lock).unwrap();

    let status = run_npm_compat(&project, &args(&["uninstall", "--no-save", "is-odd"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("node_modules").join("is-odd").exists());
    assert!(!project.join("node_modules").join("is-number").exists());
    assert_eq!(
        fs::read_to_string(project.join("package.json")).unwrap(),
        package_json
    );
    assert_eq!(
        fs::read_to_string(project.join("package-lock.json")).unwrap(),
        package_lock
    );
    assert!(!project.join("omc.lock").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_no_save_keeps_transitive_dependency_declared_by_manifest() {
    let project = test_dir("npm-remove-no-save-keeps-declared-transitive-project");
    for package in ["is-odd", "is-number"] {
        fs::create_dir_all(project.join("node_modules").join(package)).unwrap();
        fs::write(
            project.join("node_modules").join(package).join("index.js"),
            "module.exports = 42;\n",
        )
        .unwrap();
    }
    let package_json = r#"{"name":"root","version":"1.0.0","dependencies":{"is-odd":"3.0.1","is-number":"6.0.0"}}"#;
    let package_lock = r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","dependencies":{"is-odd":"3.0.1","is-number":"6.0.0"}},"node_modules/is-odd":{"version":"3.0.1","dependencies":{"is-number":"^6.0.0"}},"node_modules/is-number":{"version":"6.0.0"}}}"#;
    fs::write(project.join("package.json"), package_json).unwrap();
    fs::write(project.join("package-lock.json"), package_lock).unwrap();

    let status = run_npm_compat(&project, &args(&["uninstall", "--no-save", "is-odd"])).unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(!project.join("node_modules").join("is-odd").exists());
    assert!(project.join("node_modules").join("is-number").exists());
    assert_eq!(
        fs::read_to_string(project.join("package.json")).unwrap(),
        package_json
    );
    assert_eq!(
        fs::read_to_string(project.join("package-lock.json")).unwrap(),
        package_lock
    );
    assert!(!project.join("omc.lock").exists());

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_remove_no_save_package_lock_only_is_noop_like_npm() {
    let project = test_dir("npm-remove-no-save-package-lock-only-project");
    fs::create_dir_all(project.join("node_modules").join("left-pad")).unwrap();
    fs::write(
        project
            .join("node_modules")
            .join("left-pad")
            .join("index.js"),
        "module.exports = 42;\n",
    )
    .unwrap();
    let package_json = r#"{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#;
    let package_lock = r#"{"name":"root","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}"#;
    fs::write(project.join("package.json"), package_json).unwrap();
    fs::write(project.join("package-lock.json"), package_lock).unwrap();

    let status = run_npm_compat(
        &project,
        &args(&["uninstall", "--no-save", "--package-lock-only", "left-pad"]),
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(project.join("node_modules").join("left-pad").exists());
    assert_eq!(
        fs::read_to_string(project.join("package.json")).unwrap(),
        package_json
    );
    assert_eq!(
        fs::read_to_string(project.join("package-lock.json")).unwrap(),
        package_lock
    );
    assert!(!project.join("omc.toml").exists());
    assert!(!project.join("omc.lock").exists());

    let _ = fs::remove_dir_all(project);
}
