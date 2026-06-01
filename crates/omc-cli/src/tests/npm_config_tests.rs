use super::*;
use crate::*;

#[test]
fn npm_config_file_defaults_behave_like_global_config_flags() {
    let project = test_dir("npm-config-file-defaults");
    let user_config = project.join("user.npmrc");
    let global_config = project.join("global.npmrc");
    fs::write(
        &global_config,
        "production=true\nomit=optional\nsave-prefix=~\n",
    )
    .unwrap();
    fs::write(
        &user_config,
        "include=optional\nsave=false\nsave-exact=true\n",
    )
    .unwrap();
    fs::write(
            project.join(".npmrc"),
            "omit=dev,peer\ninclude=peer\nglobal=true\ndry-run=true\npackage-lock-only=true\nengine-strict=true\noffline=true\nmin-release-age=7\n",
        )
        .unwrap();

    with_env_values(
        &[
            ("NODE_ENV", None),
            (
                "NPM_CONFIG_GLOBALCONFIG",
                Some(global_config.to_str().unwrap()),
            ),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_USERCONFIG", Some(user_config.to_str().unwrap())),
            ("npm_config_userconfig", None),
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
                npm_args_with_config_defaults(&project, &args(&["install", "left-pad"])).unwrap(),
                args(&[
                    "--omit=dev",
                    "--include=dev,optional,peer",
                    "--omit=dev,peer",
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
                    "install",
                    "left-pad",
                ])
            );
            let action = parse_npm_compat_action(
                &npm_args_with_config_defaults(
                    &project,
                    &args(&[
                        "install",
                        "--global=false",
                        "--dry-run=false",
                        "--package-lock-only=false",
                        "--save",
                        "--save-exact=false",
                        "--include=dev",
                        "left-pad",
                    ]),
                )
                .unwrap(),
            )
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
                npm_engine_strict,
                npm_offline,
                ..
            } = action
            else {
                panic!("expected npm install action");
            };
            assert!(!omit_dev);
            assert!(!omit_optional);
            assert!(!omit_peer);
            assert!(!global);
            assert!(save);
            assert!(!lock_only);
            assert!(!dry_run);
            assert_eq!(save_prefix, DEFAULT_NPM_SAVE_PREFIX);
            assert!(npm_engine_strict);
            assert!(npm_offline);
        },
    );
}

#[test]
fn npm_config_file_defaults_support_only_and_also() {
    let project = test_dir("npm-config-file-only-also-default");
    let user_config = project.join("user.npmrc");
    let global_config = project.join("global.npmrc");
    fs::write(&user_config, "also=dev\n").unwrap();
    fs::write(&global_config, "").unwrap();
    fs::write(project.join(".npmrc"), "only=prod\n").unwrap();

    with_env_values(
        &[
            ("NODE_ENV", None),
            (
                "NPM_CONFIG_GLOBALCONFIG",
                Some(global_config.to_str().unwrap()),
            ),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_USERCONFIG", Some(user_config.to_str().unwrap())),
            ("npm_config_userconfig", None),
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
                npm_args_with_config_defaults(&project, &args(&["ci"])).unwrap(),
                args(&["--omit=dev", "--include=dev", "ci"])
            );
            let action = parse_npm_compat_action(
                &npm_args_with_config_defaults(&project, &args(&["ci"])).unwrap(),
            )
            .unwrap();
            let NpmCompatAction::Ci { omit_dev, .. } = action else {
                panic!("expected npm ci action");
            };
            assert!(!omit_dev);
        },
    );

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_config_file_defaults_support_optional_omit() {
    let project = test_dir("npm-config-file-optional-default");
    let user_config = project.join("user.npmrc");
    let global_config = project.join("global.npmrc");
    fs::write(&user_config, "").unwrap();
    fs::write(&global_config, "").unwrap();
    fs::write(project.join(".npmrc"), "optional=false\n").unwrap();

    with_env_values(
        &[
            ("NODE_ENV", None),
            (
                "NPM_CONFIG_GLOBALCONFIG",
                Some(global_config.to_str().unwrap()),
            ),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_USERCONFIG", Some(user_config.to_str().unwrap())),
            ("npm_config_userconfig", None),
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
                npm_args_with_config_defaults(&project, &args(&["install", "left-pad"])).unwrap(),
                args(&["--omit=optional", "install", "left-pad"])
            );
            let action = parse_npm_compat_action(
                &npm_args_with_config_defaults(&project, &args(&["install", "left-pad"])).unwrap(),
            )
            .unwrap();
            let NpmCompatAction::Install { omit_optional, .. } = action else {
                panic!("expected npm install action");
            };
            assert!(omit_optional);
        },
    );

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_config_file_defaults_support_save_bundle() {
    let project = test_dir("npm-config-file-save-bundle-default");
    let user_config = project.join("user.npmrc");
    let global_config = project.join("global.npmrc");
    fs::write(&user_config, "").unwrap();
    fs::write(&global_config, "").unwrap();
    fs::write(project.join(".npmrc"), "save-bundle=true\n").unwrap();

    with_env_values(
        &[
            ("NODE_ENV", None),
            (
                "NPM_CONFIG_GLOBALCONFIG",
                Some(global_config.to_str().unwrap()),
            ),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_USERCONFIG", Some(user_config.to_str().unwrap())),
            ("npm_config_userconfig", None),
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
                npm_args_with_config_defaults(&project, &args(&["install", "left-pad"])).unwrap(),
                args(&["--save-bundle", "install", "left-pad"])
            );
            let action = parse_npm_compat_action(
                &npm_args_with_config_defaults(&project, &args(&["install", "left-pad"])).unwrap(),
            )
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

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_config_file_defaults_support_save_locations() {
    let project = test_dir("npm-config-file-save-location-default");
    let user_config = project.join("user.npmrc");
    let global_config = project.join("global.npmrc");
    fs::write(&user_config, "").unwrap();
    fs::write(&global_config, "").unwrap();
    fs::write(project.join(".npmrc"), "save-dev=true\n").unwrap();

    with_env_values(
        &[
            ("NODE_ENV", None),
            (
                "NPM_CONFIG_GLOBALCONFIG",
                Some(global_config.to_str().unwrap()),
            ),
            ("npm_config_globalconfig", None),
            ("NPM_CONFIG_USERCONFIG", Some(user_config.to_str().unwrap())),
            ("npm_config_userconfig", None),
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
                npm_args_with_config_defaults(&project, &args(&["install", "left-pad"])).unwrap(),
                args(&["--save-dev", "install", "left-pad"])
            );
            let action = parse_npm_compat_action(
                &npm_args_with_config_defaults(&project, &args(&["install", "left-pad"])).unwrap(),
            )
            .unwrap();
            let NpmCompatAction::Install {
                save,
                dependency_kind,
                ..
            } = action
            else {
                panic!("expected npm install action");
            };
            assert!(save);
            assert_eq!(dependency_kind, ManifestDependencyKind::Dev);
        },
    );

    let _ = fs::remove_dir_all(project);
}

#[test]
fn npm_cache_dir_prefers_cli_then_env_like_npm() {
    let cwd = test_dir("npm-cache-env-cwd");
    with_env_values(
        &[
            ("NPM_CONFIG_CACHE", Some("upper-cache")),
            ("npm_config_cache", Some("lower-cache")),
        ],
        || {
            assert_eq!(
                npm_cache_arg_or_env(&cwd, None).unwrap(),
                cwd.join("upper-cache")
            );
            assert_eq!(
                npm_cache_arg_or_env(&cwd, Some(PathBuf::from("cli-cache"))).unwrap(),
                cwd.join("cli-cache")
            );
        },
    );
}

#[test]
fn npm_cache_remove_missing_pattern_preserves_cache_like_npm() {
    let project = test_dir("npm-cache-remove-missing");
    let cache_file = npm_cache_dir(&project)
        .join("content")
        .join("left-pad-1.3.0.tgz");
    fs::create_dir_all(cache_file.parent().unwrap()).unwrap();
    fs::write(&cache_file, b"tarball").unwrap();

    assert_eq!(
        remove_npm_cache_entries(&npm_cache_dir(&project), "definitely-not-a-cache-hit").unwrap(),
        0
    );
    assert!(cache_file.exists());
    assert_eq!(
        remove_npm_cache_entries(&npm_cache_dir(&project), "left-pad").unwrap(),
        1
    );
    assert!(!cache_file.exists());
}

#[test]
fn writes_npm_config_set_and_delete() {
    let dir = test_dir("npm-config-set-delete");
    fs::write(
        dir.join(".npmrc"),
        "registry=https://old.example.invalid/npm\n# keep this\nlegacy-peer-deps=true\n",
    )
    .unwrap();

    print_npm_config(
        &dir,
        NpmConfigAction::Set {
            assignments: vec![
                (
                    "registry".to_owned(),
                    "https://new.example.invalid/npm".to_owned(),
                ),
                (
                    "@scope:registry".to_owned(),
                    "https://scope.example.invalid/npm".to_owned(),
                ),
            ],
            location: NpmConfigLocation::Project,
        },
        None,
        None,
        None,
    )
    .unwrap();

    let config = fs::read_to_string(dir.join(".npmrc")).unwrap();
    assert!(config.contains("registry=https://new.example.invalid/npm\n"));
    assert!(config.contains("# keep this\n"));
    assert!(config.contains("@scope:registry=https://scope.example.invalid/npm\n"));
    let values = npm_config_values(
        &dir,
        None,
        Some(Path::new("empty-user.npmrc")),
        Some(Path::new("empty-global.npmrc")),
        NpmConfigLocation::Project,
    )
    .unwrap();
    assert_eq!(
        values.get("registry").map(String::as_str),
        Some("https://new.example.invalid/npm/")
    );
    assert_eq!(
        values.get("@scope:registry").map(String::as_str),
        Some("https://scope.example.invalid/npm/")
    );

    print_npm_config(
        &dir,
        NpmConfigAction::Delete {
            keys: vec!["registry".to_owned()],
            location: NpmConfigLocation::Project,
        },
        None,
        None,
        None,
    )
    .unwrap();
    let config = fs::read_to_string(dir.join(".npmrc")).unwrap();
    assert!(!config.contains("registry=https://new.example.invalid/npm\n"));
    assert!(config.contains("@scope:registry=https://scope.example.invalid/npm\n"));

    print_npm_config(
        &dir,
        NpmConfigAction::Set {
            assignments: vec![(
                "registry".to_owned(),
                "https://ci.example.invalid".to_owned(),
            )],
            location: NpmConfigLocation::User,
        },
        None,
        Some(Path::new("ci.npmrc")),
        None,
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(dir.join("ci.npmrc")).unwrap(),
        "registry=https://ci.example.invalid\n"
    );

    print_npm_config(
        &dir,
        NpmConfigAction::Set {
            assignments: vec![(
                "registry".to_owned(),
                "https://global.example.invalid/npm".to_owned(),
            )],
            location: NpmConfigLocation::Global,
        },
        None,
        None,
        Some(Path::new("global.npmrc")),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(dir.join("global.npmrc")).unwrap(),
        "registry=https://global.example.invalid/npm\n"
    );

    print_npm_config(
        &dir,
        NpmConfigAction::Delete {
            keys: vec!["registry".to_owned()],
            location: NpmConfigLocation::Global,
        },
        None,
        None,
        Some(Path::new("global.npmrc")),
    )
    .unwrap();
    assert!(!fs::read_to_string(dir.join("global.npmrc"))
        .unwrap()
        .contains("registry=https://global.example.invalid/npm\n"));
}

#[test]
fn npm_config_values_include_npmrc_defaults() {
    let dir = test_dir("npm-config-values-npmrc");
    fs::write(
        dir.join("global.npmrc"),
        "save-prefix=~\nregistry=https://global.example.invalid/npm\n",
    )
    .unwrap();
    fs::write(
            dir.join("user.npmrc"),
            "save-exact=true\nmin-release-age=7\nallow-git=none\n//registry.example.invalid/:_authToken=secret\n",
        )
        .unwrap();
    fs::write(
            dir.join(".npmrc"),
            "registry=https://project.example.invalid/npm\n@scope:registry=https://scope.example.invalid/npm\nignore-scripts=false\n",
        )
        .unwrap();

    let values = npm_config_values(
        &dir,
        None,
        Some(Path::new("user.npmrc")),
        Some(Path::new("global.npmrc")),
        NpmConfigLocation::User,
    )
    .unwrap();

    assert_eq!(values.get("save-prefix").map(String::as_str), Some("~"));
    assert_eq!(values.get("save-exact").map(String::as_str), Some("true"));
    assert_eq!(values.get("min-release-age").map(String::as_str), Some("7"));
    assert_eq!(values.get("allow-git").map(String::as_str), Some("none"));
    assert_eq!(
        values.get("ignore-scripts").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        values.get("registry").map(String::as_str),
        Some("https://project.example.invalid/npm/")
    );
    assert_eq!(
        values.get("@scope:registry").map(String::as_str),
        Some("https://scope.example.invalid/npm/")
    );
    assert!(!values.contains_key("//registry.example.invalid/:_authToken"));

    let global_values = npm_config_values(
        &dir,
        None,
        Some(Path::new("user.npmrc")),
        Some(Path::new("global.npmrc")),
        NpmConfigLocation::Global,
    )
    .unwrap();
    assert_eq!(
        global_values.get("save-prefix").map(String::as_str),
        Some("~")
    );
    assert!(!global_values.contains_key("save-exact"));

    with_env_values(
        &[
            (
                "NPM_CONFIG_REGISTRY",
                Some("https://env.example.invalid/npm"),
            ),
            ("npm_config_registry", None),
            ("NPM_CONFIG_SAVE_EXACT", Some("false")),
            ("npm_config_save_exact", None),
            ("NPM_CONFIG_MIN_RELEASE_AGE", None),
            ("npm_config_min_release_age", Some("0")),
            ("NPM_CONFIG_IGNORE_SCRIPTS", None),
            ("npm_config_ignore_scripts", Some("true")),
            ("NPM_CONFIG__AUTHTOKEN", None),
            ("npm_config__authToken", Some("secret")),
        ],
        || {
            let env_values = npm_config_values(
                &dir,
                None,
                Some(Path::new("user.npmrc")),
                Some(Path::new("global.npmrc")),
                NpmConfigLocation::User,
            )
            .unwrap();

            assert_eq!(
                env_values.get("registry").map(String::as_str),
                Some("https://env.example.invalid/npm/")
            );
            assert_eq!(
                env_values.get("save-exact").map(String::as_str),
                Some("false")
            );
            assert_eq!(
                env_values.get("min-release-age").map(String::as_str),
                Some("0")
            );
            assert_eq!(
                env_values.get("ignore-scripts").map(String::as_str),
                Some("true")
            );
            assert!(!env_values.keys().any(|key| key.contains("authtoken")));
        },
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn logs_in_npm_registry_credentials_to_config() {
    let dir = test_dir("npm-login");
    fs::write(
            dir.join("ci.npmrc"),
            "registry=https://registry.example.invalid/npm\n//scope.example.invalid/npm/:_authToken=old-scope-token\nkeep=true\n",
        )
        .unwrap();

    print_npm_login(
        &dir,
        NpmLoginAction {
            scope: Some("demo".to_owned()),
            json: true,
            npm_registry: Some("https://scope.example.invalid/npm".to_owned()),
            userconfig: Some(PathBuf::from("ci.npmrc")),
            token: Some("scope-token".to_owned()),
        },
    )
    .unwrap();

    let config = fs::read_to_string(dir.join("ci.npmrc")).unwrap();
    assert!(config.contains("@demo:registry=https://scope.example.invalid/npm/\n"));
    assert!(config.contains("//scope.example.invalid/npm/:_authToken=scope-token\n"));
    assert!(!config.contains("old-scope-token"));
    assert!(config.contains("registry=https://registry.example.invalid/npm\n"));
    assert!(config.contains("keep=true\n"));

    print_npm_login(
        &dir,
        NpmLoginAction {
            scope: None,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: Some(PathBuf::from("ci.npmrc")),
            token: Some("registry-token".to_owned()),
        },
    )
    .unwrap();
    let config = fs::read_to_string(dir.join("ci.npmrc")).unwrap();
    assert!(config.contains("//registry.example.invalid/npm/:_authToken=registry-token\n"));
    assert!(config.contains("//scope.example.invalid/npm/:_authToken=scope-token\n"));
    assert!(config.contains("keep=true\n"));
}

#[test]
fn logs_out_npm_registry_credentials_from_config() {
    let dir = test_dir("npm-logout");
    fs::write(
            dir.join("ci.npmrc"),
            "registry=https://registry.example.invalid/npm\n@demo:registry=https://scope.example.invalid/npm\n//registry.example.invalid/npm/:_authToken=registry-token\n//scope.example.invalid/npm/:_authToken=scope-token\n//scope.example.invalid/npm/:username=alice\n_authToken=legacy-token\nkeep=true\n",
        )
        .unwrap();

    print_npm_logout(
        &dir,
        NpmLogoutAction {
            scope: Some("demo".to_owned()),
            json: true,
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
        },
    )
    .unwrap();

    let config = fs::read_to_string(dir.join("ci.npmrc")).unwrap();
    assert!(!config.contains("@demo:registry="));
    assert!(!config.contains("scope-token"));
    assert!(!config.contains(":username=alice"));
    assert!(config.contains("_authToken=legacy-token"));
    assert!(config.contains("registry=https://registry.example.invalid/npm\n"));
    assert!(config.contains("registry-token"));
    assert!(config.contains("keep=true\n"));

    print_npm_logout(
        &dir,
        NpmLogoutAction {
            scope: None,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: Some(PathBuf::from("ci.npmrc")),
        },
    )
    .unwrap();
    let config = fs::read_to_string(dir.join("ci.npmrc")).unwrap();
    assert!(!config.contains("registry-token"));
    assert!(!config.contains("_authToken=legacy-token"));
    assert!(config.contains("keep=true\n"));
}

#[test]
fn direct_npm_config_resolves_config_paths_from_invocation_cwd() {
    let project = test_dir("direct-npm-config-path-project");
    let invocation_cwd = project.join("work/release");
    fs::create_dir_all(&invocation_cwd).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "config",
            "set",
            "registry",
            "https://nested-userconfig.example/npm",
            "--userconfig",
            "ci.npmrc",
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let user_config = invocation_cwd.join("ci.npmrc");
    assert!(fs::read_to_string(&user_config)
        .unwrap()
        .contains("registry=https://nested-userconfig.example/npm"));
    assert!(!project.join("ci.npmrc").exists());

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "config",
            "set",
            "registry",
            "https://nested-globalconfig.example/npm",
            "--location",
            "global",
            "--globalconfig",
            "global.npmrc",
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(fs::read_to_string(invocation_cwd.join("global.npmrc"))
        .unwrap()
        .contains("registry=https://nested-globalconfig.example/npm"));
    assert!(!project.join("global.npmrc").exists());
}

#[test]
fn direct_npm_config_edit_runs_editor_for_selected_config() {
    let project = test_dir("direct-npm-config-edit-project");
    let invocation_cwd = project.join("work/release");
    fs::create_dir_all(&invocation_cwd).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();
    let editor_script = invocation_cwd.join("edit-npm-config.sh");
    fs::write(
        &editor_script,
        "#!/bin/sh\nprintf 'registry=https://edited-npm.example/npm\\n' > \"$1\"\n",
    )
    .unwrap();
    let editor = format!("sh {}", editor_script.display());

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "config",
            "edit",
            "--location=project",
            "--editor",
            editor.as_str(),
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    assert!(fs::read_to_string(project.join(".npmrc"))
        .unwrap()
        .contains("registry=https://edited-npm.example/npm\n"));
    assert!(!invocation_cwd.join(".npmrc").exists());
}

#[test]
fn direct_npm_set_resolves_userconfig_from_invocation_cwd() {
    let project = test_dir("direct-npm-set-userconfig-project");
    let invocation_cwd = project.join("work/release");
    fs::create_dir_all(&invocation_cwd).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "set",
            "registry",
            "https://top-level-set.example/npm",
            "--userconfig",
            "ci.npmrc",
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let user_config = invocation_cwd.join("ci.npmrc");
    assert!(fs::read_to_string(&user_config)
        .unwrap()
        .contains("registry=https://top-level-set.example/npm"));
    assert!(!project.join("ci.npmrc").exists());
}

#[test]
fn direct_npm_login_resolves_userconfig_from_invocation_cwd() {
    let project = test_dir("direct-npm-login-userconfig-project");
    let invocation_cwd = project.join("work/release");
    fs::create_dir_all(&invocation_cwd).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{ "name": "root", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        invocation_cwd.join("ci.npmrc"),
        "registry=https://auth.example.invalid/npm\n",
    )
    .unwrap();

    let status = run_npm_compat_with_cwd(
        &project,
        &args(&[
            "login",
            "--scope",
            "@company",
            "--userconfig",
            "ci.npmrc",
            "--auth-token",
            "npm_secret",
            "--json",
        ]),
        &invocation_cwd,
    )
    .unwrap();

    assert_eq!(status, ExitCode::SUCCESS);
    let user_config = fs::read_to_string(invocation_cwd.join("ci.npmrc")).unwrap();
    assert!(user_config.contains("@company:registry=https://auth.example.invalid/npm/"));
    assert!(user_config.contains("//auth.example.invalid/npm/:_authToken=npm_secret"));
    assert!(!project.join("ci.npmrc").exists());
}
