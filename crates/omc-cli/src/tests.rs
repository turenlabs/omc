//! CLI unit tests — extracted verbatim from lib.rs.

use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn os_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn test_dir(name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("omc-cli-{name}-{nonce}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn policy_validate_reports_ok_for_a_well_formed_file() {
    let dir = test_dir("policy-validate-ok");
    fs::write(dir.join("omc.policy"), "package \"is-odd\" { pure }\n").unwrap();
    let code = run_policy_command(&dir, PolicyCommand::Validate).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn policy_validate_is_a_hard_error_on_malformed_input() {
    let dir = test_dir("policy-validate-bad");
    fs::write(
        dir.join("omc.policy"),
        "package \"x\" { allow bogus \"y\" }\n",
    )
    .unwrap();
    let err = run_policy_command(&dir, PolicyCommand::Validate).unwrap_err();
    assert!(matches!(err, OmcRegistryError::PolicyParse(_)));
}

#[test]
fn policy_validate_without_file_succeeds() {
    let dir = test_dir("policy-validate-missing");
    // No omc.policy present: validate still succeeds (deny-by-default).
    let code = run_policy_command(&dir, PolicyCommand::Validate).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn policy_check_runs_for_scoped_name_at_version() {
    let dir = test_dir("policy-check");
    fs::write(
        dir.join("omc.policy"),
        "npm package \"@acme/*\" { allow net \"*\" }\n",
    )
    .unwrap();
    // `@acme/widget@2.0.0` — the leading `@` of the scope must be preserved
    // and only the `@` before the version split off.
    let code = run_policy_command(
        &dir,
        PolicyCommand::Check {
            npm: true,
            pypi: false,
            package: "@acme/widget@2.0.0".to_string(),
        },
    )
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}

fn pypi_sdist_for_test(root: &str, files: &[(&str, &str)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, content) in files {
        let archive_path = format!("{root}/{path}");
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                archive_path,
                &mut std::io::Cursor::new(content.as_bytes()),
            )
            .unwrap();
    }
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn with_env_lock<T>(f: impl FnOnce() -> T) -> T {
    static ENV_MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = ENV_MUTEX
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    f()
}

fn with_env_var<T>(key: &str, value: &Path, f: impl FnOnce() -> T) -> T {
    with_env_lock(|| {
        let old = env::var_os(key);
        env::set_var(key, value);
        let result = f();
        if let Some(old) = old {
            env::set_var(key, old);
        } else {
            env::remove_var(key);
        }
        result
    })
}

fn without_env_var<T>(key: &str, f: impl FnOnce() -> T) -> T {
    with_env_lock(|| {
        let old = env::var_os(key);
        env::remove_var(key);
        let result = f();
        if let Some(old) = old {
            env::set_var(key, old);
        }
        result
    })
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

fn with_pip_env_values<T>(values: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
    with_env_lock(|| {
        let mut keys = env::vars_os()
            .filter_map(|(key, _)| {
                let key = key.to_str()?;
                key.starts_with("PIP_").then(|| key.to_owned())
            })
            .collect::<BTreeSet<_>>();
        keys.extend(values.iter().map(|(key, _)| (*key).to_owned()));

        let old_values = keys
            .iter()
            .map(|key| (key.clone(), env::var_os(key)))
            .collect::<Vec<_>>();
        for key in &keys {
            env::remove_var(key);
        }
        for (key, value) in values {
            if let Some(value) = value {
                env::set_var(key, value);
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

fn with_clean_pip_env<T>(f: impl FnOnce() -> T) -> T {
    with_pip_env_values(&[], f)
}

// npm reads install-mode config (global, dry-run, omit/include, save-*, NODE_ENV)
// straight from the process environment via `npm_config_env`/`NODE_ENV`. Tests that
// mutate those vars hold `with_env_lock`, but `run_npm_compat`-based reader tests do
// not, so a concurrently running mutator could leak e.g. NPM_CONFIG_GLOBAL/DRY_RUN
// into an install and flip it to a global dry-run. This mirrors `with_pip_env_values`:
// it takes the lock and clears all inherited npm install-mode vars so reader tests are
// both mutually exclusive with mutators and independent of ambient host config.
fn with_npm_env_values<T>(values: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
    with_env_lock(|| {
        let mut keys = env::vars_os()
            .filter_map(|(key, _)| {
                let key = key.to_str()?;
                (key.starts_with("NPM_CONFIG_")
                    || key.starts_with("npm_config_")
                    || key == "NODE_ENV")
                    .then(|| key.to_owned())
            })
            .collect::<BTreeSet<_>>();
        keys.extend(values.iter().map(|(key, _)| (*key).to_owned()));

        let old_values = keys
            .iter()
            .map(|key| (key.clone(), env::var_os(key)))
            .collect::<Vec<_>>();
        for key in &keys {
            env::remove_var(key);
        }
        for (key, value) in values {
            if let Some(value) = value {
                env::set_var(key, value);
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

fn with_clean_npm_env<T>(f: impl FnOnce() -> T) -> T {
    with_npm_env_values(&[], f)
}

/// Exercise NPM_CONFIG_*/NODE_ENV defaulting via a thread-local override
/// instead of mutating the process-global environment. Unlike
/// `with_env_values`, this never touches `std::env`, so it cannot leak
/// install-mode config (e.g. NPM_CONFIG_GLOBAL/DRY_RUN) into the many
/// `run_npm_compat` reader tests running concurrently on other threads. Only
/// the keys with a `Some` value are visible inside the closure; everything
/// else reads as unset.
fn with_npm_config_overrides<T>(values: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
    let map: std::collections::HashMap<String, String> = values
        .iter()
        .filter_map(|(key, value)| value.map(|value| ((*key).to_owned(), value.to_owned())))
        .collect();
    NPM_ENV_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(map));
    let result = f();
    NPM_ENV_OVERRIDE.with(|cell| *cell.borrow_mut() = None);
    result
}

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
fn detects_direct_compat_binaries() {
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/node").as_os_str())),
        Some(DirectCompatMode::Node)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/npm").as_os_str())),
        Some(DirectCompatMode::Npm)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/npx").as_os_str())),
        Some(DirectCompatMode::Npx)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/pip3").as_os_str())),
        Some(DirectCompatMode::Pip)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/python").as_os_str())),
        Some(DirectCompatMode::Python)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/python3").as_os_str())),
        Some(DirectCompatMode::Python)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/twine").as_os_str())),
        Some(DirectCompatMode::Twine)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/omc").as_os_str())),
        None
    );
}

#[test]
fn parses_compile_command_and_infers_source_metadata() {
    let cli = Cli::try_parse_from(args(&[
        "omc",
        "compile",
        "--npm",
        "--name",
        "date-helper",
        "--version",
        "1.2.4",
        "--output",
        "dist/date-helper.omc.json",
        "--store",
        "--allow",
        "env:NPM_TOKEN",
        "--allow-flow",
        "env:NPM_TOKEN->network:api.example.com",
        "src/index.js",
    ]))
    .unwrap();

    match cli.command {
        Command::Compile {
            npm,
            pypi,
            source,
            name,
            version,
            output,
            store,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            assert!(npm);
            assert!(!pypi);
            assert_eq!(source, PathBuf::from("src/index.js"));
            assert_eq!(name.as_deref(), Some("date-helper"));
            assert_eq!(version, "1.2.4");
            assert_eq!(output, Some(PathBuf::from("dist/date-helper.omc.json")));
            assert!(store);
            assert_eq!(allow, vec!["env:NPM_TOKEN"]);
            assert_eq!(allow_flow, vec!["env:NPM_TOKEN->network:api.example.com"]);
            assert!(!allow_all_host);
        }
        other => panic!("expected compile command, got {other:?}"),
    }

    let dir = test_dir("compile-infer");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("package.json"), "{}").unwrap();
    assert_eq!(
        infer_compile_ecosystem(&dir, false, false).unwrap(),
        Ecosystem::Npm
    );
    fs::remove_file(dir.join("package.json")).unwrap();
    fs::write(dir.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
    assert_eq!(
        infer_compile_ecosystem(&dir, false, false).unwrap(),
        Ecosystem::Pypi
    );
    assert_eq!(
        compile_source_default_name(Path::new("pkg-1.0.0.tar.gz")),
        "pkg-1.0.0"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn run_and_script_forward_help_flags_to_targets() {
    let cli = Cli::try_parse_from(args(&["omc", "run", "rich", "--help"])).unwrap();
    match cli.command {
        Command::Run {
            command,
            args: command_args,
        } => {
            assert_eq!(command, "rich");
            assert_eq!(command_args, args(&["--help"]));
        }
        other => panic!("expected run command, got {other:?}"),
    }

    let cli = Cli::try_parse_from(args(&["omc", "script", "build", "--help"])).unwrap();
    match cli.command {
        Command::Script {
            name,
            args: script_args,
        } => {
            assert_eq!(name, "build");
            assert_eq!(script_args, args(&["--help"]));
        }
        other => panic!("expected script command, got {other:?}"),
    }
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
}

#[test]
fn direct_npm_exec_package_resolves_local_paths_from_invocation_cwd() {
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
fn relative_project_paths_resolve_user_paths_from_current_directory() {
    let vendor = pip_rooted_project_path(Path::new("."), None, PathBuf::from("vendor"));

    assert!(vendor.is_absolute());
    assert_eq!(
        vendor.file_name().and_then(|name| name.to_str()),
        Some("vendor")
    );
}

fn write_npm_fixture_tarball(project: &Path, name: &str, version: &str) -> PathBuf {
    let source = project.join(format!("source-{name}"));
    fs::create_dir_all(&source).unwrap();
    fs::write(
        source.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
    fs::write(
        source.join("index.js"),
        format!("module.exports = '{name}';\n"),
    )
    .unwrap();
    let tarball = project.join(format!("{name}-{version}.tgz"));
    let files = collect_npm_pack_files(&source).unwrap();
    write_npm_pack_tarball(&tarball, &files).unwrap();
    tarball
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
fn parses_direct_compat_project_dir_prefix() {
    let cwd = env::current_dir().unwrap();
    let npm_root = test_dir("direct-compat-npm-root");
    let npm_workspace = npm_root.join("packages").join("lib");
    let npm_nested = npm_workspace.join("src");
    fs::create_dir_all(&npm_nested).unwrap();
    fs::write(npm_root.join("package.json"), r#"{"name":"root"}"#).unwrap();
    fs::write(
        npm_workspace.join("package.json"),
        r#"{"name":"@demo/lib"}"#,
    )
    .unwrap();
    assert_eq!(
        discover_direct_compat_project_dir_from(DirectCompatMode::Npm, &npm_nested),
        Some(npm_workspace.clone())
    );

    let pip_root = test_dir("direct-compat-pip-root");
    let pip_nested = pip_root.join("src").join("demo");
    fs::create_dir_all(&pip_nested).unwrap();
    fs::write(
        pip_root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    assert_eq!(
        discover_direct_compat_project_dir_from(DirectCompatMode::Pip, &pip_nested),
        Some(pip_root.clone())
    );
    assert_eq!(
        discover_direct_compat_project_dir_from(
            DirectCompatMode::Python,
            &test_dir("direct-compat-no-root")
        ),
        None
    );

    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Npm,
            os_args(&["--project-dir", "/tmp/project", "install", "left-pad",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["install", "left-pad"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Pip,
            os_args(&["--omc-project-dir=/tmp/project", "show", "requests",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["show", "requests"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Npm,
            os_args(&["--prefix=/tmp/project", "test", "--", "--watch",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["test", "--", "--watch"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Npx,
            os_args(&["--prefix=/tmp/project", "eslint", "--", "."])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["eslint", "--", "."]),
        }
    );
    assert_eq!(
        npx_compat_args(args(&["eslint", "--", "."])),
        args(&["npx", "eslint", "--", "."])
    );
    assert_eq!(npx_compat_args(args(&["--version"])), args(&["--version"]));
    assert_eq!(npx_compat_args(args(&["-v"])), args(&["-v"]));
    assert_eq!(
        npm_project_dir_from_prefix_args(
            Path::new("/tmp/root"),
            &args(&["install", "--prefix=packages/app", "left-pad"])
        )
        .unwrap(),
        (
            PathBuf::from("/tmp/root/packages/app"),
            args(&["install", "left-pad"]),
        )
    );
    assert_eq!(
        npm_project_dir_from_prefix_args(
            Path::new("/tmp/root"),
            &args(&["run", "build", "--", "--prefix", "script-arg"])
        )
        .unwrap(),
        (
            PathBuf::from("/tmp/root"),
            args(&["run", "build", "--", "--prefix", "script-arg"]),
        )
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Node,
            os_args(&["--omc-project-dir", "/tmp/project", "-e", "console.log(1)",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["-e", "console.log(1)"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Python,
            os_args(&[
                "--omc-project-dir",
                "/tmp/project",
                "-m",
                "pip",
                "install",
                "requests",
            ])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["-m", "pip", "install", "requests"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Twine,
            os_args(&[
                "--omc-project-dir",
                "/tmp/project",
                "upload",
                "--repository",
                "testpypi",
                "dist/pkg.whl",
            ])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd,
            args: args(&["upload", "--repository", "testpypi", "dist/pkg.whl"]),
        }
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
fn parses_npm_install_compat_flags() {
    assert_eq!(
        parse_npm_compat_action(&args(&["--version"])).unwrap(),
        NpmCompatAction::Version
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--silent", "--version"])).unwrap(),
        NpmCompatAction::Version
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--help"])).unwrap(),
        NpmCompatAction::Help { topic: None }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["help", "install"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("install".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["install", "--help"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("install".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["unlink", "--help"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("unlink".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["completion"])).unwrap(),
        NpmCompatAction::Completion { words: None }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["completion", "--", "npm", "expl"])).unwrap(),
        NpmCompatAction::Completion {
            words: Some(vec!["npm".to_owned(), "expl".to_owned()]),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["help-search", "cache", "--long"])).unwrap(),
        NpmCompatAction::HelpSearch {
            query: vec!["cache".to_owned()],
            long: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "doctor",
            "environment",
            "cache",
        ]))
        .unwrap(),
        NpmCompatAction::Doctor {
            action: NpmDoctorAction {
                checks: vec!["environment".to_owned(), "cache".to_owned()],
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            },
        }
    );
    assert!(npm_help_text(None).contains("Supported commands: install"));
    assert!(npm_help_text(Some("help-search")).contains("npm help-search"));
    assert!(npm_help_text(Some("doctor")).contains("npm doctor"));
    let help_search = npm_help_search_text(&args(&["cache"]), false).unwrap();
    assert!(help_search.contains("Top hits for \"cache\""));
    assert!(help_search.contains("npm help cache"));
    assert!(npm_help_text(Some("fund")).contains("npm fund [<package-spec>]"));
    assert!(npm_help_text(Some("install-test")).contains("npm install-test"));
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--silent",
            "--registry",
            "https://registry.example.invalid/npm",
            "install",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--json", "view", "left-pad", "version"])).unwrap(),
        NpmCompatAction::View {
            spec: "left-pad".to_owned(),
            fields: vec!["version".to_owned()],
            json: true,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["view", "left-pad", "version", "-j"])).unwrap(),
        NpmCompatAction::View {
            spec: "left-pad".to_owned(),
            fields: vec!["version".to_owned()],
            json: true,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["-j", "view", "left-pad", "version"])).unwrap(),
        NpmCompatAction::View {
            spec: "left-pad".to_owned(),
            fields: vec!["version".to_owned()],
            json: true,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["why", "left-pad", "-j"])).unwrap(),
        NpmCompatAction::Explain {
            specs: vec!["left-pad".to_owned()],
            json: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "run",
            "build",
        ]))
        .unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: Vec::new(),
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "init",
            "-y",
            "--scope",
            "@scope",
            "--private",
            "--type=module",
        ]))
        .unwrap(),
        NpmCompatAction::Init {
            action: NpmInitAction {
                name: None,
                version: None,
                description: None,
                main: None,
                license: None,
                scope: Some("@scope".to_owned()),
                private: true,
                package_type: Some("module".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["init", "react-app"])).unwrap(),
        NpmCompatAction::Create {
            action: NpmCreateAction {
                initializer: "react-app".to_owned(),
                args: Vec::new(),
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "create",
            "vite@latest",
            "my-app",
            "--allow=fs.write:*",
            "--allow-all-host",
            "--",
            "--template",
            "react",
        ]))
        .unwrap(),
        NpmCompatAction::Create {
            action: NpmCreateAction {
                initializer: "vite@latest".to_owned(),
                args: vec![
                    "my-app".to_owned(),
                    "--template".to_owned(),
                    "react".to_owned(),
                ],
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: vec!["fs.write:*".to_owned()],
                allow_flow: Vec::new(),
                allow_all_host: true,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["version", "--json"])).unwrap(),
        NpmCompatAction::PackageVersion {
            action: NpmVersionAction::Current { json: true },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "version",
            "patch",
            "--no-git-tag-version",
            "--allow-same-version",
        ]))
        .unwrap(),
        NpmCompatAction::PackageVersion {
            action: NpmVersionAction::Bump {
                spec: "patch".to_owned(),
                preid: None,
                allow_same_version: true,
                json: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["version", "preminor", "--preid", "rc", "--json",]))
            .unwrap(),
        NpmCompatAction::PackageVersion {
            action: NpmVersionAction::Bump {
                spec: "preminor".to_owned(),
                preid: Some("rc".to_owned()),
                allow_same_version: false,
                json: true,
            },
        }
    );

    assert_eq!(npm_next_version("1.2.3", "patch", None).unwrap(), "1.2.4");
    assert_eq!(
        npm_next_version("1.2.3", "preminor", Some("rc")).unwrap(),
        "1.3.0-rc.0"
    );
    assert_eq!(
        npm_next_version("1.2.3", "prerelease", None).unwrap(),
        "1.2.4-0"
    );
    assert_eq!(
        npm_next_version("1.2.3-rc.0", "prerelease", Some("rc")).unwrap(),
        "1.2.3-rc.1"
    );
    assert_eq!(
        npm_next_version("1.2.3-alpha.0", "prerelease", Some("rc")).unwrap(),
        "1.2.3-rc.0"
    );
    assert_eq!(
        npm_next_version("v2.0.0+build.7", "2.0.0", None).unwrap(),
        "2.0.0"
    );

    let action = parse_npm_compat_action(&args(&[
        "install",
        "-D",
        "--omit=dev",
        "--install-strategy",
        "hoisted",
        "--cache=/tmp/npm-cache",
        "--registry",
        "https://registry.example.invalid/npm",
        "--package-lock=false",
        "--no-fund",
        "--silent",
        "--loglevel",
        "warn",
        "--no-progress",
        "--progress=false",
        "--color",
        "false",
        "--legacy-peer-deps=true",
        "--legacy-peer-deps=false",
        "--strict-peer-deps=false",
        "--strict-peer-deps=true",
        "--ignore-scripts=true",
        "--prefer-offline",
        "--prefer-offline=true",
        "--prefer-online",
        "--prefer-online=false",
        "--prefer-dedupe",
        "--prefer-dedupe=false",
        "--no-prefer-dedupe",
        "--foreground-scripts=true",
        "--audit=true",
        "--fund=true",
        "--bin-links=false",
        "--global-style",
        "--legacy-bundling",
        "--dry-run",
        "--allow-all-host",
        "left-pad@1.3.0",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad@1.3.0".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Dev,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: false,
            lock_only: false,
            dry_run: true,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: true,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    let action =
        parse_npm_compat_action(&args(&["--location=global", "install", "left-pad"])).unwrap();
    let NpmCompatAction::Install { global, specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(global);
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action = parse_npm_compat_action(&args(&[
        "--prefer-dedupe",
        "--ignore-scripts=true",
        "--bin-links=false",
        "install",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action =
        parse_npm_compat_action(&args(&["install", "--location", "project", "left-pad"])).unwrap();
    let NpmCompatAction::Install { global, specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!global);
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--allow=env:API_TOKEN",
        "--allow-flow",
        "env:API_TOKEN->network:api.example.com",
        "flow-client",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        allow, allow_flow, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(allow, vec!["env:API_TOKEN".to_owned()]);
    assert_eq!(
        allow_flow,
        vec!["env:API_TOKEN->network:api.example.com".to_owned()]
    );

    let exact = parse_npm_compat_action(&args(&["install", "--save-exact", "left-pad"])).unwrap();
    let NpmCompatAction::Install { save_prefix, .. } = exact else {
        panic!("expected npm install action");
    };
    assert_eq!(save_prefix, "");

    let tilde =
        parse_npm_compat_action(&args(&["--save-prefix=~", "install", "left-pad"])).unwrap();
    let NpmCompatAction::Install { save_prefix, .. } = tilde else {
        panic!("expected npm install action");
    };
    assert_eq!(save_prefix, "~");

    let bundled = parse_npm_compat_action(&args(&["in", "-B", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        save,
        save_bundle,
        specs,
        ..
    } = bundled
    else {
        panic!("expected npm install action");
    };
    assert!(save);
    assert!(save_bundle);
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let unbundled = parse_npm_compat_action(&args(&[
        "install",
        "--save-bundle",
        "--no-save-bundle",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { save_bundle, .. } = unbundled else {
        panic!("expected npm install action");
    };
    assert!(!save_bundle);

    let save_dev_false =
        parse_npm_compat_action(&args(&["install", "--save-dev=false", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        dependency_kind, ..
    } = save_dev_false
    else {
        panic!("expected npm install action");
    };
    assert_eq!(dependency_kind, ManifestDependencyKind::Production);

    let save_peer_true =
        parse_npm_compat_action(&args(&["install", "--save-peer=true", "react"])).unwrap();
    let NpmCompatAction::Install {
        dependency_kind, ..
    } = save_peer_true
    else {
        panic!("expected npm install action");
    };
    assert_eq!(dependency_kind, ManifestDependencyKind::Peer);

    assert_eq!(
        parse_npm_compat_action(&args(&["install", "--save-optional", "fsevents"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["fsevents".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Optional,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&["install", "--save-peer", "react"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["react".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Peer,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "install",
        "./pkg.tgz",
        "file:../other.tgz",
        "../local-pkg",
        "@scope/runtime",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["@scope/runtime".to_owned()],
            archive_references: vec!["./pkg.tgz".to_owned(), "file:../other.tgz".to_owned()],
            local_paths: vec![PathBuf::from("../local-pkg")],
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&["link"])).unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Register { dry_run: false },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--location=global", "link"])).unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Register { dry_run: false },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["link", "--dry-run", "../local-pkg"])).unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Install {
                names: Vec::new(),
                archive_references: Vec::new(),
                local_paths: vec![PathBuf::from("../local-pkg")],
                save: false,
                save_bundle: false,
                dependency_kind: ManifestDependencyKind::Production,
                omit_dev: false,
                omit_optional: false,
                omit_peer: false,
                lock_only: false,
                dry_run: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--save-dev",
            "link",
            "@scope/local-pkg",
            "--omit=dev",
            "--registry=https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Install {
                names: vec!["@scope/local-pkg".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                save_bundle: false,
                dependency_kind: ManifestDependencyKind::Dev,
                omit_dev: true,
                omit_optional: false,
                omit_peer: false,
                lock_only: false,
                dry_run: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "link",
            "--dry-run",
            "./pkg.tgz",
            "file:../other.tgz",
        ]))
        .unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Install {
                names: Vec::new(),
                archive_references: vec!["./pkg.tgz".to_owned(), "file:../other.tgz".to_owned()],
                local_paths: Vec::new(),
                save: false,
                save_bundle: false,
                dependency_kind: ManifestDependencyKind::Production,
                omit_dev: false,
                omit_optional: false,
                omit_peer: false,
                lock_only: false,
                dry_run: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--no-save",
        "--omit=optional,peer",
        "--omit",
        "dev",
        "--include=dev",
        "left-pad",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: false,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: true,
            omit_peer: true,
            package_lock: false,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    let action = parse_npm_compat_action(&args(&["install", "--no-optional", "left-pad"])).unwrap();
    let NpmCompatAction::Install { omit_optional, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(omit_optional);

    let action =
        parse_npm_compat_action(&args(&["install", "--only", "prod", "left-pad"])).unwrap();
    let NpmCompatAction::Install { omit_dev, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(omit_dev);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--production",
        "--also=dev",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { omit_dev, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!omit_dev);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--optional=false",
        "--include=optional",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { omit_optional, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!omit_optional);

    let action =
        parse_npm_compat_action(&args(&["install", "--package-lock-only", "left-pad"])).unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: true,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "--dry-run",
        "--package-lock-only",
        "install",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        specs,
        dry_run,
        lock_only,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert!(dry_run);
    assert!(lock_only);

    let action =
        parse_npm_compat_action(&args(&["install", "--dry-run", "--json", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        specs,
        dry_run,
        json,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert!(dry_run);
    assert!(json);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "github:turenio/omc#main",
        "turenio/omc#v1.0.0",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        specs,
        archive_references,
        local_paths,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert_eq!(
        archive_references,
        vec![
            "github:turenio/omc#main".to_owned(),
            "turenio/omc#v1.0.0".to_owned()
        ]
    );
    assert!(local_paths.is_empty());

    let action = parse_npm_compat_action(&args(&["install", "--tag", "beta", "left-pad"])).unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad@beta".to_owned()]);

    let action = parse_npm_compat_action(&args(&[
        "--tag=beta",
        "install",
        "@scope/pkg",
        "left-pad@1.3.0",
    ]))
    .unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(
        specs,
        vec!["@scope/pkg@beta".to_owned(), "left-pad@1.3.0".to_owned()]
    );

    let action =
        parse_npm_compat_action(&args(&["install", "--before", "2025-01-01", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        specs, npm_before, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert_eq!(npm_before.as_deref(), Some("2025-01-01"));

    let action =
        parse_npm_compat_action(&args(&["--before=2025-01-01", "install", "left-pad"])).unwrap();
    let NpmCompatAction::Install { npm_before, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(npm_before.as_deref(), Some("2025-01-01"));

    let before_parse = Utc::now();
    let action =
        parse_npm_compat_action(&args(&["install", "--min-release-age=7", "left-pad"])).unwrap();
    let after_parse = Utc::now();
    let NpmCompatAction::Install { npm_before, .. } = action else {
        panic!("expected npm install action");
    };
    let cutoff = chrono::DateTime::parse_from_rfc3339(npm_before.as_deref().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!(cutoff >= before_parse - Duration::days(7) - Duration::seconds(1));
    assert!(cutoff <= after_parse - Duration::days(7) + Duration::seconds(1));

    let error = parse_npm_compat_action(&args(&["install", "--min-release-age=7d", "left-pad"]))
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported npm --min-release-age value"));

    let action =
        parse_npm_compat_action(&args(&["install", "--engine-strict", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        npm_engine_strict, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(npm_engine_strict);

    let action =
        parse_npm_compat_action(&args(&["--engine-strict=true", "ci", "--omit=dev"])).unwrap();
    let NpmCompatAction::Ci {
        npm_engine_strict, ..
    } = action
    else {
        panic!("expected npm ci action");
    };
    assert!(npm_engine_strict);

    let action = parse_npm_compat_action(&args(&["install", "--offline", "left-pad"])).unwrap();
    let NpmCompatAction::Install { npm_offline, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(npm_offline);

    let action =
        parse_npm_compat_action(&args(&["install", "--offline", "--no-offline", "left-pad"]))
            .unwrap();
    let NpmCompatAction::Install { npm_offline, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!npm_offline);

    let action = parse_npm_compat_action(&args(&["--offline=true", "ci", "--omit=dev"])).unwrap();
    let NpmCompatAction::Ci { npm_offline, .. } = action else {
        panic!("expected npm ci action");
    };
    assert!(npm_offline);

    let action =
        parse_npm_compat_action(&args(&["install", "--install-links=false", "left-pad"])).unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action =
        parse_npm_compat_action(&args(&["--json", "install", "--dry-run", "left-pad"])).unwrap();
    let NpmCompatAction::Install { dry_run, json, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(dry_run);
    assert!(json);

    let action =
        parse_npm_compat_action(&args(&["install", "--json", "--no-json", "left-pad"])).unwrap();
    let NpmCompatAction::Install { json, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!json);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--dry-run=true",
        "--package-lock-only=true",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        dry_run, lock_only, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(dry_run);
    assert!(lock_only);

    let action = parse_npm_compat_action(&args(&[
        "--dry-run=false",
        "--package-lock-only=false",
        "install",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        dry_run, lock_only, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(!dry_run);
    assert!(!lock_only);

    let action = parse_npm_compat_action(&args(&["--dry-run", "ci", "--omit=dev"])).unwrap();
    let NpmCompatAction::Ci {
        dry_run,
        omit_dev,
        workspaces,
        all_workspaces,
        include_workspace_root,
        ..
    } = action
    else {
        panic!("expected npm ci action");
    };
    assert!(dry_run);
    assert!(omit_dev);
    assert!(workspaces.is_empty());
    assert!(!all_workspaces);
    assert!(!include_workspace_root);

    let action = parse_npm_compat_action(&args(&["ci", "--json", "--dry-run"])).unwrap();
    let NpmCompatAction::Ci { dry_run, json, .. } = action else {
        panic!("expected npm ci action");
    };
    assert!(dry_run);
    assert!(json);

    let action = parse_npm_compat_action(&args(&[
        "ci",
        "--workspace",
        "@demo/lib",
        "--include-workspace-root",
    ]))
    .unwrap();
    let NpmCompatAction::Ci {
        workspaces,
        all_workspaces,
        include_workspace_root,
        ..
    } = action
    else {
        panic!("expected npm ci action");
    };
    assert_eq!(workspaces, vec!["@demo/lib"]);
    assert!(!all_workspaces);
    assert!(include_workspace_root);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--save=false",
        "--package-lock=true",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        save, package_lock, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(!save);
    assert!(!package_lock);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--save=false",
        "--save=true",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        save, package_lock, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(save);
    assert!(package_lock);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--workspace",
        "@demo/lib",
        "--include-workspace-root",
        "left-pad",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: true,
        }
    );

    let action = parse_npm_compat_action(&args(&["install", "-w@demo/lib", "left-pad"])).unwrap();
    let NpmCompatAction::Install { workspaces, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(workspaces, vec!["@demo/lib"]);

    let action = parse_npm_compat_action(&args(&["install", "-ws", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        workspaces,
        all_workspaces,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(workspaces.is_empty());
    assert!(all_workspaces);

    let action =
        parse_npm_compat_action(&args(&["install", "--workspace=true", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        workspaces,
        all_workspaces,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(workspaces, vec!["true"]);
    assert!(!all_workspaces);

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "remove",
            "--package-lock-only",
            "left-pad",
            "--workspace",
            "@demo/lib",
            "--include-workspace-root=false",
        ]))
        .unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: false,
            save: true,
            package_lock: true,
            lock_only: true,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--location=global",
            "remove",
            "left-pad",
            "--location",
            "project",
        ]))
        .unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: false,
            save: true,
            package_lock: true,
            lock_only: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--workspace=@demo/lib",
            "unlink",
            "left-pad",
            "--no-save",
        ]))
        .unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: false,
            save: false,
            package_lock: true,
            lock_only: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--location=global", "r", "left-pad"])).unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: true,
            save: true,
            package_lock: true,
            lock_only: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "it",
            "--omit=dev",
            "left-pad",
            "--",
            "--watch",
        ]))
        .unwrap(),
        NpmCompatAction::InstallTest {
            command: "it".to_owned(),
            use_ci: false,
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
            test_args: vec!["--watch".to_owned()],
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "cit",
            "--dry-run",
            "--omit=dev",
            "--",
            "--runInBand",
        ]))
        .unwrap(),
        NpmCompatAction::InstallTest {
            command: "cit".to_owned(),
            use_ci: true,
            specs: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: true,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
            test_args: vec!["--runInBand".to_owned()],
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "update",
        "--package-lock-only",
        "--omit=dev",
        "--registry=https://registry.example.invalid/npm",
        "left-pad",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: false,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: true,
            dry_run: false,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&["up", "--save-dev", "left-pad"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Dev,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["udpate", "--dry-run", "left-pad"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: false,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: true,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
}

#[test]
fn parses_npm_run_and_exec_compat_commands() {
    assert_eq!(
        parse_npm_compat_action(&args(&["run"])).unwrap(),
        NpmCompatAction::RunList {
            action: NpmRunListAction {
                json: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--json", "--workspace", "@demo/lib", "run",])).unwrap(),
        NpmCompatAction::RunList {
            action: NpmRunListAction {
                json: true,
                workspaces: vec!["@demo/lib".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["run", "test", "--", "--watch"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "test".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["test", "--", "--watch"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "test".to_owned(),
            name: "test".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["run", "--if-present", "--silent", "build"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: Vec::new(),
            if_present: true,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["test", "--if-present", "--", "--watch"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "test".to_owned(),
            name: "test".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: true,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["-w@demo/lib", "run", "build", "--", "--watch",])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: false,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "test",
            "--workspaces=true",
            "--include-workspace-root=false",
            "--if-present",
        ]))
        .unwrap(),
        NpmCompatAction::RunScript {
            command: "test".to_owned(),
            name: "test".to_owned(),
            args: Vec::new(),
            if_present: true,
            workspaces: Vec::new(),
            all_workspaces: true,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--ws", "run", "build"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: Vec::new(),
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: true,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["exec", "eslint", "--", "."])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: Vec::new(),
                command: "eslint".to_owned(),
                args: vec![".".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["exec", "--help"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("exec".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["exec", "eslint", "--help"])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: Vec::new(),
                command: "eslint".to_owned(),
                args: vec!["--help".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--yes",
            "--package",
            "eslint",
            "--cache=/tmp/npm-cache",
            "--loglevel=warn",
            "--ignore-scripts=true",
            "--prefer-offline",
            "--prefer-dedupe",
            "--bin-links=false",
            "--audit=false",
            "--fund=false",
            "eslint",
            "--",
            ".",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["eslint".to_owned()],
                command: "eslint".to_owned(),
                args: vec![".".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    let (call_command, call_args) = npm_exec_call_command("node -e \"console.log(1)\"".to_owned());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--package",
            "typescript",
            "--call",
            "node -e \"console.log(1)\"",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["typescript".to_owned()],
                command: call_command,
                args: call_args,
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "npx",
            "-y",
            "-p",
            "typescript",
            "tsc",
            "--version",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["typescript".to_owned()],
                command: "tsc".to_owned(),
                args: vec!["--version".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["npx", "semver@7.6.3", "1.2.3"])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["semver@7.6.3".to_owned()],
                command: "semver".to_owned(),
                args: vec!["1.2.3".to_owned()],
                no_install: false,
                prefer_project_bin: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["npx", "@scope/tool@1.2.3", "--help"])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["@scope/tool@1.2.3".to_owned()],
                command: "tool".to_owned(),
                args: vec!["--help".to_owned()],
                no_install: false,
                prefer_project_bin: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--package=@scope/tool@1.2.3",
            "--registry",
            "https://registry.example",
            "--allow=env:TOOL_TOKEN",
            "--allow-all-host",
            "--",
            "tool",
            "--help",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["@scope/tool@1.2.3".to_owned()],
                command: "tool".to_owned(),
                args: vec!["--help".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: Some("https://registry.example".to_owned()),
                allow: vec!["env:TOOL_TOKEN".to_owned()],
                allow_flow: Vec::new(),
                allow_all_host: true,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "-ws",
            "exec",
            "--include-workspace-root=false",
            "--",
            "node",
            "-e",
            "console.log(process.cwd())",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: Vec::new(),
                command: "node".to_owned(),
                args: vec!["-e".to_owned(), "console.log(process.cwd())".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: true,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--no-install",
            "--package",
            "eslint",
            "eslint",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["eslint".to_owned()],
                command: "eslint".to_owned(),
                args: Vec::new(),
                no_install: true,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--shell",
            "zsh",
            "explore",
            "@scope/pkg@1.2.3",
            "--",
            "pwd",
            "-P",
        ]))
        .unwrap(),
        NpmCompatAction::Explore {
            action: NpmExploreAction {
                package: "@scope/pkg@1.2.3".to_owned(),
                command: Some("pwd".to_owned()),
                args: vec!["-P".to_owned()],
                shell: Some("zsh".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--editor",
            "true",
            "edit",
            "@scope/pkg/package.json",
        ]))
        .unwrap(),
        NpmCompatAction::Edit {
            target: "@scope/pkg/package.json".to_owned(),
            editor: Some("true".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["bin", "--silent"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Bin,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["root"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Root,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["prefix", "--parseable"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Prefix,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--global", "bin"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Bin,
            global: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--location", "global", "prefix"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Prefix,
            global: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["root", "--location=project"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Root,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "pack",
            "--pack-destination",
            "dist",
            "--json",
            "--dry-run",
            ".",
        ]))
        .unwrap(),
        NpmCompatAction::Pack {
            action: NpmPackAction {
                packages: vec![NpmPackInput::Local(PathBuf::from("."))],
                destination: PathBuf::from("dist"),
                json: true,
                dry_run: true,
                npm_registry: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "pack",
            "left-pad@1.3.0",
        ]))
        .unwrap(),
        NpmCompatAction::Pack {
            action: NpmPackAction {
                packages: vec![NpmPackInput::Registry("left-pad@1.3.0".to_owned())],
                destination: PathBuf::from("."),
                json: false,
                dry_run: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json=true",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "publish",
            "--tag=beta",
            "--access",
            "public",
            "--workspace",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Publish {
            action: NpmPublishAction {
                package: None,
                tag: "beta".to_owned(),
                access: Some("public".to_owned()),
                provenance: NpmPublishProvenance::None,
                dry_run: false,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
                workspaces: vec!["@demo/pkg".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "publish",
            "./pkg.tgz",
            "--dry-run",
            "--no-provenance",
        ]))
        .unwrap(),
        NpmCompatAction::Publish {
            action: NpmPublishAction {
                package: Some(PathBuf::from("./pkg.tgz")),
                tag: "latest".to_owned(),
                access: None,
                provenance: NpmPublishProvenance::None,
                dry_run: true,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "publish",
            "--dry-run",
            "--provenance-file=build.sigstore",
            "--provenance=false",
            "--provenance",
        ]))
        .unwrap(),
        NpmCompatAction::Publish {
            action: NpmPublishAction {
                package: None,
                tag: "latest".to_owned(),
                access: None,
                provenance: NpmPublishProvenance::Generate,
                dry_run: true,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "--force",
            "unpublish",
            "@scope/pkg@1.2.3",
            "--dry-run",
        ]))
        .unwrap(),
        NpmCompatAction::Unpublish {
            action: NpmUnpublishAction {
                spec: Some("@scope/pkg@1.2.3".to_owned()),
                dry_run: true,
                force: true,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["unpublish", "--workspace", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Unpublish {
            action: NpmUnpublishAction {
                spec: None,
                dry_run: false,
                force: false,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                workspaces: vec!["@demo/pkg".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["unpublish", "a", "b"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "deprecate",
            "demo-pkg@1.x",
            "old line",
            "--dry-run",
        ]))
        .unwrap(),
        NpmCompatAction::Deprecate {
            action: NpmDeprecateAction {
                spec: "demo-pkg@1.x".to_owned(),
                message: "old line".to_owned(),
                dry_run: true,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
                undeprecate: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["undeprecate", "demo-pkg@1.0.0"])).unwrap(),
        NpmCompatAction::Deprecate {
            action: NpmDeprecateAction {
                spec: "demo-pkg@1.0.0".to_owned(),
                message: String::new(),
                dry_run: false,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                undeprecate: true,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["deprecate", "demo-pkg@1.0.0"])).is_err());
    assert!(parse_npm_compat_action(&args(&["undeprecate", "demo-pkg@1.0.0", "extra"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "prune",
            "--omit=dev",
            "--loglevel=silent",
            "--allow-all-host",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Maintenance {
            command: NpmMaintenanceCommand::Prune,
            packages: vec!["left-pad".to_owned()],
            dry_run: false,
            json: false,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "dedupe",
            "--dry-run",
            "--json",
            "--cache",
            "/tmp/npm-cache",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Maintenance {
            command: NpmMaintenanceCommand::Dedupe,
            packages: vec!["left-pad".to_owned()],
            dry_run: true,
            json: true,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--omit=dev",
            "rebuild",
            "node-sass",
            "--ignore-scripts",
            "--build-from-source",
            "--dry-run",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Maintenance {
            command: NpmMaintenanceCommand::Rebuild,
            packages: vec!["node-sass".to_owned()],
            dry_run: true,
            json: true,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "audit",
            "--json",
            "--audit-level=high",
            "--omit",
            "dev",
            "--registry",
            "https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Audit { json: true }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["audit", "-j"])).unwrap(),
        NpmCompatAction::Audit { json: true }
    );
    assert!(parse_npm_compat_action(&args(&["audit", "fix"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--workspace",
            "@demo/lib",
            "fund",
            "left-pad@1.3.0",
            "--browser=false",
        ]))
        .unwrap(),
        NpmCompatAction::Fund {
            action: NpmFundAction {
                json: true,
                package: Some("left-pad@1.3.0".to_owned()),
                workspaces: vec!["@demo/lib".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "fund",
            "--ws",
            "--include-workspace-root",
            "--which",
            "1",
        ]))
        .unwrap(),
        NpmCompatAction::Fund {
            action: NpmFundAction {
                json: false,
                package: None,
                workspaces: Vec::new(),
                all_workspaces: true,
                include_workspace_root: true,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["fund", "left-pad", "chalk"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "verify", "--cache=/tmp/npm-cache"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Verify,
            cache_dir: Some(PathBuf::from("/tmp/npm-cache")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--cache", ".npm-cache", "cache", "verify"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Verify,
            cache_dir: Some(PathBuf::from(".npm-cache")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "ls", "left-pad"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::List {
                pattern: Some("left-pad".to_owned()),
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "rm", "left-pad"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Remove {
                pattern: "left-pad".to_owned(),
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "clean", "--force"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Clean,
            cache_dir: None,
        }
    );
    assert!(parse_npm_compat_action(&args(&["cache", "clean"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&["pkg", "get", "name", "version", "--json"])).unwrap(),
        NpmCompatAction::Pkg {
            action: NpmPkgAction::Get {
                fields: vec!["name".to_owned(), "version".to_owned()],
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "pkg",
            "set",
            "scripts.test=\"vitest\"",
            "private=true",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Pkg {
            action: NpmPkgAction::Set {
                assignments: vec![
                    (
                        "scripts.test".to_owned(),
                        serde_json::Value::String("vitest".to_owned()),
                    ),
                    ("private".to_owned(), serde_json::Value::Bool(true)),
                ],
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["pkg", "delete", "scripts.pretest"])).unwrap(),
        NpmCompatAction::Pkg {
            action: NpmPkgAction::Delete {
                fields: vec!["scripts.pretest".to_owned()],
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["shrinkwrap", "--dry-run", "ignored"])).unwrap(),
        NpmCompatAction::Shrinkwrap
    );
    assert!(parse_npm_compat_action(&args(&["shrinkwrap", "--workspace", "@demo/lib"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "outdated",
            "--json",
            "--parseable",
            "--depth=0",
            "--registry",
            "https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: true,
            packages: Vec::new(),
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "outdated",
            "left-pad@1.1.0",
            "@demo/pkg",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: false,
            packages: vec!["left-pad@1.1.0".to_owned(), "@demo/pkg".to_owned()],
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["outdated", "-al", "--json"])).unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: false,
            packages: Vec::new(),
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["outdated", "-j"])).unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: false,
            packages: Vec::new(),
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--searchlimit=3",
            "--json",
            "search",
            "--registry",
            "https://registry.example.invalid/npm",
            "left",
            "pad",
        ]))
        .unwrap(),
        NpmCompatAction::Search {
            action: NpmSearchAction {
                query: "left pad".to_owned(),
                json: true,
                parseable: false,
                limit: 3,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["find", "left-pad", "--parseable", "--limit=500"]))
            .unwrap(),
        NpmCompatAction::Search {
            action: NpmSearchAction {
                query: "left-pad".to_owned(),
                json: false,
                parseable: true,
                limit: 250,
                npm_registry: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--diff=left-pad@1.1.0",
            "--diff",
            "left-pad@1.3.0",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "diff",
            "--diff-name-only",
            "--diff-unified=5",
            "--diff-ignore-all-space",
            "--diff-src-prefix=old/",
            "--diff-dst-prefix",
            "new/",
            "index.js",
        ]))
        .unwrap(),
        NpmCompatAction::Diff {
            action: NpmDiffAction {
                specs: vec!["left-pad@1.1.0".to_owned(), "left-pad@1.3.0".to_owned()],
                paths: vec!["index.js".to_owned()],
                name_only: true,
                unified: 5,
                ignore_all_space: true,
                no_prefix: false,
                src_prefix: "old/".to_owned(),
                dst_prefix: "new/".to_owned(),
                text: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "star",
            "left-pad",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Star {
            action: NpmStarAction::Mutate {
                specs: vec!["left-pad".to_owned(), "@demo/pkg".to_owned()],
                starred: true,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["unstar", "left-pad", "--otp=123456"])).unwrap(),
        NpmCompatAction::Star {
            action: NpmStarAction::Mutate {
                specs: vec!["left-pad".to_owned()],
                starred: false,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "stars",
            "alice",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Star {
            action: NpmStarAction::List {
                user: Some("alice".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "ping",
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Ping {
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "whoami",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Whoami {
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: Some(PathBuf::from("ci.npmrc")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--scope",
            "@demo",
            "login",
            "--auth-type=legacy",
            "--token",
            "npm_abc123",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Login {
            action: NpmLoginAction {
                scope: Some("@demo".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                token: Some("npm_abc123".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["adduser", "--scope=demo", "--auth-token=npm_xyz"]))
            .unwrap(),
        NpmCompatAction::Login {
            action: NpmLoginAction {
                scope: Some("demo".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                token: Some("npm_xyz".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--scope",
            "@demo",
            "logout",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Logout {
            action: NpmLogoutAction {
                scope: Some("@demo".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["logout", "--scope=demo"])).unwrap(),
        NpmCompatAction::Logout {
            action: NpmLogoutAction {
                scope: Some("demo".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "token",
            "list",
            "--parseable",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::List {
                json: true,
                parseable: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "token",
            "revoke",
            "a1b2c3",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::Revoke {
                token: "a1b2c3".to_owned(),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "token",
            "create",
            "--password",
            "correct-horse",
            "--name=ci-publish",
            "--token-description",
            "publish from CI",
            "--expires=30",
            "--packages=@demo/pkg",
            "--packages-all=false",
            "--scopes",
            "@demo",
            "--orgs=demo-org",
            "--packages-and-scopes-permission=read-write",
            "--orgs-permission",
            "read-only",
            "--cidr=192.0.2.0/24,198.51.100.0/24",
            "--bypass-2fa",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::Create {
                options: Box::new(NpmTokenCreateOptions {
                    password: Some("correct-horse".to_owned()),
                    name: Some("ci-publish".to_owned()),
                    description: Some("publish from CI".to_owned()),
                    expires: Some(30),
                    packages: vec!["@demo/pkg".to_owned()],
                    packages_all: false,
                    scopes: vec!["@demo".to_owned()],
                    orgs: vec!["demo-org".to_owned()],
                    packages_and_scopes_permission: Some("read-write".to_owned()),
                    orgs_permission: Some("read-only".to_owned()),
                    cidr: vec!["192.0.2.0/24".to_owned(), "198.51.100.0/24".to_owned()],
                    bypass_2fa: true,
                    read_only: false,
                }),
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--password=correct-horse",
            "--name",
            "ci-publish",
            "token",
            "create",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::Create {
                options: Box::new(NpmTokenCreateOptions {
                    password: Some("correct-horse".to_owned()),
                    name: Some("ci-publish".to_owned()),
                    ..NpmTokenCreateOptions::default()
                }),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["token", "create", "--cidr=2001:db8::/32"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "trust",
            "list",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Trust {
            action: NpmTrustAction::List {
                package: Some("@demo/pkg".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--dry-run",
            "trust",
            "github",
            "@demo/pkg",
            "--file",
            "release.yml",
            "--repo",
            "turenio/omc",
            "--env=prod",
        ]))
        .unwrap(),
        NpmCompatAction::Trust {
            action: NpmTrustAction::Create {
                provider: NpmTrustProvider::GitHub,
                package: Some("@demo/pkg".to_owned()),
                config: serde_json::json!({
                    "type": "github",
                    "claims": {
                        "repository": "turenio/omc",
                        "workflow_ref": {
                            "file": "release.yml",
                        },
                        "environment": "prod",
                    },
                }),
                dry_run: true,
                json: true,
                yes: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "profile",
            "get",
            "name,email",
            "github",
        ]))
        .unwrap(),
        NpmCompatAction::Profile {
            action: NpmProfileAction::Get {
                keys: vec!["name,email".to_owned(), "github".to_owned()],
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--parseable",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "--otp",
            "123456",
            "profile",
            "set",
            "fullname",
            "Alice",
            "Example",
        ]))
        .unwrap(),
        NpmCompatAction::Profile {
            action: NpmProfileAction::Set {
                property: "fullname".to_owned(),
                value: "Alice Example".to_owned(),
                json: false,
                parseable: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["profile", "set", "name", "alice"])).is_err());
    assert!(parse_npm_compat_action(&args(&["profile", "enable-2fa"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "owner",
            "ls",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Owner {
            action: NpmOwnerAction::List {
                spec: Some("left-pad".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "--otp",
            "123456",
            "owner",
            "add",
            "alice",
            "@scope/pkg",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Owner {
            action: NpmOwnerAction::Add {
                user: "alice".to_owned(),
                spec: Some("@scope/pkg".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["owner", "rm", "alice", "left-pad"])).unwrap(),
        NpmCompatAction::Owner {
            action: NpmOwnerAction::Remove {
                user: "alice".to_owned(),
                spec: Some("left-pad".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["owner", "add"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "access",
            "list",
            "packages",
            "@demo:publishers",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::ListPackages {
                owner: Some("@demo:publishers".to_owned()),
                package: Some("@demo/pkg".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "ls-collaborators", "@demo/pkg", "alice"]))
            .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::ListCollaborators {
                package: Some("@demo/pkg".to_owned()),
                user: Some("alice".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "get", "status", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::GetStatus {
                package: Some("@demo/pkg".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--otp=123456",
            "access",
            "set",
            "status=public",
            "@demo/pkg",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::SetStatus {
                package: Some("@demo/pkg".to_owned()),
                status: "public".to_owned(),
                json: true,
                npm_registry: None,
                userconfig: None,
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "restricted", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::SetStatus {
                package: Some("@demo/pkg".to_owned()),
                status: "private".to_owned(),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "set", "mfa=automation", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::SetMfa {
                package: Some("@demo/pkg".to_owned()),
                level: "automation".to_owned(),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "access",
            "grant",
            "read-write",
            "@demo:publishers",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::Grant {
                permission: "read-write".to_owned(),
                scope_team: "@demo:publishers".to_owned(),
                package: Some("@demo/pkg".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "access",
            "revoke",
            "@demo:publishers",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::Revoke {
                scope_team: "@demo:publishers".to_owned(),
                package: Some("@demo/pkg".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["access", "grant", "write"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "org",
            "set",
            "@demo",
            "alice",
            "admin",
        ]))
        .unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::Set {
                org: "@demo".to_owned(),
                user: "alice".to_owned(),
                role: Some("admin".to_owned()),
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["org", "add", "demo", "bob", "--parseable",])).unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::Set {
                org: "demo".to_owned(),
                user: "bob".to_owned(),
                role: None,
                json: false,
                parseable: true,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["org", "rm", "demo", "alice"])).unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::Remove {
                org: "demo".to_owned(),
                user: "alice".to_owned(),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["org", "ls", "demo", "alice"])).unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::List {
                org: "demo".to_owned(),
                user: Some("alice".to_owned()),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["org", "set", "demo", "alice", "writer"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "team",
            "create",
            "@demo:publishers",
        ]))
        .unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::Create {
                scope_team: "@demo:publishers".to_owned(),
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "team",
            "add",
            "@demo:publishers",
            "alice",
            "--parseable",
        ]))
        .unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::Add {
                scope_team: "@demo:publishers".to_owned(),
                user: "alice".to_owned(),
                json: false,
                parseable: true,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["team", "rm", "@demo:publishers", "alice"])).unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::Remove {
                scope_team: "@demo:publishers".to_owned(),
                user: "alice".to_owned(),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["team", "ls", "@demo:publishers"])).unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::List {
                scope_or_team: "@demo:publishers".to_owned(),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["team", "add", "@demo:publishers"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "dist-tag",
            "ls",
            "left-pad",
            "--json",
            "--workspace",
            "@demo/app",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::List {
                spec: Some("left-pad".to_owned()),
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["dist-tags", "react"])).unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::List {
                spec: Some("react".to_owned()),
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["dist-tag"])).unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::List {
                spec: None,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "--otp",
            "123456",
            "dist-tag",
            "add",
            "left-pad@1.3.0",
            "beta",
        ]))
        .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::Add {
                spec: "left-pad@1.3.0".to_owned(),
                tag: "beta".to_owned(),
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["dist-tag", "add", "left-pad@1.3.0", "--tag=next",]))
            .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::Add {
                spec: "left-pad@1.3.0".to_owned(),
                tag: "next".to_owned(),
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "dist-tag",
            "rm",
            "left-pad",
            "beta",
            "--otp=123456",
        ]))
        .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::Remove {
                spec: "left-pad".to_owned(),
                tag: "beta".to_owned(),
                npm_registry: None,
                userconfig: None,
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "sbom",
            "--sbom-format=cyclonedx",
            "--sbom-type",
            "application",
            "--package-lock-only",
            "--omit=dev",
            "--workspace",
            "@demo/app",
        ]))
        .unwrap(),
        NpmCompatAction::Sbom {
            action: NpmSbomAction {
                format: NpmSbomFormat::CycloneDx,
                sbom_type: NpmSbomType::Application,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--json", "sbom", "--sbom-format", "spdx"])).unwrap(),
        NpmCompatAction::Sbom {
            action: NpmSbomAction {
                format: NpmSbomFormat::Spdx,
                sbom_type: NpmSbomType::Library,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--sbom-format",
            "spdx",
            "--sbom-type=framework",
            "sbom",
        ]))
        .unwrap(),
        NpmCompatAction::Sbom {
            action: NpmSbomAction {
                format: NpmSbomFormat::Spdx,
                sbom_type: NpmSbomType::Framework,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["sbom"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "view",
            "left-pad@1.3.0",
            "version",
            "dist.tarball",
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::View {
            spec: "left-pad@1.3.0".to_owned(),
            fields: vec!["version".to_owned(), "dist.tarball".to_owned()],
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["info", "@scope/pkg", "versions"])).unwrap(),
        NpmCompatAction::View {
            spec: "@scope/pkg".to_owned(),
            fields: vec!["versions".to_owned()],
            json: false,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "repo",
            "left-pad",
            "--browser=false",
            "--json",
            "--registry=https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::MetadataUrl {
            kind: NpmMetadataUrlKind::Repo,
            spec: Some("left-pad".to_owned()),
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["docs", "--browser=false"])).unwrap(),
        NpmCompatAction::MetadataUrl {
            kind: NpmMetadataUrlKind::Docs,
            spec: None,
            json: false,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "get",
            "registry",
            "--json",
            "--userconfig",
            "ci.npmrc",
            "--location=project",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Get {
                keys: vec!["registry".to_owned()],
                json: true,
                location: NpmConfigLocation::Project,
            },
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "get",
            "prefix",
            "--registry",
            "https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Get {
                keys: vec!["prefix".to_owned()],
                json: false,
                location: NpmConfigLocation::User,
            },
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["config", "list", "--json", "--long"])).unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::List {
                json: true,
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "edit",
            "--location=project",
            "--editor",
            "true",
        ]))
        .unwrap(),
        NpmCompatAction::ConfigEdit {
            location: NpmConfigLocation::Project,
            editor: Some("true".to_owned()),
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "--location=project",
            "--editor=true",
            "edit",
        ]))
        .unwrap(),
        NpmCompatAction::ConfigEdit {
            location: NpmConfigLocation::Project,
            editor: Some("true".to_owned()),
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["config", "set", "registry", "x"])).unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![("registry".to_owned(), "x".to_owned())],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "set",
            "registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![(
                    "registry".to_owned(),
                    "https://registry.example.invalid/npm".to_owned(),
                )],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "set",
            "@scope:registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![(
                    "@scope:registry".to_owned(),
                    "https://registry.example.invalid/npm".to_owned(),
                )],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "set",
            "registry",
            "https://global.example.invalid/npm",
            "--location=global",
            "--globalconfig",
            "global.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![(
                    "registry".to_owned(),
                    "https://global.example.invalid/npm".to_owned(),
                )],
                location: NpmConfigLocation::Global,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: Some(PathBuf::from("global.npmrc")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["config", "delete", "registry"])).unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Delete {
                keys: vec!["registry".to_owned()],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: None,
        }
    );
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
fn parses_twine_upload_compat_flags() {
    assert_eq!(
        parse_twine_compat_action(&args(&["--version"])).unwrap(),
        TwineCompatAction::Version
    );
    assert_eq!(
        parse_twine_compat_action(&args(&["--help"])).unwrap(),
        TwineCompatAction::Help { topic: None }
    );
    assert_eq!(
        parse_twine_compat_action(&args(&["upload", "--help"])).unwrap(),
        TwineCompatAction::Help {
            topic: Some("upload".to_owned())
        }
    );
    assert_eq!(
        parse_twine_compat_action(&args(&["check", "--help"])).unwrap(),
        TwineCompatAction::Help {
            topic: Some("check".to_owned())
        }
    );
    assert_eq!(
        parse_twine_compat_action(&args(&[
            "check",
            "--strict",
            "--non-interactive",
            "dist/demo-1.0.0.tar.gz",
            "dist/demo-1.0.0-py3-none-any.whl",
        ]))
        .unwrap(),
        TwineCompatAction::Check(TwineCheckAction {
            paths: vec![
                PathBuf::from("dist/demo-1.0.0.tar.gz"),
                PathBuf::from("dist/demo-1.0.0-py3-none-any.whl"),
            ],
            strict: true,
        })
    );
    assert_eq!(
        parse_twine_compat_action(&args(&[
            "upload",
            "--repository-url",
            "https://upload.example/legacy/",
            "-u",
            "__token__",
            "-p",
            "pypi-token",
            "--config-file=release.pypirc",
            "--cert",
            "certs/ca.pem",
            "--client-cert=certs/client.pem",
            "--skip-existing",
            "--comment",
            "release upload",
            "--sign",
            "--sign-with",
            "gpg2",
            "--identity=release@example.com",
            "--attestations",
            "--non-interactive",
            "--disable-progress-bar",
            "dist/demo-1.0.0.tar.gz",
            "dist/demo-1.0.0-py3-none-any.whl",
        ]))
        .unwrap(),
        TwineCompatAction::Upload(Box::new(TwineUploadAction {
            paths: vec![
                PathBuf::from("dist/demo-1.0.0.tar.gz"),
                PathBuf::from("dist/demo-1.0.0-py3-none-any.whl"),
            ],
            repository: None,
            repository_url: Some("https://upload.example/legacy/".to_owned()),
            username: Some("__token__".to_owned()),
            password: Some("pypi-token".to_owned()),
            config_file: Some(PathBuf::from("release.pypirc")),
            cert: Some(PathBuf::from("certs/ca.pem")),
            client_cert: Some(PathBuf::from("certs/client.pem")),
            skip_existing: true,
            comment: Some("release upload".to_owned()),
            sign: true,
            sign_with: Some("gpg2".to_owned()),
            identity: Some("release@example.com".to_owned()),
            attestations: true,
        }))
    );
    assert!(print_twine_check(
        Path::new("."),
        TwineCheckAction {
            paths: Vec::new(),
            strict: false,
        },
    )
    .is_err());
}

#[test]
fn resolves_twine_upload_settings_from_pypirc() {
    let dir = test_dir("twine-pypirc");
    fs::write(
            dir.join("release.pypirc"),
            "[distutils]\nindex-servers =\n    private\n\n[private]\nrepository = https://upload.example/legacy/\nusername = __token__\npassword = pypi-token\nca_cert = certs/ca.pem\nclient_cert = certs/client.pem\n",
        )
        .unwrap();

    let settings = resolve_twine_upload_settings(
        &dir,
        &TwineUploadAction {
            paths: vec![PathBuf::from("dist/demo-1.0.0.tar.gz")],
            repository: Some("private".to_owned()),
            repository_url: None,
            username: None,
            password: None,
            config_file: Some(PathBuf::from("release.pypirc")),
            cert: None,
            client_cert: None,
            skip_existing: false,
            comment: None,
            sign: false,
            sign_with: None,
            identity: None,
            attestations: false,
        },
    )
    .unwrap();
    assert_eq!(settings.repository_url, "https://upload.example/legacy/");
    assert_eq!(settings.username, "__token__");
    assert_eq!(settings.password, "pypi-token");
    assert_eq!(settings.cert, Some(dir.join("certs/ca.pem")));
    assert_eq!(settings.client_cert, Some(dir.join("certs/client.pem")));

    let mtls_settings = resolve_twine_upload_settings(
        &dir,
        &TwineUploadAction {
            paths: vec![PathBuf::from("dist/demo-1.0.0.tar.gz")],
            repository: None,
            repository_url: Some("https://private.example/legacy/".to_owned()),
            username: None,
            password: None,
            config_file: None,
            cert: Some(PathBuf::from("certs/ca.pem")),
            client_cert: Some(PathBuf::from("certs/client.pem")),
            skip_existing: false,
            comment: None,
            sign: false,
            sign_with: None,
            identity: None,
            attestations: false,
        },
    )
    .unwrap();
    assert_eq!(
        mtls_settings.repository_url,
        "https://private.example/legacy/"
    );
    assert_eq!(mtls_settings.username, "");
    assert_eq!(mtls_settings.password, "");
    assert_eq!(mtls_settings.cert, Some(dir.join("certs/ca.pem")));
    assert_eq!(
        mtls_settings.client_cert,
        Some(dir.join("certs/client.pem"))
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn groups_twine_attestations_with_matching_distribution() {
    let dir = test_dir("twine-attestations");
    let dist = dir.join("dist/demo-1.0.0-py3-none-any.whl");
    let attestation = dir.join("dist/demo-1.0.0-py3-none-any.whl.publish.attestation");
    fs::create_dir_all(dist.parent().unwrap()).unwrap();
    fs::write(&dist, b"wheel").unwrap();
    fs::write(
        &attestation,
        r#"{"predicateType":"https://example.invalid/build"}"#,
    )
    .unwrap();

    let action = TwineUploadAction {
        paths: vec![
            PathBuf::from("dist/demo-1.0.0-py3-none-any.whl"),
            PathBuf::from("dist/demo-1.0.0-py3-none-any.whl.publish.attestation"),
        ],
        repository: None,
        repository_url: None,
        username: None,
        password: None,
        config_file: None,
        cert: None,
        client_cert: None,
        skip_existing: false,
        comment: None,
        sign: false,
        sign_with: None,
        identity: None,
        attestations: true,
    };

    let inputs = twine_upload_inputs(&dir, &action).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].path, dist);
    assert_eq!(inputs[0].attestation_paths, vec![attestation.clone()]);
    assert!(!twine_attestation_path(&dir.join("dist/demo.attestation")));
    assert_eq!(
        twine_upload_attestations_json(&inputs[0].path, &inputs[0].attestation_paths).unwrap(),
        r#"[{"predicateType":"https://example.invalid/build"}]"#
    );

    let missing = TwineUploadAction {
        paths: vec![PathBuf::from("dist/demo-1.0.0-py3-none-any.whl")],
        attestations: true,
        ..action
    };
    assert!(twine_upload_inputs(&dir, &missing)
        .unwrap_err()
        .to_string()
        .contains("has no associated attestations"));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn direct_twine_upload_paths_resolve_from_invocation_cwd() {
    let project = test_dir("direct-twine-project");
    let invocation_cwd = project.join("packages").join("publisher");
    let dist = invocation_cwd.join("dist/demo-1.0.0-py3-none-any.whl");
    let attestation = invocation_cwd.join("dist/demo-1.0.0-py3-none-any.whl.publish.attestation");
    fs::create_dir_all(dist.parent().unwrap()).unwrap();
    fs::create_dir_all(invocation_cwd.join("certs")).unwrap();
    fs::write(&dist, b"wheel").unwrap();
    fs::write(
        &attestation,
        r#"{"predicateType":"https://example.invalid/build"}"#,
    )
    .unwrap();

    let mut action = TwineUploadAction {
        paths: vec![
            PathBuf::from("dist/demo-1.0.0-py3-none-any.whl"),
            PathBuf::from("dist/demo-1.0.0-py3-none-any.whl.publish.attestation"),
        ],
        repository: None,
        repository_url: Some("https://private.example/legacy/".to_owned()),
        username: None,
        password: None,
        config_file: Some(PathBuf::from("release.pypirc")),
        cert: Some(PathBuf::from("certs/ca.pem")),
        client_cert: Some(PathBuf::from("certs/client.pem")),
        skip_existing: false,
        comment: None,
        sign: false,
        sign_with: None,
        identity: None,
        attestations: true,
    };

    absolutize_twine_upload_action_paths(&invocation_cwd, &mut action);

    let inputs = twine_upload_inputs(&project, &action).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].path, dist);
    assert_eq!(inputs[0].attestation_paths, vec![attestation]);
    assert_eq!(
        action.config_file,
        Some(invocation_cwd.join("release.pypirc"))
    );
    assert_eq!(action.cert, Some(invocation_cwd.join("certs/ca.pem")));
    assert_eq!(
        action.client_cert,
        Some(invocation_cwd.join("certs/client.pem"))
    );

    fs::remove_dir_all(project).unwrap();
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

fn locked_pypi_package(name: &str, version: &str, dependencies: Vec<String>) -> LockedPackage {
    LockedPackage {
        ecosystem: Ecosystem::Pypi,
        name: name.to_owned(),
        version: version.to_owned(),
        source_url: format!("https://files.example/{name}-{version}.whl"),
        archive: String::new(),
        artifact: String::new(),
        sha256: String::new(),
        artifact_sha256: String::new(),
        behavior: Behavior::Pure,
        verdict: Verdict::Accepted,
        dependencies,
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        grants: Vec::new(),
        capabilities: Vec::new(),
        verifier_findings: Vec::new(),
    }
}

fn locked_npm_package(name: &str, version: &str, dependencies: Vec<String>) -> LockedPackage {
    LockedPackage {
        ecosystem: Ecosystem::Npm,
        name: name.to_owned(),
        version: version.to_owned(),
        source_url: format!("https://registry.example/{name}/-/{name}-{version}.tgz"),
        archive: String::new(),
        artifact: String::new(),
        sha256: "a".repeat(64),
        artifact_sha256: String::new(),
        behavior: Behavior::Pure,
        verdict: Verdict::Accepted,
        dependencies,
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        grants: Vec::new(),
        capabilities: Vec::new(),
        verifier_findings: Vec::new(),
    }
}

fn locked_local_source(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    source_path: &str,
) -> LockedLocalSource {
    LockedLocalSource {
        ecosystem,
        name: name.to_owned(),
        version: version.to_owned(),
        source_url: format!("file:///{source_path}"),
        source_path: source_path.to_owned(),
        artifact: format!(".omc/artifacts/{}/{}/{}/omc.json", ecosystem, name, version),
        sha256: "b".repeat(64),
        behavior: Behavior::Pure,
        verdict: Verdict::Accepted,
        grants: Vec::new(),
        capabilities: Vec::new(),
        verifier_findings: Vec::new(),
    }
}

fn temp_test_dir() -> PathBuf {
    let mut path = env::temp_dir();
    path.push(format!(
        "omc-cli-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    path
}
