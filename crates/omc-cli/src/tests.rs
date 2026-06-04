//! CLI unit tests — extracted verbatim from lib.rs.

use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn os_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

/// Point `$OMC_HOME` at a process-unique temp directory exactly once, so the
/// shared content store / caches that installs write never touch the
/// developer's real `~/.omc`. One isolated home shared across all (parallel)
/// tests in this binary is correct because the store is content-addressed
/// (keyed by artifact sha256) — identical bytes dedup, different bytes never
/// collide. The set runs under the env lock and only when OMC_HOME is unset, so
/// it neither races other env mutations nor overrides an explicit override.
fn isolate_omc_home() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        with_env_lock(|| {
            if env::var_os("OMC_HOME").is_none() {
                let home = env::temp_dir().join(format!("omc-cli-home-{}", std::process::id()));
                let _ = fs::create_dir_all(&home);
                env::set_var("OMC_HOME", home);
            }
        });
    });
}

fn test_dir(name: &str) -> PathBuf {
    isolate_omc_home();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("omc-cli-{name}-{nonce}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
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

mod agent_tests;
mod graph_tests;
mod inspect_tests;
mod misc_tests;
mod npm_compat_tests;
mod npm_config_tests;
mod npm_install_tests;
mod parse_npm_tests;
mod parse_pip_tests;
mod pip_compat_tests;
mod pip_config_tests;
mod policy_tests;
mod twine_tests;
