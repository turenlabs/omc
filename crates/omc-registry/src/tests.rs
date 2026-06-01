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

// Per-domain test modules (extracted from the original monolithic tests.rs).
mod config_tests;
mod lockfile_tests;
mod npm_tests;
mod npm_registry_tests;
mod policy_tests;
mod profiler_tests;
mod pypi_tests;
mod pypi_install_tests;
mod pypi_publish_tests;
mod verify_tests;
