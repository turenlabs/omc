use crate::*;
use super::*;

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
