//! `pypi_publish` domain tests, extracted from the original monolithic tests.rs.

use super::*;

#[test]
fn uploads_pypi_wheel_with_basic_auth_and_metadata() {
    use std::io::{Read as _, Write as _};

    let wheel = python_wheel_for_test(
            "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\nSummary: demo package\n\nLong description\n",
        );
    let expected_digest = sha256_hex(&wheel);
    let dir = tempfile::tempdir().unwrap();
    let wheel_path = dir.path().join("demo_pkg-1.0.0-py3-none-any.whl");
    fs::write(&wheel_path, &wheel).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_expected_digest = expected_digest.clone();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
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

        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /legacy/ "));
        let lower = headers.to_ascii_lowercase();
        let expected_auth = format!(
            "authorization: basic {}",
            STANDARD.encode("__token__:pypi-token")
        )
        .to_ascii_lowercase();
        assert!(lower.contains(&expected_auth));

        let body = String::from_utf8_lossy(&buffer[body_start..]);
        assert!(body.contains(r#"name=":action""#));
        assert!(body.contains("file_upload"));
        assert!(body.contains(r#"name="protocol_version""#));
        assert!(body.contains(r#"name="metadata_version""#));
        assert!(body.contains(r#"name="name""#));
        assert!(body.contains("demo-pkg"));
        assert!(body.contains(r#"name="version""#));
        assert!(body.contains("1.0.0"));
        assert!(body.contains(r#"name="filetype""#));
        assert!(body.contains("bdist_wheel"));
        assert!(body.contains(r#"name="pyversion""#));
        assert!(body.contains("py3"));
        assert!(body.contains(r#"name="sha256_digest""#));
        assert!(body.contains(&server_expected_digest));
        assert!(body.contains(r#"name="comment""#));
        assert!(body.contains("release upload"));
        assert!(body.contains(r#"name="attestations""#));
        assert!(body.contains("predicateType"));
        assert!(body.contains("https://example.invalid/build"));
        assert!(body.contains(r#"filename="demo_pkg-1.0.0-py3-none-any.whl""#));
        assert!(body.contains(r#"name="gpg_signature""#));
        assert!(body.contains(r#"filename="demo_pkg-1.0.0-py3-none-any.whl.asc""#));
        assert!(body.contains("fake-signature"));

        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let result = upload_pypi_distribution(
        &format!("http://{addr}/legacy/"),
        "__token__",
        "pypi-token",
        &wheel_path,
        PypiUploadOptions {
            comment: Some("release upload"),
            signature: Some(PypiUploadSignature {
                filename: "demo_pkg-1.0.0-py3-none-any.whl.asc",
                bytes: b"fake-signature",
            }),
            attestations: Some(r#"[{"predicateType":"https://example.invalid/build"}]"#),
            ..PypiUploadOptions::default()
        },
    )
    .unwrap();
    assert_eq!(result.repository_url, format!("http://{addr}/legacy/"));
    assert_eq!(result.filename, "demo_pkg-1.0.0-py3-none-any.whl");
    assert_eq!(result.name, "demo-pkg");
    assert_eq!(result.version, "1.0.0");
    assert_eq!(result.filetype, "bdist_wheel");
    assert_eq!(result.pyversion, "py3");
    assert_eq!(result.status, 200);
    assert_eq!(result.sha256_digest, expected_digest);
    assert!(!result.skipped);
    handle.join().unwrap();
}

#[test]
fn checks_pypi_distribution_metadata_warnings_and_strict_mode() {
    let dir = tempfile::tempdir().unwrap();

    let clean_wheel = python_wheel_for_test(
            "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\nDescription-Content-Type: text/markdown\n\n# Long description\n",
        );
    let clean_path = dir.path().join("demo_pkg-1.0.0-py3-none-any.whl");
    fs::write(&clean_path, clean_wheel).unwrap();
    let clean = check_pypi_distribution(&clean_path, true).unwrap();
    assert!(clean.passed);
    assert!(clean.warnings.is_empty());

    let warning_wheel =
        python_wheel_for_test("Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.1\n\n");
    let warning_path = dir.path().join("demo_pkg-1.0.1-py3-none-any.whl");
    fs::write(&warning_path, warning_wheel).unwrap();
    let relaxed = check_pypi_distribution(&warning_path, false).unwrap();
    assert!(relaxed.passed);
    assert!(relaxed
        .warnings
        .iter()
        .any(|warning| warning.contains("long_description_content_type")));
    assert!(relaxed
        .warnings
        .iter()
        .any(|warning| warning.contains("long_description")));

    let strict = check_pypi_distribution(&warning_path, true).unwrap();
    assert!(!strict.passed);
    assert_eq!(strict.warnings, relaxed.warnings);
}

#[test]
fn recognizes_pypi_existing_upload_responses() {
    assert!(pypi_upload_response_is_existing(409, ""));
    assert!(pypi_upload_response_is_existing(
        400,
        "File already exists. See https://pypi.org/help/#file-name-reuse"
    ));
    assert!(!pypi_upload_response_is_existing(403, "Forbidden"));
}
