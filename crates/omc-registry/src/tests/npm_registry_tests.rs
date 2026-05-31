//! `npm_registry` domain tests, extracted from the original monolithic tests.rs.

use super::*;
use crate::*;

#[test]
fn parses_npm_search_response_packages() {
    let response = serde_json::from_str::<NpmSearchResponse>(
        r#"
            {
              "objects": [
                {
                  "package": {
                    "name": "pad-left",
                    "keywords": ["pad", "left"],
                    "version": "2.1.0",
                    "description": "Left pad a string",
                    "sanitized_name": "pad-left",
                    "publisher": {"username": "alice", "email": "alice@example.invalid"},
                    "maintainers": [{"username": "alice"}],
                    "license": "MIT",
                    "date": "2016-05-07T10:18:51.750Z",
                    "links": {"npm": "https://www.npmjs.com/package/pad-left"}
                  }
                }
              ]
            }
            "#,
    )
    .unwrap();

    assert_eq!(response.objects.len(), 1);
    let package = &response.objects[0].package;
    assert_eq!(package.name, "pad-left");
    assert_eq!(package.version, "2.1.0");
    assert_eq!(package.keywords, vec!["pad", "left"]);
    assert_eq!(
        package.links.get("npm").map(String::as_str),
        Some("https://www.npmjs.com/package/pad-left")
    );
}

#[test]
fn parses_npmrc_registry_and_auth_config() {
    let mut config = NpmConfig::default();
    parse_npmrc_content(
        r#"
            registry=https://registry.example.invalid/npm
            @scope:registry=https://scope.example.invalid/
            //scope.example.invalid/:_authToken=scope-token
            //registry.example.invalid/npm/:_authToken=default-token
            //registry.example.invalid:4873/npm/:_authToken=port-token
            "#,
        &mut config,
    );

    assert_eq!(config.registry, "https://registry.example.invalid/npm/");
    assert_eq!(
        config.registry_for("left-pad"),
        "https://registry.example.invalid/npm/"
    );
    assert_eq!(
        config.registry_for("@scope/pkg"),
        "https://scope.example.invalid/"
    );
    assert_eq!(
        config.auth_token_for_url("https://scope.example.invalid/@scope%2fpkg"),
        Some("scope-token")
    );
    assert_eq!(
        config.auth_token_for_url("https://registry.example.invalid/npm/left-pad/-/left-pad.tgz"),
        Some("default-token")
    );
    assert_eq!(
        config.auth_token_for_url(
            "https://registry.example.invalid:4873/npm/left-pad/-/left-pad.tgz"
        ),
        Some("port-token")
    );
}

#[test]
fn downloads_npm_package_tarball_with_userconfig_auth() {
    use std::io::Write as _;

    let tarball = npm_tgz_for_test(r#"{ "name": "demo-pkg", "version": "1.0.1" }"#);
    let expected = tarball.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let root = format!(
            r#"{{
                  "dist-tags": {{"latest": "1.0.1"}},
                  "versions": {{
                    "1.0.1": {{"name": "demo-pkg", "version": "1.0.1", "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-1.0.1.tgz"}}}}
                  }}
                }}"#
        );
        let version = format!(
            r#"{{
                  "name": "demo-pkg",
                  "version": "1.0.1",
                  "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-1.0.1.tgz"}}
                }}"#
        );

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                root.len(),
                root
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg/1.0.1 "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                version.len(),
                version
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg/-/demo-pkg-1.0.1.tgz "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                expected.len()
            );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&expected).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg@^1.0.0").unwrap();
    let result =
        download_npm_package_tarball(dir.path(), &spec, None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(result.metadata.name, "demo-pkg");
    assert_eq!(result.metadata.version, "1.0.1");
    assert_eq!(result.bytes, tarball);
    handle.join().unwrap();
}

#[test]
fn reads_npm_whoami_with_userconfig_auth() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let len = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..len]);
        assert!(request.starts_with("GET /-/whoami "));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let body = r#"{"username":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let whoami = read_npm_whoami(dir.path(), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(whoami.registry, format!("http://{addr}/"));
    assert_eq!(whoami.username, "alice");
    assert_eq!(
        whoami
            .response
            .get("username")
            .and_then(serde_json::Value::as_str),
        Some("alice")
    );
    handle.join().unwrap();
}

#[test]
fn reads_npm_profile_with_userconfig_auth() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/npm/v1/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let body = r#"{"name":"alice","email":"alice@example.invalid","email_verified":true,"tfa":{"pending":false,"mode":"auth-and-writes"},"fullname":"Alice Example","github":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let profile = read_npm_profile(dir.path(), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(profile.registry, format!("http://{addr}/"));
    assert_eq!(
        profile
            .profile
            .get("name")
            .and_then(serde_json::Value::as_str),
        Some("alice")
    );
    assert_eq!(
        profile
            .profile
            .get("tfa")
            .and_then(|tfa| tfa.get("mode"))
            .and_then(serde_json::Value::as_str),
        Some("auth-and-writes")
    );
    handle.join().unwrap();
}

#[test]
fn sets_npm_profile_property_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/npm/v1/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"name":"alice","email":"alice@example.invalid","fullname":"Alice Example","homepage":"","github":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/npm/v1/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["email"], "alice@example.invalid");
        assert_eq!(body["fullname"], "Alice Updated");
        assert_eq!(body["github"], "alice");

        let response_body = r#"{"name":"alice","email":"alice@example.invalid","fullname":"Alice Updated","homepage":"","github":"alice"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let result = set_npm_profile_property(
        dir.path(),
        "fullname",
        "Alice Updated",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.property, "fullname");
    assert_eq!(result.value, serde_json::json!("Alice Updated"));
    assert_eq!(result.status, 200);
    handle.join().unwrap();
}

#[test]
fn reads_npm_token_list_with_userconfig_auth() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let len = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..len]);
        assert!(request.starts_with("GET /-/npm/v1/tokens?perPage=1000 "));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let body = r#"{
              "objects": [
                {
                  "key": "a1b2c3",
                  "token": "npm_aBcD...7890",
                  "readonly": true,
                  "cidr": ["192.0.2.0/24"],
                  "created": "2026-05-23T00:00:00Z"
                }
              ],
              "total": 1,
              "urls": {"next": "https://registry.example.invalid/-/npm/v1/tokens?page=1"}
            }"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let list = read_npm_token_list(dir.path(), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(list.registry, format!("http://{addr}/"));
    assert_eq!(list.total, Some(1));
    assert_eq!(list.tokens.len(), 1);
    assert_eq!(list.tokens[0].key.as_deref(), Some("a1b2c3"));
    assert_eq!(list.tokens[0].readonly, Some(true));
    assert_eq!(list.tokens[0].cidr, vec!["192.0.2.0/24"]);
    assert_eq!(
        list.urls.get("next").map(String::as_str),
        Some("https://registry.example.invalid/-/npm/v1/tokens?page=1")
    );
    handle.join().unwrap();
}

#[test]
fn creates_npm_token_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/npm/v1/tokens "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["password"], "correct-horse");
        assert_eq!(body["name"], "ci-publish");
        assert_eq!(body["description"], "publish from CI");
        assert_eq!(body["expires"], 30);
        assert_eq!(body["packages"], serde_json::json!(["@demo/pkg"]));
        assert_eq!(body["packages_all"], true);
        assert_eq!(body["scopes"], serde_json::json!(["@demo"]));
        assert_eq!(body["orgs"], serde_json::json!(["demo-org"]));
        assert_eq!(body["packages_and_scopes_permission"], "read-write");
        assert_eq!(body["orgs_permission"], "read-only");
        assert_eq!(body["cidr_whitelist"], serde_json::json!(["192.0.2.0/24"]));
        assert_eq!(body["bypass_2fa"], true);

        let response_body = r#"{
              "key": "a1b2c3",
              "token": "npm_full_created_token",
              "readonly": false,
              "cidr_whitelist": ["192.0.2.0/24"],
              "created": "2026-05-23T00:00:00Z",
              "expires": "2026-06-22T00:00:00Z",
              "updated": "2026-05-23T00:00:00Z"
            }"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let created = create_npm_token(
        dir.path(),
        NpmTokenCreateOptions {
            password: Some("correct-horse".to_owned()),
            name: Some("ci-publish".to_owned()),
            description: Some("publish from CI".to_owned()),
            expires: Some(30),
            packages: vec!["@demo/pkg".to_owned()],
            packages_all: true,
            scopes: vec!["@demo".to_owned()],
            orgs: vec!["demo-org".to_owned()],
            packages_and_scopes_permission: Some("read-write".to_owned()),
            orgs_permission: Some("read-only".to_owned()),
            cidr: vec!["192.0.2.0/24".to_owned()],
            bypass_2fa: true,
            read_only: false,
        },
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(created.registry, format!("http://{addr}/"));
    assert_eq!(created.status, 201);
    assert_eq!(
        created.token.token.as_deref(),
        Some("npm_full_created_token")
    );
    assert_eq!(created.token.cidr, vec!["192.0.2.0/24"]);
    assert_eq!(
        created.token.expiry.as_deref(),
        Some("2026-06-22T00:00:00Z")
    );
    handle.join().unwrap();
}

#[test]
fn revokes_npm_token_with_userconfig_auth_and_otp() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let len = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..len]);
        assert!(request.starts_with("DELETE /-/npm/v1/tokens/token/a1b2c3 "));
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let revoked = revoke_npm_token(
        dir.path(),
        "a1b2c3",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(revoked.registry, format!("http://{addr}/"));
    assert_eq!(revoked.token, "a1b2c3");
    assert_eq!(revoked.status, 204);
    handle.join().unwrap();
}

#[test]
fn reads_and_sets_npm_access_status_and_mfa() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/package/%40demo%2Fpkg/visibility "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"public":false}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/package/%40demo%2Fpkg/access "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"access": "public"}));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("POST /-/package/%40demo%2Fpkg/access "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "publish_requires_tfa": true,
                "automation_token_overrides_tfa": true
            })
        );
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let status =
        read_npm_access_status(dir.path(), "@demo/pkg", None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(status.registry, format!("http://{addr}/"));
    assert_eq!(status.package, "@demo/pkg");
    assert_eq!(status.status, "private");

    let changed = set_npm_access_status(
        dir.path(),
        "@demo/pkg",
        "public",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(changed.registry, format!("http://{addr}/"));
    assert_eq!(changed.package, "@demo/pkg");
    assert_eq!(changed.action, "status");
    assert_eq!(changed.status, 200);
    assert_eq!(changed.response["ok"], true);

    let mfa = set_npm_access_mfa(
        dir.path(),
        "@demo/pkg",
        "automation",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(mfa.action, "mfa");
    assert_eq!(mfa.status, 202);
    handle.join().unwrap();
}

#[test]
fn lists_and_mutates_npm_access_team_permissions() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/team/demo/publishers/package "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"@demo/pkg":"write","@demo/readme":"read"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/package/%40demo%2Fpkg/collaborators "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"alice":"write","bob":"read"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/team/demo/publishers/package "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "package": "@demo/pkg",
                "permissions": "read-write"
            })
        );
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/team/demo/publishers/package "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"package": "@demo/pkg"}));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let packages = read_npm_access_packages(
        dir.path(),
        "@demo:publishers",
        None,
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(packages.registry, format!("http://{addr}/"));
    assert_eq!(
        packages.items.get("@demo/pkg").map(String::as_str),
        Some("read-write")
    );
    assert_eq!(
        packages.items.get("@demo/readme").map(String::as_str),
        Some("read-only")
    );

    let collaborators = read_npm_access_collaborators(
        dir.path(),
        "@demo/pkg",
        Some("bob"),
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(collaborators.package.as_deref(), Some("@demo/pkg"));
    assert_eq!(collaborators.items.len(), 1);
    assert_eq!(
        collaborators.items.get("bob").map(String::as_str),
        Some("read-only")
    );

    let grant = grant_npm_access(
        dir.path(),
        "@demo:publishers",
        "@demo/pkg",
        "read-write",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(grant.action, "grant");
    assert_eq!(grant.status, 201);

    let revoke = revoke_npm_access(
        dir.path(),
        "@demo:publishers",
        "@demo/pkg",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(revoke.action, "revoke");
    assert_eq!(revoke.status, 204);
    handle.join().unwrap();
}

#[test]
fn manages_npm_org_members_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/org/demo/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "alice", "role": "admin"}));
        let response_body = r#"{"org":{"name":"demo","size":2},"user":"alice","role":"admin"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/org/demo/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"alice":"admin","bob":"developer"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/org/demo/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "bob"}));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/org/demo/user "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{"alice":"admin"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let set = set_npm_org_user(
        dir.path(),
        "@demo",
        "@alice",
        Some("admin"),
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(set.registry, format!("http://{addr}/"));
    assert_eq!(set.action, "set");
    assert_eq!(set.org, "demo");
    assert_eq!(set.user, "alice");
    assert_eq!(set.role.as_deref(), Some("admin"));
    assert_eq!(set.user_count, Some(2));
    assert_eq!(set.status, 200);

    let users = read_npm_org_users(
        dir.path(),
        "demo",
        Some("alice"),
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(users.org, "demo");
    assert_eq!(users.users.len(), 1);
    assert_eq!(users.users.get("alice").map(String::as_str), Some("admin"));

    let removed = remove_npm_org_user(
        dir.path(),
        "demo",
        "~bob",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(removed.action, "rm");
    assert_eq!(removed.user, "bob");
    assert_eq!(removed.user_count, Some(1));
    assert_eq!(removed.status, 204);
    handle.join().unwrap();
}

#[test]
fn manages_npm_teams_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/org/demo/team "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["name"], "publishers");
        assert!(body["description"].is_null());
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/team/demo/publishers/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "alice"}));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/org/demo/team?format=cli "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"["publishers","readers"]"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/team/demo/publishers/user?format=cli "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"[{"name":"alice"},{"name":"bob"}]"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/team/demo/publishers/user "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body, serde_json::json!({"user": "alice"}));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/team/demo/publishers "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let created = create_npm_team(
        dir.path(),
        "@demo:publishers",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(created.registry, format!("http://{addr}/"));
    assert_eq!(created.scope, "demo");
    assert_eq!(created.team, "publishers");
    assert_eq!(created.action, "create");
    assert_eq!(created.status, 201);

    let added = add_npm_team_user(
        dir.path(),
        "@demo:publishers",
        "alice",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(added.user.as_deref(), Some("alice"));
    assert_eq!(added.action, "add");
    assert_eq!(added.status, 200);

    let teams = read_npm_teams(dir.path(), "@demo", None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(teams.scope, "demo");
    assert_eq!(teams.items, vec!["publishers", "readers"]);

    let users = read_npm_team_users(
        dir.path(),
        "@demo:publishers",
        None,
        Some(Path::new("ci.npmrc")),
    )
    .unwrap();
    assert_eq!(users.team.as_deref(), Some("publishers"));
    assert_eq!(users.items, vec!["alice", "bob"]);

    let removed = remove_npm_team_user(
        dir.path(),
        "@demo:publishers",
        "alice",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(removed.action, "rm");
    assert_eq!(removed.status, 204);

    let destroyed = destroy_npm_team(
        dir.path(),
        "@demo:publishers",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(destroyed.action, "destroy");
    assert_eq!(destroyed.status, 204);
    handle.join().unwrap();
}

#[test]
fn mutates_npm_dist_tags_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /-/package/demo-pkg/dist-tags/beta "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body = String::from_utf8_lossy(&buffer[body_start..]);
        assert_eq!(body, "\"1.0.0\"");

        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /-/package/demo-pkg/dist-tags/beta "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let added = add_npm_dist_tag(
        dir.path(),
        "demo-pkg",
        "1.0.0",
        "beta",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(added.registry, format!("http://{addr}/"));
    assert_eq!(added.package, "demo-pkg");
    assert_eq!(added.version.as_deref(), Some("1.0.0"));
    assert_eq!(added.tag, "beta");
    assert_eq!(added.status, 201);
    assert_eq!(added.response["ok"], true);

    let removed = remove_npm_dist_tag(
        dir.path(),
        "demo-pkg",
        "beta",
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(removed.registry, format!("http://{addr}/"));
    assert_eq!(removed.package, "demo-pkg");
    assert_eq!(removed.version, None);
    assert_eq!(removed.tag, "beta");
    assert_eq!(removed.status, 204);
    assert_eq!(removed.response, serde_json::Value::Null);
    handle.join().unwrap();
}

#[test]
fn deprecates_npm_versions_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));

        let packument = r#"{
              "name": "demo-pkg",
              "versions": {
                "1.0.0": {"name": "demo-pkg", "version": "1.0.0"},
                "1.1.0": {"name": "demo-pkg", "version": "1.1.0"},
                "2.0.0": {"name": "demo-pkg", "version": "2.0.0", "deprecated": "old"}
              },
              "dist-tags": {"latest": "2.0.0"}
            }"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["versions"]["1.0.0"]["deprecated"], "old line");
        assert_eq!(body["versions"]["1.1.0"]["deprecated"], "old line");
        assert_eq!(body["versions"]["2.0.0"]["deprecated"], "old");

        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg@1.x").unwrap();
    let result = deprecate_npm_package(
        dir.path(),
        &spec,
        "old line",
        false,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.package, "demo-pkg");
    assert_eq!(result.requirement, "1.x");
    assert_eq!(result.message, "old line");
    assert_eq!(result.versions, vec!["1.0.0", "1.1.0"]);
    assert_eq!(result.status, Some(200));
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn unpublishes_npm_version_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let packument = format!(
            r#"{{
                  "_id": "demo-pkg",
                  "_rev": "1-abc",
                  "_revisions": {{"start": 1}},
                  "_attachments": {{"demo-pkg-1.0.0.tgz": {{}}}},
                  "name": "demo-pkg",
                  "versions": {{
                    "1.0.0": {{"name": "demo-pkg", "version": "1.0.0", "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-1.0.0.tgz"}}}},
                    "2.0.0": {{"name": "demo-pkg", "version": "2.0.0", "dist": {{"tarball": "http://{addr}/demo-pkg/-/demo-pkg-2.0.0.tgz"}}}}
                  }},
                  "dist-tags": {{"latest": "2.0.0", "beta": "1.0.0", "old": "1.0.0"}}
                }}"#
        );

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg/-rev/1-abc "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert!(body["versions"].get("1.0.0").is_none());
        assert!(body.get("_revisions").is_none());
        assert!(body.get("_attachments").is_none());
        assert_eq!(body["dist-tags"], serde_json::json!({"latest": "2.0.0"}));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let fresh_packument = r#"{
              "_id": "demo-pkg",
              "_rev": "2-def",
              "name": "demo-pkg",
              "versions": {
                "2.0.0": {"name": "demo-pkg", "version": "2.0.0"}
              },
              "dist-tags": {"latest": "2.0.0"}
            }"#;
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                fresh_packument.len(),
                fresh_packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /demo-pkg/-/demo-pkg-1.0.0.tgz/-rev/2-def "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg@1.0.0").unwrap();
    let result = unpublish_npm_package(
        dir.path(),
        &spec,
        false,
        false,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.package, "demo-pkg");
    assert_eq!(result.version.as_deref(), Some("1.0.0"));
    assert_eq!(result.removed_versions, vec!["1.0.0"]);
    assert!(!result.whole_package);
    assert!(result.changed);
    assert_eq!(result.status, Some(201));
    assert_eq!(result.tarball_status, Some(204));
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn force_unpublishes_entire_npm_package() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "1-abc",
              "name": "demo-pkg",
              "versions": {
                "1.0.0": {"name": "demo-pkg", "version": "1.0.0"}
              },
              "dist-tags": {"latest": "1.0.0"}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("DELETE /demo-pkg/-rev/1-abc "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg").unwrap();
    let result = unpublish_npm_package(
        dir.path(),
        &spec,
        false,
        true,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.package, "demo-pkg");
    assert_eq!(result.version, None);
    assert_eq!(result.removed_versions, vec!["1.0.0"]);
    assert!(result.whole_package);
    assert!(result.changed);
    assert_eq!(result.status, Some(202));
    assert_eq!(result.tarball_status, None);
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn reads_and_mutates_npm_owners_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "1-abc",
              "name": "demo-pkg",
              "maintainers": [
                {"name": "alice", "email": "alice@example.invalid"},
                {"name": "bob", "email": "bob@example.invalid"}
              ],
              "versions": {"1.0.0": {"name": "demo-pkg", "version": "1.0.0"}}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/user/org.couchdb.user:carol "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let user = r#"{"name":"carol","email":"carol@example.invalid"}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                user.len(),
                user
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg/-rev/1-abc "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["_rev"], "1-abc");
        assert_eq!(
            body["maintainers"],
            serde_json::json!([
                {"name": "alice", "email": "alice@example.invalid"},
                {"name": "bob", "email": "bob@example.invalid"},
                {"name": "carol", "email": "carol@example.invalid"}
            ])
        );
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg").unwrap();
    let owners =
        read_npm_package_owners(dir.path(), &spec, None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(owners.registry, format!("http://{addr}/"));
    assert_eq!(owners.package, "demo-pkg");
    assert_eq!(owners.owners.len(), 2);
    assert_eq!(owners.owners[0].username.as_deref(), Some("alice"));
    assert_eq!(
        owners.owners[0].email.as_deref(),
        Some("alice@example.invalid")
    );

    let mutation = mutate_npm_package_owner(
        dir.path(),
        &spec,
        "carol",
        true,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(mutation.registry, format!("http://{addr}/"));
    assert_eq!(mutation.package, "demo-pkg");
    assert_eq!(mutation.user, "carol");
    assert!(mutation.added);
    assert!(mutation.changed);
    assert_eq!(mutation.status, Some(201));
    assert_eq!(mutation.owners.len(), 3);
    assert_eq!(mutation.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn stars_and_unstars_npm_packages_with_userconfig_auth_and_otp() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let whoami = r#"{"username":"alice"}"#;
        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "1-abc",
              "name": "demo-pkg",
              "users": {"bob": true}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/whoami "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                whoami.len(),
                whoami
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["_rev"], "1-abc");
        assert_eq!(body["users"]["alice"], true);
        assert_eq!(body["users"]["bob"], true);
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();

        let packument = r#"{
              "_id": "demo-pkg",
              "_rev": "2-def",
              "name": "demo-pkg",
              "users": {"alice": true, "bob": true}
            }"#;

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/whoami "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                whoami.len(),
                whoami
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /demo-pkg?write=true "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                packument.len(),
                packument
            );
        stream.write_all(response.as_bytes()).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));
        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["_rev"], "2-def");
        assert!(body["users"].get("alice").is_none());
        assert_eq!(body["users"]["bob"], true);
        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let spec = PackageSpec::parse("npm:demo-pkg").unwrap();
    let starred = mutate_npm_package_star(
        dir.path(),
        &spec,
        true,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(starred.registry, format!("http://{addr}/"));
    assert_eq!(starred.package, "demo-pkg");
    assert_eq!(starred.user, "alice");
    assert!(starred.starred);
    assert_eq!(starred.status, 200);
    assert_eq!(starred.response["ok"], true);

    let unstarred = mutate_npm_package_star(
        dir.path(),
        &spec,
        false,
        None,
        Some(Path::new("ci.npmrc")),
        Some("123456"),
    )
    .unwrap();
    assert_eq!(unstarred.registry, format!("http://{addr}/"));
    assert_eq!(unstarred.package, "demo-pkg");
    assert_eq!(unstarred.user, "alice");
    assert!(!unstarred.starred);
    assert_eq!(unstarred.status, 200);
    assert_eq!(unstarred.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn reads_npm_stars_with_userconfig_auth() {
    use std::io::Write as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let buffer = read_http_request_bytes(&mut stream);
        let body_start = http_body_start(&buffer).unwrap();
        let headers = String::from_utf8_lossy(&buffer[..body_start]);
        assert!(headers.starts_with("GET /-/_view/starredByUser?key=%22alice%22 "));
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer registry-token"));
        let body = r#"{
              "rows": [
                {"value": "left-pad"},
                {"value": "@demo/pkg"},
                {"value": 42}
              ]
            }"#;
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let result =
        read_npm_stars(dir.path(), Some("alice"), None, Some(Path::new("ci.npmrc"))).unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.user, "alice");
    assert_eq!(result.packages, vec!["left-pad", "@demo/pkg"]);
    assert!(result.response.get("rows").is_some());
    handle.join().unwrap();
}

#[test]
fn publishes_npm_package_with_userconfig_auth_and_otp() {
    use std::io::{Read as _, Write as _};

    let tarball = npm_tgz_for_test(r#"{"name":"demo-pkg","version":"1.0.0"}"#);
    let expected_tarball = tarball.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
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
        assert!(headers.starts_with("PUT /demo-pkg "));
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer registry-token"));
        assert!(lower.contains("npm-otp: 123456"));

        let body: serde_json::Value = serde_json::from_slice(&buffer[body_start..]).unwrap();
        assert_eq!(body["_id"], "demo-pkg");
        assert_eq!(body["dist-tags"]["beta"], "1.0.0");
        assert_eq!(body["versions"]["1.0.0"]["name"], "demo-pkg");
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["shasum"],
            sha1_hex(&expected_tarball)
        );
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["integrity"],
            npm_publish_integrity(&expected_tarball)
        );
        let encoded = body["_attachments"]["demo-pkg-1.0.0.tgz"]["data"]
            .as_str()
            .unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap(), expected_tarball);
        assert_eq!(
            body["_attachments"]["demo-pkg-1.0.0.sigstore"]["content_type"],
            "application/vnd.dev.sigstore.bundle+json;version=0.3"
        );
        assert_eq!(
            body["_attachments"]["demo-pkg-1.0.0.sigstore"]["data"],
            r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{"payload":"e30="}}"#
        );

        let response_body = r#"{"ok":true}"#;
        let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        format!("registry=http://{addr}/\n//{addr}/:_authToken=registry-token\n"),
    )
    .unwrap();

    let result = publish_npm_package(
            dir.path(),
            NpmPublishPackage {
                name: "demo-pkg".to_owned(),
                version: "1.0.0".to_owned(),
                manifest: serde_json::json!({
                    "name": "demo-pkg",
                    "version": "1.0.0",
                    "description": "demo",
                }),
                filename: "demo-pkg-1.0.0.tgz".to_owned(),
                tarball,
                tag: "beta".to_owned(),
                access: Some("public".to_owned()),
                provenance: Some(NpmProvenanceBundle {
                    media_type: "application/vnd.dev.sigstore.bundle+json;version=0.3".to_owned(),
                    data: r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{"payload":"e30="}}"#.to_owned(),
                }),
            },
            None,
            Some(Path::new("ci.npmrc")),
            Some("123456"),
        )
        .unwrap();
    assert_eq!(result.registry, format!("http://{addr}/"));
    assert_eq!(result.name, "demo-pkg");
    assert_eq!(result.version, "1.0.0");
    assert_eq!(result.tag, "beta");
    assert_eq!(result.status, 201);
    assert_eq!(result.response["ok"], true);
    handle.join().unwrap();
}

#[test]
fn npm_options_override_default_registry() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".npmrc"),
        "registry=https://npmrc.example.invalid/\n",
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options.npm_registry_url = Some("https://cli.example.invalid/npm".to_owned());
    let config = read_npm_config_for_options(dir.path(), &options).unwrap();

    assert_eq!(config.registry, "https://cli.example.invalid/npm/");
}

#[test]
fn npm_environment_overrides_npmrc_registry() {
    let mut config = NpmConfig::default();
    parse_npmrc_content("registry=https://npmrc.example.invalid/\n", &mut config);

    apply_npm_environment_values(&mut config, Some("https://env.example.invalid/npm"));

    assert_eq!(config.registry, "https://env.example.invalid/npm/");
}

#[test]
fn npm_userconfig_override_reads_custom_user_npmrc() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("ci.npmrc"),
        "registry=https://ci-userconfig.example.invalid/npm\n",
    )
    .unwrap();

    let mut config = NpmConfig::default();
    read_npm_user_config(dir.path(), Some(Path::new("ci.npmrc")), &mut config).unwrap();

    assert_eq!(
        config.registry,
        "https://ci-userconfig.example.invalid/npm/"
    );
}

#[test]
fn npm_globalconfig_reads_before_user_and_project_npmrc() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("global.npmrc"),
        "registry=https://global.example.invalid/npm\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("user.npmrc"),
        "@scope:registry=https://scope.example.invalid/npm\n",
    )
    .unwrap();
    fs::write(dir.path().join(".npmrc"), "legacy-peer-deps=true\n").unwrap();

    let snapshot = read_npm_config_snapshot_with_globalconfig(
        dir.path(),
        None,
        Some(Path::new("user.npmrc")),
        Some(Path::new("global.npmrc")),
    )
    .unwrap();

    assert_eq!(snapshot.registry, "https://global.example.invalid/npm/");
    assert_eq!(
        snapshot.scoped_registries.get("@scope").map(String::as_str),
        Some("https://scope.example.invalid/npm/")
    );
}
