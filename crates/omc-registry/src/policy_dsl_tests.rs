//! `policy_dsl_tests` unit tests — extracted verbatim from lib.rs.

use super::*;

/// A base policy mimicking what the flat `omc.toml [policy]` / CLI grants
/// would produce: just the public env reads, no host capabilities.
fn base_policy() -> Policy {
    policy_from_link_options(&LinkOptions::new("."))
}

fn write_policy(dir: &Path, src: &str) {
    std::fs::write(dir.join(POLICY_FILE), src).unwrap();
}

#[test]
fn no_policy_file_returns_base_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load_policy_document(dir.path()).unwrap().is_none());
    let effective = effective_package_policy(
        dir.path(),
        base_policy(),
        Ecosystem::Npm,
        "left-pad",
        "1.3.0",
    )
    .unwrap();
    // Identical to today's behaviour: only the default public env reads.
    assert_eq!(
        effective.allowed_capabilities,
        base_policy().allowed_capabilities
    );
    assert!(effective.allowed_flows.is_empty());
    assert!(!effective.sensitive_reads_allowed());
}

#[test]
fn matching_package_block_grants_are_layered_on() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"
            npm package "stripe" >=12.0.0 {
                allow env "STRIPE_API_KEY"
                allow net "api.stripe.com"
                flow env "STRIPE_API_KEY" -> net "api.stripe.com"
            }
            "#,
    );
    let effective = effective_package_policy(
        dir.path(),
        base_policy(),
        Ecosystem::Npm,
        "stripe",
        "13.1.0",
    )
    .unwrap();
    assert!(effective
        .allowed_capabilities
        .contains(&Capability::EnvRead("STRIPE_API_KEY".to_owned())));
    assert!(effective
        .allowed_capabilities
        .contains(&Capability::HttpHost("api.stripe.com".to_owned())));
    assert_eq!(effective.allowed_flows.len(), 1);
    // The base public env read is preserved (the flat grants stay as the
    // default baseline beneath the DSL).
    assert!(effective
        .allowed_capabilities
        .contains(&Capability::EnvRead("NODE_DEBUG".to_owned())));
}

#[test]
fn non_matching_version_leaves_package_denied() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"
            npm package "stripe" >=12.0.0 { allow net "api.stripe.com" }
            "#,
    );
    // stripe@11 does not satisfy >=12.0.0, so it gets only the base policy.
    let effective = effective_package_policy(
        dir.path(),
        base_policy(),
        Ecosystem::Npm,
        "stripe",
        "11.4.0",
    )
    .unwrap();
    assert!(!effective
        .allowed_capabilities
        .contains(&Capability::HttpHost("api.stripe.com".to_owned())));
}

#[test]
fn pure_block_resets_default_grants_for_that_package() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"
            default { allow time, random }
            package "is-odd" { pure }
            "#,
    );
    // is-odd is reset to pure; even the default time/random are dropped.
    let effective =
        effective_package_policy(dir.path(), base_policy(), Ecosystem::Npm, "is-odd", "1.0.0")
            .unwrap();
    assert!(!effective
        .allowed_capabilities
        .contains(&Capability::TimeNow));
    assert!(!effective
        .allowed_capabilities
        .contains(&Capability::RandomBytes));
    // A different package still picks up the default baseline.
    let other = effective_package_policy(
        dir.path(),
        base_policy(),
        Ecosystem::Npm,
        "left-pad",
        "1.0.0",
    )
    .unwrap();
    assert!(other.allowed_capabilities.contains(&Capability::TimeNow));
}

#[test]
fn deny_removes_a_matching_default_grant() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"
            default { allow net "*" }
            npm package "is-odd" { deny net "*" }
            "#,
    );
    let effective =
        effective_package_policy(dir.path(), base_policy(), Ecosystem::Npm, "is-odd", "1.0.0")
            .unwrap();
    assert!(!effective
        .allowed_capabilities
        .iter()
        .any(|cap| matches!(cap, Capability::HttpHost(_))));
}

#[test]
fn allow_sensitive_lifts_the_guard() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"
            npm package "creds" {
                allow read "*"
                allow-sensitive
            }
            "#,
    );
    let effective =
        effective_package_policy(dir.path(), base_policy(), Ecosystem::Npm, "creds", "1.0.0")
            .unwrap();
    assert!(effective.sensitive_reads_allowed());
}

#[test]
fn ecosystem_qualifier_scopes_the_block() {
    let dir = tempfile::tempdir().unwrap();
    write_policy(
        dir.path(),
        r#"
            npm package "shared" { allow net "npm.example" }
            "#,
    );
    // The npm-qualified block does not apply to a PyPI package of the same name.
    let pypi = effective_package_policy(
        dir.path(),
        base_policy(),
        Ecosystem::Pypi,
        "shared",
        "1.0.0",
    )
    .unwrap();
    assert!(!pypi
        .allowed_capabilities
        .contains(&Capability::HttpHost("npm.example".to_owned())));
    let npm =
        effective_package_policy(dir.path(), base_policy(), Ecosystem::Npm, "shared", "1.0.0")
            .unwrap();
    assert!(npm
        .allowed_capabilities
        .contains(&Capability::HttpHost("npm.example".to_owned())));
}

#[test]
fn malformed_policy_is_a_hard_error_never_silently_empty() {
    let dir = tempfile::tempdir().unwrap();
    // `allow nonsense "x"` — `nonsense` is not a known capability keyword.
    write_policy(dir.path(), "package \"x\" { allow nonsense \"y\" }");
    let err = load_policy_document(dir.path()).unwrap_err();
    assert!(matches!(err, OmcRegistryError::PolicyParse(_)));
    // The install/verify path therefore fails closed too.
    assert!(
        effective_package_policy(dir.path(), base_policy(), Ecosystem::Npm, "x", "1.0.0").is_err()
    );
}
