use crate::*;
use super::*;

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
