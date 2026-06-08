use super::*;

#[test]
fn policy_list_parses_global_as_default_scope() {
    let cli = Cli::try_parse_from(args(&["omc", "policy", "list"])).unwrap();
    match cli.command {
        Command::Policy {
            action: PolicyCommand::List { scope },
        } => assert_eq!(scope, None),
        other => panic!("expected policy list command, got {other:?}"),
    }

    let cli = Cli::try_parse_from(args(&["omc", "policy", "list", "global"])).unwrap();
    match cli.command {
        Command::Policy {
            action: PolicyCommand::List { scope },
        } => assert_eq!(scope, Some(PolicyListScope::Global)),
        other => panic!("expected policy list global command, got {other:?}"),
    }
}

#[test]
fn policy_allow_and_grant_parse_as_policy_subcommands() {
    let cli = Cli::try_parse_from(args(&[
        "omc",
        "policy",
        "allow",
        "--flow",
        "env:API_TOKEN->network:api.example.com",
        "http:api.example.com",
    ]))
    .unwrap();
    match cli.command {
        Command::Policy {
            action: PolicyCommand::Allow { grants, flows },
        } => {
            assert_eq!(grants, vec!["http:api.example.com"]);
            assert_eq!(flows, vec!["env:API_TOKEN->network:api.example.com"]);
        }
        other => panic!("expected policy allow command, got {other:?}"),
    }

    let cli = Cli::try_parse_from(args(&[
        "omc",
        "policy",
        "grant",
        "pypi:requests@2.32.5",
        "--allow",
        "dynamic.eval",
        "--allow-flow",
        "env:*->network:*",
    ]))
    .unwrap();
    match cli.command {
        Command::Policy {
            action:
                PolicyCommand::Grant {
                    spec,
                    allow,
                    allow_flow,
                },
        } => {
            assert_eq!(spec, "pypi:requests@2.32.5");
            assert_eq!(allow, vec!["dynamic.eval"]);
            assert_eq!(allow_flow, vec!["env:*->network:*"]);
        }
        other => panic!("expected policy grant command, got {other:?}"),
    }
}

/// Back-compat: the old `omc policy trust` spelling is kept as a hidden clap
/// alias and must still parse to `PolicyCommand::Grant`.
#[test]
fn policy_trust_alias_still_parses_as_grant() {
    let cli = Cli::try_parse_from(args(&[
        "omc",
        "policy",
        "trust",
        "npm:lodash@4.18.1",
        "--allow",
        "dynamic.eval",
    ]))
    .unwrap();
    match cli.command {
        Command::Policy {
            action: PolicyCommand::Grant { spec, allow, .. },
        } => {
            assert_eq!(spec, "npm:lodash@4.18.1");
            assert_eq!(allow, vec!["dynamic.eval"]);
        }
        other => panic!("expected `trust` alias to parse as policy grant, got {other:?}"),
    }
}

#[test]
fn policy_list_global_renders_version_pinned_trust_files() {
    let project = test_dir("policy-list-global");
    let home = test_dir("policy-list-global-home");
    with_env_var("OMC_HOME", &home, || {
        let grant = "dynamic.eval".to_owned();
        let flow = "env:*->network:*".to_owned();
        let path = omc_registry::write_global_package_trust(
            Ecosystem::Pypi,
            "requests",
            "2.32.5",
            &[grant],
            &[flow],
        )
        .unwrap();

        let text = crate::policy::global_policy_list_text().unwrap();
        assert!(
            text.contains(&format!(
                "global policy trust store: {}",
                home.join("policy.d").display()
            )),
            "{text}"
        );
        let file_name = path.file_name().unwrap().to_string_lossy();
        assert!(text.contains(file_name.as_ref()), "{text}");
        assert!(
            text.contains("package") && text.contains("version") && text.contains("grant"),
            "{text}"
        );
        assert!(
            text.lines().any(|line| {
                line.contains("pypi:requests")
                    && line.contains("==2.32.5")
                    && line.contains("allow")
                    && line.contains("eval")
                    && line.contains("requests.omc.policy")
            }),
            "{text}"
        );
        assert!(
            text.lines().any(|line| {
                line.contains("pypi:requests")
                    && line.contains("==2.32.5")
                    && line.contains("flow")
                    && line.contains(r#"env "*" -> net "*""#)
                    && line.contains("requests.omc.policy")
            }),
            "{text}"
        );
        assert!(!text.contains(r#"pypi package "requests""#), "{text}");

        let code = run_policy_command(&project, PolicyCommand::List { scope: None }).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    });
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
