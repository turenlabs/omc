use super::*;
use crate::agent_skill::{agent_skill_document, print_agent_skill};

#[test]
fn agent_command_exits_zero() {
    assert_eq!(print_agent_skill(false), ExitCode::SUCCESS);
    assert_eq!(print_agent_skill(true), ExitCode::SUCCESS);
}

#[test]
fn agent_markdown_contains_core_anchors() {
    let doc = agent_skill_document(false);
    for anchor in [
        "deny-by-default",
        "omc add",
        "omc install",
        "omc inspect",
        "omc graph",
        "omc audit",
        "omc policy trust",
        "omc policy allow",
        "omc.policy",
        "Shai-Hulud",
        "dynamic_eval",
        "proc_spawn",
        "env_read",
        "--allow",
        "--allow-flow",
        "--allow-all-host",
        "OMC_VERBOSE",
        "OMC_HOME",
        "OMC_META_TTL_SECS",
        "NO_COLOR",
        "`0` = accepted, `2` = blocked",
    ] {
        assert!(
            doc.contains(anchor),
            "agent guide is missing anchor: {anchor}"
        );
    }
}

#[test]
fn agent_json_wraps_the_markdown() {
    let json = agent_skill_document(true);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["format"], "markdown");
    let skill = parsed["skill"].as_str().unwrap();
    assert!(skill.contains("deny-by-default"));
    assert!(skill.contains("dynamic_eval"));
}

#[test]
fn help_agent_parses_as_help_topic() {
    let cli = Cli::try_parse_from(args(&["omc", "help", "agent"])).unwrap();
    match cli.command {
        Command::Help { topic, json } => {
            assert_eq!(topic, vec!["agent"]);
            assert!(!json);
        }
        other => panic!("expected help agent command, got {other:?}"),
    }

    let cli = Cli::try_parse_from(args(&["omc", "help", "agent", "--json"])).unwrap();
    match cli.command {
        Command::Help { topic, json } => {
            assert_eq!(topic, vec!["agent"]);
            assert!(json);
        }
        other => panic!("expected JSON help agent command, got {other:?}"),
    }

    assert!(Cli::try_parse_from(args(&["omc", "agent"])).is_err());
}
