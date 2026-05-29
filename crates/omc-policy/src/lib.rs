//! Per-package capability **policy DSL** (`omc.policy`) for OSS Microcode.
//!
//! OMC is deny-by-default. Historically a policy was a flat list of capability
//! and flow strings in `omc.toml` with no per-package scoping. This crate adds a
//! small, hand-written DSL — file name `omc.policy` — that scopes grants to
//! individual packages (and ecosystems / version ranges), with a `default`
//! baseline applied to every package and layered `allow`/`deny` semantics.
//!
//! It is a greenfield crate that depends only on [`omc_cap`]: it owns a lexer, a
//! recursive-descent parser, an AST, and a lowering pass into
//! [`omc_cap::Policy`]. There is **no** external parser/regex dependency.
//!
//! # Grammar (frozen)
//!
//! ```text
//!   document          := item*
//!   item              := default_block | package_block
//!   default_block     := "default" "{" stmt* "}"
//!   package_block     := [("npm"|"pypi")] "package" STRING [version_constraint] "{" stmt* "}"
//!   version_constraint:= ("=="|">="|">"|"<="|"<"|"^"|"~") (STRING | bareversion)
//!   stmt              := "pure"
//!                      | "allow-sensitive"
//!                      | ("allow"|"deny") cap ("," cap)*
//!                      | "flow" flow_src "->" flow_sink
//!   cap               := ("env"|"read"|"write"|"net"|"http"|"dns"|"spawn"|"exec") STRING
//!                      | "eval" | "time" | "random"
//!   flow_src          := ("env"|"file"|"read"|"secret") STRING | "any"
//!   flow_sink         := ("net"|"http") STRING | "write" STRING
//!                      | ("spawn"|"exec") STRING | "eval"
//! ```
//!
//! Comments start with `#` and run to end of line.
//!
//! # Fail-closed contract
//!
//! Parsing is deny-by-default: a malformed document, an unknown keyword, an
//! unknown capability/flow name, or a stray token is a hard [`PolicyError`] with
//! a line/column. The parser NEVER yields a silently-empty or
//! silently-permissive document on bad input.
//!
//! # Example
//!
//! ```
//! use omc_policy::{parse, Ecosystem};
//!
//! let doc = parse(r#"
//!     default { allow time, random }
//!     package "is-odd" { pure }
//!     npm package "stripe" >=12.0.0 {
//!         allow env "STRIPE_API_KEY"
//!         allow net "api.stripe.com"
//!         flow env "STRIPE_API_KEY" -> net "api.stripe.com"
//!     }
//! "#).unwrap();
//!
//! // `is-odd` is reset to pure, dropping the default time/random grants.
//! let p = doc.compile_for(Ecosystem::Npm, "is-odd", "1.0.0");
//! assert!(p.allowed_capabilities.is_empty());
//!
//! // `stripe@13` picks up the default baseline plus its own grants.
//! let p = doc.compile_for(Ecosystem::Npm, "stripe", "13.1.0");
//! assert_eq!(p.allowed_capabilities.len(), 4); // time, random, env, net
//! assert_eq!(p.allowed_flows.len(), 1);
//! ```

mod ast;
mod compile;
mod lexer;
mod parser;

pub use ast::{
    Block, Cap, EcosystemQualifier, FlowSink, FlowSrc, PackageRule, PolicyDocument, Stmt,
    VersionConstraint, VersionOp,
};
pub use compile::{constraint_satisfied, glob_matches, Ecosystem};

/// A policy parse error, carrying a 1-based line and column.
///
/// Every malformed-input path produces one of these — the DSL never fails open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl PolicyError {
    pub fn new(message: impl Into<String>, line: usize, col: usize) -> Self {
        Self {
            message: message.into(),
            line,
            col,
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy error at {}:{}: {}",
            self.line, self.col, self.message
        )
    }
}

impl std::error::Error for PolicyError {}

/// Parse an `omc.policy` source string into a [`PolicyDocument`].
///
/// Fails closed on malformed input, unknown keywords, and unknown
/// capabilities/flows, reporting the offending line/column.
pub fn parse(src: &str) -> Result<PolicyDocument, PolicyError> {
    let tokens = lexer::lex(src)?;
    parser::parse(&tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use omc_cap::{Capability, FlowRule, LabelMatcher, Sink};

    fn doc(src: &str) -> PolicyDocument {
        parse(src).unwrap_or_else(|e| panic!("parse failed: {e}"))
    }

    // ---- parsing: each statement form ------------------------------------

    #[test]
    fn parses_empty_document() {
        let d = doc("");
        assert!(d.default.is_none());
        assert!(d.packages.is_empty());
    }

    #[test]
    fn parses_comments_and_whitespace_only() {
        let d = doc("# just a comment\n\n   # another\n");
        assert!(d.default.is_none());
        assert!(d.packages.is_empty());
    }

    #[test]
    fn parses_default_block_with_multiple_caps() {
        let d = doc("default { allow time, random }");
        let block = d.default.expect("default block");
        assert_eq!(block.stmts, vec![Stmt::Allow(vec![Cap::Time, Cap::Random])]);
    }

    #[test]
    fn parses_pure_package() {
        let d = doc(r#"package "is-odd" { pure }"#);
        assert_eq!(d.packages.len(), 1);
        let pkg = &d.packages[0];
        assert_eq!(pkg.name, "is-odd");
        assert_eq!(pkg.ecosystem, None);
        assert_eq!(pkg.constraint, None);
        assert_eq!(pkg.block.stmts, vec![Stmt::Pure]);
    }

    #[test]
    fn parses_all_targeted_caps() {
        let d = doc(r#"package "p" {
                allow env "E"
                allow read "./r"
                allow write "./w"
                allow net "n"
                allow http "h"
                allow dns "d"
                allow spawn "s"
                allow exec "x"
            }"#);
        let stmts = &d.packages[0].block.stmts;
        assert_eq!(stmts[0], Stmt::Allow(vec![Cap::Env("E".into())]));
        assert_eq!(stmts[1], Stmt::Allow(vec![Cap::Read("./r".into())]));
        assert_eq!(stmts[2], Stmt::Allow(vec![Cap::Write("./w".into())]));
        assert_eq!(stmts[3], Stmt::Allow(vec![Cap::Net("n".into())]));
        // `http` parses to the same AST node as `net`.
        assert_eq!(stmts[4], Stmt::Allow(vec![Cap::Net("h".into())]));
        assert_eq!(stmts[5], Stmt::Allow(vec![Cap::Dns("d".into())]));
        assert_eq!(stmts[6], Stmt::Allow(vec![Cap::Spawn("s".into())]));
        // `exec` parses to the same AST node as `spawn`.
        assert_eq!(stmts[7], Stmt::Allow(vec![Cap::Spawn("x".into())]));
    }

    #[test]
    fn parses_targetless_caps() {
        let d = doc(r#"package "p" { allow eval, time, random }"#);
        assert_eq!(
            d.packages[0].block.stmts,
            vec![Stmt::Allow(vec![Cap::Eval, Cap::Time, Cap::Random])]
        );
    }

    #[test]
    fn parses_deny_and_allow_sensitive() {
        let d = doc(r#"package "p" {
                allow net "*"
                deny net "*"
                allow-sensitive
            }"#);
        let stmts = &d.packages[0].block.stmts;
        assert_eq!(stmts[0], Stmt::Allow(vec![Cap::Net("*".into())]));
        assert_eq!(stmts[1], Stmt::Deny(vec![Cap::Net("*".into())]));
        assert_eq!(stmts[2], Stmt::AllowSensitive);
    }

    #[test]
    fn parses_all_flow_forms() {
        let d = doc(r#"package "p" {
                flow env "E" -> net "h"
                flow file "f" -> write "o"
                flow read "r" -> http "h"
                flow secret "s" -> spawn "c"
                flow any -> eval
                flow env "E" -> exec "c"
            }"#);
        let s = &d.packages[0].block.stmts;
        assert_eq!(
            s[0],
            Stmt::Flow {
                from: FlowSrc::Env("E".into()),
                to: FlowSink::Net("h".into())
            }
        );
        assert_eq!(
            s[1],
            Stmt::Flow {
                from: FlowSrc::File("f".into()),
                to: FlowSink::Write("o".into())
            }
        );
        assert_eq!(
            s[2],
            Stmt::Flow {
                from: FlowSrc::File("r".into()),
                to: FlowSink::Net("h".into())
            }
        );
        assert_eq!(
            s[3],
            Stmt::Flow {
                from: FlowSrc::Secret("s".into()),
                to: FlowSink::Spawn("c".into())
            }
        );
        assert_eq!(
            s[4],
            Stmt::Flow {
                from: FlowSrc::Any,
                to: FlowSink::Eval
            }
        );
        assert_eq!(
            s[5],
            Stmt::Flow {
                from: FlowSrc::Env("E".into()),
                to: FlowSink::Spawn("c".into())
            }
        );
    }

    #[test]
    fn parses_ecosystem_qualifiers() {
        let d = doc(r#"npm package "a" { pure }
               pypi package "b" { pure }
               package "c" { pure }"#);
        assert_eq!(d.packages[0].ecosystem, Some(EcosystemQualifier::Npm));
        assert_eq!(d.packages[1].ecosystem, Some(EcosystemQualifier::Pypi));
        assert_eq!(d.packages[2].ecosystem, None);
    }

    #[test]
    fn parses_all_version_constraint_operators() {
        let cases = [
            ("==", VersionOp::Eq),
            (">=", VersionOp::Ge),
            (">", VersionOp::Gt),
            ("<=", VersionOp::Le),
            ("<", VersionOp::Lt),
            ("^", VersionOp::Caret),
            ("~", VersionOp::Tilde),
        ];
        for (op_str, op) in cases {
            let d = doc(&format!(r#"package "p" {op_str}1.2.3 {{ pure }}"#));
            let c = d.packages[0].constraint.as_ref().expect("constraint");
            assert_eq!(c.op, op, "operator {op_str}");
            assert_eq!(c.version, "1.2.3");
        }
    }

    #[test]
    fn parses_quoted_version() {
        let d = doc(r#"package "stripe" >="12.0.0" { pure }"#);
        let c = d.packages[0].constraint.as_ref().unwrap();
        assert_eq!(c.op, VersionOp::Ge);
        assert_eq!(c.version, "12.0.0");
    }

    #[test]
    fn parses_glob_name_and_scoped_package() {
        let d = doc(r#"npm package "@acme/*" { allow net "*" }"#);
        assert_eq!(d.packages[0].name, "@acme/*");
    }

    #[test]
    fn parses_string_escapes() {
        let d = doc(r#"package "p" { allow env "A\tB" }"#);
        assert_eq!(
            d.packages[0].block.stmts[0],
            Stmt::Allow(vec![Cap::Env("A\tB".into())])
        );
    }

    // ---- compile semantics -----------------------------------------------

    #[test]
    fn default_baseline_applies_to_every_package() {
        let d = doc(r#"default { allow time, random }"#);
        let p = d.compile_for(Ecosystem::Npm, "anything", "1.0.0");
        assert_eq!(
            p.allowed_capabilities,
            vec![Capability::TimeNow, Capability::RandomBytes]
        );
    }

    #[test]
    fn package_block_layers_on_top_of_default() {
        let d = doc(r#"default { allow time }
               package "stripe" { allow net "api.stripe.com" }"#);
        let p = d.compile_for(Ecosystem::Npm, "stripe", "1.0.0");
        assert_eq!(
            p.allowed_capabilities,
            vec![
                Capability::TimeNow,
                Capability::HttpHost("api.stripe.com".into())
            ]
        );
    }

    #[test]
    fn pure_resets_capabilities_overriding_default() {
        let d = doc(r#"default { allow time, random }
               package "is-odd" { pure }"#);
        let p = d.compile_for(Ecosystem::Npm, "is-odd", "1.0.0");
        assert!(p.allowed_capabilities.is_empty());
    }

    #[test]
    fn pure_then_allow_adds_only_after_reset() {
        let d = doc(r#"default { allow time, random }
               package "p" { pure allow net "x" }"#);
        let p = d.compile_for(Ecosystem::Npm, "p", "1.0.0");
        assert_eq!(
            p.allowed_capabilities,
            vec![Capability::HttpHost("x".into())]
        );
    }

    #[test]
    fn deny_removes_a_matching_allow() {
        let d = doc(r#"package "p" {
                allow net "api.stripe.com"
                allow net "evil.example.com"
                deny net "evil.example.com"
            }"#);
        let p = d.compile_for(Ecosystem::Npm, "p", "1.0.0");
        assert_eq!(
            p.allowed_capabilities,
            vec![Capability::HttpHost("api.stripe.com".into())]
        );
    }

    #[test]
    fn deny_wildcard_removes_all_of_a_kind() {
        let d = doc(r#"package "p" {
                allow net "a.com"
                allow net "b.com"
                allow env "E"
                deny net "*"
            }"#);
        let p = d.compile_for(Ecosystem::Npm, "p", "1.0.0");
        assert_eq!(
            p.allowed_capabilities,
            vec![Capability::EnvRead("E".into())]
        );
    }

    #[test]
    fn specific_deny_also_strips_a_wildcard_allow() {
        // A broad `allow net "*"` followed by a specific deny must not leave the
        // denied host reachable via the surviving wildcard.
        let d = doc(r#"package "p" {
                allow net "*"
                deny net "evil.example.com"
            }"#);
        let p = d.compile_for(Ecosystem::Npm, "p", "1.0.0");
        assert!(p.allowed_capabilities.is_empty());
    }

    #[test]
    fn allow_sensitive_enables_sensitive_reads() {
        let d = doc(r#"package "p" { allow read "*" allow-sensitive }"#);
        let p = d.compile_for(Ecosystem::Npm, "p", "1.0.0");
        // Under allow-sensitive a wildcard read covers a sensitive file.
        p.require(Capability::FsRead("/home/a/.ssh/id_rsa".into()))
            .expect("sensitive read allowed");
    }

    #[test]
    fn without_allow_sensitive_wildcard_read_denies_sensitive() {
        let d = doc(r#"package "p" { allow read "*" }"#);
        let p = d.compile_for(Ecosystem::Npm, "p", "1.0.0");
        assert!(p
            .require(Capability::FsRead("/home/a/.ssh/id_rsa".into()))
            .is_err());
    }

    #[test]
    fn flow_rules_are_lowered() {
        let d = doc(r#"package "p" {
                flow env "TOKEN" -> net "api.x.com"
                flow any -> eval
            }"#);
        let p = d.compile_for(Ecosystem::Npm, "p", "1.0.0");
        assert_eq!(
            p.allowed_flows,
            vec![
                FlowRule::new(
                    LabelMatcher::Env("TOKEN".into()),
                    Sink::Network("api.x.com".into())
                ),
                FlowRule::new(LabelMatcher::Any, Sink::Eval),
            ]
        );
    }

    // ---- ecosystem / glob / version matching -----------------------------

    #[test]
    fn ecosystem_qualifier_scopes_matching() {
        let d = doc(r#"npm package "left-pad" { allow net "x" }"#);
        // npm consumer sees the grant.
        assert!(!d
            .compile_for(Ecosystem::Npm, "left-pad", "1.0.0")
            .allowed_capabilities
            .is_empty());
        // pypi consumer does not.
        assert!(d
            .compile_for(Ecosystem::Pypi, "left-pad", "1.0.0")
            .allowed_capabilities
            .is_empty());
    }

    #[test]
    fn unqualified_package_matches_any_ecosystem() {
        let d = doc(r#"package "shared" { allow time }"#);
        assert!(!d
            .compile_for(Ecosystem::Npm, "shared", "1.0.0")
            .allowed_capabilities
            .is_empty());
        assert!(!d
            .compile_for(Ecosystem::Pypi, "shared", "1.0.0")
            .allowed_capabilities
            .is_empty());
    }

    #[test]
    fn name_glob_matching() {
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("@acme/*", "@acme/widget"));
        assert!(glob_matches("@acme/*", "@acme/"));
        assert!(!glob_matches("@acme/*", "@other/widget"));
        assert!(glob_matches("*-plugin", "my-plugin"));
        assert!(glob_matches("@acme/*-plugin", "@acme/cool-plugin"));
        assert!(!glob_matches("@acme/*-plugin", "@acme/cool-widget"));
        assert!(glob_matches("exact", "exact"));
        assert!(!glob_matches("exact", "exacto"));
        assert!(glob_matches("a*b*c", "axxbyyc"));
    }

    #[test]
    fn glob_scopes_package_block() {
        let d = doc(r#"npm package "@acme/*" { allow net "*" }"#);
        assert!(!d
            .compile_for(Ecosystem::Npm, "@acme/anything", "1.0.0")
            .allowed_capabilities
            .is_empty());
        assert!(d
            .compile_for(Ecosystem::Npm, "@other/thing", "1.0.0")
            .allowed_capabilities
            .is_empty());
    }

    #[test]
    fn version_constraint_basic_operators() {
        let mk = |op: &str| doc(&format!(r#"package "p" {op}12.0.0 {{ allow time }}"#));

        let ge = mk(">=");
        assert!(!ge
            .compile_for(Ecosystem::Npm, "p", "12.0.0")
            .allowed_capabilities
            .is_empty());
        assert!(!ge
            .compile_for(Ecosystem::Npm, "p", "13.5.1")
            .allowed_capabilities
            .is_empty());
        assert!(ge
            .compile_for(Ecosystem::Npm, "p", "11.9.9")
            .allowed_capabilities
            .is_empty());

        let lt = mk("<");
        assert!(!lt
            .compile_for(Ecosystem::Npm, "p", "11.0.0")
            .allowed_capabilities
            .is_empty());
        assert!(lt
            .compile_for(Ecosystem::Npm, "p", "12.0.0")
            .allowed_capabilities
            .is_empty());
    }

    #[test]
    fn version_eq_treats_missing_components_as_zero() {
        let c = VersionConstraint {
            op: VersionOp::Eq,
            version: "12".into(),
        };
        assert!(constraint_satisfied(&c, "12.0.0"));
        assert!(constraint_satisfied(&c, "12"));
        assert!(!constraint_satisfied(&c, "12.0.1"));
    }

    #[test]
    fn version_caret_locks_left_most_nonzero() {
        let caret = |v: &str| VersionConstraint {
            op: VersionOp::Caret,
            version: v.into(),
        };
        // ^1.2.3 => >=1.2.3, <2.0.0
        assert!(constraint_satisfied(&caret("1.2.3"), "1.9.9"));
        assert!(!constraint_satisfied(&caret("1.2.3"), "2.0.0"));
        assert!(!constraint_satisfied(&caret("1.2.3"), "1.2.2"));
        // ^0.2.3 => >=0.2.3, <0.3.0
        assert!(constraint_satisfied(&caret("0.2.3"), "0.2.9"));
        assert!(!constraint_satisfied(&caret("0.2.3"), "0.3.0"));
        // ^0.0.3 => >=0.0.3, <0.0.4
        assert!(constraint_satisfied(&caret("0.0.3"), "0.0.3"));
        assert!(!constraint_satisfied(&caret("0.0.3"), "0.0.4"));
    }

    #[test]
    fn version_tilde_locks_minor() {
        let tilde = |v: &str| VersionConstraint {
            op: VersionOp::Tilde,
            version: v.into(),
        };
        // ~1.2.3 => >=1.2.3, <1.3.0
        assert!(constraint_satisfied(&tilde("1.2.3"), "1.2.9"));
        assert!(!constraint_satisfied(&tilde("1.2.3"), "1.3.0"));
        // ~1 => >=1.0.0, <2.0.0
        assert!(constraint_satisfied(&tilde("1"), "1.9.9"));
        assert!(!constraint_satisfied(&tilde("1"), "2.0.0"));
    }

    #[test]
    fn missing_constraint_matches_any_version() {
        let d = doc(r#"package "p" { allow time }"#);
        assert!(!d
            .compile_for(Ecosystem::Npm, "p", "0.0.1")
            .allowed_capabilities
            .is_empty());
        assert!(!d
            .compile_for(Ecosystem::Npm, "p", "99.99.99")
            .allowed_capabilities
            .is_empty());
    }

    #[test]
    fn non_numeric_version_only_matches_verbatim_eq() {
        let c = VersionConstraint {
            op: VersionOp::Eq,
            version: "next".into(),
        };
        assert!(constraint_satisfied(&c, "next"));
        // An ordered operator against a non-numeric concrete version fails closed.
        let ge = VersionConstraint {
            op: VersionOp::Ge,
            version: "1.0.0".into(),
        };
        assert!(!constraint_satisfied(&ge, "next"));
    }

    #[test]
    fn prerelease_suffix_is_ignored_for_ordering() {
        let ge = VersionConstraint {
            op: VersionOp::Ge,
            version: "1.2.0".into(),
        };
        assert!(constraint_satisfied(&ge, "1.2.3-rc.1"));
    }

    #[test]
    fn multiple_matching_blocks_apply_in_order() {
        let d = doc(r#"package "*" { allow net "*" }
               package "evil" { deny net "*" }"#);
        // `evil` matches both blocks; the second strips the wildcard.
        assert!(d
            .compile_for(Ecosystem::Npm, "evil", "1.0.0")
            .allowed_capabilities
            .is_empty());
        // A different package keeps the wildcard from the first block.
        assert!(!d
            .compile_for(Ecosystem::Npm, "good", "1.0.0")
            .allowed_capabilities
            .is_empty());
    }

    // ---- explain ----------------------------------------------------------

    #[test]
    fn explain_lists_caps_and_flows() {
        let d = doc(r#"package "p" {
                allow net "api.x.com"
                flow env "T" -> net "api.x.com"
            }"#);
        let text = d.explain_for(Ecosystem::Npm, "p", "1.0.0");
        assert!(text.contains("npm:p@1.0.0"));
        assert!(text.contains("http:api.x.com"));
        assert!(text.contains("env:T"));
        assert!(text.contains("network:api.x.com"));
    }

    #[test]
    fn explain_reports_pure() {
        let d = doc(r#"package "p" { pure }"#);
        let text = d.explain_for(Ecosystem::Npm, "p", "1.0.0");
        assert!(text.contains("none"), "got: {text}");
    }

    // ---- fail closed ------------------------------------------------------

    fn err(src: &str) -> PolicyError {
        parse(src).expect_err("expected a parse error")
    }

    #[test]
    fn rejects_unknown_top_level_keyword() {
        let e = err(r#"frobnicate "p" { pure }"#);
        assert!(e.message.contains("frobnicate") || e.message.contains("default or package"));
    }

    #[test]
    fn rejects_unknown_statement() {
        assert!(err(r#"package "p" { wibble net "x" }"#)
            .message
            .contains("wibble"));
    }

    #[test]
    fn rejects_unknown_capability() {
        assert!(err(r#"package "p" { allow telepathy "x" }"#)
            .message
            .contains("telepathy"));
    }

    #[test]
    fn rejects_unknown_flow_source() {
        assert!(err(r#"package "p" { flow mind "x" -> net "y" }"#)
            .message
            .contains("mind"));
    }

    #[test]
    fn rejects_unknown_flow_sink() {
        assert!(err(r#"package "p" { flow env "x" -> telepath "y" }"#)
            .message
            .contains("telepath"));
    }

    #[test]
    fn rejects_missing_arrow_in_flow() {
        assert!(err(r#"package "p" { flow env "x" net "y" }"#)
            .message
            .contains("->"));
    }

    #[test]
    fn rejects_unterminated_block() {
        assert!(err(r#"package "p" { allow time"#).message.contains("}"));
    }

    #[test]
    fn rejects_unterminated_string() {
        let e = err(r#"package "p"#);
        assert!(e.message.contains("string"));
    }

    #[test]
    fn rejects_missing_brace() {
        assert!(err(r#"package "p" pure }"#).message.contains("{"));
    }

    #[test]
    fn rejects_missing_capability_target() {
        assert!(err(r#"package "p" { allow env }"#)
            .message
            .contains("string"));
    }

    #[test]
    fn rejects_duplicate_default_block() {
        assert!(err(r#"default { allow time } default { allow random }"#)
            .message
            .contains("duplicate"));
    }

    #[test]
    fn rejects_stray_token_after_document() {
        // A trailing `}` with no opening block is not a valid item: fail closed.
        assert!(err(r#"package "p" { pure } }"#).message.contains("default"));
    }

    #[test]
    fn rejects_unexpected_character() {
        assert!(err(r#"package "p" { allow net "x" @ }"#)
            .message
            .contains("unexpected character"));
    }

    #[test]
    fn error_carries_line_and_column() {
        // The bad keyword is on line 2.
        let e = err("default { allow time }\npackage \"p\" { wibble }");
        assert_eq!(e.line, 2);
        assert!(e.col > 0);
    }

    #[test]
    fn malformed_input_never_silently_empty() {
        // A document that is almost valid but has a typo must error, not yield
        // an empty (permissive-looking) document.
        assert!(parse(r#"package "p" { allwo net "x" }"#).is_err());
    }
}
