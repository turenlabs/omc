//! Recursive-descent parser for the `omc.policy` DSL.
//!
//! Grammar (frozen):
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
//! Anything outside this grammar is a hard [`PolicyError`] carrying the offending
//! token's line/column: a malformed policy is never silently accepted, and an
//! unknown keyword or capability name fails closed.

use crate::ast::{
    Block, Cap, EcosystemQualifier, FlowSink, FlowSrc, PackageRule, PolicyDocument, Stmt,
    VersionConstraint, VersionOp,
};
use crate::lexer::{Spanned, Tok, VersionOpTok};
use crate::PolicyError;

/// Parse a token stream into a [`PolicyDocument`].
pub fn parse(tokens: &[Spanned]) -> Result<PolicyDocument, PolicyError> {
    let mut p = Parser {
        toks: tokens,
        pos: 0,
    };
    let doc = p.parse_document()?;
    p.expect_eof()?;
    Ok(doc)
}

struct Parser<'a> {
    toks: &'a [Spanned],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &Spanned {
        // The lexer always appends Eof, so the last element is a valid fallback.
        self.toks
            .get(self.pos)
            .unwrap_or_else(|| self.toks.last().expect("token stream has Eof"))
    }

    fn bump(&mut self) -> &Spanned {
        let idx = self.pos.min(self.toks.len().saturating_sub(1));
        self.pos += 1;
        &self.toks[idx]
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek().tok, Tok::Eof)
    }

    fn expect_eof(&self) -> Result<(), PolicyError> {
        if self.at_eof() {
            Ok(())
        } else {
            Err(self.error_here("expected end of policy document"))
        }
    }

    fn error_here(&self, message: impl Into<String>) -> PolicyError {
        let s = self.peek();
        PolicyError::new(message, s.line, s.col)
    }

    /// Consume a `{`-brace, erroring with the given context if absent.
    fn expect_lbrace(&mut self, context: &str) -> Result<(), PolicyError> {
        match self.peek().tok {
            Tok::LBrace => {
                self.bump();
                Ok(())
            }
            _ => Err(self.error_here(format!("expected `{{` {context}"))),
        }
    }

    /// Consume a string literal token, returning its contents.
    fn expect_string(&mut self, context: &str) -> Result<String, PolicyError> {
        match &self.peek().tok {
            Tok::Str(s) => {
                let s = s.clone();
                self.bump();
                Ok(s)
            }
            _ => Err(self.error_here(format!("expected a quoted string {context}"))),
        }
    }

    /// Peek at the current identifier/keyword, if any.
    fn peek_ident(&self) -> Option<&str> {
        match &self.peek().tok {
            Tok::Ident(word) => Some(word.as_str()),
            _ => None,
        }
    }

    // ---- top level --------------------------------------------------------

    fn parse_document(&mut self) -> Result<PolicyDocument, PolicyError> {
        let mut doc = PolicyDocument::default();
        while !self.at_eof() {
            match self.peek_ident() {
                Some("default") => {
                    self.bump();
                    if doc.default.is_some() {
                        return Err(self.error_here("duplicate `default` block"));
                    }
                    self.expect_lbrace("after `default`")?;
                    doc.default = Some(self.parse_block_body()?);
                }
                Some("npm") | Some("pypi") | Some("package") => {
                    doc.packages.push(self.parse_package_rule()?);
                }
                Some(other) => {
                    return Err(self.error_here(format!(
                        "expected `default` or `package` (with optional `npm`/`pypi`), found `{other}`"
                    )));
                }
                None => {
                    return Err(self.error_here("expected `default` or `package`"));
                }
            }
        }
        Ok(doc)
    }

    fn parse_package_rule(&mut self) -> Result<PackageRule, PolicyError> {
        // Optional ecosystem qualifier.
        let ecosystem = match self.peek_ident() {
            Some("npm") => {
                self.bump();
                Some(EcosystemQualifier::Npm)
            }
            Some("pypi") => {
                self.bump();
                Some(EcosystemQualifier::Pypi)
            }
            _ => None,
        };

        // `package` keyword.
        match self.peek_ident() {
            Some("package") => {
                self.bump();
            }
            _ => return Err(self.error_here("expected `package`")),
        }

        let name = self.expect_string("for the package name")?;

        // Optional version constraint.
        let constraint = self.parse_version_constraint()?;

        self.expect_lbrace("to open the package block")?;
        let block = self.parse_block_body()?;

        Ok(PackageRule {
            ecosystem,
            name,
            constraint,
            block,
        })
    }

    fn parse_version_constraint(&mut self) -> Result<Option<VersionConstraint>, PolicyError> {
        let op = match self.peek().tok {
            Tok::VersionOp(op) => op,
            _ => return Ok(None),
        };
        self.bump();
        let op = match op {
            VersionOpTok::EqEq => VersionOp::Eq,
            VersionOpTok::Ge => VersionOp::Ge,
            VersionOpTok::Gt => VersionOp::Gt,
            VersionOpTok::Le => VersionOp::Le,
            VersionOpTok::Lt => VersionOp::Lt,
            VersionOpTok::Caret => VersionOp::Caret,
            VersionOpTok::Tilde => VersionOp::Tilde,
        };
        // The version may be a quoted string or a bare dotted version (lexed as
        // an identifier-word).
        let version = match &self.peek().tok {
            Tok::Str(s) => {
                let s = s.clone();
                self.bump();
                s
            }
            Tok::Ident(word) => {
                let word = word.clone();
                self.bump();
                word
            }
            _ => return Err(self.error_here("expected a version after the constraint operator")),
        };
        Ok(Some(VersionConstraint { op, version }))
    }

    // ---- block / statements ----------------------------------------------

    /// Parse statements until the closing `}` (which is consumed). The opening
    /// `{` must already have been consumed by the caller.
    fn parse_block_body(&mut self) -> Result<Block, PolicyError> {
        let mut block = Block::default();
        loop {
            match self.peek().tok {
                Tok::RBrace => {
                    self.bump();
                    return Ok(block);
                }
                Tok::Eof => {
                    return Err(self.error_here("unterminated block: expected `}`"));
                }
                _ => block.stmts.push(self.parse_stmt()?),
            }
        }
    }

    fn parse_stmt(&mut self) -> Result<Stmt, PolicyError> {
        match self.peek_ident() {
            Some("pure") => {
                self.bump();
                Ok(Stmt::Pure)
            }
            Some("allow-sensitive") => {
                self.bump();
                Ok(Stmt::AllowSensitive)
            }
            Some("allow") => {
                self.bump();
                Ok(Stmt::Allow(self.parse_cap_list()?))
            }
            Some("deny") => {
                self.bump();
                Ok(Stmt::Deny(self.parse_cap_list()?))
            }
            Some("flow") => {
                self.bump();
                let from = self.parse_flow_src()?;
                match self.peek().tok {
                    Tok::Arrow => {
                        self.bump();
                    }
                    _ => return Err(self.error_here("expected `->` in flow statement")),
                }
                let to = self.parse_flow_sink()?;
                Ok(Stmt::Flow { from, to })
            }
            Some(other) => Err(self.error_here(format!(
                "unknown statement `{other}`; expected `pure`, `allow-sensitive`, `allow`, `deny`, or `flow`"
            ))),
            None => Err(self.error_here("expected a statement")),
        }
    }

    /// Parse `cap ("," cap)*`.
    fn parse_cap_list(&mut self) -> Result<Vec<Cap>, PolicyError> {
        let mut caps = vec![self.parse_cap()?];
        while matches!(self.peek().tok, Tok::Comma) {
            self.bump();
            caps.push(self.parse_cap()?);
        }
        Ok(caps)
    }

    fn parse_cap(&mut self) -> Result<Cap, PolicyError> {
        let keyword = match self.peek_ident() {
            Some(word) => word.to_owned(),
            None => return Err(self.error_here("expected a capability")),
        };
        self.bump();
        // Targetless capabilities.
        match keyword.as_str() {
            "eval" => return Ok(Cap::Eval),
            "time" => return Ok(Cap::Time),
            "random" => return Ok(Cap::Random),
            _ => {}
        }
        // Targeted capabilities require a string argument.
        let target = self.expect_string(&format!("for `{keyword}` capability target"))?;
        match keyword.as_str() {
            "env" => Ok(Cap::Env(target)),
            "read" => Ok(Cap::Read(target)),
            "write" => Ok(Cap::Write(target)),
            "net" | "http" => Ok(Cap::Net(target)),
            "dns" => Ok(Cap::Dns(target)),
            "spawn" | "exec" => Ok(Cap::Spawn(target)),
            other => Err(PolicyError::new(
                format!("unknown capability `{other}`"),
                // Point at the keyword token, which we already consumed.
                self.toks[self.pos.saturating_sub(2)].line,
                self.toks[self.pos.saturating_sub(2)].col,
            )),
        }
    }

    fn parse_flow_src(&mut self) -> Result<FlowSrc, PolicyError> {
        let keyword = match self.peek_ident() {
            Some(word) => word.to_owned(),
            None => return Err(self.error_here("expected a flow source")),
        };
        self.bump();
        if keyword == "any" {
            return Ok(FlowSrc::Any);
        }
        let target = self.expect_string(&format!("for flow source `{keyword}`"))?;
        match keyword.as_str() {
            "env" => Ok(FlowSrc::Env(target)),
            "file" | "read" => Ok(FlowSrc::File(target)),
            "secret" => Ok(FlowSrc::Secret(target)),
            other => Err(PolicyError::new(
                format!("unknown flow source `{other}`"),
                self.toks[self.pos.saturating_sub(2)].line,
                self.toks[self.pos.saturating_sub(2)].col,
            )),
        }
    }

    fn parse_flow_sink(&mut self) -> Result<FlowSink, PolicyError> {
        let keyword = match self.peek_ident() {
            Some(word) => word.to_owned(),
            None => return Err(self.error_here("expected a flow sink")),
        };
        self.bump();
        if keyword == "eval" {
            return Ok(FlowSink::Eval);
        }
        let target = self.expect_string(&format!("for flow sink `{keyword}`"))?;
        match keyword.as_str() {
            "net" | "http" => Ok(FlowSink::Net(target)),
            "write" => Ok(FlowSink::Write(target)),
            "spawn" | "exec" => Ok(FlowSink::Spawn(target)),
            other => Err(PolicyError::new(
                format!("unknown flow sink `{other}`"),
                self.toks[self.pos.saturating_sub(2)].line,
                self.toks[self.pos.saturating_sub(2)].col,
            )),
        }
    }
}
