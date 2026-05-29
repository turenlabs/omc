//! Abstract syntax tree for the `omc.policy` DSL.
//!
//! The AST is a faithful, lossless representation of a parsed policy document.
//! It carries no host-policy semantics itself; lowering into an
//! [`omc_cap::Policy`] happens in [`crate::compile`]. Keeping the AST separate
//! from the runtime policy model means the parser can be tested in isolation and
//! the lowering rules can evolve without reshaping the grammar.

/// A capability granted or denied by an `allow`/`deny` statement.
///
/// Each variant maps 1:1 onto an [`omc_cap::Capability`]; see
/// [`crate::compile`] for the mapping. Targets are stored verbatim (e.g. a host
/// name, an env var name, a path); the wildcard target `"*"` is handled by the
/// runtime matcher, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cap {
    Env(String),
    Read(String),
    Write(String),
    /// `net` and `http` both lower to `HttpHost`; the spelling is not retained.
    Net(String),
    Dns(String),
    /// `spawn` and `exec` both lower to `ProcSpawn`.
    Spawn(String),
    Eval,
    Time,
    Random,
}

/// The source side of a `flow` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowSrc {
    Any,
    Env(String),
    /// `file` and `read` both lower to `LabelMatcher::File`.
    File(String),
    Secret(String),
}

/// The sink side of a `flow` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowSink {
    /// `net` and `http` both lower to `Sink::Network`.
    Net(String),
    Write(String),
    /// `spawn` and `exec` both lower to `Sink::Process`.
    Spawn(String),
    Eval,
}

/// A single statement inside a `default` or `package` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    /// `pure` — reset the accumulated capabilities to empty for this package.
    Pure,
    /// `allow-sensitive` — lift the sensitive-file read guard.
    AllowSensitive,
    /// `allow cap (, cap)*` — add one or more capabilities.
    Allow(Vec<Cap>),
    /// `deny cap (, cap)*` — remove matching capabilities from the accumulator.
    Deny(Vec<Cap>),
    /// `flow src -> sink` — add a single flow rule.
    Flow { from: FlowSrc, to: FlowSink },
}

/// The ecosystem qualifier on a `package` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcosystemQualifier {
    Npm,
    Pypi,
}

/// The comparison operator of a version constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOp {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    /// `^` — caret: compatible-with, locking the left-most non-zero component.
    Caret,
    /// `~` — tilde: reasonably-close, locking down to the minor component.
    Tilde,
}

/// A parsed version constraint, e.g. `>=12.0.0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionConstraint {
    pub op: VersionOp,
    pub version: String,
}

/// A `default { ... }` or `package "name" { ... }` block body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Block {
    pub stmts: Vec<Stmt>,
}

/// A `package` rule: an optional ecosystem qualifier, a name glob, an optional
/// version constraint, and the block body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRule {
    pub ecosystem: Option<EcosystemQualifier>,
    /// The package name glob (e.g. `"stripe"`, `"@acme/*"`). `*` is a wildcard.
    pub name: String,
    pub constraint: Option<VersionConstraint>,
    pub block: Block,
}

/// A fully parsed policy document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyDocument {
    /// The optional `default { ... }` baseline applied to every package.
    pub default: Option<Block>,
    /// The `package` rules, in source order.
    pub packages: Vec<PackageRule>,
}
