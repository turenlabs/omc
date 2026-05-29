//! Lowering of a parsed [`PolicyDocument`] into a runtime [`omc_cap::Policy`].
//!
//! This is where the frozen `compile_for` semantics live: the `default` baseline
//! is applied first, then every matching `package` block is layered on top in
//! source order. `pure` resets the accumulated capabilities; `allow` adds;
//! `deny` removes matching caps; `flow` appends a flow rule; `allow-sensitive`
//! lifts the sensitive-read guard.

use omc_cap::{Capability, FlowRule, LabelMatcher, Policy, Sink};

use crate::ast::{
    Block, Cap, EcosystemQualifier, FlowSink, FlowSrc, PackageRule, PolicyDocument, Stmt,
    VersionConstraint, VersionOp,
};

/// The package ecosystem a policy is being compiled for. Local and simple by
/// design — this crate does not depend on the registry's richer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pypi,
}

impl Ecosystem {
    fn matches_qualifier(self, qualifier: Option<EcosystemQualifier>) -> bool {
        match qualifier {
            // An unqualified `package` block applies to every ecosystem.
            None => true,
            Some(EcosystemQualifier::Npm) => self == Ecosystem::Npm,
            Some(EcosystemQualifier::Pypi) => self == Ecosystem::Pypi,
        }
    }
}

/// The mutable accumulator threaded through lowering. We accumulate into plain
/// `Vec`s and only build the immutable [`Policy`] at the end so that `deny` and
/// `pure` can edit the in-progress capability set.
#[derive(Default)]
struct Accumulator {
    capabilities: Vec<Capability>,
    flows: Vec<FlowRule>,
    allow_sensitive: bool,
}

impl Accumulator {
    fn apply_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.apply_stmt(stmt);
        }
    }

    fn apply_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Pure => {
                // `pure` resets the accumulated capabilities for this package.
                // Flow rules and the sensitive flag are independent grants and
                // are intentionally left untouched.
                self.capabilities.clear();
            }
            Stmt::AllowSensitive => self.allow_sensitive = true,
            Stmt::Allow(caps) => {
                for cap in caps {
                    let lowered = lower_cap(cap);
                    // Keep the set free of exact duplicates so `explain_for`
                    // reads cleanly; semantics are unaffected either way.
                    if !self.capabilities.contains(&lowered) {
                        self.capabilities.push(lowered);
                    }
                }
            }
            Stmt::Deny(caps) => {
                for cap in caps {
                    let lowered = lower_cap(cap);
                    // `deny` removes every capability that the denied grant
                    // would match. A `deny net "*"` removes all host grants;
                    // a `deny net "api.x"` removes exactly that host (and any
                    // wildcard, since the wildcard matches it).
                    self.capabilities.retain(|held| !cap_denies(&lowered, held));
                }
            }
            Stmt::Flow { from, to } => {
                let rule = FlowRule::new(lower_flow_src(from), lower_flow_sink(to));
                if !self.flows.contains(&rule) {
                    self.flows.push(rule);
                }
            }
        }
    }

    fn into_policy(self) -> Policy {
        let mut policy = Policy::pure();
        for cap in self.capabilities {
            policy = policy.allow_capability(cap);
        }
        for flow in self.flows {
            policy = policy.allow_flow_rule(flow);
        }
        if self.allow_sensitive {
            policy = policy.allow_sensitive_reads();
        }
        policy
    }
}

impl PolicyDocument {
    /// Compile the effective [`Policy`] for a concrete `(ecosystem, name,
    /// version)` triple, applying the frozen semantics.
    pub fn compile_for(&self, ecosystem: Ecosystem, name: &str, version: &str) -> Policy {
        let mut acc = Accumulator::default();
        if let Some(default) = &self.default {
            acc.apply_block(default);
        }
        for rule in &self.packages {
            if rule_matches(rule, ecosystem, name, version) {
                acc.apply_block(&rule.block);
            }
        }
        acc.into_policy()
    }

    /// Produce a human-readable summary of the effective capabilities and flows
    /// for a concrete triple. Intended for an `omc policy check` command.
    pub fn explain_for(&self, ecosystem: Ecosystem, name: &str, version: &str) -> String {
        let policy = self.compile_for(ecosystem, name, version);
        let eco = match ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
        };
        let mut out = format!("effective policy for {eco}:{name}@{version}\n");

        if policy.allowed_capabilities.is_empty() {
            out.push_str("  capabilities: (none — pure)\n");
        } else {
            out.push_str("  capabilities:\n");
            for cap in &policy.allowed_capabilities {
                out.push_str(&format!("    - {cap}\n"));
            }
        }

        if policy.allowed_flows.is_empty() {
            out.push_str("  flows: (none)\n");
        } else {
            out.push_str("  flows:\n");
            for flow in &policy.allowed_flows {
                out.push_str(&format!("    - {flow}\n"));
            }
        }

        out
    }
}

/// Does `rule` apply to this triple? The ecosystem must be unqualified-or-equal,
/// the name glob must match, and the version constraint (if any) must hold.
fn rule_matches(rule: &PackageRule, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
    ecosystem.matches_qualifier(rule.ecosystem)
        && glob_matches(&rule.name, name)
        && rule
            .constraint
            .as_ref()
            .map(|c| constraint_satisfied(c, version))
            .unwrap_or(true)
}

// ---- capability / flow lowering -------------------------------------------

fn lower_cap(cap: &Cap) -> Capability {
    match cap {
        Cap::Env(name) => Capability::EnvRead(name.clone()),
        Cap::Read(path) => Capability::FsRead(path.clone()),
        Cap::Write(path) => Capability::FsWrite(path.clone()),
        Cap::Net(host) => Capability::HttpHost(host.clone()),
        Cap::Dns(host) => Capability::DnsHost(host.clone()),
        Cap::Spawn(cmd) => Capability::ProcSpawn(cmd.clone()),
        Cap::Eval => Capability::DynamicEval,
        Cap::Time => Capability::TimeNow,
        Cap::Random => Capability::RandomBytes,
    }
}

fn lower_flow_src(src: &FlowSrc) -> LabelMatcher {
    match src {
        FlowSrc::Any => LabelMatcher::Any,
        FlowSrc::Env(name) => LabelMatcher::Env(name.clone()),
        FlowSrc::File(path) => LabelMatcher::File(path.clone()),
        FlowSrc::Secret(name) => LabelMatcher::Secret(name.clone()),
    }
}

fn lower_flow_sink(sink: &FlowSink) -> Sink {
    match sink {
        FlowSink::Net(host) => Sink::Network(host.clone()),
        FlowSink::Write(path) => Sink::File(path.clone()),
        FlowSink::Spawn(cmd) => Sink::Process(cmd.clone()),
        FlowSink::Eval => Sink::Eval,
    }
}

/// Does a `deny <denied>` statement remove a held capability `held`?
///
/// A targeted capability matches another of the same kind when the denied
/// target is `"*"` (removes all of that kind), or when the two targets are
/// equal, or when the held grant itself is a wildcard `"*"` (a specific deny
/// also strips a broad wildcard so it cannot leak the denied target back in).
/// Targetless capabilities (`eval`/`time`/`random`) match only their own kind.
fn cap_denies(denied: &Capability, held: &Capability) -> bool {
    use Capability::*;
    match (denied, held) {
        (EnvRead(d), EnvRead(h))
        | (FsRead(d), FsRead(h))
        | (FsWrite(d), FsWrite(h))
        | (HttpHost(d), HttpHost(h))
        | (DnsHost(d), DnsHost(h))
        | (ProcSpawn(d), ProcSpawn(h)) => d == "*" || h == "*" || d == h,
        (TimeNow, TimeNow) | (RandomBytes, RandomBytes) | (DynamicEval, DynamicEval) => true,
        _ => false,
    }
}

// ---- name glob matching ----------------------------------------------------

/// Match a package name against a glob pattern. `*` matches any (possibly empty)
/// run of characters; all other characters match literally. Supports multiple
/// `*` (e.g. `@acme/*-plugin`). This is a small two-pointer backtracking matcher
/// — no regex dependency.
pub fn glob_matches(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = name.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Remembered backtrack point for the most recent `*`.
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < txt.len() {
        if pi < pat.len() && pat[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < pat.len() && pat[pi] == txt[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star {
            // Backtrack: let the last `*` swallow one more character.
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // Consume any trailing `*`s in the pattern.
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

// ---- version-constraint evaluation -----------------------------------------

/// Evaluate a version constraint against a concrete version string.
///
/// Versions are compared on their dotted **numeric** components (a SemVer-ish
/// subset). Any pre-release / build suffix after the numeric core (e.g.
/// `-rc.1`, `+build`) is ignored for ordering; only the leading numeric
/// components participate. Missing components are treated as `0`, so `12` and
/// `12.0.0` compare equal. A non-numeric component makes that version
/// incomparable, in which case only `==` (exact string equality) can succeed —
/// every ordered constraint fails closed.
///
/// Operator semantics:
/// - `==`, `>=`, `>`, `<=`, `<`: numeric comparison as above.
/// - `^` (caret): `>=` the constraint AND less than the next change of the
///   left-most non-zero component (e.g. `^1.2.3` => `>=1.2.3, <2.0.0`;
///   `^0.2.3` => `>=0.2.3, <0.3.0`; `^0.0.3` => `>=0.0.3, <0.0.4`).
/// - `~` (tilde): `>=` the constraint AND less than the next minor when a minor
///   is given (`~1.2.3` => `>=1.2.3, <1.3.0`), else the next major (`~1` =>
///   `>=1.0.0, <2.0.0`).
pub fn constraint_satisfied(constraint: &VersionConstraint, version: &str) -> bool {
    if constraint.op == VersionOp::Eq {
        // Exact equality is string-normalised on the numeric core so `12` and
        // `12.0.0` match, but also accepts a verbatim string match for the rare
        // non-numeric version.
        if constraint.version == version {
            return true;
        }
    }

    let Some(have) = NumericVersion::parse(version) else {
        // Incomparable concrete version: only a verbatim `==` (handled above)
        // can match; fail closed for every ordered operator.
        return false;
    };
    let Some(want) = NumericVersion::parse(&constraint.version) else {
        return false;
    };

    match constraint.op {
        VersionOp::Eq => have.cmp_key() == want.cmp_key(),
        VersionOp::Ge => have.cmp_key() >= want.cmp_key(),
        VersionOp::Gt => have.cmp_key() > want.cmp_key(),
        VersionOp::Le => have.cmp_key() <= want.cmp_key(),
        VersionOp::Lt => have.cmp_key() < want.cmp_key(),
        VersionOp::Caret => have.cmp_key() >= want.cmp_key() && have.cmp_key() < want.caret_upper(),
        VersionOp::Tilde => have.cmp_key() >= want.cmp_key() && have.cmp_key() < want.tilde_upper(),
    }
}

/// A version reduced to up to three numeric components (major, minor, patch).
/// Missing components default to `0`. Used only for ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NumericVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl NumericVersion {
    /// Parse the leading numeric core of a version. Returns `None` if the first
    /// component is not numeric (the version is then incomparable). A leading
    /// `v` (e.g. `v1.2.3`) is tolerated. Pre-release/build suffixes after the
    /// numeric core are ignored.
    fn parse(version: &str) -> Option<Self> {
        let trimmed = version.trim();
        let core = trimmed.strip_prefix('v').unwrap_or(trimmed);
        // Stop the numeric core at the first '-' (pre-release) or '+' (build).
        let core = core.split(['-', '+']).next().unwrap_or(core);

        let mut parts = core.split('.');
        let major = parse_component(parts.next())?;
        let minor = parse_component(parts.next()).unwrap_or(0);
        let patch = parse_component(parts.next()).unwrap_or(0);
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    fn cmp_key(&self) -> (u64, u64, u64) {
        (self.major, self.minor, self.patch)
    }

    /// The exclusive upper bound for a `^` constraint anchored at this version.
    fn caret_upper(&self) -> (u64, u64, u64) {
        if self.major > 0 {
            (self.major + 1, 0, 0)
        } else if self.minor > 0 {
            (0, self.minor + 1, 0)
        } else {
            (0, 0, self.patch + 1)
        }
    }

    /// The exclusive upper bound for a `~` constraint anchored at this version.
    /// When a minor component is present we lock the minor; otherwise we lock
    /// the major. Since missing components default to `0`, both `~1` and `~1.0`
    /// lock to `<2.0.0`; distinguishing them would require retaining the raw
    /// component count, which the frozen subset does not need.
    fn tilde_upper(&self) -> (u64, u64, u64) {
        if self.minor > 0 || self.patch > 0 {
            (self.major, self.minor + 1, 0)
        } else {
            (self.major + 1, 0, 0)
        }
    }
}

fn parse_component(part: Option<&str>) -> Option<u64> {
    let part = part?;
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse::<u64>().ok()
}
