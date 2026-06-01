//! policy_bridge — flat + DSL policy composition and grant rendering.
//!
//! Composes the flat `omc.toml [policy]` / CLI grants with the per-package
//! `omc.policy` DSL (project + global trust store), renders the actionable
//! block guidance shown when a package is denied, and parses CLI grant/flow
//! tokens. Extracted verbatim from lib.rs.

use crate::*;

use std::fs;
use std::path::{Path, PathBuf};

use omc_cap::{Capability, FlowRule, LabelMatcher, Policy, Sink};

/// Load and parse the optional `omc.policy` DSL file from a project directory.
///
/// Returns `Ok(None)` when the file is absent (full back-compat: behaviour is
/// exactly as before). A present-but-malformed file is a hard, clearly-reported
/// error — the policy layer is deny-by-default and never fails open.
pub fn load_policy_document(project_dir: &Path) -> Result<Option<omc_policy::PolicyDocument>> {
    let path = project_dir.join(POLICY_FILE);
    if !path.exists() {
        return Ok(None);
    }
    // batou:ignore file_read -- `omc.policy` is a fixed, project-local config
    // file name joined onto the operator-chosen project dir; reading it is the
    // explicit purpose, identical to how `read_manifest` loads `omc.toml`.
    let source = fs::read_to_string(&path)?;
    Ok(Some(omc_policy::parse(&source)?))
}

/// Merge the DSL-compiled per-package [`Policy`] into a base policy built from
/// the flat `omc.toml [policy]` / CLI grants.
///
/// The existing flat grants are treated as additional `default` grants (they
/// stay in `base`); the DSL `default` block plus every matching `package` block
/// are layered on top. Capabilities and flows are unioned (deduped); the
/// sensitive-read guard is lifted if either side lifted it.
pub(crate) fn merge_dsl_policy(base: Policy, dsl: &Policy) -> Policy {
    let mut merged = base;
    for capability in &dsl.allowed_capabilities {
        if !merged.allowed_capabilities.contains(capability) {
            merged = merged.allow_capability(capability.clone());
        }
    }
    for flow in &dsl.allowed_flows {
        if !merged.allowed_flows.contains(flow) {
            merged = merged.allow_flow_rule(flow.clone());
        }
    }
    if dsl.sensitive_reads_allowed() {
        merged = merged.allow_sensitive_reads();
    }
    merged
}

/// Build the effective verification [`Policy`] for one concrete package.
///
/// `base` is the policy assembled from the flat `omc.toml [policy]` / CLI grants
/// (the historical global allow-list). When an `omc.policy` DSL file is present,
/// the package's compiled per-package policy is layered on top so each
/// dependency is checked against ITS block, not just the one global list. When
/// no `omc.policy` exists, `base` is returned unchanged.
pub fn effective_package_policy(
    project_dir: &Path,
    base: Policy,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<Policy> {
    let eco = policy_ecosystem(ecosystem);
    let mut policy = base;
    // Project `omc.policy` (committable, project-scoped).
    if let Some(document) = load_policy_document(project_dir)? {
        policy = merge_dsl_policy(policy, &document.compile_for(eco, name, version));
    }
    // Global drop-in trust store `~/.omc/policy.d/*.omc.policy` (personal,
    // per-package, version-pinned). Each block only grants for its exact package,
    // so it composes as a baseline under every project without leaking to other
    // packages or transitive dependencies.
    for document in load_global_policy_documents()? {
        policy = merge_dsl_policy(policy, &document.compile_for(eco, name, version));
    }
    Ok(policy)
}

/// Load every drop-in per-package policy from the global trust directory
/// `$OMC_HOME/policy.d/` (default `~/.omc/policy.d/`). Each `*.omc.policy` /
/// `*.policy` file is parsed independently (a parse error in any file fails
/// closed); files are read in sorted order for determinism. Missing dir → empty.
pub(crate) fn load_global_policy_documents() -> Result<Vec<omc_policy::PolicyDocument>> {
    let Some(dir) = global_omc_home().map(|home| home.join("policy.d")) else {
        return Ok(Vec::new());
    };
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        let is_policy = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".omc.policy") || name.ends_with(".policy"));
        if path.is_file() && is_policy {
            paths.push(path);
        }
    }
    paths.sort();
    let mut documents = Vec::new();
    for path in paths {
        // batou:ignore file_read -- drop-in policy files in the operator's own
        // $OMC_HOME/policy.d trust dir; reading them is the explicit purpose.
        let source = fs::read_to_string(&path)?;
        documents.push(omc_policy::parse(&source)?);
    }
    Ok(documents)
}

/// Auto-accept a package's BENIGN runtime capabilities at the install gate.
///
/// Installing runs none of the package's source, so the capabilities a library
/// uses only when later called — network, DNS, env reads, file reads, the clock,
/// randomness — are not install-time risks. We grant them here so they don't
/// block the install (they remain recorded on the artifact as the runtime
/// profile). We deliberately do NOT grant: `ProcSpawn` (also represents npm
/// lifecycle scripts), `DynamicEval` (eval / unresolved obfuscation), or
/// `FsWrite` (persistence/backdoor) — those stay deny-by-default. Reads of
/// SENSITIVE files remain denied even though `FsRead("*")` is granted, because
/// the sensitive-read guard ignores wildcard grants. Data FLOWS are unaffected
/// (no flow is granted here), so a package that combines a secret read with a
/// sink still needs an explicit flow grant.
pub(crate) fn allow_benign_runtime_capabilities(policy: Policy) -> Policy {
    policy
        .allow_capability(Capability::EnvRead("*".to_owned()))
        .allow_capability(Capability::FsRead("*".to_owned()))
        .allow_capability(Capability::HttpHost("*".to_owned()))
        .allow_capability(Capability::DnsHost("*".to_owned()))
        .allow_capability(Capability::TimeNow)
        .allow_capability(Capability::RandomBytes)
}

pub fn parse_capability_grant(value: &str) -> Result<Capability> {
    if value == "dynamic-eval" || value == "dynamic.eval" {
        return Ok(Capability::DynamicEval);
    }
    if value == "time.now" || value == "time" {
        return Ok(Capability::TimeNow);
    }
    if value == "random.bytes" || value == "random" {
        return Ok(Capability::RandomBytes);
    }

    let (kind, target) = value
        .split_once(':')
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    let target = target.to_owned();

    match kind {
        "env" | "env.read" | "env-read" => Ok(Capability::EnvRead(target)),
        "fs.read" | "fs-read" => Ok(Capability::FsRead(target)),
        "fs.write" | "fs-write" => Ok(Capability::FsWrite(target)),
        "http" | "network" => Ok(Capability::HttpHost(target)),
        "dns" => Ok(Capability::DnsHost(target)),
        "proc" | "proc.spawn" | "proc-spawn" => Ok(Capability::ProcSpawn(target)),
        _ => Err(OmcRegistryError::UnsupportedSpec(value.to_owned())),
    }
}

pub fn parse_flow_rule(value: &str) -> Result<FlowRule> {
    let (from, to) = value
        .split_once("->")
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    Ok(FlowRule::new(
        parse_flow_label_matcher(from.trim())?,
        parse_flow_sink(to.trim())?,
    ))
}

fn parse_flow_label_matcher(value: &str) -> Result<LabelMatcher> {
    if matches!(value, "*" | "any") {
        return Ok(LabelMatcher::Any);
    }
    let (kind, target) = value
        .split_once(':')
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    let target = target.to_owned();
    match kind {
        "env" | "env.read" | "env-read" => Ok(LabelMatcher::Env(target)),
        "file" | "fs.read" | "fs-read" => Ok(LabelMatcher::File(target)),
        "secret" => Ok(LabelMatcher::Secret(target)),
        _ => Err(OmcRegistryError::UnsupportedSpec(value.to_owned())),
    }
}

fn parse_flow_sink(value: &str) -> Result<Sink> {
    if matches!(value, "eval" | "dynamic_eval" | "dynamic.eval") {
        return Ok(Sink::Eval);
    }
    let (kind, target) = value
        .split_once(':')
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
    let target = target.to_owned();
    match kind {
        "network" | "http" => Ok(Sink::Network(target)),
        "file" | "fs.write" | "fs-write" => Ok(Sink::File(target)),
        "process" | "proc" | "proc.spawn" | "proc-spawn" => Ok(Sink::Process(target)),
        _ => Err(OmcRegistryError::UnsupportedSpec(value.to_owned())),
    }
}

/// One blocked verifier finding, reduced to everything the CLI needs to explain
/// it and offer an EXACT, minimal grant. The raw machine token is always carried
/// verbatim (`raw`) so the audit trail is never replaced, only annotated.
#[derive(Debug, Clone)]
pub struct GrantNeed {
    /// The raw machine token, e.g. `env:NPM_TOKEN may not flow to network:evil.com`.
    pub raw: String,
    /// Consequence-first plain English describing what granting this permits.
    pub human: String,
    /// An exfiltration/backdoor warning for dangerous shapes (secret->sink,
    /// proc-spawn, eval, fs-write, sensitive read); `None` for benign reads.
    pub risk: Option<String>,
    /// The exact one-run CLI flag, e.g. `--allow-flow env:NPM_TOKEN->network:evil.com`.
    pub cli_flag: String,
    /// The equivalent `omc.policy` statement, e.g. `flow env "NPM_TOKEN" -> net "evil.com"`.
    pub policy_stmt: String,
    /// True for the deny-by-default classes that must never be one-keystroke
    /// granted (flows, proc-spawn, eval, fs-write, sensitive read).
    pub dangerous: bool,
}

/// Strip the `<function>[<instruction>]: ` prefix off a verifier finding.
fn finding_message(finding: &str) -> &str {
    finding.split_once("]: ").map(|(_, m)| m).unwrap_or(finding)
}

/// Render a `<kind>:<target>` capability token as its `omc.policy` `allow` clause.
pub(crate) fn dsl_allow_clause(token: &str) -> Option<String> {
    match token {
        "dynamic.eval" | "dynamic-eval" | "eval" => return Some("allow eval".to_owned()),
        "time.now" | "time" => return Some("allow time".to_owned()),
        "random.bytes" | "random" => return Some("allow random".to_owned()),
        _ => {}
    }
    let (kind, target) = token.split_once(':')?;
    let keyword = match kind {
        "env" | "env.read" | "env-read" => "env",
        "fs.read" | "fs-read" => "read",
        "fs.write" | "fs-write" => "write",
        "http" | "network" => "net",
        "dns" => "dns",
        "proc" | "proc.spawn" | "proc-spawn" => "spawn",
        _ => return None,
    };
    Some(format!("allow {keyword} {target:?}"))
}

/// Render a flow source token (`env:X` / `file:X` / `secret:X` / `*`) as its DSL form.
pub(crate) fn dsl_flow_src(token: &str) -> Option<String> {
    if token == "*" || token == "any" {
        return Some("any".to_owned());
    }
    let (kind, target) = token.split_once(':')?;
    let keyword = match kind {
        "env" | "env.read" | "env-read" => "env",
        "file" | "fs.read" | "fs-read" => "file",
        "secret" => "secret",
        _ => return None,
    };
    Some(format!("{keyword} {target:?}"))
}

/// Render a flow sink token (`network:Y` / `process:Y` / `file:Y` / `eval`) as its DSL form.
pub(crate) fn dsl_flow_sink(token: &str) -> Option<String> {
    if matches!(token, "eval" | "dynamic_eval" | "dynamic.eval") {
        return Some("eval".to_owned());
    }
    let (kind, target) = token.split_once(':')?;
    let keyword = match kind {
        "network" | "http" => "net",
        "process" | "proc" | "proc.spawn" | "proc-spawn" => "spawn",
        "file" | "fs.write" | "fs-write" => "write",
        _ => return None,
    };
    Some(format!("{keyword} {target:?}"))
}

/// Plain-English description of a flow source token (for the human line).
fn describe_flow_src(token: &str) -> String {
    match token.split_once(':') {
        Some(("env" | "env.read" | "env-read", "*")) => "your environment variables".to_owned(),
        Some(("env" | "env.read" | "env-read", t)) => {
            format!("the value of environment variable {t}")
        }
        Some(("file" | "fs.read" | "fs-read", "*")) => "files it reads".to_owned(),
        Some(("file" | "fs.read" | "fs-read", t)) => format!("the contents of file {t}"),
        Some(("secret", t)) => format!("the secret {t}"),
        _ => "a secret it read".to_owned(),
    }
}

/// Plain-English description of a flow sink token (for the human line).
fn describe_flow_sink(token: &str) -> String {
    if matches!(token, "eval" | "dynamic_eval" | "dynamic.eval") {
        return "dynamically evaluated code".to_owned();
    }
    match token.split_once(':') {
        Some(("network" | "http", "*")) => "the network (any host)".to_owned(),
        Some(("network" | "http", t)) => format!("the network host {t}"),
        Some(("process" | "proc" | "proc.spawn" | "proc-spawn", _)) => {
            "a spawned process".to_owned()
        }
        Some(("file" | "fs.write" | "fs-write", _)) => "a file it writes".to_owned(),
        _ => "an external sink".to_owned(),
    }
}

/// (human phrase, risk line, dangerous?) for a capability token.
fn describe_capability_token(token: &str) -> (String, Option<String>, bool) {
    match token {
        "dynamic.eval" | "dynamic-eval" | "eval" => (
            "run dynamically generated or loaded code (eval / exec / dynamic import)".to_owned(),
            Some("can hide arbitrary behavior from static analysis".to_owned()),
            true,
        ),
        "time.now" | "time" => ("read the current time".to_owned(), None, false),
        "random.bytes" | "random" => ("read secure random bytes".to_owned(), None, false),
        _ => {
            let (kind, target) = match token.split_once(':') {
                Some(kt) => kt,
                None => return (token.to_owned(), None, true),
            };
            match kind {
                "proc" | "proc.spawn" | "proc-spawn" => {
                    let human = if let Some(script) = target.strip_prefix("npm-script:") {
                        format!("run the npm lifecycle script `{script}` during install")
                    } else if target == "*" {
                        "spawn arbitrary processes".to_owned()
                    } else {
                        format!("spawn the process `{target}`")
                    };
                    (
                        human,
                        Some("install-time / arbitrary code execution".to_owned()),
                        true,
                    )
                }
                "fs.write" | "fs-write" => (
                    if target == "*" {
                        "write arbitrary files".to_owned()
                    } else {
                        format!("write the file {target}")
                    },
                    Some("could install a persistent backdoor".to_owned()),
                    true,
                ),
                "env" | "env.read" | "env-read" => {
                    (format!("read environment variable {target}"), None, false)
                }
                "fs.read" | "fs-read" => (
                    format!("read the file {target}"),
                    Some(
                        "reading a sensitive file (keys/credentials) stays blocked even here"
                            .to_owned(),
                    ),
                    true,
                ),
                "http" | "network" => (
                    if target == "*" {
                        "make network requests to any host".to_owned()
                    } else {
                        format!("make network requests to {target}")
                    },
                    None,
                    false,
                ),
                "dns" => (format!("resolve DNS for {target}"), None, false),
                _ => (token.to_owned(), None, true),
            }
        }
    }
}

/// Parse one verifier finding into a [`GrantNeed`] with a minimal grant. Returns
/// `None` only if the finding shape is unrecognized (the caller still shows the
/// raw line so nothing is silently dropped).
pub(crate) fn parse_block_finding(finding: &str) -> Option<GrantNeed> {
    let message = finding_message(finding);

    // Flow: `<source> may not flow to <sink>`.
    if let Some((src, sink)) = message.split_once(" may not flow to ") {
        let (src, sink) = (src.trim(), sink.trim());
        let human = format!(
            "send {} to {}",
            describe_flow_src(src),
            describe_flow_sink(sink)
        );
        let risk = Some(
            "this is the shape used to exfiltrate credentials/data — only allow it if you trust this package"
                .to_owned(),
        );
        let cli_flag = format!("--allow-flow {src}->{sink}");
        let policy_stmt = match (dsl_flow_src(src), dsl_flow_sink(sink)) {
            (Some(s), Some(d)) => format!("flow {s} -> {d}"),
            _ => return None,
        };
        return Some(GrantNeed {
            raw: message.to_owned(),
            human,
            risk,
            cli_flag,
            policy_stmt,
            dangerous: true,
        });
    }

    // Capability: `capability <kind>:<target> not granted`.
    let token = message
        .strip_prefix("capability ")
        .and_then(|s| s.strip_suffix(" not granted"))?
        .trim();
    let policy_stmt = dsl_allow_clause(token)?;
    let (human, risk, dangerous) = describe_capability_token(token);
    Some(GrantNeed {
        raw: message.to_owned(),
        human,
        risk,
        cli_flag: format!("--allow {token}"),
        policy_stmt,
        dangerous,
    })
}

/// Build the actionable, plain-language guidance shown when a package is blocked:
/// what it wants to do (human + raw token + risk), the exact one-run `--allow`
/// command, and a per-package, version-pinned `omc.policy` block to persist it.
/// All output is advisory text — it never grants anything.
pub(crate) fn render_block_guidance(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    findings: &[String],
) -> String {
    let mut needs: Vec<GrantNeed> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for finding in findings {
        match parse_block_finding(finding) {
            Some(need) if !needs.iter().any(|n| n.cli_flag == need.cli_flag) => needs.push(need),
            Some(_) => {}
            None => {
                let raw = finding_message(finding).to_owned();
                if !unknown.contains(&raw) {
                    unknown.push(raw);
                }
            }
        }
    }

    let mut out = String::new();
    out.push_str(&format!("  {name} was blocked. It wants to:\n"));
    for need in &needs {
        let marker = if need.dangerous { "!" } else { " " };
        out.push_str(&format!("    {marker} {}   ({})\n", need.human, need.raw));
        if let Some(risk) = &need.risk {
            out.push_str(&format!("      \u{2514} {risk}\n"));
        }
    }
    for raw in &unknown {
        out.push_str(&format!("    ! {raw}\n"));
    }

    if needs.is_empty() {
        return out;
    }

    let flags: Vec<&str> = needs.iter().map(|n| n.cli_flag.as_str()).collect();
    out.push_str("\n  To allow it for THIS run only:\n");
    out.push_str(&format!(
        "      omc add {ecosystem}:{name}@{version} \\\n        {}\n",
        flags.join(" \\\n        ")
    ));
    out.push_str(&format!(
        "\n  To trust {name} {version} everywhere (writes ~/.omc/policy.d/):\n"
    ));
    out.push_str(&format!(
        "      omc trust {ecosystem}:{name}@{version} {}\n",
        flags.join(" ")
    ));
    out.push_str(&format!(
        "\n  ...or add this version-pinned block to ./omc.policy (project) or\n  ~/.omc/policy.d/{name}.omc.policy (personal, applies everywhere):\n"
    ));
    out.push_str(&format!(
        "      {ecosystem} package {name:?} =={version} {{\n"
    ));
    for need in &needs {
        out.push_str(&format!("        {}\n", need.policy_stmt));
    }
    out.push_str("      }\n");
    out
}
