use std::path::Path;
use std::process::ExitCode;

use omc_policy::{
    Block, Cap, EcosystemQualifier, FlowSink, FlowSrc, PackageRule, Stmt, VersionConstraint,
    VersionOp,
};
use omc_registry::{
    add_manifest_policy_flows, add_manifest_policy_grants, write_global_package_trust,
    GlobalPolicyFile, OmcRegistryError, PackageSpec,
};

use crate::args::{PolicyCommand, PolicyListScope};

/// Dispatch `omc policy <list|check|validate>`.
pub(crate) fn run_policy_command(
    project_dir: &Path,
    action: PolicyCommand,
) -> Result<ExitCode, OmcRegistryError> {
    match action {
        PolicyCommand::Allow { flows, grants } => {
            run_policy_allow(project_dir, &grants, &flows)?;
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommand::Trust {
            spec,
            allow,
            allow_flow,
        } => {
            run_policy_trust(&spec, &allow, &allow_flow)?;
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommand::List { scope } => {
            match scope.unwrap_or(PolicyListScope::Global) {
                PolicyListScope::Global => print!("{}", global_policy_list_text()?),
            }
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommand::Validate => {
            match omc_registry::load_policy_document(project_dir)? {
                Some(_) => println!("omc.policy OK"),
                None => println!(
                    "no omc.policy in {} (deny-by-default)",
                    project_dir.display()
                ),
            }
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommand::Check { npm, pypi, package } => {
            // Parse NAME or NAME@VERSION; a leading `@scope/name` keeps its first
            // `@`, so only split on an `@` that is not at index 0.
            let (name, version) = match package
                .char_indices()
                .find(|&(idx, ch)| ch == '@' && idx > 0)
            {
                Some((idx, _)) => (&package[..idx], &package[idx + 1..]),
                None => (package.as_str(), "0.0.0"),
            };
            let ecosystem = match (npm, pypi) {
                (false, true) => omc_policy::Ecosystem::Pypi,
                // npm is the default when neither flag is given.
                _ => omc_policy::Ecosystem::Npm,
            };
            match omc_registry::load_policy_document(project_dir)? {
                Some(document) => {
                    print!("{}", document.explain_for(ecosystem, name, version));
                }
                None => {
                    let eco = match ecosystem {
                        omc_policy::Ecosystem::Npm => "npm",
                        omc_policy::Ecosystem::Pypi => "pypi",
                    };
                    println!(
                        "no omc.policy in {}; {eco}:{name}@{version} gets the deny-by-default policy \
                         (only omc.toml [policy] / CLI grants apply)",
                        project_dir.display()
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub(crate) fn run_policy_allow(
    project_dir: &Path,
    grants: &[String],
    flows: &[String],
) -> Result<(), OmcRegistryError> {
    if grants.is_empty() && flows.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "at least one grant is required".to_owned(),
        ));
    }
    let added = add_manifest_policy_grants(project_dir, grants)?;
    let added_flows = add_manifest_policy_flows(project_dir, flows)?;
    if added.is_empty() && added_flows.is_empty() {
        println!("policy unchanged");
    } else {
        for grant in added {
            println!("allowed {grant}");
        }
        for flow in added_flows {
            println!("allowed flow {flow}");
        }
    }
    Ok(())
}

pub(crate) fn run_policy_trust(
    spec: &str,
    allow: &[String],
    allow_flow: &[String],
) -> Result<(), OmcRegistryError> {
    if allow.is_empty() && allow_flow.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "at least one --allow or --allow-flow is required".to_owned(),
        ));
    }
    let parsed = PackageSpec::parse(spec)?;
    let version = parsed.version.as_deref().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!(
            "pin an exact version to trust, e.g. {}:{}@<version>",
            parsed.ecosystem, parsed.name
        ))
    })?;
    let path =
        write_global_package_trust(parsed.ecosystem, &parsed.name, version, allow, allow_flow)?;
    println!("trusted {spec}");
    println!("  wrote {}", path.display());
    Ok(())
}

pub(crate) fn global_policy_list_text() -> Result<String, OmcRegistryError> {
    let dir = omc_registry::global_policy_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "(unresolved)".to_owned());
    let files = omc_registry::list_global_policy_files()?;
    Ok(render_global_policy_files(&dir, &files))
}

pub(crate) fn render_global_policy_files(dir: &str, files: &[GlobalPolicyFile]) -> String {
    let mut out = format!("global policy trust store: {dir}\n");
    if files.is_empty() {
        out.push_str("  (no global policy files)\n");
        return out;
    }

    let rows = global_policy_rows(files);
    if rows.is_empty() {
        out.push_str("  (no accepted grants)\n");
        return out;
    }

    out.push('\n');
    write_table(
        &mut out,
        "",
        &["package", "version", "kind", "grant", "file"],
        &rows,
    );
    out
}

fn global_policy_rows(files: &[GlobalPolicyFile]) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for file in files {
        let file_label = policy_file_label(file);
        if let Some(default) = &file.document.default {
            append_block_rows(&mut rows, "default", "*", default, &file_label);
        }
        for rule in &file.document.packages {
            append_package_rule_rows(&mut rows, rule, &file_label);
        }
    }
    rows
}

fn policy_file_label(file: &GlobalPolicyFile) -> String {
    file.path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| file.path.display().to_string())
}

fn append_package_rule_rows(rows: &mut Vec<Vec<String>>, rule: &PackageRule, file_label: &str) {
    let package = match rule.ecosystem {
        Some(EcosystemQualifier::Npm) => format!("npm:{}", rule.name),
        Some(EcosystemQualifier::Pypi) => format!("pypi:{}", rule.name),
        None => rule.name.clone(),
    };
    let version = rule
        .constraint
        .as_ref()
        .map(version_constraint_text)
        .unwrap_or_else(|| "*".to_owned());
    append_block_rows(rows, &package, &version, &rule.block, file_label);
}

fn append_block_rows(
    rows: &mut Vec<Vec<String>>,
    package: &str,
    version: &str,
    block: &Block,
    file_label: &str,
) {
    if block.stmts.is_empty() {
        rows.push(vec![
            package.to_owned(),
            version.to_owned(),
            "block".to_owned(),
            "(empty)".to_owned(),
            file_label.to_owned(),
        ]);
        return;
    }

    for stmt in &block.stmts {
        append_stmt_rows(rows, package, version, stmt, file_label);
    }
}

fn append_stmt_rows(
    rows: &mut Vec<Vec<String>>,
    package: &str,
    version: &str,
    stmt: &Stmt,
    file_label: &str,
) {
    let mut push = |kind: &str, grant: String| {
        rows.push(vec![
            package.to_owned(),
            version.to_owned(),
            kind.to_owned(),
            grant,
            file_label.to_owned(),
        ]);
    };
    match stmt {
        Stmt::Pure => push("pure", "pure".to_owned()),
        Stmt::AllowSensitive => push("allow-sensitive", "sensitive file reads".to_owned()),
        Stmt::Allow(caps) => {
            for cap in caps {
                push("allow", cap_text(cap));
            }
        }
        Stmt::Deny(caps) => {
            for cap in caps {
                push("deny", cap_text(cap));
            }
        }
        Stmt::Flow { from, to } => {
            push(
                "flow",
                format!("{} -> {}", flow_src_text(from), flow_sink_text(to)),
            );
        }
        Stmt::MinAge(duration) => push("min-age", duration.clone()),
    }
}

fn version_constraint_text(constraint: &VersionConstraint) -> String {
    let op = match constraint.op {
        VersionOp::Eq => "==",
        VersionOp::Ge => ">=",
        VersionOp::Gt => ">",
        VersionOp::Le => "<=",
        VersionOp::Lt => "<",
        VersionOp::Caret => "^",
        VersionOp::Tilde => "~",
    };
    format!("{op}{}", constraint.version)
}

fn write_table(out: &mut String, indent: &str, headers: &[&str], rows: &[Vec<String>]) {
    use std::fmt::Write as _;
    if headers.is_empty() {
        return;
    }
    let mut widths = headers
        .iter()
        .map(|header| header.chars().count())
        .collect::<Vec<_>>();
    for row in rows {
        for (idx, cell) in row.iter().enumerate().take(widths.len()) {
            widths[idx] = widths[idx].max(cell.chars().count());
        }
    }

    write_table_row(
        out,
        indent,
        &headers.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>(),
        &widths,
    );
    let separator = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>();
    write_table_row(out, indent, &separator, &widths);
    for row in rows {
        write_table_row(out, indent, row, &widths);
    }
    let _ = writeln!(out);
}

fn write_table_row(out: &mut String, indent: &str, cells: &[String], widths: &[usize]) {
    use std::fmt::Write as _;
    let _ = write!(out, "{indent}");
    for (idx, width) in widths.iter().enumerate() {
        let cell = cells.get(idx).map(String::as_str).unwrap_or("");
        let _ = write!(out, "{cell}");
        if idx + 1 < widths.len() {
            let padding = width.saturating_sub(cell.chars().count());
            let _ = write!(out, "{}  ", " ".repeat(padding));
        }
    }
    let _ = writeln!(out);
}

fn cap_text(cap: &Cap) -> String {
    match cap {
        Cap::Env(value) => format!("env {value:?}"),
        Cap::Read(value) => format!("read {value:?}"),
        Cap::Write(value) => format!("write {value:?}"),
        Cap::Net(value) => format!("net {value:?}"),
        Cap::Dns(value) => format!("dns {value:?}"),
        Cap::Spawn(value) => format!("spawn {value:?}"),
        Cap::Eval => "eval".to_owned(),
        Cap::Time => "time".to_owned(),
        Cap::Random => "random".to_owned(),
    }
}

fn flow_src_text(src: &FlowSrc) -> String {
    match src {
        FlowSrc::Any => "*".to_owned(),
        FlowSrc::Env(value) => format!("env {value:?}"),
        FlowSrc::File(value) => format!("file {value:?}"),
        FlowSrc::Secret(value) => format!("secret {value:?}"),
    }
}

fn flow_sink_text(sink: &FlowSink) -> String {
    match sink {
        FlowSink::Net(value) => format!("net {value:?}"),
        FlowSink::Write(value) => format!("write {value:?}"),
        FlowSink::Spawn(value) => format!("spawn {value:?}"),
        FlowSink::Eval => "eval".to_owned(),
    }
}
