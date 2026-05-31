use crate::*;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::compile::{compile_source_default_name, infer_compile_ecosystem};
use crate::shim::{run_node, run_python};

#[derive(Debug)]
pub(crate) struct ExecCellCommand {
    pub(crate) source: PathBuf,
    pub(crate) name: Option<String>,
    pub(crate) version: String,
    pub(crate) args: Vec<i64>,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
    pub(crate) allow_sensitive: bool,
    pub(crate) fallback: bool,
}

/// Lower a supported source file into OMC microcode, then run it through the
/// real verify -> link -> execute pipeline (`omc_runtime`) inside the fueled
/// VM under the project policy. This is the in-cell execution path: the source
/// is parsed and lowered offline (never executed as host code), only verified
/// bytecode runs, and every capability is gated by the policy + broker.
///
/// If the source is outside the supported subset and `--fallback` is set, we
/// defer to the existing host-interpreter shim (node/python) so unsupported
/// packages still work, just without the in-cell guarantee.
pub(crate) fn run_exec_cell(
    project_dir: &Path,
    command: ExecCellCommand,
) -> Result<ExitCode, OmcRegistryError> {
    let ecosystem = infer_compile_ecosystem(&command.source, false, false)?;
    let pkg_name = command
        .name
        .clone()
        .unwrap_or_else(|| compile_source_default_name(&command.source));

    // batou:ignore file_read -- exec-cell is a CLI tool that lowers a
    // user-named source file by design; the path is the command's purpose, not
    // an injection (mirrors the existing `omc compile <source>` handler).
    let source = std::fs::read_to_string(&command.source)?;

    // Build the policy the same way for BOTH the leaf and graph paths: the
    // project manifest's persistent `[policy]` grants form the base, and the
    // one-shot CLI `--allow`/`--allow-flow` flags layer on top (matching
    // `omc add`/`compile`/`install` semantics). Without this unification the
    // graph path silently ignored the CLI flags and the leaf path silently
    // ignored the manifest. A bare-file run with no manifest just uses pure +
    // CLI grants.
    let mut capabilities = Vec::new();
    let mut flows = Vec::new();
    if let Ok(manifest) = omc_registry::read_manifest(project_dir.join("omc.toml")) {
        capabilities.extend(parse_grants(&manifest.policy.allow, false)?);
        flows.extend(parse_flow_grants(&manifest.policy.allow_flow)?);
    }
    capabilities.extend(parse_grants(&command.allow, command.allow_all_host)?);
    flows.extend(parse_flow_grants(&command.allow_flow)?);
    let mut policy = omc_cap::Policy::pure();
    for capability in capabilities {
        policy = policy.allow_capability(capability);
    }
    for flow in flows {
        policy = policy.allow_flow_rule(flow);
    }
    // Sensitive files (.ssh/.env/keys/tokens) are denied by default even under a
    // wildcard fs.read grant; --allow-sensitive opts out of that protection.
    if command.allow_sensitive {
        policy = policy.allow_sensitive_reads();
    }
    // Layer the optional `omc.policy` DSL for the entry package on top of the
    // manifest + CLI grants, so an in-cell run is held to the same per-package
    // block an installed package would be (no `omc.policy` => unchanged).
    policy = omc_registry::effective_package_policy(
        project_dir,
        policy,
        ecosystem,
        &pkg_name,
        &command.version,
    )?;

    // Lower the source through the matching front end (deny-by-default: an
    // unsupported construct is a hard FrontendError, surfaced below).
    let lowered = match ecosystem {
        Ecosystem::Npm => {
            let meta = omc_frontend_js::PackageMeta {
                package: pkg_name.clone(),
                version: command.version.clone(),
                declared_behavior: omc_format::BehaviorType::Unknown,
            };
            omc_frontend_js::compile(&source, &meta).map_err(|error| error.to_string())
        }
        Ecosystem::Pypi => {
            let meta = omc_frontend_py::PackageMeta {
                package: pkg_name.clone(),
                version: command.version.clone(),
                declared_behavior: omc_format::BehaviorType::Unknown,
            };
            omc_frontend_py::compile(&source, &meta).map_err(|error| error.to_string())
        }
    };

    // Both front ends return a shared CompileOutput { module, imports }. If the
    // entry imports third-party packages, we must assemble the whole lock graph
    // (entry + every transitive dependency) and run it via execute_project; a
    // single leaf cannot resolve cross-package CallImports.
    let output = match lowered {
        Ok(output) => output,
        Err(message) => {
            if command.fallback {
                eprintln!(
                    "omc exec-cell: `{}` is outside the supported subset ({message}); \
                     falling back to the host interpreter shim",
                    command.source.display()
                );
                let source_arg = command.source.to_string_lossy().to_string();
                return match ecosystem {
                    Ecosystem::Npm => run_node(project_dir, &[source_arg]),
                    Ecosystem::Pypi => run_python(project_dir, &[source_arg]),
                };
            }
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "{} cannot be lowered for in-cell execution: {message} \
                 (re-run with --fallback to use the host interpreter shim)",
                command.source.display()
            )));
        }
    };

    let call_args = command
        .args
        .iter()
        .map(|value| omc_taint::Labeled::public(omc_format::Value::Int(*value)))
        .collect::<Vec<_>>();

    // Graph path: the entry requires/imports lock-resolved packages, so build
    // and run the closed graph through execute_project_with_policy under the
    // unified policy (manifest grants + CLI one-shot grants), so `--allow`/
    // `--allow-flow` apply to the whole graph exactly as they do to a leaf run.
    // Deny-by-default; an unresolved/unlowerable dependency is a hard error,
    // never a host fallback unless --fallback was explicitly requested for an
    // unlowerable ENTRY above.
    if !output.imports.is_empty() {
        let mut broker = omc_cap::MemoryBroker::new();
        let target = omc_runtime::ExecTarget::EntryFile {
            path: command.source.clone(),
            name: pkg_name,
            version: command.version.clone(),
        };
        return render_exec_outcome(omc_runtime::execute_project_with_policy(
            project_dir,
            target,
            &policy,
            call_args,
            &mut broker,
        ));
    }

    // Leaf path: a self-contained entry with no imports runs directly under the
    // CLI-supplied policy (the same grant flags as `omc add`/`compile`).
    let module = output.module;
    let mut broker = omc_cap::MemoryBroker::new();
    render_exec_outcome(omc_runtime::execute_leaf(
        module,
        &policy,
        &mut broker,
        call_args,
    ))
}

/// Render the outcome of an in-cell execution (leaf or project graph) to stdout
/// (on success) or stderr (on denial/trap), mapping it to an exit code.
fn render_exec_outcome(
    outcome: Result<omc_taint::Labeled<omc_format::Value>, omc_runtime::ExecError>,
) -> Result<ExitCode, OmcRegistryError> {
    match outcome {
        Ok(result) => {
            println!("result {}", render_cell_value(&result.value));
            println!("label {:?}", result.label);
            Ok(ExitCode::SUCCESS)
        }
        Err(omc_runtime::ExecError::Verify { module, error }) => {
            eprintln!("denied: module `{module}` failed verification under the project policy");
            eprintln!("{error}");
            Ok(ExitCode::from(2))
        }
        Err(omc_runtime::ExecError::Trap(trap)) => {
            eprintln!("trapped: {trap}");
            Ok(ExitCode::from(2))
        }
        Err(other) => Err(OmcRegistryError::UnsupportedSpec(other.to_string())),
    }
}

/// Render an executed cell's result value for human-readable CLI output.
fn render_cell_value(value: &omc_format::Value) -> String {
    match value {
        omc_format::Value::Unit => "unit".to_owned(),
        omc_format::Value::Bool(boolean) => boolean.to_string(),
        omc_format::Value::Int(int) => int.to_string(),
        omc_format::Value::String(string) => format!("{string:?}"),
        omc_format::Value::Array(_) | omc_format::Value::Map(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| value.type_name().to_owned())
        }
    }
}
