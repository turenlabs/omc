//! verify — verdict evaluation + microcode bridge.
//!
//! Builds VM microcode from observed capability findings, runs the verifier
//! against the effective policy, and renders the resulting verdict/findings.
//! Extracted verbatim from lib.rs.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use omc_cap::{Capability, Policy};
use omc_format::{BehaviorType, CapOp, Function, HttpRequest, Module, Op, Value, VirtualPath};
use omc_verify::{verify_module, VerifyFinding};

pub(crate) fn grants_all_host_capabilities(capabilities: &[Capability]) -> bool {
    capabilities
        .iter()
        .any(|capability| matches!(capability, Capability::EnvRead(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::FsRead(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::FsWrite(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::HttpHost(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::DnsHost(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::ProcSpawn(target) if target == "*"))
        && capabilities
            .iter()
            .any(|capability| matches!(capability, Capability::DynamicEval))
}

pub fn compile_source_path(options: CompileSourceOptions) -> Result<CompileSourceReport> {
    let source_path = fs::canonicalize(&options.source_path)?;
    let source_url = file_url_from_path(&source_path, "compile source path")?;
    let filename = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source")
        .to_owned();
    let package = ResolvedPackage {
        ecosystem: options.ecosystem,
        name: options.name.clone(),
        version: options.version.clone(),
        source_url: source_url.clone(),
        download_url: None,
        local_path: Some(source_path.clone()),
        filename,
        expected_sha256: None,
        expected_sha1: None,
        expected_integrity: None,
        npm_direct_tarball: false,
        pypi_direct_wheel: false,
        npm_scripts: BTreeMap::new(),
        platform_compatible: true,
        dependencies: Vec::new(),
    };
    let (source_sha256, profile) = if source_path.is_dir() {
        (
            hash_profiled_directory(&source_path)?,
            profile_source_directory(&source_path)?,
        )
    } else {
        let bytes = fs::read(&source_path)?;
        (sha256_hex(&bytes), profile_archive(&package, &bytes)?)
    };
    let module = module_from_profile(&package, &profile.capabilities);
    let explicit_grants_all_host = grants_all_host_capabilities(&options.allowed_capabilities);
    let policy = default_public_capabilities()
        .into_iter()
        .chain(options.allowed_capabilities.iter().cloned())
        .fold(Policy::pure(), Policy::allow_capability);
    let policy = options
        .allowed_flows
        .iter()
        .cloned()
        .fold(policy, Policy::allow_flow_rule);
    let policy = if explicit_grants_all_host {
        policy.allow_all_flows()
    } else {
        policy
    };
    // Layer the optional `omc.policy` DSL for this compiled local source too, so
    // a locally-compiled package is held to the same per-package block an
    // installed one would be.
    let policy = effective_package_policy(
        &options.project_dir,
        policy,
        package.ecosystem,
        &package.name,
        &package.version,
    )?;
    let mut verifier_findings = verify_module(&module, &policy)
        .err()
        .map(|error| {
            error
                .findings
                .into_iter()
                .map(render_verify_finding)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // OPTIONAL sound dataflow verification (flagged, default OFF) — same additive
    // contract as the install path. No-op unless the flag is set; when ON it
    // lowers the compiled JS source(s) and folds the sound engine's findings in,
    // so the verdict can only strengthen. See docs/SOUND-VERIFY.md.
    if crate::sound_verify::sound_verify_enabled(false) {
        if source_path.is_dir() {
            verifier_findings.extend(crate::sound_verify::sound_verify_js_directory(
                &package,
                &source_path,
                &policy,
            ));
        } else {
            let bytes = fs::read(&source_path)?;
            verifier_findings.extend(crate::sound_verify::sound_verify_js_archive(
                &package, &bytes, &policy,
            ));
        }
    }
    let verdict = if verifier_findings.is_empty() {
        Verdict::Accepted
    } else {
        Verdict::Blocked
    };
    let behavior = if profile.capabilities.is_empty() {
        Behavior::Pure
    } else {
        Behavior::HostCapability
    };
    let mut artifact = OmcArtifact {
        schema: ARTIFACT_SCHEMA,
        package: ArtifactPackage {
            ecosystem: options.ecosystem,
            name: options.name,
            version: options.version,
        },
        source_url,
        source_sha256,
        compiler: "omc-prototype-source-profiler".to_owned(),
        microcode: module,
        behavior,
        verdict,
        grants: options
            .allowed_capabilities
            .iter()
            .map(ToString::to_string)
            .collect(),
        dependencies: Vec::new(),
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        files_scanned: profile.files_scanned,
        capabilities: profile.capabilities,
        verifier_findings,
        signature: None,
    };
    sign_artifact(&options.project_dir, &mut artifact)?;
    let artifact_path = if options.write_artifact {
        Some(write_artifact(&options.project_dir, &package, &artifact)?)
    } else {
        None
    };

    Ok(CompileSourceReport {
        artifact,
        artifact_path,
    })
}

fn file_url_from_path(path: &Path, description: &str) -> Result<String> {
    reqwest::Url::from_file_path(path)
        .map(|url| url.to_string())
        .map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "{description} `{}` could not be converted to a file URL",
                path.display()
            ))
        })
}

pub(crate) fn module_from_profile(
    package: &ResolvedPackage,
    capabilities: &[CapabilityFinding],
) -> Module {
    let capabilities = unique_capability_findings(capabilities);
    let behavior = if capabilities.is_empty() {
        BehaviorType::Pure
    } else {
        BehaviorType::HostCapability
    };
    // F2: model a tainted DATA FLOW from EVERY sensitive source (env/file read)
    // to EVERY sink (network, process spawn, fs write, dynamic eval) so the
    // verifier's `check_flows` evaluates each source->sink pair. Previously only
    // the env-read x http pairing was wired (`body_from_stack`), so fs-read->net,
    // env->proc, env->eval and env->fs-write were silently Accepted at install
    // time even though the identical env->http pattern was Blocked. We emit, for
    // each (source, sink) pair, a self-contained `push source; consume in sink`
    // sequence; the sink's *_from_stack flag makes the verifier pop the tainted
    // label and run the flow check, requiring a covering flow grant to pass.
    let mut code = Vec::new();
    let is_source = |finding: &&CapabilityFinding| {
        matches!(
            finding.kind,
            CapabilityKind::EnvRead | CapabilityKind::FsRead
        )
    };
    let is_sink = |finding: &&CapabilityFinding| {
        matches!(
            finding.kind,
            CapabilityKind::HttpRequest
                | CapabilityKind::ProcSpawn
                | CapabilityKind::FsWrite
                | CapabilityKind::DynamicEval
        )
    };
    let sources = capabilities.iter().filter(is_source).collect::<Vec<_>>();
    let sinks = capabilities.iter().filter(is_sink).collect::<Vec<_>>();

    if sources.is_empty() || sinks.is_empty() {
        // No source->sink edge to model; emit each capability once so the
        // per-capability grant check (and the F1 DynamicEval deny) still runs.
        for finding in &capabilities {
            code.push(Op::Cap(cap_op_from_finding(finding)));
        }
    } else {
        for source in &sources {
            for sink in &sinks {
                code.push(Op::Cap(cap_op_from_finding(source)));
                code.push(Op::Cap(sink_cap_op_consuming_stack(sink)));
            }
        }
        // Emit sources/sinks once more standalone is unnecessary: every source
        // and every sink already appears in at least one pair above, so their
        // capability grant is checked. Nothing else to add.
    }
    code.push(Op::Const(Value::Unit));
    code.push(Op::Return);

    Module {
        id: format!("{}:{}@{}", package.ecosystem, package.name, package.version),
        package: package.name.clone(),
        version: package.version.clone(),
        declared_behavior: behavior,
        functions: vec![Function::new(0, "package_init", 0, code)],
    }
}

fn unique_capability_findings(capabilities: &[CapabilityFinding]) -> Vec<CapabilityFinding> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for finding in capabilities {
        if seen.insert((finding.kind, finding.target.clone())) {
            unique.push(finding.clone());
        }
    }
    unique
}

fn cap_op_from_finding(finding: &CapabilityFinding) -> CapOp {
    match finding.kind {
        CapabilityKind::EnvRead => CapOp::EnvRead {
            name: finding.target.clone(),
        },
        CapabilityKind::FsRead => CapOp::FsRead {
            path: VirtualPath(finding.target.clone()),
        },
        CapabilityKind::FsWrite => CapOp::FsWrite {
            path: VirtualPath(finding.target.clone()),
            value_from_stack: false,
        },
        CapabilityKind::HttpRequest => CapOp::HttpRequest {
            request: HttpRequest {
                method: "POST".to_owned(),
                url: "omc://observed-network".to_owned(),
                host: finding.target.clone(),
                body_from_stack: false,
            },
        },
        CapabilityKind::ProcSpawn => CapOp::ProcSpawn {
            command: finding.target.clone(),
            args: Vec::new(),
            args_from_stack: 0,
        },
        CapabilityKind::DynamicEval => CapOp::DynamicEval {
            source_from_stack: false,
        },
    }
}

/// Build the sink CapOp for a finding with its from-stack flag set, so the
/// verifier pops the tainted source label pushed immediately before it and runs
/// `check_flows` for the source->sink pair (F2). Non-sink findings fall back to
/// the plain op.
fn sink_cap_op_consuming_stack(finding: &CapabilityFinding) -> CapOp {
    match finding.kind {
        CapabilityKind::HttpRequest => CapOp::HttpRequest {
            request: HttpRequest {
                method: "POST".to_owned(),
                url: "omc://observed-network".to_owned(),
                host: finding.target.clone(),
                body_from_stack: true,
            },
        },
        CapabilityKind::ProcSpawn => CapOp::ProcSpawn {
            command: finding.target.clone(),
            args: Vec::new(),
            args_from_stack: 1,
        },
        CapabilityKind::FsWrite => CapOp::FsWrite {
            path: VirtualPath(finding.target.clone()),
            value_from_stack: true,
        },
        CapabilityKind::DynamicEval => CapOp::DynamicEval {
            source_from_stack: true,
        },
        // Not a sink: emit the plain op (no stack consumption).
        CapabilityKind::EnvRead | CapabilityKind::FsRead => cap_op_from_finding(finding),
    }
}

pub(crate) fn render_verify_finding(finding: VerifyFinding) -> String {
    format!(
        "{}[{}]: {}",
        finding.function, finding.instruction, finding.message
    )
}
