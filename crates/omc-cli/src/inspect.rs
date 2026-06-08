//! `omc inspect` — resolve and capability-profile one or more registry packages
//! and either print the full per-package report (`--format text`, the default)
//! or render a dependency-graph PNG (`--format png`, the surface formerly
//! exposed as `omc graph`), WITHOUT touching the user's project (no omc.lock,
//! omc.toml, node_modules, or site-packages writes).
//!
//! Inspect is informational: it resolves the dependency graph into a throwaway
//! temporary directory (used only as `LinkOptions::project_dir`), records blocked
//! packages instead of aborting on the first denial, renders the report, and
//! exits 0 even when a package would be blocked — the deny-by-default verdict is
//! still shown in full, it is just not enforced as a non-zero exit here because
//! nothing is being installed.

use std::path::PathBuf;
use std::process::ExitCode;

use omc_registry::{add_package_graph, LinkOptions, LinkReport, OmcRegistryError, PackageSpec};

use crate::args::InspectFormat;
use crate::graph::{render_graph, DependencyGraph};
use crate::manifest::{ecosystem_hint, parse_package_specs};
use crate::policy_args::apply_cli_policy_options;
use crate::render::print_inspect_report;

/// Default PNG path used by `--format png` when `--output` is omitted (matches
/// the legacy `omc graph` default).
const DEFAULT_GRAPH_OUTPUT: &str = "omc-graph.png";

/// Arguments for `omc inspect`, mirroring the resolve-relevant subset of `add`
/// plus the output format and (for `--format png`) the PNG path.
pub(crate) struct InspectCommand {
    pub(crate) npm: bool,
    pub(crate) pypi: bool,
    pub(crate) specs: Vec<String>,
    pub(crate) format: InspectFormat,
    pub(crate) output: Option<PathBuf>,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
}

pub(crate) fn run_inspect(command: InspectCommand) -> Result<ExitCode, OmcRegistryError> {
    let specs = parse_package_specs(&command.specs, ecosystem_hint(command.npm, command.pypi))?;

    // Resolve into a unique throwaway directory so NOTHING is written to the
    // user's cwd/project: any omc.lock, omc.toml, archives, or artifacts that
    // resolution materializes land here and are removed when we return.
    let scratch = ScratchDir::new()?;

    let mut options = LinkOptions::new(scratch.path());
    // Record (don't throw on) blocked packages so a blocked dependency is still
    // reported in full rather than aborting the whole inspection.
    options.record_blocked = true;
    apply_cli_policy_options(
        &mut options,
        &command.allow,
        &command.allow_flow,
        command.allow_all_host,
    )?;

    let reports = resolve_reports(&specs, &options)?;

    match command.format {
        InspectFormat::Text => print_inspect_report(&reports),
        InspectFormat::Png => render_inspect_png(&reports, command.output)?,
    }

    // Informational command: always exit 0, even if a package would be blocked.
    // The blocked verdict is shown in the report above; inspect does not install
    // anything, so there is no deny-by-default action to fail.
    Ok(ExitCode::SUCCESS)
}

/// Render the resolved reports to a dependency-graph PNG at `output` (or the
/// default path). This is the body of the former `omc graph` command, now
/// reached via `omc inspect --format png`.
fn render_inspect_png(
    reports: &[LinkReport],
    output: Option<PathBuf>,
) -> Result<(), OmcRegistryError> {
    let output = output.unwrap_or_else(|| PathBuf::from(DEFAULT_GRAPH_OUTPUT));
    let graph = DependencyGraph::from_reports(reports);
    let pixmap = render_graph(&graph);
    pixmap
        .save_png(&output)
        .map_err(|err| OmcRegistryError::UnsupportedSpec(format!("failed to write PNG: {err}")))?;
    println!(
        "wrote {} ({} nodes, {} edges)",
        output.display(),
        graph.nodes.len(),
        graph.edges.len()
    );
    Ok(())
}

fn resolve_reports(
    specs: &[PackageSpec],
    options: &LinkOptions,
) -> Result<Vec<LinkReport>, OmcRegistryError> {
    let mut reports = Vec::new();
    for spec in specs {
        reports.extend(add_package_graph(spec, options)?);
    }
    Ok(reports)
}

/// A unique temporary directory that is best-effort removed on drop. Used purely
/// as a sandboxed `LinkOptions::project_dir` so inspection never writes into the
/// user's project.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new() -> Result<Self, OmcRegistryError> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("omc-inspect-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
