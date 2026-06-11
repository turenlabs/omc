//! `omc diff` — resolve and capability-profile two package versions (each into
//! its own throwaway directory, like `omc inspect`) and report what changed
//! between them: capability findings by (package, kind, target), the resolved
//! dependency set, and the deny-by-default verdicts. This is the
//! version-to-version escalation check — "does the upgrade request anything the
//! old version couldn't already do?" — the shape in which supply-chain
//! compromises typically land.
//!
//! Informational like inspect: nothing is installed and the exit code is always
//! 0; gate on the `escalation` field of `--json` output in CI.

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use omc_registry::{
    add_package_graph, CapabilityKind, LinkOptions, LinkReport, OmcRegistryError, PackageSpec,
    Verdict,
};

use crate::manifest::{ecosystem_hint, parse_package_specs};
use crate::render::print_diff_report;
use crate::scratch::ScratchDir;

/// Arguments for `omc diff`.
pub(crate) struct DiffCommand {
    pub(crate) npm: bool,
    pub(crate) pypi: bool,
    pub(crate) old_spec: String,
    pub(crate) new_spec: String,
    pub(crate) json: bool,
}

/// One capability present on only one side of the diff, keyed by
/// (package name, kind, target). `version` and `source` carry the evidence from
/// the side where the capability exists.
pub(crate) struct CapabilityChange {
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) kind: CapabilityKind,
    pub(crate) target: String,
    pub(crate) source: String,
}

/// A package present on both sides whose resolved version(s) changed.
pub(crate) struct PackageChange {
    pub(crate) name: String,
    pub(crate) old_version: String,
    pub(crate) new_version: String,
}

/// Per-side summary of a resolved graph.
pub(crate) struct DiffSide {
    pub(crate) requested: String,
    pub(crate) resolved: String,
    pub(crate) packages: usize,
    pub(crate) blocked: usize,
}

pub(crate) struct PackageDiff {
    pub(crate) old: DiffSide,
    pub(crate) new: DiffSide,
    pub(crate) added_capabilities: Vec<CapabilityChange>,
    pub(crate) removed_capabilities: Vec<CapabilityChange>,
    pub(crate) added_packages: Vec<(String, String)>,
    pub(crate) removed_packages: Vec<(String, String)>,
    pub(crate) changed_packages: Vec<PackageChange>,
}

impl PackageDiff {
    /// The new version escalates when it gains any capability anywhere in its
    /// tree, or when its tree has more blocked packages than the old one.
    pub(crate) fn escalates(&self) -> bool {
        !self.added_capabilities.is_empty() || self.new.blocked > self.old.blocked
    }
}

pub(crate) fn run_diff(command: DiffCommand) -> Result<ExitCode, OmcRegistryError> {
    let specs = parse_package_specs(
        &[command.old_spec.clone(), command.new_spec.clone()],
        ecosystem_hint(command.npm, command.pypi),
    )?;

    let old_reports = resolve_side("omc-diff-old", &specs[0])?;
    let new_reports = resolve_side("omc-diff-new", &specs[1])?;
    let diff = diff_reports(
        &command.old_spec,
        &command.new_spec,
        &old_reports,
        &new_reports,
    );

    if command.json {
        println!("{}", serde_json::to_string_pretty(&diff_json(&diff))?);
    } else {
        print_diff_report(&diff, &old_reports, &new_reports);
    }

    // Informational command, like inspect: nothing was installed, so there is
    // no deny-by-default action to fail. CI gates on the JSON `escalation`.
    Ok(ExitCode::SUCCESS)
}

/// Resolve one side of the diff into its own scratch dir; the two sides must
/// not share a lockfile or the second resolve would see the first's state.
fn resolve_side(prefix: &str, spec: &PackageSpec) -> Result<Vec<LinkReport>, OmcRegistryError> {
    let scratch = ScratchDir::new(prefix)?;
    let mut options = LinkOptions::new(scratch.path());
    options.record_blocked = true;
    add_package_graph(spec, &options)
}

pub(crate) fn diff_reports(
    old_requested: &str,
    new_requested: &str,
    old: &[LinkReport],
    new: &[LinkReport],
) -> PackageDiff {
    let old_caps = capability_index(old);
    let new_caps = capability_index(new);
    let added_capabilities = capability_changes(&new_caps, &old_caps);
    let removed_capabilities = capability_changes(&old_caps, &new_caps);

    let old_versions = package_versions(old);
    let new_versions = package_versions(new);
    // The diffed roots' own version change is the premise of the command, not a
    // dependency change — leave it out of the changed list when both sides
    // diff the same package.
    let root_name = match (old.first(), new.first()) {
        (Some(old_root), Some(new_root)) if old_root.locked.name == new_root.locked.name => {
            Some(old_root.locked.name.as_str())
        }
        _ => None,
    };
    let mut added_packages = Vec::new();
    let mut changed_packages = Vec::new();
    for (name, versions) in &new_versions {
        match old_versions.get(name) {
            None => added_packages.push((name.clone(), join_versions(versions))),
            Some(old) if old != versions && root_name != Some(name.as_str()) => changed_packages
                .push(PackageChange {
                    name: name.clone(),
                    old_version: join_versions(old),
                    new_version: join_versions(versions),
                }),
            Some(_) => {}
        }
    }
    let removed_packages = old_versions
        .iter()
        .filter(|(name, _)| !new_versions.contains_key(*name))
        .map(|(name, versions)| (name.clone(), join_versions(versions)))
        .collect();

    PackageDiff {
        old: side_summary(old_requested, old),
        new: side_summary(new_requested, new),
        added_capabilities,
        removed_capabilities,
        added_packages,
        removed_packages,
        changed_packages,
    }
}

/// (package name, kind, target) → (version, evidence source file), first
/// occurrence wins. Versions are intentionally NOT part of the key: a version
/// bump that keeps the same capability surface is "no change".
type CapabilityIndex = BTreeMap<(String, CapabilityKind, String), (String, String)>;

fn capability_index(reports: &[LinkReport]) -> CapabilityIndex {
    let mut index = CapabilityIndex::new();
    for report in reports {
        for finding in &report.artifact.capabilities {
            index
                .entry((
                    report.locked.name.clone(),
                    finding.kind,
                    finding.target.clone(),
                ))
                .or_insert_with(|| (report.locked.version.clone(), finding.source.clone()));
        }
    }
    index
}

/// Capabilities present in `from` but absent in `without`.
fn capability_changes(from: &CapabilityIndex, without: &CapabilityIndex) -> Vec<CapabilityChange> {
    from.iter()
        .filter(|(key, _)| !without.contains_key(*key))
        .map(
            |((package, kind, target), (version, source))| CapabilityChange {
                package: package.clone(),
                version: version.clone(),
                kind: *kind,
                target: target.clone(),
                source: source.clone(),
            },
        )
        .collect()
}

fn package_versions(reports: &[LinkReport]) -> BTreeMap<String, BTreeSet<String>> {
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for report in reports {
        versions
            .entry(report.locked.name.clone())
            .or_default()
            .insert(report.locked.version.clone());
    }
    versions
}

fn join_versions(versions: &BTreeSet<String>) -> String {
    versions.iter().cloned().collect::<Vec<_>>().join("/")
}

fn side_summary(requested: &str, reports: &[LinkReport]) -> DiffSide {
    let resolved = reports
        .first()
        .map(|root| {
            format!(
                "{}:{}@{}",
                root.locked.ecosystem, root.locked.name, root.locked.version
            )
        })
        .unwrap_or_else(|| requested.to_owned());
    DiffSide {
        requested: requested.to_owned(),
        resolved,
        packages: reports.len(),
        blocked: reports
            .iter()
            .filter(|r| r.locked.verdict == Verdict::Blocked)
            .count(),
    }
}

fn capability_change_json(change: &CapabilityChange) -> serde_json::Value {
    serde_json::json!({
        "package": change.package,
        "version": change.version,
        "kind": change.kind.to_string(),
        "target": change.target,
        "source": change.source,
    })
}

pub(crate) fn diff_json(diff: &PackageDiff) -> serde_json::Value {
    let side = |side: &DiffSide| {
        serde_json::json!({
            "requested": side.requested,
            "resolved": side.resolved,
            "packages": side.packages,
            "blocked": side.blocked,
        })
    };
    serde_json::json!({
        "old": side(&diff.old),
        "new": side(&diff.new),
        "added_capabilities": diff.added_capabilities.iter().map(capability_change_json).collect::<Vec<_>>(),
        "removed_capabilities": diff.removed_capabilities.iter().map(capability_change_json).collect::<Vec<_>>(),
        "added_packages": diff.added_packages.iter().map(|(name, version)| {
            serde_json::json!({"name": name, "version": version})
        }).collect::<Vec<_>>(),
        "removed_packages": diff.removed_packages.iter().map(|(name, version)| {
            serde_json::json!({"name": name, "version": version})
        }).collect::<Vec<_>>(),
        "changed_packages": diff.changed_packages.iter().map(|change| {
            serde_json::json!({
                "name": change.name,
                "old_version": change.old_version,
                "new_version": change.new_version,
            })
        }).collect::<Vec<_>>(),
        "escalation": diff.escalates(),
    })
}
