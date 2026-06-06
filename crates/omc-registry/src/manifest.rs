//! `omc.toml` read/write plus grant editing (manifest policy/flows/local paths)
//! and the global per-package trust drop-in writer.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::*;

/// Initialize an `omc` project: create `.omc/`, an `omc.toml` manifest, and an
/// `omc.lock` lockfile if they do not already exist. Returns the manifest path.
pub fn init_project(project_dir: impl AsRef<Path>, name: Option<&str>) -> Result<PathBuf> {
    let project_dir = project_dir.as_ref();
    fs::create_dir_all(project_dir.join(".omc"))?;

    let manifest_path = project_dir.join(MANIFEST);
    if !manifest_path.exists() {
        let project_name = name.map(str::to_owned).unwrap_or_else(|| {
            project_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("omc-project")
                .to_owned()
        });
        let manifest = OmcManifest::new(project_name);
        fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    }

    let lockfile_path = project_dir.join(LOCKFILE);
    if !lockfile_path.exists() {
        fs::write(&lockfile_path, toml::to_string_pretty(&OmcLock::new())?)?;
    }

    Ok(manifest_path)
}

pub fn read_manifest(path: impl AsRef<Path>) -> Result<OmcManifest> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(OmcManifest::new("omc-project"));
    }
    // batou:ignore file_read -- `path` is the operator-chosen `omc.toml` manifest
    // location; reading it is the explicit purpose of this function (same pattern
    // as `load_policy_document` reading `omc.policy`).
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

pub fn add_manifest_npm_local_paths(
    project_dir: impl AsRef<Path>,
    paths: &[PathBuf],
    kind: ManifestDependencyKind,
) -> Result<Vec<String>> {
    let project_dir = project_dir.as_ref();
    init_project(project_dir, None)?;

    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    for path in paths {
        let path = path.to_string_lossy();
        manifest
            .npm_local_paths
            .retain(|existing| existing != &path);
        manifest
            .npm_dev_local_paths
            .retain(|existing| existing != &path);
        manifest
            .npm_optional_local_paths
            .retain(|existing| existing != &path);
        manifest
            .npm_peer_local_paths
            .retain(|existing| existing != &path);
    }
    let target = manifest_npm_local_paths_mut(&mut manifest, kind);
    let mut existing = target.iter().cloned().collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for path in paths {
        let path = path.to_string_lossy().into_owned();
        if existing.insert(path.clone()) {
            added.push(path);
        }
    }
    *target = existing.into_iter().collect();
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(added)
}

fn manifest_npm_local_paths_mut(
    manifest: &mut OmcManifest,
    kind: ManifestDependencyKind,
) -> &mut Vec<String> {
    match kind {
        ManifestDependencyKind::Production => &mut manifest.npm_local_paths,
        ManifestDependencyKind::Dev => &mut manifest.npm_dev_local_paths,
        ManifestDependencyKind::Optional => &mut manifest.npm_optional_local_paths,
        ManifestDependencyKind::Peer => &mut manifest.npm_peer_local_paths,
    }
}

pub fn add_manifest_policy_grants(
    project_dir: impl AsRef<Path>,
    grants: &[String],
) -> Result<Vec<String>> {
    let project_dir = project_dir.as_ref();
    init_project(project_dir, None)?;

    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    let mut existing = manifest
        .policy
        .allow
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for grant in grants {
        let normalized = parse_capability_grant(grant)?.to_string();
        if existing.insert(normalized.clone()) {
            added.push(normalized);
        }
    }
    manifest.policy.allow = existing.into_iter().collect();
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(added)
}

pub fn add_manifest_policy_flows(
    project_dir: impl AsRef<Path>,
    flows: &[String],
) -> Result<Vec<String>> {
    let project_dir = project_dir.as_ref();
    init_project(project_dir, None)?;

    let manifest_path = project_dir.join(MANIFEST);
    let mut manifest = read_manifest(&manifest_path)?;
    let mut existing = manifest
        .policy
        .allow_flow
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for flow in flows {
        let normalized = parse_flow_rule(flow)?.to_string();
        if existing.insert(normalized.clone()) {
            added.push(normalized);
        }
    }
    manifest.policy.allow_flow = existing.into_iter().collect();
    fs::write(&manifest_path, toml::to_string_pretty(&manifest)?)?;
    Ok(added)
}

fn sanitize_policy_filename(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

/// Persist a per-package, version-pinned trust block to the global drop-in dir
/// `$OMC_HOME/policy.d/<name>.omc.policy` (default `~/.omc/policy.d/`). Grants and
/// flows are validated and rendered as an `omc.policy` package block; the file is
/// overwritten (re-trusting a package updates its pin). Returns the written path.
pub fn write_global_package_trust(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    grants: &[String],
    flows: &[String],
) -> Result<PathBuf> {
    // Validate every grant/flow up front so we never write a malformed file.
    for grant in grants {
        parse_capability_grant(grant)?;
    }
    for flow in flows {
        parse_flow_rule(flow)?;
    }

    let mut block = String::new();
    block.push_str("# Written by `omc policy trust`: a per-package, version-pinned grant.\n");
    block.push_str("# Delete this file to revoke. Applies to this exact version only.\n");
    block.push_str(&format!("{ecosystem} package {name:?} =={version} {{\n"));
    for grant in grants {
        if let Some(stmt) = dsl_allow_clause(grant) {
            block.push_str(&format!("  {stmt}\n"));
        }
    }
    for flow in flows {
        if let Some((src, sink)) = flow.split_once("->") {
            if let (Some(s), Some(d)) = (dsl_flow_src(src.trim()), dsl_flow_sink(sink.trim())) {
                block.push_str(&format!("  flow {s} -> {d}\n"));
            }
        }
    }
    block.push_str("}\n");

    // The rendered block must parse with the real DSL (defense in depth).
    omc_policy::parse(&block)?;

    let dir = global_omc_home()
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "cannot resolve home directory for ~/.omc/policy.d".to_owned(),
            )
        })?
        .join("policy.d");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.omc.policy", sanitize_policy_filename(name)));
    fs::write(&path, block)?;
    Ok(path)
}
