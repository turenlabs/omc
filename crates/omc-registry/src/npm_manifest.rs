//! npm manifest extraction and version-range parsing helpers.
//!
//! Pure parsing/compatibility logic for npm package manifests and version
//! documents: reading `package.json` out of a tarball, extracting runtime
//! dependency/peer/bundle fields, platform/engine compatibility checks, and the
//! semver-range satisfaction routines. Resolution dispatch and install
//! orchestration stay in `lib.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{Cursor, Read};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use flate2::read::GzDecoder;
use semver::Version;
use tar::Archive;

use crate::*;

pub(crate) fn npm_manifest_from_tgz(bytes: &[u8]) -> Result<NpmPackageManifest> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        if strip_first_path_component(Path::new(&path)).as_deref()
            != Some(Path::new("package.json"))
        {
            continue;
        }
        let mut content = String::new();
        entry.read_to_string(&mut content)?;
        return Ok(serde_json::from_str(&content)?);
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "npm tarball did not contain package.json".to_owned(),
    ))
}

pub(crate) fn npm_manifest_runtime_dependencies(
    manifest: &NpmPackageManifest,
) -> Vec<PackageDependency> {
    npm_dependency_fields(
        manifest.dependencies.clone(),
        manifest.optional_dependencies.clone(),
        manifest.bundle_dependencies.as_ref(),
        manifest.bundled_dependencies.as_ref(),
        manifest.peer_dependencies.clone(),
        manifest.peer_dependencies_meta.clone(),
    )
}

pub(crate) fn npm_manifest_platform_compatible(manifest: &NpmPackageManifest) -> bool {
    npm_platform_fields(
        manifest.os.as_ref(),
        manifest.cpu.as_ref(),
        manifest.libc.as_ref(),
    )
}

pub(crate) fn npm_manifest_engine_compatible(
    manifest: &NpmPackageManifest,
    options: &LinkOptions,
) -> bool {
    npm_engine_compatible(manifest.engines.as_ref(), options.npm_engine_strict)
}

pub(crate) fn npm_runtime_dependencies(version_doc: &NpmVersion) -> Vec<PackageDependency> {
    npm_dependency_fields(
        version_doc.dependencies.clone(),
        version_doc.optional_dependencies.clone(),
        version_doc.bundle_dependencies.as_ref(),
        version_doc.bundled_dependencies.as_ref(),
        version_doc.peer_dependencies.clone(),
        version_doc.peer_dependencies_meta.clone(),
    )
}

pub(crate) fn npm_dependency_fields(
    dependencies_field: Option<BTreeMap<String, String>>,
    optional_dependencies_field: Option<BTreeMap<String, String>>,
    bundle_dependencies: Option<&NpmStringList>,
    bundled_dependencies: Option<&NpmStringList>,
    peer_dependencies: Option<BTreeMap<String, String>>,
    peer_dependencies_meta: Option<BTreeMap<String, NpmPeerDependencyMeta>>,
) -> Vec<PackageDependency> {
    let mut dependencies = Vec::new();
    let bundled = npm_bundled_dependency_names(
        dependencies_field.as_ref(),
        optional_dependencies_field.as_ref(),
        bundle_dependencies,
        bundled_dependencies,
    );

    dependencies.extend(
        dependencies_field
            .unwrap_or_default()
            .into_iter()
            .filter(|(name, _)| !bundled.contains(name))
            .map(|(name, requirement)| npm_dependency(name, requirement, false, false)),
    );
    dependencies.extend(
        optional_dependencies_field
            .unwrap_or_default()
            .into_iter()
            .filter(|(name, _)| !bundled.contains(name))
            .map(|(name, requirement)| npm_dependency(name, requirement, true, false)),
    );
    dependencies.extend(
        required_peer_dependencies(
            peer_dependencies.unwrap_or_default(),
            peer_dependencies_meta.unwrap_or_default(),
        )
        .into_iter()
        .filter(|(name, _)| !bundled.contains(name))
        .map(|(name, requirement)| npm_dependency(name, requirement, false, true)),
    );

    dependencies.sort_by(|left, right| {
        left.spec
            .name
            .cmp(&right.spec.name)
            .then_with(|| left.spec.version.cmp(&right.spec.version))
            .then_with(|| left.optional.cmp(&right.optional))
            .then_with(|| left.peer.cmp(&right.peer))
    });
    dependencies.dedup_by(|left, right| {
        left.spec.name == right.spec.name && left.spec.version == right.spec.version
    });
    dependencies
}

pub(crate) fn npm_bundled_dependency_names(
    dependencies: Option<&BTreeMap<String, String>>,
    optional_dependencies: Option<&BTreeMap<String, String>>,
    bundle_dependencies: Option<&NpmStringList>,
    bundled_dependencies: Option<&NpmStringList>,
) -> BTreeSet<String> {
    let field = bundle_dependencies.or(bundled_dependencies);

    match field.and_then(NpmStringList::bool_value) {
        Some(true) => dependencies
            .cloned()
            .unwrap_or_default()
            .into_keys()
            .chain(
                optional_dependencies
                    .cloned()
                    .unwrap_or_default()
                    .into_keys(),
            )
            .collect(),
        Some(false) => BTreeSet::new(),
        None => field
            .map(NpmStringList::values)
            .unwrap_or_default()
            .into_iter()
            .collect(),
    }
}

pub(crate) fn npm_dependency(
    name: String,
    requirement: String,
    optional: bool,
    peer: bool,
) -> PackageDependency {
    PackageDependency {
        spec: PackageSpec::new(Ecosystem::Npm, name, Some(requirement)),
        optional,
        peer,
    }
}

pub(crate) fn required_peer_dependencies(
    peer_dependencies: BTreeMap<String, String>,
    peer_dependencies_meta: BTreeMap<String, NpmPeerDependencyMeta>,
) -> BTreeMap<String, String> {
    peer_dependencies
        .into_iter()
        .filter(|(name, _)| {
            !peer_dependencies_meta
                .get(name)
                .map(|meta| meta.optional)
                .unwrap_or(false)
        })
        .collect()
}

pub(crate) fn npm_platform_compatible(version_doc: &NpmVersion) -> bool {
    npm_platform_fields(
        version_doc.os.as_ref(),
        version_doc.cpu.as_ref(),
        version_doc.libc.as_ref(),
    )
}

pub(crate) fn npm_version_engine_compatible(
    version_doc: &NpmVersion,
    options: &LinkOptions,
) -> bool {
    npm_engine_compatible(version_doc.engines.as_ref(), options.npm_engine_strict)
}

pub(crate) fn npm_engine_compatible(
    engines: Option<&BTreeMap<String, String>>,
    strict: bool,
) -> bool {
    if !strict {
        return true;
    }
    let Some(node_requirement) = engines.and_then(|engines| engines.get("node")) else {
        return true;
    };
    let Some(node_version) = current_node_version() else {
        return true;
    };
    npm_engine_requirement_satisfied(&node_version, node_requirement)
}

fn current_node_version() -> Option<Version> {
    static CURRENT_NODE_VERSION: OnceLock<Option<Version>> = OnceLock::new();
    CURRENT_NODE_VERSION
        .get_or_init(|| {
            let output = Command::new("node").arg("--version").output().ok()?;
            if !output.status.success() {
                return None;
            }
            let version = String::from_utf8_lossy(&output.stdout);
            Version::parse(version.trim().trim_start_matches('v')).ok()
        })
        .clone()
}

pub(crate) fn npm_engine_requirement_satisfied(version: &Version, requirement: &str) -> bool {
    let version = version.to_string();
    requirement
        .split("||")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .any(|part| npm_version_satisfies(&version, &normalize_npm_engine_requirement(part)))
}

fn normalize_npm_engine_requirement(requirement: &str) -> String {
    let mut normalized = String::new();
    let mut previous_was_operator = false;
    for token in requirement.split_whitespace() {
        if previous_was_operator {
            normalized.push_str(token);
            previous_was_operator = false;
            continue;
        }
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(token);
        previous_was_operator = matches!(token, ">" | ">=" | "<" | "<=" | "=");
    }
    normalized
}

fn npm_platform_fields(
    os: Option<&NpmStringList>,
    cpu: Option<&NpmStringList>,
    libc: Option<&NpmStringList>,
) -> bool {
    npm_string_list_allows(os, Some(current_npm_os()))
        && npm_string_list_allows(cpu, Some(current_npm_cpu()))
        && npm_string_list_allows(libc, current_npm_libc())
}

pub(crate) fn npm_string_list_allows(list: Option<&NpmStringList>, current: Option<&str>) -> bool {
    let Some(list) = list else {
        return true;
    };
    let values = list.values();
    let Some(current) = current else {
        return values.iter().all(|value| value.strip_prefix('!').is_some());
    };

    if values
        .iter()
        .any(|value| value.strip_prefix('!') == Some(current))
    {
        return false;
    }

    let positive = values
        .iter()
        .filter(|value| !value.starts_with('!'))
        .collect::<Vec<_>>();
    positive.is_empty() || positive.iter().any(|value| value.as_str() == current)
}

pub(crate) fn current_npm_os() -> &'static str {
    match env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn current_npm_cpu() -> &'static str {
    match env::consts::ARCH {
        "x86_64" => "x64",
        "x86" | "i386" | "i586" | "i686" => "ia32",
        "aarch64" => "arm64",
        "arm" => "arm",
        "powerpc64" => "ppc64",
        "s390x" => "s390x",
        other => other,
    }
}

fn current_npm_libc() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    {
        Some("musl")
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        Some("glibc")
    }
    #[cfg(not(any(
        all(target_os = "linux", target_env = "musl"),
        all(target_os = "linux", target_env = "gnu")
    )))]
    {
        None
    }
}

pub(crate) fn is_exact_npm_version(requirement: &str) -> bool {
    Version::parse(requirement).is_ok()
}

pub(crate) fn npm_version_satisfies(version: &str, requirement: &str) -> bool {
    let raw_version = version.trim();
    let Ok(version) = Version::parse(version) else {
        return false;
    };
    let requirement = requirement.trim();

    if requirement.is_empty() || requirement == "*" || requirement == "latest" {
        return true;
    }
    if let Ok(exact) = Version::parse(requirement) {
        return version == exact;
    }
    let parts = requirement
        .replace(',', " ")
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parts.len() > 1 {
        return parts
            .iter()
            .all(|part| npm_version_satisfies(raw_version, part));
    }
    if let Some(base) = requirement
        .strip_prefix('^')
        .and_then(parse_partial_npm_version)
    {
        let upper = if base.major > 0 {
            Version::new(base.major + 1, 0, 0)
        } else if base.minor > 0 {
            Version::new(0, base.minor + 1, 0)
        } else {
            Version::new(0, 0, base.patch + 1)
        };
        return version >= base && version < upper;
    }
    if let Some(base) = requirement
        .strip_prefix('~')
        .and_then(parse_partial_npm_version)
    {
        let upper = Version::new(base.major, base.minor + 1, 0);
        return version >= base && version < upper;
    }

    requirement
        .replace(',', " ")
        .split_whitespace()
        .all(|part| npm_comparator_satisfied(&version, part))
}

fn npm_comparator_satisfied(version: &Version, comparator: &str) -> bool {
    for op in [">=", "<=", ">", "<", "="] {
        if let Some(raw) = comparator.strip_prefix(op) {
            let Some(required) = parse_partial_npm_version(raw) else {
                return false;
            };
            return match op {
                ">=" => version >= &required,
                "<=" => version <= &required,
                ">" => version > &required,
                "<" => version < &required,
                "=" => version == &required,
                _ => false,
            };
        }
    }

    if comparator == "*" || comparator.eq_ignore_ascii_case("x") {
        true
    } else if comparator.ends_with(".x") || comparator.ends_with(".*") {
        let prefix = comparator.trim_end_matches('x').trim_end_matches('*');
        version.to_string().starts_with(prefix)
    } else {
        parse_partial_npm_version(comparator)
            .map(|required| version == &required)
            .unwrap_or(false)
    }
}

pub(crate) fn parse_partial_npm_version(raw: &str) -> Option<Version> {
    let mut parts = raw.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    Some(Version::new(major, minor, patch))
}

pub fn compare_npm_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (Version::parse(left), Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}
