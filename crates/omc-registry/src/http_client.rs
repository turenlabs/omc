//! Artifact download + caching.

use crate::*;

use std::fs;
use std::path::{Path, PathBuf};

use reqwest::blocking::Client;

pub(crate) fn download_artifact(
    client: &Client,
    package: &ResolvedPackage,
    project_dir: &Path,
) -> Result<Vec<u8>> {
    if let Some(path) = &package.local_path {
        return Ok(fs::read(path)?);
    }

    // Global content-addressed cache: a registry artifact for a given
    // (ecosystem, name, version, filename) is immutable, so a cache hit can be
    // reused across every project — download each artifact once, ever. We
    // re-verify the cached bytes against the expected hash (self-healing: a
    // corrupt/mismatched entry is dropped and refetched), and the caller still
    // runs its full hash verification on whatever we return.
    let cache_path = global_artifact_cache_path(package);
    if let Some(cache_path) = &cache_path {
        if let Ok(bytes) = fs::read(cache_path) {
            if global_cache_bytes_ok(package, &bytes) {
                return Ok(bytes);
            }
            let _ = fs::remove_file(cache_path);
        }
    }

    let source_url = package
        .download_url
        .as_deref()
        .unwrap_or(&package.source_url);
    let config = if package.ecosystem == Ecosystem::Npm {
        Some(read_npm_config(project_dir)?)
    } else {
        None
    };
    let request = if let Some(config) = config.as_ref() {
        npm_get(client, source_url, config)
    } else {
        client.get(source_url)
    };
    let bytes = request.send()?.error_for_status()?.bytes()?.to_vec();

    if let Some(cache_path) = &cache_path {
        if global_cache_bytes_ok(package, &bytes) {
            store_global_cache(cache_path, &bytes);
        }
    }
    Ok(bytes)
}

/// The global cache path for a registry artifact, under `$OMC_HOME/cache`
/// (default `~/.omc/cache`). `None` for local-path packages (read directly) or
/// when no home directory can be resolved.
fn global_artifact_cache_path(package: &ResolvedPackage) -> Option<PathBuf> {
    if package.local_path.is_some() {
        return None;
    }
    Some(
        global_omc_home()?
            .join("cache")
            .join(package.ecosystem.to_string())
            .join(safe_name(&package.name))
            .join(&package.version)
            .join(safe_name(&package.filename)),
    )
}

/// Whether `bytes` satisfy whatever expected hash the package carries (sha256 or
/// npm integrity). With no expected hash we trust the immutable cache key and let
/// the caller's own verification be the backstop.
fn global_cache_bytes_ok(package: &ResolvedPackage, bytes: &[u8]) -> bool {
    if let Some(expected) = &package.expected_sha256 {
        return expected.eq_ignore_ascii_case(&sha256_hex(bytes));
    }
    if let Some(integrity) = &package.expected_integrity {
        return verify_npm_integrity(&package.name, integrity, bytes).is_ok();
    }
    true
}

/// Write `bytes` to the global cache atomically (temp file + rename) so a partial
/// write is never observed and concurrent writers of the same artifact don't
/// corrupt it. A per-thread temp name keeps parallel workers from colliding.
fn store_global_cache(cache_path: &Path, bytes: &[u8]) {
    if cache_path.exists() {
        return;
    }
    let Some(dir) = cache_path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let file_name = cache_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    let tmp = dir.join(format!(".{file_name}.tmp-{:?}", std::thread::current().id()));
    if fs::write(&tmp, bytes).is_ok() {
        let _ = fs::rename(&tmp, cache_path);
    }
    let _ = fs::remove_file(&tmp);
}

pub(crate) fn cache_archive(
    project_dir: &Path,
    package: &ResolvedPackage,
    sha256: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    let cache_dir = project_dir
        .join(".omc")
        .join("cache")
        .join(package.ecosystem.to_string())
        .join(safe_name(&package.name))
        .join(&package.version);
    fs::create_dir_all(&cache_dir)?;

    let extension = archive_extension(&package.filename);
    let archive_path = cache_dir.join(format!("{sha256}.{extension}"));
    if !archive_path.exists() {
        fs::write(&archive_path, bytes)?;
    }
    Ok(archive_path)
}

pub(crate) fn write_artifact(
    project_dir: &Path,
    package: &ResolvedPackage,
    artifact: &OmcArtifact,
) -> Result<PathBuf> {
    let artifact_path = artifact_path_for(
        project_dir,
        package.ecosystem,
        &package.name,
        &package.version,
    );
    let artifact_dir = artifact_path.parent().ok_or_else(|| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "artifact path `{}` has no parent",
            artifact_path.display()
        ))
    })?;
    fs::create_dir_all(artifact_dir)?;

    fs::write(&artifact_path, serde_json::to_string_pretty(artifact)?)?;
    Ok(artifact_path)
}

pub(crate) fn artifact_path_for(
    project_dir: &Path,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> PathBuf {
    project_dir
        .join(".omc")
        .join("artifacts")
        .join(ecosystem.to_string())
        .join(safe_name(name))
        .join(version)
        .join("omc.json")
}

fn archive_extension(filename: &str) -> &'static str {
    if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        "tgz"
    } else if filename.ends_with(".whl") {
        "whl"
    } else if filename.ends_with(".zip") {
        "zip"
    } else {
        "archive"
    }
}
