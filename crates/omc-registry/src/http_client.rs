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
    Ok(request.send()?.error_for_status()?.bytes()?.to_vec())
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
