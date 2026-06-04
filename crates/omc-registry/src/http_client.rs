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

/// A temp-file suffix unique across processes AND threads: `<pid>-<thread>-<n>`.
/// `thread::current().id()` alone is process-local, so two concurrent `omc`
/// processes sharing one `$OMC_HOME` (e.g. parallel installs, CI, the smoke
/// harness) would otherwise pick the SAME temp path, interleave their writes,
/// and rename a corrupt cache entry into place. The pid disambiguates processes
/// and the counter disambiguates repeated writes on one thread.
static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub(crate) fn unique_tmp_suffix() -> String {
    format!(
        "{}-{:?}-{}",
        std::process::id(),
        std::thread::current().id(),
        TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// Write `bytes` to the global cache atomically (temp file + rename) so a partial
/// write is never observed and concurrent writers of the same artifact — even in
/// separate processes — never corrupt it.
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
    let tmp = dir.join(format!(".{file_name}.tmp-{}", unique_tmp_suffix()));
    if fs::write(&tmp, bytes).is_ok() {
        let _ = fs::rename(&tmp, cache_path);
    }
    let _ = fs::remove_file(&tmp);
}

/// Read-through cache for a registry metadata GET (packument / version doc),
/// keyed by request URL under `$OMC_HOME/cache/meta`. Returns `Ok(None)` for a
/// 404 (package/version not found) so callers keep their not-found handling;
/// other HTTP errors still propagate. Only 200 bodies are cached.
///
/// `immutable` selects the freshness window: a per-version document
/// (`{name}/{version}/json`) never changes once published, so it is cached
/// effectively forever; a packument (`{name}/json`, the list of all versions)
/// is mutable and honours the short TTL from `metadata_cache_ttl`. A stale
/// packument can only ever resolve to an OLDER real version — the artifact is
/// still sha/integrity-verified and capability-analyzed regardless — so the TTL
/// bounds a freshness lag, never a security bypass. `OMC_META_TTL_SECS=0`
/// disables metadata caching entirely.
pub(crate) fn metadata_get_cached(
    builder: reqwest::blocking::RequestBuilder,
    cache_url: &str,
    immutable: bool,
) -> Result<Option<Vec<u8>>> {
    let ttl = metadata_cache_ttl();
    if let Some(ttl_secs) = ttl {
        let max_age = if immutable {
            std::time::Duration::from_secs(60 * 60 * 24 * 365)
        } else {
            std::time::Duration::from_secs(ttl_secs)
        };
        if let Some(body) = read_metadata_cache(cache_url, max_age) {
            return Ok(Some(body));
        }
    }

    let response = builder.send()?;
    if response.status().as_u16() == 404 {
        return Ok(None);
    }
    let bytes = response.error_for_status()?.bytes()?.to_vec();
    if ttl.is_some() {
        write_metadata_cache(cache_url, &bytes);
    }
    Ok(Some(bytes))
}

/// The metadata-cache freshness window for mutable packuments, in seconds.
/// `None` disables metadata caching. Default 600s (10 min); `OMC_META_TTL_SECS`
/// overrides it, where `0` disables and any unparseable value falls back to the
/// default rather than silently turning the cache off.
fn metadata_cache_ttl() -> Option<u64> {
    match std::env::var("OMC_META_TTL_SECS") {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(secs) => Some(secs),
            Err(_) => Some(600),
        },
        Err(_) => Some(600),
    }
}

/// Cache file for a metadata URL: `$OMC_HOME/cache/meta/<sha256(url)>.json`. The
/// URL is hashed so credentials embedded in a private-index URL never land in a
/// path on disk; the cached content is registry metadata only.
fn metadata_cache_path(cache_url: &str) -> Option<PathBuf> {
    Some(
        global_omc_home()?
            .join("cache")
            .join("meta")
            .join(format!("{}.json", sha256_hex(cache_url.as_bytes()))),
    )
}

/// Cached metadata body if present and younger than `max_age` (measured from the
/// file's mtime, which is its fetch time). Any error (missing/unreadable/clock
/// skew) is treated as a miss.
fn read_metadata_cache(cache_url: &str, max_age: std::time::Duration) -> Option<Vec<u8>> {
    let path = metadata_cache_path(cache_url)?;
    let modified = fs::metadata(&path).ok()?.modified().ok()?;
    if std::time::SystemTime::now().duration_since(modified).ok()? > max_age {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    // Self-heal: never let a malformed cache entry drive resolution. A complete
    // registry response is always well-formed JSON, so anything that fails to
    // parse is corrupt (a stray/legacy entry, external tampering, a truncated
    // write) — drop it and treat as a miss so the caller refetches fresh.
    if serde_json::from_slice::<serde::de::IgnoredAny>(&bytes).is_err() {
        let _ = fs::remove_file(&path);
        return None;
    }
    Some(bytes)
}

/// Store a metadata body, atomically (temp + rename) with a per-thread temp name
/// so concurrent resolver workers never observe a partial write. Best-effort:
/// any failure just means the next resolve refetches.
fn write_metadata_cache(cache_url: &str, body: &[u8]) {
    let Some(path) = metadata_cache_path(cache_url) else {
        return;
    };
    let Some(dir) = path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let tmp = dir.join(format!(".meta.tmp-{}", unique_tmp_suffix()));
    if fs::write(&tmp, body).is_ok() {
        let _ = fs::rename(&tmp, &path);
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
