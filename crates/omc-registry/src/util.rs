//! Hashing, archive, and path helpers shared across the registry crate.

use crate::*;

// External crate imports do NOT flow in through `use crate::*`.
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

pub(crate) fn strip_first_path_component(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    components.next()?;
    let stripped = components.as_path();
    (!stripped.as_os_str().is_empty()).then(|| stripped.to_path_buf())
}

pub(crate) fn checked_join(base: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(OmcRegistryError::UnsafeArchivePath(
            relative.display().to_string(),
        ));
    }
    Ok(base.join(relative))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

pub(crate) fn sha1_hex(bytes: &[u8]) -> String {
    let mut digest = Sha1::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

pub(crate) fn verify_npm_integrity(name: &str, integrity: &str, bytes: &[u8]) -> Result<()> {
    let mut saw_supported = false;
    for token in integrity.split_whitespace() {
        let Some((algorithm, expected_b64)) = token.split_once('-') else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "malformed npm integrity for {name}"
            )));
        };
        let expected_b64 = expected_b64.split('?').next().unwrap_or(expected_b64);
        let expected = STANDARD.decode(expected_b64).map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!("malformed npm integrity for {name}"))
        })?;
        let Some(actual) = npm_integrity_digest(algorithm, bytes) else {
            continue;
        };
        saw_supported = true;
        if expected != actual {
            return Err(OmcRegistryError::DigestMismatch {
                name: name.to_owned(),
                expected: format!("{algorithm}-{expected_b64}"),
                actual: format!("{algorithm}-{}", STANDARD.encode(actual)),
            });
        }
    }

    if !saw_supported {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm integrity digest for {name}"
        )));
    }

    Ok(())
}

fn npm_integrity_digest(algorithm: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        "sha1" => {
            let mut digest = Sha1::new();
            digest.update(bytes);
            Some(digest.finalize().to_vec())
        }
        "sha256" => {
            let mut digest = Sha256::new();
            digest.update(bytes);
            Some(digest.finalize().to_vec())
        }
        "sha512" => {
            let mut digest = Sha512::new();
            digest.update(bytes);
            Some(digest.finalize().to_vec())
        }
        _ => None,
    }
}

pub(crate) fn safe_name(name: &str) -> String {
    name.replace('/', "__")
}

pub(crate) fn relative_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
