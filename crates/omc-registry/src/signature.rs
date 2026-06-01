//! ed25519 artifact signing — extracted verbatim from lib.rs.

use crate::*;

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub(crate) fn sign_artifact(project_dir: &Path, artifact: &mut OmcArtifact) -> Result<()> {
    artifact.signature = None;
    let payload = serde_json::to_vec(artifact)?;
    let signing_key = read_or_create_artifact_signing_key(project_dir)?;
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&payload);
    let public_key = verifying_key.to_bytes();

    artifact.signature = Some(ArtifactSignature {
        algorithm: "ed25519".to_owned(),
        key_id: sha256_hex(&public_key)[..16].to_owned(),
        public_key: STANDARD.encode(public_key),
        payload_sha256: sha256_hex(&payload),
        signature: STANDARD.encode(signature.to_bytes()),
    });
    Ok(())
}

/// Pin the project's artifact signing public key into the lock if not already
/// set (F3). Idempotent: once pinned, the value is left untouched so a later
/// run cannot silently rotate the trust anchor without an explicit re-lock.
pub(crate) fn ensure_lock_signing_key(project_dir: &Path, lock: &mut OmcLock) -> Result<()> {
    if lock.signing_key.as_deref().is_none_or(str::is_empty) {
        lock.signing_key = Some(project_signing_public_key(project_dir)?);
    }
    Ok(())
}

/// Base64 ed25519 PUBLIC key of the project's artifact signing key. This is the
/// F3 trust anchor pinned into `omc.lock` on first sign. Reading the signing key
/// creates it on first call (mirrors `sign_artifact`), so the pinned key always
/// matches the key that signs the artifacts written in the same run.
pub(crate) fn project_signing_public_key(project_dir: &Path) -> Result<String> {
    let signing_key = read_or_create_artifact_signing_key(project_dir)?;
    Ok(STANDARD.encode(signing_key.verifying_key().to_bytes()))
}

/// sha256 of the artifact's canonical JSON payload with the signature stripped.
/// This is the value pinned into the lock (`LockedPackage::artifact_sha256`) and
/// re-checked at locked-install time so a tampered artifact cannot be trusted
/// even if re-signed with the project's own key.
pub(crate) fn artifact_payload_sha256(artifact: &OmcArtifact) -> Result<String> {
    let mut unsigned = artifact.clone();
    unsigned.signature = None;
    Ok(sha256_hex(&serde_json::to_vec(&unsigned)?))
}

pub fn verify_artifact_signature(artifact: &OmcArtifact) -> Result<()> {
    let signature = artifact.signature.as_ref().ok_or_else(|| {
        OmcRegistryError::UnsupportedInstallArtifact("artifact is unsigned".to_owned())
    })?;
    if signature.algorithm != "ed25519" {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(format!(
            "unsupported artifact signature algorithm `{}`",
            signature.algorithm
        )));
    }

    let mut unsigned = artifact.clone();
    unsigned.signature = None;
    let payload = serde_json::to_vec(&unsigned)?;
    let actual_payload_sha256 = sha256_hex(&payload);
    if !signature
        .payload_sha256
        .eq_ignore_ascii_case(&actual_payload_sha256)
    {
        return Err(OmcRegistryError::DigestMismatch {
            name: artifact.package.name.clone(),
            expected: format!("sha256:{}", signature.payload_sha256),
            actual: format!("sha256:{actual_payload_sha256}"),
        });
    }

    let public_key = decode_base64_array::<32>(&signature.public_key, "artifact public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "invalid artifact public key: {error}"
        ))
    })?;
    let signature_bytes = STANDARD.decode(&signature.signature).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "invalid artifact signature encoding: {error}"
        ))
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!("invalid artifact signature: {error}"))
    })?;
    verifying_key.verify(&payload, &signature).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "artifact signature verification failed: {error}"
        ))
    })
}

/// Pre-create the per-project artifact signing key (single-threaded) so the
/// parallel resolver's workers only ever READ it — the create path below is not
/// atomic and would race if two workers hit it at once.
pub(crate) fn ensure_artifact_signing_key(project_dir: &Path) -> Result<()> {
    read_or_create_artifact_signing_key(project_dir)?;
    Ok(())
}

fn read_or_create_artifact_signing_key(project_dir: &Path) -> Result<SigningKey> {
    let key_path = artifact_signing_key_path(project_dir);
    if key_path.exists() {
        let encoded = fs::read_to_string(&key_path)?;
        let bytes = decode_base64_array::<32>(encoded.trim(), "artifact signing key")?;
        return Ok(SigningKey::from_bytes(&bytes));
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
        restrict_private_key_dir(parent)?;
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    fs::write(&key_path, STANDARD.encode(signing_key.to_bytes()))?;
    restrict_private_key_file(&key_path)?;
    Ok(signing_key)
}

fn artifact_signing_key_path(project_dir: &Path) -> PathBuf {
    project_dir
        .join(".omc")
        .join("keys")
        .join(ARTIFACT_SIGNING_KEY)
}

fn decode_base64_array<const N: usize>(encoded: &str, description: &str) -> Result<[u8; N]> {
    let bytes = STANDARD.decode(encoded).map_err(|error| {
        OmcRegistryError::UnsupportedInstallArtifact(format!("{description} is invalid: {error}"))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        OmcRegistryError::UnsupportedInstallArtifact(format!(
            "{description} must be {N} bytes, got {}",
            bytes.len()
        ))
    })
}

#[cfg(unix)]
fn restrict_private_key_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_key_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_private_key_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_key_file(_path: &Path) -> Result<()> {
    Ok(())
}
