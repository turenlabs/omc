//! Error type and the crate `Result` alias.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, OmcRegistryError>;

#[derive(Debug, Error)]
pub enum OmcRegistryError {
    #[error("{0}")]
    Usage(String),
    #[error("unsupported package spec `{0}`")]
    UnsupportedSpec(String),
    #[error("unsupported requirements entry `{0}`")]
    UnsupportedRequirement(String),
    #[error("package version was not found: {0}")]
    PackageNotFound(String),
    #[error("blocked package `{spec}`")]
    BlockedPackage {
        spec: String,
        /// Structured explanation + the exact minimal grant tokens, so the CLI
        /// can render guidance and offer an interactive allow-once/allow-always
        /// choice. `None` for aggregate blocks with no single-package context.
        suggestion: Option<Box<crate::policy_bridge::BlockSuggestion>>,
    },
    #[error("registry response did not include a downloadable artifact for {0}")]
    MissingArtifact(String),
    #[error("registry response did not include a compatible PyPI archive for {0}")]
    MissingCompatibleWheel(String),
    #[error("could not resolve a version for {name} matching `{requirement}`")]
    UnsatisfiedRequirement { name: String, requirement: String },
    #[error("install requires an accepted lockfile; blocked package remains: {0}")]
    BlockedLockedPackage(String),
    #[error("omc.lock does not satisfy `{0}`; run omc install without --locked to update it")]
    LockfileOutOfDate(String),
    #[error("cannot install unsupported artifact type: {0}")]
    UnsupportedInstallArtifact(String),
    #[error("archive contains an unsafe path: {0}")]
    UnsafeArchivePath(String),
    #[error("could not locate an entry source file for {0}")]
    MissingEntrySource(String),
    #[error("downloaded artifact digest mismatch for {name}: expected {expected}, got {actual}")]
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml decode error: {0}")]
    TomlDecode(#[from] toml::de::Error),
    #[error("toml encode error: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("omc.policy parse error: {0}")]
    PolicyParse(#[from] omc_policy::PolicyError),
}
