//! A unique temporary directory that is best-effort removed on drop. Used purely
//! as a sandboxed `LinkOptions::project_dir` by the read-only commands
//! (`inspect`, `scan`, `diff`) so resolution never writes into the user's
//! project: any omc.lock, omc.toml, archives, or artifacts land here and are
//! removed when the command returns.

use std::path::{Path, PathBuf};

use omc_registry::OmcRegistryError;

pub(crate) struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub(crate) fn new(prefix: &str) -> Result<Self, OmcRegistryError> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
