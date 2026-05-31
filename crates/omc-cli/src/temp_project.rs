use std::path::{Path, PathBuf};
use std::{env, fs};

use omc_registry::OmcRegistryError;

pub(crate) struct TempOmcProject {
    path: PathBuf,
}

impl TempOmcProject {
    pub(crate) fn new(prefix: &str, source_project_dir: &Path) -> Result<Self, OmcRegistryError> {
        let path = Self::create_path(prefix)?;
        for file in [
            "omc.toml",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ] {
            let source = source_project_dir.join(file);
            if source.exists() {
                fs::copy(source, path.join(file))?;
            }
        }
        Ok(Self { path })
    }

    pub(crate) fn empty(prefix: &str) -> Result<Self, OmcRegistryError> {
        Ok(Self {
            path: Self::create_path(prefix)?,
        })
    }

    fn create_path(prefix: &str) -> Result<PathBuf, OmcRegistryError> {
        static TEMP_PROJECT_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| OmcRegistryError::UnsupportedSpec(error.to_string()))?
            .as_nanos();
        let sequence = TEMP_PROJECT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "omc-{prefix}-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempOmcProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
