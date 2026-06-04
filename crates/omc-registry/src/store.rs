//! Shared content store + link-mode materialization.
//!
//! Packages are extracted ONCE into `$OMC_HOME/store/<eco>/<name>/<version>/`,
//! then their files are hard-linked into each project's `node_modules` /
//! `site-packages`. N projects that share a package version therefore keep ~1
//! physical copy on disk (the pnpm / uv model) instead of a full per-project
//! copy. A byte copy is the fallback when a hard link is impossible (the store
//! and the project live on different filesystems, or the FS rejects links).
//!
//! Mutation note: hard-linked files share an inode with the store, so a tool
//! that rewrites a file in `node_modules` would also rewrite the store copy.
//! omc never runs install scripts and treats installed dependencies as
//! read-only inputs, so this matches pnpm's default and is safe here. (A
//! copy-on-write reflink — `clonefile`/`FICLONE` — would remove even that
//! caveat and is a natural future upgrade behind this same primitive.)

use crate::*;

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Root of the shared content store: `$OMC_HOME/store` (default `~/.omc/store`).
pub(crate) fn store_root() -> Option<PathBuf> {
    Some(global_omc_home()?.join("store"))
}

/// Store directory for one package, addressed by the **content hash** of its
/// artifact (`<eco>/<safe-name>/<sha256>`) rather than its version.
///
/// Content addressing is what makes a shared, immutable store correct: identical
/// artifact bytes — the same package@version across every project — map to one
/// entry (so projects dedup), while different bytes can never collide under one
/// key (so a stale entry can never serve the wrong content). The name component
/// is kept only for human-readable browsing; the `sha256` is the real key.
pub(crate) fn package_store_dir(ecosystem: Ecosystem, name: &str, sha256: &str) -> Option<PathBuf> {
    if sha256.is_empty() {
        return None;
    }
    Some(
        store_root()?
            .join(ecosystem.to_string())
            .join(safe_name(name))
            .join(sha256),
    )
}

/// How a file was materialized into a project — reported for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkMode {
    HardLink,
    Copy,
}

/// Populate `store_dir` with the extracted contents of an npm tarball exactly
/// once. Extraction goes to a sibling temp directory and is then atomically
/// renamed into place, so concurrent installers — even separate `omc`
/// processes sharing one `$OMC_HOME` — never observe a half-populated store
/// entry; whoever wins the rename, every installer ends up linking the same
/// content. The locked artifact `bytes` were already integrity-checked upstream
/// (`read_locked_archive` / the global cache), so this is a verify-once-at-
/// ingest store.
pub(crate) fn ensure_npm_extracted(store_dir: &Path, bytes: &[u8]) -> Result<()> {
    ensure_extracted_with(store_dir, |tmp| npm_install::unpack_npm_tarball(bytes, tmp))
}

/// Populate `store_dir` with an already-extracted directory tree exactly once,
/// using the same atomic temp+rename discipline as [`ensure_npm_extracted`].
/// `extract` receives a fresh temp directory to fill.
pub(crate) fn ensure_extracted_with(
    store_dir: &Path,
    extract: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    if store_dir.exists() {
        return Ok(());
    }
    let parent = store_dir
        .parent()
        .ok_or_else(|| OmcRegistryError::UnsafeArchivePath(store_dir.display().to_string()))?;
    fs::create_dir_all(parent)?;
    let leaf = store_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pkg");
    let tmp = parent.join(format!(".{leaf}.tmp-{}", http_client::unique_tmp_suffix()));
    // batou:ignore-start file_write -- `tmp` is a path omc constructs itself
    // under $OMC_HOME/store (parent derived from package_store_dir; the package
    // name is run through safe_name, which strips `/`). Every removal below
    // targets only that freshly-created temp directory. No web/user-input source
    // reaches this code — omc-registry has no request handler — so the flagged
    // CWE-22 taint path is a false attribution.
    let _ = fs::remove_dir_all(&tmp);

    extract(&tmp)?;

    // Atomic publish. If another installer populated `store_dir` first, the
    // rename fails (non-empty target) — that's fine, their copy is equivalent;
    // we just drop our temp.
    if fs::rename(&tmp, store_dir).is_err() && !store_dir.exists() {
        // Rename failed for a reason other than "already there" (e.g. the temp
        // and final dir straddle a mount). Fall back to a recursive copy so the
        // store still gets populated.
        let result = copy_tree(&tmp, store_dir);
        let _ = fs::remove_dir_all(&tmp);
        return result;
    }
    let _ = fs::remove_dir_all(&tmp);
    // batou:ignore-end
    Ok(())
}

/// Materialize every file under `store_dir` into `target`, hard-linking (or
/// copying as a fallback). `target` is recreated fresh. Symlinks never appear in
/// the store (the extractor drops them), and each destination is validated with
/// `checked_join`.
pub(crate) fn link_tree_into(store_dir: &Path, target: &Path) -> Result<()> {
    if target.exists() {
        fs::remove_dir_all(target)?;
    }
    fs::create_dir_all(target)?;
    for entry in WalkDir::new(store_dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(store_dir).unwrap_or(entry.path());
        let dst = checked_join(target, relative)?;
        link_or_copy_file(entry.path(), &dst)?;
    }
    Ok(())
}

/// Recursive file copy used only as the cross-device fallback when an atomic
/// rename into the store is impossible.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in WalkDir::new(from).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(from).unwrap_or(entry.path());
        let dst = checked_join(to, relative)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), &dst)?;
    }
    Ok(())
}

/// Materialize the store file `src` at `dst`, preferring a hard link (one inode,
/// ~0 extra bytes) and falling back to a byte copy when a link is impossible
/// (cross-device store, or a filesystem that rejects hard links). Works on both
/// Linux and macOS — `fs::hard_link` maps to `link(2)` on each.
///
/// Refuses a symlinked `src` as defense-in-depth: the store only ever holds
/// regular files omc extracted, but following a symlink here could escape it
/// (the same tar-slip class the extractor guards against). This symlink check is
/// the CWE-59 (link-following) mitigation; callers additionally derive `dst`
/// from archive-relative paths through `checked_join` (no `..`, no absolute).
pub(crate) fn link_or_copy_file(src: &Path, dst: &Path) -> Result<LinkMode> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        return Err(OmcRegistryError::UnsafeArchivePath(
            src.display().to_string(),
        ));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    // batou:ignore-start file_write -- internal install primitive: `src` is an
    // omc-extracted regular file in $OMC_HOME/store (symlink-refused one line
    // above, closing CWE-59 link-following) and `dst` is derived by callers via
    // checked_join (no `..`/absolute). No web/user-input source reaches here;
    // omc-registry has no request handler. Spanning store→project is the
    // function's purpose, so a single-root confinement check does not apply.
    // Replace any existing destination so re-installs are deterministic and
    // `hard_link` (which fails on EEXIST) can proceed.
    if fs::symlink_metadata(dst).is_ok() {
        let _ = fs::remove_file(dst);
    }
    match fs::hard_link(src, dst) {
        Ok(()) => Ok(LinkMode::HardLink),
        Err(_) => {
            fs::copy(src, dst)?;
            Ok(LinkMode::Copy)
        }
    }
    // batou:ignore-end
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn links_share_one_inode_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("store").join("a.txt");
        fs::create_dir_all(src.parent().unwrap()).unwrap();
        fs::write(&src, b"hello").unwrap();
        let dst = dir.path().join("nm").join("pkg").join("a.txt");

        let mode = link_or_copy_file(&src, &dst).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"hello");
        // A same-filesystem tmpdir links rather than copies.
        assert_eq!(mode, LinkMode::HardLink);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&src).unwrap().ino(),
            fs::metadata(&dst).unwrap().ino(),
            "hard-linked files must share an inode"
        );
    }

    #[test]
    fn overwrites_an_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        fs::write(&src, b"new").unwrap();
        let dst = dir.path().join("dst.txt");
        fs::write(&dst, b"old").unwrap();

        link_or_copy_file(&src, &dst).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_source() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        fs::write(&real, b"secret").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let dst = dir.path().join("out.txt");
        assert!(
            link_or_copy_file(&link, &dst).is_err(),
            "must refuse to materialize through a symlinked source"
        );
        assert!(!dst.exists());
    }
}
