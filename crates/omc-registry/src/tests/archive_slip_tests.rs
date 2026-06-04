//! Red-team tests for archive path-traversal (tar-slip / zip-slip).
//!
//! omc extracts attacker-controlled npm `.tgz` and PyPI sdist/wheel archives.
//! These tests lock the two invariants that keep extraction inside the target
//! directory: (1) declared paths are validated by `checked_join` (no `..`, no
//! absolute), and (2) symlink/hardlink entries are NEVER materialized, so no
//! escaping link can exist on disk for a later entry to be written through.

use super::*;

use crate::npm_install::unpack_npm_tarball;
use crate::pypi_install::unpack_python_tar_sdist;
use crate::util::checked_join;

/// Append a symlink entry `path -> target` (relative) to a tar builder.
fn append_symlink<W: std::io::Write>(archive: &mut tar::Builder<W>, path: &str, target: &str) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    archive
        .append_link(&mut header, path, Path::new(target))
        .unwrap();
}

/// Append a regular file entry.
fn append_file<W: std::io::Write>(archive: &mut tar::Builder<W>, path: &str, content: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, path, content).unwrap();
}

fn gzip(build: impl FnOnce(&mut tar::Builder<flate2::write::GzEncoder<&mut Vec<u8>>>)) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        build(&mut archive);
        archive.into_inner().unwrap().finish().unwrap();
    }
    bytes
}

/// npm: a symlink that escapes the target dir, followed by a file written
/// *through* it, must NOT write outside the target — the symlink is dropped.
#[test]
fn npm_tarball_symlink_escape_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let escape = dir.path().join("ESCAPE_ZONE");
    fs::create_dir_all(&escape).unwrap();
    // target lives two levels under dir: dir/nm/evil
    let target = dir.path().join("nm").join("evil");

    // package/sneaky -> ../../ESCAPE_ZONE (resolves to dir/ESCAPE_ZONE), then a
    // file under package/sneaky/ that would land in ESCAPE_ZONE if honored.
    let bytes = gzip(|archive| {
        append_symlink(archive, "package/sneaky", "../../ESCAPE_ZONE");
        append_file(archive, "package/sneaky/pwned.txt", b"pwned");
        append_file(archive, "package/index.js", b"// real file\n");
    });

    unpack_npm_tarball(&bytes, &target).unwrap();

    // Nothing was written through the symlink into the escape zone.
    assert!(
        !escape.join("pwned.txt").exists(),
        "tar-slip: file written outside target via symlink"
    );
    // No symlink was materialized inside the target.
    let sneaky = target.join("sneaky");
    let is_symlink = sneaky
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    assert!(!is_symlink, "symlink entry was materialized inside target");
    // The legitimate file still extracted.
    assert!(target.join("index.js").exists());
}

/// npm: a hardlink entry must not be materialized either.
#[test]
fn npm_tarball_hardlink_entry_is_not_materialized() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, b"top secret").unwrap();
    let target = dir.path().join("nm").join("evil");

    let bytes = gzip(|archive| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o644);
        // hardlink target points up out of the tree at the secret file
        archive
            .append_link(&mut header, "package/alias", Path::new("../../secret.txt"))
            .unwrap();
        append_file(archive, "package/index.js", b"// real\n");
    });

    unpack_npm_tarball(&bytes, &target).unwrap();

    assert!(
        !target.join("alias").exists(),
        "hardlink entry was materialized"
    );
    assert!(target.join("index.js").exists());
}

/// PyPI sdist (tar.gz): same symlink-escape invariant.
#[test]
fn pypi_sdist_symlink_escape_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let escape = dir.path().join("ESCAPE_ZONE");
    fs::create_dir_all(&escape).unwrap();
    let target = dir.path().join("extract"); // one level under dir

    // first path component is stripped (pkg-1.0/...), symlink resolves to
    // dir/ESCAPE_ZONE from dir/extract via ../ESCAPE_ZONE.
    let bytes = gzip(|archive| {
        append_symlink(archive, "pkg-1.0/sneaky", "../ESCAPE_ZONE");
        append_file(archive, "pkg-1.0/sneaky/pwned.txt", b"pwned");
        append_file(archive, "pkg-1.0/mod.py", b"VALUE = 1\n");
    });

    unpack_python_tar_sdist(&bytes, &target).unwrap();

    assert!(
        !escape.join("pwned.txt").exists(),
        "tar-slip: file written outside target via symlink"
    );
    let sneaky = target.join("sneaky");
    let is_symlink = sneaky
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    assert!(!is_symlink, "symlink entry was materialized inside target");
    assert!(target.join("mod.py").exists());
}

/// The name-based guard: `..` and absolute declared paths are rejected.
#[test]
fn checked_join_rejects_parent_and_absolute_paths() {
    let base = Path::new("/tmp/omc-base");
    assert!(checked_join(base, Path::new("../escape")).is_err());
    assert!(checked_join(base, Path::new("a/../../escape")).is_err());
    assert!(checked_join(base, Path::new("/etc/passwd")).is_err());
    // a normal nested path is allowed
    assert_eq!(
        checked_join(base, Path::new("a/b/c.txt")).unwrap(),
        base.join("a/b/c.txt")
    );
}
// Note: an end-to-end `..`-in-declared-path test is not constructible through
// the `tar` builder (it refuses to emit `..` entries: "paths in archives must
// not have `..`"). That vector is authoritatively covered by the
// `checked_join_rejects_parent_and_absolute_paths` unit test above, which
// guards every extraction site.
