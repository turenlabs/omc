use crate::*;

use std::collections::BTreeSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Clone)]
pub(crate) struct ArchiveProfile {
    pub(crate) files_scanned: usize,
    pub(crate) capabilities: Vec<CapabilityFinding>,
}

pub(crate) fn profile_archive(package: &ResolvedPackage, bytes: &[u8]) -> Result<ArchiveProfile> {
    let mut profiler = SourceProfiler::default();

    for (name, script) in &package.npm_scripts {
        if is_npm_lifecycle_script(name) {
            profiler.add(
                CapabilityKind::ProcSpawn,
                format!("npm-script:{name}"),
                "package.json",
                format!("lifecycle script `{name}` = `{script}`"),
            );
        }
    }

    if package.filename.ends_with(".tgz") || package.filename.ends_with(".tar.gz") {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(decoder);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_BYTES {
                continue;
            }
            let path = entry.path()?.to_string_lossy().into_owned();
            let mut raw = Vec::new();
            entry.read_to_end(&mut raw).ok();
            profiler.scan_bytes(&path, &raw);
        }
    } else if package.filename.ends_with(".whl") || package.filename.ends_with(".zip") {
        let reader = Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)?;
        for index in 0..archive.len() {
            let mut file = archive.by_index(index)?;
            if file.is_dir() || file.size() > MAX_FILE_BYTES {
                continue;
            }
            let path = file.name().to_owned();
            let mut raw = Vec::new();
            file.read_to_end(&mut raw).ok();
            profiler.scan_bytes(&path, &raw);
        }
    } else {
        profiler.scan_bytes(&package.filename, bytes);
    }

    Ok(profiler.finish())
}

pub(crate) fn profile_source_directory(root: &Path) -> Result<ArchiveProfile> {
    let mut profiler = SourceProfiler::default();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_enter_source_profile_dir)
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() || fs::metadata(entry.path())?.len() > MAX_FILE_BYTES {
            continue;
        }
        let relative = source_profile_relative_path(root, entry.path());
        let raw = fs::read(entry.path()).unwrap_or_default();
        profiler.scan_bytes(&relative, &raw);
    }
    Ok(profiler.finish())
}

pub(crate) fn hash_profiled_directory(root: &Path) -> Result<String> {
    let mut files = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(should_enter_source_profile_dir)
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .metadata()
                    .map(|metadata| metadata.len() <= MAX_FILE_BYTES)
                    .unwrap_or(false)
        })
        .map(|entry| entry.path().to_path_buf())
        .collect::<Vec<_>>();
    files.sort();

    let mut digest = Sha256::new();
    for path in files {
        let relative = source_profile_relative_path(root, &path);
        digest.update(relative.as_bytes());
        digest.update([0]);
        let bytes = fs::read(&path)?;
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update([0]);
        digest.update(bytes);
        digest.update([0]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn source_profile_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn should_enter_source_profile_dir(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }

    !matches!(
        entry.file_name().to_str(),
        Some(
            "node_modules"
                | ".git"
                | ".omc"
                | "target"
                | "build"
                | "dist"
                | "venv"
                | ".venv"
                | ".tox"
                | ".mypy_cache"
                | ".pytest_cache"
                | "__pycache__"
        )
    )
}

#[derive(Debug, Default)]
pub(crate) struct SourceProfiler {
    files_scanned: usize,
    findings: BTreeSet<CapabilityFinding>,
}

impl SourceProfiler {
    /// Decode raw file bytes and scan them. The bytes are decoded with
    /// `String::from_utf8_lossy` so a file is ALWAYS scanned best-effort — a
    /// `read_to_string`-style decode would yield an empty string on the first
    /// invalid byte, so a one-byte `0xFF` prefix would hide the entire payload
    /// from the scanner while the file still installed and executed.
    ///
    /// FAIL CLOSED on mangling: when a source-like file's bytes are NOT valid
    /// UTF-8 we additionally emit a `DynamicEval` capability (mirroring
    /// `detect_opaque_capability_access`) so the package is denied-by-default
    /// rather than silently Accepted. Real-world JS/Py source is UTF-8; invalid
    /// bytes in a `.js`/`.py` file are a deliberate evasion signal, not noise.
    pub(crate) fn scan_bytes(&mut self, path: &str, bytes: &[u8]) {
        if !is_source_like(path) || is_ignored_source_path(path) || bytes.is_empty() {
            return;
        }
        let content = String::from_utf8_lossy(bytes);
        if matches!(content, std::borrow::Cow::Owned(_)) {
            // Lossy replacement happened => the bytes were not valid UTF-8.
            self.files_scanned += 1;
            self.add(
                CapabilityKind::DynamicEval,
                "*",
                path,
                "non-UTF8 bytes in a source file — deliberate mangling, cannot verify",
            );
        }
        self.scan_file(path, &content);
    }

    pub(crate) fn scan_file(&mut self, path: &str, content: &str) {
        if !is_source_like(path) || is_ignored_source_path(path) || content.is_empty() {
            return;
        }

        self.files_scanned += 1;
        // Comments never execute, so a URL / env name / `eval` / `child_process`
        // appearing only in a comment must not become a capability — axios ships a
        // `// (e.g. ... 'https://evil.com')` example that otherwise looked like a
        // real network host. Blank comments first (string-literal aware, comment
        // syntax keyed by extension), then run every text scan on the code only.
        let code = strip_comments(content, comment_syntax(path));
        // Alias pre-pass: detection keys on literal surface tokens
        // (`process.env`, `child_process`, `os.environ`, fetch markers, ...), so
        // binding a capability ROOT to a variable first
        // (`const proc = process; proc.env.X`, `import os as m; m.environ['X']`)
        // slips past every layer. Conservatively resolve such aliases back to
        // the canonical root token so the existing marker scans catch them.
        let code = resolve_capability_aliases(&code);
        let content = code.as_str();
        let lower = content.to_ascii_lowercase();

        let env_targets = extract_env_read_targets(content);
        if env_targets.is_empty() {
            for pattern in ["process.env", "os.environ", "getenv("] {
                if lower.contains(pattern) {
                    self.add(CapabilityKind::EnvRead, "*", path, pattern);
                }
            }
        } else {
            for name in env_targets {
                self.add(
                    CapabilityKind::EnvRead,
                    name.clone(),
                    path,
                    format!("static env read `{name}`"),
                );
            }
        }

        // F4: capture the concrete LITERAL read path when present so the verdict
        // gate can run `is_sensitive_read_path` against it (reading ~/.ssh/.env/
        // keys is denied even under fs.read:* / --allow-all-host, mirroring the
        // in-cell guarantee). A genuinely dynamic read path (no literal arg) is
        // opaque, so it falls back to "*" AND trips F1's fail-closed below.
        for marker in ["readfilesync", "readfile", "createreadstream", "open"] {
            for target in fs_read_call_targets(content, marker) {
                self.add(CapabilityKind::FsRead, target, path, marker);
            }
        }
        for pattern in ["require(\"fs\")", "require('fs')"] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::FsRead, "*", path, pattern);
            }
        }

        for pattern in ["writefilesync", "writefile(", "createwritestream"] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::FsWrite, "*", path, pattern);
            }
        }
        if contains_python_file_write(content) {
            self.add(CapabilityKind::FsWrite, "*", path, "open write mode");
        }

        if let Some(evidence) = http_client_usage_evidence(&lower) {
            let http_hosts = extract_http_hosts(content);
            if http_hosts.is_empty() {
                self.add(CapabilityKind::HttpRequest, "*", path, evidence);
            } else {
                for host in http_hosts {
                    self.add(
                        CapabilityKind::HttpRequest,
                        host.clone(),
                        path,
                        format!("static URL host `{host}`"),
                    );
                }
            }
        }

        for pattern in [
            "child_process",
            "subprocess",
            "os.system",
            "popen(",
            "spawn(",
            "execfile(",
        ] {
            if lower.contains(pattern) {
                self.add(CapabilityKind::ProcSpawn, "*", path, pattern);
            }
        }

        if contains_dynamic_eval(content) {
            self.add(CapabilityKind::DynamicEval, "*", path, "dynamic eval");
        }

        // F1 fail-closed: opaque/dynamic access to a capability ROOT means we
        // cannot statically see what the package does. Emit a DynamicEval
        // capability so the verdict gate denies-by-default (mirrors the in-cell
        // path). Scoped to dangerous roots only so ordinary computed access on
        // local objects/arrays (obj[key], arr[i]) and literal fs reads stay Pure.
        for evidence in detect_opaque_capability_access(content) {
            self.add(CapabilityKind::DynamicEval, "*", path, evidence);
        }
    }

    pub(crate) fn add(
        &mut self,
        kind: CapabilityKind,
        target: impl Into<String>,
        source: impl Into<String>,
        evidence: impl Into<String>,
    ) {
        self.findings.insert(CapabilityFinding {
            kind,
            target: target.into(),
            source: source.into(),
            evidence: evidence.into(),
        });
    }

    pub(crate) fn finish(self) -> ArchiveProfile {
        ArchiveProfile {
            files_scanned: self.files_scanned,
            capabilities: self.findings.into_iter().collect(),
        }
    }
}

/// CONSERVATIVE alias pre-pass. Detection downstream keys on literal surface
/// tokens (`process.env`, `child_process`, `os.environ`, the fetch markers,
/// etc.), so binding a capability ROOT to a fresh variable first defeats every
/// layer:
/// ```text
/// JS:  const proc = process; proc.env.NPM_TOKEN          // EnvRead missed
///      const cp = require('child_process'); cp.execSync(x) // ProcSpawn missed
/// PY:  import os as m; m.environ['X']                     // EnvRead missed
///      from os import environ as e; e['X']                // EnvRead missed
/// ```
/// This walks the (comment-stripped) code, recognises ONLY the simple forms
/// where the right-hand side is EXACTLY a bare capability root identifier or a
/// known `require()`/`import` of one, and rewrites every later word-boundary
/// occurrence of the alias name to the canonical root token so the existing
/// marker scans fire. It deliberately does NOT alias ordinary code: a member
/// expression like `const x = obj.process` (where `obj` is not the global), a
/// call result, or any RHS that is not exactly a recognised root is ignored.
fn resolve_capability_aliases(code: &str) -> String {
    let aliases = collect_capability_aliases(code);
    if aliases.is_empty() {
        return code.to_owned();
    }
    rewrite_identifiers(code, &aliases)
}

/// Collect `alias_name -> canonical_root_token` bindings. The canonical token is
/// a literal surface form the downstream marker scans already recognise
/// (`process`, `child_process`, `fetch`, `os`, `subprocess`, `os.environ`,
/// `require`). Only exact, unambiguous RHS forms are accepted.
fn collect_capability_aliases(code: &str) -> std::collections::BTreeMap<String, String> {
    let mut aliases = std::collections::BTreeMap::new();

    // --- JS/TS: `const|let|var NAME = <root>;`  and
    //            `const|let|var NAME = require('<mod>');` -----------------------
    for kw in ["const", "let", "var"] {
        let mut offset = 0;
        while let Some(index) = code[offset..].find(kw) {
            let start = offset + index;
            let after_kw = start + kw.len();
            offset = after_kw;
            // `const` must stand as a whole keyword (boundary before, whitespace
            // after) so `constant`/`myconst` do not match.
            if !is_identifier_boundary(code, start) {
                continue;
            }
            let rest = &code[after_kw..];
            if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
                continue;
            }
            let rest = rest.trim_start();
            let (name, after_name) = take_identifier(rest);
            if name.is_empty() {
                continue;
            }
            let after_eq = after_name.trim_start();
            let Some(rhs) = after_eq.strip_prefix('=') else {
                continue;
            };
            // Reject `==`/`=>` — not an assignment.
            if rhs.starts_with('=') || rhs.starts_with('>') {
                continue;
            }
            let rhs = rhs.trim_start();
            if let Some(canonical) = js_rhs_capability_root(rhs) {
                aliases.insert(name.to_owned(), canonical);
            }
        }
    }

    // --- Python: `import os as m`  /  `import subprocess as s` ----------------
    //            `from os import environ as e` ---------------------------------
    for line in code.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("import ") {
            // `import <root> as <alias>` — single module only (a comma list is
            // not a simple alias we model).
            if !rest.contains(',') {
                if let Some((module, alias)) = rest.split_once(" as ") {
                    let module = module.trim();
                    let alias = alias.trim();
                    if is_simple_identifier(alias)
                        && PY_CAPABILITY_ROOTS.contains(&module.to_ascii_lowercase().as_str())
                    {
                        aliases.insert(alias.to_owned(), module.to_ascii_lowercase());
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("from ") {
            // `from <root> import <name> as <alias>` — map alias to `<root>.<name>`
            // so e.g. `from os import environ as e` makes `e[...]` scan as
            // `os.environ[...]`.
            if let Some((module, imported)) = rest.split_once(" import ") {
                let module = module.trim().to_ascii_lowercase();
                if PY_CAPABILITY_ROOTS.contains(&module.as_str()) && !imported.contains(',') {
                    if let Some((name, alias)) = imported.split_once(" as ") {
                        let name = name.trim();
                        let alias = alias.trim();
                        if is_simple_identifier(alias) && is_simple_identifier(name) {
                            aliases.insert(alias.to_owned(), format!("{module}.{name}"));
                        }
                    }
                }
            }
        }
    }

    // Never alias a name to itself, and drop any alias whose name is itself a
    // capability root (would be a no-op / could loop).
    aliases.retain(|name, canonical| name != canonical);
    aliases
}

/// Classify a JS assignment right-hand side. Returns the canonical capability
/// token IFF the RHS is EXACTLY a bare capability root identifier or a
/// `require('<mod>')` of a known capability module — nothing else. A member
/// expression (`obj.process`), a property of something, or a call other than the
/// recognised `require(...)` returns `None`, so ordinary aliasing stays untouched.
fn js_rhs_capability_root(rhs: &str) -> Option<String> {
    // Bare root identifier: `process` / `child_process` / `fetch` terminated by
    // a non-identifier char (`;`, newline, end). `globalThis`/`global` are
    // containers, not the capability itself, so we do NOT alias them here (their
    // computed access is handled by the F1 backstop).
    for root in ["process", "child_process", "fetch"] {
        if let Some(after) = rhs.strip_prefix(root) {
            let next = after.chars().next();
            if next.is_none_or(|ch| !is_identifier_char(ch) && ch != '.' && ch != '[') {
                return Some((*root).to_owned());
            }
        }
    }

    // `require('<mod>')` / `require("<mod>")` of a capability module.
    if let Some(after) = rhs.strip_prefix("require") {
        let after = after.trim_start();
        if let Some(args) = after.strip_prefix('(') {
            if let Some((module, _)) = parse_quoted_literal(args.trim_start()) {
                return match module.as_str() {
                    "child_process" | "node:child_process" => Some("child_process".to_owned()),
                    "fs" | "node:fs" | "fs/promises" | "node:fs/promises" => {
                        Some("require(\"fs\")".to_owned())
                    }
                    "http" | "node:http" => Some("require(\"http\")".to_owned()),
                    "https" | "node:https" => Some("require(\"https\")".to_owned()),
                    _ => None,
                };
            }
        }
    }
    None
}

/// Replace every word-boundary occurrence of each alias identifier with its
/// canonical token. Occurrences immediately preceded by `.` (a member name) are
/// left alone so we only rewrite the alias used as a free identifier.
fn rewrite_identifiers(code: &str, aliases: &std::collections::BTreeMap<String, String>) -> String {
    let bytes = code.as_bytes();
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    while i < bytes.len() {
        // Start of an identifier at a boundary?
        let prev = if i == 0 {
            None
        } else {
            code[..i].chars().next_back()
        };
        let at_boundary = prev.is_none_or(|ch| !is_identifier_char(ch) && ch != '.');
        if at_boundary && is_identifier_char(bytes[i] as char) && bytes[i] != b'$' {
            let (ident, _) = take_identifier(&code[i..]);
            if !ident.is_empty() {
                if let Some(canonical) = aliases.get(ident) {
                    out.push_str(canonical);
                    i += ident.len();
                    continue;
                }
                // Skip the whole identifier so we don't re-enter mid-token.
                out.push_str(ident);
                i += ident.len();
                continue;
            }
        }
        let ch = code[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Take a leading ASCII identifier (`[A-Za-z_$][A-Za-z0-9_$]*`) from `s`,
/// returning it and the remainder.
fn take_identifier(s: &str) -> (&str, &str) {
    let end = s
        .char_indices()
        .take_while(|(idx, ch)| {
            if *idx == 0 {
                ch.is_ascii_alphabetic() || *ch == '_' || *ch == '$'
            } else {
                is_identifier_char(*ch)
            }
        })
        .map(|(idx, ch)| idx + ch.len_utf8())
        .last()
        .unwrap_or(0);
    s.split_at(end)
}

fn is_simple_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().enumerate().all(|(idx, ch)| {
            if idx == 0 {
                ch.is_ascii_alphabetic() || ch == '_'
            } else {
                ch.is_ascii_alphanumeric() || ch == '_'
            }
        })
}

fn extract_env_read_targets(content: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    collect_process_env_dot_targets(content, &mut targets);
    for marker in ["process.env[", "os.environ[", "os.getenv(", "getenv("] {
        collect_quoted_argument_targets(content, marker, &mut targets);
    }
    targets
}

fn collect_process_env_dot_targets(content: &str, targets: &mut BTreeSet<String>) {
    let marker = "process.env.";
    let mut offset = 0;
    while let Some(index) = content[offset..].find(marker) {
        let start = offset + index + marker.len();
        let name = content[start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect::<String>();
        if !name.is_empty() {
            targets.insert(name);
        }
        offset = start.saturating_add(1);
    }
}

fn collect_quoted_argument_targets(content: &str, marker: &str, targets: &mut BTreeSet<String>) {
    let mut offset = 0;
    while let Some(index) = content[offset..].find(marker) {
        let start = offset + index + marker.len();
        if let Some((target, consumed)) = parse_quoted_literal(content[start..].trim_start()) {
            if !target.is_empty()
                && target
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                targets.insert(target);
            }
            offset = start + consumed;
        } else {
            offset = start.saturating_add(1);
        }
    }
}

fn extract_http_hosts(content: &str) -> BTreeSet<String> {
    quoted_string_literals(content)
        .into_iter()
        .filter_map(|literal| http_url_host_authority(&literal))
        .collect()
}

fn http_url_host_authority(literal: &str) -> Option<String> {
    let scheme = literal.split_once(':')?.0;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let url = reqwest::Url::parse(literal).ok()?;
    let host = url.host_str()?;
    Some(
        url.port()
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned()),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommentSyntax {
    /// `//` line + `/* */` block comments — JS/TS family.
    CStyle,
    /// `#` line comments — Python (note `//` is floor-division there, NOT a
    /// comment, so it must be left intact).
    Hash,
}

fn comment_syntax(path: &str) -> Option<CommentSyntax> {
    match Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => Some(CommentSyntax::CStyle),
        Some("py") => Some(CommentSyntax::Hash),
        _ => None,
    }
}

/// Return `content` with comment spans blanked to whitespace (newlines kept) so
/// the capability text-scan only ever sees executable code. String literals are
/// copied through verbatim — a `//`, `/*`, or `#` inside a string is not a
/// comment — and Python triple-quoted strings are handled so a `#` in a docstring
/// stays string content. `None` syntax (non source files) returns the input as-is.
fn strip_comments(content: &str, syntax: Option<CommentSyntax>) -> String {
    let Some(syntax) = syntax else {
        return content.to_owned();
    };
    let c_style = syntax == CommentSyntax::CStyle;
    let bytes = content.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        // String literals — copy verbatim, honoring escapes (and Python triple
        // quotes). A comment marker inside a string is just string content.
        if b == b'"' || b == b'\'' || (c_style && b == b'`') {
            let triple = !c_style && i + 2 < bytes.len() && bytes[i + 1] == b && bytes[i + 2] == b;
            if triple {
                out.extend_from_slice(&bytes[i..i + 3]);
                i += 3;
                while i < bytes.len() {
                    if bytes[i] == b && bytes.get(i + 1) == Some(&b) && bytes.get(i + 2) == Some(&b)
                    {
                        out.extend_from_slice(&bytes[i..i + 3]);
                        i += 3;
                        break;
                    }
                    out.push(bytes[i]);
                    i += 1;
                }
            } else {
                let quote = b;
                out.push(b);
                i += 1;
                while i < bytes.len() {
                    let c = bytes[i];
                    out.push(c);
                    i += 1;
                    if c == b'\\' && i < bytes.len() {
                        out.push(bytes[i]);
                        i += 1;
                        continue;
                    }
                    if c == quote {
                        break;
                    }
                    // A bare newline ends a malformed single/double-quoted string
                    // (templates may span lines); bail so we never eat the file.
                    if c == b'\n' && quote != b'`' {
                        break;
                    }
                }
            }
            continue;
        }

        // Line comment: `//` (C-style) or `#` (Python).
        if (c_style && b == b'/' && bytes.get(i + 1) == Some(&b'/')) || (!c_style && b == b'#') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }

        // Block comment: `/* ... */` (C-style only).
        if c_style && b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < bytes.len() {
                if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    break;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            continue;
        }

        out.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn quoted_string_literals(content: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"' | b'`') {
            if let Some((literal, consumed)) = parse_quoted_literal(&content[index..]) {
                literals.push(literal);
                index += consumed;
                continue;
            }
        }
        index += 1;
    }
    literals
}

fn parse_quoted_literal(content: &str) -> Option<(String, usize)> {
    let bytes = content.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }

    let mut literal = Vec::new();
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(1) {
        if escaped {
            literal.push(*byte);
            escaped = false;
            continue;
        }
        if *byte == b'\\' {
            escaped = true;
            continue;
        }
        if *byte == quote {
            return String::from_utf8(literal)
                .ok()
                .map(|literal| (literal, index + 1));
        }
        literal.push(*byte);
    }
    None
}

/// F4 — find file-read call sites for `<marker>(` and return their read
/// targets. When the first call argument is a string LITERAL, the concrete path
/// is returned so the verdict gate can run `is_sensitive_read_path` against it
/// (e.g. reading `~/.ssh/id_rsa` is blocked even under `fs.read:*`). When the
/// path is dynamic (a variable/expression), we fall back to "*": this preserves
/// the prior accept-under-grant behavior for ordinary packages that read
/// computed project paths, and does NOT fail closed (that is reserved for
/// dynamic access to capability ROOTS in `detect_opaque_capability_access`).
fn fs_read_call_targets(content: &str, marker: &str) -> BTreeSet<String> {
    let lower = content.to_ascii_lowercase();
    let mut targets = BTreeSet::new();
    let mut offset = 0;
    while let Some(index) = lower[offset..].find(marker) {
        let start = offset + index;
        let after = start + marker.len();
        // The marker must start a real identifier OR be a member method name
        // (`fs.readFileSync(`): allow a preceding `.` so member calls match, but
        // reject a preceding identifier char (so `myReadFile` does not match
        // `readfile`). The char after the marker must not continue an identifier.
        let preceded_ok = lower[..start]
            .chars()
            .next_back()
            .is_none_or(|ch| !is_identifier_char(ch));
        let followed_ok = lower[after..]
            .chars()
            .next()
            .is_none_or(|ch| !is_identifier_char(ch));
        if preceded_ok && followed_ok {
            let rest = content[after..].trim_start();
            if let Some(args) = rest.strip_prefix('(') {
                match parse_quoted_literal(args.trim_start()) {
                    Some((literal, _)) if !literal.is_empty() => {
                        targets.insert(literal);
                    }
                    _ => {
                        // Dynamic path: opaque target, accept-under-grant only.
                        targets.insert("*".to_owned());
                    }
                }
            }
        }
        offset = after;
    }
    targets
}

fn contains_python_file_write(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(index) = lower[offset..].find("open") {
        let start = offset + index;
        let after_name = start + "open".len();
        if is_identifier_boundary(&lower, start)
            && lower[after_name..]
                .chars()
                .next()
                .is_none_or(|ch| !is_identifier_char(ch))
        {
            let rest = lower[after_name..].trim_start();
            if let Some(args) = rest.strip_prefix('(').and_then(extract_call_arguments) {
                if python_open_args_include_write_mode(args) {
                    return true;
                }
            }
        }
        offset = after_name;
    }
    false
}

fn extract_call_arguments(content_after_open_paren: &str) -> Option<&str> {
    let mut depth = 1usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in content_after_open_paren.char_indices() {
        if let Some(current_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == current_quote {
                quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&content_after_open_paren[..index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn python_open_args_include_write_mode(args: &str) -> bool {
    let lower = args.to_ascii_lowercase();
    let Some(mode_index) = lower.find("mode") else {
        let Some((_, mode_args)) = args.split_once(',') else {
            return false;
        };
        return quoted_string_literals(mode_args)
            .into_iter()
            .any(|literal| python_open_mode_writes(&literal));
    };
    let after_mode = lower[mode_index + "mode".len()..].trim_start();
    let Some(after_equals) = after_mode.strip_prefix('=').map(str::trim_start) else {
        return false;
    };
    parse_quoted_literal(after_equals)
        .map(|(literal, _)| python_open_mode_writes(&literal))
        .unwrap_or(false)
}

fn python_open_mode_writes(mode: &str) -> bool {
    mode.chars()
        .any(|ch| matches!(ch.to_ascii_lowercase(), 'w' | 'a' | 'x' | '+'))
}

fn http_client_usage_evidence(lower: &str) -> Option<&'static str> {
    if contains_standalone_call(lower, "fetch") {
        return Some("fetch()");
    }
    for pattern in [
        "require(\"http\")",
        "require('http')",
        "require(\"https\")",
        "require('https')",
    ] {
        if lower.contains(pattern) {
            return Some(pattern);
        }
    }
    if contains_standalone_call(lower, "axios")
        || contains_any_member_call(
            lower,
            "axios",
            &[
                "request", "get", "post", "put", "patch", "delete", "head", "options",
            ],
        )
    {
        return Some("axios request call");
    }
    if contains_any_member_call(
        lower,
        "requests",
        &[
            "request", "get", "post", "put", "patch", "delete", "head", "options",
        ],
    ) {
        return Some("requests request call");
    }
    if contains_any_member_call(
        lower,
        "httpx",
        &[
            "request", "get", "post", "put", "patch", "delete", "head", "options",
        ],
    ) {
        return Some("httpx request call");
    }
    if contains_any_member_call(
        lower,
        "urllib.request",
        &["urlopen", "urlretrieve", "request", "build_opener"],
    ) {
        return Some("urllib.request call");
    }
    if contains_any_member_call(
        lower,
        "socket",
        &["socket", "create_connection", "connect", "getaddrinfo"],
    ) {
        return Some("socket network call");
    }
    None
}

fn contains_any_member_call(lower: &str, receiver: &str, methods: &[&str]) -> bool {
    methods
        .iter()
        .any(|method| contains_member_call(lower, receiver, method))
}

fn contains_member_call(lower: &str, receiver: &str, method: &str) -> bool {
    let pattern = format!("{receiver}.{method}");
    let mut offset = 0;
    while let Some(index) = lower[offset..].find(&pattern) {
        let start = offset + index;
        let after_pattern = start + pattern.len();
        if is_identifier_boundary(lower, start)
            && lower[after_pattern..]
                .chars()
                .next()
                .is_none_or(|ch| !is_identifier_char(ch))
            && lower[after_pattern..].trim_start().starts_with('(')
        {
            return true;
        }
        offset = after_pattern;
    }
    false
}

fn contains_dynamic_eval(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    contains_standalone_call(&lower, "eval")
        || contains_standalone_call(&lower, "exec")
        || contains_new_function(&lower)
}

/// Capability roots whose name, if reached through opaque/dynamic access,
/// hands the package the full host surface. Computed/bracket access or
/// string-concatenated references to ANY of these means the profiler cannot
/// statically see the behavior, so we must fail closed (F1). Ordinary local
/// objects/arrays are NOT in this set, so `obj[key]` / `arr[i]` stay Pure.
const JS_CAPABILITY_ROOTS: &[&str] = &[
    "process",
    "require",
    "module",
    "globalthis",
    "global",
    "reflect",
    "child_process",
    "fetch",
    "eval",
];

const PY_CAPABILITY_ROOTS: &[&str] = &[
    "os",
    "sys",
    "subprocess",
    "builtins",
    "__builtins__",
    "importlib",
    "socket",
];

/// F1 — detect "I cannot statically see what this does" indicators that resolve
/// to a capability root, and return human-readable evidence strings. Each
/// returned evidence becomes a DynamicEval capability so the verdict gate fails
/// closed. Deliberately narrow: only dynamism aimed at the dangerous roots
/// (or at fetch/eval/Function) trips this; plain computed access on local data
/// does not.
fn detect_opaque_capability_access(content: &str) -> BTreeSet<String> {
    let mut evidence = BTreeSet::new();
    let lower = content.to_ascii_lowercase();

    // --- JavaScript / TypeScript --------------------------------------------

    // Computed/bracket access on a dangerous root: process[...], globalThis[...],
    // require[...], Reflect[...], fs[...], child_process[...], module[...].
    for root in JS_CAPABILITY_ROOTS {
        if js_has_computed_access_on(&lower, root) {
            evidence.insert(format!(
                "opaque/dynamic access to capability root `{root}[...]` — cannot verify"
            ));
        }
    }

    // dynamic import(): `import(` used as a call (not `import x from`).
    if js_has_dynamic_import(&lower) {
        evidence.insert(
            "opaque/dynamic `import(...)` — cannot verify dynamically imported module".to_owned(),
        );
    }

    // `new Function(` constructor — builds code at runtime. (Bare anonymous
    // `function(` declarations are ordinary and must NOT trip this; only the
    // constructor form via `new Function` or a concat-built `Function` does.)
    if contains_new_function(&lower) {
        evidence.insert("`new Function(...)` builds code at runtime — cannot verify".to_owned());
    }

    // Indirect require: `const r = require; r(...)` (alias then call).
    if js_has_indirect_require(&lower) {
        evidence.insert("indirect `require` via alias — cannot verify required module".to_owned());
    }

    // Identifier/member name built by string concatenation that resolves to a
    // dangerous root or to fetch/eval/Function (e.g. 'en'+'v', 'fet'+'ch').
    for fragment in concatenation_built_capability_fragments(content) {
        evidence.insert(format!(
            "capability identifier `{fragment}` assembled from string fragments — cannot verify"
        ));
    }

    // --- Python --------------------------------------------------------------

    // `getattr` is ubiquitous and benign in ordinary Python (`getattr(self, x)`),
    // so we only fail closed when its FIRST argument is a capability root
    // (`getattr(os, ...)`, `getattr(__import__('os'), ...)`, `getattr(builtins, ...)`).
    if py_getattr_on_capability_root(&lower) {
        evidence.insert(
            "opaque `getattr(...)` on a capability root — cannot verify dynamic attribute"
                .to_owned(),
        );
    }
    // Dynamic imports: a clean literal import of an ORDINARY module (a lazy
    // import of an optional dependency or a package submodule) is benign — the
    // capabilities of whatever is imported are still detected at their own call
    // sites. We fail closed only when the module is named by a non-literal
    // expression (cannot resolve) or is a capability-bearing module that could be
    // loaded dynamically to evade call-site detection.
    if py_dynamic_import_is_opaque(content) {
        evidence.insert(
            "opaque dynamic import (computed target or capability module) — cannot verify"
                .to_owned(),
        );
    }
    // importlib *loaders* pull code from an arbitrary spec/path — always opaque.
    if py_uses_importlib_loader(&lower) {
        evidence.insert(
            "opaque `importlib` loader (module_from_spec / SourceFileLoader) — cannot verify"
                .to_owned(),
        );
    }
    if contains_standalone_call(&lower, "compile") {
        evidence.insert("`compile(...)` builds code objects at runtime — cannot verify".to_owned());
    }
    if lower.contains("globals()[") || lower.contains("locals()[") {
        evidence
            .insert("opaque `globals()`/`locals()` subscript access — cannot verify".to_owned());
    }
    if lower.contains("__builtins__") {
        evidence.insert(
            "reference to `__builtins__` — opaque access to builtins, cannot verify".to_owned(),
        );
    }
    // Reflection-style subscript on a dangerous root (e.g. `os.__dict__[...]`).
    for root in PY_CAPABILITY_ROOTS {
        if py_has_computed_access_on(&lower, root) {
            evidence.insert(format!(
                "opaque dynamic access to capability root `{root}.__dict__[...]` — cannot verify"
            ));
        }
    }

    evidence
}

/// True if `getattr(` is called with a capability root as its first argument:
/// `getattr(os, ...)`, `getattr(sys, ...)`, `getattr(subprocess, ...)`, etc.
/// Plain `getattr(self, name)` / `getattr(obj, k)` does NOT trip this.
fn py_getattr_on_capability_root(lower: &str) -> bool {
    let mut offset = 0;
    while let Some(index) = lower[offset..].find("getattr") {
        let start = offset + index;
        let after = start + "getattr".len();
        if is_identifier_boundary(lower, start) {
            let rest = lower[after..].trim_start();
            if let Some(args) = rest.strip_prefix('(') {
                let first_arg = args.trim_start();
                for root in PY_CAPABILITY_ROOTS {
                    if first_arg.starts_with(root) {
                        let next = first_arg[root.len()..].chars().next();
                        if next.is_none_or(|ch| !is_identifier_char(ch)) {
                            return true;
                        }
                    }
                }
                // getattr(__import__(...), ...) is opaque regardless of the
                // imported module name.
                if first_arg.starts_with("__import__") {
                    return true;
                }
            }
        }
        offset = after;
    }
    false
}

/// True if importlib is used as a *loader* that pulls code from an arbitrary
/// spec/path (`module_from_spec`, `SourceFileLoader`, `spec_from_file_location`).
/// These are always opaque — we cannot see what code they load. Plain
/// `import importlib.metadata` for reading package metadata is not flagged.
fn py_uses_importlib_loader(lower: &str) -> bool {
    lower.contains("module_from_spec")
        || lower.contains("sourcefileloader")
        || lower.contains("spec_from_file_location")
}

/// Capability-bearing modules that, if loaded via a *literal* dynamic import,
/// stay opaque (fail closed) — they expose process/exec/FFI/socket/code-loading
/// surfaces, so a dynamic import is a way to obtain them while dodging call-site
/// detection of the dangerous call. Importing an ORDINARY module literally (a
/// lazy import of an optional dependency or a package submodule) is benign.
const PY_SENSITIVE_IMPORT_MODULES: &[&str] = &[
    "os",
    "nt",
    "subprocess",
    "_posixsubprocess",
    "sys",
    "ctypes",
    "socket",
    "multiprocessing",
    "pty",
    "runpy",
    "code",
    "builtins",
    "marshal",
    "pickle",
    "popen2",
    "commands",
    "msvcrt",
    "_winapi",
];

/// True if a module name (possibly dotted / relative) has a sensitive top-level
/// component per `PY_SENSITIVE_IMPORT_MODULES`.
fn py_module_is_sensitive(module: &str) -> bool {
    let top = module
        .trim()
        .trim_start_matches('.')
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    PY_SENSITIVE_IMPORT_MODULES.contains(&top.as_str())
}

/// Classify Python dynamic-import calls — `__import__(...)`,
/// `importlib.import_module(...)`, and bare `import_module(...)`. Returns true if
/// ANY such call is OPAQUE: its module argument is not a clean string literal
/// (a variable, an f-string, or a concatenation like `"." + x`), or it names a
/// capability-bearing module (`PY_SENSITIVE_IMPORT_MODULES`). A plain literal
/// import of an ordinary module is benign and does NOT trip this — the
/// capabilities of whatever it imports are still detected at their own call
/// sites, so a lazy `import_module("idna.idnadata")` is no riskier than a static
/// `import idna.idnadata`.
fn py_dynamic_import_is_opaque(content: &str) -> bool {
    for marker in ["__import__", "import_module"] {
        let mut offset = 0;
        while let Some(index) = content[offset..].find(marker) {
            let start = offset + index;
            let after = start + marker.len();
            offset = after;
            // Reject `xyzimport_module` but ALLOW a leading `.` so
            // `importlib.import_module` still matches.
            let preceded_by_ident = start > 0
                && content[..start]
                    .chars()
                    .next_back()
                    .is_some_and(is_identifier_char);
            if preceded_by_ident {
                continue;
            }
            let rest = content[after..].trim_start();
            let Some(args) = rest.strip_prefix('(') else {
                continue;
            };
            let arg = args.trim_start();
            match parse_quoted_literal(arg) {
                Some((module, consumed)) => {
                    // The literal must be the WHOLE first argument; a trailing
                    // `+` (concatenation) or other expression makes it computed.
                    let tail = arg[consumed..].trim_start();
                    let clean_literal = tail.starts_with(',') || tail.starts_with(')');
                    if !clean_literal || py_module_is_sensitive(&module) {
                        return true;
                    }
                    // benign: a clean literal import of an ordinary module
                }
                None => return true, // computed / non-literal module target
            }
        }
    }
    false
}

/// True if `content` (lowercased) contains `<root>[` where `root` stands as a
/// real identifier (not part of a longer name / not preceded by `.`). The `[`
/// may be separated by whitespace.
fn js_has_computed_access_on(lower: &str, root: &str) -> bool {
    let mut offset = 0;
    while let Some(index) = lower[offset..].find(root) {
        let start = offset + index;
        let after = start + root.len();
        if is_identifier_boundary(lower, start)
            && lower[after..]
                .chars()
                .next()
                .is_none_or(|ch| !is_identifier_char(ch))
            && lower[after..].trim_start().starts_with('[')
        {
            return true;
        }
        offset = after;
    }
    false
}

/// Python opaque subscript on a dangerous root, e.g. `sys.modules[` /
/// `os.environ[` are normal (handled elsewhere); here we flag direct dynamic
/// subscripting that resolves a capability root by computed key only when the
/// key is non-literal. To stay simple and avoid over-blocking, we only flag
/// `__dict__[` style reflection on these roots.
fn py_has_computed_access_on(lower: &str, root: &str) -> bool {
    let needle = format!("{root}.__dict__[");
    lower.contains(&needle)
}

/// dynamic `import(` call form (JS/TS). Excludes static `import x from 'y'` and
/// `import 'side-effect'` (no `(` directly after `import`), AND Python's grouped
/// import statement `from <module> import (a, b)` — a parenthesized import LIST,
/// not a dynamic-import call. A JS dynamic `import(...)` is an expression and is
/// never preceded by `from` within the same statement, so a `from ` earlier in
/// the statement (since the last newline / `;`) marks the Python form.
fn js_has_dynamic_import(lower: &str) -> bool {
    let mut offset = 0;
    while let Some(index) = lower[offset..].find("import") {
        let start = offset + index;
        let after = start + "import".len();
        offset = after;
        let standalone = is_identifier_boundary(lower, start)
            && lower[after..]
                .chars()
                .next()
                .is_none_or(|ch| !is_identifier_char(ch));
        if standalone && lower[after..].trim_start().starts_with('(') {
            let stmt_start = lower[..start]
                .rfind(|ch| ch == '\n' || ch == ';')
                .map(|i| i + 1)
                .unwrap_or(0);
            // `from <mod> import (...)` is a Python grouped import, not a call.
            if !lower[stmt_start..start].contains("from ") {
                return true;
            }
        }
    }
    false
}

/// Detect `alias = require;` (require assigned without an immediate call), which
/// later lets the package call the alias to load arbitrary modules opaquely.
fn js_has_indirect_require(lower: &str) -> bool {
    let mut offset = 0;
    while let Some(index) = lower[offset..].find("require") {
        let start = offset + index;
        let after = start + "require".len();
        if is_identifier_boundary(lower, start) {
            let rest = lower[after..].trim_start();
            // `require` followed by anything that is NOT a call `(` and NOT a
            // member access `.`/`[` and NOT another identifier char → it is
            // being used as a value (aliased / passed), which is opaque.
            let next = rest.chars().next();
            let used_as_value = matches!(next, Some(';') | Some(',') | Some(')'))
                || rest.starts_with("=>")
                || (rest.starts_with('=') && !rest.starts_with("=="));
            if used_as_value {
                return true;
            }
        }
        offset = after;
    }
    false
}

/// Find capability identifiers assembled from adjacent quoted string fragments
/// joined by `+`, e.g. `'en'+'v'`, `'fet' + 'ch'`, `'glob'+'alThis'`. We
/// concatenate runs of `"..." +`/`'...' +` literals and, if the joined result
/// (lowercased) equals or contains a capability root / fetch / eval / function,
/// report it. This catches `process['en'+'v']`, `globalThis['fet'+'ch']`, etc.
fn concatenation_built_capability_fragments(content: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes = content.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"' | b'`') {
            if let Some((first, consumed)) = parse_quoted_literal(&content[index..]) {
                // Begin a concatenation run.
                let mut joined = first;
                let mut cursor = index + consumed;
                let mut pieces = 1;
                loop {
                    let rest = content[cursor..].trim_start();
                    let advanced = content[cursor..].len() - rest.len();
                    if let Some(after_plus) = rest.strip_prefix('+') {
                        let next = after_plus.trim_start();
                        let next_advanced = after_plus.len() - next.len();
                        if let Some((piece, piece_consumed)) = parse_quoted_literal(next) {
                            joined.push_str(&piece);
                            pieces += 1;
                            cursor = cursor + advanced + 1 + next_advanced + piece_consumed;
                            continue;
                        }
                    }
                    break;
                }
                if pieces >= 2 {
                    let lowered = joined.to_ascii_lowercase();
                    if JS_CAPABILITY_ROOTS.iter().any(|root| lowered == *root)
                        || matches!(lowered.as_str(), "fetch" | "eval" | "function" | "env")
                    {
                        found.insert(joined);
                    }
                }
                index += consumed;
                continue;
            }
        }
        index += 1;
    }
    found
}

fn contains_new_function(lower: &str) -> bool {
    let mut offset = 0;
    while let Some(index) = lower[offset..].find("new") {
        let start = offset + index;
        let after_new = start + "new".len();
        if is_identifier_boundary(lower, start)
            && lower[after_new..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_whitespace())
        {
            let rest = lower[after_new..].trim_start();
            if rest.starts_with("function")
                && is_identifier_boundary(rest, 0)
                && rest["function".len()..]
                    .chars()
                    .next()
                    .is_none_or(|ch| !is_identifier_char(ch))
            {
                return true;
            }
        }
        offset = after_new;
    }
    false
}

fn contains_standalone_call(lower: &str, name: &str) -> bool {
    let mut offset = 0;
    while let Some(index) = lower[offset..].find(name) {
        let start = offset + index;
        let after_name = start + name.len();
        if is_identifier_boundary(lower, start)
            && lower[after_name..]
                .chars()
                .next()
                .is_none_or(|ch| !is_identifier_char(ch))
        {
            let rest = lower[after_name..].trim_start();
            if rest.starts_with('(') {
                return true;
            }
        }
        offset = after_name;
    }
    false
}

fn is_identifier_boundary(content: &str, index: usize) -> bool {
    if index == 0 {
        return true;
    }
    content[..index]
        .chars()
        .next_back()
        .is_none_or(|ch| !is_identifier_char(ch) && ch != '.')
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
}

fn is_npm_lifecycle_script(name: &str) -> bool {
    matches!(
        name,
        "preinstall"
            | "install"
            | "postinstall"
            | "prepare"
            | "prepublish"
            | "prepack"
            | "postpack"
    )
}

fn is_source_like(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let file_name = Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();

    if file_name.ends_with(".d.ts")
        || file_name.ends_with(".d.mts")
        || file_name.ends_with(".d.cts")
    {
        return false;
    }

    if matches!(
        file_name,
        "package.json"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "Pipfile.lock"
            | "uv.lock"
            | "pylock.toml"
            | "pylock.omc.toml"
            | "setup.py"
            | "conftest.py"
            | "tox.ini"
            | "noxfile.py"
            | "pyproject.toml"
            | "setup.cfg"
    ) {
        return false;
    }

    matches!(
        Path::new(&path).extension().and_then(|ext| ext.to_str()),
        Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "py")
    )
}

fn is_ignored_source_path(path: &str) -> bool {
    path.split('/').any(|component| {
        matches!(
            component.to_ascii_lowercase().as_str(),
            "test"
                | "tests"
                | "__tests__"
                | "docs"
                | "doc"
                | "examples"
                | "example"
                | "benchmark"
                | "benchmarks"
                | "perf"
                | "performance"
        )
    })
}
