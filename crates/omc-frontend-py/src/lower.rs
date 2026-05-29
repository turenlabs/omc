//! Lowering from the parsed Python-subset AST to an [`omc_format::Module`].
//!
//! The lowering is deny-by-default: any construct that cannot be soundly
//! represented as microcode is a hard [`FrontendError`]. Dangerous host calls
//! lower to explicit `Op::Cap(CapOp::..)` instructions per the frozen
//! capability table; they are never turned into benign ops.

use std::collections::HashMap;

use omc_format::{
    CapOp, Function, FunctionId, HttpRequest, ImportId, Module, Op, Value, VirtualPath,
};

use crate::parser::{BinOp, Expr, FuncDef, Import, ParsedModule, Stmt};
use crate::{FrontendError, PackageMeta};

/// Lower a parsed module into microcode.
pub fn lower(parsed: &ParsedModule, meta: &PackageMeta) -> Result<Module, FrontendError> {
    let module_id = format!("pypi:{}@{}", meta.package, meta.version);

    // Build the import alias -> ImportId table. Each binding gets a positional
    // ImportId that the linker resolves. `import requests` binds `requests`;
    // `from pkg import f` binds `f`.
    let imports = ImportTable::build(&parsed.imports);

    // Resolve sibling-function names to FunctionIds (declaration order).
    let mut func_ids: HashMap<String, FunctionId> = HashMap::new();
    for (index, func) in parsed.functions.iter().enumerate() {
        if func_ids.insert(func.name.clone(), index as FunctionId).is_some() {
            return Err(FrontendError::new(format!(
                "duplicate function definition `{}`",
                func.name
            )));
        }
    }

    let mut functions = Vec::new();
    for (index, func) in parsed.functions.iter().enumerate() {
        functions.push(lower_function(index as FunctionId, func, &func_ids, &imports)?);
    }

    Ok(Module {
        id: module_id,
        package: meta.package.clone(),
        version: meta.version.clone(),
        declared_behavior: meta.declared_behavior.clone(),
        functions,
    })
}

/// Maps imported names to positional ImportIds and remembers which alias refers
/// to which capability family (e.g. `requests` -> http client).
struct ImportTable {
    /// name (alias or imported symbol) -> (ImportId, source module dotted name)
    bindings: HashMap<String, (ImportId, String)>,
}

impl ImportTable {
    fn build(imports: &[Import]) -> Self {
        let mut bindings = HashMap::new();
        let mut next: ImportId = 0;
        for import in imports {
            match import {
                Import::Module { name, alias } => {
                    bindings
                        .entry(alias.clone())
                        .or_insert_with(|| {
                            let id = next;
                            next += 1;
                            (id, name.clone())
                        });
                }
                Import::From { module, names } => {
                    for symbol in names {
                        bindings.entry(symbol.clone()).or_insert_with(|| {
                            let id = next;
                            next += 1;
                            (id, module.clone())
                        });
                    }
                }
            }
        }
        Self { bindings }
    }

    /// The dotted source-module name a bound alias refers to, if any.
    fn source_of(&self, name: &str) -> Option<&str> {
        self.bindings.get(name).map(|(_, module)| module.as_str())
    }

    fn import_id(&self, name: &str) -> Option<ImportId> {
        self.bindings.get(name).map(|(id, _)| *id)
    }
}

/// Per-function lowering context.
struct LowerCtx<'a> {
    func_ids: &'a HashMap<String, FunctionId>,
    imports: &'a ImportTable,
    /// Parameter name -> positional index (for LoadArg).
    params: HashMap<String, u8>,
    /// Local variable name -> slot (for StoreLocal/LoadLocal).
    locals: HashMap<String, u16>,
    /// Emitted instructions.
    code: Vec<Op>,
}

fn lower_function(
    id: FunctionId,
    func: &FuncDef,
    func_ids: &HashMap<String, FunctionId>,
    imports: &ImportTable,
) -> Result<Function, FrontendError> {
    if func.params.len() > u8::MAX as usize {
        return Err(FrontendError::new(format!(
            "function `{}` has too many parameters",
            func.name
        )));
    }
    let mut params = HashMap::new();
    for (index, param) in func.params.iter().enumerate() {
        if params.insert(param.clone(), index as u8).is_some() {
            return Err(FrontendError::new(format!(
                "function `{}` has duplicate parameter `{}`",
                func.name, param
            )));
        }
    }

    let mut ctx = LowerCtx {
        func_ids,
        imports,
        params,
        locals: HashMap::new(),
        code: Vec::new(),
    };

    // Pre-allocate local slots for every assigned name so LoadLocal of a name
    // assigned later in a branch still has a slot (verifier needs locals count).
    collect_locals(&func.body, &mut ctx)?;

    ctx.lower_block(&func.body)?;

    // Functions that can fall off the end implicitly return Unit; the VM does
    // this already, so we do not need a trailing Return. But to keep the
    // instruction stream non-empty and well-formed we ensure there is at least
    // one terminator-reachable path. An empty body was already rejected by the
    // parser.

    let locals_count = ctx.locals.len() as u16;
    Ok(Function::new(id, func.name.clone(), func.params.len() as u8, ctx.code)
        .with_locals(locals_count))
}

/// Walk the body and assign a local slot to every assignment target. A name
/// that collides with a parameter is rejected (we will not silently shadow a
/// parameter, which would mislead the reader about which value is used).
fn collect_locals(body: &[Stmt], ctx: &mut LowerCtx) -> Result<(), FrontendError> {
    for stmt in body {
        match stmt {
            Stmt::Assign { name, .. } => {
                if ctx.params.contains_key(name) {
                    return Err(FrontendError::new(format!(
                        "assignment to parameter `{name}` is not supported (params are read-only)"
                    )));
                }
                let next = ctx.locals.len() as u16;
                ctx.locals.entry(name.clone()).or_insert(next);
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_locals(then_body, ctx)?;
                collect_locals(else_body, ctx)?;
            }
            Stmt::While { body, .. } => collect_locals(body, ctx)?,
            Stmt::Return(_) | Stmt::Expr(_) => {}
        }
    }
    Ok(())
}

impl LowerCtx<'_> {
    fn emit(&mut self, op: Op) -> usize {
        let index = self.code.len();
        self.code.push(op);
        index
    }

    /// Patch a previously-emitted Jmp/JmpIfFalse at `at` so it targets `dest`.
    /// Offsets are relative to the instruction AFTER the branch.
    fn patch_jump(&mut self, at: usize, dest: usize) {
        let offset = dest as i64 - (at as i64 + 1);
        let offset = offset as i32;
        match &mut self.code[at] {
            Op::Jmp(o) | Op::JmpIfFalse(o) => *o = offset,
            other => panic!("patch_jump called on non-branch op {other:?}"),
        }
    }

    fn lower_block(&mut self, body: &[Stmt]) -> Result<(), FrontendError> {
        for stmt in body {
            self.lower_stmt(stmt)?;
        }
        Ok(())
    }

    fn lower_stmt(&mut self, stmt: &Stmt) -> Result<(), FrontendError> {
        match stmt {
            Stmt::Assign { name, value } => {
                self.lower_expr(value)?;
                let slot = *self.locals.get(name).expect("local pre-allocated");
                self.emit(Op::StoreLocal(slot));
                Ok(())
            }
            Stmt::Return(Some(expr)) => {
                self.lower_expr(expr)?;
                self.emit(Op::Return);
                Ok(())
            }
            Stmt::Return(None) => {
                self.emit(Op::Const(Value::Unit));
                self.emit(Op::Return);
                Ok(())
            }
            Stmt::Expr(expr) => {
                // Evaluate for effect, then discard the result to keep the
                // stack balanced at the next statement / merge point.
                self.lower_expr(expr)?;
                self.emit(Op::Pop);
                Ok(())
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => self.lower_if(cond, then_body, else_body),
            Stmt::While { cond, body } => self.lower_while(cond, body),
        }
    }

    fn lower_if(
        &mut self,
        cond: &Expr,
        then_body: &[Stmt],
        else_body: &[Stmt],
    ) -> Result<(), FrontendError> {
        // cond ; JmpIfFalse(else) ; <then> ; Jmp(end) ; else: <else> ; end:
        //
        // When a branch always returns, the `Jmp(end)` after it would be dead
        // code that the verifier (rightly) rejects as unreachable. We therefore
        // omit the merge jump for any branch that always returns, and skip the
        // post-merge label entirely when BOTH branches always return.
        self.lower_expr(cond)?;
        let jmp_to_else = self.emit(Op::JmpIfFalse(0));
        self.lower_block(then_body)?;
        let then_returns = block_always_returns(then_body);

        if else_body.is_empty() {
            // No else: JmpIfFalse simply skips the then-block. (If the then
            // block always returns this is still fine: control re-enters here.)
            let end = self.code.len();
            self.patch_jump(jmp_to_else, end);
            return Ok(());
        }

        // Only bridge over the else-block if the then-block can fall through.
        let jmp_to_end = if then_returns {
            None
        } else {
            Some(self.emit(Op::Jmp(0)))
        };
        let else_start = self.code.len();
        self.patch_jump(jmp_to_else, else_start);
        self.lower_block(else_body)?;
        if let Some(jmp_to_end) = jmp_to_end {
            let end = self.code.len();
            self.patch_jump(jmp_to_end, end);
        }
        Ok(())
    }

    fn lower_while(&mut self, cond: &Expr, body: &[Stmt]) -> Result<(), FrontendError> {
        // head: cond ; JmpIfFalse(end) ; <body> ; Jmp(head) ; end:
        let head = self.code.len();
        self.lower_expr(cond)?;
        let jmp_to_end = self.emit(Op::JmpIfFalse(0));
        self.lower_block(body)?;
        let back = self.emit(Op::Jmp(0));
        self.patch_jump(back, head);
        let end = self.code.len();
        self.patch_jump(jmp_to_end, end);
        Ok(())
    }

    // ----- Expression lowering -----
    // Every expression lowers to code that pushes exactly one value.

    fn lower_expr(&mut self, expr: &Expr) -> Result<(), FrontendError> {
        match expr {
            Expr::Int(value) => {
                self.emit(Op::Const(Value::Int(*value)));
                Ok(())
            }
            Expr::Str(value) => {
                self.emit(Op::Const(Value::String(value.clone())));
                Ok(())
            }
            Expr::Bool(value) => {
                self.emit(Op::Const(Value::Bool(*value)));
                Ok(())
            }
            Expr::Name(name) => self.lower_name(name),
            Expr::Not(inner) => {
                self.lower_expr(inner)?;
                self.emit(Op::Not);
                Ok(())
            }
            Expr::Neg(inner) => {
                // -x  ==>  0 - x
                self.emit(Op::Const(Value::Int(0)));
                self.lower_expr(inner)?;
                self.emit(Op::Sub);
                Ok(())
            }
            Expr::Binary { op, left, right } => self.lower_binary(op, left, right),
            Expr::Index { base, index } => {
                // os.environ['X'] is an environment read, not a container index.
                if let Some((root, path)) = attr_chain(base) {
                    let source = self.imports.source_of(&root);
                    let chain = format!("{}.{}", root, path_join(&path));
                    if matches_module(&root, source, "os") && chain == "os.environ" {
                        let name = match index.as_ref() {
                            Expr::Str(value) => value.clone(),
                            _ => "*".to_owned(),
                        };
                        self.emit(Op::Cap(CapOp::EnvRead { name }));
                        return Ok(());
                    }
                }
                self.lower_expr(base)?;
                self.lower_expr(index)?;
                self.emit(Op::Index);
                Ok(())
            }
            Expr::List(items) => Err(FrontendError::new(format!(
                "list literals are not yet lowerable ({} elements); only used as call args or indexable values are unsupported",
                items.len()
            ))),
            Expr::Attr { .. } => Err(FrontendError::new(
                "bare attribute access is not supported outside of a recognised capability call",
            )),
            Expr::Call { callee, args } => self.lower_call(callee, args),
        }
    }

    fn lower_name(&mut self, name: &str) -> Result<(), FrontendError> {
        if let Some(index) = self.params.get(name) {
            self.emit(Op::LoadArg(*index));
            Ok(())
        } else if let Some(slot) = self.locals.get(name) {
            self.emit(Op::LoadLocal(*slot));
            Ok(())
        } else {
            Err(FrontendError::new(format!(
                "use of undefined name `{name}` (not a parameter, local, or import)"
            )))
        }
    }

    fn lower_binary(&mut self, op: &BinOp, left: &Expr, right: &Expr) -> Result<(), FrontendError> {
        match op {
            BinOp::And | BinOp::Or => self.lower_short_circuit(op, left, right),
            BinOp::NotEq => {
                self.lower_expr(left)?;
                self.lower_expr(right)?;
                self.emit(Op::Eq);
                self.emit(Op::Not);
                Ok(())
            }
            _ => {
                self.lower_expr(left)?;
                self.lower_expr(right)?;
                let op = match op {
                    BinOp::Add => Op::Add,
                    BinOp::Sub => Op::Sub,
                    BinOp::Mul => Op::Mul,
                    BinOp::Div => Op::Div,
                    BinOp::Mod => Op::Mod,
                    BinOp::Eq => Op::Eq,
                    BinOp::Lt => Op::Lt,
                    BinOp::Gt => Op::Gt,
                    BinOp::Le => Op::Le,
                    BinOp::Ge => Op::Ge,
                    BinOp::And | BinOp::Or | BinOp::NotEq => unreachable!(),
                };
                self.emit(op);
                Ok(())
            }
        }
    }

    /// `a and b` / `a or b` with short-circuit semantics, lowered with branches.
    /// Conditions must evaluate to booleans (the VM traps on non-bool), keeping
    /// the analysis sound without a truthiness model.
    fn lower_short_circuit(
        &mut self,
        op: &BinOp,
        left: &Expr,
        right: &Expr,
    ) -> Result<(), FrontendError> {
        self.lower_expr(left)?;
        match op {
            BinOp::And => {
                // if !left { false } else { right }
                let jmp_false = self.emit(Op::JmpIfFalse(0));
                self.lower_expr(right)?;
                let jmp_end = self.emit(Op::Jmp(0));
                let false_label = self.code.len();
                self.patch_jump(jmp_false, false_label);
                self.emit(Op::Const(Value::Bool(false)));
                let end = self.code.len();
                self.patch_jump(jmp_end, end);
            }
            BinOp::Or => {
                // if left { true } else { right }
                // JmpIfFalse jumps to the right-operand branch when left is false.
                let jmp_to_right = self.emit(Op::JmpIfFalse(0));
                self.emit(Op::Const(Value::Bool(true)));
                let jmp_end = self.emit(Op::Jmp(0));
                let right_label = self.code.len();
                self.patch_jump(jmp_to_right, right_label);
                self.lower_expr(right)?;
                let end = self.code.len();
                self.patch_jump(jmp_end, end);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn lower_call(&mut self, callee: &Expr, args: &[Expr]) -> Result<(), FrontendError> {
        // 1. Builtins: abs(x), len(x).
        if let Expr::Name(name) = callee {
            match name.as_str() {
                "abs" => return self.lower_abs(args),
                "len" => return self.lower_len(args),
                _ => {}
            }
            // 2. Sibling function call.
            if let Some(func_id) = self.func_ids.get(name).copied() {
                for arg in args {
                    self.lower_expr(arg)?;
                }
                self.emit(Op::CallLocal(func_id));
                return Ok(());
            }
            // 3. A bare-name import used as a callable (e.g. `from x import f; f()`).
            if let Some(import_id) = self.imports.import_id(name) {
                // `f(...)` on an imported symbol that is not a recognised
                // capability resolves to a cross-module CallImport.
                for arg in args {
                    self.lower_expr(arg)?;
                }
                self.emit(Op::CallImport(import_id));
                return Ok(());
            }
        }

        // 4. Attribute / capability calls (os.environ.get, requests.get, ...).
        if let Expr::Attr { base, attr } = callee {
            if let Some(cap) = self.try_lower_capability_call(base, attr, args)? {
                let _ = cap;
                return Ok(());
            }
        }

        Err(FrontendError::new(format!(
            "unsupported call expression: {callee:?}"
        )))
    }

    fn lower_abs(&mut self, args: &[Expr]) -> Result<(), FrontendError> {
        if args.len() != 1 {
            return Err(FrontendError::new("abs() takes exactly one argument"));
        }
        // abs(x) == (x if x >= 0 else -x). Lower with a branch:
        //   <x> ; <x> dup? — no Dup op, so store to a temp local is needed.
        // Instead compute via:  x ; Const(0) ; Lt ; JmpIfFalse(pos) ; (neg) ; Jmp(end) ; pos: (x) ; end:
        // We need x twice; recompute it (pure subset, x is a name/literal expr
        // produced by the parser, so re-lowering is safe and side-effect free).
        let x = &args[0];
        ensure_pure_reevaluable(x)?;
        // condition: x < 0
        self.lower_expr(x)?;
        self.emit(Op::Const(Value::Int(0)));
        self.emit(Op::Lt);
        let jmp_pos = self.emit(Op::JmpIfFalse(0));
        // negative branch: 0 - x
        self.emit(Op::Const(Value::Int(0)));
        self.lower_expr(x)?;
        self.emit(Op::Sub);
        let jmp_end = self.emit(Op::Jmp(0));
        // positive branch: x
        let pos = self.code.len();
        self.patch_jump(jmp_pos, pos);
        self.lower_expr(x)?;
        let end = self.code.len();
        self.patch_jump(jmp_end, end);
        Ok(())
    }

    fn lower_len(&mut self, args: &[Expr]) -> Result<(), FrontendError> {
        if args.len() != 1 {
            return Err(FrontendError::new("len() takes exactly one argument"));
        }
        self.lower_expr(&args[0])?;
        self.emit(Op::Len);
        Ok(())
    }

    /// Recognise the frozen capability-call forms. Returns `Ok(Some(()))` when a
    /// capability was emitted, `Ok(None)` when this is not a capability call (so
    /// the caller can report it), and `Err` when it *looks* like a dangerous
    /// host call but cannot be soundly represented (deny-by-default).
    fn try_lower_capability_call(
        &mut self,
        base: &Expr,
        attr: &str,
        args: &[Expr],
    ) -> Result<Option<()>, FrontendError> {
        // os.getenv("X")  /  os.environ.get("X")
        if let Some((root, path)) = attr_chain(base) {
            // Full dotted chain including root and the called attribute, e.g.
            // "os.getenv", "os.environ.get", "urllib.request.urlopen".
            let mut segments = vec![root.clone()];
            segments.extend(path.iter().cloned());
            segments.push(attr.to_owned());
            let chain = segments.join(".");
            let source = self.imports.source_of(&root);

            // ---- Environment reads -> CapOp::EnvRead -------------------------
            // os.getenv("X") | os.environ.get("X")
            if matches_module(&root, source, "os")
                && (chain == "os.getenv"
                    || chain == "os.environ.get"
                    || chain == "os.environ.__getitem__")
            {
                // EnvRead pushes the value and pops nothing; the env name is
                // carried in the cap op itself, so no operand is pushed here.
                let name = const_string_arg(args, 0).unwrap_or_else(|| "*".to_owned());
                self.emit(Op::Cap(CapOp::EnvRead { name }));
                return Ok(Some(()));
            }

            // ---- HTTP client -> CapOp::HttpRequest ---------------------------
            // requests.get(url) / requests.post(url) / urllib.request.urlopen(url)
            let is_requests = matches_module(&root, source, "requests")
                && matches!(attr, "get" | "post" | "put" | "delete" | "patch" | "head");
            let is_urllib = (matches_module(&root, source, "urllib")
                || matches_module(&root, source, "urllib.request"))
                && (attr == "urlopen" || chain.ends_with("request.urlopen"));
            if is_requests || is_urllib {
                let url = const_string_arg(args, 0).unwrap_or_else(|| "*".to_owned());
                let host = host_of(&url);
                let method = match attr {
                    "post" => "POST",
                    "put" => "PUT",
                    "patch" => "PATCH",
                    "delete" => "DELETE",
                    "head" => "HEAD",
                    _ => "GET",
                }
                .to_owned();
                // A request body (the second positional arg) is pushed onto the
                // stack so the verifier sees its taint flowing into the network
                // sink. requests.post(url, body) / requests.put(url, body) etc.
                let has_body = args.len() > 1;
                if has_body {
                    self.lower_expr(&args[1])?;
                }
                let request = HttpRequest {
                    method,
                    url: url.clone(),
                    host,
                    body_from_stack: has_body,
                };
                self.emit(Op::Cap(CapOp::HttpRequest { request }));
                return Ok(Some(()));
            }

            // ---- DNS -> CapOp::DnsLookup -------------------------------------
            if matches_module(&root, source, "socket") && attr == "getaddrinfo" {
                let host = const_string_arg(args, 0).unwrap_or_else(|| "*".to_owned());
                self.emit(Op::Cap(CapOp::DnsLookup { host }));
                return Ok(Some(()));
            }

            // ---- Subprocess -> CapOp::ProcSpawn -----------------------------
            if (matches_module(&root, source, "subprocess")
                && matches!(attr, "run" | "Popen" | "call" | "check_output"))
                || (matches_module(&root, source, "os") && attr == "system")
            {
                let command = const_string_arg(args, 0).unwrap_or_else(|| "*".to_owned());
                // Lower each spawn argument onto the operand stack (deepest-first)
                // so its taint label reaches the process sink in the verifier/VM.
                let dynamic = if args.len() > 1 { &args[1..] } else { &[][..] };
                for argument in dynamic {
                    self.lower_expr(argument)?;
                }
                self.emit(Op::Cap(CapOp::ProcSpawn {
                    command,
                    args: Vec::new(),
                    args_from_stack: dynamic.len(),
                }));
                return Ok(Some(()));
            }

            // ---- open(path).read() handled separately (open is a bare call) --

            // A call on a known dangerous module whose specific method we do NOT
            // model must fail closed rather than mislower to a benign op.
            if let Some(src) = source {
                if is_sensitive_module(src) {
                    return Err(FrontendError::new(format!(
                        "unsupported call `{chain}` on security-sensitive module `{src}` (cannot soundly lower)"
                    )));
                }
            }
        }

        // open(p).read() — base is `open(p)`, attr is `read`.
        if attr == "read" {
            if let Expr::Call { callee, args: open_args } = base {
                if let Expr::Name(fname) = callee.as_ref() {
                    if fname == "open" {
                        let path = const_string_arg(open_args, 0).unwrap_or_else(|| "*".to_owned());
                        self.emit(Op::Cap(CapOp::FsRead {
                            path: VirtualPath(path),
                        }));
                        return Ok(Some(()));
                    }
                }
            }
        }

        // eval/exec/__import__ are bare-name calls, not attribute calls; reject
        // any unresolved attribute call rather than silently dropping it.
        let _ = args;
        Ok(None)
    }
}

/// Does a statement block always end by returning (on every path)? Used to
/// avoid emitting dead merge-jumps after fully-terminating branches, which the
/// verifier would flag as unreachable code.
fn block_always_returns(body: &[Stmt]) -> bool {
    match body.last() {
        Some(Stmt::Return(_)) => true,
        Some(Stmt::If {
            then_body,
            else_body,
            ..
        }) => {
            !else_body.is_empty()
                && block_always_returns(then_body)
                && block_always_returns(else_body)
        }
        _ => false,
    }
}

/// Reject re-evaluation of an expression with potential side effects. For the
/// subset, `abs()`'s argument must be a pure value (name, literal, arithmetic
/// over those) so that lowering it twice is observationally identical.
fn ensure_pure_reevaluable(expr: &Expr) -> Result<(), FrontendError> {
    match expr {
        Expr::Int(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Name(_) => Ok(()),
        Expr::Not(inner) | Expr::Neg(inner) => ensure_pure_reevaluable(inner),
        Expr::Binary { left, right, .. } => {
            ensure_pure_reevaluable(left)?;
            ensure_pure_reevaluable(right)
        }
        Expr::Index { base, index } => {
            ensure_pure_reevaluable(base)?;
            ensure_pure_reevaluable(index)
        }
        Expr::Call { .. } | Expr::Attr { .. } | Expr::List(_) => Err(FrontendError::new(
            "abs() argument must be a side-effect-free expression (no calls)",
        )),
    }
}

/// Decompose a base expression into a dotted attribute chain rooted at a name,
/// e.g. `os.environ` -> ("os", ["environ"]); `requests` -> ("requests", []).
fn attr_chain(expr: &Expr) -> Option<(String, Vec<String>)> {
    match expr {
        Expr::Name(name) => Some((name.clone(), Vec::new())),
        Expr::Attr { base, attr } => {
            let (root, mut path) = attr_chain(base)?;
            path.push(attr.clone());
            Some((root, path))
        }
        _ => None,
    }
}

fn path_join(segments: &[String]) -> String {
    if segments.is_empty() {
        return String::new();
    }
    segments.join(".")
}

/// Does the bare root `root` refer to module `target`, either directly or via an
/// import alias whose source module is (or is under) `target`?
fn matches_module(root: &str, source: Option<&str>, target: &str) -> bool {
    if root == target {
        return true;
    }
    match source {
        Some(src) => src == target || src.starts_with(&format!("{target}.")),
        None => false,
    }
}

fn is_sensitive_module(src: &str) -> bool {
    let head = src.split('.').next().unwrap_or(src);
    matches!(
        head,
        "os" | "subprocess" | "socket" | "requests" | "urllib" | "shutil" | "ctypes" | "pickle"
    )
}

/// Extract a constant string argument at position `idx`, if it is a literal.
fn const_string_arg(args: &[Expr], idx: usize) -> Option<String> {
    match args.get(idx) {
        Some(Expr::Str(value)) => Some(value.clone()),
        _ => None,
    }
}

/// Best-effort host extraction from a URL literal. Non-constant or
/// unparseable URLs collapse to "*", which the policy still gates.
fn host_of(url: &str) -> String {
    if url == "*" {
        return "*".to_owned();
    }
    let without_scheme = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    // Strip any userinfo / port.
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        "*".to_owned()
    } else {
        host.to_owned()
    }
}

