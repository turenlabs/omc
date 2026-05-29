//! Lowering pass: AST -> `omc_format::Module`.
//!
//! This is the load-bearing part of the front end. It enforces the frozen
//! capability-lowering contract: a dangerous host call ALWAYS becomes an
//! explicit `Op::Cap(..)`, never a benign op, and any construct that cannot be
//! soundly represented is a hard `FrontendError` (deny-by-default).

use std::collections::HashMap;

use omc_format::{
    CapOp, Function, HttpRequest, ImportSpec, Module, Op, TrapCode, Value, VirtualPath,
};

use crate::ast::{BinOp, Expr, FunctionDecl, Program, Stmt};
use crate::{CompileOutput, FrontendError, PackageMeta};

/// Lower a parsed program against package metadata.
pub fn lower(program: &Program, meta: &PackageMeta) -> Result<CompileOutput, FrontendError> {
    let mut ctx = LowerCtx::new(&program.export)?;
    ctx.lower_body(&program.export.body)?;

    // A trailing implicit `return undefined`, but ONLY if control can fall off
    // the end of the body. Emitting it after a body that always returns would
    // be dead code, which the verifier (correctly) rejects.
    if !body_always_returns(&program.export.body) {
        ctx.emit(Op::Const(Value::Unit));
        ctx.emit(Op::Return);
    }

    let LowerCtx {
        code,
        local_count,
        imports,
        ..
    } = ctx;

    let function = Function::new(
        0,
        program.export.name.clone(),
        program.export.params.len() as u8,
        code,
    )
    .with_locals(local_count);

    let module = Module {
        id: format!("npm:{}@{}", meta.package, meta.version),
        package: meta.package.clone(),
        version: meta.version.clone(),
        declared_behavior: meta.declared_behavior.clone(),
        functions: vec![function],
    };
    Ok(CompileOutput { module, imports })
}

struct LowerCtx {
    code: Vec<Op>,
    /// param name -> arg index.
    params: HashMap<String, u8>,
    /// local name -> local slot.
    locals: HashMap<String, u16>,
    local_count: u16,
    /// require('pkg') aliases: local var name -> imported module specifier.
    /// Phase 3 linker resolves these; we only track which names are imports.
    import_aliases: HashMap<String, ImportTarget>,
    /// The positional import table, indexed by ImportId: the i-th entry is the
    /// `ImportSpec` emitted as `Op::CallImport(i)`. Each distinct third-party
    /// package gets one id, assigned in first-use order.
    imports: Vec<ImportSpec>,
    /// Memoizes the assigned ImportId for a `(package, member)` pair so repeated
    /// calls to the same imported binding reuse one id.
    import_ids: HashMap<(String, Option<String>), u32>,
}

#[derive(Clone)]
enum ImportTarget {
    /// A builtin module we know how to lower to capabilities, e.g. "fs".
    Builtin(String),
    /// A third-party package: calls to it become `CallImport`.
    Package(String),
}

impl LowerCtx {
    fn new(decl: &FunctionDecl) -> Result<Self, FrontendError> {
        let mut params = HashMap::new();
        for (i, name) in decl.params.iter().enumerate() {
            if i > u8::MAX as usize {
                return Err(FrontendError::new("too many parameters"));
            }
            params.insert(name.clone(), i as u8);
        }
        Ok(Self {
            code: Vec::new(),
            params,
            locals: HashMap::new(),
            local_count: 0,
            import_aliases: HashMap::new(),
            imports: Vec::new(),
            import_ids: HashMap::new(),
        })
    }

    /// Assign (or reuse) the positional `ImportId` for a `(package, member)`
    /// pair, recording its `ImportSpec` in first-use order. Distinct packages
    /// get distinct ids; repeated use of the same binding reuses one id.
    fn intern_import(
        &mut self,
        package: &str,
        member: Option<&str>,
    ) -> Result<u32, FrontendError> {
        let key = (package.to_owned(), member.map(str::to_owned));
        if let Some(id) = self.import_ids.get(&key) {
            return Ok(*id);
        }
        let id = u32::try_from(self.imports.len())
            .map_err(|_| FrontendError::new("too many imports"))?;
        self.imports.push(ImportSpec {
            package: package.to_owned(),
            member: member.map(str::to_owned),
        });
        self.import_ids.insert(key, id);
        Ok(id)
    }

    fn emit(&mut self, op: Op) -> usize {
        let at = self.code.len();
        self.code.push(op);
        at
    }

    /// Patch a previously-emitted `Jmp`/`JmpIfFalse` placeholder so it targets
    /// the current end of the code. Offset is relative to the instruction
    /// AFTER the branch: target = (branch_index + 1) + offset.
    fn patch_to_here(&mut self, branch_index: usize) {
        let target = self.code.len();
        let offset = target as i64 - (branch_index as i64 + 1);
        let offset = offset as i32;
        match &mut self.code[branch_index] {
            Op::Jmp(o) | Op::JmpIfFalse(o) => *o = offset,
            other => panic!("patch_to_here on non-branch op {other:?}"),
        }
    }

    /// Patch a branch to target a specific absolute index.
    fn patch_to(&mut self, branch_index: usize, target: usize) {
        let offset = (target as i64 - (branch_index as i64 + 1)) as i32;
        match &mut self.code[branch_index] {
            Op::Jmp(o) | Op::JmpIfFalse(o) => *o = offset,
            other => panic!("patch_to on non-branch op {other:?}"),
        }
    }

    fn alloc_local(&mut self, name: &str) -> Result<u16, FrontendError> {
        if let Some(slot) = self.locals.get(name) {
            return Ok(*slot);
        }
        let slot = self.local_count;
        self.local_count = self
            .local_count
            .checked_add(1)
            .ok_or_else(|| FrontendError::new("too many locals"))?;
        self.locals.insert(name.to_owned(), slot);
        Ok(slot)
    }

    // ---- statements -------------------------------------------------------

    fn lower_body(&mut self, body: &[Stmt]) -> Result<(), FrontendError> {
        for stmt in body {
            self.lower_stmt(stmt)?;
        }
        Ok(())
    }

    fn lower_stmt(&mut self, stmt: &Stmt) -> Result<(), FrontendError> {
        match stmt {
            Stmt::Local { name, value } => {
                // Special case: `const fs = require('fs')` binds an import alias
                // rather than a runtime local. We record the alias and emit no
                // code (the capability is materialised at the call site).
                if let Some(target) = self.recognize_require(value)? {
                    self.import_aliases.insert(name.clone(), target);
                    return Ok(());
                }
                self.lower_expr(value)?;
                let slot = self.alloc_local(name)?;
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
            Stmt::Assign { name, value } => {
                // Reassign an existing local only. Assigning to a parameter,
                // an import alias, or an undeclared name fails closed.
                if self.params.contains_key(name) {
                    return Err(FrontendError::new(format!(
                        "cannot reassign parameter `{name}` (parameters are read-only in the subset)"
                    )));
                }
                if self.import_aliases.contains_key(name) {
                    return Err(FrontendError::new(format!(
                        "cannot reassign require alias `{name}`"
                    )));
                }
                let Some(slot) = self.locals.get(name).copied() else {
                    return Err(FrontendError::new(format!(
                        "assignment to undeclared variable `{name}` (declare with let/const first)"
                    )));
                };
                self.lower_expr(value)?;
                self.emit(Op::StoreLocal(slot));
                Ok(())
            }
            Stmt::Expr(expr) => {
                self.lower_expr(expr)?;
                // Statement context: discard the produced value to keep the
                // stack balanced at the next merge point.
                self.emit(Op::Pop);
                Ok(())
            }
            Stmt::If {
                cond,
                then_branch,
                else_branch,
            } => self.lower_if(cond, then_branch, else_branch),
            Stmt::While { cond, body } => self.lower_while(cond, body),
        }
    }

    fn lower_if(
        &mut self,
        cond: &Expr,
        then_branch: &[Stmt],
        else_branch: &[Stmt],
    ) -> Result<(), FrontendError> {
        self.lower_expr(cond)?;
        // JmpIfFalse over the then-branch.
        let to_else = self.emit(Op::JmpIfFalse(0));
        self.lower_body(then_branch)?;
        if else_branch.is_empty() {
            self.patch_to_here(to_else);
        } else if body_always_returns(then_branch) {
            // The then-branch always returns, so the unconditional jump over the
            // else would be dead code. Fall the false-path directly into else.
            self.patch_to_here(to_else);
            self.lower_body(else_branch)?;
        } else {
            // Jump over the else-branch at the end of then.
            let to_end = self.emit(Op::Jmp(0));
            self.patch_to_here(to_else);
            self.lower_body(else_branch)?;
            self.patch_to_here(to_end);
        }
        Ok(())
    }

    fn lower_while(&mut self, cond: &Expr, body: &[Stmt]) -> Result<(), FrontendError> {
        let loop_top = self.code.len();
        self.lower_expr(cond)?;
        let exit = self.emit(Op::JmpIfFalse(0));
        self.lower_body(body)?;
        // Back-edge to the condition.
        let back = self.emit(Op::Jmp(0));
        self.patch_to(back, loop_top);
        self.patch_to_here(exit);
        Ok(())
    }

    // ---- expressions ------------------------------------------------------

    fn lower_expr(&mut self, expr: &Expr) -> Result<(), FrontendError> {
        match expr {
            Expr::Int(v) => {
                self.emit(Op::Const(Value::Int(*v)));
                Ok(())
            }
            Expr::Str(v) => {
                self.emit(Op::Const(Value::String(v.clone())));
                Ok(())
            }
            Expr::Bool(v) => {
                self.emit(Op::Const(Value::Bool(*v)));
                Ok(())
            }
            Expr::Array(elems) => {
                // Only constant-foldable array literals are supported, because
                // the ISA has no "build array" op. We fold literals into a
                // single Const(Array). Non-constant elements fail closed.
                let mut values = Vec::with_capacity(elems.len());
                for e in elems {
                    values.push(self.const_value(e)?);
                }
                self.emit(Op::Const(Value::Array(values)));
                Ok(())
            }
            Expr::Ident(name) => self.lower_ident(name),
            Expr::Neg(inner) => {
                // `-x` == `0 - x`.
                self.emit(Op::Const(Value::Int(0)));
                self.lower_expr(inner)?;
                self.emit(Op::Sub);
                Ok(())
            }
            Expr::Not(inner) => {
                self.lower_expr(inner)?;
                self.emit(Op::Not);
                Ok(())
            }
            Expr::Binary { op, left, right } => self.lower_binary(op, left, right),
            Expr::Member { target, name } => self.lower_member_read(target, name),
            Expr::Index { target, index } => {
                self.lower_expr(target)?;
                self.lower_expr(index)?;
                self.emit(Op::Index);
                Ok(())
            }
            Expr::Call { callee, args } => self.lower_call(callee, args),
            Expr::New { callee, args } => self.lower_new(callee, args),
        }
    }

    fn lower_ident(&mut self, name: &str) -> Result<(), FrontendError> {
        if let Some(idx) = self.params.get(name) {
            self.emit(Op::LoadArg(*idx));
            return Ok(());
        }
        if let Some(slot) = self.locals.get(name) {
            self.emit(Op::LoadLocal(*slot));
            return Ok(());
        }
        Err(FrontendError::new(format!(
            "unknown identifier `{name}` (not a parameter, local, or supported global)"
        )))
    }

    fn lower_binary(&mut self, op: &BinOp, left: &Expr, right: &Expr) -> Result<(), FrontendError> {
        // Short-circuit boolean operators lower to branches so the result is a
        // single Bool on the stack and both paths leave equal stack depth.
        match op {
            BinOp::And => return self.lower_and(left, right),
            BinOp::Or => return self.lower_or(left, right),
            _ => {}
        }

        self.lower_expr(left)?;
        self.lower_expr(right)?;
        match op {
            BinOp::Add => self.emit(Op::Add),
            BinOp::Sub => self.emit(Op::Sub),
            BinOp::Mul => self.emit(Op::Mul),
            BinOp::Div => self.emit(Op::Div),
            BinOp::Mod => self.emit(Op::Mod),
            BinOp::Lt => self.emit(Op::Lt),
            BinOp::Gt => self.emit(Op::Gt),
            BinOp::Le => self.emit(Op::Le),
            BinOp::Ge => self.emit(Op::Ge),
            BinOp::Eq => self.emit(Op::Eq),
            BinOp::Ne => {
                self.emit(Op::Eq);
                self.emit(Op::Not)
            }
            BinOp::And | BinOp::Or => unreachable!("handled above"),
        };
        Ok(())
    }

    fn lower_and(&mut self, left: &Expr, right: &Expr) -> Result<(), FrontendError> {
        // a && b:
        //   <a>; JmpIfFalse Lfalse; <b>; Jmp Lend; Lfalse: Const(false); Lend:
        self.lower_expr(left)?;
        let to_false = self.emit(Op::JmpIfFalse(0));
        self.lower_expr(right)?;
        let to_end = self.emit(Op::Jmp(0));
        self.patch_to_here(to_false);
        self.emit(Op::Const(Value::Bool(false)));
        self.patch_to_here(to_end);
        Ok(())
    }

    fn lower_or(&mut self, left: &Expr, right: &Expr) -> Result<(), FrontendError> {
        // a || b:
        //   <a>; JmpIfFalse Leval; Const(true); Jmp Lend; Leval: <b>; Lend:
        self.lower_expr(left)?;
        let to_eval = self.emit(Op::JmpIfFalse(0));
        self.emit(Op::Const(Value::Bool(true)));
        let to_end = self.emit(Op::Jmp(0));
        self.patch_to_here(to_eval);
        self.lower_expr(right)?;
        self.patch_to_here(to_end);
        Ok(())
    }

    // ---- member reads & capability chains ---------------------------------

    fn lower_member_read(&mut self, target: &Expr, name: &str) -> Result<(), FrontendError> {
        // process.env.X  ->  CapOp::EnvRead { name: "X" }
        if let Expr::Member {
            target: inner,
            name: env,
        } = target
        {
            if env == "env" && is_ident(inner, "process") {
                self.emit(Op::Cap(CapOp::EnvRead {
                    name: name.to_owned(),
                }));
                return Ok(());
            }
        }

        // `something.length` -> Len.
        if name == "length" {
            self.lower_expr(target)?;
            self.emit(Op::Len);
            return Ok(());
        }

        // Generic property read on a runtime value: obj.prop -> Index by string
        // key (Map+String). This is pure and capability-free.
        self.lower_expr(target)?;
        self.emit(Op::Const(Value::String(name.to_owned())));
        self.emit(Op::Index);
        Ok(())
    }

    // ---- calls ------------------------------------------------------------

    fn lower_call(&mut self, callee: &Expr, args: &[Expr]) -> Result<(), FrontendError> {
        // process.env["X"]() etc. are not calls we support; handle the call
        // forms that map to capabilities or imports.

        // require('name') used directly as an expression (not bound to a var):
        // treat a builtin as unusable standalone, and a package as a 0-arg
        // CallImport is NOT valid here — require itself is metadata.
        if let Some(_target) = self.recognize_require(&Expr::Call {
            callee: Box::new(callee.clone()),
            args: args.to_vec(),
        })? {
            return Err(FrontendError::new(
                "require(...) must be assigned to a const before use",
            ));
        }

        if let Expr::Member { target, name } = callee {
            // fs.readFileSync(p) / fs.writeFileSync(p, v) where fs is a require alias.
            if let Expr::Ident(obj) = target.as_ref() {
                if let Some(ImportTarget::Builtin(module)) = self.import_aliases.get(obj).cloned() {
                    return self.lower_builtin_call(&module, name, args);
                }
                if let Some(ImportTarget::Package(pkg)) = self.import_aliases.get(obj).cloned() {
                    // pkg.method(...) — a named export call into another module.
                    return self.lower_import_call(&pkg, Some(name), args);
                }
            }

            // require('fs').readFileSync(p) inline.
            if let Some(ImportTarget::Builtin(module)) = self.recognize_require(target)? {
                return self.lower_builtin_call(&module, name, args);
            }

            // Date.now()
            if is_ident(target, "Date") && name == "now" {
                self.expect_arity(args, 0, "Date.now")?;
                self.emit(Op::Cap(CapOp::TimeNow));
                return Ok(());
            }

            // Math.abs(x) — pure builtin we can model: abs via branch.
            if is_ident(target, "Math") && name == "abs" {
                self.expect_arity(args, 1, "Math.abs")?;
                return self.lower_math_abs(&args[0]);
            }

            // https.request(...) / http.request(...) where the object is a
            // require alias for the http(s) builtin.
            if let Expr::Ident(obj) = target.as_ref() {
                if matches!(self.import_aliases.get(obj), Some(ImportTarget::Builtin(m)) if m == "http" || m == "https")
                    && (name == "request" || name == "get")
                {
                    return self.lower_http_call(args);
                }
            }
        }

        // fetch(url, ...) global.
        if is_ident(callee, "fetch") {
            return self.lower_http_call(args);
        }

        // eval(s) global.
        if is_ident(callee, "eval") {
            self.expect_arity(args, 1, "eval")?;
            self.lower_expr(&args[0])?;
            self.emit(Op::Cap(CapOp::DynamicEval {
                source_from_stack: true,
            }));
            return Ok(());
        }

        // A bare call to a package alias bound via require: pkg(...) -> import.
        if let Expr::Ident(name) = callee {
            if let Some(ImportTarget::Package(pkg)) = self.import_aliases.get(name).cloned() {
                return self.lower_import_call(&pkg, None, args);
            }
        }

        Err(FrontendError::new(format!(
            "unsupported call form: {callee:?} — only capability calls, Math.abs/Date.now, \
             and require()'d package/builtin calls are in the subset"
        )))
    }

    /// Lower a call to a known builtin module method to its capability op.
    fn lower_builtin_call(
        &mut self,
        module: &str,
        method: &str,
        args: &[Expr],
    ) -> Result<(), FrontendError> {
        match (module, method) {
            ("fs", "readFileSync") | ("fs", "readFile") => {
                self.expect_min_arity(args, 1, "fs.readFileSync")?;
                let path = self.const_string(&args[0], "fs.readFileSync path")?;
                self.emit(Op::Cap(CapOp::FsRead {
                    path: VirtualPath(path),
                }));
                Ok(())
            }
            ("fs", "writeFileSync") | ("fs", "writeFile") => {
                self.expect_min_arity(args, 2, "fs.writeFileSync")?;
                let path = self.const_string(&args[0], "fs.writeFileSync path")?;
                // Push the value to write so FsWrite consumes it from the stack.
                self.lower_expr(&args[1])?;
                self.emit(Op::Cap(CapOp::FsWrite {
                    path: VirtualPath(path),
                    value_from_stack: true,
                }));
                // FsWrite leaves a Unit on the stack (the transfer pushes
                // Public); callers in statement position will Pop it.
                Ok(())
            }
            ("http", "request") | ("https", "request") | ("http", "get") | ("https", "get") => {
                self.lower_http_call(args)
            }
            ("crypto", "randomBytes") => {
                self.expect_arity(args, 1, "crypto.randomBytes")?;
                let len = self.const_int(&args[0], "crypto.randomBytes len")?;
                if len < 0 {
                    return Err(FrontendError::new("crypto.randomBytes length must be >= 0"));
                }
                self.emit(Op::Cap(CapOp::RandomBytes { len: len as usize }));
                Ok(())
            }
            ("child_process", "spawn")
            | ("child_process", "exec")
            | ("child_process", "execSync") => {
                self.expect_min_arity(args, 1, "child_process.spawn")?;
                let command = self.const_string(&args[0], "child_process command")?;
                // Lower each spawn argument (argv[1..]) onto the operand stack so
                // its taint label is visible to the verifier/VM at the process
                // sink. They are pushed deepest-first (left-to-right), matching
                // the VM which pops `args_from_stack` and restores order.
                let dynamic = &args[1..];
                for argument in dynamic {
                    self.lower_expr(argument)?;
                }
                self.emit(Op::Cap(CapOp::ProcSpawn {
                    command,
                    args: Vec::new(),
                    args_from_stack: dynamic.len(),
                }));
                Ok(())
            }
            ("dns", "lookup") => {
                self.expect_min_arity(args, 1, "dns.lookup")?;
                let host = self.const_string(&args[0], "dns.lookup host")?;
                self.emit(Op::Cap(CapOp::DnsLookup { host }));
                Ok(())
            }
            _ => Err(FrontendError::new(format!(
                "unsupported builtin call {module}.{method}(...)"
            ))),
        }
    }

    /// Lower an http(s)/fetch call: extract the host (constant or `*`), push the
    /// request body if present, emit `CapOp::HttpRequest`.
    fn lower_http_call(&mut self, args: &[Expr]) -> Result<(), FrontendError> {
        self.expect_min_arity(args, 1, "http request")?;
        // First argument is the URL/host. Constant string -> resolve host; a
        // non-constant target lowers to host "*" so policy still gates it.
        let (url, host) = match self.try_const_string(&args[0]) {
            Some(url) => {
                let host = host_of(&url);
                (url, host)
            }
            None => ("*".to_owned(), "*".to_owned()),
        };

        // Optional body: second argument (or a `{ body }` option object). We
        // support a literal/expression body as the second argument.
        let request = HttpRequest {
            method: "POST".to_owned(),
            url,
            host,
            body_from_stack: true,
        };
        if args.len() >= 2 {
            self.lower_expr(&args[1])?;
        } else {
            // No explicit body: push Unit so body_from_stack has something to
            // consume and the stack stays balanced.
            self.emit(Op::Const(Value::Unit));
        }
        self.emit(Op::Cap(CapOp::HttpRequest { request }));
        Ok(())
    }

    fn lower_import_call(
        &mut self,
        pkg: &str,
        member: Option<&str>,
        args: &[Expr],
    ) -> Result<(), FrontendError> {
        // Push the arguments left-to-right; the linker-resolved CallImport pops
        // N args (N = callee.args) and reverses, matching CallLocal semantics.
        for arg in args {
            self.lower_expr(arg)?;
        }
        // The module carries a positional import table indexed by ImportId.
        // Each distinct (package, member) binding is interned to its own id in
        // first-use order; `Op::CallImport(id)` references the recorded
        // `ImportSpec`, which the linker resolves to a concrete `ImportRef`.
        let id = self.intern_import(pkg, member)?;
        self.emit(Op::CallImport(id));
        Ok(())
    }

    fn lower_new(&mut self, callee: &Expr, args: &[Expr]) -> Result<(), FrontendError> {
        // new Function(src) -> DynamicEval. Every other `new` fails closed.
        if is_ident(callee, "Function") {
            // The source is the last argument (Function(args.., body)).
            let body = args
                .last()
                .ok_or_else(|| FrontendError::new("new Function requires a body argument"))?;
            self.lower_expr(body)?;
            self.emit(Op::Cap(CapOp::DynamicEval {
                source_from_stack: true,
            }));
            return Ok(());
        }
        Err(FrontendError::new(format!(
            "unsupported `new {callee:?}` — only `new Function(...)` (DynamicEval) is recognised"
        )))
    }

    /// Math.abs(x): lower to `if (x < 0) { 0 - x } else { x }` keeping one Int
    /// on the stack on both paths.
    fn lower_math_abs(&mut self, arg: &Expr) -> Result<(), FrontendError> {
        // Stack-balanced branch: compute x, test < 0, negate on one path.
        // <x>; <x<0?>; we need x twice, so use a local.
        let slot = self.alloc_synthetic_local()?;
        self.lower_expr(arg)?;
        self.emit(Op::StoreLocal(slot));
        // cond: x < 0
        self.emit(Op::LoadLocal(slot));
        self.emit(Op::Const(Value::Int(0)));
        self.emit(Op::Lt);
        let to_else = self.emit(Op::JmpIfFalse(0));
        // then: 0 - x
        self.emit(Op::Const(Value::Int(0)));
        self.emit(Op::LoadLocal(slot));
        self.emit(Op::Sub);
        let to_end = self.emit(Op::Jmp(0));
        self.patch_to_here(to_else);
        // else: x
        self.emit(Op::LoadLocal(slot));
        self.patch_to_here(to_end);
        Ok(())
    }

    fn alloc_synthetic_local(&mut self) -> Result<u16, FrontendError> {
        let slot = self.local_count;
        self.local_count = self
            .local_count
            .checked_add(1)
            .ok_or_else(|| FrontendError::new("too many locals"))?;
        Ok(slot)
    }

    // ---- require recognition ----------------------------------------------

    /// If `expr` is a `require("name")` call, classify the target.
    fn recognize_require(&self, expr: &Expr) -> Result<Option<ImportTarget>, FrontendError> {
        let Expr::Call { callee, args } = expr else {
            return Ok(None);
        };
        if !is_ident(callee, "require") {
            return Ok(None);
        }
        if args.len() != 1 {
            return Err(FrontendError::new("require expects exactly one argument"));
        }
        let Expr::Str(name) = &args[0] else {
            return Err(FrontendError::new(
                "require argument must be a string literal",
            ));
        };
        Ok(Some(classify_module(name)))
    }

    // ---- constant-folding helpers -----------------------------------------

    fn const_value(&self, expr: &Expr) -> Result<Value, FrontendError> {
        match expr {
            Expr::Int(v) => Ok(Value::Int(*v)),
            Expr::Str(v) => Ok(Value::String(v.clone())),
            Expr::Bool(v) => Ok(Value::Bool(*v)),
            Expr::Array(elems) => {
                let mut values = Vec::with_capacity(elems.len());
                for e in elems {
                    values.push(self.const_value(e)?);
                }
                Ok(Value::Array(values))
            }
            _ => Err(FrontendError::new(
                "expected a constant literal (array literals must be fully constant)",
            )),
        }
    }

    fn try_const_string(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Str(s) => Some(s.clone()),
            _ => None,
        }
    }

    fn const_string(&self, expr: &Expr, what: &str) -> Result<String, FrontendError> {
        self.try_const_string(expr)
            .ok_or_else(|| FrontendError::new(format!("{what} must be a constant string literal")))
    }

    fn const_int(&self, expr: &Expr, what: &str) -> Result<i64, FrontendError> {
        match expr {
            Expr::Int(v) => Ok(*v),
            _ => Err(FrontendError::new(format!(
                "{what} must be a constant integer literal"
            ))),
        }
    }

    fn expect_arity(&self, args: &[Expr], n: usize, what: &str) -> Result<(), FrontendError> {
        if args.len() != n {
            return Err(FrontendError::new(format!(
                "{what} expects {n} argument(s), got {}",
                args.len()
            )));
        }
        Ok(())
    }

    fn expect_min_arity(&self, args: &[Expr], n: usize, what: &str) -> Result<(), FrontendError> {
        if args.len() < n {
            return Err(FrontendError::new(format!(
                "{what} expects at least {n} argument(s), got {}",
                args.len()
            )));
        }
        Ok(())
    }
}

fn is_ident(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Ident(n) if n == name)
}

/// Conservative "does control always leave this block via `return`?" check used
/// to avoid emitting dead code after a guaranteed return (which the verifier
/// rejects). A block always returns iff its last statement always returns: a
/// `return`, or an `if`/`else` where BOTH branches always return.
fn body_always_returns(body: &[Stmt]) -> bool {
    match body.last() {
        Some(Stmt::Return(_)) => true,
        Some(Stmt::If {
            then_branch,
            else_branch,
            ..
        }) => {
            !else_branch.is_empty()
                && body_always_returns(then_branch)
                && body_always_returns(else_branch)
        }
        _ => false,
    }
}

/// Classify a `require("name")` target as a known capability builtin or an
/// external package (CallImport).
fn classify_module(name: &str) -> ImportTarget {
    match name {
        "fs" | "http" | "https" | "crypto" | "child_process" | "dns" => {
            ImportTarget::Builtin(name.to_owned())
        }
        // node: prefixed builtins.
        other if other.starts_with("node:") => {
            ImportTarget::Builtin(other.trim_start_matches("node:").to_owned())
        }
        other => ImportTarget::Package(other.to_owned()),
    }
}

/// Extract a host from a URL string. For a bare host (no scheme) returns it
/// unchanged. Conservative: anything we cannot parse becomes "*".
fn host_of(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("*")
        .split('@')
        .last()
        .unwrap_or("*");
    let host = host.split(':').next().unwrap_or("*");
    if host.is_empty() {
        "*".to_owned()
    } else {
        host.to_owned()
    }
}

// Keep TrapCode import meaningful: an explicitly unrepresentable construct could
// lower to a verification trap. We expose a small helper so future expansion of
// the subset has a single, documented place to emit it rather than silently
// dropping a dangerous form.
#[allow(dead_code)]
pub(crate) fn unrepresentable() -> Op {
    Op::Trap(TrapCode::VerificationFailed)
}
