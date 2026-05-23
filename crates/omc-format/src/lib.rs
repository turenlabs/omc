use std::fmt;

pub type CellId = u64;
pub type FunctionId = u32;
pub type ImportId = u32;
pub type LocalId = u16;
pub type ModuleId = String;
pub type ValueId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
        args: Vec<String>,
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

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Const(Value),
    LoadArg(u8),
    StoreLocal(LocalId),
    LoadLocal(LocalId),
    Add,
    Sub,
    Eq,
    Len,
    Slice,
    CallLocal(FunctionId),
    CallImport(ImportId),
    Cap(CapOp),
    Return,
    Trap(TrapCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorType {
    Pure,
    Network,
    HostCapability,
    BuildOnly,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
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
