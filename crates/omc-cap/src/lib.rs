use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use omc_format::{CapOp, CellId, HttpRequest, TrapCode, Value, VirtualPath};
use omc_taint::{Label, Labeled, SecretKind, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    EnvRead(String),
    FsRead(String),
    FsWrite(String),
    HttpHost(String),
    DnsHost(String),
    TimeNow,
    RandomBytes,
    ProcSpawn(String),
    DynamicEval,
}

impl Capability {
    pub fn for_cap_op(op: &CapOp) -> Self {
        match op {
            CapOp::EnvRead { name } => Self::EnvRead(name.clone()),
            CapOp::FsRead { path } => Self::FsRead(path.to_string()),
            CapOp::FsWrite { path, .. } => Self::FsWrite(path.to_string()),
            CapOp::HttpRequest { request } => Self::HttpHost(request.host.clone()),
            CapOp::DnsLookup { host } => Self::DnsHost(host.clone()),
            CapOp::TimeNow => Self::TimeNow,
            CapOp::RandomBytes { .. } => Self::RandomBytes,
            CapOp::ProcSpawn { command, .. } => Self::ProcSpawn(command.clone()),
            CapOp::DynamicEval { .. } => Self::DynamicEval,
        }
    }

    fn matches(&self, requested: &Capability) -> bool {
        use Capability::*;

        match (self, requested) {
            (EnvRead(allowed), EnvRead(name))
            | (FsRead(allowed), FsRead(name))
            | (FsWrite(allowed), FsWrite(name))
            | (HttpHost(allowed), HttpHost(name))
            | (DnsHost(allowed), DnsHost(name))
            | (ProcSpawn(allowed), ProcSpawn(name)) => allowed == "*" || allowed == name,
            (TimeNow, TimeNow) | (RandomBytes, RandomBytes) | (DynamicEval, DynamicEval) => true,
            _ => false,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvRead(name) => write!(f, "env.read:{name}"),
            Self::FsRead(path) => write!(f, "fs.read:{path}"),
            Self::FsWrite(path) => write!(f, "fs.write:{path}"),
            Self::HttpHost(host) => write!(f, "http:{host}"),
            Self::DnsHost(host) => write!(f, "dns:{host}"),
            Self::TimeNow => f.write_str("time.now"),
            Self::RandomBytes => f.write_str("random.bytes"),
            Self::ProcSpawn(command) => write!(f, "proc.spawn:{command}"),
            Self::DynamicEval => f.write_str("dynamic.eval"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sink {
    Network(String),
    File(String),
    Process(String),
    Eval,
}

impl Sink {
    fn matches(&self, requested: &Sink) -> bool {
        match (self, requested) {
            (Self::Network(allowed), Self::Network(host))
            | (Self::File(allowed), Self::File(host))
            | (Self::Process(allowed), Self::Process(host)) => allowed == "*" || allowed == host,
            (Self::Eval, Self::Eval) => true,
            _ => false,
        }
    }
}

impl fmt::Display for Sink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(host) => write!(f, "network:{host}"),
            Self::File(path) => write!(f, "file:{path}"),
            Self::Process(command) => write!(f, "process:{command}"),
            Self::Eval => f.write_str("dynamic_eval"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelMatcher {
    Any,
    Env(String),
    File(String),
    Secret(String),
    Token(TokenKind),
}

impl LabelMatcher {
    fn matches(&self, label: &Label) -> bool {
        match (self, label) {
            (Self::Any, _) => true,
            (Self::Env(allowed), Label::Env(name)) => allowed == "*" || allowed == name,
            (Self::File(allowed), Label::File(path)) => allowed == "*" || allowed == path,
            (Self::Secret(allowed), Label::Secret(SecretKind::Env(name)))
            | (Self::Secret(allowed), Label::Secret(SecretKind::Generic(name))) => {
                allowed == "*" || allowed == name
            }
            (Self::Token(allowed), Label::Token(kind)) => allowed == kind,
            (_, Label::Mixed(labels)) => labels.iter().any(|label| self.matches(label)),
            _ => false,
        }
    }
}

impl fmt::Display for LabelMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Env(name) => write!(f, "env:{name}"),
            Self::File(path) => write!(f, "file:{path}"),
            Self::Secret(name) => write!(f, "secret:{name}"),
            Self::Token(TokenKind::Aws) => f.write_str("token:aws"),
            Self::Token(TokenKind::GitHub) => f.write_str("token:github"),
            Self::Token(TokenKind::Npm) => f.write_str("token:npm"),
            Self::Token(TokenKind::Generic(name)) => write!(f, "token:{name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRule {
    pub from: LabelMatcher,
    pub to: Sink,
}

impl FlowRule {
    pub fn new(from: LabelMatcher, to: Sink) -> Self {
        Self { from, to }
    }

    fn allows(&self, label: &Label, sink: &Sink) -> bool {
        self.from.matches(label) && self.to.matches(sink)
    }
}

impl fmt::Display for FlowRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}", self.from, self.to)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub allowed_capabilities: Vec<Capability>,
    pub allowed_flows: Vec<FlowRule>,
    allow_all_flows: bool,
}

impl Policy {
    pub fn pure() -> Self {
        Self {
            allowed_capabilities: Vec::new(),
            allowed_flows: Vec::new(),
            allow_all_flows: false,
        }
    }

    pub fn allow_capability(mut self, capability: Capability) -> Self {
        self.allowed_capabilities.push(capability);
        self
    }

    pub fn allow_flow(mut self, from: LabelMatcher, to: Sink) -> Self {
        self.allowed_flows.push(FlowRule::new(from, to));
        self
    }

    pub fn allow_flow_rule(mut self, rule: FlowRule) -> Self {
        self.allowed_flows.push(rule);
        self
    }

    pub fn allow_all_flows(mut self) -> Self {
        self.allow_all_flows = true;
        self
    }

    pub fn require(&self, requested: Capability) -> Result<(), Trap> {
        if self.allows_capability(&requested) {
            Ok(())
        } else {
            Err(Trap::denied(format!("capability {requested} not granted")))
        }
    }

    fn allows_capability(&self, requested: &Capability) -> bool {
        self.allowed_capabilities
            .iter()
            .any(|allowed| allowed.matches(requested))
    }

    pub fn require_cap_op(&self, op: &CapOp) -> Result<(), Trap> {
        self.require(Capability::for_cap_op(op))
    }

    pub fn check_flows(&self, label: &Label, sink: Sink) -> Result<(), Trap> {
        if label.is_public() {
            return Ok(());
        }
        if self.allow_all_flows {
            return Ok(());
        }

        let denied = label
            .labels()
            .into_iter()
            .filter(|label| {
                label.contains_sensitive()
                    && !self
                        .allowed_flows
                        .iter()
                        .any(|rule| rule.allows(label, &sink))
            })
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        if denied.is_empty() {
            Ok(())
        } else {
            Err(Trap::denied(format!(
                "{} may not flow to {sink}",
                denied.join(", ")
            )))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trap {
    pub code: TrapCode,
    pub message: String,
}

impl Trap {
    pub fn new(code: TrapCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(TrapCode::Denied, message)
    }

    pub fn type_error(message: impl Into<String>) -> Self {
        Self::new(TrapCode::TypeError, message)
    }
}

impl fmt::Display for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl Error for Trap {}

pub enum Never {}

pub trait CapabilityBroker {
    fn read_env(
        &mut self,
        cell: CellId,
        policy: &Policy,
        name: &str,
    ) -> Result<Labeled<Value>, Trap>;

    fn read_file(
        &mut self,
        cell: CellId,
        policy: &Policy,
        path: &VirtualPath,
    ) -> Result<Labeled<Value>, Trap>;

    fn write_file(
        &mut self,
        cell: CellId,
        policy: &Policy,
        path: &VirtualPath,
        value: Labeled<Value>,
    ) -> Result<Labeled<Value>, Trap>;

    fn http_request(
        &mut self,
        cell: CellId,
        policy: &Policy,
        request: &HttpRequest,
        body: Labeled<Value>,
    ) -> Result<Labeled<Value>, Trap>;

    fn spawn_process(
        &mut self,
        cell: CellId,
        policy: &Policy,
        command: &str,
        args: &[String],
    ) -> Result<Never, Trap>;
}

#[derive(Debug, Default)]
pub struct MemoryBroker {
    env: HashMap<String, String>,
    pub http_log: Vec<(String, Label)>,
}

impl MemoryBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }
}

impl CapabilityBroker for MemoryBroker {
    fn read_env(
        &mut self,
        _cell: CellId,
        policy: &Policy,
        name: &str,
    ) -> Result<Labeled<Value>, Trap> {
        policy.require(Capability::EnvRead(name.to_owned()))?;
        let value = self.env.get(name).cloned().unwrap_or_default();
        Ok(Labeled::new(
            Value::String(value),
            Label::Env(name.to_owned()),
        ))
    }

    fn read_file(
        &mut self,
        _cell: CellId,
        policy: &Policy,
        path: &VirtualPath,
    ) -> Result<Labeled<Value>, Trap> {
        policy.require(Capability::FsRead(path.to_string()))?;
        Ok(Labeled::new(
            Value::String(String::new()),
            Label::File(path.to_string()),
        ))
    }

    fn write_file(
        &mut self,
        _cell: CellId,
        policy: &Policy,
        path: &VirtualPath,
        value: Labeled<Value>,
    ) -> Result<Labeled<Value>, Trap> {
        policy.require(Capability::FsWrite(path.to_string()))?;
        policy.check_flows(&value.label, Sink::File(path.to_string()))?;
        Ok(Labeled::public(Value::Unit))
    }

    fn http_request(
        &mut self,
        _cell: CellId,
        policy: &Policy,
        request: &HttpRequest,
        body: Labeled<Value>,
    ) -> Result<Labeled<Value>, Trap> {
        policy.require(Capability::HttpHost(request.host.clone()))?;
        policy.check_flows(&body.label, Sink::Network(request.host.clone()))?;
        self.http_log.push((request.host.clone(), body.label));
        Ok(Labeled::new(
            Value::String("simulated-response".to_owned()),
            Label::Network(request.host.clone()),
        ))
    }

    fn spawn_process(
        &mut self,
        _cell: CellId,
        policy: &Policy,
        command: &str,
        _args: &[String],
    ) -> Result<Never, Trap> {
        policy.require(Capability::ProcSpawn(command.to_owned()))?;
        Err(Trap::denied(
            "process spawning is not implemented by MemoryBroker",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_requires_explicit_flow_grant() {
        let env_to_api = (
            Label::Env("API_TOKEN".to_owned()),
            Sink::Network("api.example.com".to_owned()),
        );

        assert!(Policy::pure()
            .allow_capability(Capability::EnvRead("API_TOKEN".to_owned()))
            .check_flows(&env_to_api.0, env_to_api.1.clone())
            .is_err());

        assert!(Policy::pure()
            .allow_capability(Capability::HttpHost("api.example.com".to_owned()))
            .check_flows(&env_to_api.0, env_to_api.1.clone())
            .is_err());

        assert!(Policy::pure()
            .allow_capability(Capability::EnvRead("API_TOKEN".to_owned()))
            .allow_capability(Capability::HttpHost("api.example.com".to_owned()))
            .check_flows(&env_to_api.0, env_to_api.1.clone())
            .is_err());

        Policy::pure()
            .allow_flow(
                LabelMatcher::Env("API_TOKEN".to_owned()),
                Sink::Network("api.example.com".to_owned()),
            )
            .check_flows(&env_to_api.0, env_to_api.1)
            .unwrap();
    }

    #[test]
    fn allow_all_flows_allows_sensitive_flows() {
        Policy::pure()
            .allow_all_flows()
            .check_flows(
                &Label::Env("NODE_INSPECTOR_IPC".to_owned()),
                Sink::Network("www.w3.org".to_owned()),
            )
            .unwrap();
    }
}
