//! Linker for OSS Microcode modules.
//!
//! Front ends emit one [`omc_format::Module`] per package. The linker resolves
//! cross-module references so that an `Op::CallImport(ImportId)` in one module
//! dispatches to an exported function of another module.
//!
//! # Module/linking format (frozen)
//!
//! Each `Module` declares an `id` of the form `npm:{pkg}@{ver}` or
//! `pypi:{pkg}@{ver}`. A module's imports are a positional table: the
//! `ImportId` (a `u32`) used by `Op::CallImport(id)` indexes into that module's
//! ordered list of [`ImportRef`]s. An `ImportRef` names the target module id and
//! the exported function within it (by name). Function id 0 is the conventional
//! entry/default export, matching `Module::entry()`.
//!
//! Resolution is a pure, offline pass over a closed set of modules (the lock
//! graph): every `ImportRef` MUST resolve to a known module + a function whose
//! name is exported by that module, or linking fails. Deny-by-default — an
//! unresolved or ambiguous import is a hard `LinkError`, never a runtime guess.
//! There is no dynamic/ambient import at link time; dynamic import remains a
//! capability (`CapOp::DynamicEval`) gated by the verifier and broker.
//!
//! The output is a [`LinkedProgram`]: the set of verified modules plus a
//! resolution table mapping `(module_id, ImportId) -> ResolvedImport`. The VM /
//! a multi-module driver consults this table when it encounters
//! `Op::CallImport`; `omc-vm`'s single-cell `run_cell` is unchanged and still
//! traps on unlinked imports. Each member module is expected to have passed
//! [`omc_verify::verify_module`] before it is admitted to a `LinkedProgram`.

use std::collections::HashMap;

use omc_format::{Function, FunctionId, ImportId, Module, ModuleId, Op};
use omc_vm::ImportResolver;

/// One entry in a module's positional import table. `Op::CallImport(i)` refers
/// to the i-th `ImportRef` declared by that module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRef {
    /// The id of the module being imported, e.g. `"npm:lodash@4.17.21"`.
    pub module: ModuleId,
    /// The exported function name within the target module.
    pub function: String,
}

/// A fully resolved import: the concrete target module id and function id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImport {
    pub module: ModuleId,
    pub function: FunctionId,
}

/// A link-time failure. Deny-by-default: any unresolved/ambiguous import fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkError {
    pub message: String,
}

impl LinkError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "link error: {}", self.message)
    }
}

impl std::error::Error for LinkError {}

/// A module paired with its positional import table, the unit the linker links.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkUnit {
    pub module: Module,
    /// Ordered import table; index = the `ImportId` used in `Op::CallImport`.
    pub imports: Vec<ImportRef>,
}

impl LinkUnit {
    /// A leaf module with no cross-module imports.
    pub fn leaf(module: Module) -> Self {
        Self {
            module,
            imports: Vec::new(),
        }
    }
}

/// The result of linking: all member modules plus the resolved import table.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkedProgram {
    pub modules: HashMap<ModuleId, Module>,
    pub resolution: HashMap<(ModuleId, ImportId), ResolvedImport>,
}

impl LinkedProgram {
    /// Look up the module that should serve as the cell entry point.
    pub fn module(&self, id: &ModuleId) -> Option<&Module> {
        self.modules.get(id)
    }

    /// Build an [`ImportResolver`] view over this program for `omc-vm`'s
    /// multi-module driver (`run_linked`). The resolver clones the target
    /// module + function on each hit; this keeps the VM ignorant of link
    /// internals at the cost of a clone per cross-module call.
    pub fn resolver(&self) -> ProgramResolver<'_> {
        ProgramResolver { program: self }
    }
}

/// An [`ImportResolver`] backed by a [`LinkedProgram`]'s resolution table.
pub struct ProgramResolver<'a> {
    program: &'a LinkedProgram,
}

impl ImportResolver for ProgramResolver<'_> {
    fn resolve(&self, module: &ModuleId, import: ImportId) -> Option<(Module, Function)> {
        let resolved = self.program.resolution.get(&(module.clone(), import))?;
        let target_module = self.program.modules.get(&resolved.module)?;
        let function = target_module.function(resolved.function)?;
        Some((target_module.clone(), function.clone()))
    }
}

/// Link a closed set of [`LinkUnit`]s into a [`LinkedProgram`].
///
/// Pure, offline pass over the lock graph. Deny-by-default: every `ImportRef`
/// declared by every unit must resolve to a known member module that exports a
/// function with that name, or linking fails with a `LinkError`. We also reject
/// duplicate module ids (an ambiguous graph) and `Op::CallImport(id)` whose id
/// has no entry in the importing module's import table — an out-of-range import
/// would otherwise resolve to nothing at runtime.
pub fn link(units: Vec<LinkUnit>) -> Result<LinkedProgram, LinkError> {
    let mut modules: HashMap<ModuleId, Module> = HashMap::new();
    let mut import_tables: HashMap<ModuleId, Vec<ImportRef>> = HashMap::new();

    for unit in units {
        let id = unit.module.id.clone();
        if modules.contains_key(&id) {
            return Err(LinkError::new(format!(
                "duplicate module id `{id}` in link graph (ambiguous)"
            )));
        }
        import_tables.insert(id.clone(), unit.imports);
        modules.insert(id, unit.module);
    }

    let mut resolution: HashMap<(ModuleId, ImportId), ResolvedImport> = HashMap::new();

    for (module_id, imports) in &import_tables {
        // Resolve every declared import to a concrete (module, function id).
        for (index, import_ref) in imports.iter().enumerate() {
            let import_id = index as ImportId;
            let target = modules.get(&import_ref.module).ok_or_else(|| {
                LinkError::new(format!(
                    "module `{module_id}` imports unknown module `{}` (import {import_id})",
                    import_ref.module
                ))
            })?;
            let function = find_exported_function(target, &import_ref.function).ok_or_else(|| {
                LinkError::new(format!(
                    "module `{}` does not export function `{}` (imported by `{module_id}` as import {import_id})",
                    import_ref.module, import_ref.function
                ))
            })?;
            resolution.insert(
                (module_id.clone(), import_id),
                ResolvedImport {
                    module: import_ref.module.clone(),
                    function,
                },
            );
        }

        // Every CallImport(id) actually emitted by the module must have a slot
        // in the import table; an out-of-range id can never resolve.
        let module = &modules[module_id];
        for function in &module.functions {
            for op in &function.code {
                if let Op::CallImport(id) = op {
                    if (*id as usize) >= imports.len() {
                        return Err(LinkError::new(format!(
                            "module `{module_id}` calls import {id} but declares only {} import(s)",
                            imports.len()
                        )));
                    }
                }
            }
        }
    }

    Ok(LinkedProgram {
        modules,
        resolution,
    })
}

/// Find an exported function by name. The conventional default export is the
/// entry function (id 0), but any named function in the module is exportable.
fn find_exported_function(module: &Module, name: &str) -> Option<FunctionId> {
    module
        .functions
        .iter()
        .find(|function| function.name == name)
        .map(|function| function.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    use omc_cap::{MemoryBroker, Policy};
    use omc_format::{BehaviorType, Op, Value};
    use omc_taint::{Label, Labeled};
    use omc_vm::{run_cell, run_linked, Cell};

    fn pure_module(id: &str, pkg: &str, function: Function) -> Module {
        Module {
            id: id.to_owned(),
            package: pkg.to_owned(),
            version: "1.0.0".to_owned(),
            declared_behavior: BehaviorType::Pure,
            functions: vec![function],
        }
    }

    /// A leaf module exporting `inc(n) = n + 1`.
    fn inc_module() -> Module {
        pure_module(
            "npm:inc@1.0.0",
            "inc",
            Function::new(
                0,
                "inc",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::Const(Value::Int(1)),
                    Op::Add,
                    Op::Return,
                ],
            ),
        )
    }

    /// A module that imports `inc` and computes `inc(arg) + 10`.
    fn caller_module() -> Module {
        pure_module(
            "npm:caller@1.0.0",
            "caller",
            Function::new(
                0,
                "caller",
                1,
                vec![
                    Op::LoadArg(0),
                    Op::CallImport(0),
                    Op::Const(Value::Int(10)),
                    Op::Add,
                    Op::Return,
                ],
            ),
        )
    }

    #[test]
    fn empty_program_links_to_empty_tables() {
        let program = link(Vec::new()).unwrap();
        assert!(program.modules.is_empty());
        assert!(program.resolution.is_empty());
    }

    #[test]
    fn links_two_modules_where_one_calls_the_other() {
        let units = vec![
            LinkUnit {
                module: caller_module(),
                imports: vec![ImportRef {
                    module: "npm:inc@1.0.0".to_owned(),
                    function: "inc".to_owned(),
                }],
            },
            LinkUnit::leaf(inc_module()),
        ];

        let program = link(units).unwrap();
        assert_eq!(program.modules.len(), 2);
        let resolved = program
            .resolution
            .get(&("npm:caller@1.0.0".to_owned(), 0))
            .unwrap();
        assert_eq!(resolved.module, "npm:inc@1.0.0");
        assert_eq!(resolved.function, 0);
    }

    #[test]
    fn linked_program_executes_cross_module_call() {
        let units = vec![
            LinkUnit {
                module: caller_module(),
                imports: vec![ImportRef {
                    module: "npm:inc@1.0.0".to_owned(),
                    function: "inc".to_owned(),
                }],
            },
            LinkUnit::leaf(inc_module()),
        ];
        let program = link(units).unwrap();
        let resolver = program.resolver();

        let entry = program
            .module(&"npm:caller@1.0.0".to_owned())
            .unwrap()
            .clone();
        let mut cell = Cell::new(1, entry, Policy::pure());
        let mut broker = MemoryBroker::new();

        // caller(5) = inc(5) + 10 = 6 + 10 = 16.
        let result = run_linked(
            &mut cell,
            &mut broker,
            &resolver,
            vec![Labeled::public(Value::Int(5))],
        )
        .unwrap();
        assert_eq!(result.value, Value::Int(16));
        assert_eq!(result.label, Label::Public);
    }

    #[test]
    fn single_cell_run_still_traps_on_unlinked_import() {
        let mut cell = Cell::new(1, caller_module(), Policy::pure());
        let mut broker = MemoryBroker::new();
        let err =
            run_cell(&mut cell, &mut broker, vec![Labeled::public(Value::Int(5))]).unwrap_err();
        assert_eq!(err.code, omc_format::TrapCode::HostError);
    }

    #[test]
    fn unresolved_module_fails_closed() {
        let units = vec![LinkUnit {
            module: caller_module(),
            imports: vec![ImportRef {
                module: "npm:missing@9.9.9".to_owned(),
                function: "inc".to_owned(),
            }],
        }];
        let err = link(units).unwrap_err();
        assert!(err.message.contains("unknown module"));
    }

    #[test]
    fn unexported_function_fails_closed() {
        let units = vec![
            LinkUnit {
                module: caller_module(),
                imports: vec![ImportRef {
                    module: "npm:inc@1.0.0".to_owned(),
                    function: "nope".to_owned(),
                }],
            },
            LinkUnit::leaf(inc_module()),
        ];
        let err = link(units).unwrap_err();
        assert!(err.message.contains("does not export"));
    }

    #[test]
    fn call_import_without_table_slot_fails_closed() {
        // caller emits CallImport(0) but declares no imports.
        let units = vec![LinkUnit::leaf(caller_module())];
        let err = link(units).unwrap_err();
        assert!(err.message.contains("declares only 0 import"));
    }

    #[test]
    fn duplicate_module_id_fails_closed() {
        let units = vec![LinkUnit::leaf(inc_module()), LinkUnit::leaf(inc_module())];
        let err = link(units).unwrap_err();
        assert!(err.message.contains("duplicate module id"));
    }
}
