use std::path::Path;
use std::process::ExitCode;

use omc_registry::OmcRegistryError;

use crate::args::PolicyCommand;

/// Dispatch `omc policy <check|validate>`.
pub(crate) fn run_policy_command(
    project_dir: &Path,
    action: PolicyCommand,
) -> Result<ExitCode, OmcRegistryError> {
    match action {
        PolicyCommand::Validate => {
            match omc_registry::load_policy_document(project_dir)? {
                Some(_) => println!("omc.policy OK"),
                None => println!(
                    "no omc.policy in {} (deny-by-default)",
                    project_dir.display()
                ),
            }
            Ok(ExitCode::SUCCESS)
        }
        PolicyCommand::Check { npm, pypi, package } => {
            // Parse NAME or NAME@VERSION; a leading `@scope/name` keeps its first
            // `@`, so only split on an `@` that is not at index 0.
            let (name, version) = match package
                .char_indices()
                .find(|&(idx, ch)| ch == '@' && idx > 0)
            {
                Some((idx, _)) => (&package[..idx], &package[idx + 1..]),
                None => (package.as_str(), "0.0.0"),
            };
            let ecosystem = match (npm, pypi) {
                (false, true) => omc_policy::Ecosystem::Pypi,
                // npm is the default when neither flag is given.
                _ => omc_policy::Ecosystem::Npm,
            };
            match omc_registry::load_policy_document(project_dir)? {
                Some(document) => {
                    print!("{}", document.explain_for(ecosystem, name, version));
                }
                None => {
                    let eco = match ecosystem {
                        omc_policy::Ecosystem::Npm => "npm",
                        omc_policy::Ecosystem::Pypi => "pypi",
                    };
                    println!(
                        "no omc.policy in {}; {eco}:{name}@{version} gets the deny-by-default policy \
                         (only omc.toml [policy] / CLI grants apply)",
                        project_dir.display()
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
