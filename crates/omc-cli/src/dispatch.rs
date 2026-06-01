use std::env;
use std::process::ExitCode;

use clap::Parser;

use std::io::{IsTerminal, Write};

use omc_registry::{
    add_manifest_policy_flows, add_manifest_policy_grants, add_package_graph, init_project,
    install_locked_packages, install_locked_project, install_project, parse_capability_grant,
    parse_flow_rule, read_lockfile, write_global_package_trust, LinkOptions, LinkReport,
    OmcRegistryError, PackageSpec,
};

use crate::args::{Cli, Command, CompileCommand};
use crate::compile::print_compile_source;
use crate::direct_compat::{
    direct_compat_mode, npx_compat_args, parse_direct_compat_invocation, DirectCompatMode,
};
use crate::exec_cell::{run_exec_cell, ExecCellCommand};
use crate::install::{install_options, DependencyOmit};
use crate::manifest::{dependency_kind_from_booleans, ecosystem_hint, parse_package_specs};
use crate::npm_compat::{run_npm_compat, run_npm_compat_with_cwd};
use crate::policy::run_policy_command;
use crate::policy_args::{apply_cli_policy_options, CliPolicyArgs};
use crate::render::{
    behavior_label, print_audit_report, print_install_report, print_link_reports, verdict_label,
};
use crate::script::run_package_script;
use crate::shim::{run_node, run_node_in_cwd, run_project_command, run_python, run_python_in_cwd};
use crate::twine_compat::{run_twine_compat, run_twine_compat_with_cwd};
use crate::{remove_specs, run_pip_compat, run_pip_compat_with_cwd};

pub fn omc_main() -> ExitCode {
    match run_entry() {
        Ok(code) => code,
        Err(OmcRegistryError::BlockedPackage { spec, suggestion }) => {
            // Findings + the exact minimal grant go to STDERR (stdout stays clean
            // for piping). This is advisory only; the package is NOT installed and
            // the exit code stays 2 — the deny-by-default contract is unchanged.
            eprintln!("blocked: {spec}");
            if let Some(suggestion) = suggestion {
                eprintln!();
                eprint!("{}", suggestion.guidance);
            }
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

/// Resolve+install one spec, and on an interactive terminal turn a block into a
/// `[y] allow once / [a] allow always / [N] deny` choice:
///   - `y` applies the suggested grants to this run only (not persisted);
///   - `a` writes a per-package, version-pinned block to `~/.omc/policy.d/`
///     (via `omc trust`), so the trust applies everywhere and never leaks to
///     other packages or transitive deps;
///   - anything else (incl. Enter / EOF) denies and keeps the block.
/// Non-interactive (no TTY, e.g. CI) NEVER prompts — it fails closed (the caller
/// surfaces the guidance + exit 2), preserving deny-by-default exactly.
fn add_with_optional_prompt(
    spec: &PackageSpec,
    options: &LinkOptions,
) -> Result<Vec<LinkReport>, OmcRegistryError> {
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let mut options = options.clone();
    loop {
        match add_package_graph(spec, &options) {
            Ok(reports) => return Ok(reports),
            Err(OmcRegistryError::BlockedPackage {
                spec: blocked_spec,
                suggestion: Some(suggestion),
            }) if interactive => {
                eprintln!();
                eprint!("{}", suggestion.guidance);
                eprint!(
                    "\n  Allow {}? [y] once   [a] always (writes ~/.omc/policy.d)   [N] deny: ",
                    suggestion.name
                );
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                let choice = if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
                    None // EOF / read error → deny
                } else {
                    line.trim().to_ascii_lowercase().chars().next()
                };
                match choice {
                    Some('y') => {
                        for grant in &suggestion.allow {
                            options
                                .allowed_capabilities
                                .push(parse_capability_grant(grant)?);
                        }
                        for flow in &suggestion.allow_flow {
                            options.allowed_flows.push(parse_flow_rule(flow)?);
                        }
                        eprintln!("  → allowing {} for this run\n", suggestion.name);
                    }
                    Some('a') => {
                        let path = write_global_package_trust(
                            suggestion.ecosystem,
                            &suggestion.name,
                            &suggestion.version,
                            &suggestion.allow,
                            &suggestion.allow_flow,
                        )?;
                        eprintln!(
                            "  → trusted {} (wrote {})\n",
                            suggestion.name,
                            path.display()
                        );
                    }
                    _ => {
                        eprintln!("  → denied; {} not added", suggestion.name);
                        return Err(OmcRegistryError::BlockedPackage {
                            spec: blocked_spec,
                            suggestion: None,
                        });
                    }
                }
                // loop: retry the resolve with the grant applied (or persisted).
            }
            Err(error) => return Err(error),
        }
    }
}

fn run_entry() -> Result<ExitCode, OmcRegistryError> {
    let mut raw_args = env::args_os();
    let program = raw_args.next();
    if let Some(mode) = direct_compat_mode(program.as_deref()) {
        let invocation = parse_direct_compat_invocation(mode, raw_args)?;
        return match mode {
            DirectCompatMode::Node => {
                run_node_in_cwd(&invocation.project_dir, &invocation.cwd, &invocation.args)
            }
            DirectCompatMode::Npm => {
                run_npm_compat_with_cwd(&invocation.project_dir, &invocation.args, &invocation.cwd)
            }
            DirectCompatMode::Npx => run_npm_compat_with_cwd(
                &invocation.project_dir,
                &npx_compat_args(invocation.args),
                &invocation.cwd,
            ),
            DirectCompatMode::Pip => {
                run_pip_compat_with_cwd(&invocation.project_dir, &invocation.args, &invocation.cwd)
            }
            DirectCompatMode::Python => {
                run_python_in_cwd(&invocation.project_dir, &invocation.cwd, &invocation.args)
            }
            DirectCompatMode::Twine => run_twine_compat_with_cwd(
                &invocation.project_dir,
                &invocation.args,
                &invocation.cwd,
            ),
        };
    }

    run()
}

fn run() -> Result<ExitCode, OmcRegistryError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { name } => {
            let manifest = init_project(&cli.project_dir, name.as_deref())?;
            println!("initialized {}", manifest.display());
        }
        Command::Add {
            npm,
            pypi,
            specs,
            dev,
            optional,
            peer,
            record_blocked,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            let specs = parse_package_specs(&specs, ecosystem_hint(npm, pypi))?;
            let mut options = LinkOptions::new(&cli.project_dir);
            options.record_blocked = record_blocked;
            apply_cli_policy_options(&mut options, &allow, &allow_flow, allow_all_host)?;
            options.save_dependency_kind = dependency_kind_from_booleans(dev, optional, peer);

            let mut all_reports = Vec::new();
            for spec in &specs {
                all_reports.extend(add_with_optional_prompt(spec, &options)?);
            }
            print_link_reports(&all_reports);
            let install = install_locked_packages(&cli.project_dir)?;
            println!();
            print_install_report(&install);
        }
        Command::Compile {
            npm,
            pypi,
            source,
            name,
            version,
            output,
            store,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            print_compile_source(
                &cli.project_dir,
                CompileCommand {
                    npm,
                    pypi,
                    source,
                    name,
                    version,
                    output,
                    store,
                    allow,
                    allow_flow,
                    allow_all_host,
                },
            )?;
        }
        Command::Remove {
            npm,
            pypi,
            specs,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            let _ = remove_specs(
                &cli.project_dir,
                &specs,
                ecosystem_hint(npm, pypi),
                CliPolicyArgs::new(&allow, &allow_flow, allow_all_host),
                true,
                false,
                false,
                true,
                false,
                false,
            )?;
        }
        Command::Allow { flows, grants } => {
            if grants.is_empty() && flows.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "at least one grant is required".to_owned(),
                ));
            }
            let added = add_manifest_policy_grants(&cli.project_dir, &grants)?;
            let added_flows = add_manifest_policy_flows(&cli.project_dir, &flows)?;
            if added.is_empty() && added_flows.is_empty() {
                println!("policy unchanged");
            } else {
                for grant in added {
                    println!("allowed {grant}");
                }
                for flow in added_flows {
                    println!("allowed flow {flow}");
                }
            }
        }
        Command::Trust {
            spec,
            allow,
            allow_flow,
        } => {
            if allow.is_empty() && allow_flow.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "at least one --allow or --allow-flow is required".to_owned(),
                ));
            }
            let parsed = PackageSpec::parse(&spec)?;
            let version = parsed.version.as_deref().ok_or_else(|| {
                OmcRegistryError::UnsupportedSpec(format!(
                    "pin an exact version to trust, e.g. {}:{}@<version>",
                    parsed.ecosystem, parsed.name
                ))
            })?;
            let path = write_global_package_trust(
                parsed.ecosystem,
                &parsed.name,
                version,
                &allow,
                &allow_flow,
            )?;
            println!("trusted {spec}");
            println!("  wrote {}", path.display());
        }
        Command::Install {
            allow,
            allow_flow,
            extra,
            requirements,
            constraints,
            omit_dev,
            omit_optional,
            omit_peer,
            locked,
            allow_all_host,
        } => {
            let options = install_options(
                &cli.project_dir,
                CliPolicyArgs::new(&allow, &allow_flow, allow_all_host),
                extra,
                requirements,
                constraints,
                DependencyOmit {
                    dev: omit_dev,
                    optional: omit_optional,
                    peer: omit_peer,
                },
            )?;
            let install = if locked {
                install_locked_project(&options)?
            } else {
                install_project(&options)?
            };
            print_install_report(&install);
        }
        Command::Ci {
            allow,
            allow_flow,
            extra,
            requirements,
            constraints,
            omit_dev,
            omit_optional,
            omit_peer,
            allow_all_host,
        } => {
            let options = install_options(
                &cli.project_dir,
                CliPolicyArgs::new(&allow, &allow_flow, allow_all_host),
                extra,
                requirements,
                constraints,
                DependencyOmit {
                    dev: omit_dev,
                    optional: omit_optional,
                    peer: omit_peer,
                },
            )?;
            let install = install_locked_project(&options)?;
            print_install_report(&install);
        }
        Command::Audit { json } => return print_audit_report(&cli.project_dir, json),
        Command::List { json } => {
            let lock = read_lockfile(cli.project_dir.join("omc.lock"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "packages": lock.packages,
                        "local_sources": lock.local_sources,
                    }))?
                );
            } else if lock.packages.is_empty() && lock.local_sources.is_empty() {
                println!("packages: 0");
            } else {
                for package in lock.packages {
                    println!(
                        "{}:{}@{} {} {}",
                        package.ecosystem,
                        package.name,
                        package.version,
                        verdict_label(package.verdict),
                        behavior_label(package.behavior)
                    );
                }
                for source in lock.local_sources {
                    println!(
                        "local-source {}:{}@{} {} {} {}",
                        source.ecosystem,
                        source.name,
                        source.version,
                        verdict_label(source.verdict),
                        behavior_label(source.behavior),
                        source.source_path
                    );
                }
            }
        }
        Command::Node { args } => return run_node(&cli.project_dir, &args),
        Command::Python { args } => return run_python(&cli.project_dir, &args),
        Command::Script { name, args } => {
            return run_package_script(&cli.project_dir, &name, &args)
        }
        Command::Run { command, args } => {
            return run_project_command(&cli.project_dir, &command, &args)
        }
        Command::Npm { args } => return run_npm_compat(&cli.project_dir, &args),
        Command::Pip { args } => return run_pip_compat(&cli.project_dir, &args),
        Command::Twine { args } => return run_twine_compat(&cli.project_dir, &args),
        Command::ExecCell {
            source,
            name,
            version,
            args,
            allow,
            allow_flow,
            allow_all_host,
            allow_sensitive,
            fallback,
        } => {
            return run_exec_cell(
                &cli.project_dir,
                ExecCellCommand {
                    source,
                    name,
                    version,
                    args,
                    allow,
                    allow_flow,
                    allow_all_host,
                    allow_sensitive,
                    fallback,
                },
            )
        }
        Command::Policy { action } => return run_policy_command(&cli.project_dir, action),
    }

    Ok(ExitCode::SUCCESS)
}
