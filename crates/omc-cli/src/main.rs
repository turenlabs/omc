use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::{env, ffi::OsString, fs};

use clap::{Parser, Subcommand};
use omc_cap::Capability;
use omc_registry::{
    add_manifest_policy_grants, add_package_graph, init_project, install_locked_packages,
    install_locked_project, install_project, parse_capability_grant, read_lockfile,
    read_package_scripts, remove_manifest_dependency, Behavior, LinkOptions, OmcRegistryError,
    PackageSpec, Verdict,
};

#[derive(Debug, Parser)]
#[command(name = "omc")]
#[command(about = "OMC package-manager prototype")]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    project_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Create omc.toml, omc.lock, and .omc/")]
    Init {
        #[arg(long, help = "Project name to write into omc.toml")]
        #[arg(long)]
        name: Option<String>,
    },
    #[command(about = "Resolve, verify, lock, and install a package plus dependencies")]
    Add {
        #[arg(help = "Package spec such as npm:left-pad@1.3.0 or pypi:idna==3.7")]
        spec: String,
        #[arg(long, help = "Save the package as a development dependency")]
        dev: bool,
        #[arg(long, help = "Write blocked packages into omc.lock for review")]
        record_blocked: bool,
        #[arg(
            long = "allow",
            help = "Grant a capability, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(about = "Remove an OMC-managed dependency and reinstall current project inputs")]
    Remove {
        #[arg(help = "Package spec such as npm:left-pad or pypi:idna")]
        spec: String,
        #[arg(
            long = "allow",
            help = "Grant a capability while reinstalling remaining dependencies"
        )]
        allow: Vec<String>,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(about = "Persist capability grants in omc.toml policy")]
    Allow {
        #[arg(help = "Capability grants such as http:api.example.com or env:API_TOKEN")]
        grants: Vec<String>,
    },
    #[command(about = "Resolve omc.toml dependencies and install locked packages")]
    Install {
        #[arg(
            long = "allow",
            help = "Grant a capability, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(
            long = "extra",
            help = "Install a pyproject.toml optional dependency group"
        )]
        extra: Vec<String>,
        #[arg(
            long = "omit-dev",
            alias = "production",
            help = "Skip package.json devDependencies"
        )]
        omit_dev: bool,
        #[arg(long, help = "Install from omc.lock without registry resolution")]
        locked: bool,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(about = "Summarize locked packages and fail if any are blocked")]
    Audit {
        #[arg(long, help = "Emit machine-readable JSON")]
        json: bool,
    },
    #[command(about = "List locked packages without changing install state")]
    List {
        #[arg(long, help = "Emit machine-readable JSON")]
        json: bool,
    },
    #[command(about = "Run node with this project's OMC-installed node_modules")]
    Node {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[command(about = "Run python3 with this project's OMC-installed site-packages")]
    Python {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[command(about = "Run a package.json or Pipfile script with OMC npm/Python bins and imports")]
    Script {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[command(about = "Run a command with OMC npm/Python bins and imports on PATH")]
    Run {
        command: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(OmcRegistryError::BlockedPackage { spec }) => {
            eprintln!("blocked: {spec}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, OmcRegistryError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { name } => {
            let manifest = init_project(&cli.project_dir, name.as_deref())?;
            println!("initialized {}", manifest.display());
        }
        Command::Add {
            spec,
            dev,
            record_blocked,
            allow,
            allow_all_host,
        } => {
            let spec = PackageSpec::parse(&spec)?;
            let mut options = LinkOptions::new(&cli.project_dir);
            options.record_blocked = record_blocked;
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            options.save_dev_dependency = dev;

            match add_package_graph(&spec, &options) {
                Ok(reports) => {
                    print_link_reports(&reports);
                    let install = install_locked_packages(&cli.project_dir)?;
                    println!();
                    println!(
                        "installed npm={} pypi={} npm_bins={} python_scripts={} node_modules={} python_site_packages={}",
                        install.npm_packages,
                        install.pypi_packages,
                        install.npm_bins,
                        install.python_scripts,
                        install.node_modules.display(),
                        install.python_site_packages.display()
                    );
                }
                Err(OmcRegistryError::BlockedPackage { spec }) => {
                    return Err(OmcRegistryError::BlockedPackage { spec });
                }
                Err(error) => return Err(error),
            }
        }
        Command::Remove {
            spec,
            allow,
            allow_all_host,
        } => {
            let spec = PackageSpec::parse(&spec)?;
            if !remove_manifest_dependency(&cli.project_dir, &spec)? {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "dependency `{}` is not in omc.toml",
                    spec.package_key()
                )));
            }

            let mut options = LinkOptions::new(&cli.project_dir);
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            let install = install_project(&options)?;
            println!("removed {}", spec.package_key());
            println!(
                "installed npm={} pypi={} npm_bins={} python_scripts={} node_modules={} python_site_packages={}",
                install.npm_packages,
                install.pypi_packages,
                install.npm_bins,
                install.python_scripts,
                install.node_modules.display(),
                install.python_site_packages.display()
            );
        }
        Command::Allow { grants } => {
            if grants.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "at least one grant is required".to_owned(),
                ));
            }
            let added = add_manifest_policy_grants(&cli.project_dir, &grants)?;
            if added.is_empty() {
                println!("policy unchanged");
            } else {
                for grant in added {
                    println!("allowed {grant}");
                }
            }
        }
        Command::Install {
            allow,
            extra,
            omit_dev,
            locked,
            allow_all_host,
        } => {
            let mut options = LinkOptions::new(&cli.project_dir);
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            options.project_extras = extra
                .into_iter()
                .map(|extra| normalize_extra(&extra))
                .collect();
            options.include_dev_dependencies = !omit_dev;
            let install = if locked {
                install_locked_project(&options)?
            } else {
                install_project(&options)?
            };
            println!(
                "installed npm={} pypi={} npm_bins={} python_scripts={} node_modules={} python_site_packages={}",
                install.npm_packages,
                install.pypi_packages,
                install.npm_bins,
                install.python_scripts,
                install.node_modules.display(),
                install.python_site_packages.display()
            );
        }
        Command::Audit { json } => {
            let lock = read_lockfile(cli.project_dir.join("omc.lock"))?;
            let blocked = lock
                .packages
                .iter()
                .filter(|package| package.verdict == Verdict::Blocked)
                .count();
            if json {
                let audit = serde_json::json!({
                    "packages": lock.packages.len(),
                    "blocked": blocked,
                    "lock": lock,
                });
                println!("{}", serde_json::to_string_pretty(&audit)?);
            } else {
                println!("packages: {}", lock.packages.len());
                println!("blocked: {blocked}");
                for package in lock.packages {
                    println!(
                        "{} {}:{}@{}",
                        verdict_label(package.verdict),
                        package.ecosystem,
                        package.name,
                        package.version
                    );
                }
            }

            if blocked > 0 {
                return Err(OmcRegistryError::BlockedPackage {
                    spec: format!("{blocked} locked package(s)"),
                });
            }
        }
        Command::List { json } => {
            let lock = read_lockfile(cli.project_dir.join("omc.lock"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&lock.packages)?);
            } else if lock.packages.is_empty() {
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
    }

    Ok(ExitCode::SUCCESS)
}

fn run_node(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    let mut command = ProcessCommand::new("node");
    apply_project_runtime_env(&mut command, project_dir)?;
    let status = command.args(args).status()?;
    Ok(exit_code(status.code()))
}

fn run_python(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    let mut command = ProcessCommand::new("python3");
    apply_project_runtime_env(&mut command, project_dir)?;
    let status = command.arg("-S").args(args).status()?;
    Ok(exit_code(status.code()))
}

fn run_package_script(
    project_dir: &Path,
    name: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    let scripts = read_package_scripts(project_dir)?;
    let script = scripts.get(name).ok_or_else(|| {
        let available = scripts.keys().cloned().collect::<Vec<_>>().join(", ");
        let detail = if available.is_empty() {
            format!("missing project script `{name}`")
        } else {
            format!("missing project script `{name}`; available scripts: {available}")
        };
        OmcRegistryError::UnsupportedSpec(detail)
    })?;

    let mut command = package_script_command(script);
    apply_project_runtime_env(&mut command, project_dir)?;
    let status = command.args(args).status()?;
    Ok(exit_code(status.code()))
}

fn run_project_command(
    project_dir: &Path,
    command: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    let mut process = ProcessCommand::new(command);
    apply_project_runtime_env(&mut process, project_dir)?;
    let status = process.args(args).status()?;
    Ok(exit_code(status.code()))
}

fn apply_project_runtime_env(
    command: &mut ProcessCommand,
    project_dir: &Path,
) -> Result<(), OmcRegistryError> {
    command
        .current_dir(project_dir)
        .env("PATH", project_path(project_dir)?)
        .env("PYTHONPATH", project_python_path(project_dir)?)
        .env("PYTHONNOUSERSITE", "1")
        .env_remove("NODE_OPTIONS")
        .env_remove("NODE_PATH");
    for key in [
        "PYTHONBREAKPOINT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONSTARTUP",
    ] {
        command.env_remove(key);
    }
    Ok(())
}

fn project_path(project_dir: &Path) -> Result<OsString, OmcRegistryError> {
    let mut paths = vec![
        project_dir.join("node_modules").join(".bin"),
        project_dir.join(".omc").join("python").join("bin"),
    ];
    if let Some(existing) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing));
    }
    env::join_paths(paths).map_err(|error| OmcRegistryError::UnsupportedSpec(error.to_string()))
}

fn project_python_path(project_dir: &Path) -> Result<OsString, OmcRegistryError> {
    let mut paths = vec![project_dir
        .join(".omc")
        .join("python")
        .join("site-packages")];
    let local_paths_file = project_dir.join(".omc").join("python").join("local-paths");
    if let Ok(content) = fs::read_to_string(local_paths_file) {
        paths.extend(
            content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(PathBuf::from),
        );
    }
    env::join_paths(paths).map_err(|error| OmcRegistryError::UnsupportedSpec(error.to_string()))
}

#[cfg(unix)]
fn package_script_command(script: &str) -> ProcessCommand {
    let mut command = ProcessCommand::new("sh");
    command
        .arg("-c")
        .arg(format!("{script} \"$@\""))
        .arg("omc-script");
    command
}

#[cfg(not(unix))]
fn package_script_command(script: &str) -> ProcessCommand {
    let mut command = ProcessCommand::new("cmd");
    command.arg("/C").arg(script);
    command
}

fn exit_code(code: Option<i32>) -> ExitCode {
    code.and_then(|code| u8::try_from(code).ok())
        .map(ExitCode::from)
        .unwrap_or(ExitCode::FAILURE)
}

fn print_link_reports(reports: &[omc_registry::LinkReport]) {
    for report in reports {
        println!(
            "{} {}:{}@{}",
            verdict_label(report.locked.verdict),
            report.locked.ecosystem,
            report.locked.name,
            report.locked.version
        );
        println!("archive  {}", report.locked.archive);
        println!("artifact {}", report.locked.artifact);
        println!("lockfile {}", report.lockfile.display());

        if !report.artifact.dependencies.is_empty() {
            println!("dependencies: {}", report.artifact.dependencies.join(", "));
        }
        if !report.artifact.optional_dependencies.is_empty() {
            println!(
                "optional dependencies: {}",
                report.artifact.optional_dependencies.join(", ")
            );
        }

        if !report.artifact.capabilities.is_empty() {
            println!("capabilities:");
            for finding in &report.artifact.capabilities {
                println!(
                    "  - {} {} from {} ({})",
                    finding.kind, finding.target, finding.source, finding.evidence
                );
            }
        }

        if !report.artifact.verifier_findings.is_empty() {
            println!("verifier findings:");
            for finding in &report.artifact.verifier_findings {
                println!("  - {finding}");
            }
        }
    }
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accepted => "accepted",
        Verdict::Blocked => "blocked",
    }
}

fn behavior_label(behavior: Behavior) -> &'static str {
    match behavior {
        Behavior::Pure => "pure",
        Behavior::HostCapability => "host-capability",
    }
}

fn parse_grants(
    allow: &[String],
    allow_all_host: bool,
) -> Result<Vec<Capability>, OmcRegistryError> {
    let mut grants = allow
        .iter()
        .map(|grant| parse_capability_grant(grant))
        .collect::<Result<Vec<_>, _>>()?;

    if allow_all_host {
        grants.extend([
            Capability::EnvRead("*".to_owned()),
            Capability::FsRead("*".to_owned()),
            Capability::FsWrite("*".to_owned()),
            Capability::HttpHost("*".to_owned()),
            Capability::DnsHost("*".to_owned()),
            Capability::ProcSpawn("*".to_owned()),
            Capability::DynamicEval,
            Capability::TimeNow,
            Capability::RandomBytes,
        ]);
    }

    Ok(grants)
}

fn normalize_extra(extra: &str) -> String {
    extra.trim().replace('_', "-").to_ascii_lowercase()
}
