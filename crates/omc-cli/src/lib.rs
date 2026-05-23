use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::{env, ffi::OsString, fs};

use clap::{Parser, Subcommand};
use omc_cap::Capability;
use omc_registry::{
    add_manifest_npm_local_paths, add_manifest_policy_grants, add_package_graph,
    apply_pypi_binary_option, check_pypi_lock, init_project, install_locked_packages,
    install_locked_project, install_project, lock_project, parse_capability_grant,
    parse_npm_direct_archive_reference, parse_pypi_direct_archive_reference, read_lockfile,
    read_package_scripts, read_requirements_files, remove_manifest_dependency, Behavior, Ecosystem,
    InstallReport, LinkOptions, LockedPackage, OmcRegistryError, PackageSpec, PypiBinaryMode,
    PypiCheckIssue, PythonLocalRequirement, Verdict,
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
        #[arg(
            long,
            conflicts_with = "pypi",
            help = "Treat unprefixed specs as npm specs"
        )]
        npm: bool,
        #[arg(
            long,
            conflicts_with = "npm",
            help = "Treat unprefixed specs as PyPI specs"
        )]
        pypi: bool,
        #[arg(
            required = true,
            num_args = 1..,
            help = "Package specs such as npm:left-pad@1.3.0, pypi:idna==3.7, or unprefixed specs with --npm/--pypi"
        )]
        specs: Vec<String>,
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
    #[command(about = "Remove an OMC-managed dependency and reinstall remaining manifest inputs")]
    Remove {
        #[arg(
            long,
            conflicts_with = "pypi",
            help = "Treat unprefixed specs as npm specs"
        )]
        npm: bool,
        #[arg(
            long,
            conflicts_with = "npm",
            help = "Treat unprefixed specs as PyPI specs"
        )]
        pypi: bool,
        #[arg(
            required = true,
            num_args = 1..,
            help = "Package specs such as npm:left-pad, pypi:idna, or unprefixed specs with --npm/--pypi"
        )]
        specs: Vec<String>,
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
            short = 'r',
            long = "requirement",
            value_name = "PATH",
            help = "Read an additional requirements file"
        )]
        requirements: Vec<PathBuf>,
        #[arg(
            short = 'c',
            long = "constraint",
            value_name = "PATH",
            help = "Read an additional pip-style constraints file"
        )]
        constraints: Vec<PathBuf>,
        #[arg(
            long = "omit-dev",
            alias = "production",
            help = "Skip dev dependency inputs across npm and Python project files"
        )]
        omit_dev: bool,
        #[arg(long, help = "Install from omc.lock without registry resolution")]
        locked: bool,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(about = "Install from omc.lock without registry resolution")]
    Ci {
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
            short = 'r',
            long = "requirement",
            value_name = "PATH",
            help = "Read an additional requirements file"
        )]
        requirements: Vec<PathBuf>,
        #[arg(
            short = 'c',
            long = "constraint",
            value_name = "PATH",
            help = "Read an additional pip-style constraints file"
        )]
        constraints: Vec<PathBuf>,
        #[arg(
            long = "omit-dev",
            alias = "production",
            help = "Skip dev dependency inputs across npm and Python project files"
        )]
        omit_dev: bool,
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
    #[command(about = "Run common npm-compatible commands through OMC")]
    Npm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[command(about = "Run common pip-compatible commands through OMC")]
    Pip {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum NpmCompatAction {
    Version,
    Install {
        specs: Vec<String>,
        archive_references: Vec<String>,
        local_paths: Vec<PathBuf>,
        save: bool,
        dev: bool,
        omit_dev: bool,
        lock_only: bool,
        npm_registry: Option<String>,
        allow: Vec<String>,
        allow_all_host: bool,
    },
    Ci {
        omit_dev: bool,
        allow: Vec<String>,
        allow_all_host: bool,
    },
    Remove {
        specs: Vec<String>,
        allow: Vec<String>,
        allow_all_host: bool,
    },
    RunScript {
        command: String,
        name: String,
        args: Vec<String>,
        if_present: bool,
    },
    Exec {
        command: String,
        args: Vec<String>,
    },
    Path {
        kind: NpmPathKind,
    },
    List {
        json: bool,
    },
    Audit {
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmPathKind {
    Bin,
    Root,
    Prefix,
}

#[derive(Debug, PartialEq, Eq)]
enum PipCompatAction {
    Version,
    Install(Box<PipInstallAction>),
    Uninstall {
        specs: Vec<String>,
        requirements: Vec<PathBuf>,
        allow: Vec<String>,
        allow_all_host: bool,
    },
    Show {
        specs: Vec<String>,
        files: bool,
    },
    Check,
    Freeze,
    List {
        format: PipListFormat,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct PipInstallAction {
    specs: Vec<String>,
    requirements: Vec<PathBuf>,
    constraints: Vec<PathBuf>,
    archive_references: Vec<String>,
    local_paths: Vec<PythonLocalRequirement>,
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    binary_all: Option<PypiBinaryMode>,
    binary_packages: BTreeMap<String, PypiBinaryMode>,
    require_hashes: bool,
    no_deps: bool,
    target: Option<PathBuf>,
    allow: Vec<String>,
    allow_all_host: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipListFormat {
    Columns,
    Freeze,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectCompatMode {
    Node,
    Npm,
    Npx,
    Pip,
    Python,
}

#[derive(Debug, PartialEq, Eq)]
struct DirectCompatInvocation {
    project_dir: PathBuf,
    args: Vec<String>,
}

pub fn omc_main() -> ExitCode {
    match run_entry() {
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

fn run_entry() -> Result<ExitCode, OmcRegistryError> {
    let mut raw_args = env::args_os();
    let program = raw_args.next();
    if let Some(mode) = direct_compat_mode(program.as_deref()) {
        let invocation = parse_direct_compat_invocation(mode, raw_args)?;
        return match mode {
            DirectCompatMode::Node => run_node(&invocation.project_dir, &invocation.args),
            DirectCompatMode::Npm => run_npm_compat(&invocation.project_dir, &invocation.args),
            DirectCompatMode::Npx => {
                run_npm_compat(&invocation.project_dir, &npx_compat_args(invocation.args))
            }
            DirectCompatMode::Pip => run_pip_compat(&invocation.project_dir, &invocation.args),
            DirectCompatMode::Python => run_python(&invocation.project_dir, &invocation.args),
        };
    }

    run()
}

fn direct_compat_mode(program: Option<&std::ffi::OsStr>) -> Option<DirectCompatMode> {
    let name = Path::new(program?)
        .file_stem()
        .and_then(|name| name.to_str())?;
    match name {
        "node" => Some(DirectCompatMode::Node),
        "npm" => Some(DirectCompatMode::Npm),
        "npx" => Some(DirectCompatMode::Npx),
        "pip" | "pip3" => Some(DirectCompatMode::Pip),
        "python" | "python3" => Some(DirectCompatMode::Python),
        _ => None,
    }
}

fn npx_compat_args(args: Vec<String>) -> Vec<String> {
    let mut compat_args = Vec::with_capacity(args.len() + 1);
    compat_args.push("exec".to_owned());
    compat_args.extend(args);
    compat_args
}

fn parse_direct_compat_invocation<I>(
    mode: DirectCompatMode,
    args: I,
) -> Result<DirectCompatInvocation, OmcRegistryError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut project_dir = env::var_os("OMC_PROJECT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut compat_args = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = os_arg_to_string(arg)?;
        if arg == "--omc-project-dir"
            || arg == "--project-dir"
            || (direct_compat_uses_npm_prefix(mode) && arg == "--prefix")
        {
            let Some(path) = args.next() else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            project_dir = PathBuf::from(os_arg_to_string(path)?);
        } else if let Some(path) = arg.strip_prefix("--omc-project-dir=") {
            project_dir = PathBuf::from(path);
        } else if let Some(path) = arg.strip_prefix("--project-dir=") {
            project_dir = PathBuf::from(path);
        } else if let Some(path) = direct_compat_uses_npm_prefix(mode)
            .then(|| arg.strip_prefix("--prefix="))
            .flatten()
        {
            project_dir = PathBuf::from(path);
        } else {
            compat_args.push(arg);
            compat_args.extend(
                args.map(os_arg_to_string)
                    .collect::<Result<Vec<_>, OmcRegistryError>>()?,
            );
            break;
        }
    }
    Ok(DirectCompatInvocation {
        project_dir,
        args: compat_args,
    })
}

fn direct_compat_uses_npm_prefix(mode: DirectCompatMode) -> bool {
    matches!(mode, DirectCompatMode::Npm | DirectCompatMode::Npx)
}

fn os_arg_to_string(arg: OsString) -> Result<String, OmcRegistryError> {
    arg.into_string().map_err(|arg| {
        OmcRegistryError::UnsupportedSpec(format!(
            "argument is not valid UTF-8: {}",
            arg.to_string_lossy()
        ))
    })
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
            record_blocked,
            allow,
            allow_all_host,
        } => {
            let specs = parse_package_specs(&specs, ecosystem_hint(npm, pypi))?;
            let mut options = LinkOptions::new(&cli.project_dir);
            options.record_blocked = record_blocked;
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            options.save_dev_dependency = dev;

            let mut all_reports = Vec::new();
            for spec in &specs {
                match add_package_graph(spec, &options) {
                    Ok(reports) => all_reports.extend(reports),
                    Err(OmcRegistryError::BlockedPackage { spec }) => {
                        return Err(OmcRegistryError::BlockedPackage { spec });
                    }
                    Err(error) => return Err(error),
                }
            }
            print_link_reports(&all_reports);
            let install = install_locked_packages(&cli.project_dir)?;
            println!();
            print_install_report(&install);
        }
        Command::Remove {
            npm,
            pypi,
            specs,
            allow,
            allow_all_host,
        } => {
            let specs = parse_package_specs(&specs, ecosystem_hint(npm, pypi))?;
            let mut removed = Vec::new();
            for spec in &specs {
                if !remove_manifest_dependency(&cli.project_dir, spec)? {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "dependency `{}` is not in omc.toml",
                        spec.package_key()
                    )));
                }
                removed.push(spec.package_key());
            }

            let mut options = LinkOptions::new(&cli.project_dir);
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            let install = install_project(&options)?;
            println!("removed {}", removed.join(", "));
            print_install_report(&install);
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
            requirements,
            constraints,
            omit_dev,
            locked,
            allow_all_host,
        } => {
            let options = install_options(
                &cli.project_dir,
                &allow,
                extra,
                requirements,
                constraints,
                omit_dev,
                allow_all_host,
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
            extra,
            requirements,
            constraints,
            omit_dev,
            allow_all_host,
        } => {
            let options = install_options(
                &cli.project_dir,
                &allow,
                extra,
                requirements,
                constraints,
                omit_dev,
                allow_all_host,
            )?;
            let install = install_locked_project(&options)?;
            print_install_report(&install);
        }
        Command::Audit { json } => return print_audit_report(&cli.project_dir, json),
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
        Command::Npm { args } => return run_npm_compat(&cli.project_dir, &args),
        Command::Pip { args } => return run_pip_compat(&cli.project_dir, &args),
    }

    Ok(ExitCode::SUCCESS)
}

fn install_options(
    project_dir: &Path,
    allow: &[String],
    extra: Vec<String>,
    requirements: Vec<PathBuf>,
    constraints: Vec<PathBuf>,
    omit_dev: bool,
    allow_all_host: bool,
) -> Result<LinkOptions, OmcRegistryError> {
    let mut options = LinkOptions::new(project_dir);
    options.allowed_capabilities = parse_grants(allow, allow_all_host)?;
    options.project_extras = extra
        .into_iter()
        .map(|extra| normalize_extra(&extra))
        .collect();
    options.requirement_files = requirements
        .into_iter()
        .map(|path| absolutize_path(project_dir, path))
        .collect();
    options.constraint_files = constraints
        .into_iter()
        .map(|path| absolutize_path(project_dir, path))
        .collect();
    options.include_dev_dependencies = !omit_dev;
    Ok(options)
}

fn print_install_report(install: &InstallReport) {
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

fn run_node(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    let mut command = ProcessCommand::new(host_node_program()?);
    apply_project_runtime_env(&mut command, project_dir)?;
    let status = command.args(args).status()?;
    Ok(exit_code(status.code()))
}

fn host_node_program() -> Result<PathBuf, OmcRegistryError> {
    host_program("OMC_HOST_NODE", &["node"], "host node")
}

fn run_python(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    if let Some(pip_args) = python_pip_module_args(args) {
        return run_pip_compat(project_dir, pip_args);
    }

    let mut command = ProcessCommand::new(host_python_program()?);
    apply_project_runtime_env(&mut command, project_dir)?;
    let status = command.arg("-S").args(args).status()?;
    Ok(exit_code(status.code()))
}

fn host_python_program() -> Result<PathBuf, OmcRegistryError> {
    host_program("OMC_HOST_PYTHON", &["python3", "python"], "host python3")
}

fn host_program(
    override_var: &str,
    programs: &[&str],
    description: &str,
) -> Result<PathBuf, OmcRegistryError> {
    if let Some(path) = env::var_os(override_var) {
        return Ok(PathBuf::from(path));
    }

    programs
        .iter()
        .find_map(|program| find_program_outside_current_exe_dir(program))
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "could not find a {description} outside the OMC shim directory; set {override_var}"
            ))
        })
}

fn python_pip_module_args(args: &[String]) -> Option<&[String]> {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "-m" {
            let module = args.get(index + 1)?;
            return is_pip_module(module).then_some(&args[index + 2..]);
        }
        if let Some(module) = arg.strip_prefix("-m") {
            if !module.is_empty() {
                return is_pip_module(module).then_some(&args[index + 1..]);
            }
        }

        match arg {
            "-S" | "-s" | "-E" | "-I" | "-B" | "-u" | "-q" | "-O" | "-OO" => index += 1,
            "-W" | "-X" => index += 2,
            _ if arg.starts_with("-W") || arg.starts_with("-X") => index += 1,
            _ => return None,
        }
    }
    None
}

fn is_pip_module(module: &str) -> bool {
    matches!(module, "pip" | "pip3" | "pip.__main__")
}

fn run_package_script(
    project_dir: &Path,
    name: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    run_package_script_with_npm_command(project_dir, "run-script", name, args, false)
}

fn run_package_script_with_npm_command(
    project_dir: &Path,
    npm_command: &str,
    name: &str,
    args: &[String],
    if_present: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let scripts = read_package_scripts(project_dir)?;
    if if_present && !scripts.contains_key(name) {
        return Ok(ExitCode::SUCCESS);
    }
    let lifecycle = package_script_lifecycle_order(&scripts, name)?;

    for lifecycle_name in lifecycle {
        let script = scripts.get(&lifecycle_name).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("missing project script `{lifecycle_name}`"))
        })?;
        let script_args = if lifecycle_name == name {
            args
        } else {
            &[] as &[String]
        };
        let status = run_single_package_script(
            project_dir,
            npm_command,
            &lifecycle_name,
            script,
            script_args,
        )?;
        if status != ExitCode::SUCCESS {
            return Ok(status);
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn package_script_lifecycle_order(
    scripts: &BTreeMap<String, String>,
    name: &str,
) -> Result<Vec<String>, OmcRegistryError> {
    if !scripts.contains_key(name) {
        let available = scripts.keys().cloned().collect::<Vec<_>>().join(", ");
        let detail = if available.is_empty() {
            format!("missing project script `{name}`")
        } else {
            format!("missing project script `{name}`; available scripts: {available}")
        };
        return Err(OmcRegistryError::UnsupportedSpec(detail));
    }

    let mut lifecycle = Vec::new();
    let pre = format!("pre{name}");
    if scripts.contains_key(&pre) {
        lifecycle.push(pre);
    }
    lifecycle.push(name.to_owned());
    let post = format!("post{name}");
    if scripts.contains_key(&post) {
        lifecycle.push(post);
    }
    Ok(lifecycle)
}

fn run_single_package_script(
    project_dir: &Path,
    npm_command: &str,
    name: &str,
    script: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    let mut command = package_script_command(script);
    apply_project_runtime_env(&mut command, project_dir)?;
    apply_npm_lifecycle_env(&mut command, project_dir, npm_command, name, script)?;
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

fn run_npm_compat(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    match parse_npm_compat_action(args)? {
        NpmCompatAction::Version => println!("{}", env!("CARGO_PKG_VERSION")),
        NpmCompatAction::Install {
            specs,
            archive_references,
            local_paths,
            save,
            dev,
            omit_dev,
            lock_only,
            npm_registry,
            allow,
            allow_all_host,
        } => {
            let allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            if specs.is_empty() && archive_references.is_empty() {
                let mut options = LinkOptions::new(project_dir);
                options.allowed_capabilities = allowed_capabilities;
                options.npm_registry_url = npm_registry.clone();
                options.include_dev_dependencies = !omit_dev;
                options.npm_local_paths = absolutize_paths(project_dir, local_paths.clone());
                if save && !local_paths.is_empty() {
                    add_manifest_npm_local_paths(project_dir, &local_paths, dev)?;
                }
                if lock_only {
                    let reports = lock_project(&options)?;
                    print_link_reports(&reports);
                    print_lock_only_report(project_dir);
                } else {
                    let install = install_project(&options)?;
                    print_install_report(&install);
                }
            } else {
                let mut options = LinkOptions::new(project_dir);
                options.allowed_capabilities = allowed_capabilities;
                options.npm_registry_url = npm_registry.clone();
                options.save_manifest_dependency = save;
                options.save_dev_dependency = dev;
                options.include_dev_dependencies = !omit_dev;
                options.npm_local_paths = absolutize_paths(project_dir, local_paths.clone());
                if save && !local_paths.is_empty() {
                    add_manifest_npm_local_paths(project_dir, &local_paths, dev)?;
                }
                let mut specs = parse_package_specs(&specs, Some(Ecosystem::Npm))?;
                specs.extend(parse_npm_archive_references(
                    project_dir,
                    &archive_references,
                )?);
                let mut all_reports = Vec::new();
                for spec in &specs {
                    all_reports.extend(add_package_graph(spec, &options)?);
                }
                print_link_reports(&all_reports);
                if lock_only {
                    print_lock_only_report(project_dir);
                    return Ok(ExitCode::SUCCESS);
                }
                let install = if options.npm_local_paths.is_empty() {
                    install_locked_packages(project_dir)?
                } else {
                    install_project(&options)?
                };
                println!();
                print_install_report(&install);
            }
        }
        NpmCompatAction::Ci {
            omit_dev,
            allow,
            allow_all_host,
        } => {
            let mut options = LinkOptions::new(project_dir);
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            options.include_dev_dependencies = !omit_dev;
            let install = install_locked_project(&options)?;
            print_install_report(&install);
        }
        NpmCompatAction::Remove {
            specs,
            allow,
            allow_all_host,
        } => {
            remove_specs(
                project_dir,
                &specs,
                Some(Ecosystem::Npm),
                &allow,
                allow_all_host,
            )?;
        }
        NpmCompatAction::RunScript {
            command,
            name,
            args,
            if_present,
        } => {
            return run_package_script_with_npm_command(
                project_dir,
                &command,
                &name,
                &args,
                if_present,
            )
        }
        NpmCompatAction::Exec { command, args } => {
            return run_project_command(project_dir, &command, &args)
        }
        NpmCompatAction::Path { kind } => print_npm_path(project_dir, kind)?,
        NpmCompatAction::List { json } => {
            print_locked_packages(project_dir, Some(Ecosystem::Npm), json)?
        }
        NpmCompatAction::Audit { json } => return print_audit_report(project_dir, json),
    }

    Ok(ExitCode::SUCCESS)
}

fn run_pip_compat(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    match parse_pip_compat_action(args)? {
        PipCompatAction::Version => println!("pip {} from OMC", env!("CARGO_PKG_VERSION")),
        PipCompatAction::Install(action) => {
            let PipInstallAction {
                specs,
                requirements,
                constraints,
                archive_references,
                local_paths,
                index_url,
                extra_index_urls,
                find_links,
                no_index,
                binary_all,
                binary_packages,
                require_hashes,
                no_deps,
                target,
                allow,
                allow_all_host,
            } = *action;
            let allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            if specs.is_empty() && archive_references.is_empty() {
                let mut options = LinkOptions::new(project_dir);
                options.allowed_capabilities = allowed_capabilities;
                options.requirement_files = absolutize_paths(project_dir, requirements);
                options.constraint_files = absolutize_paths(project_dir, constraints);
                options.python_local_requirements =
                    absolutize_python_local_requirements(project_dir, local_paths);
                apply_pip_compat_index_options(
                    &mut options,
                    index_url,
                    extra_index_urls,
                    find_links,
                    no_index,
                );
                options.pypi_require_hashes = require_hashes;
                options.pypi_include_dependencies = !no_deps;
                options.pypi_binary_all = binary_all;
                options.pypi_binary_packages = binary_packages;
                options.python_target_dir = target.map(|path| absolutize_path(project_dir, path));
                let install = install_project(&options)?;
                print_install_report(&install);
            } else {
                let mut options = LinkOptions::new(project_dir);
                options.allowed_capabilities = allowed_capabilities;
                options.requirement_files = absolutize_paths(project_dir, requirements);
                options.constraint_files = absolutize_paths(project_dir, constraints);
                options.python_local_requirements =
                    absolutize_python_local_requirements(project_dir, local_paths);
                apply_pip_compat_index_options(
                    &mut options,
                    index_url,
                    extra_index_urls,
                    find_links,
                    no_index,
                );
                options.pypi_require_hashes = require_hashes;
                options.pypi_include_dependencies = !no_deps;
                options.pypi_binary_all = binary_all;
                options.pypi_binary_packages = binary_packages;
                options.python_target_dir = target.map(|path| absolutize_path(project_dir, path));
                let mut specs = parse_package_specs(&specs, Some(Ecosystem::Pypi))?;
                specs.extend(parse_pip_archive_references(
                    project_dir,
                    &archive_references,
                    &mut options,
                )?);
                let mut all_reports = Vec::new();
                for spec in &specs {
                    all_reports.extend(add_package_graph(spec, &options)?);
                }
                print_link_reports(&all_reports);
                let install = if options.requirement_files.is_empty()
                    && options.constraint_files.is_empty()
                    && options.python_local_paths.is_empty()
                    && options.python_local_requirements.is_empty()
                    && options.python_target_dir.is_none()
                    && options.pypi_include_dependencies
                {
                    install_locked_packages(project_dir)?
                } else if options.requirement_files.is_empty()
                    && options.constraint_files.is_empty()
                    && options.python_local_paths.is_empty()
                    && options.python_local_requirements.is_empty()
                {
                    install_locked_project(&options)?
                } else {
                    install_project(&options)?
                };
                println!();
                print_install_report(&install);
            }
        }
        PipCompatAction::Uninstall {
            mut specs,
            requirements,
            allow,
            allow_all_host,
        } => {
            specs.extend(pip_uninstall_specs_from_requirements(
                project_dir,
                requirements,
            )?);
            remove_specs(
                project_dir,
                &specs,
                Some(Ecosystem::Pypi),
                &allow,
                allow_all_host,
            )?;
        }
        PipCompatAction::Show { specs, files } => {
            return print_locked_pip_show(project_dir, &specs, files)
        }
        PipCompatAction::Check => return print_locked_pip_check(project_dir),
        PipCompatAction::Freeze => print_locked_freeze(project_dir)?,
        PipCompatAction::List { format } => match format {
            PipListFormat::Columns => {
                print_locked_packages(project_dir, Some(Ecosystem::Pypi), false)?
            }
            PipListFormat::Freeze => print_locked_freeze(project_dir)?,
            PipListFormat::Json => print_locked_pip_json(project_dir)?,
        },
    }

    Ok(ExitCode::SUCCESS)
}

fn print_npm_path(project_dir: &Path, kind: NpmPathKind) -> Result<(), OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let path = match kind {
        NpmPathKind::Bin => project_dir.join("node_modules").join(".bin"),
        NpmPathKind::Root => project_dir.join("node_modules"),
        NpmPathKind::Prefix => project_dir,
    };
    println!("{}", path.display());
    Ok(())
}

fn print_audit_report(project_dir: &Path, json: bool) -> Result<ExitCode, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
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

    Ok(ExitCode::SUCCESS)
}

fn print_lock_only_report(project_dir: &Path) {
    println!("lockfile {}", project_dir.join("omc.lock").display());
}

fn remove_specs(
    project_dir: &Path,
    specs: &[String],
    ecosystem_hint: Option<Ecosystem>,
    allow: &[String],
    allow_all_host: bool,
) -> Result<(), OmcRegistryError> {
    let specs = parse_package_specs(specs, ecosystem_hint)?;
    let mut removed = Vec::new();
    for spec in &specs {
        if !remove_manifest_dependency(project_dir, spec)? {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "dependency `{}` is not in omc.toml",
                spec.package_key()
            )));
        }
        removed.push(spec.package_key());
    }

    let mut options = LinkOptions::new(project_dir);
    options.allowed_capabilities = parse_grants(allow, allow_all_host)?;
    options.discover_project_requirements = false;
    let install = install_project(&options)?;
    println!("removed {}", removed.join(", "));
    print_install_report(&install);
    Ok(())
}

fn parse_pip_archive_references(
    project_dir: &Path,
    references: &[String],
    options: &mut LinkOptions,
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    let mut specs = Vec::new();
    for reference in references {
        let Some((spec, hashes)) = parse_pypi_direct_archive_reference(reference, project_dir)?
        else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported direct PyPI archive `{reference}`"
            )));
        };
        if !hashes.is_empty() {
            options
                .hashes
                .entry(spec.package_key())
                .or_default()
                .extend(hashes);
        }
        specs.push(spec);
    }
    Ok(specs)
}

fn parse_npm_archive_references(
    project_dir: &Path,
    references: &[String],
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    let mut specs = Vec::new();
    for reference in references {
        let Some(spec) = parse_npm_direct_archive_reference(reference, project_dir)? else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported direct npm archive `{reference}`"
            )));
        };
        specs.push(spec);
    }
    Ok(specs)
}

fn print_locked_packages(
    project_dir: &Path,
    ecosystem: Option<Ecosystem>,
    json: bool,
) -> Result<(), OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let packages = lock
        .packages
        .into_iter()
        .filter(|package| {
            ecosystem
                .map(|ecosystem| package.ecosystem == ecosystem)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    if json {
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else if packages.is_empty() {
        println!("packages: 0");
    } else {
        for package in packages {
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
    Ok(())
}

fn print_locked_freeze(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    for package in lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
    {
        println!("{}=={}", package.name, package.version);
    }
    Ok(())
}

fn print_locked_pip_json(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let packages = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .map(|package| {
            serde_json::json!({
                "name": package.name,
                "version": package.version,
            })
        })
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&packages)?);
    Ok(())
}

fn print_locked_pip_show(
    project_dir: &Path,
    specs: &[String],
    include_files: bool,
) -> Result<ExitCode, OmcRegistryError> {
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip show needs at least one package".to_owned(),
        ));
    }

    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let packages = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .collect::<Vec<_>>();
    let mut missing = Vec::new();
    let mut printed = false;
    for spec in specs {
        let normalized = normalize_pip_show_name(spec);
        let Some(package) = packages
            .iter()
            .find(|package| normalize_pip_show_name(&package.name) == normalized)
        else {
            missing.push(spec.clone());
            continue;
        };
        if printed {
            println!("---");
        }
        print_pip_show_package(project_dir, package, &packages, include_files)?;
        printed = true;
    }

    if !missing.is_empty() {
        eprintln!("WARNING: Package(s) not found: {}", missing.join(", "));
        return Ok(ExitCode::FAILURE);
    }

    Ok(ExitCode::SUCCESS)
}

fn print_locked_pip_check(project_dir: &Path) -> Result<ExitCode, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let issues = check_pypi_lock(&lock);
    if issues.is_empty() {
        println!("No broken requirements found.");
        return Ok(ExitCode::SUCCESS);
    }

    for issue in issues {
        match issue {
            PypiCheckIssue::Missing {
                package,
                version,
                requirement,
            } => {
                println!("{package} {version} requires {requirement}, which is not installed.");
            }
            PypiCheckIssue::Incompatible {
                package,
                version,
                requirement,
                installed_name,
                installed_version,
            } => {
                println!(
                    "{package} {version} has requirement {requirement}, but you have {installed_name} {installed_version}."
                );
            }
        }
    }
    Ok(ExitCode::FAILURE)
}

fn print_pip_show_package(
    project_dir: &Path,
    package: &LockedPackage,
    packages: &[LockedPackage],
    include_files: bool,
) -> Result<(), OmcRegistryError> {
    let site_packages = absolute_project_dir(project_dir)
        .join(".omc")
        .join("python")
        .join("site-packages");
    println!("Name: {}", package.name);
    println!("Version: {}", package.version);
    println!("Summary:");
    println!("Home-page: {}", package.source_url);
    println!("Author:");
    println!("Author-email:");
    println!("License:");
    println!("Location: {}", site_packages.display());
    println!("Requires: {}", pip_dependency_names(package).join(", "));
    println!(
        "Required-by: {}",
        pip_required_by_names(package, packages).join(", ")
    );
    if include_files {
        println!("Files:");
        for file in pip_installed_files(&site_packages, package)? {
            println!("  {file}");
        }
    }
    Ok(())
}

fn pip_dependency_names(package: &LockedPackage) -> Vec<String> {
    package
        .dependencies
        .iter()
        .filter_map(|dependency| pip_dependency_name(dependency))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn pip_required_by_names(package: &LockedPackage, packages: &[LockedPackage]) -> Vec<String> {
    let target = normalize_pip_show_name(&package.name);
    packages
        .iter()
        .filter(|candidate| candidate.name != package.name)
        .filter(|candidate| {
            candidate
                .dependencies
                .iter()
                .filter_map(|dependency| pip_dependency_name(dependency))
                .any(|name| normalize_pip_show_name(&name) == target)
        })
        .map(|candidate| candidate.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn pip_dependency_name(dependency: &str) -> Option<String> {
    PackageSpec::parse(dependency)
        .ok()
        .filter(|spec| spec.ecosystem == Ecosystem::Pypi)
        .map(|spec| spec.name)
}

fn pip_installed_files(
    site_packages: &Path,
    package: &LockedPackage,
) -> Result<Vec<String>, OmcRegistryError> {
    let Some(dist_info) = match_dist_info_dir(site_packages, package)? else {
        return Ok(Vec::new());
    };
    let record = dist_info.join("RECORD");
    if !record.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for line in fs::read_to_string(record)?.lines() {
        if let Some((file, _)) = line.split_once(',') {
            if !file.is_empty() {
                files.push(file.to_owned());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn match_dist_info_dir(
    site_packages: &Path,
    package: &LockedPackage,
) -> Result<Option<PathBuf>, OmcRegistryError> {
    if !site_packages.exists() {
        return Ok(None);
    }
    let prefix = format!(
        "{}-{}",
        normalize_pip_show_name(&package.name),
        normalize_pip_show_name(&package.version)
    );
    for entry in fs::read_dir(site_packages)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.ends_with(".dist-info") && normalize_pip_show_name(&name).starts_with(&prefix) {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn normalize_pip_show_name(name: &str) -> String {
    let name = name
        .strip_prefix("pypi:")
        .or_else(|| name.strip_prefix("py:"))
        .or_else(|| name.strip_prefix("python:"))
        .unwrap_or(name);
    let name = name.split_once('[').map(|(name, _)| name).unwrap_or(name);
    name.chars()
        .map(|ch| match ch {
            '_' | '.' => '-',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

fn absolutize_paths(project_dir: &Path, paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .map(|path| absolutize_path(project_dir, path))
        .collect()
}

fn absolutize_python_local_requirements(
    project_dir: &Path,
    requirements: Vec<PythonLocalRequirement>,
) -> Vec<PythonLocalRequirement> {
    requirements
        .into_iter()
        .map(|requirement| {
            PythonLocalRequirement::new(
                absolutize_path(project_dir, requirement.path),
                requirement.extras,
            )
        })
        .collect()
}

fn absolutize_path(project_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        project_dir.join(path)
    }
}

fn absolute_project_dir(project_dir: &Path) -> PathBuf {
    if let Ok(path) = fs::canonicalize(project_dir) {
        return path;
    }
    if project_dir.is_absolute() {
        return project_dir.to_path_buf();
    }
    env::current_dir()
        .map(|cwd| cwd.join(project_dir))
        .unwrap_or_else(|_| project_dir.to_path_buf())
}

fn apply_pip_compat_index_options(
    options: &mut LinkOptions,
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
) {
    if index_url.is_some() {
        options.pypi_index_url = index_url;
    }
    options.pypi_extra_index_urls.extend(extra_index_urls);
    options.pypi_find_links.extend(find_links);
    options.pypi_no_index |= no_index;
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

fn apply_npm_lifecycle_env(
    command: &mut ProcessCommand,
    project_dir: &Path,
    npm_command: &str,
    script_name: &str,
    script: &str,
) -> Result<(), OmcRegistryError> {
    for (key, value) in npm_lifecycle_env(project_dir, npm_command, script_name, script)? {
        command.env(key, value);
    }
    Ok(())
}

fn npm_lifecycle_env(
    project_dir: &Path,
    npm_command: &str,
    script_name: &str,
    script: &str,
) -> Result<BTreeMap<String, String>, OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let init_cwd = env::current_dir().unwrap_or_else(|_| project_dir.clone());
    let mut vars = BTreeMap::from([
        (
            "INIT_CWD".to_owned(),
            init_cwd.to_string_lossy().into_owned(),
        ),
        ("npm_command".to_owned(), npm_command.to_owned()),
        (
            "npm_config_local_prefix".to_owned(),
            project_dir.to_string_lossy().into_owned(),
        ),
        (
            "npm_config_npm_version".to_owned(),
            env!("CARGO_PKG_VERSION").to_owned(),
        ),
        ("npm_config_user_agent".to_owned(), omc_npm_user_agent()),
        ("npm_lifecycle_event".to_owned(), script_name.to_owned()),
        ("npm_lifecycle_script".to_owned(), script.to_owned()),
    ]);

    if let Ok(exe) = env::current_exe() {
        vars.insert(
            "npm_execpath".to_owned(),
            exe.to_string_lossy().into_owned(),
        );
    }
    if let Some(node) = find_program_on_path("node") {
        vars.insert(
            "npm_node_execpath".to_owned(),
            node.to_string_lossy().into_owned(),
        );
    }

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        vars.insert(
            "npm_package_json".to_owned(),
            package_json.to_string_lossy().into_owned(),
        );
        let package =
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(package_json)?)?;
        if let Some(name) = package.get("name").and_then(serde_json::Value::as_str) {
            vars.insert("npm_package_name".to_owned(), name.to_owned());
        }
        if let Some(version) = package.get("version").and_then(serde_json::Value::as_str) {
            vars.insert("npm_package_version".to_owned(), version.to_owned());
        }
        collect_npm_package_bin_env(&package, &mut vars);
        if let Some(config) = package.get("config") {
            collect_npm_package_config_env("npm_package_config", config, &mut vars);
        }
    }

    Ok(vars)
}

fn omc_npm_user_agent() -> String {
    format!(
        "omc/{} {} {} workspaces/false",
        env!("CARGO_PKG_VERSION"),
        env::consts::OS,
        env::consts::ARCH
    )
}

fn find_program_on_path(program: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn find_program_outside_current_exe_dir(program: &str) -> Option<PathBuf> {
    let current_exe = env::current_exe().ok().and_then(canonicalize_path);
    let current_exe_dir = current_exe
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(program);
        if !candidate.is_file() {
            continue;
        }
        let normalized = canonicalize_path(candidate.clone()).unwrap_or_else(|| candidate.clone());
        if current_exe
            .as_ref()
            .is_some_and(|current| current == &normalized)
        {
            continue;
        }
        if current_exe_dir
            .as_ref()
            .is_some_and(|current_dir| normalized.parent() == Some(current_dir.as_path()))
        {
            continue;
        }
        return Some(candidate);
    }
    None
}

fn canonicalize_path(path: PathBuf) -> Option<PathBuf> {
    path.canonicalize().ok()
}

fn collect_npm_package_bin_env(package: &serde_json::Value, vars: &mut BTreeMap<String, String>) {
    let Some(bin) = package.get("bin") else {
        return;
    };
    if let Some(path) = bin.as_str() {
        if let Some(name) = package.get("name").and_then(serde_json::Value::as_str) {
            if !name.is_empty() {
                vars.insert(
                    format!("npm_package_bin_{}", npm_package_bin_name(name)),
                    path.to_owned(),
                );
            }
        }
        return;
    }
    let Some(entries) = bin.as_object() else {
        return;
    };
    for (name, value) in entries {
        if let Some(path) = value.as_str() {
            vars.insert(format!("npm_package_bin_{name}"), path.to_owned());
        }
    }
}

fn npm_package_bin_name(package_name: &str) -> &str {
    package_name
        .rsplit_once('/')
        .map_or(package_name, |(_, name)| name)
}

fn collect_npm_package_config_env(
    prefix: &str,
    value: &serde_json::Value,
    vars: &mut BTreeMap<String, String>,
) {
    if let Some(entries) = value.as_object() {
        for (key, value) in entries {
            collect_npm_package_config_env(&format!("{prefix}_{key}"), value, vars);
        }
        return;
    }
    if let Some(value) = npm_package_env_value(value) {
        vars.insert(prefix.to_owned(), value);
    }
}

fn npm_package_env_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::String(value) => Some(value.clone()),
        _ => None,
    }
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

fn parse_npm_compat_action(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(NpmCompatAction::Install {
            specs: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            dev: false,
            omit_dev: false,
            lock_only: false,
            npm_registry: None,
            allow: Vec::new(),
            allow_all_host: false,
        });
    };

    match command {
        "--version" | "-v" => Ok(NpmCompatAction::Version),
        "install" | "i" | "add" | "update" | "up" | "upgrade" => parse_npm_install_args(&args[1..]),
        "ci" => {
            let CommonCompatFlags {
                omit_dev,
                allow,
                allow_all_host,
                positionals,
                ..
            } = parse_common_compat_flags(&args[1..], true)?;
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("npm ci", &positionals[0]));
            }
            Ok(NpmCompatAction::Ci {
                omit_dev,
                allow,
                allow_all_host,
            })
        }
        "remove" | "uninstall" | "rm" | "un" => {
            let CommonCompatFlags {
                allow,
                allow_all_host,
                positionals,
                ..
            } = parse_common_compat_flags(&args[1..], false)?;
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm remove needs at least one package".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Remove {
                specs: positionals,
                allow,
                allow_all_host,
            })
        }
        "run" | "run-script" => {
            let NpmRunArgs {
                name,
                args,
                if_present,
            } = parse_npm_run_args("npm run", &args[1..], None)?;
            Ok(NpmCompatAction::RunScript {
                command: command.to_owned(),
                name,
                args,
                if_present,
            })
        }
        "test" | "start" | "stop" | "restart" => {
            let NpmRunArgs {
                name,
                args,
                if_present,
            } = parse_npm_run_args(command, &args[1..], Some(command))?;
            Ok(NpmCompatAction::RunScript {
                command: command.to_owned(),
                name,
                args,
                if_present,
            })
        }
        "exec" | "x" | "npx" => {
            let (command, rest) = parse_npm_exec_args(&args[1..])?;
            Ok(NpmCompatAction::Exec {
                command,
                args: rest,
            })
        }
        "bin" => {
            parse_npm_path_args("npm bin", &args[1..])?;
            Ok(NpmCompatAction::Path {
                kind: NpmPathKind::Bin,
            })
        }
        "root" => {
            parse_npm_path_args("npm root", &args[1..])?;
            Ok(NpmCompatAction::Path {
                kind: NpmPathKind::Root,
            })
        }
        "prefix" => {
            parse_npm_path_args("npm prefix", &args[1..])?;
            Ok(NpmCompatAction::Path {
                kind: NpmPathKind::Prefix,
            })
        }
        "list" | "ls" => Ok(NpmCompatAction::List {
            json: parse_json_list_flag("npm list", &args[1..])?,
        }),
        "audit" => parse_npm_audit_args(&args[1..]),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm compatibility command `{other}`"
        ))),
    }
}

fn parse_npm_path_args(command: &str, args: &[String]) -> Result<(), OmcRegistryError> {
    for arg in args {
        if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p") {
            continue;
        }
        return Err(unsupported_compat_arg(command, arg));
    }
    Ok(())
}

fn parse_npm_install_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if is_npm_archive_arg(arg) {
            archive_references.push(arg.clone());
        } else if ignored_npm_value_flag(arg) {
            filtered.push(arg.clone());
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            filtered.push(value.clone());
        } else if is_npm_local_directory_arg(arg) {
            local_paths.push(npm_local_path_arg(arg)?);
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        dev,
        omit_dev,
        save,
        lock_only,
        npm_registry,
        allow,
        allow_all_host,
        positionals,
    } = parse_common_compat_flags(&filtered, true)?;

    Ok(NpmCompatAction::Install {
        specs: positionals,
        archive_references,
        local_paths,
        save,
        dev,
        omit_dev,
        lock_only,
        npm_registry,
        allow,
        allow_all_host,
    })
}

fn parse_npm_audit_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(arg.as_str(), "--audit-level" | "--audit-levels") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if matches!(arg.as_str(), "--parseable" | "--long")
            || npm_audit_equals_value_flag(arg)
        {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags { positionals, .. } = parse_common_compat_flags(&filtered, true)?;
    if !positionals.is_empty() {
        return Err(unsupported_compat_arg("npm audit", &positionals[0]));
    }

    Ok(NpmCompatAction::Audit { json })
}

fn npm_audit_equals_value_flag(arg: &str) -> bool {
    ["--audit-level=", "--audit-levels="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

#[derive(Debug, PartialEq, Eq)]
struct NpmRunArgs {
    name: String,
    args: Vec<String>,
    if_present: bool,
}

fn parse_npm_run_args(
    command: &str,
    args: &[String],
    implicit_name: Option<&str>,
) -> Result<NpmRunArgs, OmcRegistryError> {
    let mut name = implicit_name.map(str::to_owned);
    let mut script_args = Vec::new();
    let mut if_present = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            script_args.extend(args[index + 1..].iter().cloned());
            break;
        } else if matches!(
            arg.as_str(),
            "--if-present" | "--silent" | "-s" | "--loglevel=silent"
        ) {
            if arg == "--if-present" {
                if_present = true;
            }
        } else if arg == "--loglevel" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_run_equals_value_flag(arg) {
        } else if name.is_none() && !arg.starts_with('-') {
            name = Some(arg.clone());
        } else if name.is_some() {
            script_args.push(arg.clone());
        } else {
            return Err(unsupported_compat_arg(command, arg));
        }
        index += 1;
    }

    let Some(name) = name else {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{command} needs a target"
        )));
    };
    Ok(NpmRunArgs {
        name,
        args: script_args,
        if_present,
    })
}

fn npm_run_equals_value_flag(arg: &str) -> bool {
    ["--loglevel="].iter().any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_exec_args(args: &[String]) -> Result<(String, Vec<String>), OmcRegistryError> {
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            filtered.extend(args[index + 1..].iter().cloned());
            break;
        } else if matches!(
            arg.as_str(),
            "-y" | "--yes"
                | "--no"
                | "--ignore-existing"
                | "--foreground-scripts"
                | "--no-install"
                | "--quiet"
                | "--silent"
        ) {
        } else if matches!(
            arg.as_str(),
            "-p" | "--package" | "--cache" | "--registry" | "--userconfig"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_exec_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm exec", arg));
        } else {
            filtered.push(arg.clone());
            filtered.extend(args[index + 1..].iter().cloned());
            break;
        }
        index += 1;
    }
    split_first_position("npm exec", &filtered)
}

fn npm_exec_equals_value_flag(arg: &str) -> bool {
    ["--package=", "--cache=", "--registry=", "--userconfig="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_pip_compat_action(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip compatibility needs a command such as install, uninstall, freeze, or list"
                .to_owned(),
        ));
    };

    match command {
        "--version" | "-V" => Ok(PipCompatAction::Version),
        "install" => parse_pip_install_args(&args[1..]),
        "uninstall" | "remove" => parse_pip_uninstall_args(&args[1..]),
        "show" => parse_pip_show_args(&args[1..]),
        "check" => {
            parse_pip_check_args(&args[1..])?;
            Ok(PipCompatAction::Check)
        }
        "freeze" => {
            parse_pip_freeze_args(&args[1..])?;
            Ok(PipCompatAction::Freeze)
        }
        "list" => Ok(PipCompatAction::List {
            format: parse_pip_list_format(&args[1..])?,
        }),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip compatibility command `{other}`"
        ))),
    }
}

fn parse_pip_uninstall_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut requirements = Vec::new();
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-r" || arg == "--requirement" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--requirement=") {
            requirements.push(PathBuf::from(path));
        } else if matches!(
            arg.as_str(),
            "-y" | "--yes" | "--disable-pip-version-check" | "-v" | "--verbose" | "-q" | "--quiet"
        ) {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        allow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, false)?;
    if positionals.is_empty() && requirements.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip uninstall needs at least one package or requirement file".to_owned(),
        ));
    }
    Ok(PipCompatAction::Uninstall {
        specs: positionals,
        requirements,
        allow,
        allow_all_host,
    })
}

fn parse_pip_show_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut specs = Vec::new();
    let mut files = false;
    for arg in args {
        if matches!(
            arg.as_str(),
            "--disable-pip-version-check" | "-v" | "--verbose"
        ) {
            continue;
        }
        if matches!(arg.as_str(), "-f" | "--files") {
            files = true;
            continue;
        }
        if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip show", arg));
        }
        specs.push(arg.clone());
    }
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip show needs at least one package".to_owned(),
        ));
    }
    Ok(PipCompatAction::Show { specs, files })
}

fn parse_pip_check_args(args: &[String]) -> Result<(), OmcRegistryError> {
    for arg in args {
        if matches!(
            arg.as_str(),
            "--disable-pip-version-check" | "-v" | "--verbose"
        ) {
            continue;
        }
        return Err(unsupported_compat_arg("pip check", arg));
    }
    Ok(())
}

fn parse_pip_freeze_args(args: &[String]) -> Result<(), OmcRegistryError> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "--all"
                | "--local"
                | "--user"
                | "--exclude-editable"
                | "--disable-pip-version-check"
                | "-v"
                | "--verbose"
                | "-q"
                | "--quiet"
        ) {
        } else if matches!(
            arg.as_str(),
            "-r" | "--requirement" | "--path" | "--exclude"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_freeze_equals_value_flag(arg) {
        } else {
            return Err(unsupported_compat_arg("pip freeze", arg));
        }
        index += 1;
    }
    Ok(())
}

fn parse_pip_install_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut requirements = Vec::new();
    let mut constraints = Vec::new();
    let mut index_url = None;
    let mut extra_index_urls = Vec::new();
    let mut find_links = Vec::new();
    let mut no_index = false;
    let mut binary_all = None;
    let mut binary_packages = BTreeMap::new();
    let mut require_hashes = false;
    let mut no_deps = false;
    let mut target = None;
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-r" || arg == "--requirement" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            requirements.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--requirement=") {
            requirements.push(PathBuf::from(path));
        } else if arg == "-c" || arg == "--constraint" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            constraints.push(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--constraint=") {
            constraints.push(PathBuf::from(path));
        } else if arg == "-i" || arg == "--index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            index_url = Some(url.clone());
        } else if let Some(url) = arg.strip_prefix("--index-url=") {
            index_url = Some(url.to_owned());
        } else if arg == "--extra-index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            extra_index_urls.push(url.clone());
        } else if let Some(url) = arg.strip_prefix("--extra-index-url=") {
            extra_index_urls.push(url.to_owned());
        } else if arg == "-f" || arg == "--find-links" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path or URL"
                )));
            };
            find_links.push(value.clone());
        } else if let Some(value) = arg.strip_prefix("--find-links=") {
            find_links.push(value.to_owned());
        } else if arg == "--no-index" {
            no_index = true;
        } else if arg == "--require-hashes" {
            require_hashes = true;
        } else if arg == "--no-deps" {
            no_deps = true;
        } else if arg == "-t" || arg == "--target" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            target = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--target=") {
            target = Some(PathBuf::from(path));
        } else if arg == "--prefer-binary" {
        } else if arg == "--only-binary" || arg == "--no-binary" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            let mode = if arg == "--only-binary" {
                PypiBinaryMode::Binary
            } else {
                PypiBinaryMode::Source
            };
            apply_pypi_binary_option(&mut binary_all, &mut binary_packages, mode, value);
        } else if let Some(value) = arg.strip_prefix("--only-binary=") {
            apply_pypi_binary_option(
                &mut binary_all,
                &mut binary_packages,
                PypiBinaryMode::Binary,
                value,
            );
        } else if let Some(value) = arg.strip_prefix("--no-binary=") {
            apply_pypi_binary_option(
                &mut binary_all,
                &mut binary_packages,
                PypiBinaryMode::Source,
                value,
            );
        } else if arg == "--trusted-host" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with("--trusted-host=") {
        } else if arg == "-e" || arg == "--editable" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            local_paths.push(pip_local_path_arg(path)?);
        } else if let Some(path) = arg.strip_prefix("--editable=") {
            local_paths.push(pip_local_path_arg(path)?);
        } else if matches!(
            arg.as_str(),
            "--upgrade"
                | "-U"
                | "--user"
                | "--break-system-packages"
                | "--disable-pip-version-check"
                | "--no-cache-dir"
                | "--force-reinstall"
                | "--ignore-installed"
                | "--no-build-isolation"
                | "--use-pep517"
                | "--no-use-pep517"
                | "--compile"
                | "--no-compile"
                | "--no-warn-script-location"
                | "--no-warn-conflicts"
        ) {
        } else if pip_ignored_install_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_ignored_install_equals_flag(arg) {
        } else if is_pip_archive_arg(arg) {
            archive_references.push(arg.clone());
        } else if is_pip_local_directory_arg(arg) {
            local_paths.push(pip_local_path_arg(arg)?);
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        allow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, false)?;

    Ok(PipCompatAction::Install(Box::new(PipInstallAction {
        specs: positionals.into_iter().filter(|spec| spec != ".").collect(),
        requirements,
        constraints,
        archive_references,
        local_paths,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        binary_all,
        binary_packages,
        require_hashes,
        no_deps,
        target,
        allow,
        allow_all_host,
    })))
}

fn pip_ignored_install_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--progress-bar"
            | "--upgrade-strategy"
            | "--root-user-action"
            | "--retries"
            | "--timeout"
            | "--exists-action"
            | "--keyring-provider"
    )
}

fn pip_ignored_install_equals_flag(arg: &str) -> bool {
    [
        "--progress-bar=",
        "--upgrade-strategy=",
        "--root-user-action=",
        "--retries=",
        "--timeout=",
        "--exists-action=",
        "--keyring-provider=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_local_path_arg(value: &str) -> Result<PathBuf, OmcRegistryError> {
    let path = value
        .strip_prefix("file:")
        .or_else(|| value.strip_prefix("link:"))
        .unwrap_or(value);
    if path.starts_with("//") {
        let url = reqwest::Url::parse(value)
            .map_err(|_| OmcRegistryError::UnsupportedSpec(value.to_owned()))?;
        return url.to_file_path().map_err(|_| {
            OmcRegistryError::UnsupportedSpec(format!(
                "local npm dependency `{value}` must use a valid file URL"
            ))
        });
    }
    if path.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "local npm path cannot be empty".to_owned(),
        ));
    }
    Ok(PathBuf::from(path))
}

fn is_npm_local_directory_arg(value: &str) -> bool {
    if is_npm_archive_arg(value) {
        return false;
    }
    let value = value
        .strip_prefix("file:")
        .or_else(|| value.strip_prefix("link:"))
        .unwrap_or(value);
    value == "."
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with("~/")
        || value.contains('\\')
}

fn is_npm_archive_arg(value: &str) -> bool {
    let path = value.strip_prefix("file:").unwrap_or(value);
    let path = path.split_once('#').map(|(path, _)| path).unwrap_or(path);
    let path = path.split_once('?').map(|(path, _)| path).unwrap_or(path);
    let lower = path.to_ascii_lowercase();
    (lower.ends_with(".tgz") || lower.ends_with(".tar.gz"))
        && (path.starts_with("https://")
            || path.starts_with("http://")
            || path.starts_with("./")
            || path.starts_with("../")
            || path.starts_with('/')
            || path.starts_with("~/")
            || path.contains('\\'))
}

fn pip_local_path_arg(value: &str) -> Result<PythonLocalRequirement, OmcRegistryError> {
    if value.contains("://") || value.starts_with("git+") || is_pip_archive_arg(value) {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "pip editable path `{value}` must be a local directory"
        )));
    }
    let (path, extras) = pip_local_path_and_extras(value);
    if path.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip editable path cannot be empty".to_owned(),
        ));
    }
    Ok(PythonLocalRequirement::new(PathBuf::from(path), extras))
}

fn is_pip_local_directory_arg(value: &str) -> bool {
    if value.contains("://") || value.starts_with("git+") || is_pip_archive_arg(value) {
        return false;
    }
    let (path, _) = pip_local_path_and_extras(value);
    path == "."
        || path.starts_with("./")
        || path.starts_with("../")
        || path.starts_with('/')
        || path.starts_with("~/")
        || path.contains('/')
        || path.contains('\\')
}

fn pip_local_path_and_extras(value: &str) -> (&str, BTreeSet<String>) {
    let Some((path, extras)) = value.split_once('[') else {
        return (value, BTreeSet::new());
    };
    let extras = extras
        .trim_end_matches(']')
        .split(',')
        .map(normalize_extra)
        .filter(|extra| !extra.is_empty())
        .collect();
    (path, extras)
}

fn is_pip_archive_arg(value: &str) -> bool {
    let value = value.split_once('#').map(|(path, _)| path).unwrap_or(value);
    let filename = value
        .rsplit_once('/')
        .map(|(_, filename)| filename)
        .unwrap_or(value);
    filename.ends_with(".whl")
        || filename.ends_with(".zip")
        || filename.ends_with(".tgz")
        || filename.ends_with(".tar.gz")
}

#[derive(Debug)]
struct CommonCompatFlags {
    dev: bool,
    omit_dev: bool,
    save: bool,
    lock_only: bool,
    npm_registry: Option<String>,
    allow: Vec<String>,
    allow_all_host: bool,
    positionals: Vec<String>,
}

impl Default for CommonCompatFlags {
    fn default() -> Self {
        Self {
            dev: false,
            omit_dev: false,
            save: true,
            lock_only: false,
            npm_registry: None,
            allow: Vec::new(),
            allow_all_host: false,
            positionals: Vec::new(),
        }
    }
}

fn parse_common_compat_flags(
    args: &[String],
    npm_mode: bool,
) -> Result<CommonCompatFlags, OmcRegistryError> {
    let mut parsed = CommonCompatFlags::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            parsed.positionals.extend(args[index + 1..].iter().cloned());
            break;
        } else if arg == "--allow" {
            index += 1;
            let Some(grant) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--allow needs a capability grant".to_owned(),
                ));
            };
            parsed.allow.push(grant.clone());
        } else if let Some(grant) = arg.strip_prefix("--allow=") {
            parsed.allow.push(grant.to_owned());
        } else if arg == "--allow-all-host" {
            parsed.allow_all_host = true;
        } else if npm_mode && matches!(arg.as_str(), "-D" | "--save-dev" | "--dev") {
            parsed.dev = true;
            parsed.save = true;
        } else if npm_mode && arg == "--no-save" {
            parsed.save = false;
        } else if npm_mode && matches!(arg.as_str(), "--save" | "-S" | "--save-prod") {
            parsed.save = true;
        } else if npm_mode && arg == "--package-lock-only" {
            parsed.lock_only = true;
        } else if npm_mode && arg == "--registry" {
            index += 1;
            let Some(registry) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--registry needs a URL".to_owned(),
                ));
            };
            parsed.npm_registry = Some(registry.clone());
        } else if npm_mode {
            if let Some(registry) = arg.strip_prefix("--registry=") {
                parsed.npm_registry = Some(registry.to_owned());
                index += 1;
                continue;
            }
            if matches!(
                arg.as_str(),
                "--omit-dev" | "--production" | "--prod" | "--only=production"
            ) {
                parsed.omit_dev = true;
            } else if matches!(arg.as_str(), "--production=false" | "--prod=false") {
                parsed.omit_dev = false;
            } else if let Some(value) = arg.strip_prefix("--omit=") {
                parsed.omit_dev |= npm_dependency_set_contains(value, "dev");
            } else if let Some(value) = arg.strip_prefix("--include=") {
                if npm_dependency_set_contains(value, "dev") {
                    parsed.omit_dev = false;
                }
            } else if arg == "--omit" {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--omit needs a value".to_owned(),
                    ));
                };
                parsed.omit_dev |= npm_dependency_set_contains(value, "dev");
            } else if arg == "--include" {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "--include needs a value".to_owned(),
                    ));
                };
                if npm_dependency_set_contains(value, "dev") {
                    parsed.omit_dev = false;
                }
            } else if ignored_npm_value_flag(arg) {
                index += 1;
                if args.get(index).is_none() {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "{arg} needs a value"
                    )));
                }
            } else if ignored_compat_flag(npm_mode, arg) {
            } else if arg.starts_with('-') {
                return Err(unsupported_compat_arg("compatibility command", arg));
            } else {
                parsed.positionals.push(arg.clone());
            }
        } else if ignored_compat_flag(npm_mode, arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("compatibility command", arg));
        } else {
            parsed.positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(parsed)
}

fn npm_dependency_set_contains(value: &str, target: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|part| part.eq_ignore_ascii_case(target))
}

fn ignored_compat_flag(npm_mode: bool, arg: &str) -> bool {
    if npm_mode {
        matches!(
            arg,
            "--ignore-scripts"
                | "--ignore-scripts=false"
                | "--save-exact"
                | "--save-optional"
                | "--save-peer"
                | "-O"
                | "--no-fund"
                | "--fund"
                | "--fund=false"
                | "--audit"
                | "--no-audit"
                | "--audit=false"
                | "--package-lock"
                | "--package-lock=true"
                | "--package-lock=false"
                | "--foreground-scripts"
                | "--legacy-peer-deps"
                | "--legacy-peer-deps=true"
                | "--strict-peer-deps"
                | "--strict-peer-deps=false"
                | "--engine-strict=false"
        ) || ignored_npm_equals_flag(arg)
    } else {
        arg == "-y"
    }
}

fn ignored_npm_value_flag(arg: &str) -> bool {
    matches!(arg, "--install-strategy" | "--cache" | "--registry")
}

fn ignored_npm_equals_flag(arg: &str) -> bool {
    ["--install-strategy=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_json_list_flag(command: &str, args: &[String]) -> Result<bool, OmcRegistryError> {
    let mut json = false;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else if arg == "--depth=0" || arg == "--all" {
        } else {
            return Err(unsupported_compat_arg(command, arg));
        }
    }
    Ok(json)
}

fn parse_pip_list_format(args: &[String]) -> Result<PipListFormat, OmcRegistryError> {
    let mut format = PipListFormat::Columns;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--format" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip list --format needs a value".to_owned(),
                ));
            };
            format = parse_pip_list_format_value(value)?;
        } else if let Some(value) = arg.strip_prefix("--format=") {
            format = parse_pip_list_format_value(value)?;
        } else if matches!(
            arg.as_str(),
            "--local"
                | "--user"
                | "--editable"
                | "--include-editable"
                | "--exclude-editable"
                | "--disable-pip-version-check"
                | "-v"
                | "--verbose"
                | "-q"
                | "--quiet"
        ) {
        } else if matches!(arg.as_str(), "--path" | "--exclude") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_path_or_exclude_equals_value_flag(arg) {
        } else {
            return Err(unsupported_compat_arg("pip list", arg));
        }
        index += 1;
    }
    Ok(format)
}

fn parse_pip_list_format_value(value: &str) -> Result<PipListFormat, OmcRegistryError> {
    match value {
        "columns" => Ok(PipListFormat::Columns),
        "freeze" => Ok(PipListFormat::Freeze),
        "json" => Ok(PipListFormat::Json),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip list format `{other}`"
        ))),
    }
}

fn pip_freeze_equals_value_flag(arg: &str) -> bool {
    ["--path=", "--exclude=", "--requirement="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn pip_path_or_exclude_equals_value_flag(arg: &str) -> bool {
    ["--path=", "--exclude="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn pip_uninstall_specs_from_requirements(
    project_dir: &Path,
    requirements: Vec<PathBuf>,
) -> Result<Vec<String>, OmcRegistryError> {
    if requirements.is_empty() {
        return Ok(Vec::new());
    }

    let requirements = read_requirements_files(&absolutize_paths(project_dir, requirements))?;
    if !requirements.python_local_paths.is_empty()
        || !requirements.python_local_requirements.is_empty()
    {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip uninstall -r cannot remove unnamed local path requirements".to_owned(),
        ));
    }

    let mut specs = requirements
        .specs
        .into_iter()
        .map(|spec| spec.package_key())
        .collect::<Vec<_>>();
    specs.extend(
        requirements
            .python_vcs_requirements
            .into_iter()
            .map(|requirement| format!("pypi:{}", requirement.name)),
    );
    Ok(specs)
}

fn split_first_position(
    command: &str,
    args: &[String],
) -> Result<(String, Vec<String>), OmcRegistryError> {
    let mut args = args.to_vec();
    if args.first().map(String::as_str) == Some("--") {
        args.remove(0);
    }
    if args.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{command} needs a target"
        )));
    }
    let name = args.remove(0);
    if args.first().map(String::as_str) == Some("--") {
        args.remove(0);
    }
    Ok((name, args))
}

fn unsupported_compat_arg(command: &str, arg: &str) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!(
        "{command} does not support compatibility argument `{arg}`"
    ))
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

fn parse_package_specs(
    specs: &[String],
    ecosystem_hint: Option<Ecosystem>,
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    specs
        .iter()
        .map(|spec| parse_package_spec(spec, ecosystem_hint))
        .collect::<Result<Vec<_>, _>>()
}

fn parse_package_spec(
    spec: &str,
    ecosystem_hint: Option<Ecosystem>,
) -> Result<PackageSpec, OmcRegistryError> {
    if package_spec_has_ecosystem_prefix(spec) {
        return PackageSpec::parse(spec);
    }

    let Some(ecosystem) = ecosystem_hint else {
        return PackageSpec::parse(spec);
    };

    PackageSpec::parse(&format!("{ecosystem}:{spec}"))
}

fn package_spec_has_ecosystem_prefix(spec: &str) -> bool {
    spec.split_once(':')
        .map(|(prefix, _)| matches!(prefix, "npm" | "pypi" | "py" | "python"))
        .unwrap_or(false)
}

fn ecosystem_hint(npm: bool, pypi: bool) -> Option<Ecosystem> {
    if npm {
        Some(Ecosystem::Npm)
    } else if pypi {
        Some(Ecosystem::Pypi)
    } else {
        None
    }
}

fn normalize_extra(extra: &str) -> String {
    extra.trim().replace('_', "-").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn os_args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn test_dir(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!("omc-cli-{name}-{nonce}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detects_direct_compat_binaries() {
        assert_eq!(
            direct_compat_mode(Some(Path::new("/tmp/node").as_os_str())),
            Some(DirectCompatMode::Node)
        );
        assert_eq!(
            direct_compat_mode(Some(Path::new("/tmp/npm").as_os_str())),
            Some(DirectCompatMode::Npm)
        );
        assert_eq!(
            direct_compat_mode(Some(Path::new("/tmp/npx").as_os_str())),
            Some(DirectCompatMode::Npx)
        );
        assert_eq!(
            direct_compat_mode(Some(Path::new("/tmp/pip3").as_os_str())),
            Some(DirectCompatMode::Pip)
        );
        assert_eq!(
            direct_compat_mode(Some(Path::new("/tmp/python").as_os_str())),
            Some(DirectCompatMode::Python)
        );
        assert_eq!(
            direct_compat_mode(Some(Path::new("/tmp/python3").as_os_str())),
            Some(DirectCompatMode::Python)
        );
        assert_eq!(
            direct_compat_mode(Some(Path::new("/tmp/omc").as_os_str())),
            None
        );
    }

    #[test]
    fn parses_direct_compat_project_dir_prefix() {
        assert_eq!(
            parse_direct_compat_invocation(
                DirectCompatMode::Npm,
                os_args(&["--project-dir", "/tmp/project", "install", "left-pad",])
            )
            .unwrap(),
            DirectCompatInvocation {
                project_dir: PathBuf::from("/tmp/project"),
                args: args(&["install", "left-pad"]),
            }
        );
        assert_eq!(
            parse_direct_compat_invocation(
                DirectCompatMode::Pip,
                os_args(&["--omc-project-dir=/tmp/project", "show", "requests",])
            )
            .unwrap(),
            DirectCompatInvocation {
                project_dir: PathBuf::from("/tmp/project"),
                args: args(&["show", "requests"]),
            }
        );
        assert_eq!(
            parse_direct_compat_invocation(
                DirectCompatMode::Npm,
                os_args(&["--prefix=/tmp/project", "test", "--", "--watch",])
            )
            .unwrap(),
            DirectCompatInvocation {
                project_dir: PathBuf::from("/tmp/project"),
                args: args(&["test", "--", "--watch"]),
            }
        );
        assert_eq!(
            parse_direct_compat_invocation(
                DirectCompatMode::Npx,
                os_args(&["--prefix=/tmp/project", "eslint", "--", "."])
            )
            .unwrap(),
            DirectCompatInvocation {
                project_dir: PathBuf::from("/tmp/project"),
                args: args(&["eslint", "--", "."]),
            }
        );
        assert_eq!(
            npx_compat_args(args(&["eslint", "--", "."])),
            args(&["exec", "eslint", "--", "."])
        );
        assert_eq!(
            parse_direct_compat_invocation(
                DirectCompatMode::Node,
                os_args(&["--omc-project-dir", "/tmp/project", "-e", "console.log(1)",])
            )
            .unwrap(),
            DirectCompatInvocation {
                project_dir: PathBuf::from("/tmp/project"),
                args: args(&["-e", "console.log(1)"]),
            }
        );
        assert_eq!(
            parse_direct_compat_invocation(
                DirectCompatMode::Python,
                os_args(&[
                    "--omc-project-dir",
                    "/tmp/project",
                    "-m",
                    "pip",
                    "install",
                    "requests",
                ])
            )
            .unwrap(),
            DirectCompatInvocation {
                project_dir: PathBuf::from("/tmp/project"),
                args: args(&["-m", "pip", "install", "requests"]),
            }
        );
    }

    #[test]
    fn parses_npm_install_compat_flags() {
        assert_eq!(
            parse_npm_compat_action(&args(&["--version"])).unwrap(),
            NpmCompatAction::Version
        );

        let action = parse_npm_compat_action(&args(&[
            "install",
            "-D",
            "--omit=dev",
            "--install-strategy",
            "hoisted",
            "--cache=/tmp/npm-cache",
            "--registry",
            "https://registry.example.invalid/npm",
            "--package-lock=false",
            "--no-fund",
            "--legacy-peer-deps=true",
            "--strict-peer-deps=false",
            "--foreground-scripts",
            "--allow-all-host",
            "left-pad@1.3.0",
        ]))
        .unwrap();

        assert_eq!(
            action,
            NpmCompatAction::Install {
                specs: vec!["left-pad@1.3.0".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                dev: true,
                omit_dev: true,
                lock_only: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: Vec::new(),
                allow_all_host: true,
            }
        );

        let action = parse_npm_compat_action(&args(&[
            "install",
            "./pkg.tgz",
            "file:../other.tgz",
            "../local-pkg",
            "@scope/runtime",
        ]))
        .unwrap();

        assert_eq!(
            action,
            NpmCompatAction::Install {
                specs: vec!["@scope/runtime".to_owned()],
                archive_references: vec!["./pkg.tgz".to_owned(), "file:../other.tgz".to_owned()],
                local_paths: vec![PathBuf::from("../local-pkg")],
                save: true,
                dev: false,
                omit_dev: false,
                lock_only: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_all_host: false,
            }
        );

        let action = parse_npm_compat_action(&args(&[
            "install",
            "--no-save",
            "--omit=optional,peer",
            "--omit",
            "dev",
            "--include=dev",
            "left-pad",
        ]))
        .unwrap();

        assert_eq!(
            action,
            NpmCompatAction::Install {
                specs: vec!["left-pad".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: false,
                dev: false,
                omit_dev: false,
                lock_only: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_all_host: false,
            }
        );

        let action =
            parse_npm_compat_action(&args(&["install", "--package-lock-only", "left-pad"]))
                .unwrap();

        assert_eq!(
            action,
            NpmCompatAction::Install {
                specs: vec!["left-pad".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                dev: false,
                omit_dev: false,
                lock_only: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_all_host: false,
            }
        );

        let action = parse_npm_compat_action(&args(&[
            "update",
            "--package-lock-only",
            "--omit=dev",
            "--registry=https://registry.example.invalid/npm",
            "left-pad",
        ]))
        .unwrap();

        assert_eq!(
            action,
            NpmCompatAction::Install {
                specs: vec!["left-pad".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                dev: false,
                omit_dev: true,
                lock_only: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: Vec::new(),
                allow_all_host: false,
            }
        );
    }

    #[test]
    fn parses_npm_run_and_exec_compat_commands() {
        assert_eq!(
            parse_npm_compat_action(&args(&["run", "test", "--", "--watch"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "run".to_owned(),
                name: "test".to_owned(),
                args: vec!["--watch".to_owned()],
                if_present: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["test", "--", "--watch"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "test".to_owned(),
                name: "test".to_owned(),
                args: vec!["--watch".to_owned()],
                if_present: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["run", "--if-present", "--silent", "build"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "run".to_owned(),
                name: "build".to_owned(),
                args: Vec::new(),
                if_present: true,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["test", "--if-present", "--", "--watch"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "test".to_owned(),
                name: "test".to_owned(),
                args: vec!["--watch".to_owned()],
                if_present: true,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["exec", "eslint", "--", "."])).unwrap(),
            NpmCompatAction::Exec {
                command: "eslint".to_owned(),
                args: vec![".".to_owned()],
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "exec",
                "--yes",
                "--package",
                "eslint",
                "--cache=/tmp/npm-cache",
                "eslint",
                "--",
                ".",
            ]))
            .unwrap(),
            NpmCompatAction::Exec {
                command: "eslint".to_owned(),
                args: vec![".".to_owned()],
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "npx",
                "-y",
                "-p",
                "typescript",
                "tsc",
                "--version",
            ]))
            .unwrap(),
            NpmCompatAction::Exec {
                command: "tsc".to_owned(),
                args: vec!["--version".to_owned()],
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["bin", "--silent"])).unwrap(),
            NpmCompatAction::Path {
                kind: NpmPathKind::Bin,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["root"])).unwrap(),
            NpmCompatAction::Path {
                kind: NpmPathKind::Root,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["prefix", "--parseable"])).unwrap(),
            NpmCompatAction::Path {
                kind: NpmPathKind::Prefix,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "audit",
                "--json",
                "--audit-level=high",
                "--omit",
                "dev",
                "--registry",
                "https://registry.example.invalid/npm",
            ]))
            .unwrap(),
            NpmCompatAction::Audit { json: true }
        );
        assert!(parse_npm_compat_action(&args(&["audit", "fix"])).is_err());
    }

    #[test]
    fn builds_npm_lifecycle_env_from_package_json() {
        let dir = test_dir("npm-lifecycle-env");
        fs::write(
            dir.join("package.json"),
            r#"{
              "name": "@scope/env-demo",
              "version": "1.2.3",
              "bin": "cli.js",
              "config": {
                "port": 8080,
                "nested": {"token-name": "DEMO_TOKEN"}
              },
              "scripts": {"show": "node show.js"}
            }"#,
        )
        .unwrap();

        let vars = npm_lifecycle_env(&dir, "run", "show", "node show.js").unwrap();

        assert_eq!(vars.get("npm_command").map(String::as_str), Some("run"));
        assert_eq!(
            vars.get("npm_lifecycle_event").map(String::as_str),
            Some("show")
        );
        assert_eq!(
            vars.get("npm_lifecycle_script").map(String::as_str),
            Some("node show.js")
        );
        assert_eq!(
            vars.get("npm_package_name").map(String::as_str),
            Some("@scope/env-demo")
        );
        assert_eq!(
            vars.get("npm_package_version").map(String::as_str),
            Some("1.2.3")
        );
        assert_eq!(
            vars.get("npm_package_bin_env-demo").map(String::as_str),
            Some("cli.js")
        );
        assert_eq!(
            vars.get("npm_package_config_port").map(String::as_str),
            Some("8080")
        );
        assert_eq!(
            vars.get("npm_package_config_nested_token-name")
                .map(String::as_str),
            Some("DEMO_TOKEN")
        );
        let absolute_dir = absolute_project_dir(&dir);
        let package_json = absolute_dir
            .join("package.json")
            .to_string_lossy()
            .into_owned();
        let local_prefix = absolute_dir.to_string_lossy().into_owned();
        assert_eq!(
            vars.get("npm_package_json").map(String::as_str),
            Some(package_json.as_str())
        );
        assert_eq!(
            vars.get("npm_config_local_prefix").map(String::as_str),
            Some(local_prefix.as_str())
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn orders_npm_pre_and_post_lifecycle_scripts() {
        let scripts = BTreeMap::from([
            ("check".to_owned(), "node check.js".to_owned()),
            ("precheck".to_owned(), "node pre.js".to_owned()),
            ("postcheck".to_owned(), "node post.js".to_owned()),
            ("prepare".to_owned(), "node prepare.js".to_owned()),
        ]);

        assert_eq!(
            package_script_lifecycle_order(&scripts, "check").unwrap(),
            vec![
                "precheck".to_owned(),
                "check".to_owned(),
                "postcheck".to_owned()
            ]
        );
        assert_eq!(
            package_script_lifecycle_order(&scripts, "prepare").unwrap(),
            vec!["prepare".to_owned()]
        );
    }

    #[test]
    fn npm_run_if_present_allows_missing_script() {
        let dir = test_dir("npm-run-if-present");
        fs::write(
            dir.join("package.json"),
            r#"{ "scripts": { "test": "true" } }"#,
        )
        .unwrap();

        let status = run_package_script_with_npm_command(&dir, "run", "build", &[], true).unwrap();

        assert_eq!(status, ExitCode::SUCCESS);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parses_pip_install_requirements_and_indexes() {
        let action = parse_pip_compat_action(&args(&[
            "install",
            "-r",
            "requirements.txt",
            "-c",
            "constraints.txt",
            "--index-url",
            "https://mirror.example/simple",
            "--extra-index-url=https://extra.example/simple",
            "--find-links",
            "wheelhouse",
            "--no-index",
            "--require-hashes",
            "--no-deps",
            "--target",
            "vendor",
            "--no-binary=:all:",
            "--only-binary",
            "idna",
            "--trusted-host",
            "mirror.example",
            "--prefer-binary",
            "--force-reinstall",
            "--ignore-installed",
            "--upgrade-strategy",
            "eager",
            "--root-user-action=ignore",
            "--progress-bar",
            "off",
            "--retries",
            "1",
            "--timeout=5",
            "--exists-action",
            "i",
            "--no-build-isolation",
            "--no-warn-script-location",
            "--no-compile",
            "--allow-all-host",
            "requests==2.32.3",
        ]))
        .unwrap();

        assert_eq!(
            action,
            PipCompatAction::Install(Box::new(PipInstallAction {
                specs: vec!["requests==2.32.3".to_owned()],
                requirements: vec![PathBuf::from("requirements.txt")],
                constraints: vec![PathBuf::from("constraints.txt")],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                index_url: Some("https://mirror.example/simple".to_owned()),
                extra_index_urls: vec!["https://extra.example/simple".to_owned()],
                find_links: vec!["wheelhouse".to_owned()],
                no_index: true,
                binary_all: Some(PypiBinaryMode::Source),
                binary_packages: BTreeMap::from([("idna".to_owned(), PypiBinaryMode::Binary)]),
                require_hashes: true,
                no_deps: true,
                target: Some(PathBuf::from("vendor")),
                allow: Vec::new(),
                allow_all_host: true,
            }))
        );
    }

    #[test]
    fn parses_pip_install_local_paths() {
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "install",
                "-e",
                "../editable_pkg[dev]",
                "--editable=./another_pkg",
                "./local_pkg",
                "requests==2.32.3",
            ]))
            .unwrap(),
            PipCompatAction::Install(Box::new(PipInstallAction {
                specs: vec!["requests==2.32.3".to_owned()],
                requirements: Vec::new(),
                constraints: Vec::new(),
                archive_references: Vec::new(),
                local_paths: vec![
                    PythonLocalRequirement::new(
                        PathBuf::from("../editable_pkg"),
                        BTreeSet::from(["dev".to_owned()]),
                    ),
                    PythonLocalRequirement::new(PathBuf::from("./another_pkg"), BTreeSet::new()),
                    PythonLocalRequirement::new(PathBuf::from("./local_pkg"), BTreeSet::new()),
                ],
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: Vec::new(),
                no_index: false,
                binary_all: None,
                binary_packages: BTreeMap::new(),
                require_hashes: false,
                no_deps: false,
                target: None,
                allow: Vec::new(),
                allow_all_host: false,
            }))
        );
    }

    #[test]
    fn parses_pip_install_archive_references() {
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "install",
                "./wheelhouse/demo_pkg-1.0.0-py3-none-any.whl",
                "https://files.example/source_pkg-2.0.0.tar.gz#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]))
            .unwrap(),
            PipCompatAction::Install(Box::new(PipInstallAction {
                specs: Vec::new(),
                requirements: Vec::new(),
                constraints: Vec::new(),
                archive_references: vec![
                    "./wheelhouse/demo_pkg-1.0.0-py3-none-any.whl".to_owned(),
                    "https://files.example/source_pkg-2.0.0.tar.gz#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                ],
                local_paths: Vec::new(),
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: Vec::new(),
                no_index: false,
                binary_all: None,
                binary_packages: BTreeMap::new(),
                require_hashes: false,
                no_deps: false,
                target: None,
                allow: Vec::new(),
                allow_all_host: false,
            }))
        );
    }

    #[test]
    fn detects_python_module_pip_invocations() {
        let command = args(&["-m", "pip", "install", "requests==2.32.3"]);
        assert_eq!(
            python_pip_module_args(&command),
            Some(args(&["install", "requests==2.32.3"]).as_slice())
        );

        let isolated = args(&["-I", "-S", "-m", "pip3", "--version"]);
        assert_eq!(
            python_pip_module_args(&isolated),
            Some(args(&["--version"]).as_slice())
        );

        let compact = args(&["-mpip", "freeze"]);
        assert_eq!(
            python_pip_module_args(&compact),
            Some(args(&["freeze"]).as_slice())
        );

        let script = args(&["script.py", "-m", "pip"]);
        assert_eq!(python_pip_module_args(&script), None);
    }

    #[test]
    fn parses_pip_uninstall_and_freeze() {
        assert_eq!(
            parse_pip_compat_action(&args(&["--version"])).unwrap(),
            PipCompatAction::Version
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["uninstall", "-y", "requests"])).unwrap(),
            PipCompatAction::Uninstall {
                specs: vec!["requests".to_owned()],
                requirements: Vec::new(),
                allow: Vec::new(),
                allow_all_host: false,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "uninstall",
                "--yes",
                "-r",
                "requirements.txt",
                "--requirement=dev-requirements.txt",
                "--disable-pip-version-check",
                "pytest",
            ]))
            .unwrap(),
            PipCompatAction::Uninstall {
                specs: vec!["pytest".to_owned()],
                requirements: vec![
                    PathBuf::from("requirements.txt"),
                    PathBuf::from("dev-requirements.txt"),
                ],
                allow: Vec::new(),
                allow_all_host: false,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["freeze"])).unwrap(),
            PipCompatAction::Freeze
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["check", "--disable-pip-version-check"])).unwrap(),
            PipCompatAction::Check
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["show", "-f", "requests"])).unwrap(),
            PipCompatAction::Show {
                specs: vec!["requests".to_owned()],
                files: true,
            }
        );
    }

    #[test]
    fn parses_npm_and_pip_machine_readable_lists() {
        assert_eq!(
            parse_npm_compat_action(&args(&["list", "--json"])).unwrap(),
            NpmCompatAction::List { json: true }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "freeze",
                "--all",
                "--local",
                "--path",
                "vendor",
                "--exclude=requests",
                "-r",
                "requirements.txt",
            ]))
            .unwrap(),
            PipCompatAction::Freeze
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["list", "--format=freeze"])).unwrap(),
            PipCompatAction::List {
                format: PipListFormat::Freeze,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["list", "--format", "json"])).unwrap(),
            PipCompatAction::List {
                format: PipListFormat::Json,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "list",
                "--format=json",
                "--local",
                "--path",
                "vendor",
                "--exclude=requests",
                "--exclude-editable",
            ]))
            .unwrap(),
            PipCompatAction::List {
                format: PipListFormat::Json,
            }
        );
        assert!(parse_pip_compat_action(&args(&["list", "--outdated"])).is_err());
    }

    #[test]
    fn reports_pip_show_dependency_and_file_metadata() {
        let package = locked_pypi_package(
            "charset-normalizer",
            "3.4.0",
            vec!["pypi:idna@>=3".to_owned()],
        );
        let dependent = locked_pypi_package(
            "requests",
            "2.32.3",
            vec!["pypi:charset-normalizer@>=2".to_owned()],
        );

        assert_eq!(pip_dependency_names(&package), vec!["idna".to_owned()]);
        assert_eq!(
            pip_required_by_names(&package, &[package.clone(), dependent]),
            vec!["requests".to_owned()]
        );

        let site_packages = temp_test_dir().join("site-packages");
        let dist_info = site_packages.join("charset_normalizer-3.4.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        fs::write(
            dist_info.join("RECORD"),
            "charset_normalizer/__init__.py,,\ncharset_normalizer-3.4.0.dist-info/METADATA,,\n",
        )
        .unwrap();

        assert_eq!(
            pip_installed_files(&site_packages, &package).unwrap(),
            vec![
                "charset_normalizer-3.4.0.dist-info/METADATA".to_owned(),
                "charset_normalizer/__init__.py".to_owned(),
            ]
        );
        fs::remove_dir_all(site_packages.parent().unwrap()).unwrap();
    }

    fn locked_pypi_package(name: &str, version: &str, dependencies: Vec<String>) -> LockedPackage {
        LockedPackage {
            ecosystem: Ecosystem::Pypi,
            name: name.to_owned(),
            version: version.to_owned(),
            source_url: format!("https://files.example/{name}-{version}.whl"),
            archive: String::new(),
            artifact: String::new(),
            sha256: String::new(),
            behavior: Behavior::Pure,
            verdict: Verdict::Accepted,
            dependencies,
            optional_dependencies: Vec::new(),
            grants: Vec::new(),
            capabilities: Vec::new(),
            verifier_findings: Vec::new(),
        }
    }

    fn temp_test_dir() -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "omc-cli-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }
}
