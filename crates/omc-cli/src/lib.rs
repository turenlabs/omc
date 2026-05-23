use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::{env, ffi::OsString, fs};

use clap::{Parser, Subcommand};
use omc_cap::Capability;
use omc_registry::{
    add_manifest_npm_local_paths, add_manifest_policy_grants, add_package_graph,
    apply_pypi_binary_option, check_pypi_lock, compare_npm_versions, compare_pypi_versions,
    init_project, install_locked_packages, install_locked_project, install_project, lock_project,
    parse_capability_grant, parse_npm_direct_archive_reference,
    parse_pypi_direct_archive_reference, read_constraint_files, read_lockfile,
    read_npm_config_snapshot, read_npm_package_metadata, read_package_scripts,
    read_pip_config_snapshot, read_pypi_available_versions, read_requirements_files,
    remove_manifest_dependency, Behavior, Ecosystem, InstallReport, LinkOptions, LockedPackage,
    OmcRegistryError, PackageSpec, ProjectRequirements, PypiBinaryMode, PypiCheckIssue,
    PythonLocalRequirement, Verdict,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

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
    Maintenance {
        command: NpmMaintenanceCommand,
        omit_dev: bool,
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
    Outdated {
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
    },
    Audit {
        json: bool,
    },
    Cache {
        action: NpmCacheAction,
    },
    Config {
        action: NpmConfigAction,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    View {
        spec: String,
        fields: Vec<String>,
        json: bool,
        npm_registry: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmMaintenanceCommand {
    Prune,
    Dedupe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmPathKind {
    Bin,
    Root,
    Prefix,
}

#[derive(Debug, PartialEq, Eq)]
enum NpmCacheAction {
    Verify,
    List { pattern: Option<String> },
    Remove { pattern: String },
    Clean,
}

#[derive(Debug, PartialEq, Eq)]
enum NpmConfigAction {
    Get { keys: Vec<String>, json: bool },
    List { json: bool },
}

#[derive(Debug, PartialEq, Eq)]
enum PipCompatAction {
    Version,
    Install(Box<PipInstallAction>),
    Download(Box<PipDownloadAction>),
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
    Hash {
        algorithm: PipHashAlgorithm,
        paths: Vec<PathBuf>,
    },
    Cache {
        action: PipCacheAction,
    },
    Check,
    Freeze,
    List {
        format: PipListFormat,
        outdated: bool,
        index_url: Option<String>,
        extra_index_urls: Vec<String>,
        find_links: Vec<String>,
        no_index: bool,
    },
    IndexVersions {
        package: String,
        index_url: Option<String>,
        extra_index_urls: Vec<String>,
        find_links: Vec<String>,
        no_index: bool,
        json: bool,
    },
    Config {
        action: PipConfigAction,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum PipCacheAction {
    Dir,
    Info,
    List { pattern: Option<String> },
    Remove { pattern: String },
    Purge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl PipHashAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
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

#[derive(Debug, PartialEq, Eq)]
struct PipDownloadAction {
    specs: Vec<String>,
    requirements: Vec<PathBuf>,
    constraints: Vec<PathBuf>,
    archive_references: Vec<String>,
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    binary_all: Option<PypiBinaryMode>,
    binary_packages: BTreeMap<String, PypiBinaryMode>,
    require_hashes: bool,
    no_deps: bool,
    destination: PathBuf,
    allow: Vec<String>,
    allow_all_host: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipListFormat {
    Columns,
    Freeze,
    Json,
}

#[derive(Debug, PartialEq, Eq)]
enum PipConfigAction {
    Get { keys: Vec<String>, json: bool },
    List { json: bool },
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
        NpmCompatAction::Maintenance {
            command,
            omit_dev,
            allow,
            allow_all_host,
        } => {
            let mut options = LinkOptions::new(project_dir);
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            options.include_dev_dependencies = !omit_dev;
            let install = install_locked_project(&options)?;
            print_npm_maintenance_report(command, &install);
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
        NpmCompatAction::Outdated {
            json,
            parseable,
            npm_registry,
        } => return print_npm_outdated(project_dir, json, parseable, npm_registry.as_deref()),
        NpmCompatAction::Audit { json } => return print_audit_report(project_dir, json),
        NpmCompatAction::Cache { action } => print_npm_cache(project_dir, action)?,
        NpmCompatAction::Config {
            action,
            npm_registry,
            userconfig,
        } => print_npm_config(
            project_dir,
            action,
            npm_registry.as_deref(),
            userconfig.as_deref(),
        )?,
        NpmCompatAction::View {
            spec,
            fields,
            json,
            npm_registry,
        } => print_npm_view(project_dir, &spec, &fields, json, npm_registry.as_deref())?,
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
        PipCompatAction::Download(action) => {
            download_pip_packages(project_dir, *action)?;
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
        PipCompatAction::Hash { algorithm, paths } => {
            print_pip_hash(project_dir, algorithm, paths)?
        }
        PipCompatAction::Cache { action } => print_pip_cache(project_dir, action)?,
        PipCompatAction::Check => return print_locked_pip_check(project_dir),
        PipCompatAction::Freeze => print_locked_freeze(project_dir)?,
        PipCompatAction::List {
            format,
            outdated,
            index_url,
            extra_index_urls,
            find_links,
            no_index,
        } => {
            if outdated {
                print_locked_pip_outdated(
                    project_dir,
                    format,
                    index_url,
                    extra_index_urls,
                    find_links,
                    no_index,
                )?;
            } else {
                match format {
                    PipListFormat::Columns => {
                        print_locked_packages(project_dir, Some(Ecosystem::Pypi), false)?
                    }
                    PipListFormat::Freeze => print_locked_freeze(project_dir)?,
                    PipListFormat::Json => print_locked_pip_json(project_dir)?,
                }
            }
        }
        PipCompatAction::IndexVersions {
            package,
            index_url,
            extra_index_urls,
            find_links,
            no_index,
            json,
        } => print_pip_index_versions(
            project_dir,
            &package,
            index_url,
            extra_index_urls,
            find_links,
            no_index,
            json,
        )?,
        PipCompatAction::Config { action } => print_pip_config(project_dir, action)?,
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

fn print_npm_config(
    project_dir: &Path,
    action: NpmConfigAction,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
) -> Result<(), OmcRegistryError> {
    let values = npm_config_values(project_dir, npm_registry, userconfig)?;
    match action {
        NpmConfigAction::Get { keys, json } => {
            if json {
                if keys.len() == 1 {
                    let value = npm_config_value_for_key(&values, &keys[0]);
                    println!("{}", serde_json::to_string_pretty(&value)?);
                } else {
                    let selected = keys
                        .into_iter()
                        .map(|key| {
                            let value = npm_config_value_for_key(&values, &key);
                            (key, value)
                        })
                        .collect::<BTreeMap<_, _>>();
                    println!("{}", serde_json::to_string_pretty(&selected)?);
                }
            } else {
                for key in keys {
                    println!("{}", npm_config_value_for_key(&values, &key));
                }
            }
        }
        NpmConfigAction::List { json } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&values)?);
            } else {
                for (key, value) in values {
                    println!("{key} = {value}");
                }
            }
        }
    }
    Ok(())
}

fn npm_config_values(
    project_dir: &Path,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
) -> Result<BTreeMap<String, String>, OmcRegistryError> {
    let snapshot = read_npm_config_snapshot(project_dir, npm_registry, userconfig)?;
    let project_dir = absolute_project_dir(project_dir);
    let mut values = BTreeMap::from([
        ("audit".to_owned(), "true".to_owned()),
        (
            "cache".to_owned(),
            project_dir
                .join(".omc")
                .join("cache")
                .join("npm")
                .to_string_lossy()
                .into_owned(),
        ),
        ("fund".to_owned(), "false".to_owned()),
        ("global".to_owned(), "false".to_owned()),
        (
            "local-prefix".to_owned(),
            project_dir.to_string_lossy().into_owned(),
        ),
        ("loglevel".to_owned(), "notice".to_owned()),
        ("package-lock".to_owned(), "true".to_owned()),
        (
            "prefix".to_owned(),
            project_dir.to_string_lossy().into_owned(),
        ),
        ("registry".to_owned(), snapshot.registry),
        ("save".to_owned(), "true".to_owned()),
        (
            "userconfig".to_owned(),
            npm_userconfig_path(project_dir.as_path(), userconfig)
                .to_string_lossy()
                .into_owned(),
        ),
    ]);
    for (scope, registry) in snapshot.scoped_registries {
        values.insert(format!("{scope}:registry"), registry);
    }
    Ok(values)
}

fn npm_userconfig_path(project_dir: &Path, userconfig: Option<&Path>) -> PathBuf {
    if let Some(userconfig) = userconfig {
        return absolutize_path(project_dir, userconfig.to_path_buf());
    }
    if let Some(userconfig) = env::var_os("npm_config_userconfig")
        .or_else(|| env::var_os("NPM_CONFIG_USERCONFIG"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return absolutize_path(project_dir, userconfig);
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| project_dir.to_path_buf())
        .join(".npmrc")
}

fn npm_config_value_for_key(values: &BTreeMap<String, String>, key: &str) -> String {
    values
        .get(key)
        .cloned()
        .unwrap_or_else(|| "undefined".to_owned())
}

fn print_npm_view(
    project_dir: &Path,
    spec: &str,
    fields: &[String],
    json: bool,
    npm_registry: Option<&str>,
) -> Result<(), OmcRegistryError> {
    let spec = parse_package_spec(spec, Some(Ecosystem::Npm))?;
    let metadata = read_npm_package_metadata(project_dir, &spec, npm_registry)?;
    if fields.is_empty() {
        if json {
            println!("{}", serde_json::to_string_pretty(&metadata.manifest)?);
        } else {
            println!("{}@{}", metadata.name, metadata.version);
            if let Some(tarball) = npm_view_field_value(&metadata, "dist.tarball") {
                println!("dist.tarball = {}", npm_view_text_value(&tarball));
            }
            if !metadata.dist_tags.is_empty() {
                let tags = serde_json::to_value(&metadata.dist_tags)?;
                println!("dist-tags = {}", npm_view_text_value(&tags));
            }
        }
        return Ok(());
    }

    if json {
        if fields.len() == 1 {
            let value =
                npm_view_field_value(&metadata, &fields[0]).unwrap_or(serde_json::Value::Null);
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            let selected = fields
                .iter()
                .map(|field| {
                    (
                        field.clone(),
                        npm_view_field_value(&metadata, field).unwrap_or(serde_json::Value::Null),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            println!("{}", serde_json::to_string_pretty(&selected)?);
        }
    } else if fields.len() == 1 {
        let value = npm_view_field_value(&metadata, &fields[0]).unwrap_or(serde_json::Value::Null);
        println!("{}", npm_view_text_value(&value));
    } else {
        for field in fields {
            let value = npm_view_field_value(&metadata, field).unwrap_or(serde_json::Value::Null);
            println!("{field} = {}", npm_view_text_value(&value));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct NpmOutdatedPackage {
    name: String,
    current: String,
    wanted: String,
    latest: String,
    location: PathBuf,
    dependent: String,
}

fn print_npm_outdated(
    project_dir: &Path,
    json: bool,
    parseable: bool,
    npm_registry: Option<&str>,
) -> Result<ExitCode, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let dependent = npm_outdated_dependent(project_dir);
    let mut rows = Vec::new();
    for package in lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
    {
        let spec = parse_package_spec(&package.name, Some(Ecosystem::Npm))?;
        let metadata = read_npm_package_metadata(project_dir, &spec, npm_registry)?;
        if compare_npm_versions(&metadata.version, &package.version).is_gt() {
            rows.push(NpmOutdatedPackage {
                location: npm_outdated_location(project_dir, &package.name),
                name: package.name.clone(),
                current: package.version.clone(),
                wanted: metadata.version.clone(),
                latest: metadata.version,
                dependent: dependent.clone(),
            });
        }
    }
    rows.sort_by(|left, right| left.name.cmp(&right.name));

    if json {
        let packages = rows
            .iter()
            .map(|row| {
                (
                    row.name.clone(),
                    serde_json::json!({
                        "current": row.current,
                        "wanted": row.wanted,
                        "latest": row.latest,
                        "dependent": row.dependent,
                        "location": row.location.display().to_string(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else if parseable {
        for row in &rows {
            println!(
                "{}:{}:{}:{}",
                row.location.display(),
                row.current,
                row.wanted,
                row.latest
            );
        }
    } else if !rows.is_empty() {
        println!("Package Current Wanted Latest Location Depended by");
        for row in &rows {
            println!(
                "{} {} {} {} {} {}",
                row.name,
                row.current,
                row.wanted,
                row.latest,
                row.location.display(),
                row.dependent
            );
        }
    }

    if rows.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn npm_outdated_location(project_dir: &Path, package: &str) -> PathBuf {
    project_dir.join("node_modules").join(package)
}

fn npm_outdated_dependent(project_dir: &Path) -> String {
    let package_json = project_dir.join("package.json");
    if let Ok(content) = fs::read_to_string(package_json) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(name) = value.get("name").and_then(serde_json::Value::as_str) {
                if !name.is_empty() {
                    return name.to_owned();
                }
            }
        }
    }
    project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("omc-project")
        .to_owned()
}

fn npm_view_field_value(
    metadata: &omc_registry::NpmPackageMetadata,
    field: &str,
) -> Option<serde_json::Value> {
    match field {
        "name" => Some(serde_json::Value::String(metadata.name.clone())),
        "version" => Some(serde_json::Value::String(metadata.version.clone())),
        "versions" => serde_json::to_value(&metadata.versions).ok(),
        "dist-tags" | "distTags" => serde_json::to_value(&metadata.dist_tags).ok(),
        _ => metadata
            .manifest
            .pointer(&json_pointer_for_dotted_field(field))
            .cloned(),
    }
}

fn json_pointer_for_dotted_field(field: &str) -> String {
    let mut pointer = String::new();
    for part in field.split('.') {
        pointer.push('/');
        pointer.push_str(&part.replace('~', "~0").replace('/', "~1"));
    }
    pointer
}

fn npm_view_text_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "undefined".to_owned(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}

fn print_pip_index_versions(
    project_dir: &Path,
    package: &str,
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    json: bool,
) -> Result<(), OmcRegistryError> {
    let listing = read_pypi_available_versions(
        project_dir,
        package,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
    )?;
    let latest = listing.versions.first().cloned().unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "name": listing.name,
                "latest": latest,
                "versions": listing.versions,
            }))?
        );
    } else {
        println!("{} ({latest})", listing.name);
        println!("Available versions: {}", listing.versions.join(", "));
    }
    Ok(())
}

fn print_pip_hash(
    project_dir: &Path,
    algorithm: PipHashAlgorithm,
    paths: Vec<PathBuf>,
) -> Result<(), OmcRegistryError> {
    for path in paths {
        let resolved = absolutize_path(project_dir, path.clone());
        let bytes = fs::read(&resolved)?;
        println!("{}:", path.display());
        println!(
            "--hash={}:{}",
            algorithm.name(),
            pip_hash_digest(algorithm, &bytes)
        );
    }
    Ok(())
}

fn pip_hash_digest(algorithm: PipHashAlgorithm, bytes: &[u8]) -> String {
    let digest = match algorithm {
        PipHashAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
        PipHashAlgorithm::Sha384 => Sha384::digest(bytes).to_vec(),
        PipHashAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
    };
    digest
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn download_pip_packages(
    project_dir: &Path,
    action: PipDownloadAction,
) -> Result<(), OmcRegistryError> {
    let PipDownloadAction {
        specs,
        requirements,
        constraints,
        archive_references,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        binary_all,
        binary_packages,
        require_hashes,
        no_deps,
        destination,
        allow,
        allow_all_host,
    } = action;

    let destination = absolutize_path(project_dir, destination);
    fs::create_dir_all(&destination)?;

    let mut options = LinkOptions::new(project_dir);
    options.save_manifest_dependency = false;
    options.discover_project_requirements = false;
    options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
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

    let mut resolved_specs = parse_package_specs(&specs, Some(Ecosystem::Pypi))?;
    resolved_specs.extend(parse_pip_archive_references(
        project_dir,
        &archive_references,
        &mut options,
    )?);
    if !requirements.is_empty() {
        let requirements = read_requirements_files(&absolutize_paths(project_dir, requirements))?;
        apply_pypi_download_requirements(&mut options, &mut resolved_specs, requirements)?;
    }
    if !constraints.is_empty() {
        let constraints = read_constraint_files(&absolutize_paths(project_dir, constraints))?;
        apply_pypi_download_requirements(&mut options, &mut resolved_specs, constraints)?;
    }
    if resolved_specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip download needs at least one package, archive, or requirement file".to_owned(),
        ));
    }

    let mut reports = Vec::new();
    for spec in &resolved_specs {
        reports.extend(add_package_graph(spec, &options)?);
    }
    copy_downloaded_pypi_archives(project_dir, &destination, &reports)?;
    Ok(())
}

fn apply_pypi_download_requirements(
    options: &mut LinkOptions,
    specs: &mut Vec<PackageSpec>,
    requirements: ProjectRequirements,
) -> Result<(), OmcRegistryError> {
    if !requirements.python_local_paths.is_empty()
        || !requirements.python_local_requirements.is_empty()
        || !requirements.python_vcs_requirements.is_empty()
    {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip download supports registry requirements and direct wheel/sdist archives; local directories and VCS requirements need pip install"
                .to_owned(),
        ));
    }

    specs.extend(requirements.specs);
    options.constraints.extend(requirements.constraints);
    options.hashes.extend(requirements.hashes);
    if requirements.pypi_binary_all.is_some() {
        options.pypi_binary_all = requirements.pypi_binary_all;
    }
    options
        .pypi_binary_packages
        .extend(requirements.pypi_binary_packages);
    if requirements.pypi_index_url.is_some() {
        options.pypi_index_url = requirements.pypi_index_url;
    }
    options
        .pypi_extra_index_urls
        .extend(requirements.pypi_extra_index_urls);
    options.pypi_find_links.extend(requirements.pypi_find_links);
    options.pypi_no_index |= requirements.pypi_no_index;
    options.pypi_require_hashes |= requirements.pypi_require_hashes;
    if requirements.pypi_no_deps {
        options.pypi_include_dependencies = false;
    }
    Ok(())
}

fn copy_downloaded_pypi_archives(
    project_dir: &Path,
    destination: &Path,
    reports: &[omc_registry::LinkReport],
) -> Result<(), OmcRegistryError> {
    let mut copied = BTreeSet::new();
    for report in reports {
        let package = &report.locked;
        if package.ecosystem != Ecosystem::Pypi {
            continue;
        }
        let key = format!("{}=={}:{}", package.name, package.version, package.sha256);
        if !copied.insert(key) {
            continue;
        }
        let source = project_dir.join(&package.archive);
        let filename = pypi_download_filename(package);
        let target = destination.join(filename);
        fs::copy(&source, &target)?;
        println!("Saved {}", target.display());
    }
    println!("Successfully downloaded {} package(s)", copied.len());
    Ok(())
}

fn pypi_download_filename(package: &LockedPackage) -> String {
    if let Ok(url) = reqwest::Url::parse(&package.source_url) {
        if let Some(filename) = url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
        {
            if !filename.is_empty() {
                return filename.to_owned();
            }
        }
    }
    let without_fragment = package
        .source_url
        .split_once('#')
        .map(|(path, _)| path)
        .unwrap_or(&package.source_url);
    let source = without_fragment
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(without_fragment);
    Path::new(source)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            Path::new(&package.archive)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("{}-{}.archive", package.name, package.version))
}

fn print_npm_cache(project_dir: &Path, action: NpmCacheAction) -> Result<(), OmcRegistryError> {
    let cache_dir = npm_cache_dir(project_dir);
    match action {
        NpmCacheAction::Verify => {
            let files = compat_cache_files(&cache_dir)?;
            let bytes = cache_files_size(&files)?;
            let locked_verified = verify_npm_locked_cache(project_dir)?;
            println!("Cache verified and compressed ({})", cache_dir.display());
            println!("Content verified: {} ({bytes} bytes)", files.len());
            println!("Index entries: {}", files.len());
            if locked_verified > 0 {
                println!("OMC lock entries verified: {locked_verified}");
            }
        }
        NpmCacheAction::List { pattern } => {
            let mut files = compat_cache_files(&cache_dir)?;
            if let Some(pattern) = pattern {
                files.retain(|path| compat_cache_pattern_matches(path, &cache_dir, &pattern));
            }
            files.sort();
            for path in files {
                println!("{}", compat_cache_display_path(&path, &cache_dir));
            }
        }
        NpmCacheAction::Remove { pattern } => {
            let mut files = compat_cache_files(&cache_dir)?;
            files.retain(|path| compat_cache_pattern_matches(path, &cache_dir, &pattern));
            let count = remove_cache_files(&files)?;
            prune_empty_cache_dirs(&cache_dir)?;
            println!("Files removed: {count}");
        }
        NpmCacheAction::Clean => {
            let count = compat_cache_files(&cache_dir)?.len();
            if cache_dir.exists() {
                fs::remove_dir_all(&cache_dir)?;
            }
            println!("Files removed: {count}");
        }
    }
    Ok(())
}

fn npm_cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".omc").join("cache").join("npm")
}

fn verify_npm_locked_cache(project_dir: &Path) -> Result<usize, OmcRegistryError> {
    let lockfile = project_dir.join("omc.lock");
    if !lockfile.exists() {
        return Ok(0);
    }
    let lock = read_lockfile(&lockfile)?;
    let mut verified = 0;
    for package in lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
    {
        let archive_path = absolutize_path(project_dir, PathBuf::from(&package.archive));
        let bytes = fs::read(&archive_path)?;
        let actual = pip_hash_digest(PipHashAlgorithm::Sha256, &bytes);
        if !package.sha256.eq_ignore_ascii_case(&actual) {
            return Err(OmcRegistryError::DigestMismatch {
                name: package.name.clone(),
                expected: format!("sha256:{}", package.sha256),
                actual: format!("sha256:{actual}"),
            });
        }
        verified += 1;
    }
    Ok(verified)
}

fn print_pip_cache(project_dir: &Path, action: PipCacheAction) -> Result<(), OmcRegistryError> {
    let cache_dir = pip_cache_dir(project_dir);
    match action {
        PipCacheAction::Dir => println!("{}", cache_dir.display()),
        PipCacheAction::Info => {
            let files = compat_cache_files(&cache_dir)?;
            let bytes = cache_files_size(&files)?;
            println!("Package index page cache location: {}", cache_dir.display());
            println!("Number of files: {}", files.len());
            println!("Size: {bytes} bytes");
        }
        PipCacheAction::List { pattern } => {
            let mut files = compat_cache_files(&cache_dir)?;
            if let Some(pattern) = pattern {
                files.retain(|path| compat_cache_pattern_matches(path, &cache_dir, &pattern));
            }
            files.sort();
            for path in files {
                println!("{}", compat_cache_display_path(&path, &cache_dir));
            }
        }
        PipCacheAction::Remove { pattern } => {
            let mut files = compat_cache_files(&cache_dir)?;
            files.retain(|path| compat_cache_pattern_matches(path, &cache_dir, &pattern));
            let count = remove_cache_files(&files)?;
            prune_empty_cache_dirs(&cache_dir)?;
            println!("Files removed: {count}");
        }
        PipCacheAction::Purge => {
            let count = compat_cache_files(&cache_dir)?.len();
            if cache_dir.exists() {
                fs::remove_dir_all(&cache_dir)?;
            }
            println!("Files removed: {count}");
        }
    }
    Ok(())
}

fn pip_cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".omc").join("cache").join("pypi")
}

fn compat_cache_files(cache_dir: &Path) -> Result<Vec<PathBuf>, OmcRegistryError> {
    let mut files = Vec::new();
    collect_cache_files(cache_dir, &mut files)?;
    Ok(files)
}

fn collect_cache_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), OmcRegistryError> {
    if !path.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_cache_files(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn cache_files_size(files: &[PathBuf]) -> Result<u64, OmcRegistryError> {
    let mut bytes = 0;
    for path in files {
        bytes += fs::metadata(path)?.len();
    }
    Ok(bytes)
}

fn remove_cache_files(files: &[PathBuf]) -> Result<usize, OmcRegistryError> {
    let mut count = 0;
    for path in files {
        fs::remove_file(path)?;
        count += 1;
    }
    Ok(count)
}

fn prune_empty_cache_dirs(root: &Path) -> Result<(), OmcRegistryError> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            prune_empty_cache_dirs(&path)?;
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(path)?;
            }
        }
    }
    Ok(())
}

fn compat_cache_pattern_matches(path: &Path, cache_dir: &Path, pattern: &str) -> bool {
    let display = compat_cache_display_path(path, cache_dir);
    wildcard_match(&display, pattern)
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| wildcard_match(name, pattern))
            .unwrap_or(false)
}

fn compat_cache_display_path(path: &Path, cache_dir: &Path) -> String {
    path.strip_prefix(cache_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .trim_start_matches(std::path::MAIN_SEPARATOR)
        .to_owned()
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return value.contains(pattern);
    }
    let mut rest = value;
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return true;
    }
    if !starts_with_wildcard {
        let Some(first) = parts.first() else {
            return true;
        };
        if !rest.starts_with(first) {
            return false;
        }
        rest = &rest[first.len()..];
    }
    for (index, part) in parts.iter().enumerate() {
        if index == 0 && !starts_with_wildcard {
            continue;
        }
        let Some(found) = rest.find(part) else {
            return false;
        };
        rest = &rest[found + part.len()..];
    }
    ends_with_wildcard || rest.is_empty()
}

fn print_pip_config(project_dir: &Path, action: PipConfigAction) -> Result<(), OmcRegistryError> {
    let values = pip_config_values(project_dir)?;
    match action {
        PipConfigAction::Get { keys, json } => {
            if json {
                if keys.len() == 1 {
                    let value = pip_config_value_for_key(&values, &keys[0])?;
                    println!("{}", serde_json::to_string_pretty(&value)?);
                } else {
                    let mut selected = BTreeMap::new();
                    for key in keys {
                        selected.insert(key.clone(), pip_config_value_for_key(&values, &key)?);
                    }
                    println!("{}", serde_json::to_string_pretty(&selected)?);
                }
            } else {
                for key in keys {
                    println!("{}", pip_config_value_for_key(&values, &key)?);
                }
            }
        }
        PipConfigAction::List { json } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&values)?);
            } else {
                for (key, value) in values {
                    println!("{key}={value}");
                }
            }
        }
    }
    Ok(())
}

fn pip_config_values(project_dir: &Path) -> Result<BTreeMap<String, String>, OmcRegistryError> {
    let snapshot = read_pip_config_snapshot(project_dir)?;
    let mut values = BTreeMap::from([
        ("global.index-url".to_owned(), snapshot.index_url),
        ("global.no-index".to_owned(), snapshot.no_index.to_string()),
    ]);
    if !snapshot.extra_index_urls.is_empty() {
        values.insert(
            "global.extra-index-url".to_owned(),
            snapshot.extra_index_urls.join(" "),
        );
    }
    if !snapshot.find_links.is_empty() {
        values.insert(
            "global.find-links".to_owned(),
            snapshot.find_links.join(" "),
        );
    }
    if let Some(value) = pip_binary_config_value(snapshot.binary_all, PypiBinaryMode::Source) {
        values.insert("global.no-binary".to_owned(), value);
    }
    if let Some(value) = pip_binary_config_value(snapshot.binary_all, PypiBinaryMode::Binary) {
        values.insert("global.only-binary".to_owned(), value);
    }
    for (package, mode) in snapshot.binary_packages {
        match mode {
            PypiBinaryMode::Source => values
                .entry("global.no-binary".to_owned())
                .and_modify(|value| {
                    if !value.is_empty() {
                        value.push(',');
                    }
                    value.push_str(&package);
                })
                .or_insert(package),
            PypiBinaryMode::Binary => values
                .entry("global.only-binary".to_owned())
                .and_modify(|value| {
                    if !value.is_empty() {
                        value.push(',');
                    }
                    value.push_str(&package);
                })
                .or_insert(package),
        };
    }
    Ok(values)
}

fn pip_binary_config_value(mode: Option<PypiBinaryMode>, target: PypiBinaryMode) -> Option<String> {
    (mode == Some(target)).then(|| ":all:".to_owned())
}

fn pip_config_value_for_key(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<String, OmcRegistryError> {
    pip_config_key_aliases(key)
        .into_iter()
        .find_map(|key| values.get(&key).cloned())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("pip config key `{key}` is not set"))
        })
}

fn pip_config_key_aliases(key: &str) -> Vec<String> {
    let normalized = key.trim().to_ascii_lowercase().replace('_', "-");
    if let Some((section, name)) = normalized.split_once('.') {
        if matches!(section, "global" | "install") {
            return vec![normalized.clone(), format!("global.{name}")];
        }
        return vec![normalized];
    }
    vec![
        format!("global.{normalized}"),
        format!("install.{normalized}"),
    ]
}

fn print_lock_only_report(project_dir: &Path) {
    println!("lockfile {}", project_dir.join("omc.lock").display());
}

fn print_npm_maintenance_report(command: NpmMaintenanceCommand, install: &InstallReport) {
    match command {
        NpmMaintenanceCommand::Prune => println!("pruned OMC npm install state"),
        NpmMaintenanceCommand::Dedupe => println!("deduped OMC npm install state"),
    }
    print_install_report(install);
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

#[derive(Debug)]
struct PipOutdatedPackage {
    name: String,
    version: String,
    latest_version: String,
    latest_filetype: String,
}

fn print_locked_pip_outdated(
    project_dir: &Path,
    format: PipListFormat,
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
) -> Result<(), OmcRegistryError> {
    if format == PipListFormat::Freeze {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip list --outdated does not support --format=freeze".to_owned(),
        ));
    }

    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let mut rows = Vec::new();
    for package in lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
    {
        let listing = match read_pypi_available_versions(
            project_dir,
            &package.name,
            index_url.clone(),
            extra_index_urls.clone(),
            find_links.clone(),
            no_index,
        ) {
            Ok(listing) => listing,
            Err(OmcRegistryError::PackageNotFound(_)) => continue,
            Err(error) => return Err(error),
        };
        let Some(latest_version) = listing.versions.first() else {
            continue;
        };
        if compare_pypi_versions(latest_version, &package.version).is_gt() {
            rows.push(PipOutdatedPackage {
                name: package.name.clone(),
                version: package.version.clone(),
                latest_version: latest_version.clone(),
                latest_filetype: pip_locked_package_filetype(&package).to_owned(),
            });
        }
    }
    rows.sort_by(|left, right| left.name.cmp(&right.name));

    match format {
        PipListFormat::Columns => {
            if !rows.is_empty() {
                println!("Package Version Latest Type");
                for row in rows {
                    println!(
                        "{} {} {} {}",
                        row.name, row.version, row.latest_version, row.latest_filetype
                    );
                }
            }
        }
        PipListFormat::Json => {
            let packages = rows
                .into_iter()
                .map(|row| {
                    serde_json::json!({
                        "name": row.name,
                        "version": row.version,
                        "latest_version": row.latest_version,
                        "latest_filetype": row.latest_filetype,
                    })
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&packages)?);
        }
        PipListFormat::Freeze => unreachable!("freeze format rejected before listing"),
    }
    Ok(())
}

fn pip_locked_package_filetype(package: &LockedPackage) -> &'static str {
    let source = if package.source_url.is_empty() {
        package.archive.as_str()
    } else {
        package.source_url.as_str()
    }
    .to_ascii_lowercase();
    if source.ends_with(".tar.gz")
        || source.ends_with(".tar.bz2")
        || source.ends_with(".tar.xz")
        || source.ends_with(".zip")
        || source.ends_with(".tgz")
    {
        "sdist"
    } else {
        "wheel"
    }
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
        "prune" => {
            parse_npm_maintenance_args("npm prune", NpmMaintenanceCommand::Prune, &args[1..])
        }
        "dedupe" | "ddp" | "find-dupes" => {
            parse_npm_maintenance_args("npm dedupe", NpmMaintenanceCommand::Dedupe, &args[1..])
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
        "outdated" => parse_npm_outdated_args(&args[1..]),
        "audit" => parse_npm_audit_args(&args[1..]),
        "cache" => parse_npm_cache_args(&args[1..]),
        "view" | "info" | "show" | "v" => parse_npm_view_args(&args[1..]),
        "config" | "c" => parse_npm_config_args(&args[1..]),
        "get" => parse_npm_config_get_args(&args[1..]),
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

fn parse_npm_maintenance_args(
    command: &str,
    maintenance: NpmMaintenanceCommand,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--dry-run" | "--json" | "--silent" | "-s") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_maintenance_equals_value_flag(arg) {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        omit_dev,
        allow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    if !positionals.is_empty() {
        return Err(unsupported_compat_arg(command, &positionals[0]));
    }
    Ok(NpmCompatAction::Maintenance {
        command: maintenance,
        omit_dev,
        allow,
        allow_all_host,
    })
}

fn npm_maintenance_equals_value_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
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

fn parse_npm_cache_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut force = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--force" | "-f") {
            force = true;
        } else if matches!(
            arg.as_str(),
            "--json"
                | "--parseable"
                | "-p"
                | "--long"
                | "--silent"
                | "-s"
                | "--prefer-offline"
                | "--prefer-online"
                | "--offline"
        ) {
        } else if matches!(arg.as_str(), "--cache" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_cache_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm cache", arg));
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let Some(command) = filtered.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm cache needs a command such as verify, ls, rm, or clean".to_owned(),
        ));
    };
    let rest = &filtered[1..];
    let action = match command {
        "verify" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("npm cache verify", &rest[0]));
            }
            NpmCacheAction::Verify
        }
        "ls" | "list" => {
            if rest.len() > 1 {
                return Err(unsupported_compat_arg("npm cache ls", &rest[1]));
            }
            NpmCacheAction::List {
                pattern: rest.first().cloned(),
            }
        }
        "rm" | "remove" | "delete" => {
            if rest.len() != 1 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm cache rm needs exactly one pattern".to_owned(),
                ));
            }
            NpmCacheAction::Remove {
                pattern: rest[0].clone(),
            }
        }
        "clean" | "clear" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("npm cache clean", &rest[0]));
            }
            if !force {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm cache clean needs --force".to_owned(),
                ));
            }
            NpmCacheAction::Clean
        }
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported npm cache command `{other}`"
            )))
        }
    };
    Ok(NpmCompatAction::Cache { action })
}

fn npm_cache_equals_value_flag(arg: &str) -> bool {
    ["--cache=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_outdated_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut parseable = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(arg.as_str(), "--parseable" | "-p") {
            parseable = true;
        } else if matches!(
            arg.as_str(),
            "--all"
                | "--long"
                | "--silent"
                | "-s"
                | "--global"
                | "-g"
                | "--dev"
                | "--prod"
                | "--production"
                | "--color=false"
        ) {
        } else if matches!(
            arg.as_str(),
            "--depth" | "--omit" | "--include" | "--loglevel" | "--userconfig"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_outdated_equals_value_flag(arg) {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        npm_registry,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    if !positionals.is_empty() {
        return Err(unsupported_compat_arg("npm outdated", &positionals[0]));
    }

    Ok(NpmCompatAction::Outdated {
        json,
        parseable,
        npm_registry,
    })
}

fn npm_outdated_equals_value_flag(arg: &str) -> bool {
    [
        "--depth=",
        "--omit=",
        "--include=",
        "--loglevel=",
        "--userconfig=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_config_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(NpmCompatAction::Config {
            action: NpmConfigAction::List { json: false },
            npm_registry: None,
            userconfig: None,
        });
    };
    match command {
        "get" => parse_npm_config_get_args(&args[1..]),
        "list" | "ls" => parse_npm_config_list_args(&args[1..]),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm config command `{other}`"
        ))),
    }
}

fn parse_npm_view_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(arg.as_str(), "--userconfig" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "--long")
            || npm_view_equals_value_flag(arg)
        {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        npm_registry,
        mut positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm view needs a package".to_owned(),
        ));
    }
    let spec = positionals.remove(0);
    Ok(NpmCompatAction::View {
        spec,
        fields: positionals,
        json,
        npm_registry,
    })
}

fn npm_view_equals_value_flag(arg: &str) -> bool {
    ["--userconfig=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_config_get_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let NpmConfigArgs {
        json,
        npm_registry,
        userconfig,
        positionals,
    } = parse_npm_config_common_args(args)?;
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config get needs at least one key".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Config {
        action: NpmConfigAction::Get {
            keys: positionals,
            json,
        },
        npm_registry,
        userconfig,
    })
}

fn parse_npm_config_list_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let NpmConfigArgs {
        json,
        npm_registry,
        userconfig,
        positionals,
    } = parse_npm_config_common_args(args)?;
    if !positionals.is_empty() {
        return Err(unsupported_compat_arg("npm config list", &positionals[0]));
    }
    Ok(NpmCompatAction::Config {
        action: NpmConfigAction::List { json },
        npm_registry,
        userconfig,
    })
}

#[derive(Debug)]
struct NpmConfigArgs {
    json: bool,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
    positionals: Vec<String>,
}

fn parse_npm_config_common_args(args: &[String]) -> Result<NpmConfigArgs, OmcRegistryError> {
    let mut json = false;
    let mut userconfig = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--userconfig" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--userconfig needs a path".to_owned(),
                ));
            };
            userconfig = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(path));
        } else if matches!(
            arg.as_str(),
            "--global" | "-g" | "--long" | "-l" | "--parseable"
        ) {
        } else if arg == "--location" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--location needs a value".to_owned(),
                ));
            }
        } else if arg.starts_with("--location=") {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        npm_registry,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    Ok(NpmConfigArgs {
        json,
        npm_registry,
        userconfig,
        positionals,
    })
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
        "download" => parse_pip_download_args(&args[1..]),
        "uninstall" | "remove" => parse_pip_uninstall_args(&args[1..]),
        "show" => parse_pip_show_args(&args[1..]),
        "hash" => parse_pip_hash_args(&args[1..]),
        "cache" => parse_pip_cache_args(&args[1..]),
        "check" => {
            parse_pip_check_args(&args[1..])?;
            Ok(PipCompatAction::Check)
        }
        "freeze" => {
            parse_pip_freeze_args(&args[1..])?;
            Ok(PipCompatAction::Freeze)
        }
        "list" => parse_pip_list_args(&args[1..]),
        "index" => parse_pip_index_args(&args[1..]),
        "config" => parse_pip_config_args(&args[1..]),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip compatibility command `{other}`"
        ))),
    }
}

fn parse_pip_index_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let PipIndexArgs {
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        json,
        mut positionals,
    } = parse_pip_index_common_args(args)?;
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip index needs a command such as versions".to_owned(),
        ));
    }
    let command = positionals.remove(0);
    match command.as_str() {
        "versions" => {
            if positionals.len() != 1 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip index versions needs exactly one package".to_owned(),
                ));
            }
            Ok(PipCompatAction::IndexVersions {
                package: positionals.remove(0),
                index_url,
                extra_index_urls,
                find_links,
                no_index,
                json,
            })
        }
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip index command `{other}`"
        ))),
    }
}

#[derive(Debug)]
struct PipIndexArgs {
    index_url: Option<String>,
    extra_index_urls: Vec<String>,
    find_links: Vec<String>,
    no_index: bool,
    json: bool,
    positionals: Vec<String>,
}

fn parse_pip_index_common_args(args: &[String]) -> Result<PipIndexArgs, OmcRegistryError> {
    let mut parsed = PipIndexArgs {
        index_url: None,
        extra_index_urls: Vec::new(),
        find_links: Vec::new(),
        no_index: false,
        json: false,
        positionals: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            parsed.json = true;
        } else if arg == "-i" || arg == "--index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            parsed.index_url = Some(url.clone());
        } else if let Some(url) = arg.strip_prefix("--index-url=") {
            parsed.index_url = Some(url.to_owned());
        } else if arg == "--extra-index-url" {
            index += 1;
            let Some(url) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a URL"
                )));
            };
            parsed.extra_index_urls.push(url.clone());
        } else if let Some(url) = arg.strip_prefix("--extra-index-url=") {
            parsed.extra_index_urls.push(url.to_owned());
        } else if arg == "-f" || arg == "--find-links" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path or URL"
                )));
            };
            parsed.find_links.push(value.clone());
        } else if let Some(value) = arg.strip_prefix("--find-links=") {
            parsed.find_links.push(value.to_owned());
        } else if arg == "--no-index" {
            parsed.no_index = true;
        } else if matches!(
            arg.as_str(),
            "--pre"
                | "--disable-pip-version-check"
                | "--isolated"
                | "--no-cache-dir"
                | "--ignore-requires-python"
                | "-v"
                | "--verbose"
                | "-q"
                | "--quiet"
        ) {
        } else if pip_index_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_index_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip index", arg));
        } else {
            parsed.positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(parsed)
}

fn pip_index_ignored_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--trusted-host"
            | "--timeout"
            | "--retries"
            | "--cert"
            | "--client-cert"
            | "--proxy"
            | "--cache-dir"
            | "--log"
            | "--platform"
            | "--python-version"
            | "--implementation"
            | "--abi"
    )
}

fn pip_index_ignored_equals_flag(arg: &str) -> bool {
    [
        "--trusted-host=",
        "--timeout=",
        "--retries=",
        "--cert=",
        "--client-cert=",
        "--proxy=",
        "--cache-dir=",
        "--log=",
        "--platform=",
        "--python-version=",
        "--implementation=",
        "--abi=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn parse_pip_config_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let PipConfigArgs {
        json,
        mut positionals,
    } = parse_pip_config_common_args(args)?;
    let command = if positionals.is_empty() {
        "list".to_owned()
    } else {
        positionals.remove(0)
    };
    match command.as_str() {
        "get" => {
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip config get needs at least one key".to_owned(),
                ));
            }
            Ok(PipCompatAction::Config {
                action: PipConfigAction::Get {
                    keys: positionals,
                    json,
                },
            })
        }
        "list" => {
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("pip config list", &positionals[0]));
            }
            Ok(PipCompatAction::Config {
                action: PipConfigAction::List { json },
            })
        }
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip config command `{other}`"
        ))),
    }
}

#[derive(Debug)]
struct PipConfigArgs {
    json: bool,
    positionals: Vec<String>,
}

fn parse_pip_config_common_args(args: &[String]) -> Result<PipConfigArgs, OmcRegistryError> {
    let mut json = false;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(
            arg.as_str(),
            "--user" | "--global" | "--site" | "--isolated" | "-v" | "--verbose" | "-q" | "--quiet"
        ) {
        } else if arg == "--editor" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--editor needs a value".to_owned(),
                ));
            }
        } else if arg.starts_with("--editor=") {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip config", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(PipConfigArgs { json, positionals })
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

fn parse_pip_hash_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut algorithm = PipHashAlgorithm::Sha256;
    let mut paths = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-a" || arg == "--algorithm" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            algorithm = parse_pip_hash_algorithm(value)?;
        } else if let Some(value) = arg.strip_prefix("--algorithm=") {
            algorithm = parse_pip_hash_algorithm(value)?;
        } else if matches!(
            arg.as_str(),
            "--disable-pip-version-check" | "-v" | "--verbose" | "-q" | "--quiet"
        ) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip hash", arg));
        } else {
            paths.push(PathBuf::from(arg));
        }
        index += 1;
    }
    if paths.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip hash needs at least one file".to_owned(),
        ));
    }
    Ok(PipCompatAction::Hash { algorithm, paths })
}

fn parse_pip_hash_algorithm(value: &str) -> Result<PipHashAlgorithm, OmcRegistryError> {
    match value.to_ascii_lowercase().as_str() {
        "sha256" => Ok(PipHashAlgorithm::Sha256),
        "sha384" => Ok(PipHashAlgorithm::Sha384),
        "sha512" => Ok(PipHashAlgorithm::Sha512),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported pip hash algorithm `{other}`"
        ))),
    }
}

fn parse_pip_cache_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut filtered = Vec::new();
    for arg in args {
        if matches!(
            arg.as_str(),
            "--disable-pip-version-check" | "-v" | "--verbose" | "-q" | "--quiet"
        ) {
            continue;
        }
        if arg.starts_with('-') {
            return Err(unsupported_compat_arg("pip cache", arg));
        }
        filtered.push(arg.clone());
    }
    let Some(command) = filtered.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip cache needs a command such as dir, list, remove, or purge".to_owned(),
        ));
    };
    let rest = &filtered[1..];
    let action = match command {
        "dir" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("pip cache dir", &rest[0]));
            }
            PipCacheAction::Dir
        }
        "info" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("pip cache info", &rest[0]));
            }
            PipCacheAction::Info
        }
        "list" => {
            if rest.len() > 1 {
                return Err(unsupported_compat_arg("pip cache list", &rest[1]));
            }
            PipCacheAction::List {
                pattern: rest.first().cloned(),
            }
        }
        "remove" | "rm" => {
            if rest.len() != 1 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip cache remove needs exactly one pattern".to_owned(),
                ));
            }
            PipCacheAction::Remove {
                pattern: rest[0].clone(),
            }
        }
        "purge" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("pip cache purge", &rest[0]));
            }
            PipCacheAction::Purge
        }
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported pip cache command `{other}`"
            )))
        }
    };
    Ok(PipCompatAction::Cache { action })
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

fn parse_pip_download_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
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
    let mut destination = PathBuf::from(".");
    let mut archive_references = Vec::new();
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
        } else if arg == "-d" || arg == "--dest" || arg == "--destination-dir" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            destination = PathBuf::from(path);
        } else if let Some(path) = arg
            .strip_prefix("--dest=")
            .or_else(|| arg.strip_prefix("--destination-dir="))
        {
            destination = PathBuf::from(path);
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
        } else if matches!(
            arg.as_str(),
            "--disable-pip-version-check"
                | "--no-cache-dir"
                | "--ignore-requires-python"
                | "--no-build-isolation"
                | "--use-pep517"
                | "--no-use-pep517"
                | "-v"
                | "--verbose"
                | "-q"
                | "--quiet"
        ) || arg.starts_with("--trusted-host=")
        {
        } else if pip_ignored_download_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_ignored_download_equals_flag(arg) {
        } else if is_pip_archive_arg(arg) {
            archive_references.push(arg.clone());
        } else if is_pip_local_directory_arg(arg) {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "pip download cannot build local directory `{arg}`; pass a wheel or sdist archive"
            )));
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

    Ok(PipCompatAction::Download(Box::new(PipDownloadAction {
        specs: positionals.into_iter().filter(|spec| spec != ".").collect(),
        requirements,
        constraints,
        archive_references,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        binary_all,
        binary_packages,
        require_hashes,
        no_deps,
        destination,
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

fn pip_ignored_download_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--progress-bar"
            | "--retries"
            | "--timeout"
            | "--exists-action"
            | "--keyring-provider"
            | "--cert"
            | "--client-cert"
            | "--proxy"
            | "--cache-dir"
            | "--log"
            | "--platform"
            | "--python-version"
            | "--implementation"
            | "--abi"
    )
}

fn pip_ignored_download_equals_flag(arg: &str) -> bool {
    [
        "--progress-bar=",
        "--retries=",
        "--timeout=",
        "--exists-action=",
        "--keyring-provider=",
        "--cert=",
        "--client-cert=",
        "--proxy=",
        "--cache-dir=",
        "--log=",
        "--platform=",
        "--python-version=",
        "--implementation=",
        "--abi=",
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

fn parse_pip_list_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut format = PipListFormat::Columns;
    let mut outdated = false;
    let mut index_url = None;
    let mut extra_index_urls = Vec::new();
    let mut find_links = Vec::new();
    let mut no_index = false;
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
        } else if arg == "-o" || arg == "--outdated" {
            outdated = true;
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
        } else if matches!(
            arg.as_str(),
            "--local"
                | "--user"
                | "--editable"
                | "--include-editable"
                | "--exclude-editable"
                | "--disable-pip-version-check"
                | "--pre"
                | "--not-required"
                | "--ignore-requires-python"
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
        } else if pip_index_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_index_ignored_equals_flag(arg) {
        } else {
            return Err(unsupported_compat_arg("pip list", arg));
        }
        index += 1;
    }
    if outdated && format == PipListFormat::Freeze {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip list --outdated does not support --format=freeze".to_owned(),
        ));
    }
    Ok(PipCompatAction::List {
        format,
        outdated,
        index_url,
        extra_index_urls,
        find_links,
        no_index,
    })
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
                "prune",
                "--omit=dev",
                "--loglevel=silent",
                "--allow-all-host",
            ]))
            .unwrap(),
            NpmCompatAction::Maintenance {
                command: NpmMaintenanceCommand::Prune,
                omit_dev: true,
                allow: Vec::new(),
                allow_all_host: true,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["dedupe", "--dry-run", "--cache", "/tmp/npm-cache"]))
                .unwrap(),
            NpmCompatAction::Maintenance {
                command: NpmMaintenanceCommand::Dedupe,
                omit_dev: false,
                allow: Vec::new(),
                allow_all_host: false,
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
        assert_eq!(
            parse_npm_compat_action(&args(&["cache", "verify", "--cache=/tmp/npm-cache"])).unwrap(),
            NpmCompatAction::Cache {
                action: NpmCacheAction::Verify,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["cache", "ls", "left-pad"])).unwrap(),
            NpmCompatAction::Cache {
                action: NpmCacheAction::List {
                    pattern: Some("left-pad".to_owned()),
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["cache", "rm", "left-pad"])).unwrap(),
            NpmCompatAction::Cache {
                action: NpmCacheAction::Remove {
                    pattern: "left-pad".to_owned(),
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["cache", "clean", "--force"])).unwrap(),
            NpmCompatAction::Cache {
                action: NpmCacheAction::Clean,
            }
        );
        assert!(parse_npm_compat_action(&args(&["cache", "clean"])).is_err());
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "outdated",
                "--json",
                "--parseable",
                "--depth=0",
                "--registry",
                "https://registry.example.invalid/npm",
            ]))
            .unwrap(),
            NpmCompatAction::Outdated {
                json: true,
                parseable: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "view",
                "left-pad@1.3.0",
                "version",
                "dist.tarball",
                "--json",
                "--registry",
                "https://registry.example.invalid/npm",
                "--userconfig=ci.npmrc",
            ]))
            .unwrap(),
            NpmCompatAction::View {
                spec: "left-pad@1.3.0".to_owned(),
                fields: vec!["version".to_owned(), "dist.tarball".to_owned()],
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["info", "@scope/pkg", "versions"])).unwrap(),
            NpmCompatAction::View {
                spec: "@scope/pkg".to_owned(),
                fields: vec!["versions".to_owned()],
                json: false,
                npm_registry: None,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "config",
                "get",
                "registry",
                "--json",
                "--userconfig",
                "ci.npmrc",
                "--location=project",
            ]))
            .unwrap(),
            NpmCompatAction::Config {
                action: NpmConfigAction::Get {
                    keys: vec!["registry".to_owned()],
                    json: true,
                },
                npm_registry: None,
                userconfig: Some(PathBuf::from("ci.npmrc")),
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "get",
                "prefix",
                "--registry",
                "https://registry.example.invalid/npm",
            ]))
            .unwrap(),
            NpmCompatAction::Config {
                action: NpmConfigAction::Get {
                    keys: vec!["prefix".to_owned()],
                    json: false,
                },
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: None,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["config", "list", "--json", "--long"])).unwrap(),
            NpmCompatAction::Config {
                action: NpmConfigAction::List { json: true },
                npm_registry: None,
                userconfig: None,
            }
        );
        assert!(parse_npm_compat_action(&args(&["config", "set", "registry", "x"])).is_err());
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

        let action = parse_pip_compat_action(&args(&[
            "download",
            "-r",
            "requirements.txt",
            "-c",
            "constraints.txt",
            "--dest",
            "wheelhouse",
            "--index-url=https://mirror.example/simple",
            "--find-links=vendor",
            "--no-index",
            "--require-hashes",
            "--no-deps",
            "--only-binary=:all:",
            "--trusted-host",
            "mirror.example",
            "--allow",
            "http:files.example",
            "requests==2.32.3",
        ]))
        .unwrap();

        assert_eq!(
            action,
            PipCompatAction::Download(Box::new(PipDownloadAction {
                specs: vec!["requests==2.32.3".to_owned()],
                requirements: vec![PathBuf::from("requirements.txt")],
                constraints: vec![PathBuf::from("constraints.txt")],
                archive_references: Vec::new(),
                index_url: Some("https://mirror.example/simple".to_owned()),
                extra_index_urls: Vec::new(),
                find_links: vec!["vendor".to_owned()],
                no_index: true,
                binary_all: Some(PypiBinaryMode::Binary),
                binary_packages: BTreeMap::new(),
                require_hashes: true,
                no_deps: true,
                destination: PathBuf::from("wheelhouse"),
                allow: vec!["http:files.example".to_owned()],
                allow_all_host: false,
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
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "hash",
                "--algorithm",
                "sha512",
                "--disable-pip-version-check",
                "dist/pkg.whl",
            ]))
            .unwrap(),
            PipCompatAction::Hash {
                algorithm: PipHashAlgorithm::Sha512,
                paths: vec![PathBuf::from("dist/pkg.whl")],
            }
        );
        assert!(
            parse_pip_compat_action(&args(&["hash", "--algorithm", "md5", "pkg.whl"])).is_err()
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["cache", "dir"])).unwrap(),
            PipCompatAction::Cache {
                action: PipCacheAction::Dir,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["cache", "list", "idna"])).unwrap(),
            PipCompatAction::Cache {
                action: PipCacheAction::List {
                    pattern: Some("idna".to_owned()),
                },
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["cache", "remove", "idna"])).unwrap(),
            PipCompatAction::Cache {
                action: PipCacheAction::Remove {
                    pattern: "idna".to_owned(),
                },
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["cache", "purge", "--disable-pip-version-check"]))
                .unwrap(),
            PipCompatAction::Cache {
                action: PipCacheAction::Purge,
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
                outdated: false,
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: Vec::new(),
                no_index: false,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["list", "--format", "json"])).unwrap(),
            PipCompatAction::List {
                format: PipListFormat::Json,
                outdated: false,
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: Vec::new(),
                no_index: false,
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
                outdated: false,
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: Vec::new(),
                no_index: false,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "list",
                "--outdated",
                "--format=json",
                "--no-index",
                "--find-links=wheelhouse",
                "--timeout",
                "5",
            ]))
            .unwrap(),
            PipCompatAction::List {
                format: PipListFormat::Json,
                outdated: true,
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: vec!["wheelhouse".to_owned()],
                no_index: true,
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "index",
                "versions",
                "idna",
                "--json",
                "--no-index",
                "--find-links",
                "wheelhouse",
                "--disable-pip-version-check",
            ]))
            .unwrap(),
            PipCompatAction::IndexVersions {
                package: "idna".to_owned(),
                index_url: None,
                extra_index_urls: Vec::new(),
                find_links: vec!["wheelhouse".to_owned()],
                no_index: true,
                json: true,
            }
        );
        assert!(parse_pip_compat_action(&args(&["index", "foo", "requests"])).is_err());
        assert!(
            parse_pip_compat_action(&args(&["list", "--outdated", "--format=freeze"])).is_err()
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "config",
                "--user",
                "get",
                "global.index-url",
                "--json",
            ]))
            .unwrap(),
            PipCompatAction::Config {
                action: PipConfigAction::Get {
                    keys: vec!["global.index-url".to_owned()],
                    json: true,
                },
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["config", "list", "--verbose"])).unwrap(),
            PipCompatAction::Config {
                action: PipConfigAction::List { json: false },
            }
        );
        assert!(
            parse_pip_compat_action(&args(&["config", "set", "global.index-url", "x"])).is_err()
        );
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
