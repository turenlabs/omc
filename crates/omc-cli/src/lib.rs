use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::{env, ffi::OsString, fs};

use clap::{Parser, Subcommand};
use flate2::write::GzEncoder;
use flate2::Compression;
use omc_cap::Capability;
use omc_registry::{
    add_manifest_npm_local_paths, add_manifest_policy_grants, add_package_graph,
    apply_pypi_binary_option, check_pypi_lock, compare_npm_versions, compare_pypi_versions,
    init_project, install_locked_packages, install_locked_project, install_project, lock_project,
    parse_capability_grant, parse_npm_direct_archive_reference,
    parse_pypi_direct_archive_reference, parse_pypi_vcs_requirement, read_constraint_files,
    read_lockfile, read_manifest, read_npm_config_snapshot, read_npm_package_metadata,
    read_npm_search, read_npm_workspace_packages, read_package_scripts, read_pip_config_snapshot,
    read_pypi_available_versions, read_requirements_files, remove_manifest_dependency, Behavior,
    Ecosystem, InstallReport, LinkOptions, LockedPackage, LockedPythonVcsDependency,
    NpmSearchPackage, NpmWorkspacePackage, OmcRegistryError, PackageSpec, ProjectRequirements,
    PypiBinaryMode, PypiCheckIssue, PythonLocalRequirement, PythonVcsRequirement, Verdict,
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
    Help {
        topic: Option<String>,
    },
    Version,
    Init {
        action: NpmInitAction,
    },
    PackageVersion {
        action: NpmVersionAction,
    },
    Install {
        specs: Vec<String>,
        archive_references: Vec<String>,
        local_paths: Vec<PathBuf>,
        save: bool,
        dev: bool,
        omit_dev: bool,
        lock_only: bool,
        dry_run: bool,
        npm_registry: Option<String>,
        allow: Vec<String>,
        allow_all_host: bool,
    },
    InstallTest {
        command: String,
        use_ci: bool,
        specs: Vec<String>,
        archive_references: Vec<String>,
        local_paths: Vec<PathBuf>,
        save: bool,
        dev: bool,
        omit_dev: bool,
        lock_only: bool,
        dry_run: bool,
        npm_registry: Option<String>,
        allow: Vec<String>,
        allow_all_host: bool,
        test_args: Vec<String>,
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
        packages: Vec<String>,
        omit_dev: bool,
        allow: Vec<String>,
        allow_all_host: bool,
    },
    RunScript {
        command: String,
        name: String,
        args: Vec<String>,
        if_present: bool,
        workspaces: Vec<String>,
        all_workspaces: bool,
        include_workspace_root: bool,
    },
    RunList {
        action: NpmRunListAction,
    },
    Exec {
        command: String,
        args: Vec<String>,
    },
    Path {
        kind: NpmPathKind,
    },
    List {
        action: NpmListAction,
    },
    Explain {
        specs: Vec<String>,
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
    Fund {
        action: NpmFundAction,
    },
    Cache {
        action: NpmCacheAction,
    },
    Pkg {
        action: NpmPkgAction,
    },
    Pack {
        action: NpmPackAction,
    },
    Search {
        action: NpmSearchAction,
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
    Rebuild,
}

#[derive(Debug, PartialEq, Eq)]
struct NpmListAction {
    json: bool,
    packages: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct NpmRunListAction {
    json: bool,
    workspaces: Vec<String>,
    all_workspaces: bool,
    include_workspace_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct NpmFundAction {
    json: bool,
    package: Option<String>,
    workspaces: Vec<String>,
    all_workspaces: bool,
    include_workspace_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct NpmInitAction {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    main: Option<String>,
    license: Option<String>,
    scope: Option<String>,
    private: bool,
    package_type: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum NpmVersionAction {
    Current {
        json: bool,
    },
    Bump {
        spec: String,
        preid: Option<String>,
        allow_same_version: bool,
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
enum NpmCacheAction {
    Verify,
    List { pattern: Option<String> },
    Remove { pattern: String },
    Clean,
}

#[derive(Debug, PartialEq, Eq)]
enum NpmPkgAction {
    Get {
        fields: Vec<String>,
    },
    Set {
        assignments: Vec<(String, serde_json::Value)>,
    },
    Delete {
        fields: Vec<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct NpmPackAction {
    packages: Vec<NpmPackInput>,
    destination: PathBuf,
    json: bool,
    dry_run: bool,
    npm_registry: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct NpmSearchAction {
    query: String,
    json: bool,
    parseable: bool,
    limit: usize,
    npm_registry: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum NpmPackInput {
    Local(PathBuf),
    Registry(String),
}

#[derive(Debug, PartialEq, Eq)]
enum NpmConfigAction {
    Get { keys: Vec<String>, json: bool },
    List { json: bool },
    Set { assignments: Vec<(String, String)> },
    Delete { keys: Vec<String> },
}

#[derive(Debug, PartialEq, Eq)]
enum PipCompatAction {
    Help {
        topic: Option<String>,
    },
    Version,
    Install(Box<PipInstallAction>),
    Download(Box<PipDownloadAction>),
    Wheel(Box<PipDownloadAction>),
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
    Debug {
        action: PipDebugAction,
    },
    Inspect,
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

#[derive(Debug, PartialEq, Eq)]
struct PipDebugAction {
    verbose: bool,
    platform: Option<String>,
    python_version: Option<String>,
    implementation: Option<String>,
    abis: Vec<String>,
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
    report: Option<PathBuf>,
    dry_run: bool,
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
    vcs_requirements: Vec<PythonVcsRequirement>,
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
    Get {
        keys: Vec<String>,
        json: bool,
    },
    List {
        json: bool,
    },
    Set {
        assignments: Vec<(String, String)>,
        location: PipConfigLocation,
    },
    Unset {
        keys: Vec<String>,
        location: PipConfigLocation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipConfigLocation {
    Auto,
    User,
    Site,
    Global,
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

fn write_pip_install_report(
    project_dir: &Path,
    report_path: Option<&Path>,
    install: &InstallReport,
) -> Result<(), OmcRegistryError> {
    write_pip_install_report_from(project_dir, project_dir, report_path, install)
}

fn write_pip_install_report_from(
    lock_project_dir: &Path,
    output_project_dir: &Path,
    report_path: Option<&Path>,
    install: &InstallReport,
) -> Result<(), OmcRegistryError> {
    let Some(report_path) = report_path else {
        return Ok(());
    };
    let report = pip_install_report_json(lock_project_dir, install)?;
    let report = serde_json::to_string_pretty(&report)?;
    if report_path == Path::new("-") {
        println!("{report}");
    } else {
        let report_path = absolutize_path(output_project_dir, report_path.to_path_buf());
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(report_path, format!("{report}\n"))?;
    }
    Ok(())
}

fn pip_install_report_json(
    project_dir: &Path,
    install: &InstallReport,
) -> Result<serde_json::Value, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let install_entries = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .map(pip_install_report_entry)
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "version": "1",
        "pip_version": format!("omc-{}", env!("CARGO_PKG_VERSION")),
        "install": install_entries,
        "environment": {
            "implementation_name": "omc",
            "implementation_version": env!("CARGO_PKG_VERSION"),
            "os_name": env::consts::OS,
            "platform_machine": env::consts::ARCH,
            "platform_system": env::consts::OS,
        },
        "omc": {
            "python_site_packages": install.python_site_packages,
            "python_bin_dir": install.python_bin_dir,
            "python_scripts": install.python_scripts,
            "pypi_packages": install.pypi_packages,
        },
    }))
}

fn pip_install_report_entry(package: LockedPackage) -> serde_json::Value {
    serde_json::json!({
        "download_info": {
            "url": package.source_url,
            "archive_info": {
                "hashes": {
                    "sha256": package.sha256,
                },
            },
        },
        "is_direct": false,
        "is_yanked": false,
        "requested": true,
        "metadata": {
            "metadata_version": "2.1",
            "name": package.name,
            "version": package.version,
        },
    })
}

struct TempOmcProject {
    path: PathBuf,
}

impl TempOmcProject {
    fn new(prefix: &str, source_project_dir: &Path) -> Result<Self, OmcRegistryError> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| OmcRegistryError::UnsupportedSpec(error.to_string()))?
            .as_nanos();
        let path = env::temp_dir().join(format!("omc-{prefix}-{}-{nonce}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        for file in [
            "omc.toml",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ] {
            let source = source_project_dir.join(file);
            if source.exists() {
                fs::copy(source, path.join(file))?;
            }
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempOmcProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
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
    run_package_script_in_dir(
        project_dir,
        project_dir,
        npm_command,
        name,
        args,
        if_present,
    )
}

fn run_package_script_with_npm_command_for_workspaces(
    project_dir: &Path,
    npm_command: &str,
    name: &str,
    args: &[String],
    if_present: bool,
    targets: NpmScriptTargets<'_>,
) -> Result<ExitCode, OmcRegistryError> {
    let script_dirs = npm_script_target_dirs(
        project_dir,
        targets.workspaces,
        targets.all_workspaces,
        targets.include_workspace_root,
    )?;
    for script_dir in script_dirs {
        let status = run_package_script_in_dir(
            project_dir,
            &script_dir,
            npm_command,
            name,
            args,
            if_present,
        )?;
        if status != ExitCode::SUCCESS {
            return Ok(status);
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Clone, Copy)]
struct NpmScriptTargets<'a> {
    workspaces: &'a [String],
    all_workspaces: bool,
    include_workspace_root: bool,
}

fn run_package_script_in_dir(
    project_dir: &Path,
    script_dir: &Path,
    npm_command: &str,
    name: &str,
    args: &[String],
    if_present: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let script_dir = script_dir.to_path_buf();
    let scripts = read_package_scripts(&script_dir)?;
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
            &script_dir,
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

fn npm_script_target_dirs(
    project_dir: &Path,
    workspaces: &[String],
    all_workspaces: bool,
    include_workspace_root: bool,
) -> Result<Vec<PathBuf>, OmcRegistryError> {
    if workspaces.is_empty() && !all_workspaces {
        return Ok(vec![project_dir.to_path_buf()]);
    }

    let workspace_packages = read_npm_workspace_packages(project_dir)?;
    let mut targets = Vec::new();
    if include_workspace_root {
        targets.push(project_dir.to_path_buf());
    }
    if all_workspaces {
        targets.extend(
            workspace_packages
                .iter()
                .map(|workspace| workspace.path.clone()),
        );
    }
    for selector in workspaces {
        let workspace = select_npm_workspace(project_dir, &workspace_packages, selector)?;
        targets.push(workspace.path);
    }

    let mut seen = BTreeSet::new();
    targets.retain(|path| seen.insert(absolute_project_dir(path)));
    Ok(targets)
}

fn select_npm_workspace(
    project_dir: &Path,
    workspaces: &[NpmWorkspacePackage],
    selector: &str,
) -> Result<NpmWorkspacePackage, OmcRegistryError> {
    let selector_path = absolutize_path(project_dir, PathBuf::from(selector));
    let selector_path = fs::canonicalize(&selector_path).unwrap_or(selector_path);
    for workspace in workspaces {
        if workspace.name.as_deref() == Some(selector) {
            return Ok(workspace.clone());
        }
        let workspace_path =
            fs::canonicalize(&workspace.path).unwrap_or_else(|_| workspace.path.clone());
        if workspace_path == selector_path {
            return Ok(workspace.clone());
        }
    }

    let available = workspaces
        .iter()
        .map(|workspace| {
            workspace
                .name
                .clone()
                .unwrap_or_else(|| workspace.path.display().to_string())
        })
        .collect::<Vec<_>>()
        .join(", ");
    let detail = if available.is_empty() {
        format!("npm workspace `{selector}` was not found")
    } else {
        format!("npm workspace `{selector}` was not found; available workspaces: {available}")
    };
    Err(OmcRegistryError::UnsupportedSpec(detail))
}

fn print_npm_run_list(
    project_dir: &Path,
    action: NpmRunListAction,
) -> Result<(), OmcRegistryError> {
    let script_dirs = npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )?;
    let workspace_mode =
        !action.workspaces.is_empty() || action.all_workspaces || action.include_workspace_root;
    let mut entries = Vec::new();
    for script_dir in script_dirs {
        let scripts = read_package_scripts(&script_dir)?;
        let label = npm_run_list_label(project_dir, &script_dir)?;
        entries.push((label, scripts));
    }

    if action.json {
        if workspace_mode {
            let value = entries.into_iter().collect::<BTreeMap<_, _>>();
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            let scripts = entries
                .into_iter()
                .next()
                .map(|(_, scripts)| scripts)
                .unwrap_or_default();
            println!("{}", serde_json::to_string_pretty(&scripts)?);
        }
    } else {
        for (index, (label, scripts)) in entries.iter().enumerate() {
            if index > 0 {
                println!();
            }
            print_npm_run_text_list(label, scripts);
        }
    }

    Ok(())
}

fn npm_run_list_label(project_dir: &Path, script_dir: &Path) -> Result<String, OmcRegistryError> {
    let package_json = script_dir.join("package.json");
    if package_json.exists() {
        let package = read_npm_pkg_json(&package_json)?;
        if let Some(name) = package.get("name").and_then(serde_json::Value::as_str) {
            return Ok(name.to_owned());
        }
    }
    if script_dir == project_dir {
        return Ok("undefined".to_owned());
    }
    Ok(script_dir
        .strip_prefix(project_dir)
        .unwrap_or(script_dir)
        .to_string_lossy()
        .into_owned())
}

fn print_npm_run_text_list(label: &str, scripts: &BTreeMap<String, String>) {
    let lifecycle = ["test", "start", "stop", "restart"];
    let lifecycle_scripts = lifecycle
        .iter()
        .filter_map(|name| scripts.get(*name).map(|script| (*name, script)))
        .collect::<Vec<_>>();
    if !lifecycle_scripts.is_empty() {
        println!("Lifecycle scripts included in {label}:");
        for (name, script) in lifecycle_scripts {
            println!("  {name}");
            println!("    {script}");
        }
    }

    let available = scripts
        .iter()
        .filter(|(name, _)| !lifecycle.contains(&name.as_str()))
        .collect::<Vec<_>>();
    if !available.is_empty() {
        println!("available via `npm run`:");
        for (name, script) in available {
            println!("  {name}");
            println!("    {script}");
        }
    }
    if scripts.is_empty() {
        println!("No scripts found in {label}");
    }
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
    script_dir: &Path,
    npm_command: &str,
    name: &str,
    script: &str,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    let mut command = package_script_command(script);
    apply_project_runtime_env_for_cwd(&mut command, project_dir, script_dir)?;
    apply_npm_lifecycle_env(&mut command, script_dir, npm_command, name, script)?;
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

#[derive(Debug)]
struct NpmInstallCompatRequest {
    specs: Vec<String>,
    archive_references: Vec<String>,
    local_paths: Vec<PathBuf>,
    save: bool,
    dev: bool,
    omit_dev: bool,
    lock_only: bool,
    dry_run: bool,
    npm_registry: Option<String>,
    allow: Vec<String>,
    allow_all_host: bool,
}

fn run_npm_install_compat(
    project_dir: &Path,
    request: NpmInstallCompatRequest,
) -> Result<ExitCode, OmcRegistryError> {
    let NpmInstallCompatRequest {
        specs,
        archive_references,
        local_paths,
        save,
        dev,
        omit_dev,
        lock_only,
        dry_run,
        npm_registry,
        allow,
        allow_all_host,
    } = request;
    if dry_run {
        return run_npm_install_dry_run(
            project_dir,
            NpmInstallCompatRequest {
                specs,
                archive_references,
                local_paths,
                save,
                dev,
                omit_dev,
                lock_only,
                dry_run,
                npm_registry,
                allow,
                allow_all_host,
            },
        );
    }
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
    Ok(ExitCode::SUCCESS)
}

fn run_npm_install_dry_run(
    project_dir: &Path,
    request: NpmInstallCompatRequest,
) -> Result<ExitCode, OmcRegistryError> {
    let NpmInstallCompatRequest {
        specs,
        archive_references,
        local_paths,
        save: _,
        dev: _,
        omit_dev,
        lock_only,
        dry_run: _,
        npm_registry,
        allow,
        allow_all_host,
    } = request;

    let dry_run_project = TempOmcProject::new("npm-dry-run", project_dir)?;
    let mut options = LinkOptions::new(dry_run_project.path());
    options.save_manifest_dependency = false;
    options.discover_project_requirements = specs.is_empty() && archive_references.is_empty();
    options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
    options.npm_registry_url = npm_registry.clone();
    options.include_dev_dependencies = !omit_dev;

    let mut reports = Vec::new();
    if specs.is_empty() && archive_references.is_empty() {
        if options.discover_project_requirements {
            reports.extend(lock_project(&options)?);
        }
    } else {
        let mut specs = parse_package_specs(&specs, Some(Ecosystem::Npm))?;
        specs.extend(parse_npm_archive_references(
            project_dir,
            &archive_references,
        )?);
        for spec in &specs {
            reports.extend(add_package_graph(spec, &options)?);
        }
    }

    if !reports.is_empty() {
        print_link_reports(&reports);
    }
    if !local_paths.is_empty() {
        if !reports.is_empty() {
            println!();
        }
        println!("dry-run: would link npm local paths:");
        for path in &local_paths {
            println!(
                "  - {}",
                absolutize_path(project_dir, path.clone()).display()
            );
        }
    }

    let npm_packages = reports
        .iter()
        .filter(|report| report.locked.ecosystem == Ecosystem::Npm)
        .count();
    if !reports.is_empty() || !local_paths.is_empty() {
        println!();
    }
    let lock_detail = if lock_only {
        " and update omc.lock"
    } else {
        ""
    };
    println!(
        "dry-run: would install npm={} local_paths={} node_modules={}{}",
        npm_packages,
        local_paths.len(),
        project_dir.join("node_modules").display(),
        lock_detail
    );
    Ok(ExitCode::SUCCESS)
}

fn run_npm_ci_compat(
    project_dir: &Path,
    omit_dev: bool,
    allow: Vec<String>,
    allow_all_host: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let mut options = LinkOptions::new(project_dir);
    options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
    options.include_dev_dependencies = !omit_dev;
    let install = install_locked_project(&options)?;
    print_install_report(&install);
    Ok(ExitCode::SUCCESS)
}

fn run_npm_compat(project_dir: &Path, args: &[String]) -> Result<ExitCode, OmcRegistryError> {
    match parse_npm_compat_action(args)? {
        NpmCompatAction::Help { topic } => print_npm_help(topic.as_deref()),
        NpmCompatAction::Version => println!("{}", env!("CARGO_PKG_VERSION")),
        NpmCompatAction::Init { action } => print_npm_init(project_dir, action)?,
        NpmCompatAction::PackageVersion { action } => print_npm_version(project_dir, action)?,
        NpmCompatAction::Install {
            specs,
            archive_references,
            local_paths,
            save,
            dev,
            omit_dev,
            lock_only,
            dry_run,
            npm_registry,
            allow,
            allow_all_host,
        } => {
            return run_npm_install_compat(
                project_dir,
                NpmInstallCompatRequest {
                    specs,
                    archive_references,
                    local_paths,
                    save,
                    dev,
                    omit_dev,
                    lock_only,
                    dry_run,
                    npm_registry,
                    allow,
                    allow_all_host,
                },
            )
        }
        NpmCompatAction::InstallTest {
            command,
            use_ci,
            specs,
            archive_references,
            local_paths,
            save,
            dev,
            omit_dev,
            lock_only,
            dry_run,
            npm_registry,
            allow,
            allow_all_host,
            test_args,
        } => {
            let status = if use_ci {
                run_npm_ci_compat(project_dir, omit_dev, allow, allow_all_host)?
            } else {
                run_npm_install_compat(
                    project_dir,
                    NpmInstallCompatRequest {
                        specs,
                        archive_references,
                        local_paths,
                        save,
                        dev,
                        omit_dev,
                        lock_only,
                        dry_run,
                        npm_registry,
                        allow,
                        allow_all_host,
                    },
                )?
            };
            if status != ExitCode::SUCCESS {
                return Ok(status);
            }
            return run_package_script_with_npm_command_for_workspaces(
                project_dir,
                &command,
                "test",
                &test_args,
                false,
                NpmScriptTargets {
                    workspaces: &[],
                    all_workspaces: false,
                    include_workspace_root: false,
                },
            );
        }
        NpmCompatAction::Ci {
            omit_dev,
            allow,
            allow_all_host,
        } => return run_npm_ci_compat(project_dir, omit_dev, allow, allow_all_host),
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
            packages,
            omit_dev,
            allow,
            allow_all_host,
        } => {
            let mut options = LinkOptions::new(project_dir);
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;
            options.include_dev_dependencies = !omit_dev;
            let install = install_locked_project(&options)?;
            print_npm_maintenance_report(command, &packages, &install);
        }
        NpmCompatAction::RunScript {
            command,
            name,
            args,
            if_present,
            workspaces,
            all_workspaces,
            include_workspace_root,
        } => {
            return run_package_script_with_npm_command_for_workspaces(
                project_dir,
                &command,
                &name,
                &args,
                if_present,
                NpmScriptTargets {
                    workspaces: &workspaces,
                    all_workspaces,
                    include_workspace_root,
                },
            )
        }
        NpmCompatAction::RunList { action } => {
            print_npm_run_list(project_dir, action)?;
        }
        NpmCompatAction::Exec { command, args } => {
            return run_project_command(project_dir, &command, &args)
        }
        NpmCompatAction::Path { kind } => print_npm_path(project_dir, kind)?,
        NpmCompatAction::List { action } => print_locked_packages(
            project_dir,
            Some(Ecosystem::Npm),
            action.json,
            &action.packages,
        )?,
        NpmCompatAction::Explain { specs, json } => {
            return print_npm_explain(project_dir, &specs, json)
        }
        NpmCompatAction::Outdated {
            json,
            parseable,
            npm_registry,
        } => return print_npm_outdated(project_dir, json, parseable, npm_registry.as_deref()),
        NpmCompatAction::Audit { json } => return print_audit_report(project_dir, json),
        NpmCompatAction::Fund { action } => print_npm_fund(project_dir, action)?,
        NpmCompatAction::Cache { action } => print_npm_cache(project_dir, action)?,
        NpmCompatAction::Pkg { action } => print_npm_pkg(project_dir, action)?,
        NpmCompatAction::Pack { action } => print_npm_pack(project_dir, action)?,
        NpmCompatAction::Search { action } => print_npm_search(project_dir, action)?,
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
        PipCompatAction::Help { topic } => print_pip_help(topic.as_deref()),
        PipCompatAction::Version => println!("pip {} from OMC", env!("CARGO_PKG_VERSION")),
        PipCompatAction::Install(action) => {
            let action = *action;
            if action.dry_run {
                return run_pip_install_dry_run(project_dir, action);
            }
            let PipInstallAction {
                specs,
                requirements,
                constraints,
                report,
                dry_run: _,
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
                vcs_requirements,
                allow,
                allow_all_host,
            } = action;
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
                options.python_vcs_requirements = vcs_requirements;
                let install = install_project(&options)?;
                print_install_report(&install);
                write_pip_install_report(project_dir, report.as_deref(), &install)?;
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
                options.python_vcs_requirements = vcs_requirements;
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
                write_pip_install_report(project_dir, report.as_deref(), &install)?;
            }
        }
        PipCompatAction::Download(action) => {
            download_pip_packages(project_dir, *action)?;
        }
        PipCompatAction::Wheel(action) => {
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
        PipCompatAction::Debug { action } => print_pip_debug(project_dir, action)?,
        PipCompatAction::Inspect => print_locked_pip_inspect(project_dir)?,
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
                        print_locked_packages(project_dir, Some(Ecosystem::Pypi), false, &[])?
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

fn run_pip_install_dry_run(
    project_dir: &Path,
    action: PipInstallAction,
) -> Result<ExitCode, OmcRegistryError> {
    let PipInstallAction {
        specs,
        requirements,
        constraints,
        report,
        dry_run: _,
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
        vcs_requirements,
        allow,
        allow_all_host,
    } = action;

    if !local_paths.is_empty() || !vcs_requirements.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip install --dry-run currently supports registry requirements and direct wheel/sdist archives; editable, local directory, and VCS requirements need a real OMC install".to_owned(),
        ));
    }

    let dry_run_project = TempOmcProject::new("pip-dry-run", project_dir)?;
    let mut options = LinkOptions::new(dry_run_project.path());
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
            "pip install --dry-run needs at least one package, archive, or requirement file"
                .to_owned(),
        ));
    }

    let mut reports = Vec::new();
    for spec in &resolved_specs {
        reports.extend(add_package_graph(spec, &options)?);
    }
    print_link_reports(&reports);

    let pypi_packages = reports
        .iter()
        .filter(|report| report.locked.ecosystem == Ecosystem::Pypi)
        .count();
    let python_site_packages = target
        .map(|path| absolutize_path(project_dir, path))
        .unwrap_or_else(|| {
            project_dir
                .join(".omc")
                .join("python")
                .join("site-packages")
        });
    let install = InstallReport {
        npm_packages: 0,
        pypi_packages,
        npm_bins: 0,
        python_scripts: 0,
        node_modules: project_dir.join("node_modules"),
        npm_bin_dir: project_dir.join("node_modules").join(".bin"),
        python_bin_dir: python_site_packages.join("bin"),
        python_site_packages,
    };
    println!();
    println!(
        "dry-run: would install pypi={} python_site_packages={}",
        install.pypi_packages,
        install.python_site_packages.display()
    );
    write_pip_install_report_from(
        dry_run_project.path(),
        project_dir,
        report.as_deref(),
        &install,
    )?;
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

fn print_npm_help(topic: Option<&str>) {
    print!("{}", npm_help_text(topic));
}

fn npm_help_text(topic: Option<&str>) -> String {
    match topic.and_then(npm_help_topic) {
        None => npm_general_help_text(),
        Some("install") => npm_command_help(
            "npm install [<package-spec>...]",
            &[
                "Resolve, verify, lock, and install npm packages with OMC.",
                "Aliases: i, add, update, up, upgrade.",
                "Common flags: --save, --no-save, --save-dev, --omit=dev, --include=dev, --package-lock-only, --dry-run, --registry, --allow, --allow-all-host.",
                "Direct local inputs are supported for .tgz archives and local package directories.",
            ],
        ),
        Some("ci") => npm_command_help(
            "npm ci",
            &[
                "Install the exact OMC lockfile state.",
                "Common flags: --omit=dev, --include=dev, --allow, --allow-all-host.",
            ],
        ),
        Some("install-test") => npm_command_help(
            "npm install-test [<package-spec>...] [-- <test-args>...]",
            &[
                "Run OMC npm install, then run the root package's test script.",
                "Alias: it.",
            ],
        ),
        Some("install-ci-test") => npm_command_help(
            "npm install-ci-test [-- <test-args>...]",
            &[
                "Run OMC npm ci, then run the root package's test script.",
                "Alias: cit.",
            ],
        ),
        Some("run") => npm_command_help(
            "npm run [<script>] [-- <args>...]",
            &[
                "Run package.json scripts with OMC npm/Python bins and imports on PATH.",
                "Without a script, lists scripts in text or JSON mode.",
                "Common flags: --if-present, --workspace, --workspaces, --include-workspace-root, --json, --silent.",
                "Aliases: run-script. Also supports npm test/start/stop/restart.",
            ],
        ),
        Some("exec") => npm_command_help(
            "npm exec <command> [-- <args>...]",
            &[
                "Run a project-local executable with OMC runtime paths.",
                "Aliases: x, npx. Common flags: --yes, --package, --cache, --registry.",
            ],
        ),
        Some("remove") => npm_command_help(
            "npm remove <package-spec>...",
            &[
                "Remove OMC-managed npm dependencies and reinstall the remaining graph.",
                "Aliases: uninstall, rm, un.",
            ],
        ),
        Some("list") => npm_command_help(
            "npm list [<package-spec>...]",
            &[
                "List locked npm packages.",
                "Aliases: ls, ll, la. Common flags: --json, --depth, --omit, --include.",
            ],
        ),
        Some("explain") => npm_command_help(
            "npm explain <package-spec>...",
            &[
                "Explain why locked npm packages are present.",
                "Alias: why. Supports --json.",
            ],
        ),
        Some("audit") => npm_command_help(
            "npm audit",
            &["Print OMC verifier and capability findings. Supports --json."],
        ),
        Some("outdated") => npm_command_help(
            "npm outdated",
            &["Compare locked npm packages to registry versions. Supports --json and --parseable."],
        ),
        Some("fund") => npm_command_help(
            "npm fund [<package-spec>]",
            &[
                "Show funding metadata from root/workspace package.json and installed packages.",
                "Supports --json, --workspace, --workspaces, and --include-workspace-root.",
            ],
        ),
        Some("rebuild") => npm_command_help(
            "npm rebuild [<package-spec>...]",
            &[
                "Refresh OMC's locked install state without running package lifecycle scripts.",
                "Alias: rb.",
            ],
        ),
        Some("maintenance") => npm_command_help(
            "npm <prune|dedupe>",
            &[
                "Refresh OMC's locked install state for common npm maintenance workflows.",
                "Aliases: ddp, find-dupes.",
            ],
        ),
        Some("pack") => npm_command_help(
            "npm pack [<package-spec>|<local-dir>...]",
            &[
                "Create local package tarballs or download registry tarballs.",
                "Common flags: --pack-destination, --json, --dry-run, --registry.",
            ],
        ),
        Some("search") => npm_command_help(
            "npm search <terms...>",
            &["Search the configured npm registry. Aliases: s, se, find. Supports --json, --parseable, --searchlimit."],
        ),
        Some("view") => npm_command_help(
            "npm view <package-spec> [field...]",
            &["Read package metadata from the configured npm registry. Aliases: info, show, v. Supports --json."],
        ),
        Some("config") => npm_command_help(
            "npm config <get|set|delete|list> ...",
            &[
                "Read and update npm registry config used by OMC.",
                "Aliases: c, npm get. Supports --json, --registry, and --userconfig where relevant.",
            ],
        ),
        Some("cache") => npm_command_help(
            "npm cache <verify|ls|rm|clean>",
            &["Inspect or clear OMC's npm cache. cache clean requires --force."],
        ),
        Some("pkg") => npm_command_help(
            "npm pkg <get|set|delete> ...",
            &["Read and update package.json fields."],
        ),
        Some("version") => npm_command_help(
            "npm version [<newversion>|major|minor|patch|pre...]",
            &["Read or bump package.json version. Supports --json, --preid, --allow-same-version, and --no-git-tag-version."],
        ),
        Some("init") => npm_command_help(
            "npm init -y",
            &["Create or update package.json with npm-compatible defaults."],
        ),
        Some("path") => npm_command_help(
            "npm <bin|root|prefix>",
            &["Print OMC project bin, node_modules, or project prefix paths."],
        ),
        Some(_) => npm_command_help(
            "npm help [command]",
            &["No focused OMC help is available for that topic yet."],
        ),
    }
}

fn npm_general_help_text() -> String {
    npm_command_help(
        "npm <command>",
        &[
            "OMC npm compatibility runs supported npm workflows through OMC's verifier, lockfile, cache, and project-local runtime paths.",
            "Supported commands: install, install-test, ci, install-ci-test, remove, run, test, start, stop, restart, exec, list, explain, audit, outdated, fund, prune, dedupe, rebuild, cache, pkg, version, pack, search, view, config, init, bin, root, prefix.",
            "Use `npm help <command>` for focused OMC compatibility notes.",
        ],
    )
}

fn npm_command_help(usage: &str, lines: &[&str]) -> String {
    let mut output = format!("OMC npm compatibility\n\nUsage: {usage}\n");
    if !lines.is_empty() {
        output.push('\n');
        for line in lines {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn npm_help_topic(topic: &str) -> Option<&'static str> {
    match topic {
        "help" | "--help" | "-h" => None,
        "install" | "i" | "add" | "update" | "up" | "upgrade" => Some("install"),
        "install-test" | "it" => Some("install-test"),
        "ci" => Some("ci"),
        "install-ci-test" | "cit" => Some("install-ci-test"),
        "run" | "run-script" | "test" | "start" | "stop" | "restart" => Some("run"),
        "exec" | "x" | "npx" => Some("exec"),
        "remove" | "uninstall" | "rm" | "un" => Some("remove"),
        "list" | "ls" | "ll" | "la" => Some("list"),
        "explain" | "why" => Some("explain"),
        "audit" => Some("audit"),
        "outdated" => Some("outdated"),
        "fund" => Some("fund"),
        "prune" | "dedupe" | "ddp" | "find-dupes" => Some("maintenance"),
        "rebuild" | "rb" => Some("rebuild"),
        "pack" => Some("pack"),
        "search" | "s" | "se" | "find" => Some("search"),
        "view" | "info" | "show" | "v" => Some("view"),
        "config" | "c" | "get" => Some("config"),
        "cache" => Some("cache"),
        "pkg" => Some("pkg"),
        "version" => Some("version"),
        "init" => Some("init"),
        "bin" | "root" | "prefix" => Some("path"),
        _ => Some("unknown"),
    }
}

fn print_pip_help(topic: Option<&str>) {
    print!("{}", pip_help_text(topic));
}

fn pip_help_text(topic: Option<&str>) -> String {
    match topic.and_then(pip_help_topic) {
        None => pip_general_help_text(),
        Some("install") => pip_command_help(
            "pip install [<requirement>...]",
            &[
                "Resolve, verify, lock, and install PyPI packages with OMC.",
                "Supports requirements/constraints, indexes, find-links, no-index, hashes, no-deps, install reports, registry/archive dry-runs, binary policy, target dirs, local archives, local directories, editable paths, and editable VCS requirements.",
            ],
        ),
        Some("download") => pip_command_help(
            "pip download [<requirement>...]",
            &["Download locked PyPI archives into a destination directory. Shares install-style requirement and index flags."],
        ),
        Some("wheel") => pip_command_help(
            "pip wheel [<requirement>...]",
            &["Download wheel artifacts into a wheelhouse. Shares install-style requirement and index flags."],
        ),
        Some("uninstall") => pip_command_help(
            "pip uninstall <package>...",
            &["Remove OMC-managed PyPI dependencies and reinstall the remaining graph. Supports -r/--requirement."],
        ),
        Some("freeze") => pip_command_help(
            "pip freeze",
            &["Print locked PyPI requirements, including local editable and VCS entries where present."],
        ),
        Some("list") => pip_command_help(
            "pip list",
            &["List locked PyPI packages. Supports --format=columns|freeze|json and --outdated."],
        ),
        Some("show") => pip_command_help(
            "pip show <package>...",
            &["Show locked package metadata. Supports -f/--files."],
        ),
        Some("check") => pip_command_help(
            "pip check",
            &["Validate locked PyPI dependency requirements."],
        ),
        Some("inspect") => pip_command_help(
            "pip inspect",
            &["Print a JSON report for locked PyPI packages in pip inspect shape."],
        ),
        Some("debug") => pip_command_help(
            "pip debug",
            &["Print OMC compatibility diagnostics, including project paths, cache, index config, lockfile status, and optional target platform/Python/ABI args."],
        ),
        Some("hash") => pip_command_help(
            "pip hash <file>...",
            &["Hash local files with sha256, sha384, or sha512."],
        ),
        Some("cache") => pip_command_help(
            "pip cache <dir|info|list|remove|purge>",
            &["Inspect or clear OMC's PyPI cache."],
        ),
        Some("index") => pip_command_help(
            "pip index versions <package>",
            &["List available package versions from the configured index. Supports --json and index flags."],
        ),
        Some("config") => pip_command_help(
            "pip config <get|set|unset|list> ...",
            &["Read and update pip config used by OMC. Supports --site, --user, and --json where relevant."],
        ),
        Some(_) => pip_command_help(
            "pip help [command]",
            &["No focused OMC help is available for that topic yet."],
        ),
    }
}

fn pip_general_help_text() -> String {
    pip_command_help(
        "pip <command>",
        &[
            "OMC pip compatibility runs supported pip workflows through OMC's resolver, verifier, lockfile, cache, and isolated Python site-packages.",
            "Supported commands: install, download, wheel, uninstall, freeze, list, show, check, inspect, debug, hash, cache, index versions, config.",
            "Use `pip help <command>` for focused OMC compatibility notes.",
        ],
    )
}

fn pip_command_help(usage: &str, lines: &[&str]) -> String {
    let mut output = format!("OMC pip compatibility\n\nUsage: {usage}\n");
    if !lines.is_empty() {
        output.push('\n');
        for line in lines {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn pip_help_topic(topic: &str) -> Option<&'static str> {
    match topic {
        "help" | "--help" | "-h" => None,
        "install" => Some("install"),
        "download" => Some("download"),
        "wheel" => Some("wheel"),
        "uninstall" | "remove" => Some("uninstall"),
        "freeze" => Some("freeze"),
        "list" => Some("list"),
        "show" => Some("show"),
        "check" => Some("check"),
        "inspect" => Some("inspect"),
        "debug" => Some("debug"),
        "hash" => Some("hash"),
        "cache" => Some("cache"),
        "index" => Some("index"),
        "config" => Some("config"),
        _ => Some("unknown"),
    }
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
    match action {
        NpmConfigAction::Set { assignments } => {
            write_npm_config_assignments(project_dir, userconfig, &assignments)?;
            return Ok(());
        }
        NpmConfigAction::Delete { keys } => {
            delete_npm_config_keys(project_dir, userconfig, &keys)?;
            return Ok(());
        }
        NpmConfigAction::Get { .. } | NpmConfigAction::List { .. } => {}
    }

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
        NpmConfigAction::Set { .. } | NpmConfigAction::Delete { .. } => unreachable!(),
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

fn write_npm_config_assignments(
    project_dir: &Path,
    userconfig: Option<&Path>,
    assignments: &[(String, String)],
) -> Result<(), OmcRegistryError> {
    let path = npm_config_write_path(project_dir, userconfig);
    let mut lines = read_npm_config_lines(&path)?;
    for (key, value) in assignments {
        upsert_npm_config_line(&mut lines, key, value);
    }
    write_npm_config_lines(&path, &lines)
}

fn delete_npm_config_keys(
    project_dir: &Path,
    userconfig: Option<&Path>,
    keys: &[String],
) -> Result<(), OmcRegistryError> {
    let path = npm_config_write_path(project_dir, userconfig);
    let mut lines = read_npm_config_lines(&path)?;
    lines.retain(|line| {
        let Some(key) = npm_config_line_key(line) else {
            return true;
        };
        !keys.iter().any(|target| target == key)
    });
    write_npm_config_lines(&path, &lines)
}

fn npm_config_write_path(project_dir: &Path, userconfig: Option<&Path>) -> PathBuf {
    if let Some(userconfig) = userconfig {
        return absolutize_path(project_dir, userconfig.to_path_buf());
    }
    project_dir.join(".npmrc")
}

fn read_npm_config_lines(path: &Path) -> Result<Vec<String>, OmcRegistryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::to_owned)
        .collect())
}

fn write_npm_config_lines(path: &Path, lines: &[String]) -> Result<(), OmcRegistryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

fn upsert_npm_config_line(lines: &mut Vec<String>, key: &str, value: &str) {
    if let Some(line) = lines
        .iter_mut()
        .find(|line| npm_config_line_key(line).is_some_and(|existing| existing == key))
    {
        *line = format!("{key}={value}");
        return;
    }
    lines.push(format!("{key}={value}"));
}

fn npm_config_line_key(line: &str) -> Option<&str> {
    let line = strip_npm_config_comment(line).trim();
    if line.is_empty() {
        return None;
    }
    line.split_once('=')
        .map(|(key, _)| key.trim())
        .filter(|key| !key.is_empty())
}

fn strip_npm_config_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return "";
    }
    for (index, ch) in line.char_indices() {
        let previous_was_whitespace = line[..index]
            .chars()
            .last()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if matches!(ch, '#' | ';') && previous_was_whitespace {
            return &line[..index];
        }
    }
    line
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

fn print_npm_search(project_dir: &Path, action: NpmSearchAction) -> Result<(), OmcRegistryError> {
    let packages = read_npm_search(
        project_dir,
        &action.query,
        action.limit,
        action.npm_registry.as_deref(),
    )?;
    if action.json {
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else if action.parseable {
        for package in &packages {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                package.name,
                package.description.as_deref().unwrap_or_default(),
                npm_search_short_date(package),
                package.version,
                package.keywords.join(",")
            );
        }
    } else if packages.is_empty() {
        println!("No matches found for \"{}\"", action.query);
    } else {
        for package in &packages {
            println!("{}", package.name);
            if let Some(description) = &package.description {
                if !description.is_empty() {
                    println!("{description}");
                }
            }
            println!(
                "Version {} published {}{}",
                package.version,
                npm_search_short_date(package),
                npm_search_publisher_suffix(package)
            );
            let maintainers = npm_search_usernames(&package.maintainers);
            if !maintainers.is_empty() {
                println!("Maintainers: {}", maintainers.join(" "));
            }
            if !package.keywords.is_empty() {
                println!("Keywords: {}", package.keywords.join(" "));
            }
            println!("{}", npm_search_package_url(package));
            println!();
        }
    }
    Ok(())
}

fn npm_search_short_date(package: &NpmSearchPackage) -> &str {
    package
        .date
        .as_deref()
        .and_then(|date| date.get(..10))
        .unwrap_or("unknown")
}

fn npm_search_publisher_suffix(package: &NpmSearchPackage) -> String {
    package
        .publisher
        .as_ref()
        .and_then(npm_search_username)
        .map(|publisher| format!(" by {publisher}"))
        .unwrap_or_default()
}

fn npm_search_usernames(users: &[omc_registry::NpmSearchUser]) -> Vec<String> {
    users.iter().filter_map(npm_search_username).collect()
}

fn npm_search_username(user: &omc_registry::NpmSearchUser) -> Option<String> {
    user.username.clone().or_else(|| user.email.clone())
}

fn npm_search_package_url(package: &NpmSearchPackage) -> String {
    package
        .links
        .get("npm")
        .cloned()
        .unwrap_or_else(|| format!("https://npm.im/{}", package.name))
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

#[derive(Debug)]
struct NpmExplainPackage {
    name: String,
    version: String,
    location: PathBuf,
    dependents: Vec<String>,
}

fn print_npm_explain(
    project_dir: &Path,
    specs: &[String],
    json: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let targets = specs
        .iter()
        .map(|spec| npm_explain_requested_name(spec))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let packages = lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
        .collect::<Vec<_>>();
    let root_dependencies = npm_root_dependency_names(project_dir)?;
    let root = npm_outdated_dependent(project_dir);
    let mut rows = Vec::new();

    for package in packages.iter().copied() {
        if !targets.contains(&package.name) {
            continue;
        }
        let mut dependents = BTreeSet::new();
        if root_dependencies.contains(&package.name) {
            dependents.insert(root.clone());
        }
        for parent in &packages {
            if parent.name == package.name && parent.version == package.version {
                continue;
            }
            if npm_lock_package_depends_on(parent, &package.name) {
                dependents.insert(format!("{}@{}", parent.name, parent.version));
            }
        }
        let dependents = if dependents.is_empty() {
            vec!["omc.lock".to_owned()]
        } else {
            dependents.into_iter().collect()
        };
        rows.push(NpmExplainPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            location: npm_outdated_location(project_dir, &package.name),
            dependents,
        });
    }

    rows.sort_by(|left, right| {
        (left.name.as_str(), left.version.as_str())
            .cmp(&(right.name.as_str(), right.version.as_str()))
    });

    if json {
        let value = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "name": row.name,
                    "version": row.version,
                    "location": row.location.display().to_string(),
                    "dependents": row.dependents,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        for row in &rows {
            println!("{}@{}", row.name, row.version);
            println!("{}", row.location.display());
            for dependent in &row.dependents {
                println!("  depended on by {dependent}");
            }
        }
    }

    if rows.is_empty() {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn npm_explain_requested_name(spec: &str) -> Result<String, OmcRegistryError> {
    parse_package_spec(spec, Some(Ecosystem::Npm)).map(|spec| spec.name)
}

fn npm_root_dependency_names(project_dir: &Path) -> Result<BTreeSet<String>, OmcRegistryError> {
    let mut names = BTreeSet::new();
    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        let package = read_npm_pkg_json(&package_json)?;
        for field in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            if let Some(object) = package.get(field).and_then(serde_json::Value::as_object) {
                names.extend(object.keys().cloned());
            }
        }
    }

    let manifest = read_manifest(project_dir.join("omc.toml"))?;
    for key in manifest
        .dependencies
        .keys()
        .chain(manifest.dev_dependencies.keys())
    {
        if let Ok(spec) = PackageSpec::parse(key) {
            if spec.ecosystem == Ecosystem::Npm {
                names.insert(spec.name);
            }
        }
    }
    Ok(names)
}

fn npm_lock_package_depends_on(package: &LockedPackage, name: &str) -> bool {
    package
        .dependencies
        .iter()
        .chain(package.optional_dependencies.iter())
        .any(|dependency| npm_dependency_name(dependency).as_deref() == Some(name))
}

fn npm_dependency_name(dependency: &str) -> Option<String> {
    let spec = PackageSpec::parse(dependency).ok()?;
    (spec.ecosystem == Ecosystem::Npm).then_some(spec.name)
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
            "pip download/wheel needs at least one package, archive, or requirement file"
                .to_owned(),
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
            "this OMC compatibility path supports registry requirements and direct wheel/sdist archives; local directories and VCS requirements need a real install"
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

fn print_npm_version(project_dir: &Path, action: NpmVersionAction) -> Result<(), OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let mut package = read_npm_pkg_json(&package_json)?;
    let current = npm_package_json_version(&package)?;
    match action {
        NpmVersionAction::Current { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": current,
                    }))?
                );
            } else {
                println!("v{current}");
            }
        }
        NpmVersionAction::Bump {
            spec,
            preid,
            allow_same_version,
            json,
        } => {
            let next = npm_next_version(&current, &spec, preid.as_deref())?;
            if next == current && !allow_same_version {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "Version not changed: {current}"
                )));
            }
            npm_pkg_set_path(
                &mut package,
                "version",
                serde_json::Value::String(next.clone()),
            )?;
            write_npm_pkg_json(&package_json, &package)?;
            update_npm_lockfile_root_version(project_dir, "package-lock.json", &next)?;
            update_npm_lockfile_root_version(project_dir, "npm-shrinkwrap.json", &next)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "old": current,
                        "new": next,
                    }))?
                );
            } else {
                println!("v{next}");
            }
        }
    }
    Ok(())
}

fn npm_package_json_version(package: &serde_json::Value) -> Result<String, OmcRegistryError> {
    package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("package.json does not define version".to_owned())
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NpmSemver {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

fn npm_next_version(
    current: &str,
    spec: &str,
    preid: Option<&str>,
) -> Result<String, OmcRegistryError> {
    let current = parse_npm_semver(current)?;
    let next = match spec {
        "major" => NpmSemver {
            major: current.major + 1,
            minor: 0,
            patch: 0,
            prerelease: None,
        },
        "minor" => NpmSemver {
            major: current.major,
            minor: current.minor + 1,
            patch: 0,
            prerelease: None,
        },
        "patch" => NpmSemver {
            major: current.major,
            minor: current.minor,
            patch: current.patch + 1,
            prerelease: None,
        },
        "premajor" => NpmSemver {
            major: current.major + 1,
            minor: 0,
            patch: 0,
            prerelease: Some(npm_initial_prerelease(preid)),
        },
        "preminor" => NpmSemver {
            major: current.major,
            minor: current.minor + 1,
            patch: 0,
            prerelease: Some(npm_initial_prerelease(preid)),
        },
        "prepatch" => NpmSemver {
            major: current.major,
            minor: current.minor,
            patch: current.patch + 1,
            prerelease: Some(npm_initial_prerelease(preid)),
        },
        "prerelease" | "pre" => npm_increment_prerelease(current, preid),
        exact => return normalize_npm_exact_version(exact),
    };
    Ok(next.to_string())
}

fn npm_initial_prerelease(preid: Option<&str>) -> String {
    match preid.filter(|value| !value.is_empty()) {
        Some(preid) => format!("{preid}.0"),
        None => "0".to_owned(),
    }
}

fn npm_increment_prerelease(mut version: NpmSemver, preid: Option<&str>) -> NpmSemver {
    if let Some(prerelease) = version.prerelease.as_deref() {
        let mut parts = prerelease.split('.').map(str::to_owned).collect::<Vec<_>>();
        if let Some(preid) = preid.filter(|value| !value.is_empty()) {
            if parts.first().is_none_or(|part| part != preid) {
                version.prerelease = Some(format!("{preid}.0"));
                return version;
            }
        }
        if let Some(last) = parts.last_mut() {
            if let Ok(number) = last.parse::<u64>() {
                *last = (number + 1).to_string();
                version.prerelease = Some(parts.join("."));
                return version;
            }
        }
        version.prerelease = Some(format!("{prerelease}.0"));
        return version;
    }
    version.patch += 1;
    version.prerelease = Some(npm_initial_prerelease(preid));
    version
}

fn normalize_npm_exact_version(value: &str) -> Result<String, OmcRegistryError> {
    Ok(parse_npm_semver(value)?.to_string())
}

fn parse_npm_semver(value: &str) -> Result<NpmSemver, OmcRegistryError> {
    let value = value.trim().trim_start_matches('v');
    let value = value.split_once('+').map(|(base, _)| base).unwrap_or(value);
    let (core, prerelease) = value
        .split_once('-')
        .map(|(core, prerelease)| (core, Some(prerelease.to_owned())))
        .unwrap_or((value, None));
    let mut parts = core.split('.');
    let major = parse_npm_version_number(parts.next(), value)?;
    let minor = parse_npm_version_number(parts.next(), value)?;
    let patch = parse_npm_version_number(parts.next(), value)?;
    if parts.next().is_some()
        || prerelease
            .as_deref()
            .is_some_and(|part| part.is_empty() || part.contains('+'))
    {
        return Err(invalid_npm_version(value));
    }
    Ok(NpmSemver {
        major,
        minor,
        patch,
        prerelease,
    })
}

fn parse_npm_version_number(value: Option<&str>, raw: &str) -> Result<u64, OmcRegistryError> {
    let Some(value) = value else {
        return Err(invalid_npm_version(raw));
    };
    if value.is_empty() || value.starts_with('-') {
        return Err(invalid_npm_version(raw));
    }
    value.parse().map_err(|_| invalid_npm_version(raw))
}

fn invalid_npm_version(value: &str) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!("invalid npm package version `{value}`"))
}

impl std::fmt::Display for NpmSemver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(prerelease) = &self.prerelease {
            write!(formatter, "-{prerelease}")?;
        }
        Ok(())
    }
}

fn update_npm_lockfile_root_version(
    project_dir: &Path,
    filename: &str,
    version: &str,
) -> Result<(), OmcRegistryError> {
    let path = project_dir.join(filename);
    if !path.exists() {
        return Ok(());
    }
    let mut value: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "version".to_owned(),
            serde_json::Value::String(version.to_owned()),
        );
    }
    if let Some(root) = value
        .get_mut("packages")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|packages| packages.get_mut(""))
        .and_then(serde_json::Value::as_object_mut)
    {
        root.insert(
            "version".to_owned(),
            serde_json::Value::String(version.to_owned()),
        );
    }
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&value)?))?;
    Ok(())
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

fn print_npm_fund(project_dir: &Path, action: NpmFundAction) -> Result<(), OmcRegistryError> {
    let report = collect_npm_fund_report(project_dir, &action)?;
    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&npm_fund_report_json(&report))?
        );
    } else {
        print_npm_fund_text(&report, action.package.as_deref());
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct NpmFundReport {
    root: Option<NpmFundPackage>,
    dependencies: Vec<NpmFundPackage>,
}

#[derive(Debug, Clone)]
struct NpmFundPackage {
    name: String,
    version: Option<String>,
    funding: Option<serde_json::Value>,
    urls: Vec<String>,
}

impl NpmFundPackage {
    fn id(&self) -> String {
        match self.version.as_deref() {
            Some(version) if !version.is_empty() => format!("{}@{}", self.name, version),
            _ => self.name.clone(),
        }
    }
}

fn collect_npm_fund_report(
    project_dir: &Path,
    action: &NpmFundAction,
) -> Result<NpmFundReport, OmcRegistryError> {
    let target_dirs = npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )?;
    let report_root_dir = if target_dirs.len() == 1 {
        target_dirs[0].clone()
    } else {
        project_dir.to_path_buf()
    };
    let report_root_dir = absolute_project_dir(&report_root_dir);
    let package_filter = action.package.as_deref().map(npm_fund_filter_name);

    let mut root = None;
    let mut dependencies = BTreeMap::new();
    for target_dir in target_dirs {
        let target_dir = absolute_project_dir(&target_dir);
        let target_root = npm_fund_package_from_dir(&target_dir)?;
        let is_report_root = target_dir == report_root_dir;
        if is_report_root {
            root = Some(target_root.clone());
        } else {
            insert_npm_fund_dependency(&mut dependencies, target_root, package_filter.as_deref());
        }

        for package_json in npm_fund_installed_package_jsons(&target_dir)? {
            let package = npm_fund_package_from_package_json(&package_json)?;
            insert_npm_fund_dependency(&mut dependencies, package, package_filter.as_deref());
        }
    }

    if let Some(filter) = package_filter.as_deref() {
        if root
            .as_ref()
            .is_some_and(|package| !npm_fund_package_matches(package, filter))
        {
            root = None;
        }
    }

    Ok(NpmFundReport {
        root,
        dependencies: dependencies.into_values().collect(),
    })
}

fn insert_npm_fund_dependency(
    dependencies: &mut BTreeMap<String, NpmFundPackage>,
    package: NpmFundPackage,
    package_filter: Option<&str>,
) {
    if package_filter.is_some_and(|filter| !npm_fund_package_matches(&package, filter)) {
        return;
    }
    if package.funding.is_none() {
        return;
    }
    dependencies.entry(package.name.clone()).or_insert(package);
}

fn npm_fund_package_from_dir(dir: &Path) -> Result<NpmFundPackage, OmcRegistryError> {
    npm_fund_package_from_package_json(&dir.join("package.json"))
}

fn npm_fund_package_from_package_json(
    package_json: &Path,
) -> Result<NpmFundPackage, OmcRegistryError> {
    let package = read_npm_pkg_json(package_json)?;
    let name = npm_package_json_name(&package)?;
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty())
        .map(str::to_owned);
    let funding = package.get("funding").and_then(normalize_npm_funding);
    let urls = funding.as_ref().map(npm_funding_urls).unwrap_or_default();
    Ok(NpmFundPackage {
        name,
        version,
        funding,
        urls,
    })
}

fn npm_fund_installed_package_jsons(project_dir: &Path) -> Result<Vec<PathBuf>, OmcRegistryError> {
    let node_modules = project_dir.join("node_modules");
    if !node_modules.exists() {
        return Ok(Vec::new());
    }

    let mut package_jsons = Vec::new();
    for entry in fs::read_dir(&node_modules)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".bin" || name.starts_with('.') || !path.is_dir() {
            continue;
        }
        if name.starts_with('@') {
            for scoped_entry in fs::read_dir(&path)? {
                let scoped_entry = scoped_entry?;
                let scoped_path = scoped_entry.path();
                if scoped_path.is_dir() {
                    let package_json = scoped_path.join("package.json");
                    if package_json.exists() {
                        package_jsons.push(package_json);
                    }
                }
            }
        } else {
            let package_json = path.join("package.json");
            if package_json.exists() {
                package_jsons.push(package_json);
            }
        }
    }
    package_jsons.sort();
    Ok(package_jsons)
}

fn normalize_npm_funding(value: &serde_json::Value) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::String(url) => npm_funding_url_value(url),
        serde_json::Value::Object(_) => {
            if npm_funding_urls(value).is_empty() {
                None
            } else {
                Some(value.clone())
            }
        }
        serde_json::Value::Array(values) => {
            let normalized = values
                .iter()
                .filter_map(normalize_npm_funding)
                .collect::<Vec<_>>();
            if normalized.is_empty() {
                None
            } else {
                Some(serde_json::Value::Array(normalized))
            }
        }
        _ => None,
    }
}

fn npm_funding_url_value(url: &str) -> Option<serde_json::Value> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    Some(serde_json::json!({ "url": url }))
}

fn npm_funding_urls(value: &serde_json::Value) -> Vec<String> {
    let mut urls = Vec::new();
    collect_npm_funding_urls(value, &mut urls);
    urls.sort();
    urls.dedup();
    urls
}

fn collect_npm_funding_urls(value: &serde_json::Value, urls: &mut Vec<String>) {
    match value {
        serde_json::Value::String(url) => {
            let url = url.trim();
            if !url.is_empty() {
                urls.push(url.to_owned());
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(url) = object
                .get("url")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|url| !url.is_empty())
            {
                urls.push(url.to_owned());
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_npm_funding_urls(value, urls);
            }
        }
        _ => {}
    }
}

fn npm_fund_report_json(report: &NpmFundReport) -> serde_json::Value {
    let mut dependencies = serde_json::Map::new();
    for package in &report.dependencies {
        if package.funding.is_none() {
            continue;
        }
        dependencies.insert(package.name.clone(), npm_fund_package_json(package, false));
    }

    let mut object = serde_json::Map::new();
    object.insert(
        "length".to_owned(),
        serde_json::Value::Number(dependencies.len().into()),
    );
    if let Some(root) = &report.root {
        object.insert(
            "name".to_owned(),
            serde_json::Value::String(root.name.clone()),
        );
        if let Some(version) = &root.version {
            object.insert(
                "version".to_owned(),
                serde_json::Value::String(version.clone()),
            );
        }
        if let Some(funding) = &root.funding {
            object.insert("funding".to_owned(), funding.clone());
        }
    }
    object.insert(
        "dependencies".to_owned(),
        serde_json::Value::Object(dependencies),
    );
    serde_json::Value::Object(object)
}

fn npm_fund_package_json(package: &NpmFundPackage, include_name: bool) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    if include_name {
        object.insert(
            "name".to_owned(),
            serde_json::Value::String(package.name.clone()),
        );
    }
    if let Some(version) = &package.version {
        object.insert(
            "version".to_owned(),
            serde_json::Value::String(version.clone()),
        );
    }
    if let Some(funding) = &package.funding {
        object.insert("funding".to_owned(), funding.clone());
    }
    serde_json::Value::Object(object)
}

fn print_npm_fund_text(report: &NpmFundReport, package_filter: Option<&str>) {
    let package_filter = package_filter.map(npm_fund_filter_name);
    let mut packages_by_url = BTreeMap::<String, Vec<String>>::new();
    if let Some(root) = &report.root {
        if package_filter
            .as_deref()
            .is_none_or(|filter| npm_fund_package_matches(root, filter))
        {
            for url in &root.urls {
                packages_by_url
                    .entry(url.clone())
                    .or_default()
                    .push(root.id());
            }
        }
    }
    for package in &report.dependencies {
        for url in &package.urls {
            packages_by_url
                .entry(url.clone())
                .or_default()
                .push(package.id());
        }
    }

    if packages_by_url.is_empty() {
        if let Some(filter) = package_filter {
            println!("No funding information found for {filter}");
        } else if let Some(root) = &report.root {
            println!("{}", root.id());
        } else {
            println!("No funding information found");
        }
        return;
    }

    let mut first = true;
    for (url, mut package_ids) in packages_by_url {
        package_ids.sort();
        package_ids.dedup();
        if !first {
            println!();
        }
        first = false;
        println!("{url}");
        for package_id in package_ids {
            println!("  - {package_id}");
        }
    }
}

fn npm_fund_filter_name(spec: &str) -> String {
    let spec = spec.strip_prefix("npm:").unwrap_or(spec);
    let spec = spec.split_once('#').map(|(base, _)| base).unwrap_or(spec);
    if let Some(index) = spec.rfind('@') {
        if index > 0 {
            return spec[..index].to_owned();
        }
    }
    spec.to_owned()
}

fn npm_fund_package_matches(package: &NpmFundPackage, filter: &str) -> bool {
    package.name == filter || package.id() == filter
}

fn print_npm_init(project_dir: &Path, action: NpmInitAction) -> Result<(), OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let mut package = if package_json.exists() {
        read_npm_pkg_json(&package_json)?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    let name = action
        .name
        .clone()
        .unwrap_or_else(|| default_npm_package_name(project_dir, action.scope.as_deref()));
    npm_pkg_set_default_string(&mut package, "name", name)?;
    npm_pkg_set_default_string(
        &mut package,
        "version",
        action.version.unwrap_or_else(|| "1.0.0".to_owned()),
    )?;
    npm_pkg_set_default_string(
        &mut package,
        "description",
        action.description.unwrap_or_default(),
    )?;
    npm_pkg_set_default_string(
        &mut package,
        "main",
        action.main.unwrap_or_else(|| "index.js".to_owned()),
    )?;
    if npm_pkg_get_path(&package, "scripts.test").is_none() {
        npm_pkg_set_path(
            &mut package,
            "scripts.test",
            serde_json::Value::String("echo \"Error: no test specified\" && exit 1".to_owned()),
        )?;
    }
    if npm_pkg_get_path(&package, "keywords").is_none() {
        npm_pkg_set_path(
            &mut package,
            "keywords",
            serde_json::Value::Array(Vec::new()),
        )?;
    }
    npm_pkg_set_default_string(&mut package, "author", String::new())?;
    npm_pkg_set_default_string(
        &mut package,
        "license",
        action.license.unwrap_or_else(|| "ISC".to_owned()),
    )?;
    if action.private && npm_pkg_get_path(&package, "private").is_none() {
        npm_pkg_set_path(&mut package, "private", serde_json::Value::Bool(true))?;
    }
    if let Some(package_type) = action.package_type {
        npm_pkg_set_default_string(&mut package, "type", package_type)?;
    }

    write_npm_pkg_json(&package_json, &package)?;
    println!("Wrote to {}", package_json.display());
    Ok(())
}

fn npm_pkg_set_default_string(
    package: &mut serde_json::Value,
    path: &str,
    value: String,
) -> Result<(), OmcRegistryError> {
    if npm_pkg_get_path(package, path).is_none() {
        npm_pkg_set_path(package, path, serde_json::Value::String(value))?;
    }
    Ok(())
}

fn default_npm_package_name(project_dir: &Path, scope: Option<&str>) -> String {
    let base = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(normalize_npm_init_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "omc-project".to_owned());
    if let Some(scope) = scope
        .map(normalize_npm_scope)
        .filter(|scope| !scope.is_empty())
    {
        format!("{scope}/{base}")
    } else {
        base
    }
}

fn normalize_npm_init_name(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn normalize_npm_scope(scope: &str) -> String {
    let scope = scope.trim().trim_start_matches('@');
    if scope.is_empty() {
        String::new()
    } else {
        format!("@{}", normalize_npm_init_name(scope))
    }
}

fn npm_cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".omc").join("cache").join("npm")
}

fn print_npm_pkg(project_dir: &Path, action: NpmPkgAction) -> Result<(), OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let mut package = read_npm_pkg_json(&package_json)?;
    match action {
        NpmPkgAction::Get { fields } => {
            if fields.is_empty() {
                println!("{}", serde_json::to_string_pretty(&package)?);
            } else if fields.len() == 1 {
                let value = npm_pkg_get_path(&package, &fields[0])
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                let mut selected = serde_json::Map::new();
                for field in fields {
                    let value = npm_pkg_get_path(&package, &field)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    selected.insert(field, value);
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::Value::Object(selected))?
                );
            }
        }
        NpmPkgAction::Set { assignments } => {
            for (field, value) in assignments {
                npm_pkg_set_path(&mut package, &field, value)?;
            }
            write_npm_pkg_json(&package_json, &package)?;
        }
        NpmPkgAction::Delete { fields } => {
            for field in fields {
                npm_pkg_delete_path(&mut package, &field);
            }
            write_npm_pkg_json(&package_json, &package)?;
        }
    }
    Ok(())
}

fn print_npm_pack(project_dir: &Path, action: NpmPackAction) -> Result<(), OmcRegistryError> {
    let destination = absolutize_path(project_dir, action.destination);
    if !action.dry_run {
        fs::create_dir_all(&destination)?;
    }
    let package_roots = if action.packages.is_empty() {
        vec![NpmPackInput::Local(PathBuf::from("."))]
    } else {
        action.packages
    };
    let mut results = Vec::new();
    for package in package_roots {
        let result = match package {
            NpmPackInput::Local(package_root) => {
                let root = absolutize_path(project_dir, package_root);
                npm_pack_package(&root, &destination, action.dry_run)?
            }
            NpmPackInput::Registry(spec) => npm_pack_registry_package(
                project_dir,
                &spec,
                &destination,
                action.dry_run,
                action.npm_registry.as_deref(),
            )?,
        };
        if !action.json {
            println!("{}", result.filename);
        }
        results.push(result);
    }
    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &results
                    .into_iter()
                    .map(npm_pack_result_json)
                    .collect::<Vec<_>>()
            )?
        );
    }
    Ok(())
}

fn npm_pack_registry_package(
    project_dir: &Path,
    spec: &str,
    destination: &Path,
    dry_run: bool,
    npm_registry: Option<&str>,
) -> Result<NpmPackResult, OmcRegistryError> {
    let spec = parse_package_spec(spec, Some(Ecosystem::Npm))?;
    let metadata = read_npm_package_metadata(project_dir, &spec, npm_registry)?;
    let tarball_url = npm_view_field_value(&metadata, "dist.tarball")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| OmcRegistryError::MissingArtifact(metadata.name.clone()))?;
    let bytes = reqwest::blocking::get(&tarball_url)?
        .error_for_status()?
        .bytes()?
        .to_vec();
    let filename = npm_pack_filename(&metadata.name, &metadata.version);
    let files = npm_packed_files_from_tarball(&bytes)?;
    let unpacked_size = files.iter().map(|file| file.size).sum();
    let size = if dry_run {
        0
    } else {
        fs::write(destination.join(&filename), &bytes)?;
        bytes.len() as u64
    };
    Ok(NpmPackResult {
        id: format!("{}@{}", metadata.name, metadata.version),
        name: metadata.name,
        version: metadata.version,
        filename,
        size,
        unpacked_size,
        files,
    })
}

fn npm_packed_files_from_tarball(bytes: &[u8]) -> Result<Vec<NpmPackedFile>, OmcRegistryError> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = Vec::new();
    for entry in archive.entries()? {
        let entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let size = entry.size();
        let path = entry.path()?.to_string_lossy().into_owned();
        let path = path
            .strip_prefix("package/")
            .unwrap_or(path.as_str())
            .to_owned();
        files.push(NpmPackedFile { path, size });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

#[derive(Debug)]
struct NpmPackResult {
    id: String,
    name: String,
    version: String,
    filename: String,
    size: u64,
    unpacked_size: u64,
    files: Vec<NpmPackedFile>,
}

#[derive(Debug)]
struct NpmPackedFile {
    path: String,
    size: u64,
}

fn npm_pack_package(
    root: &Path,
    destination: &Path,
    dry_run: bool,
) -> Result<NpmPackResult, OmcRegistryError> {
    if !root.is_dir() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm pack local path `{}` is not a directory",
            root.display()
        )));
    }
    let package_json = root.join("package.json");
    let package = read_npm_pkg_json(&package_json)?;
    let name = npm_package_json_name(&package)?;
    let version = npm_package_json_version(&package)?;
    let filename = npm_pack_filename(&name, &version);
    let tarball = destination.join(&filename);
    let files = collect_npm_pack_files(root)?;
    if files.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm pack local path `{}` has no files",
            root.display()
        )));
    }
    let unpacked_size = files.iter().map(|file| file.size).sum();
    let size = if dry_run {
        0
    } else {
        write_npm_pack_tarball(&tarball, &files)?;
        fs::metadata(&tarball)?.len()
    };
    Ok(NpmPackResult {
        id: format!("{name}@{version}"),
        name,
        version,
        filename,
        size,
        unpacked_size,
        files: files
            .into_iter()
            .map(|file| NpmPackedFile {
                path: file.relative_path,
                size: file.size,
            })
            .collect(),
    })
}

#[derive(Debug)]
struct NpmPackSourceFile {
    source: PathBuf,
    relative_path: String,
    archive_path: String,
    size: u64,
}

fn collect_npm_pack_files(root: &Path) -> Result<Vec<NpmPackSourceFile>, OmcRegistryError> {
    let mut files = Vec::new();
    collect_npm_pack_files_recursive(root, root, &mut files)?;
    files.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(files)
}

fn collect_npm_pack_files_recursive(
    root: &Path,
    dir: &Path,
    files: &mut Vec<NpmPackSourceFile>,
) -> Result<(), OmcRegistryError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if file_type.is_dir() {
            if npm_pack_excluded_dir(&name) {
                continue;
            }
            collect_npm_pack_files_recursive(root, &path, files)?;
        } else if file_type.is_file() {
            if npm_pack_excluded_file(&name) {
                continue;
            }
            let metadata = entry.metadata()?;
            let relative = path.strip_prefix(root).map_err(|error| {
                OmcRegistryError::UnsupportedSpec(format!(
                    "could not pack `{}` relative to `{}`: {error}",
                    path.display(),
                    root.display()
                ))
            })?;
            let relative_path = path_to_archive_string(relative)?;
            files.push(NpmPackSourceFile {
                source: path,
                archive_path: format!("package/{relative_path}"),
                relative_path,
                size: metadata.len(),
            });
        }
    }
    Ok(())
}

fn npm_pack_excluded_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | "node_modules" | ".omc" | "target"
    )
}

fn npm_pack_excluded_file(name: &str) -> bool {
    name == ".DS_Store" || name.ends_with(".tgz") || name.ends_with(".tar.gz")
}

fn write_npm_pack_tarball(
    tarball: &Path,
    files: &[NpmPackSourceFile],
) -> Result<(), OmcRegistryError> {
    let file = fs::File::create(tarball)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for file in files {
        let mut input = fs::File::open(&file.source)?;
        let mut header = tar::Header::new_gnu();
        header.set_path(&file.archive_path)?;
        header.set_size(file.size);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, &file.archive_path, &mut input)?;
    }
    let encoder = archive.into_inner()?;
    encoder.finish()?;
    Ok(())
}

fn npm_package_json_name(package: &serde_json::Value) -> Result<String, OmcRegistryError> {
    package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("package.json does not define name".to_owned())
        })
}

fn npm_pack_filename(name: &str, version: &str) -> String {
    let name = name.trim_start_matches('@').replace('/', "-");
    format!("{name}-{version}.tgz")
}

fn path_to_archive_string(path: &Path) -> Result<String, OmcRegistryError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported package path `{}`",
                path.display()
            )));
        };
        let Some(part) = part.to_str() else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "package path `{}` is not UTF-8",
                path.display()
            )));
        };
        parts.push(part.to_owned());
    }
    Ok(parts.join("/"))
}

fn npm_pack_result_json(result: NpmPackResult) -> serde_json::Value {
    serde_json::json!({
        "id": result.id,
        "name": result.name,
        "version": result.version,
        "filename": result.filename,
        "size": result.size,
        "unpackedSize": result.unpacked_size,
        "entryCount": result.files.len(),
        "files": result.files.into_iter().map(|file| {
            serde_json::json!({
                "path": file.path,
                "size": file.size,
            })
        }).collect::<Vec<_>>(),
    })
}

fn read_npm_pkg_json(path: &Path) -> Result<serde_json::Value, OmcRegistryError> {
    if !path.exists() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{} does not exist",
            path.display()
        )));
    }
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if !value.is_object() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{} must contain a JSON object",
            path.display()
        )));
    }
    Ok(value)
}

fn write_npm_pkg_json(path: &Path, value: &serde_json::Value) -> Result<(), OmcRegistryError> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn npm_pkg_get_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in npm_pkg_path_segments(path) {
        current = current.get(segment)?;
    }
    Some(current)
}

fn npm_pkg_set_path(
    value: &mut serde_json::Value,
    path: &str,
    new_value: serde_json::Value,
) -> Result<(), OmcRegistryError> {
    let segments = npm_pkg_path_segments(path);
    if segments.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm pkg set needs a non-empty key".to_owned(),
        ));
    }
    let mut current = value;
    for segment in &segments[..segments.len() - 1] {
        if !current.is_object() {
            *current = serde_json::Value::Object(serde_json::Map::new());
        }
        let object = current.as_object_mut().ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("cannot set npm pkg path `{path}`"))
        })?;
        current = object
            .entry((*segment).to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    let object = current.as_object_mut().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!("cannot set npm pkg path `{path}`"))
    })?;
    object.insert(segments[segments.len() - 1].to_owned(), new_value);
    Ok(())
}

fn npm_pkg_delete_path(value: &mut serde_json::Value, path: &str) -> bool {
    let segments = npm_pkg_path_segments(path);
    if segments.is_empty() {
        return false;
    }
    let mut current = value;
    for segment in &segments[..segments.len() - 1] {
        let Some(next) = current.get_mut(*segment) else {
            return false;
        };
        current = next;
    }
    current
        .as_object_mut()
        .and_then(|object| object.remove(segments[segments.len() - 1]))
        .is_some()
}

fn npm_pkg_path_segments(path: &str) -> Vec<&str> {
    path.split('.')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect()
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

fn print_pip_debug(project_dir: &Path, action: PipDebugAction) -> Result<(), OmcRegistryError> {
    print!("{}", pip_debug_report(project_dir, &action)?);
    Ok(())
}

fn pip_debug_report(
    project_dir: &Path,
    action: &PipDebugAction,
) -> Result<String, OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let cache_dir = pip_cache_dir(&project_dir);
    let executable = env::current_exe()?;
    let values = pip_config_values(&project_dir)?;
    let lockfile = project_dir.join("omc.lock");
    let packages = if lockfile.exists() {
        read_lockfile(&lockfile)?
            .packages
            .into_iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut lines = vec![
        "WARNING: This command is only meant for OMC compatibility debugging.".to_owned(),
        format!("pip version: omc-pip {}", env!("CARGO_PKG_VERSION")),
        format!("omc executable: {}", executable.display()),
        format!("omc project: {}", project_dir.display()),
        format!("sys.platform: {}", env::consts::OS),
        format!("architecture: {}", env::consts::ARCH),
        format!("python site-packages: {}", site_packages.display()),
        format!("pip cache dir: {}", cache_dir.display()),
        format!(
            "lockfile: {} ({})",
            lockfile.display(),
            if lockfile.exists() {
                "present"
            } else {
                "missing"
            }
        ),
        format!("installed pypi packages: {}", packages.len()),
        format!(
            "global.index-url: {}",
            values
                .get("global.index-url")
                .map(String::as_str)
                .unwrap_or("not configured")
        ),
        format!(
            "global.no-index: {}",
            values
                .get("global.no-index")
                .map(String::as_str)
                .unwrap_or("false")
        ),
        format!(
            "global.extra-index-url: {}",
            values
                .get("global.extra-index-url")
                .map(String::as_str)
                .unwrap_or("not configured")
        ),
        format!(
            "global.find-links: {}",
            values
                .get("global.find-links")
                .map(String::as_str)
                .unwrap_or("not configured")
        ),
        format!(
            "REQUESTS_CA_BUNDLE: {}",
            env::var("REQUESTS_CA_BUNDLE").unwrap_or_else(|_| "None".to_owned())
        ),
        format!(
            "CURL_CA_BUNDLE: {}",
            env::var("CURL_CA_BUNDLE").unwrap_or_else(|_| "None".to_owned())
        ),
    ];

    if action.platform.is_some()
        || action.python_version.is_some()
        || action.implementation.is_some()
        || !action.abis.is_empty()
    {
        lines.push("requested compatibility target:".to_owned());
        lines.push(format!(
            "  platform: {}",
            action.platform.as_deref().unwrap_or("current")
        ));
        lines.push(format!(
            "  python-version: {}",
            action.python_version.as_deref().unwrap_or("current")
        ));
        lines.push(format!(
            "  implementation: {}",
            action.implementation.as_deref().unwrap_or("current")
        ));
        lines.push(format!(
            "  abi: {}",
            if action.abis.is_empty() {
                "current".to_owned()
            } else {
                action.abis.join(", ")
            }
        ));
    }

    lines.push("compatible tags: not computed by OMC compatibility mode".to_owned());

    if action.verbose {
        lines.push("locked pypi packages:".to_owned());
        if packages.is_empty() {
            lines.push("  (none)".to_owned());
        } else {
            for package in packages {
                lines.push(format!(
                    "  {}=={} ({})",
                    package.name,
                    package.version,
                    pip_locked_package_filetype(&package)
                ));
            }
        }
    }

    Ok(format!("{}\n", lines.join("\n")))
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
    match action {
        PipConfigAction::Set {
            assignments,
            location,
        } => {
            write_pip_config_assignments(project_dir, location, &assignments)?;
            return Ok(());
        }
        PipConfigAction::Unset { keys, location } => {
            unset_pip_config_keys(project_dir, location, &keys)?;
            return Ok(());
        }
        PipConfigAction::Get { .. } | PipConfigAction::List { .. } => {}
    }

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
        PipConfigAction::Set { .. } | PipConfigAction::Unset { .. } => unreachable!(),
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

fn write_pip_config_assignments(
    project_dir: &Path,
    location: PipConfigLocation,
    assignments: &[(String, String)],
) -> Result<(), OmcRegistryError> {
    let path = pip_config_write_path(project_dir, location)?;
    let mut lines = read_pip_config_lines(&path)?;
    for (key, value) in assignments {
        let (section, key) = normalize_pip_config_key(key)?;
        upsert_pip_config_line(&mut lines, &section, &key, value);
    }
    write_pip_config_lines(&path, &lines)
}

fn unset_pip_config_keys(
    project_dir: &Path,
    location: PipConfigLocation,
    keys: &[String],
) -> Result<(), OmcRegistryError> {
    let path = pip_config_write_path(project_dir, location)?;
    let mut lines = read_pip_config_lines(&path)?;
    for key in keys {
        for (section, key) in pip_config_unset_targets(key)? {
            remove_pip_config_line(&mut lines, &section, &key);
        }
    }
    write_pip_config_lines(&path, &lines)
}

fn pip_config_write_path(
    project_dir: &Path,
    location: PipConfigLocation,
) -> Result<PathBuf, OmcRegistryError> {
    match location {
        PipConfigLocation::Auto => {
            if let Some(path) = env::var_os("PIP_CONFIG_FILE")
                .map(PathBuf::from)
                .filter(|path| !path.as_os_str().is_empty())
            {
                Ok(absolutize_path(project_dir, path))
            } else {
                Ok(project_dir.join("pip.conf"))
            }
        }
        PipConfigLocation::Site => Ok(project_dir.join("pip.conf")),
        PipConfigLocation::User => Ok(pip_user_config_path(project_dir)),
        PipConfigLocation::Global => Err(OmcRegistryError::UnsupportedSpec(
            "pip config --global writes are not supported by OMC compatibility".to_owned(),
        )),
    }
}

fn pip_user_config_path(project_dir: &Path) -> PathBuf {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return path.join("pip").join("pip.conf");
    }
    if let Some(home) = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        return home.join(".config").join("pip").join("pip.conf");
    }
    project_dir.join("pip.conf")
}

fn read_pip_config_lines(path: &Path) -> Result<Vec<String>, OmcRegistryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::to_owned)
        .collect())
}

fn write_pip_config_lines(path: &Path, lines: &[String]) -> Result<(), OmcRegistryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

fn normalize_pip_config_key(key: &str) -> Result<(String, String), OmcRegistryError> {
    let normalized = key.trim().to_ascii_lowercase().replace('_', "-");
    let (section, key) = normalized
        .split_once('.')
        .map(|(section, key)| (section.trim(), key.trim()))
        .unwrap_or(("global", normalized.trim()));
    if section.is_empty() || key.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid pip config key `{key}`"
        )));
    }
    Ok((section.to_owned(), key.to_owned()))
}

fn pip_config_unset_targets(key: &str) -> Result<Vec<(String, String)>, OmcRegistryError> {
    let normalized = key.trim().to_ascii_lowercase().replace('_', "-");
    if normalized.contains('.') {
        return normalize_pip_config_key(&normalized).map(|target| vec![target]);
    }
    if normalized.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config key cannot be empty".to_owned(),
        ));
    }
    Ok(vec![
        ("global".to_owned(), normalized.clone()),
        ("install".to_owned(), normalized),
    ])
}

fn upsert_pip_config_line(lines: &mut Vec<String>, section: &str, key: &str, value: &str) {
    if let Some((start, end)) = pip_config_section_range(lines, section) {
        if let Some(line) = lines[start..end]
            .iter_mut()
            .find(|line| pip_config_line_key_matches(line, key))
        {
            *line = format!("{key} = {value}");
            return;
        }
        let insert_at = pip_config_section_insert_index(lines, start, end);
        lines.insert(insert_at, format!("{key} = {value}"));
        return;
    }

    if !lines.is_empty() && lines.last().is_some_and(|line| !line.trim().is_empty()) {
        lines.push(String::new());
    }
    lines.push(format!("[{section}]"));
    lines.push(format!("{key} = {value}"));
}

fn remove_pip_config_line(lines: &mut Vec<String>, section: &str, key: &str) {
    let Some((start, end)) = pip_config_section_range(lines, section) else {
        return;
    };
    let mut index = start;
    while index < end && index < lines.len() {
        if pip_config_line_key_matches(&lines[index], key) {
            lines.remove(index);
        } else {
            index += 1;
        }
    }
}

fn pip_config_section_insert_index(lines: &[String], start: usize, end: usize) -> usize {
    let mut index = end;
    while index > start && lines[index - 1].trim().is_empty() {
        index -= 1;
    }
    index
}

fn pip_config_section_range(lines: &[String], section: &str) -> Option<(usize, usize)> {
    let mut start = None;
    for (index, line) in lines.iter().enumerate() {
        let Some(found) = pip_config_section_name(line) else {
            continue;
        };
        if let Some(start) = start {
            return Some((start, index));
        }
        if found == section {
            start = Some(index + 1);
        }
    }
    start.map(|start| (start, lines.len()))
}

fn pip_config_section_name(line: &str) -> Option<String> {
    let line = strip_pip_config_comment(line).trim();
    line.strip_prefix('[')
        .and_then(|line| line.strip_suffix(']'))
        .map(str::trim)
        .filter(|section| !section.is_empty())
        .map(|section| section.to_ascii_lowercase())
}

fn pip_config_line_key_matches(line: &str, key: &str) -> bool {
    let line = strip_pip_config_comment(line).trim();
    let Some((found, _)) = line.split_once('=') else {
        return false;
    };
    found.trim().to_ascii_lowercase().replace('_', "-") == key
}

fn strip_pip_config_comment(line: &str) -> &str {
    strip_npm_config_comment(line)
}

fn print_lock_only_report(project_dir: &Path) {
    println!("lockfile {}", project_dir.join("omc.lock").display());
}

fn print_npm_maintenance_report(
    command: NpmMaintenanceCommand,
    packages: &[String],
    install: &InstallReport,
) {
    match command {
        NpmMaintenanceCommand::Prune => println!("pruned OMC npm install state"),
        NpmMaintenanceCommand::Dedupe => println!("deduped OMC npm install state"),
        NpmMaintenanceCommand::Rebuild => {
            if packages.is_empty() {
                println!("rebuilt OMC npm install state without package lifecycle scripts");
            } else {
                println!(
                    "rebuilt OMC npm package request without package lifecycle scripts: {}",
                    packages.join(", ")
                );
            }
        }
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
    filters: &[String],
) -> Result<(), OmcRegistryError> {
    let filter_names = package_list_filter_names(filters, ecosystem)?;
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let packages = lock
        .packages
        .into_iter()
        .filter(|package| {
            ecosystem
                .map(|ecosystem| package.ecosystem == ecosystem)
                .unwrap_or(true)
        })
        .filter(|package| filter_names.is_empty() || filter_names.contains(&package.name))
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

fn package_list_filter_names(
    filters: &[String],
    ecosystem: Option<Ecosystem>,
) -> Result<BTreeSet<String>, OmcRegistryError> {
    filters
        .iter()
        .map(|filter| parse_package_spec(filter, ecosystem).map(|spec| spec.name))
        .collect()
}

fn print_locked_freeze(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    for package in lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
    {
        println!("{}=={}", package.name, package.version);
    }
    for dependency in &lock.python_vcs {
        println!("{}", pip_freeze_vcs_requirement(dependency));
    }
    Ok(())
}

fn pip_freeze_vcs_requirement(dependency: &LockedPythonVcsDependency) -> String {
    let mut name = dependency.name.clone();
    if !dependency.extras.is_empty() {
        name.push('[');
        name.push_str(&dependency.extras.join(","));
        name.push(']');
    }

    let reference = if dependency.resolved_commit.is_empty() {
        dependency.reference.as_deref().unwrap_or_default()
    } else {
        dependency.resolved_commit.as_str()
    };
    let mut url = format!("git+{}", dependency.url);
    if !reference.is_empty() {
        url.push('@');
        url.push_str(reference);
    }
    if let Some(subdirectory) = &dependency.subdirectory {
        if !subdirectory.is_empty() {
            url.push_str("#subdirectory=");
            url.push_str(subdirectory);
        }
    }

    format!("{name} @ {url}")
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

fn print_locked_pip_inspect(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let installed = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .map(|package| {
            let metadata_location = match_dist_info_dir(&site_packages, &package)?
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| site_packages.display().to_string());
            Ok(serde_json::json!({
                "metadata": {
                    "name": package.name,
                    "version": package.version,
                },
                "metadata_location": metadata_location,
                "installer": "omc",
                "requested": false,
                "dependencies": package.dependencies,
            }))
        })
        .collect::<Result<Vec<_>, OmcRegistryError>>()?;
    let value = serde_json::json!({
        "version": "1",
        "pip_version": format!("omc-{}", env!("CARGO_PKG_VERSION")),
        "installed": installed,
        "environment": {},
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
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
    apply_project_runtime_env_for_cwd(command, project_dir, project_dir)
}

fn apply_project_runtime_env_for_cwd(
    command: &mut ProcessCommand,
    project_dir: &Path,
    cwd: &Path,
) -> Result<(), OmcRegistryError> {
    command
        .current_dir(cwd)
        .env("PATH", project_path_for_cwd(project_dir, cwd)?)
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

fn project_path_for_cwd(project_dir: &Path, cwd: &Path) -> Result<OsString, OmcRegistryError> {
    let mut paths = vec![
        cwd.join("node_modules").join(".bin"),
        project_dir.join("node_modules").join(".bin"),
        project_dir.join(".omc").join("python").join("bin"),
    ];
    paths.dedup();
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
    let normalized = normalize_npm_global_args(args)?;
    let args = normalized.as_slice();
    if let Some(action) = parse_npm_help_request(args) {
        return Ok(action);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(NpmCompatAction::Install {
            specs: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            dev: false,
            omit_dev: false,
            lock_only: false,
            dry_run: false,
            npm_registry: None,
            allow: Vec::new(),
            allow_all_host: false,
        });
    };

    match command {
        "--version" | "-v" => Ok(NpmCompatAction::Version),
        "init" => parse_npm_init_args(&args[1..]),
        "version" => parse_npm_version_args(&args[1..]),
        "install-test" | "it" => parse_npm_install_test_args(command, false, &args[1..]),
        "install-ci-test" | "cit" => parse_npm_install_test_args(command, true, &args[1..]),
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
        "rebuild" | "rb" => parse_npm_rebuild_args(&args[1..]),
        "run" | "run-script" => {
            let NpmRunArgs {
                name,
                args,
                if_present,
                json,
                workspaces,
                all_workspaces,
                include_workspace_root,
            } = parse_npm_run_args("npm run", &args[1..], None)?;
            if let Some(name) = name {
                Ok(NpmCompatAction::RunScript {
                    command: command.to_owned(),
                    name,
                    args,
                    if_present,
                    workspaces,
                    all_workspaces,
                    include_workspace_root,
                })
            } else {
                Ok(NpmCompatAction::RunList {
                    action: NpmRunListAction {
                        json,
                        workspaces,
                        all_workspaces,
                        include_workspace_root,
                    },
                })
            }
        }
        "test" | "start" | "stop" | "restart" => {
            let NpmRunArgs {
                name,
                args,
                if_present,
                json: _,
                workspaces,
                all_workspaces,
                include_workspace_root,
            } = parse_npm_run_args(command, &args[1..], Some(command))?;
            Ok(NpmCompatAction::RunScript {
                command: command.to_owned(),
                name: name.expect("implicit npm script command has a script name"),
                args,
                if_present,
                workspaces,
                all_workspaces,
                include_workspace_root,
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
        "list" | "ls" | "ll" | "la" => parse_npm_list_args(&args[1..]),
        "explain" | "why" => parse_npm_explain_args(&args[1..]),
        "outdated" => parse_npm_outdated_args(&args[1..]),
        "audit" => parse_npm_audit_args(&args[1..]),
        "fund" => parse_npm_fund_args(&args[1..]),
        "cache" => parse_npm_cache_args(&args[1..]),
        "pkg" => parse_npm_pkg_args(&args[1..]),
        "pack" => parse_npm_pack_args(&args[1..]),
        "search" | "s" | "se" | "find" => parse_npm_search_args(&args[1..]),
        "view" | "info" | "show" | "v" => parse_npm_view_args(&args[1..]),
        "config" | "c" => parse_npm_config_args(&args[1..]),
        "get" => parse_npm_config_get_args(&args[1..]),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm compatibility command `{other}`"
        ))),
    }
}

fn parse_npm_help_request(args: &[String]) -> Option<NpmCompatAction> {
    let command = args.first()?;
    if npm_help_flag(command) {
        return Some(NpmCompatAction::Help { topic: None });
    }
    if command == "help" {
        let topic = args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned();
        return Some(NpmCompatAction::Help { topic });
    }
    if args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| npm_help_flag(arg))
    {
        return Some(NpmCompatAction::Help {
            topic: Some(command.clone()),
        });
    }
    None
}

fn npm_help_flag(arg: &str) -> bool {
    matches!(arg, "--help" | "-h")
}

fn normalize_npm_global_args(args: &[String]) -> Result<Vec<String>, OmcRegistryError> {
    let mut preserved = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--version" | "-v") {
            return Ok(vec![arg.clone()]);
        } else if npm_global_preserved_bool_flag(arg) {
            preserved.push(arg.clone());
        } else if npm_global_preserved_value_flag(arg) {
            preserved.push(arg.clone());
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            preserved.push(value.clone());
        } else if npm_global_preserved_equals_flag(arg) {
            preserved.push(arg.clone());
        } else if npm_global_ignored_bool_flag(arg) || npm_global_ignored_equals_flag(arg) {
        } else if npm_global_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with('-') {
            return Ok(args[index..].to_vec());
        } else {
            if preserved.is_empty() && index == 0 {
                return Ok(args.to_vec());
            }
            let preserved = npm_preserved_global_args_for_command(arg, preserved);
            let mut normalized = Vec::with_capacity(args.len());
            normalized.push(arg.clone());
            normalized.extend(preserved);
            normalized.extend(args[index + 1..].iter().cloned());
            return Ok(normalized);
        }
        index += 1;
    }

    if preserved.is_empty() {
        Ok(Vec::new())
    } else {
        let preserved = npm_preserved_global_args_for_command("install", preserved);
        let mut normalized = Vec::with_capacity(preserved.len() + 1);
        normalized.push("install".to_owned());
        normalized.extend(preserved);
        Ok(normalized)
    }
}

fn npm_preserved_global_args_for_command(command: &str, args: Vec<String>) -> Vec<String> {
    let mut selected = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let include = npm_global_arg_supported_by_command(command, arg);
        if include {
            selected.push(arg.clone());
        }
        if npm_global_preserved_value_flag(arg) {
            index += 1;
            if include {
                if let Some(value) = args.get(index) {
                    selected.push(value.clone());
                }
            }
        }
        index += 1;
    }
    selected
}

fn npm_global_arg_supported_by_command(command: &str, arg: &str) -> bool {
    if matches!(arg, "--global" | "-g") {
        return true;
    }
    if matches!(arg, "--registry") || arg.starts_with("--registry=") {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "install-test"
                | "it"
                | "ci"
                | "outdated"
                | "pack"
                | "search"
                | "s"
                | "se"
                | "find"
                | "view"
                | "info"
                | "show"
                | "v"
                | "config"
                | "c"
                | "get"
        );
    }
    if matches!(arg, "--userconfig") || arg.starts_with("--userconfig=") {
        return matches!(command, "config" | "c" | "get");
    }
    if matches!(arg, "--workspace" | "-w")
        || arg.starts_with("--workspace=")
        || arg.starts_with("-w=")
    {
        return matches!(
            command,
            "run" | "run-script" | "test" | "start" | "stop" | "restart" | "fund"
        );
    }
    if matches!(arg, "--workspaces" | "--include-workspace-root")
        || arg.starts_with("--include-workspace-root=")
    {
        return matches!(
            command,
            "run" | "run-script" | "test" | "start" | "stop" | "restart" | "fund"
        );
    }
    if arg == "--json" {
        return matches!(
            command,
            "version"
                | "run"
                | "run-script"
                | "list"
                | "ls"
                | "ll"
                | "la"
                | "explain"
                | "why"
                | "outdated"
                | "audit"
                | "fund"
                | "pkg"
                | "pack"
                | "search"
                | "s"
                | "se"
                | "find"
                | "view"
                | "info"
                | "show"
                | "v"
                | "config"
                | "c"
                | "get"
        );
    }
    if matches!(arg, "--depth") || arg.starts_with("--depth=") {
        return matches!(command, "list" | "ls" | "ll" | "la" | "outdated");
    }
    if matches!(arg, "--searchlimit" | "--limit")
        || arg.starts_with("--searchlimit=")
        || arg.starts_with("--limit=")
    {
        return matches!(command, "search" | "s" | "se" | "find");
    }
    if matches!(arg, "--omit" | "--include")
        || arg.starts_with("--omit=")
        || arg.starts_with("--include=")
    {
        return matches!(
            command,
            "install"
                | "i"
                | "add"
                | "update"
                | "up"
                | "upgrade"
                | "install-test"
                | "it"
                | "ci"
                | "install-ci-test"
                | "cit"
                | "prune"
                | "dedupe"
                | "ddp"
                | "find-dupes"
                | "rebuild"
                | "rb"
                | "list"
                | "ls"
                | "ll"
                | "la"
                | "outdated"
        );
    }
    false
}

fn npm_global_preserved_bool_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--json" | "--global" | "-g" | "--workspaces" | "--include-workspace-root"
    )
}

fn npm_global_preserved_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--registry"
            | "--userconfig"
            | "--depth"
            | "--omit"
            | "--include"
            | "--searchlimit"
            | "--limit"
            | "--workspace"
            | "-w"
    )
}

fn npm_global_preserved_equals_flag(arg: &str) -> bool {
    [
        "--registry=",
        "--userconfig=",
        "--depth=",
        "--omit=",
        "--include=",
        "--searchlimit=",
        "--limit=",
        "--workspace=",
        "-w=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_global_ignored_bool_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--silent"
            | "-s"
            | "--quiet"
            | "-q"
            | "--no-progress"
            | "--progress=false"
            | "--no-color"
            | "--color=false"
            | "--foreground-scripts"
    )
}

fn npm_global_ignored_value_flag(arg: &str) -> bool {
    matches!(arg, "--cache" | "--loglevel")
}

fn npm_global_ignored_equals_flag(arg: &str) -> bool {
    ["--cache=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
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
        packages: Vec::new(),
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

fn parse_npm_rebuild_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "--dry-run"
                | "--json"
                | "--silent"
                | "-s"
                | "--force"
                | "-f"
                | "--ignore-scripts"
                | "--foreground-scripts"
                | "--build-from-source"
                | "--bin-links"
                | "--no-bin-links"
                | "--install-links"
                | "--no-install-links"
                | "--audit"
                | "--audit=false"
                | "--fund"
                | "--fund=false"
        ) {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--cache" | "--install-strategy"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_rebuild_equals_value_flag(arg) {
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

    Ok(NpmCompatAction::Maintenance {
        command: NpmMaintenanceCommand::Rebuild,
        packages: positionals,
        omit_dev,
        allow,
        allow_all_host,
    })
}

fn npm_rebuild_equals_value_flag(arg: &str) -> bool {
    [
        "--loglevel=",
        "--cache=",
        "--install-strategy=",
        "--audit=",
        "--fund=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_init_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut action = NpmInitAction {
        name: None,
        version: None,
        description: None,
        main: None,
        license: None,
        scope: None,
        private: false,
        package_type: None,
    };
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "-y" | "--yes" | "--force") {
        } else if arg == "--private" {
            action.private = true;
        } else if arg == "--name" {
            action.name = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--name=") {
            action.name = Some(value.to_owned());
        } else if arg == "--version" {
            action.version = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--version=") {
            action.version = Some(value.to_owned());
        } else if arg == "--description" {
            action.description = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--description=") {
            action.description = Some(value.to_owned());
        } else if arg == "--main" {
            action.main = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--main=") {
            action.main = Some(value.to_owned());
        } else if arg == "--license" {
            action.license = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--license=") {
            action.license = Some(value.to_owned());
        } else if arg == "--scope" {
            action.scope = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--scope=") {
            action.scope = Some(value.to_owned());
        } else if arg == "--type" {
            action.package_type = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--type=") {
            action.package_type = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s") {
        } else if npm_init_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_init_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm init", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }
    if !positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm init package initializer `{}` is not supported by OMC compatibility yet",
            positionals[0]
        )));
    }
    Ok(NpmCompatAction::Init { action })
}

fn npm_init_flag_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

fn npm_init_ignored_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--cache" | "--registry" | "--userconfig" | "--loglevel"
    )
}

fn npm_init_ignored_equals_flag(arg: &str) -> bool {
    ["--cache=", "--registry=", "--userconfig=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_version_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut allow_same_version = false;
    let mut preid = None;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--allow-same-version" {
            allow_same_version = true;
        } else if arg == "--preid" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--preid needs a value".to_owned(),
                ));
            };
            preid = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--preid=") {
            preid = Some(value.to_owned());
        } else if matches!(
            arg.as_str(),
            "--no-git-tag-version"
                | "--git-tag-version=false"
                | "--git-tag-version"
                | "--git-tag-version=true"
                | "--commit-hooks=false"
                | "--sign-git-tag=false"
                | "--silent"
                | "-s"
        ) {
        } else if matches!(arg.as_str(), "--message" | "-m" | "--tag-version-prefix") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_version_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm version", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    let action = if positionals.is_empty() {
        NpmVersionAction::Current { json }
    } else if positionals.len() == 1 {
        NpmVersionAction::Bump {
            spec: positionals.remove(0),
            preid,
            allow_same_version,
            json,
        }
    } else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm version accepts at most one version argument".to_owned(),
        ));
    };
    Ok(NpmCompatAction::PackageVersion { action })
}

fn npm_version_ignored_equals_flag(arg: &str) -> bool {
    ["--message=", "--tag-version-prefix="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_install_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    let mut dry_run = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--dry-run" {
            dry_run = true;
        } else if is_npm_archive_arg(arg) {
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
        dry_run,
        npm_registry,
        allow,
        allow_all_host,
    })
}

fn parse_npm_install_test_args(
    command: &str,
    use_ci: bool,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut command_args = Vec::new();
    let mut test_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            test_args.extend(args[index + 1..].iter().cloned());
            break;
        }
        command_args.push(arg.clone());
        index += 1;
    }

    if use_ci {
        let CommonCompatFlags {
            omit_dev,
            allow,
            allow_all_host,
            positionals,
            ..
        } = parse_common_compat_flags(&command_args, true)?;
        if !positionals.is_empty() {
            return Err(unsupported_compat_arg(command, &positionals[0]));
        }
        return Ok(NpmCompatAction::InstallTest {
            command: command.to_owned(),
            use_ci,
            specs: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            dev: false,
            omit_dev,
            lock_only: false,
            dry_run: false,
            npm_registry: None,
            allow,
            allow_all_host,
            test_args,
        });
    }

    let install = parse_npm_install_args(&command_args)?;
    let NpmCompatAction::Install {
        specs,
        archive_references,
        local_paths,
        save,
        dev,
        omit_dev,
        lock_only,
        dry_run,
        npm_registry,
        allow,
        allow_all_host,
    } = install
    else {
        unreachable!("parse_npm_install_args only returns install actions")
    };
    Ok(NpmCompatAction::InstallTest {
        command: command.to_owned(),
        use_ci,
        specs,
        archive_references,
        local_paths,
        save,
        dev,
        omit_dev,
        lock_only,
        dry_run,
        npm_registry,
        allow,
        allow_all_host,
        test_args,
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

fn parse_npm_fund_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut package = None;
    let mut workspaces = Vec::new();
    let mut all_workspaces = false;
    let mut include_workspace_root = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--workspaces" | "--workspace=true") {
            all_workspaces = true;
        } else if matches!(
            arg.as_str(),
            "--include-workspace-root" | "--include-workspace-root=true"
        ) {
            include_workspace_root = true;
        } else if matches!(
            arg.as_str(),
            "--silent"
                | "-s"
                | "--browser"
                | "--browser=true"
                | "--browser=false"
                | "--no-browser"
                | "--unicode"
                | "--unicode=true"
                | "--unicode=false"
                | "--no-unicode"
                | "--global"
                | "-g"
        ) {
        } else if matches!(arg.as_str(), "--workspace" | "-w") {
            index += 1;
            let Some(workspace) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a workspace"
                )));
            };
            workspaces.push(workspace.clone());
        } else if let Some(workspace) = arg
            .strip_prefix("--workspace=")
            .or_else(|| arg.strip_prefix("-w="))
        {
            workspaces.push(workspace.to_owned());
        } else if matches!(arg.as_str(), "--which" | "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_fund_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm fund", arg));
        } else if package.is_none() {
            package = Some(arg.clone());
        } else {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm fund accepts at most one package argument".to_owned(),
            ));
        }
        index += 1;
    }

    Ok(NpmCompatAction::Fund {
        action: NpmFundAction {
            json,
            package,
            workspaces,
            all_workspaces,
            include_workspace_root,
        },
    })
}

fn npm_fund_equals_value_flag(arg: &str) -> bool {
    [
        "--which=",
        "--loglevel=",
        "--cache=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
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

fn parse_npm_pkg_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(
            arg.as_str(),
            "--silent" | "-s" | "--parseable" | "-p" | "--workspaces" | "--include-workspace-root"
        ) {
        } else if matches!(arg.as_str(), "--workspace" | "-w" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_pkg_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm pkg", arg));
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let command = filtered.first().map(String::as_str).unwrap_or("get");
    let rest = if filtered.is_empty() {
        &[][..]
    } else {
        &filtered[1..]
    };
    let action = match command {
        "get" => NpmPkgAction::Get {
            fields: rest.to_vec(),
        },
        "set" => {
            if rest.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm pkg set needs at least one key=value assignment".to_owned(),
                ));
            }
            let mut assignments = Vec::new();
            for assignment in rest {
                let Some((key, value)) = assignment.split_once('=') else {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "npm pkg set assignment `{assignment}` needs key=value"
                    )));
                };
                if key.trim().is_empty() {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "npm pkg set key cannot be empty".to_owned(),
                    ));
                }
                let value = if json {
                    serde_json::from_str(value).map_err(|error| {
                        OmcRegistryError::UnsupportedSpec(format!(
                            "invalid JSON value for npm pkg set `{assignment}`: {error}"
                        ))
                    })?
                } else {
                    serde_json::Value::String(value.to_owned())
                };
                assignments.push((key.to_owned(), value));
            }
            NpmPkgAction::Set { assignments }
        }
        "delete" | "del" => {
            if rest.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm pkg delete needs at least one key".to_owned(),
                ));
            }
            NpmPkgAction::Delete {
                fields: rest.to_vec(),
            }
        }
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported npm pkg command `{other}`"
            )))
        }
    };
    Ok(NpmCompatAction::Pkg { action })
}

fn npm_pkg_ignored_equals_flag(arg: &str) -> bool {
    ["--workspace=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_pack_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut destination = PathBuf::from(".");
    let mut json = false;
    let mut dry_run = false;
    let mut packages = Vec::new();
    let mut npm_registry = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--dry-run" {
            dry_run = true;
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--ignore-scripts") {
        } else if arg == "--pack-destination" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--pack-destination needs a path".to_owned(),
                ));
            };
            destination = PathBuf::from(path);
        } else if let Some(path) = arg.strip_prefix("--pack-destination=") {
            destination = PathBuf::from(path);
        } else if arg == "--registry" {
            index += 1;
            let Some(registry) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--registry needs a URL".to_owned(),
                ));
            };
            npm_registry = Some(registry.clone());
        } else if let Some(registry) = arg.strip_prefix("--registry=") {
            npm_registry = Some(registry.to_owned());
        } else if npm_pack_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_pack_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm pack", arg));
        } else if npm_pack_local_package_arg(arg) {
            packages.push(NpmPackInput::Local(PathBuf::from(arg)));
        } else {
            packages.push(NpmPackInput::Registry(arg.clone()));
        }
        index += 1;
    }
    Ok(NpmCompatAction::Pack {
        action: NpmPackAction {
            packages,
            destination,
            json,
            dry_run,
            npm_registry,
        },
    })
}

fn npm_pack_local_package_arg(arg: &str) -> bool {
    arg == "."
        || arg.starts_with("./")
        || arg.starts_with("../")
        || arg.starts_with('/')
        || arg.starts_with("~/")
        || Path::new(arg).is_dir()
}

fn npm_pack_ignored_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--workspace" | "-w" | "--include-workspace-root" | "--loglevel"
    )
}

fn npm_pack_ignored_equals_flag(arg: &str) -> bool {
    [
        "--workspace=",
        "--include-workspace-root=",
        "--loglevel=",
        "--cache=",
        "--registry=",
        "--userconfig=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_search_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut parseable = false;
    let mut limit = 20usize;
    let mut npm_registry = None;
    let mut terms = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--parseable" | "-p" | "--parseable=true") {
            parseable = true;
        } else if arg == "--parseable=false" {
            parseable = false;
        } else if arg == "--registry" {
            index += 1;
            let Some(registry) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--registry needs a URL".to_owned(),
                ));
            };
            npm_registry = Some(registry.clone());
        } else if let Some(registry) = arg.strip_prefix("--registry=") {
            npm_registry = Some(registry.to_owned());
        } else if matches!(arg.as_str(), "--searchlimit" | "--limit") {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            limit = parse_npm_search_limit(value)?;
        } else if let Some(value) = arg
            .strip_prefix("--searchlimit=")
            .or_else(|| arg.strip_prefix("--limit="))
        {
            limit = parse_npm_search_limit(value)?;
        } else if matches!(
            arg.as_str(),
            "--long"
                | "--description"
                | "--no-description"
                | "--color=false"
                | "--no-color"
                | "--silent"
                | "-s"
        ) {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--searchopts" | "--searchexclude"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_search_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm search", arg));
        } else {
            terms.push(arg.clone());
        }
        index += 1;
    }
    if terms.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm search needs search terms".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Search {
        action: NpmSearchAction {
            query: terms.join(" "),
            json,
            parseable,
            limit,
            npm_registry,
        },
    })
}

fn parse_npm_search_limit(value: &str) -> Result<usize, OmcRegistryError> {
    value
        .parse::<usize>()
        .ok()
        .filter(|limit| *limit > 0)
        .map(|limit| limit.min(250))
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("invalid npm search limit `{value}`"))
        })
}

fn npm_search_ignored_equals_flag(arg: &str) -> bool {
    [
        "--loglevel=",
        "--searchopts=",
        "--searchexclude=",
        "--description=",
        "--parseable=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_explain_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut specs = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--long" | "--parseable") {
        } else if matches!(arg.as_str(), "--workspace" | "-w" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_explain_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm explain", arg));
        } else {
            specs.push(arg.clone());
        }
        index += 1;
    }
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm explain needs at least one package".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Explain { specs, json })
}

fn npm_explain_ignored_equals_flag(arg: &str) -> bool {
    ["--workspace=", "--loglevel="]
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
        "set" => parse_npm_config_set_args(&args[1..]),
        "delete" | "del" | "rm" | "unset" => parse_npm_config_delete_args(&args[1..]),
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

fn parse_npm_config_set_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let NpmConfigArgs {
        npm_registry,
        userconfig,
        positionals,
        ..
    } = parse_npm_config_common_args(args)?;
    let assignments = parse_npm_config_assignments(positionals)?;
    Ok(NpmCompatAction::Config {
        action: NpmConfigAction::Set { assignments },
        npm_registry,
        userconfig,
    })
}

fn parse_npm_config_delete_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let NpmConfigArgs {
        npm_registry,
        userconfig,
        positionals,
        ..
    } = parse_npm_config_common_args(args)?;
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config delete needs at least one key".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Config {
        action: NpmConfigAction::Delete { keys: positionals },
        npm_registry,
        userconfig,
    })
}

fn parse_npm_config_assignments(
    positionals: Vec<String>,
) -> Result<Vec<(String, String)>, OmcRegistryError> {
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config set needs a key and value".to_owned(),
        ));
    }
    if positionals.iter().any(|value| value.contains('=')) {
        return positionals
            .into_iter()
            .map(|assignment| {
                let Some((key, value)) = assignment.split_once('=') else {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "npm config set mixed assignment formats at `{assignment}`"
                    )));
                };
                npm_config_assignment(key, value)
            })
            .collect();
    }
    if positionals.len() != 2 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config set needs either KEY VALUE or KEY=VALUE".to_owned(),
        ));
    }
    npm_config_assignment(&positionals[0], &positionals[1]).map(|assignment| vec![assignment])
}

fn npm_config_assignment(key: &str, value: &str) -> Result<(String, String), OmcRegistryError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config key cannot be empty".to_owned(),
        ));
    }
    Ok((key.to_owned(), value.trim().to_owned()))
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
    name: Option<String>,
    args: Vec<String>,
    if_present: bool,
    json: bool,
    workspaces: Vec<String>,
    all_workspaces: bool,
    include_workspace_root: bool,
}

fn parse_npm_run_args(
    command: &str,
    args: &[String],
    implicit_name: Option<&str>,
) -> Result<NpmRunArgs, OmcRegistryError> {
    let mut name = implicit_name.map(str::to_owned);
    let mut script_args = Vec::new();
    let mut if_present = false;
    let mut json = false;
    let mut workspaces = Vec::new();
    let mut all_workspaces = false;
    let mut include_workspace_root = false;
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
        } else if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--workspaces" | "--workspace=true") {
            all_workspaces = true;
        } else if matches!(
            arg.as_str(),
            "--include-workspace-root" | "--include-workspace-root=true"
        ) {
            include_workspace_root = true;
        } else if matches!(arg.as_str(), "--workspace" | "-w") {
            index += 1;
            let Some(workspace) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a workspace"
                )));
            };
            workspaces.push(workspace.clone());
        } else if let Some(workspace) = arg
            .strip_prefix("--workspace=")
            .or_else(|| arg.strip_prefix("-w="))
        {
            workspaces.push(workspace.to_owned());
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

    if name.is_none() && !script_args.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{command} needs a target"
        )));
    }
    Ok(NpmRunArgs {
        name,
        args: script_args,
        if_present,
        json,
        workspaces,
        all_workspaces,
        include_workspace_root,
    })
}

fn npm_run_equals_value_flag(arg: &str) -> bool {
    ["--loglevel=", "--include-workspace-root="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
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
    let normalized = normalize_pip_global_args(args)?;
    let args = normalized.as_slice();
    if let Some(action) = parse_pip_help_request(args) {
        return Ok(action);
    }
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
        "wheel" => parse_pip_wheel_args(&args[1..]),
        "uninstall" | "remove" => parse_pip_uninstall_args(&args[1..]),
        "show" => parse_pip_show_args(&args[1..]),
        "hash" => parse_pip_hash_args(&args[1..]),
        "cache" => parse_pip_cache_args(&args[1..]),
        "check" => {
            parse_pip_check_args(&args[1..])?;
            Ok(PipCompatAction::Check)
        }
        "debug" => parse_pip_debug_args(&args[1..]),
        "inspect" => {
            parse_pip_inspect_args(&args[1..])?;
            Ok(PipCompatAction::Inspect)
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

fn parse_pip_help_request(args: &[String]) -> Option<PipCompatAction> {
    let command = args.first()?;
    if pip_help_flag(command) {
        return Some(PipCompatAction::Help { topic: None });
    }
    if command == "help" {
        let topic = args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned();
        return Some(PipCompatAction::Help { topic });
    }
    if args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| pip_help_flag(arg))
    {
        return Some(PipCompatAction::Help {
            topic: Some(command.clone()),
        });
    }
    None
}

fn pip_help_flag(arg: &str) -> bool {
    matches!(arg, "--help" | "-h")
}

fn normalize_pip_global_args(args: &[String]) -> Result<Vec<String>, OmcRegistryError> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--version" | "-V") {
            return Ok(vec![arg.clone()]);
        } else if pip_global_ignored_bool_flag(arg) || pip_global_ignored_equals_flag(arg) {
        } else if pip_global_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with('-') {
            return Ok(args[index..].to_vec());
        } else if index == 0 {
            return Ok(args.to_vec());
        } else {
            return Ok(args[index..].to_vec());
        }
        index += 1;
    }
    Ok(Vec::new())
}

fn pip_global_ignored_bool_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--disable-pip-version-check"
            | "--no-cache-dir"
            | "--isolated"
            | "--require-virtualenv"
            | "-q"
            | "--quiet"
            | "-v"
            | "--verbose"
    )
}

fn pip_global_ignored_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--log"
            | "--proxy"
            | "--retries"
            | "--timeout"
            | "--exists-action"
            | "--trusted-host"
            | "--cert"
            | "--client-cert"
            | "--cache-dir"
    )
}

fn pip_global_ignored_equals_flag(arg: &str) -> bool {
    [
        "--log=",
        "--proxy=",
        "--retries=",
        "--timeout=",
        "--exists-action=",
        "--trusted-host=",
        "--cert=",
        "--client-cert=",
        "--cache-dir=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
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
        location,
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
        "set" => {
            let assignments = parse_pip_config_assignments(positionals)?;
            Ok(PipCompatAction::Config {
                action: PipConfigAction::Set {
                    assignments,
                    location,
                },
            })
        }
        "unset" | "delete" | "del" | "remove" | "rm" => {
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "pip config unset needs at least one key".to_owned(),
                ));
            }
            Ok(PipCompatAction::Config {
                action: PipConfigAction::Unset {
                    keys: positionals,
                    location,
                },
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
    location: PipConfigLocation,
    positionals: Vec<String>,
}

fn parse_pip_config_common_args(args: &[String]) -> Result<PipConfigArgs, OmcRegistryError> {
    let mut json = false;
    let mut location = PipConfigLocation::Auto;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--user" {
            location = PipConfigLocation::User;
        } else if arg == "--site" {
            location = PipConfigLocation::Site;
        } else if arg == "--global" {
            location = PipConfigLocation::Global;
        } else if matches!(
            arg.as_str(),
            "--isolated" | "-v" | "--verbose" | "-q" | "--quiet"
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
    Ok(PipConfigArgs {
        json,
        location,
        positionals,
    })
}

fn parse_pip_config_assignments(
    positionals: Vec<String>,
) -> Result<Vec<(String, String)>, OmcRegistryError> {
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config set needs a key and value".to_owned(),
        ));
    }
    if positionals.iter().any(|value| value.contains('=')) {
        return positionals
            .into_iter()
            .map(|assignment| {
                let Some((key, value)) = assignment.split_once('=') else {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "pip config set mixed assignment formats at `{assignment}`"
                    )));
                };
                pip_config_assignment(key, value)
            })
            .collect();
    }
    if positionals.len() != 2 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config set needs either KEY VALUE or KEY=VALUE".to_owned(),
        ));
    }
    pip_config_assignment(&positionals[0], &positionals[1]).map(|assignment| vec![assignment])
}

fn pip_config_assignment(key: &str, value: &str) -> Result<(String, String), OmcRegistryError> {
    let key = key.trim();
    if key.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip config key cannot be empty".to_owned(),
        ));
    }
    Ok((key.to_owned(), value.trim().to_owned()))
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

fn parse_pip_debug_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    let mut action = PipDebugAction {
        verbose: false,
        platform: None,
        python_version: None,
        implementation: None,
        abis: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "-v" | "--verbose" | "--debug" | "--disable-pip-version-check"
        ) {
            if matches!(arg.as_str(), "-v" | "--verbose") {
                action.verbose = true;
            }
        } else if matches!(arg.as_str(), "-q" | "--quiet") {
        } else if arg == "--platform" {
            action.platform = Some(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--platform=") {
            action.platform = Some(value.to_owned());
        } else if arg == "--python-version" {
            action.python_version = Some(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--python-version=") {
            action.python_version = Some(value.to_owned());
        } else if arg == "--implementation" {
            action.implementation = Some(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--implementation=") {
            action.implementation = Some(value.to_owned());
        } else if arg == "--abi" {
            action
                .abis
                .push(pip_debug_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--abi=") {
            action.abis.push(value.to_owned());
        } else if matches!(
            arg.as_str(),
            "--cert" | "--client-cert" | "--cache-dir" | "--log" | "--proxy" | "--timeout"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if pip_debug_ignored_equals_flag(arg) {
        } else {
            return Err(unsupported_compat_arg("pip debug", arg));
        }
        index += 1;
    }
    Ok(PipCompatAction::Debug { action })
}

fn pip_debug_flag_value(
    args: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

fn pip_debug_ignored_equals_flag(arg: &str) -> bool {
    [
        "--cert=",
        "--client-cert=",
        "--cache-dir=",
        "--log=",
        "--proxy=",
        "--timeout=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn parse_pip_inspect_args(args: &[String]) -> Result<(), OmcRegistryError> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "--local"
                | "--user"
                | "--verbose"
                | "-v"
                | "--quiet"
                | "-q"
                | "--disable-pip-version-check"
        ) {
        } else if arg == "--path" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with("--path=") {
        } else {
            return Err(unsupported_compat_arg("pip inspect", arg));
        }
        index += 1;
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
    let mut report = None;
    let mut dry_run = false;
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
    let mut vcs_requirements = Vec::new();
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
        } else if arg == "--report" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            report = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--report=") {
            report = Some(PathBuf::from(path));
        } else if arg == "--dry-run" {
            dry_run = true;
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
            if let Some(requirement) = parse_pypi_vcs_requirement(path)? {
                vcs_requirements.push(requirement);
            } else {
                local_paths.push(pip_local_path_arg(path)?);
            }
        } else if let Some(path) = arg.strip_prefix("--editable=") {
            if let Some(requirement) = parse_pypi_vcs_requirement(path)? {
                vcs_requirements.push(requirement);
            } else {
                local_paths.push(pip_local_path_arg(path)?);
            }
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
        } else if let Some(requirement) = parse_pypi_vcs_requirement(arg)? {
            vcs_requirements.push(requirement);
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
        report,
        dry_run,
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
        vcs_requirements,
        allow,
        allow_all_host,
    })))
}

fn parse_pip_download_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    parse_pip_artifact_args(args, PipArtifactCommand::Download)
}

fn parse_pip_wheel_args(args: &[String]) -> Result<PipCompatAction, OmcRegistryError> {
    parse_pip_artifact_args(args, PipArtifactCommand::Wheel)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipArtifactCommand {
    Download,
    Wheel,
}

fn parse_pip_artifact_args(
    args: &[String],
    command: PipArtifactCommand,
) -> Result<PipCompatAction, OmcRegistryError> {
    let mut requirements = Vec::new();
    let mut constraints = Vec::new();
    let mut index_url = None;
    let mut extra_index_urls = Vec::new();
    let mut find_links = Vec::new();
    let mut no_index = false;
    let mut binary_all = (command == PipArtifactCommand::Wheel).then_some(PypiBinaryMode::Binary);
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
        } else if command == PipArtifactCommand::Download
            && (arg == "-d" || arg == "--dest" || arg == "--destination-dir")
        {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Download
            && arg
                .strip_prefix("--dest=")
                .or_else(|| arg.strip_prefix("--destination-dir="))
                .is_some()
        {
            let path = arg
                .strip_prefix("--dest=")
                .or_else(|| arg.strip_prefix("--destination-dir="))
                .expect("checked path option");
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Wheel && (arg == "-w" || arg == "--wheel-dir") {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a path"
                )));
            };
            destination = PathBuf::from(path);
        } else if command == PipArtifactCommand::Wheel && arg.starts_with("--wheel-dir=") {
            let path = arg
                .strip_prefix("--wheel-dir=")
                .expect("checked wheel-dir option");
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
        } else if command == PipArtifactCommand::Wheel && arg == "--no-binary" {
            return Err(OmcRegistryError::UnsupportedSpec(
                "pip wheel source builds are not supported by OMC compatibility; prebuilt wheels are required".to_owned(),
            ));
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
        } else if command == PipArtifactCommand::Wheel && arg.starts_with("--no-binary=") {
            return Err(OmcRegistryError::UnsupportedSpec(
                "pip wheel source builds are not supported by OMC compatibility; prebuilt wheels are required".to_owned(),
            ));
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
            if command == PipArtifactCommand::Wheel && !is_pip_wheel_archive_arg(arg) {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "pip wheel cannot build archive `{arg}` under OMC compatibility; pass a wheel archive"
                )));
            }
            archive_references.push(arg.clone());
        } else if is_pip_local_directory_arg(arg) {
            let (command, expected) = match command {
                PipArtifactCommand::Download => ("download", "a wheel or sdist archive"),
                PipArtifactCommand::Wheel => ("wheel", "a wheel archive"),
            };
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "pip {command} cannot build local directory `{arg}`; pass {expected}"
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

    if command == PipArtifactCommand::Wheel && binary_all != Some(PypiBinaryMode::Binary) {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip wheel source builds are not supported by OMC compatibility; prebuilt wheels are required".to_owned(),
        ));
    }

    let action = PipDownloadAction {
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
    };
    Ok(match command {
        PipArtifactCommand::Download => PipCompatAction::Download(Box::new(action)),
        PipArtifactCommand::Wheel => PipCompatAction::Wheel(Box::new(action)),
    })
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

fn is_pip_wheel_archive_arg(value: &str) -> bool {
    let value = value.split_once('#').map(|(path, _)| path).unwrap_or(value);
    let filename = value
        .rsplit_once('/')
        .map(|(_, filename)| filename)
        .unwrap_or(value);
    filename.ends_with(".whl")
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

fn parse_npm_list_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut packages = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(
            arg.as_str(),
            "--all"
                | "--long"
                | "--parseable"
                | "-p"
                | "--production"
                | "--prod"
                | "--dev"
                | "--global"
                | "-g"
                | "--silent"
                | "-s"
                | "--workspaces"
                | "--color=false"
                | "--no-color"
        ) {
        } else if matches!(
            arg.as_str(),
            "--depth" | "--omit" | "--include" | "--loglevel" | "--workspace" | "-w"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_list_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm list", arg));
        } else {
            packages.push(arg.clone());
        }
        index += 1;
    }
    Ok(NpmCompatAction::List {
        action: NpmListAction { json, packages },
    })
}

fn npm_list_ignored_equals_flag(arg: &str) -> bool {
    [
        "--depth=",
        "--omit=",
        "--include=",
        "--loglevel=",
        "--workspace=",
        "--userconfig=",
        "--parseable=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
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
        assert_eq!(
            parse_npm_compat_action(&args(&["--silent", "--version"])).unwrap(),
            NpmCompatAction::Version
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["--help"])).unwrap(),
            NpmCompatAction::Help { topic: None }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["help", "install"])).unwrap(),
            NpmCompatAction::Help {
                topic: Some("install".to_owned()),
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["install", "--help"])).unwrap(),
            NpmCompatAction::Help {
                topic: Some("install".to_owned()),
            }
        );
        assert!(npm_help_text(None).contains("Supported commands: install"));
        assert!(npm_help_text(Some("fund")).contains("npm fund [<package-spec>]"));
        assert!(npm_help_text(Some("install-test")).contains("npm install-test"));
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "--silent",
                "--registry",
                "https://registry.example.invalid/npm",
                "install",
                "left-pad",
            ]))
            .unwrap(),
            NpmCompatAction::Install {
                specs: vec!["left-pad".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                dev: false,
                omit_dev: false,
                lock_only: false,
                dry_run: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: Vec::new(),
                allow_all_host: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["--json", "view", "left-pad", "version"])).unwrap(),
            NpmCompatAction::View {
                spec: "left-pad".to_owned(),
                fields: vec!["version".to_owned()],
                json: true,
                npm_registry: None,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["--json", "why", "left-pad"])).unwrap(),
            NpmCompatAction::Explain {
                specs: vec!["left-pad".to_owned()],
                json: true,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "--registry=https://registry.example.invalid/npm",
                "run",
                "build",
            ]))
            .unwrap(),
            NpmCompatAction::RunScript {
                command: "run".to_owned(),
                name: "build".to_owned(),
                args: Vec::new(),
                if_present: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "init",
                "-y",
                "--scope",
                "@scope",
                "--private",
                "--type=module",
            ]))
            .unwrap(),
            NpmCompatAction::Init {
                action: NpmInitAction {
                    name: None,
                    version: None,
                    description: None,
                    main: None,
                    license: None,
                    scope: Some("@scope".to_owned()),
                    private: true,
                    package_type: Some("module".to_owned()),
                },
            }
        );
        assert!(parse_npm_compat_action(&args(&["init", "react-app"])).is_err());
        assert_eq!(
            parse_npm_compat_action(&args(&["version", "--json"])).unwrap(),
            NpmCompatAction::PackageVersion {
                action: NpmVersionAction::Current { json: true },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "version",
                "patch",
                "--no-git-tag-version",
                "--allow-same-version",
            ]))
            .unwrap(),
            NpmCompatAction::PackageVersion {
                action: NpmVersionAction::Bump {
                    spec: "patch".to_owned(),
                    preid: None,
                    allow_same_version: true,
                    json: false,
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["version", "preminor", "--preid", "rc", "--json",]))
                .unwrap(),
            NpmCompatAction::PackageVersion {
                action: NpmVersionAction::Bump {
                    spec: "preminor".to_owned(),
                    preid: Some("rc".to_owned()),
                    allow_same_version: false,
                    json: true,
                },
            }
        );

        assert_eq!(npm_next_version("1.2.3", "patch", None).unwrap(), "1.2.4");
        assert_eq!(
            npm_next_version("1.2.3", "preminor", Some("rc")).unwrap(),
            "1.3.0-rc.0"
        );
        assert_eq!(
            npm_next_version("1.2.3", "prerelease", None).unwrap(),
            "1.2.4-0"
        );
        assert_eq!(
            npm_next_version("1.2.3-rc.0", "prerelease", Some("rc")).unwrap(),
            "1.2.3-rc.1"
        );
        assert_eq!(
            npm_next_version("1.2.3-alpha.0", "prerelease", Some("rc")).unwrap(),
            "1.2.3-rc.0"
        );
        assert_eq!(
            npm_next_version("v2.0.0+build.7", "2.0.0", None).unwrap(),
            "2.0.0"
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
            "--dry-run",
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
                dry_run: true,
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
                dry_run: false,
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
                dry_run: false,
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
                dry_run: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_all_host: false,
            }
        );

        assert_eq!(
            parse_npm_compat_action(&args(&[
                "--registry=https://registry.example.invalid/npm",
                "it",
                "--omit=dev",
                "left-pad",
                "--",
                "--watch",
            ]))
            .unwrap(),
            NpmCompatAction::InstallTest {
                command: "it".to_owned(),
                use_ci: false,
                specs: vec!["left-pad".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                dev: false,
                omit_dev: true,
                lock_only: false,
                dry_run: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: Vec::new(),
                allow_all_host: false,
                test_args: vec!["--watch".to_owned()],
            }
        );

        assert_eq!(
            parse_npm_compat_action(&args(&["cit", "--omit=dev", "--", "--runInBand"])).unwrap(),
            NpmCompatAction::InstallTest {
                command: "cit".to_owned(),
                use_ci: true,
                specs: Vec::new(),
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                dev: false,
                omit_dev: true,
                lock_only: false,
                dry_run: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_all_host: false,
                test_args: vec!["--runInBand".to_owned()],
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
                dry_run: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: Vec::new(),
                allow_all_host: false,
            }
        );
    }

    #[test]
    fn parses_npm_run_and_exec_compat_commands() {
        assert_eq!(
            parse_npm_compat_action(&args(&["run"])).unwrap(),
            NpmCompatAction::RunList {
                action: NpmRunListAction {
                    json: false,
                    workspaces: Vec::new(),
                    all_workspaces: false,
                    include_workspace_root: false,
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["--json", "--workspace", "@demo/lib", "run",]))
                .unwrap(),
            NpmCompatAction::RunList {
                action: NpmRunListAction {
                    json: true,
                    workspaces: vec!["@demo/lib".to_owned()],
                    all_workspaces: false,
                    include_workspace_root: false,
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["run", "test", "--", "--watch"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "run".to_owned(),
                name: "test".to_owned(),
                args: vec!["--watch".to_owned()],
                if_present: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["test", "--", "--watch"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "test".to_owned(),
                name: "test".to_owned(),
                args: vec!["--watch".to_owned()],
                if_present: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["run", "--if-present", "--silent", "build"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "run".to_owned(),
                name: "build".to_owned(),
                args: Vec::new(),
                if_present: true,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["test", "--if-present", "--", "--watch"])).unwrap(),
            NpmCompatAction::RunScript {
                command: "test".to_owned(),
                name: "test".to_owned(),
                args: vec!["--watch".to_owned()],
                if_present: true,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "--workspace",
                "@demo/lib",
                "run",
                "build",
                "--",
                "--watch",
            ]))
            .unwrap(),
            NpmCompatAction::RunScript {
                command: "run".to_owned(),
                name: "build".to_owned(),
                args: vec!["--watch".to_owned()],
                if_present: false,
                workspaces: vec!["@demo/lib".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "test",
                "--workspaces",
                "--include-workspace-root",
                "--if-present",
            ]))
            .unwrap(),
            NpmCompatAction::RunScript {
                command: "test".to_owned(),
                name: "test".to_owned(),
                args: Vec::new(),
                if_present: true,
                workspaces: Vec::new(),
                all_workspaces: true,
                include_workspace_root: true,
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
                "pack",
                "--pack-destination",
                "dist",
                "--json",
                "--dry-run",
                ".",
            ]))
            .unwrap(),
            NpmCompatAction::Pack {
                action: NpmPackAction {
                    packages: vec![NpmPackInput::Local(PathBuf::from("."))],
                    destination: PathBuf::from("dist"),
                    json: true,
                    dry_run: true,
                    npm_registry: None,
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "--registry=https://registry.example.invalid/npm",
                "pack",
                "left-pad@1.3.0",
            ]))
            .unwrap(),
            NpmCompatAction::Pack {
                action: NpmPackAction {
                    packages: vec![NpmPackInput::Registry("left-pad@1.3.0".to_owned())],
                    destination: PathBuf::from("."),
                    json: false,
                    dry_run: false,
                    npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                },
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
                packages: Vec::new(),
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
                packages: Vec::new(),
                omit_dev: false,
                allow: Vec::new(),
                allow_all_host: false,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "--omit=dev",
                "rebuild",
                "node-sass",
                "--ignore-scripts",
                "--build-from-source",
            ]))
            .unwrap(),
            NpmCompatAction::Maintenance {
                command: NpmMaintenanceCommand::Rebuild,
                packages: vec!["node-sass".to_owned()],
                omit_dev: true,
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
            parse_npm_compat_action(&args(&[
                "--json",
                "--workspace",
                "@demo/lib",
                "fund",
                "left-pad@1.3.0",
                "--browser=false",
            ]))
            .unwrap(),
            NpmCompatAction::Fund {
                action: NpmFundAction {
                    json: true,
                    package: Some("left-pad@1.3.0".to_owned()),
                    workspaces: vec!["@demo/lib".to_owned()],
                    all_workspaces: false,
                    include_workspace_root: false,
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "fund",
                "--workspaces",
                "--include-workspace-root",
                "--which",
                "1",
            ]))
            .unwrap(),
            NpmCompatAction::Fund {
                action: NpmFundAction {
                    json: false,
                    package: None,
                    workspaces: Vec::new(),
                    all_workspaces: true,
                    include_workspace_root: true,
                },
            }
        );
        assert!(parse_npm_compat_action(&args(&["fund", "left-pad", "chalk"])).is_err());
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
            parse_npm_compat_action(&args(&["pkg", "get", "name", "version", "--json"])).unwrap(),
            NpmCompatAction::Pkg {
                action: NpmPkgAction::Get {
                    fields: vec!["name".to_owned(), "version".to_owned()],
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "pkg",
                "set",
                "scripts.test=\"vitest\"",
                "private=true",
                "--json",
            ]))
            .unwrap(),
            NpmCompatAction::Pkg {
                action: NpmPkgAction::Set {
                    assignments: vec![
                        (
                            "scripts.test".to_owned(),
                            serde_json::Value::String("vitest".to_owned()),
                        ),
                        ("private".to_owned(), serde_json::Value::Bool(true)),
                    ],
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["pkg", "delete", "scripts.pretest"])).unwrap(),
            NpmCompatAction::Pkg {
                action: NpmPkgAction::Delete {
                    fields: vec!["scripts.pretest".to_owned()],
                },
            }
        );
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
                "--searchlimit=3",
                "--json",
                "search",
                "--registry",
                "https://registry.example.invalid/npm",
                "left",
                "pad",
            ]))
            .unwrap(),
            NpmCompatAction::Search {
                action: NpmSearchAction {
                    query: "left pad".to_owned(),
                    json: true,
                    parseable: false,
                    limit: 3,
                    npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["find", "left-pad", "--parseable", "--limit=500"]))
                .unwrap(),
            NpmCompatAction::Search {
                action: NpmSearchAction {
                    query: "left-pad".to_owned(),
                    json: false,
                    parseable: true,
                    limit: 250,
                    npm_registry: None,
                },
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
        assert_eq!(
            parse_npm_compat_action(&args(&["config", "set", "registry", "x"])).unwrap(),
            NpmCompatAction::Config {
                action: NpmConfigAction::Set {
                    assignments: vec![("registry".to_owned(), "x".to_owned())],
                },
                npm_registry: None,
                userconfig: None,
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "config",
                "set",
                "@scope:registry=https://registry.example.invalid/npm",
                "--userconfig=ci.npmrc",
            ]))
            .unwrap(),
            NpmCompatAction::Config {
                action: NpmConfigAction::Set {
                    assignments: vec![(
                        "@scope:registry".to_owned(),
                        "https://registry.example.invalid/npm".to_owned(),
                    )],
                },
                npm_registry: None,
                userconfig: Some(PathBuf::from("ci.npmrc")),
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&["config", "delete", "registry"])).unwrap(),
            NpmCompatAction::Config {
                action: NpmConfigAction::Delete {
                    keys: vec!["registry".to_owned()],
                },
                npm_registry: None,
                userconfig: None,
            }
        );
    }

    #[test]
    fn writes_npm_config_set_and_delete() {
        let dir = test_dir("npm-config-set-delete");
        fs::write(
            dir.join(".npmrc"),
            "registry=https://old.example.invalid/npm\n# keep this\nlegacy-peer-deps=true\n",
        )
        .unwrap();

        print_npm_config(
            &dir,
            NpmConfigAction::Set {
                assignments: vec![
                    (
                        "registry".to_owned(),
                        "https://new.example.invalid/npm".to_owned(),
                    ),
                    (
                        "@scope:registry".to_owned(),
                        "https://scope.example.invalid/npm".to_owned(),
                    ),
                ],
            },
            None,
            None,
        )
        .unwrap();

        let config = fs::read_to_string(dir.join(".npmrc")).unwrap();
        assert!(config.contains("registry=https://new.example.invalid/npm\n"));
        assert!(config.contains("# keep this\n"));
        assert!(config.contains("@scope:registry=https://scope.example.invalid/npm\n"));
        let values = npm_config_values(&dir, None, Some(Path::new("empty-user.npmrc"))).unwrap();
        assert_eq!(
            values.get("registry").map(String::as_str),
            Some("https://new.example.invalid/npm/")
        );
        assert_eq!(
            values.get("@scope:registry").map(String::as_str),
            Some("https://scope.example.invalid/npm/")
        );

        print_npm_config(
            &dir,
            NpmConfigAction::Delete {
                keys: vec!["registry".to_owned()],
            },
            None,
            None,
        )
        .unwrap();
        let config = fs::read_to_string(dir.join(".npmrc")).unwrap();
        assert!(!config.contains("registry=https://new.example.invalid/npm\n"));
        assert!(config.contains("@scope:registry=https://scope.example.invalid/npm\n"));

        print_npm_config(
            &dir,
            NpmConfigAction::Set {
                assignments: vec![(
                    "registry".to_owned(),
                    "https://ci.example.invalid".to_owned(),
                )],
            },
            None,
            Some(Path::new("ci.npmrc")),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("ci.npmrc")).unwrap(),
            "registry=https://ci.example.invalid\n"
        );
    }

    #[test]
    fn normalizes_npm_funding_metadata() {
        assert_eq!(
            normalize_npm_funding(&serde_json::Value::String(
                "https://example.com/pkg".to_owned()
            ))
            .unwrap(),
            serde_json::json!({ "url": "https://example.com/pkg" })
        );
        assert_eq!(
            normalize_npm_funding(&serde_json::json!([
                "https://example.com/one",
                { "type": "github", "url": "https://example.com/two" },
                "",
            ]))
            .unwrap(),
            serde_json::json!([
                { "url": "https://example.com/one" },
                { "type": "github", "url": "https://example.com/two" },
            ])
        );
        assert!(normalize_npm_funding(&serde_json::json!({ "type": "github" })).is_none());
        assert_eq!(
            npm_funding_urls(&serde_json::json!([
                { "url": "https://example.com/two" },
                { "url": "https://example.com/one" },
                { "url": "https://example.com/two" },
            ])),
            vec![
                "https://example.com/one".to_owned(),
                "https://example.com/two".to_owned(),
            ]
        );
    }

    #[test]
    fn collects_npm_funding_from_root_and_node_modules() {
        let dir = test_dir("npm-fund");
        fs::write(
            dir.join("package.json"),
            r#"{
              "name": "root",
              "version": "1.0.0",
              "funding": { "type": "github", "url": "https://github.com/sponsors/root" }
            }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("node_modules/left-pad")).unwrap();
        fs::write(
            dir.join("node_modules/left-pad/package.json"),
            r#"{ "name": "left-pad", "version": "1.3.0", "funding": "https://example.com/left-pad" }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("node_modules/@scope/scoped")).unwrap();
        fs::write(
            dir.join("node_modules/@scope/scoped/package.json"),
            r#"{
              "name": "@scope/scoped",
              "version": "2.0.0",
              "funding": [{ "type": "opencollective", "url": "https://opencollective.com/scoped" }]
            }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("node_modules/.bin")).unwrap();

        let report = collect_npm_fund_report(
            &dir,
            &NpmFundAction {
                json: true,
                package: None,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        )
        .unwrap();
        assert_eq!(
            report.root.as_ref().map(|package| package.id()).as_deref(),
            Some("root@1.0.0")
        );
        assert_eq!(
            report
                .dependencies
                .iter()
                .map(|package| package.id())
                .collect::<Vec<_>>(),
            vec![
                "@scope/scoped@2.0.0".to_owned(),
                "left-pad@1.3.0".to_owned()
            ]
        );

        let json = npm_fund_report_json(&report);
        assert_eq!(
            json.get("length").and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            npm_pkg_get_path(&json, "dependencies.left-pad.funding.url")
                .and_then(serde_json::Value::as_str),
            Some("https://example.com/left-pad")
        );

        let filtered = collect_npm_fund_report(
            &dir,
            &NpmFundAction {
                json: true,
                package: Some("@scope/scoped@2.0.0".to_owned()),
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        )
        .unwrap();
        assert!(filtered.root.is_none());
        assert_eq!(filtered.dependencies.len(), 1);
        assert_eq!(filtered.dependencies[0].name, "@scope/scoped");
    }

    #[test]
    fn collects_npm_funding_from_selected_workspaces() {
        let dir = test_dir("npm-fund-workspaces");
        fs::write(
            dir.join("package.json"),
            r#"{ "name": "root", "version": "1.0.0", "workspaces": ["packages/*"] }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("packages/lib/node_modules/dep")).unwrap();
        fs::write(
            dir.join("packages/lib/package.json"),
            r#"{
              "name": "@demo/lib",
              "version": "1.0.0",
              "funding": "https://example.com/lib"
            }"#,
        )
        .unwrap();
        fs::write(
            dir.join("packages/lib/node_modules/dep/package.json"),
            r#"{ "name": "dep", "version": "2.0.0", "funding": "https://example.com/dep" }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("packages/api")).unwrap();
        fs::write(
            dir.join("packages/api/package.json"),
            r#"{ "name": "@demo/api", "version": "1.0.0", "funding": "https://example.com/api" }"#,
        )
        .unwrap();

        let report = collect_npm_fund_report(
            &dir,
            &NpmFundAction {
                json: false,
                package: None,
                workspaces: vec!["@demo/lib".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        )
        .unwrap();

        assert_eq!(
            report.root.as_ref().map(|package| package.id()).as_deref(),
            Some("@demo/lib@1.0.0")
        );
        assert_eq!(
            report
                .dependencies
                .iter()
                .map(|package| package.id())
                .collect::<Vec<_>>(),
            vec!["dep@2.0.0".to_owned()]
        );
    }

    #[test]
    fn initializes_npm_package_json() {
        let root = test_dir("npm-init");
        let dir = root.join("demo_pkg");
        fs::create_dir_all(&dir).unwrap();
        print_npm_init(
            &dir,
            NpmInitAction {
                name: None,
                version: Some("2.0.0".to_owned()),
                description: Some("demo package".to_owned()),
                main: Some("src/index.js".to_owned()),
                license: Some("MIT".to_owned()),
                scope: Some("@scope".to_owned()),
                private: true,
                package_type: Some("module".to_owned()),
            },
        )
        .unwrap();

        let package = read_npm_pkg_json(&dir.join("package.json")).unwrap();
        assert_eq!(
            package.get("name").and_then(serde_json::Value::as_str),
            Some("@scope/demo_pkg")
        );
        assert_eq!(
            package.get("version").and_then(serde_json::Value::as_str),
            Some("2.0.0")
        );
        assert_eq!(
            package
                .get("description")
                .and_then(serde_json::Value::as_str),
            Some("demo package")
        );
        assert_eq!(
            package.get("main").and_then(serde_json::Value::as_str),
            Some("src/index.js")
        );
        assert_eq!(
            package.get("license").and_then(serde_json::Value::as_str),
            Some("MIT")
        );
        assert_eq!(
            package.get("type").and_then(serde_json::Value::as_str),
            Some("module")
        );
        assert_eq!(
            package.get("private").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            npm_pkg_get_path(&package, "scripts.test").and_then(serde_json::Value::as_str),
            Some("echo \"Error: no test specified\" && exit 1")
        );
    }

    #[test]
    fn packs_local_npm_package_tarball() {
        let dir = test_dir("npm-pack");
        fs::write(
            dir.join("package.json"),
            r#"{ "name": "@scope/demo-pkg", "version": "1.2.3" }"#,
        )
        .unwrap();
        fs::write(dir.join("index.js"), "module.exports = 1\n").unwrap();
        fs::create_dir_all(dir.join("lib")).unwrap();
        fs::write(dir.join("lib/main.js"), "module.exports = 2\n").unwrap();
        fs::create_dir_all(dir.join("node_modules/ignored")).unwrap();
        fs::write(dir.join("node_modules/ignored/index.js"), "ignored\n").unwrap();

        print_npm_pack(
            &dir,
            NpmPackAction {
                packages: Vec::new(),
                destination: PathBuf::from("dist"),
                json: false,
                dry_run: false,
                npm_registry: None,
            },
        )
        .unwrap();

        let tarball = dir.join("dist/scope-demo-pkg-1.2.3.tgz");
        assert!(tarball.exists());
        let decoder = flate2::read::GzDecoder::new(fs::File::open(tarball).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let mut paths = archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "package/index.js".to_owned(),
                "package/lib/main.js".to_owned(),
                "package/package.json".to_owned(),
            ]
        );

        print_npm_pack(
            &dir,
            NpmPackAction {
                packages: Vec::new(),
                destination: PathBuf::from("dry"),
                json: true,
                dry_run: true,
                npm_registry: None,
            },
        )
        .unwrap();
        assert!(!dir.join("dry").exists());
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
    fn resolves_npm_workspace_script_targets() {
        let dir = test_dir("npm-run-workspaces");
        fs::write(
            dir.join("package.json"),
            r#"{ "name": "root", "workspaces": ["packages/*"], "scripts": { "build": "true" } }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("packages/lib")).unwrap();
        fs::write(
            dir.join("packages/lib/package.json"),
            r#"{ "name": "@demo/lib", "scripts": { "build": "true" } }"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("packages/api")).unwrap();
        fs::write(
            dir.join("packages/api/package.json"),
            r#"{ "name": "@demo/api", "scripts": { "build": "true" } }"#,
        )
        .unwrap();

        assert_eq!(
            npm_script_target_dirs(&dir, &["@demo/lib".to_owned()], false, false).unwrap(),
            vec![dir.join("packages/lib")]
        );
        assert_eq!(
            npm_script_target_dirs(&dir, &["packages/api".to_owned()], false, false).unwrap(),
            vec![dir.join("packages/api")]
        );
        assert_eq!(
            npm_script_target_dirs(&dir, &[], true, true).unwrap(),
            vec![
                dir.clone(),
                dir.join("packages/api"),
                dir.join("packages/lib")
            ]
        );
        assert!(npm_script_target_dirs(&dir, &["missing".to_owned()], false, false).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parses_pip_install_requirements_and_indexes() {
        let action = parse_pip_compat_action(&args(&[
            "--disable-pip-version-check",
            "--quiet",
            "--timeout",
            "5",
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
            "--report",
            "install-report.json",
            "--dry-run",
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
                report: Some(PathBuf::from("install-report.json")),
                dry_run: true,
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
                vcs_requirements: Vec::new(),
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

        let action = parse_pip_compat_action(&args(&[
            "wheel",
            "-r",
            "requirements.txt",
            "-w",
            "wheelhouse",
            "--index-url=https://mirror.example/simple",
            "--find-links=vendor",
            "--no-index",
            "--require-hashes",
            "--no-deps",
            "--trusted-host",
            "mirror.example",
            "--allow",
            "http:files.example",
            "requests==2.32.3",
        ]))
        .unwrap();

        assert_eq!(
            action,
            PipCompatAction::Wheel(Box::new(PipDownloadAction {
                specs: vec!["requests==2.32.3".to_owned()],
                requirements: vec![PathBuf::from("requirements.txt")],
                constraints: Vec::new(),
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
        assert!(
            parse_pip_compat_action(&args(&["wheel", "--no-binary=:all:", "requests"])).is_err()
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
                report: None,
                dry_run: false,
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
                vcs_requirements: Vec::new(),
                allow: Vec::new(),
                allow_all_host: false,
            }))
        );

        assert_eq!(
            parse_pip_compat_action(&args(&[
                "install",
                "-e",
                "git+https://example.invalid/demo.git@main#egg=demo[cli]&subdirectory=src",
                "--editable=other @ git+https://example.invalid/other.git@v1#subdirectory=python",
            ]))
            .unwrap(),
            PipCompatAction::Install(Box::new(PipInstallAction {
                specs: Vec::new(),
                requirements: Vec::new(),
                constraints: Vec::new(),
                report: None,
                dry_run: false,
                archive_references: Vec::new(),
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
                vcs_requirements: vec![
                    PythonVcsRequirement {
                        name: "demo".to_owned(),
                        url: "https://example.invalid/demo.git".to_owned(),
                        reference: Some("main".to_owned()),
                        subdirectory: Some(PathBuf::from("src")),
                        extras: BTreeSet::from(["cli".to_owned()]),
                    },
                    PythonVcsRequirement {
                        name: "other".to_owned(),
                        url: "https://example.invalid/other.git".to_owned(),
                        reference: Some("v1".to_owned()),
                        subdirectory: Some(PathBuf::from("python")),
                        extras: BTreeSet::new(),
                    },
                ],
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
                report: None,
                dry_run: false,
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
                vcs_requirements: Vec::new(),
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
            parse_pip_compat_action(&args(&["--quiet", "--version"])).unwrap(),
            PipCompatAction::Version
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["--help"])).unwrap(),
            PipCompatAction::Help { topic: None }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["help", "install"])).unwrap(),
            PipCompatAction::Help {
                topic: Some("install".to_owned()),
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["install", "--help"])).unwrap(),
            PipCompatAction::Help {
                topic: Some("install".to_owned()),
            }
        );
        assert!(pip_help_text(None).contains("Supported commands: install"));
        assert!(pip_help_text(Some("debug")).contains("pip debug"));
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
            pip_freeze_vcs_requirement(&LockedPythonVcsDependency {
                name: "demo".to_owned(),
                url: "https://example.invalid/demo.git".to_owned(),
                reference: Some("main".to_owned()),
                resolved_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                archive: String::new(),
                sha256: String::new(),
                subdirectory: Some("src".to_owned()),
                extras: vec!["cli".to_owned(), "test".to_owned()],
            }),
            "demo[cli,test] @ git+https://example.invalid/demo.git@0123456789abcdef0123456789abcdef01234567#subdirectory=src"
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["check", "--disable-pip-version-check"])).unwrap(),
            PipCompatAction::Check
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "debug",
                "--verbose",
                "--platform",
                "macosx_14_0_arm64",
                "--python-version=3.12",
                "--implementation",
                "cp",
                "--abi=cp312",
                "--disable-pip-version-check",
            ]))
            .unwrap(),
            PipCompatAction::Debug {
                action: PipDebugAction {
                    verbose: true,
                    platform: Some("macosx_14_0_arm64".to_owned()),
                    python_version: Some("3.12".to_owned()),
                    implementation: Some("cp".to_owned()),
                    abis: vec!["cp312".to_owned()],
                },
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "inspect",
                "--local",
                "--path",
                ".omc/python/site-packages",
                "--disable-pip-version-check",
            ]))
            .unwrap(),
            PipCompatAction::Inspect
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
            NpmCompatAction::List {
                action: NpmListAction {
                    json: true,
                    packages: Vec::new(),
                },
            }
        );
        assert_eq!(
            parse_npm_compat_action(&args(&[
                "--depth=0",
                "ls",
                "--omit",
                "dev",
                "--loglevel",
                "silent",
                "left-pad@1.3.0",
                "@scope/pkg",
                "--json",
            ]))
            .unwrap(),
            NpmCompatAction::List {
                action: NpmListAction {
                    json: true,
                    packages: vec!["left-pad@1.3.0".to_owned(), "@scope/pkg".to_owned()],
                },
            }
        );
        assert_eq!(
            package_list_filter_names(
                &args(&["left-pad@1.3.0", "@scope/pkg"]),
                Some(Ecosystem::Npm),
            )
            .unwrap(),
            BTreeSet::from(["@scope/pkg".to_owned(), "left-pad".to_owned()])
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
        assert_eq!(
            parse_pip_compat_action(&args(&["config", "set", "global.index-url", "x"])).unwrap(),
            PipCompatAction::Config {
                action: PipConfigAction::Set {
                    assignments: vec![("global.index-url".to_owned(), "x".to_owned())],
                    location: PipConfigLocation::Auto,
                },
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&[
                "config",
                "--site",
                "set",
                "global.extra-index-url=https://extra.example.invalid/simple",
            ]))
            .unwrap(),
            PipCompatAction::Config {
                action: PipConfigAction::Set {
                    assignments: vec![(
                        "global.extra-index-url".to_owned(),
                        "https://extra.example.invalid/simple".to_owned(),
                    )],
                    location: PipConfigLocation::Site,
                },
            }
        );
        assert_eq!(
            parse_pip_compat_action(&args(&["config", "--user", "unset", "global.index-url"]))
                .unwrap(),
            PipCompatAction::Config {
                action: PipConfigAction::Unset {
                    keys: vec!["global.index-url".to_owned()],
                    location: PipConfigLocation::User,
                },
            }
        );
    }

    #[test]
    fn writes_pip_config_set_and_unset() {
        let dir = test_dir("pip-config-set-unset");
        fs::write(
            dir.join("pip.conf"),
            "[global]\nindex-url = https://old.example.invalid/simple\n# keep this\n\n[install]\nno-index = false\n",
        )
        .unwrap();

        print_pip_config(
            &dir,
            PipConfigAction::Set {
                assignments: vec![
                    (
                        "global.index-url".to_owned(),
                        "https://new.example.invalid/simple".to_owned(),
                    ),
                    (
                        "global.extra-index-url".to_owned(),
                        "https://extra.example.invalid/simple".to_owned(),
                    ),
                ],
                location: PipConfigLocation::Auto,
            },
        )
        .unwrap();

        let config = fs::read_to_string(dir.join("pip.conf")).unwrap();
        assert!(config.contains("index-url = https://new.example.invalid/simple\n"));
        assert!(config.contains("extra-index-url = https://extra.example.invalid/simple\n"));
        assert!(config.contains("# keep this\n"));
        let values = pip_config_values(&dir).unwrap();
        assert_eq!(
            values.get("global.index-url").map(String::as_str),
            Some("https://new.example.invalid/simple/")
        );
        assert_eq!(
            values.get("global.extra-index-url").map(String::as_str),
            Some("https://extra.example.invalid/simple/")
        );

        print_pip_config(
            &dir,
            PipConfigAction::Unset {
                keys: vec!["global.index-url".to_owned()],
                location: PipConfigLocation::Auto,
            },
        )
        .unwrap();
        let config = fs::read_to_string(dir.join("pip.conf")).unwrap();
        assert!(!config.contains("index-url = https://new.example.invalid/simple\n"));
        assert!(config.contains("extra-index-url = https://extra.example.invalid/simple\n"));
    }

    #[test]
    fn reports_pip_debug_project_state() {
        let dir = test_dir("pip-debug");
        fs::write(
            dir.join("pip.conf"),
            "[global]\nindex-url = https://mirror.example.invalid/simple\nno-index = false\n",
        )
        .unwrap();

        let report = pip_debug_report(
            &dir,
            &PipDebugAction {
                verbose: true,
                platform: Some("macosx_14_0_arm64".to_owned()),
                python_version: Some("3.12".to_owned()),
                implementation: Some("cp".to_owned()),
                abis: vec!["cp312".to_owned()],
            },
        )
        .unwrap();

        assert!(report.contains("pip version: omc-pip "));
        assert!(report.contains(&format!(
            "omc project: {}",
            absolute_project_dir(&dir).display()
        )));
        assert!(report.contains(".omc/python/site-packages"));
        assert!(report.contains(".omc/cache/pypi"));
        assert!(report.contains("lockfile: "));
        assert!(report.contains("(missing)"));
        assert!(report.contains("global.index-url: https://mirror.example.invalid/simple/"));
        assert!(report.contains("requested compatibility target:"));
        assert!(report.contains("  platform: macosx_14_0_arm64"));
        assert!(report.contains("  abi: cp312"));
        assert!(report.contains("locked pypi packages:\n  (none)"));
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
