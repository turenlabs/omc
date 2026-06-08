//! Clap `Command`/`Action` structs and parser entry types.
//!
//! Pure argument-model definitions extracted from `lib.rs`: the top-level
//! `Cli`/`Command`, every npm/pip/twine compat action enum/struct, and the
//! `CompileCommand` data struct. No dispatch or parsing logic lives here.

use crate::*;

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::npm_compat::NpmLinkAction;

#[derive(Debug, Parser)]
#[command(name = "omc")]
#[command(about = "OMC package-manager prototype")]
#[command(version)]
#[command(disable_help_subcommand = true)]
pub(crate) struct Cli {
    #[arg(long, global = true, default_value = ".")]
    pub(crate) project_dir: PathBuf,
    #[arg(
        short,
        long,
        global = true,
        help = "Print per-package artifact paths and every capability finding (default: a one-line capability-kind summary)"
    )]
    pub(crate) verbose: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
        #[arg(
            long,
            conflicts_with_all = ["dev", "peer"],
            help = "Save the package as an optional dependency"
        )]
        optional: bool,
        #[arg(
            long,
            conflicts_with_all = ["dev", "optional"],
            help = "Save the package as a peer dependency"
        )]
        peer: bool,
        #[arg(long, help = "Write blocked packages into omc.lock for review")]
        record_blocked: bool,
        #[arg(
            long = "allow",
            help = "Grant a capability, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow, e.g. env:API_TOKEN->network:api.example.com"
        )]
        allow_flow: Vec<String>,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(
        about = "Resolve and show a package's capabilities without installing (text report, or --format png graph)"
    )]
    Inspect {
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
        #[arg(
            long,
            value_enum,
            default_value = "text",
            help = "Output format: text (default, full capability report) or png (a dependency-graph image)"
        )]
        format: InspectFormat,
        #[arg(
            long,
            help = "PNG output path used with --format png (default omc-graph.png); ignored for text"
        )]
        output: Option<PathBuf>,
        #[arg(
            long = "allow",
            help = "Grant a capability to preview how it changes the verdict, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow to preview how it changes the verdict, e.g. env:API_TOKEN->network:api.example.com"
        )]
        allow_flow: Vec<String>,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(
        about = "Hidden deprecated alias for `inspect --format png`: render a dependency-graph PNG",
        hide = true
    )]
    Graph {
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
        #[arg(long, default_value = "omc-graph.png", help = "Output PNG path")]
        output: PathBuf,
        #[arg(
            long = "allow",
            help = "Grant a capability to preview how it changes the verdict, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow to preview how it changes the verdict, e.g. env:API_TOKEN->network:api.example.com"
        )]
        allow_flow: Vec<String>,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[cfg(feature = "dev-commands")]
    #[command(about = "Compile local source into a signed OMC artifact", hide = true)]
    Compile {
        #[arg(
            long,
            conflicts_with = "pypi",
            help = "Compile the source as an npm package"
        )]
        npm: bool,
        #[arg(
            long,
            conflicts_with = "npm",
            help = "Compile the source as a PyPI package"
        )]
        pypi: bool,
        #[arg(help = "Source directory or archive to profile into OMC microcode")]
        source: PathBuf,
        #[arg(long, help = "Package name for the generated artifact")]
        name: Option<String>,
        #[arg(
            long,
            default_value = "0.0.0",
            help = "Package version for the generated artifact"
        )]
        version: String,
        #[arg(long, help = "Write artifact JSON to this path instead of stdout")]
        output: Option<PathBuf>,
        #[arg(
            long,
            help = "Store artifact under .omc/artifacts as well as returning output"
        )]
        store: bool,
        #[arg(
            long = "allow",
            help = "Grant a capability while verifying the generated artifact"
        )]
        allow: Vec<String>,
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow while verifying the generated artifact"
        )]
        allow_flow: Vec<String>,
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
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow while reinstalling remaining dependencies"
        )]
        allow_flow: Vec<String>,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(about = "Resolve omc.toml dependencies and install locked packages")]
    Install {
        #[arg(
            long = "allow",
            help = "Grant a capability, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow, e.g. env:API_TOKEN->network:api.example.com"
        )]
        allow_flow: Vec<String>,
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
        #[arg(long = "omit-optional", help = "Skip npm optional dependency inputs")]
        omit_optional: bool,
        #[arg(long = "omit-peer", help = "Skip npm peer dependency inputs")]
        omit_peer: bool,
        #[arg(
            long,
            help = "Install in place from omc.lock without registry resolution (reuse and prune node_modules; use `omc ci` for a clean wipe)"
        )]
        locked: bool,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(
        about = "Clean install for CI: wipe the OMC-managed install trees, then install strictly from omc.lock"
    )]
    Ci {
        #[arg(
            long = "allow",
            help = "Grant a capability, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow, e.g. env:API_TOKEN->network:api.example.com"
        )]
        allow_flow: Vec<String>,
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
        #[arg(long = "omit-optional", help = "Skip npm optional dependency inputs")]
        omit_optional: bool,
        #[arg(long = "omit-peer", help = "Skip npm peer dependency inputs")]
        omit_peer: bool,
        #[arg(long, help = "Grant all host capabilities for compatibility testing")]
        allow_all_host: bool,
    },
    #[command(about = "CI gate: list locked packages and exit non-zero (2) if any are blocked")]
    Audit {
        #[arg(long, help = "Emit machine-readable JSON")]
        json: bool,
    },
    #[command(about = "Show the inventory of locked packages (read-only; always exits 0)")]
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
    #[command(
        about = "Run a package.json or Pipfile script with OMC npm/Python bins and imports",
        disable_help_flag = true
    )]
    Script {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[command(
        about = "Run a command with OMC npm/Python bins and imports on PATH",
        disable_help_flag = true
    )]
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
    #[command(about = "Run common Twine-compatible PyPI publish commands through OMC")]
    Twine {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    #[cfg(feature = "dev-commands")]
    #[command(
        about = "Lower a supported source file to OMC microcode and execute it in the fueled VM under the project policy",
        hide = true
    )]
    ExecCell {
        #[arg(help = "Path to a supported JS/Python source file to lower and execute")]
        source: PathBuf,
        #[arg(
            long,
            help = "Package name for the lowered module id (defaults to file stem)"
        )]
        name: Option<String>,
        #[arg(
            long,
            default_value = "0.0.0",
            help = "Package version for the module id"
        )]
        version: String,
        #[arg(
            long = "arg",
            help = "Integer argument to pass to the entry function (repeat for multiple positional args)"
        )]
        args: Vec<i64>,
        #[arg(
            long = "allow",
            help = "Grant a capability, e.g. http:api.example.com, env:API_TOKEN, fs-read:*, proc:*"
        )]
        allow: Vec<String>,
        #[arg(
            long = "allow-flow",
            help = "Grant a data flow, e.g. env:API_TOKEN->network:api.example.com"
        )]
        allow_flow: Vec<String>,
        #[arg(long, help = "Grant all host capabilities (compatibility mode)")]
        allow_all_host: bool,
        #[arg(
            long,
            help = "Let a wildcard fs.read grant also cover sensitive files (.ssh, .env, keys, tokens). Off by default: sensitive files are denied unless granted by exact path"
        )]
        allow_sensitive: bool,
        #[arg(
            long,
            help = "If the source is outside the supported subset, fall back to the host interpreter shim (node/python) instead of failing"
        )]
        fallback: bool,
    },
    #[command(about = "Inspect and validate the per-package omc.policy DSL")]
    Policy {
        #[command(subcommand)]
        action: PolicyCommand,
    },
    #[command(about = "Print help or focused OMC guide topics")]
    Help {
        #[arg(long, help = "Emit the guide wrapped as machine-readable JSON")]
        json: bool,
        #[arg(
            value_name = "COMMAND|TOPIC",
            num_args = 0..,
            help = "Command path to explain, or the focused topic `agent`"
        )]
        topic: Vec<String>,
    },
}

/// `omc policy <subcommand>` — inspect and validate the `omc.policy` DSL.
#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCommand {
    #[command(about = "Persist project policy grants in omc.toml")]
    Allow {
        #[arg(
            long = "flow",
            help = "Persist a data-flow grant such as env:API_TOKEN->network:api.example.com"
        )]
        flows: Vec<String>,
        #[arg(help = "Capability grants such as http:api.example.com or env:API_TOKEN")]
        grants: Vec<String>,
    },
    #[command(
        about = "Grant a package globally: write a version-pinned grant to ~/.omc/policy.d/",
        alias = "trust"
    )]
    Grant {
        #[arg(help = "Package spec to grant, e.g. npm:lodash@4.18.1 or pypi:requests@2.32.5")]
        spec: String,
        #[arg(
            long = "allow",
            help = "Capability grant, e.g. dynamic.eval, fs.write:*, env:TOKEN"
        )]
        allow: Vec<String>,
        #[arg(long = "allow-flow", help = "Data-flow grant, e.g. env:*->network:*")]
        allow_flow: Vec<String>,
    },
    #[command(about = "List accepted policy grants; defaults to the global trust store")]
    List {
        #[arg(
            value_enum,
            help = "Policy scope to list (defaults to global)",
            value_name = "SCOPE"
        )]
        scope: Option<PolicyListScope>,
    },
    #[command(
        about = "Show the effective compiled policy for a package, e.g. omc policy check stripe@13.1.0"
    )]
    Check {
        #[arg(
            long,
            conflicts_with = "pypi",
            help = "Resolve the package against the npm ecosystem (the default)"
        )]
        npm: bool,
        #[arg(
            long,
            conflicts_with = "npm",
            help = "Resolve the package against the PyPI ecosystem"
        )]
        pypi: bool,
        #[arg(
            help = "Package, optionally with a version: NAME or NAME@VERSION (defaults to 0.0.0)"
        )]
        package: String,
    },
    #[command(about = "Parse omc.policy and report OK, or the parse error with its location")]
    Validate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PolicyListScope {
    Global,
}

/// Output format for `omc inspect`: a text capability report (default) or a
/// dependency-graph PNG (the surface formerly exposed as `omc graph`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum InspectFormat {
    Text,
    Png,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmCompatAction {
    Help {
        topic: Option<String>,
    },
    HelpSearch {
        query: Vec<String>,
        long: bool,
    },
    Version,
    Completion {
        words: Option<Vec<String>>,
    },
    Init {
        action: NpmInitAction,
    },
    Create {
        action: NpmCreateAction,
    },
    PackageVersion {
        action: NpmVersionAction,
    },
    Link {
        action: NpmLinkAction,
    },
    Install {
        specs: Vec<String>,
        archive_references: Vec<String>,
        local_paths: Vec<PathBuf>,
        global: bool,
        save: bool,
        save_prefix: String,
        save_bundle: bool,
        dependency_kind: ManifestDependencyKind,
        omit_dev: bool,
        omit_optional: bool,
        omit_peer: bool,
        package_lock: bool,
        lock_only: bool,
        dry_run: bool,
        json: bool,
        npm_registry: Option<String>,
        npm_before: Option<String>,
        npm_engine_strict: bool,
        npm_offline: bool,
        allow: Vec<String>,
        allow_flow: Vec<String>,
        allow_all_host: bool,
        workspaces: Vec<String>,
        all_workspaces: bool,
        include_workspace_root: bool,
    },
    InstallTest {
        command: String,
        use_ci: bool,
        specs: Vec<String>,
        archive_references: Vec<String>,
        local_paths: Vec<PathBuf>,
        save: bool,
        save_prefix: String,
        save_bundle: bool,
        dependency_kind: ManifestDependencyKind,
        omit_dev: bool,
        omit_optional: bool,
        omit_peer: bool,
        package_lock: bool,
        lock_only: bool,
        dry_run: bool,
        json: bool,
        npm_registry: Option<String>,
        npm_before: Option<String>,
        npm_engine_strict: bool,
        npm_offline: bool,
        allow: Vec<String>,
        allow_flow: Vec<String>,
        allow_all_host: bool,
        workspaces: Vec<String>,
        all_workspaces: bool,
        include_workspace_root: bool,
        test_args: Vec<String>,
    },
    Ci {
        omit_dev: bool,
        omit_optional: bool,
        omit_peer: bool,
        dry_run: bool,
        json: bool,
        npm_engine_strict: bool,
        npm_offline: bool,
        allow: Vec<String>,
        allow_flow: Vec<String>,
        allow_all_host: bool,
        workspaces: Vec<String>,
        all_workspaces: bool,
        include_workspace_root: bool,
    },
    Remove {
        specs: Vec<String>,
        global: bool,
        save: bool,
        package_lock: bool,
        lock_only: bool,
        allow: Vec<String>,
        allow_flow: Vec<String>,
        allow_all_host: bool,
        workspaces: Vec<String>,
        all_workspaces: bool,
        include_workspace_root: bool,
    },
    Maintenance {
        command: NpmMaintenanceCommand,
        packages: Vec<String>,
        dry_run: bool,
        json: bool,
        omit_dev: bool,
        omit_optional: bool,
        omit_peer: bool,
        allow: Vec<String>,
        allow_flow: Vec<String>,
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
        action: NpmExecAction,
    },
    Explore {
        action: NpmExploreAction,
    },
    Edit {
        target: String,
        editor: Option<String>,
    },
    Path {
        kind: NpmPathKind,
        global: bool,
    },
    List {
        action: NpmListAction,
    },
    Query {
        action: NpmQueryAction,
    },
    Explain {
        specs: Vec<String>,
        json: bool,
    },
    Outdated {
        json: bool,
        parseable: bool,
        packages: Vec<String>,
        npm_registry: Option<String>,
    },
    Doctor {
        action: NpmDoctorAction,
    },
    Audit {
        json: bool,
    },
    Fund {
        action: NpmFundAction,
    },
    Cache {
        action: NpmCacheAction,
        cache_dir: Option<PathBuf>,
    },
    Pkg {
        action: NpmPkgAction,
    },
    Shrinkwrap,
    Pack {
        action: NpmPackAction,
    },
    Publish {
        action: NpmPublishAction,
    },
    Unpublish {
        action: NpmUnpublishAction,
    },
    Deprecate {
        action: NpmDeprecateAction,
    },
    Diff {
        action: NpmDiffAction,
    },
    Search {
        action: NpmSearchAction,
    },
    Star {
        action: NpmStarAction,
    },
    Ping {
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    Whoami {
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    Login {
        action: NpmLoginAction,
    },
    Logout {
        action: NpmLogoutAction,
    },
    Token {
        action: NpmTokenAction,
    },
    Trust {
        action: NpmTrustAction,
    },
    Profile {
        action: NpmProfileAction,
    },
    Owner {
        action: NpmOwnerAction,
    },
    Access {
        action: NpmAccessAction,
    },
    Org {
        action: NpmOrgAction,
    },
    Team {
        action: NpmTeamAction,
    },
    DistTag {
        action: NpmDistTagAction,
    },
    Sbom {
        action: NpmSbomAction,
    },
    Config {
        action: NpmConfigAction,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        globalconfig: Option<PathBuf>,
    },
    ConfigEdit {
        location: NpmConfigLocation,
        editor: Option<String>,
        userconfig: Option<PathBuf>,
        globalconfig: Option<PathBuf>,
    },
    View {
        spec: String,
        fields: Vec<String>,
        json: bool,
        npm_registry: Option<String>,
    },
    MetadataUrl {
        kind: NpmMetadataUrlKind,
        spec: Option<String>,
        json: bool,
        npm_registry: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NpmMaintenanceCommand {
    Prune,
    Dedupe,
    Rebuild,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmListAction {
    pub(crate) json: bool,
    pub(crate) depth: usize,
    pub(crate) packages: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmQueryAction {
    pub(crate) selector: String,
    pub(crate) workspaces: Vec<String>,
    pub(crate) all_workspaces: bool,
    pub(crate) include_workspace_root: bool,
    pub(crate) package_lock_only: bool,
    pub(crate) expect_results: Option<bool>,
    pub(crate) expect_result_count: Option<usize>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmRunListAction {
    pub(crate) json: bool,
    pub(crate) workspaces: Vec<String>,
    pub(crate) all_workspaces: bool,
    pub(crate) include_workspace_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmExploreAction {
    pub(crate) package: String,
    pub(crate) command: Option<String>,
    pub(crate) args: Vec<String>,
    pub(crate) shell: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmFundAction {
    pub(crate) json: bool,
    pub(crate) package: Option<String>,
    pub(crate) workspaces: Vec<String>,
    pub(crate) all_workspaces: bool,
    pub(crate) include_workspace_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmInitAction {
    pub(crate) name: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) main: Option<String>,
    pub(crate) license: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) private: bool,
    pub(crate) package_type: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmCreateAction {
    pub(crate) initializer: String,
    pub(crate) args: Vec<String>,
    pub(crate) npm_registry: Option<String>,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmExecAction {
    pub(crate) packages: Vec<String>,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) no_install: bool,
    pub(crate) prefer_project_bin: bool,
    pub(crate) npm_registry: Option<String>,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
    pub(crate) workspaces: Vec<String>,
    pub(crate) all_workspaces: bool,
    pub(crate) include_workspace_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmVersionAction {
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
pub(crate) enum NpmMetadataUrlKind {
    Docs,
    Repo,
    Bugs,
    Home,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmDistTagAction {
    List {
        spec: Option<String>,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    Add {
        spec: String,
        tag: String,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Remove {
        spec: String,
        tag: String,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmOwnerAction {
    List {
        spec: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    Add {
        user: String,
        spec: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Remove {
        user: String,
        spec: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmAccessAction {
    ListPackages {
        owner: Option<String>,
        package: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    ListCollaborators {
        package: Option<String>,
        user: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    GetStatus {
        package: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    SetStatus {
        package: Option<String>,
        status: String,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    SetMfa {
        package: Option<String>,
        level: String,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Grant {
        permission: String,
        scope_team: String,
        package: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Revoke {
        scope_team: String,
        package: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmProfileAction {
    Get {
        keys: Vec<String>,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    Set {
        property: String,
        value: String,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmOrgAction {
    Set {
        org: String,
        user: String,
        role: Option<String>,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Remove {
        org: String,
        user: String,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    List {
        org: String,
        user: Option<String>,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmTeamAction {
    Create {
        scope_team: String,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Destroy {
        scope_team: String,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Add {
        scope_team: String,
        user: String,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Remove {
        scope_team: String,
        user: String,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    List {
        scope_or_team: String,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmSbomAction {
    pub(crate) format: NpmSbomFormat,
    pub(crate) sbom_type: NpmSbomType,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmLoginAction {
    pub(crate) scope: Option<String>,
    pub(crate) json: bool,
    pub(crate) npm_registry: Option<String>,
    pub(crate) userconfig: Option<PathBuf>,
    pub(crate) token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmLogoutAction {
    pub(crate) scope: Option<String>,
    pub(crate) json: bool,
    pub(crate) npm_registry: Option<String>,
    pub(crate) userconfig: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NpmSbomFormat {
    CycloneDx,
    Spdx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NpmSbomType {
    Library,
    Application,
    Framework,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NpmPathKind {
    Bin,
    Root,
    Prefix,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmCacheAction {
    Verify,
    List { pattern: Option<String> },
    Remove { pattern: String },
    Clean,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmDoctorAction {
    pub(crate) checks: Vec<String>,
    pub(crate) npm_registry: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmPkgAction {
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
pub(crate) struct NpmPackAction {
    pub(crate) packages: Vec<NpmPackInput>,
    pub(crate) destination: PathBuf,
    pub(crate) json: bool,
    pub(crate) dry_run: bool,
    pub(crate) npm_registry: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmPublishAction {
    pub(crate) package: Option<PathBuf>,
    pub(crate) tag: String,
    pub(crate) access: Option<String>,
    pub(crate) provenance: NpmPublishProvenance,
    pub(crate) dry_run: bool,
    pub(crate) json: bool,
    pub(crate) npm_registry: Option<String>,
    pub(crate) userconfig: Option<PathBuf>,
    pub(crate) otp: Option<String>,
    pub(crate) workspaces: Vec<String>,
    pub(crate) all_workspaces: bool,
    pub(crate) include_workspace_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NpmPublishProvenance {
    None,
    Generate,
    File(PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmUnpublishAction {
    pub(crate) spec: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) force: bool,
    pub(crate) json: bool,
    pub(crate) npm_registry: Option<String>,
    pub(crate) userconfig: Option<PathBuf>,
    pub(crate) otp: Option<String>,
    pub(crate) workspaces: Vec<String>,
    pub(crate) all_workspaces: bool,
    pub(crate) include_workspace_root: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmDeprecateAction {
    pub(crate) spec: String,
    pub(crate) message: String,
    pub(crate) dry_run: bool,
    pub(crate) json: bool,
    pub(crate) npm_registry: Option<String>,
    pub(crate) userconfig: Option<PathBuf>,
    pub(crate) otp: Option<String>,
    pub(crate) undeprecate: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmDiffAction {
    pub(crate) specs: Vec<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) name_only: bool,
    pub(crate) unified: usize,
    pub(crate) ignore_all_space: bool,
    pub(crate) no_prefix: bool,
    pub(crate) src_prefix: String,
    pub(crate) dst_prefix: String,
    pub(crate) text: bool,
    pub(crate) npm_registry: Option<String>,
    pub(crate) userconfig: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NpmSearchAction {
    pub(crate) query: String,
    pub(crate) json: bool,
    pub(crate) parseable: bool,
    pub(crate) limit: usize,
    pub(crate) npm_registry: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmStarAction {
    Mutate {
        specs: Vec<String>,
        starred: bool,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    List {
        user: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmPackInput {
    Local(PathBuf),
    Registry(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmConfigAction {
    Get {
        keys: Vec<String>,
        json: bool,
        location: NpmConfigLocation,
    },
    List {
        json: bool,
        location: NpmConfigLocation,
    },
    Set {
        assignments: Vec<(String, String)>,
        location: NpmConfigLocation,
    },
    Delete {
        keys: Vec<String>,
        location: NpmConfigLocation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NpmConfigLocation {
    User,
    Project,
    Global,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmTokenAction {
    List {
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    Create {
        options: Box<NpmTokenCreateOptions>,
        json: bool,
        parseable: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Revoke {
        token: String,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NpmTrustAction {
    List {
        package: Option<String>,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
    },
    Revoke {
        package: Option<String>,
        id: String,
        dry_run: bool,
        json: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
    Create {
        provider: NpmTrustProvider,
        package: Option<String>,
        config: serde_json::Value,
        dry_run: bool,
        json: bool,
        yes: bool,
        npm_registry: Option<String>,
        userconfig: Option<PathBuf>,
        otp: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NpmTrustProvider {
    GitHub,
    GitLab,
    CircleCi,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PipCompatAction {
    Help {
        topic: Option<String>,
    },
    Version,
    Completion {
        shell: Option<PipCompletionShell>,
    },
    Install(Box<PipInstallAction>),
    Lock(Box<PipLockAction>),
    Download(Box<PipDownloadAction>),
    Wheel(Box<PipDownloadAction>),
    Uninstall {
        specs: Vec<String>,
        requirements: Vec<PathBuf>,
        user: bool,
        allow: Vec<String>,
        allow_flow: Vec<String>,
        allow_all_host: bool,
    },
    Show {
        specs: Vec<String>,
        files: bool,
        user: bool,
    },
    Hash {
        algorithm: PipHashAlgorithm,
        paths: Vec<PathBuf>,
    },
    Cache {
        action: PipCacheAction,
        cache_dir: Option<PathBuf>,
    },
    Check {
        user: bool,
    },
    Debug {
        action: PipDebugAction,
    },
    Inspect {
        paths: Vec<PathBuf>,
        user: bool,
    },
    Freeze {
        action: PipFreezeAction,
    },
    List {
        format: PipListFormat,
        verbose: bool,
        outdated: bool,
        uptodate: bool,
        paths: Vec<PathBuf>,
        user: bool,
        exclude: Vec<String>,
        editable: PipEditableMode,
        not_required: bool,
        index_url: Option<String>,
        extra_index_urls: Vec<String>,
        find_links: Vec<String>,
        no_index: bool,
        allow_prereleases: bool,
    },
    IndexVersions {
        package: String,
        index_url: Option<String>,
        extra_index_urls: Vec<String>,
        find_links: Vec<String>,
        no_index: bool,
        allow_prereleases: bool,
        release_controls: PypiReleaseControls,
        uploaded_prior_to: Option<String>,
        compatibility: PipCompatibilityTarget,
        json: bool,
    },
    Search {
        query: Vec<String>,
    },
    Config {
        action: PipConfigAction,
    },
    ConfigEdit {
        location: PipConfigLocation,
        editor: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipCompletionShell {
    Bash,
    Zsh,
    Fish,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PipCacheAction {
    Dir,
    Info,
    List {
        pattern: Option<String>,
        format: PipCacheListFormat,
    },
    Remove {
        pattern: String,
    },
    Purge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipCacheListFormat {
    Human,
    Abspath,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PipDebugAction {
    pub(crate) verbose: bool,
    pub(crate) platform: Option<String>,
    pub(crate) python_version: Option<String>,
    pub(crate) implementation: Option<String>,
    pub(crate) abis: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PipCompatibilityTarget {
    pub(crate) platforms: Vec<String>,
    pub(crate) python_version: Option<String>,
    pub(crate) implementation: Option<String>,
    pub(crate) abis: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl PipHashAlgorithm {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PipInstallAction {
    pub(crate) specs: Vec<String>,
    pub(crate) requirements: Vec<PathBuf>,
    pub(crate) constraints: Vec<PathBuf>,
    pub(crate) script_requirements: Vec<PathBuf>,
    pub(crate) groups: Vec<String>,
    pub(crate) report: Option<PathBuf>,
    pub(crate) dry_run: bool,
    pub(crate) archive_references: Vec<String>,
    pub(crate) local_paths: Vec<PythonLocalRequirement>,
    pub(crate) local_directories: Vec<PythonLocalRequirement>,
    pub(crate) index_url: Option<String>,
    pub(crate) extra_index_urls: Vec<String>,
    pub(crate) find_links: Vec<String>,
    pub(crate) no_index: bool,
    pub(crate) binary_all: Option<PypiBinaryMode>,
    pub(crate) binary_packages: BTreeMap<String, PypiBinaryMode>,
    pub(crate) require_hashes: bool,
    pub(crate) no_deps: bool,
    pub(crate) allow_prereleases: bool,
    pub(crate) release_controls: PypiReleaseControls,
    pub(crate) uploaded_prior_to: Option<String>,
    pub(crate) upgrade: bool,
    pub(crate) force_reinstall: bool,
    pub(crate) compatibility: PipCompatibilityTarget,
    pub(crate) target: Option<PathBuf>,
    pub(crate) prefix: Option<PathBuf>,
    pub(crate) root: Option<PathBuf>,
    pub(crate) user: bool,
    pub(crate) vcs_requirements: Vec<PythonVcsRequirement>,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PipLockAction {
    pub(crate) install: PipInstallAction,
    pub(crate) output: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PipDownloadAction {
    pub(crate) specs: Vec<String>,
    pub(crate) requirements: Vec<PathBuf>,
    pub(crate) constraints: Vec<PathBuf>,
    pub(crate) archive_references: Vec<String>,
    pub(crate) local_paths: Vec<PythonLocalRequirement>,
    pub(crate) index_url: Option<String>,
    pub(crate) extra_index_urls: Vec<String>,
    pub(crate) find_links: Vec<String>,
    pub(crate) no_index: bool,
    pub(crate) binary_all: Option<PypiBinaryMode>,
    pub(crate) binary_packages: BTreeMap<String, PypiBinaryMode>,
    pub(crate) require_hashes: bool,
    pub(crate) no_deps: bool,
    pub(crate) allow_prereleases: bool,
    pub(crate) release_controls: PypiReleaseControls,
    pub(crate) uploaded_prior_to: Option<String>,
    pub(crate) compatibility: PipCompatibilityTarget,
    pub(crate) destination: PathBuf,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipListFormat {
    Columns,
    Freeze,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipEditableMode {
    Include,
    Only,
    Exclude,
}

impl PipEditableMode {
    pub(crate) fn includes_editables(self) -> bool {
        !matches!(self, Self::Exclude)
    }

    pub(crate) fn includes_regular(self) -> bool {
        !matches!(self, Self::Only)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PipFreezeAction {
    pub(crate) requirements: Vec<PathBuf>,
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) user: bool,
    pub(crate) exclude: Vec<String>,
    pub(crate) exclude_editable: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PipConfigAction {
    Get {
        keys: Vec<String>,
        json: bool,
    },
    List {
        json: bool,
    },
    Debug,
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
pub(crate) enum PipConfigLocation {
    Auto,
    User,
    Site,
    Global,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TwineCompatAction {
    Help { topic: Option<String> },
    Version,
    Check(TwineCheckAction),
    Upload(Box<TwineUploadAction>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TwineCheckAction {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) strict: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TwineUploadAction {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) repository: Option<String>,
    pub(crate) repository_url: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) config_file: Option<PathBuf>,
    pub(crate) cert: Option<PathBuf>,
    pub(crate) client_cert: Option<PathBuf>,
    pub(crate) skip_existing: bool,
    pub(crate) comment: Option<String>,
    pub(crate) sign: bool,
    pub(crate) sign_with: Option<String>,
    pub(crate) identity: Option<String>,
    pub(crate) attestations: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TwineUploadSettings {
    pub(crate) repository_url: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) cert: Option<PathBuf>,
    pub(crate) client_cert: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct TwinePypirc {
    pub(crate) sections: BTreeMap<String, BTreeMap<String, String>>,
}

#[cfg(feature = "dev-commands")]
#[derive(Debug)]
pub(crate) struct CompileCommand {
    pub(crate) npm: bool,
    pub(crate) pypi: bool,
    pub(crate) source: PathBuf,
    pub(crate) name: Option<String>,
    pub(crate) version: String,
    pub(crate) output: Option<PathBuf>,
    pub(crate) store: bool,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
}
