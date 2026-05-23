use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use omc_cap::Capability;
use omc_registry::{
    init_project, link_package, parse_capability_grant, read_lockfile, LinkOptions,
    OmcRegistryError, PackageSpec, Verdict,
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
    #[command(about = "Resolve, cache, profile, verify, and lock a package")]
    Add {
        #[arg(help = "Package spec such as npm:left-pad@1.3.0 or pypi:idna==3.7")]
        spec: String,
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
    #[command(about = "Summarize locked packages and fail if any are blocked")]
    Audit,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
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

fn run() -> Result<(), OmcRegistryError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { name } => {
            let manifest = init_project(&cli.project_dir, name.as_deref())?;
            println!("initialized {}", manifest.display());
        }
        Command::Add {
            spec,
            record_blocked,
            allow,
            allow_all_host,
        } => {
            let spec = PackageSpec::parse(&spec)?;
            let mut options = LinkOptions::new(&cli.project_dir);
            options.record_blocked = record_blocked;
            options.allowed_capabilities = parse_grants(&allow, allow_all_host)?;

            match link_package(&spec, &options) {
                Ok(report) => {
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

                    if !report.artifact.capabilities.is_empty() {
                        println!();
                        println!("capabilities:");
                        for finding in &report.artifact.capabilities {
                            println!(
                                "  - {} {} from {} ({})",
                                finding.kind, finding.target, finding.source, finding.evidence
                            );
                        }
                    }

                    if !report.artifact.verifier_findings.is_empty() {
                        println!();
                        println!("verifier findings:");
                        for finding in &report.artifact.verifier_findings {
                            println!("  - {finding}");
                        }
                    }
                }
                Err(OmcRegistryError::BlockedPackage { spec }) => {
                    return Err(OmcRegistryError::BlockedPackage { spec });
                }
                Err(error) => return Err(error),
            }
        }
        Command::Audit => {
            let lock = read_lockfile(cli.project_dir.join("omc.lock"))?;
            let blocked = lock
                .packages
                .iter()
                .filter(|package| package.verdict == Verdict::Blocked)
                .count();
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

            if blocked > 0 {
                return Err(OmcRegistryError::BlockedPackage {
                    spec: format!("{blocked} locked package(s)"),
                });
            }
        }
    }

    Ok(())
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accepted => "accepted",
        Verdict::Blocked => "blocked",
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
