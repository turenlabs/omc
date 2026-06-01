//! twine CLI shim — extracted verbatim from lib.rs.

use crate::*;

use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::{env, fs};

use omc_registry::{
    check_pypi_distribution, upload_pypi_distribution, OmcRegistryError, PypiUploadOptions,
    PypiUploadResult, PypiUploadSignature,
};

pub(crate) fn run_twine_compat(
    project_dir: &Path,
    args: &[String],
) -> Result<ExitCode, OmcRegistryError> {
    run_twine_compat_with_cwd(project_dir, args, project_dir)
}

pub(crate) fn run_twine_compat_with_cwd(
    project_dir: &Path,
    args: &[String],
    invocation_cwd: &Path,
) -> Result<ExitCode, OmcRegistryError> {
    match parse_twine_compat_action(args)? {
        TwineCompatAction::Help { topic } => {
            print_twine_help(topic.as_deref());
            Ok(ExitCode::SUCCESS)
        }
        TwineCompatAction::Version => {
            println!("twine {} from OMC", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        TwineCompatAction::Check(mut action) => {
            absolutize_twine_check_action_paths(invocation_cwd, &mut action);
            let failed = print_twine_check(project_dir, action)?;
            Ok(if failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        TwineCompatAction::Upload(mut action) => {
            absolutize_twine_upload_action_paths(invocation_cwd, &mut action);
            print_twine_upload(project_dir, *action)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn absolutize_twine_check_action_paths(base_dir: &Path, action: &mut TwineCheckAction) {
    action.paths = absolutize_paths(base_dir, std::mem::take(&mut action.paths));
}

pub(crate) fn absolutize_twine_upload_action_paths(base_dir: &Path, action: &mut TwineUploadAction) {
    action.paths = absolutize_paths(base_dir, std::mem::take(&mut action.paths));
    action.config_file = action
        .config_file
        .take()
        .map(|path| absolutize_path(base_dir, path));
    action.cert = action
        .cert
        .take()
        .map(|path| absolutize_path(base_dir, path));
    action.client_cert = action
        .client_cert
        .take()
        .map(|path| absolutize_path(base_dir, path));
}

pub(crate) fn print_twine_check(
    project_dir: &Path,
    action: TwineCheckAction,
) -> Result<bool, OmcRegistryError> {
    if action.paths.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine check needs at least one distribution file".to_owned(),
        ));
    }

    let mut failed = false;
    for path in &action.paths {
        let absolute = absolutize_path(project_dir, path.clone());
        let result = check_pypi_distribution(&absolute, action.strict)?;
        print!("Checking {}: ", path.display());
        if result.passed && result.warnings.is_empty() {
            println!("PASSED");
        } else if result.passed {
            println!("PASSED with warnings");
        } else {
            println!("FAILED due to warnings");
            failed = true;
        }
        for warning in result.warnings {
            println!("warning: {warning}");
        }
    }
    Ok(failed)
}

fn print_twine_upload(
    project_dir: &Path,
    action: TwineUploadAction,
) -> Result<(), OmcRegistryError> {
    if action.paths.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine upload needs at least one distribution file".to_owned(),
        ));
    }

    let settings = resolve_twine_upload_settings(project_dir, &action)?;
    let inputs = twine_upload_inputs(project_dir, &action)?;
    println!("Uploading distributions to {}", settings.repository_url);
    for input in inputs {
        let path = input.path;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("distribution");
        println!("Uploading {filename}");
        let signature = if action.sign {
            Some(twine_sign_distribution(
                &path,
                action.sign_with.as_deref(),
                action.identity.as_deref(),
            )?)
        } else {
            None
        };
        let attestations = if action.attestations {
            Some(twine_upload_attestations_json(
                &path,
                &input.attestation_paths,
            )?)
        } else {
            None
        };
        let result = upload_pypi_distribution(
            &settings.repository_url,
            &settings.username,
            &settings.password,
            &path,
            PypiUploadOptions {
                skip_existing: action.skip_existing,
                comment: action.comment.as_deref(),
                cert: settings.cert.as_deref(),
                client_cert: settings.client_cert.as_deref(),
                signature: signature.as_ref().map(|signature| PypiUploadSignature {
                    filename: signature.filename.as_str(),
                    bytes: &signature.bytes,
                }),
                attestations: attestations.as_deref(),
            },
        )?;
        print_twine_upload_result(&result);
    }
    Ok(())
}

fn print_twine_upload_result(result: &PypiUploadResult) {
    if result.skipped {
        println!(
            "Skipping {} because it appears to already exist",
            result.filename
        );
    } else {
        println!("Uploaded {}", result.filename);
    }
}

#[derive(Debug)]
pub(crate) struct TwineUploadInput {
    pub(crate) path: PathBuf,
    pub(crate) attestation_paths: Vec<PathBuf>,
}

pub(crate) fn twine_upload_inputs(
    project_dir: &Path,
    action: &TwineUploadAction,
) -> Result<Vec<TwineUploadInput>, OmcRegistryError> {
    let paths = action
        .paths
        .iter()
        .map(|path| absolutize_path(project_dir, path.clone()))
        .collect::<Vec<_>>();
    let attestations = paths
        .iter()
        .filter(|path| twine_attestation_path(path))
        .cloned()
        .collect::<Vec<_>>();
    let mut inputs = Vec::new();
    for path in paths {
        if twine_attestation_path(&path) {
            continue;
        }
        let basename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                OmcRegistryError::UnsupportedSpec(format!(
                    "twine upload path `{}` does not have a valid UTF-8 filename",
                    path.display()
                ))
            })?;
        let prefix = format!("{basename}.");
        let attestation_paths = attestations
            .iter()
            .filter(|attestation| {
                attestation
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with(&prefix))
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>();
        if action.attestations && attestation_paths.is_empty() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "twine upload --attestations requested, but `{}` has no associated attestations",
                path.display()
            )));
        }
        inputs.push(TwineUploadInput {
            path,
            attestation_paths,
        });
    }
    if inputs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine upload needs at least one distribution file".to_owned(),
        ));
    }
    Ok(inputs)
}

pub(crate) fn twine_attestation_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".attestation"))
        .map(|stem| stem.contains('.'))
        .unwrap_or(false)
}

pub(crate) fn twine_upload_attestations_json(
    distribution: &Path,
    attestations: &[PathBuf],
) -> Result<String, OmcRegistryError> {
    if attestations.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "twine upload --attestations requested, but `{}` has no associated attestations",
            distribution.display()
        )));
    }
    let mut loaded = Vec::new();
    for attestation in attestations {
        let bytes = fs::read(attestation)?;
        let value = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| {
            OmcRegistryError::UnsupportedSpec(format!(
                "invalid JSON in attestation `{}`: {error}",
                attestation.display()
            ))
        })?;
        loaded.push(value);
    }
    Ok(serde_json::to_string(&loaded)?)
}

struct TwineUploadSignature {
    filename: String,
    bytes: Vec<u8>,
}

fn twine_sign_distribution(
    path: &Path,
    sign_with: Option<&str>,
    identity: Option<&str>,
) -> Result<TwineUploadSignature, OmcRegistryError> {
    let signer = sign_with
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("gpg");
    let mut command = ProcessCommand::new(signer);
    command.arg("--detach-sign").arg("-a");
    if let Some(identity) = identity.map(str::trim).filter(|value| !value.is_empty()) {
        command.arg("--local-user").arg(identity);
    }
    // batou:ignore command_exec -- CLI twine shim signs user-supplied dist with gpg via explicit arg list (no shell); verbatim move during refactor
    command.arg(path);
    let status = command.status()?;
    if !status.success() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "twine upload signing failed for `{}` using `{signer}`",
            path.display()
        )));
    }

    let signature_path = twine_signature_path(path)?;
    // batou:ignore file_read -- CLI tool reads gpg signature next to user-supplied dist path by design; verbatim move during refactor
    let bytes = fs::read(&signature_path)?;
    let filename = signature_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload signature path `{}` does not have a valid UTF-8 filename",
                signature_path.display()
            ))
        })?
        .to_owned();
    Ok(TwineUploadSignature { filename, bytes })
}

fn twine_signature_path(path: &Path) -> Result<PathBuf, OmcRegistryError> {
    let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "twine upload path `{}` does not have a valid UTF-8 filename",
            path.display()
        )));
    };
    Ok(path.with_file_name(format!("{filename}.asc")))
}

pub(crate) fn resolve_twine_upload_settings(
    project_dir: &Path,
    action: &TwineUploadAction,
) -> Result<TwineUploadSettings, OmcRegistryError> {
    let env_repository = env::var("TWINE_REPOSITORY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let env_repository_url = env::var("TWINE_REPOSITORY_URL")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let repository = action.repository.clone().or(env_repository);
    let repository_name = repository
        .as_deref()
        .filter(|value| !looks_like_url(value))
        .unwrap_or("pypi");
    let config = read_twine_pypirc(project_dir, action.config_file.as_deref())?;
    let section = config.sections.get(repository_name);

    let repository_url = action
        .repository_url
        .clone()
        .or(env_repository_url)
        .or_else(|| repository.clone().filter(|value| looks_like_url(value)))
        .or_else(|| section.and_then(|values| values.get("repository")).cloned())
        .or_else(|| default_twine_repository_url(repository_name).map(str::to_owned))
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload could not resolve repository `{repository_name}`"
            ))
        })?;
    let cert = action
        .cert
        .clone()
        .or_else(|| {
            env::var("TWINE_CERT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| {
            section
                .and_then(|values| values.get("ca_cert"))
                .map(PathBuf::from)
        })
        .map(|path| absolutize_path(project_dir, path));
    let client_cert = action
        .client_cert
        .clone()
        .or_else(|| {
            section
                .and_then(|values| values.get("client_cert"))
                .map(PathBuf::from)
        })
        .map(|path| absolutize_path(project_dir, path));

    let username = action
        .username
        .clone()
        .or_else(|| env::var("TWINE_USERNAME").ok())
        .or_else(|| section.and_then(|values| values.get("username")).cloned());
    let username = match username {
        Some(username) => username,
        None if client_cert.is_some() => String::new(),
        None => {
            return Err(OmcRegistryError::UnsupportedSpec(
                "twine upload needs a username; pass --username, set TWINE_USERNAME, configure .pypirc, or pass --client-cert".to_owned(),
            ));
        }
    };
    let password = action
        .password
        .clone()
        .or_else(|| env::var("TWINE_PASSWORD").ok())
        .or_else(|| section.and_then(|values| values.get("password")).cloned());
    let password = match password {
        Some(password) => password,
        None if client_cert.is_some() => String::new(),
        None => {
            return Err(OmcRegistryError::UnsupportedSpec(
                "twine upload needs a password/token; pass --password, set TWINE_PASSWORD, configure .pypirc, or pass --client-cert".to_owned(),
            ));
        }
    };
    if client_cert.is_none() && username.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
                "twine upload needs a username; pass --username, set TWINE_USERNAME, configure .pypirc, or pass --client-cert".to_owned(),
            ));
    }
    if client_cert.is_none() && password.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
                "twine upload needs a password/token; pass --password, set TWINE_PASSWORD, configure .pypirc, or pass --client-cert".to_owned(),
            ));
    }

    Ok(TwineUploadSettings {
        repository_url,
        username,
        password,
        cert,
        client_cert,
    })
}

fn looks_like_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn default_twine_repository_url(name: &str) -> Option<&'static str> {
    match name {
        "pypi" => Some("https://upload.pypi.org/legacy/"),
        "testpypi" => Some("https://test.pypi.org/legacy/"),
        _ => None,
    }
}

fn read_twine_pypirc(
    project_dir: &Path,
    config_file: Option<&Path>,
) -> Result<TwinePypirc, OmcRegistryError> {
    let Some(path) = config_file
        .map(|path| absolutize_path(project_dir, path.to_path_buf()))
        .or_else(default_twine_pypirc_path)
    else {
        return Ok(TwinePypirc::default());
    };
    if !path.exists() {
        if config_file.is_some() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "twine config file `{}` does not exist",
                path.display()
            )));
        }
        return Ok(TwinePypirc::default());
    }
    Ok(parse_twine_pypirc(&fs::read_to_string(path)?))
}

fn default_twine_pypirc_path() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(".pypirc"))
}

fn parse_twine_pypirc(content: &str) -> TwinePypirc {
    let mut config = TwinePypirc::default();
    let mut current_section: Option<String> = None;
    for raw_line in content.lines() {
        let line = strip_pypirc_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_owned();
            current_section = (!section.is_empty()).then_some(section);
            continue;
        }
        let Some(section) = current_section.as_ref() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        config
            .sections
            .entry(section.clone())
            .or_default()
            .insert(key.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    config
}

fn strip_pypirc_comment(line: &str) -> &str {
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

fn print_twine_help(topic: Option<&str>) {
    print!("{}", twine_help_text(topic));
}

fn twine_help_text(topic: Option<&str>) -> String {
    match topic.and_then(twine_help_topic) {
        None => twine_command_help(
            "twine <command>",
            &[
                "OMC Twine compatibility validates and uploads Python wheel and sdist artifacts through OMC.",
                "Supported commands: check, upload.",
            ],
        ),
        Some("check") => twine_command_help(
            "twine check [--strict] dist [dist ...]",
            &[
                "Validate Python wheel and sdist metadata before upload.",
                "Checks long_description and long_description_content_type warnings without delegating to Twine.",
                "Supports --strict to fail on warnings.",
            ],
        ),
        Some("upload") => twine_command_help(
            "twine upload [options] dist [dist ...]",
            &[
                "Upload one or more .whl, .tar.gz, .tgz, or .zip distributions.",
                "Supports -r/--repository, --repository-url, -u/--username, -p/--password, --config-file, --cert, --client-cert, --skip-existing, --non-interactive, --comment, --sign, --sign-with, --identity, --attestations, --verbose, and --disable-progress-bar.",
            ],
        ),
        Some(_) => twine_command_help(
            "twine help [command]",
            &["No focused OMC help is available for that topic yet."],
        ),
    }
}

fn twine_command_help(usage: &str, lines: &[&str]) -> String {
    let mut output = format!("OMC Twine compatibility\n\nUsage: {usage}\n");
    if !lines.is_empty() {
        output.push('\n');
        for line in lines {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn twine_help_topic(topic: &str) -> Option<&'static str> {
    match topic {
        "help" | "--help" | "-h" => None,
        "check" => Some("check"),
        "upload" => Some("upload"),
        _ => Some("unknown"),
    }
}

pub(crate) fn parse_twine_compat_action(
    args: &[String],
) -> Result<TwineCompatAction, OmcRegistryError> {
    let normalized = normalize_twine_global_args(args)?;
    let args = normalized.as_slice();
    if let Some(action) = parse_twine_help_request(args) {
        return Ok(action);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine compatibility needs a command such as check or upload".to_owned(),
        ));
    };

    match command {
        "--version" | "-V" => Ok(TwineCompatAction::Version),
        "check" => parse_twine_check_args(&args[1..]),
        "upload" => parse_twine_upload_args(&args[1..]),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported twine compatibility command `{other}`"
        ))),
    }
}

fn parse_twine_help_request(args: &[String]) -> Option<TwineCompatAction> {
    let command = args.first()?;
    if twine_help_flag(command) {
        return Some(TwineCompatAction::Help { topic: None });
    }
    if command == "help" {
        let topic = args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned();
        return Some(TwineCompatAction::Help { topic });
    }
    if args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| twine_help_flag(arg))
    {
        return Some(TwineCompatAction::Help {
            topic: Some(command.clone()),
        });
    }
    None
}

fn twine_help_flag(arg: &str) -> bool {
    matches!(arg, "--help" | "-h")
}

fn normalize_twine_global_args(args: &[String]) -> Result<Vec<String>, OmcRegistryError> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--version" | "-V") {
            return Ok(vec![arg.clone()]);
        } else if matches!(arg.as_str(), "--no-color" | "--no-input") {
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

fn parse_twine_check_args(args: &[String]) -> Result<TwineCompatAction, OmcRegistryError> {
    let mut paths = Vec::new();
    let mut strict = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if twine_help_flag(arg) {
            return Ok(TwineCompatAction::Help {
                topic: Some("check".to_owned()),
            });
        } else if arg == "--strict" {
            strict = true;
        } else if matches!(
            arg.as_str(),
            "--non-interactive" | "--disable-progress-bar" | "--verbose"
        ) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("twine check", arg));
        } else {
            paths.push(PathBuf::from(arg));
        }
        index += 1;
    }
    Ok(TwineCompatAction::Check(TwineCheckAction { paths, strict }))
}

fn parse_twine_upload_args(args: &[String]) -> Result<TwineCompatAction, OmcRegistryError> {
    let mut paths = Vec::new();
    let mut repository = None;
    let mut repository_url = None;
    let mut username = None;
    let mut password = None;
    let mut config_file = None;
    let mut cert = None;
    let mut client_cert = None;
    let mut skip_existing = false;
    let mut comment = None;
    let mut sign = false;
    let mut sign_with = None;
    let mut identity = None;
    let mut attestations = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if twine_help_flag(arg) {
            return Ok(TwineCompatAction::Help {
                topic: Some("upload".to_owned()),
            });
        } else if arg == "-r" || arg == "--repository" {
            index += 1;
            repository = Some(twine_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--repository=") {
            repository = Some(value.to_owned());
        } else if arg == "--repository-url" {
            index += 1;
            repository_url = Some(twine_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--repository-url=") {
            repository_url = Some(value.to_owned());
        } else if arg == "-u" || arg == "--username" {
            index += 1;
            username = Some(twine_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--username=") {
            username = Some(value.to_owned());
        } else if arg == "-p" || arg == "--password" {
            index += 1;
            password = Some(twine_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--password=") {
            password = Some(value.to_owned());
        } else if arg == "--config-file" {
            index += 1;
            config_file = Some(PathBuf::from(twine_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--config-file=") {
            config_file = Some(PathBuf::from(value));
        } else if arg == "--cert" {
            index += 1;
            cert = Some(PathBuf::from(twine_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--cert=") {
            cert = Some(PathBuf::from(value));
        } else if arg == "--client-cert" {
            index += 1;
            client_cert = Some(PathBuf::from(twine_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--client-cert=") {
            client_cert = Some(PathBuf::from(value));
        } else if arg == "-c" || arg == "--comment" {
            index += 1;
            comment = Some(twine_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--comment=") {
            comment = Some(value.to_owned());
        } else if arg == "--skip-existing" {
            skip_existing = true;
        } else if matches!(
            arg.as_str(),
            "--non-interactive" | "--disable-progress-bar" | "--verbose"
        ) {
        } else if matches!(arg.as_str(), "-s" | "--sign") {
            sign = true;
        } else if arg == "--sign-with" {
            index += 1;
            sign_with = Some(twine_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--sign-with=") {
            sign_with = Some(value.to_owned());
        } else if arg == "-i" || arg == "--identity" {
            index += 1;
            identity = Some(twine_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--identity=") {
            identity = Some(value.to_owned());
        } else if arg == "--attestations" {
            attestations = true;
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("twine upload", arg));
        } else {
            paths.push(PathBuf::from(arg));
        }
        index += 1;
    }
    Ok(TwineCompatAction::Upload(Box::new(TwineUploadAction {
        paths,
        repository,
        repository_url,
        username,
        password,
        config_file,
        cert,
        client_cert,
        skip_existing,
        comment,
        sign,
        sign_with,
        identity,
        attestations,
    })))
}

fn twine_flag_value(args: &[String], index: usize, flag: &str) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}
