//! `omc compile` source command: ecosystem inference and source compilation.

use crate::*;

use std::fs;
use std::path::Path;

use omc_registry::{compile_source_path, CompileSourceOptions, Ecosystem, OmcRegistryError};

pub(crate) fn print_compile_source(
    project_dir: &Path,
    command: CompileCommand,
) -> Result<(), OmcRegistryError> {
    let ecosystem = infer_compile_ecosystem(&command.source, command.npm, command.pypi)?;
    let name = command
        .name
        .unwrap_or_else(|| compile_source_default_name(&command.source));
    let report = compile_source_path(CompileSourceOptions {
        project_dir: project_dir.to_path_buf(),
        source_path: command.source,
        ecosystem,
        name,
        version: command.version,
        allowed_capabilities: parse_grants(&command.allow, command.allow_all_host)?,
        allowed_flows: parse_flow_grants(&command.allow_flow)?,
        write_artifact: command.store,
    })?;

    if let Some(output) = command.output {
        if let Some(parent) = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(&output, serde_json::to_string_pretty(&report.artifact)?)?;
        println!("{}", output.display());
    } else if let Some(artifact_path) = report.artifact_path {
        println!("{}", artifact_path.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&report.artifact)?);
    }

    Ok(())
}

pub(crate) fn infer_compile_ecosystem(
    source: &Path,
    npm: bool,
    pypi: bool,
) -> Result<Ecosystem, OmcRegistryError> {
    match (npm, pypi) {
        (true, false) => return Ok(Ecosystem::Npm),
        (false, true) => return Ok(Ecosystem::Pypi),
        (true, true) => {
            return Err(OmcRegistryError::UnsupportedSpec(
                "omc compile cannot combine --npm and --pypi".to_owned(),
            ));
        }
        (false, false) => {}
    }

    if source.is_dir() {
        if source.join("package.json").exists() {
            return Ok(Ecosystem::Npm);
        }
        if source.join("pyproject.toml").exists()
            || source.join("setup.cfg").exists()
            || source.join("setup.py").exists()
        {
            return Ok(Ecosystem::Pypi);
        }
    }

    let lower_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if lower_name.ends_with(".whl") {
        return Ok(Ecosystem::Pypi);
    }
    match source.extension().and_then(|extension| extension.to_str()) {
        Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => Ok(Ecosystem::Npm),
        Some("py") => Ok(Ecosystem::Pypi),
        _ => Err(OmcRegistryError::UnsupportedSpec(
            "omc compile needs --npm or --pypi when the source ecosystem cannot be inferred"
                .to_owned(),
        )),
    }
}

pub(crate) fn compile_source_default_name(source: &Path) -> String {
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("local-source");
    let name = name
        .strip_suffix(".tar.gz")
        .or_else(|| name.strip_suffix(".tgz"))
        .or_else(|| name.strip_suffix(".whl"))
        .or_else(|| name.strip_suffix(".zip"))
        .unwrap_or(name);
    name.trim()
        .is_empty()
        .then_some("local-source")
        .unwrap_or(name)
        .to_owned()
}
