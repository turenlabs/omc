//! npm publish/pack/unpublish/deprecate compat commands.
//!
//! Argument parsing, path absolutization, package tarball assembly, and output
//! rendering for `npm pack`, `npm publish`, `npm unpublish`, and
//! `npm deprecate`/`npm undeprecate`. Extracted verbatim from `lib.rs`.

use crate::*;

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha512};

use omc_registry::{Ecosystem, OmcRegistryError, PackageSpec};

pub(crate) fn absolutize_npm_pack_action_paths(base_dir: &Path, action: &mut NpmPackAction) {
    action.destination = absolutize_path(base_dir, std::mem::take(&mut action.destination));
    for package in &mut action.packages {
        if let NpmPackInput::Local(path) = package {
            *path = absolutize_path(base_dir, std::mem::take(path));
        }
    }
}

pub(crate) fn absolutize_npm_publish_action_paths(base_dir: &Path, action: &mut NpmPublishAction) {
    action.package = action
        .package
        .take()
        .map(|path| absolutize_path(base_dir, path));
    action.userconfig = action
        .userconfig
        .take()
        .map(|path| absolutize_path(base_dir, path));
    if let NpmPublishProvenance::File(path) = &mut action.provenance {
        *path = absolutize_path(base_dir, std::mem::take(path));
    }
}

pub(crate) fn absolutize_npm_unpublish_action_paths(base_dir: &Path, action: &mut NpmUnpublishAction) {
    absolutize_optional_path(base_dir, &mut action.userconfig);
}

pub(crate) fn absolutize_npm_deprecate_action_paths(base_dir: &Path, action: &mut NpmDeprecateAction) {
    absolutize_optional_path(base_dir, &mut action.userconfig);
}

pub(crate) fn print_npm_pack(project_dir: &Path, action: NpmPackAction) -> Result<(), OmcRegistryError> {
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

pub(crate) fn print_npm_publish(project_dir: &Path, action: NpmPublishAction) -> Result<(), OmcRegistryError> {
    let mut outputs = Vec::new();
    for source in npm_publish_sources(project_dir, &action)? {
        let mut prepared = prepare_npm_publish_package(&source)?;
        prepared.package.tag = action.tag.clone();
        prepared.package.access = action.access.clone();
        apply_npm_publish_provenance(&mut prepared.package, &action.provenance, action.dry_run)?;
        if npm_manifest_bool_field(&prepared.manifest, "private") && !action.dry_run {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "npm publish refuses private package {}@{}",
                prepared.package.name, prepared.package.version
            )));
        }
        if prepared.package.access.as_deref() == Some("restricted")
            && npm_package_scope(&prepared.package.name).is_none()
        {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm publish --access=restricted requires a scoped package".to_owned(),
            ));
        }

        let registry_override = action
            .npm_registry
            .clone()
            .or_else(|| npm_publish_config_registry(&prepared.manifest));
        if action.dry_run {
            let target = npm_auth_target(
                project_dir,
                registry_override.as_deref(),
                action.userconfig.as_deref(),
                npm_package_scope(&prepared.package.name).as_deref(),
            )?;
            outputs.push(NpmPublishOutput::dry_run(
                prepared.package,
                target.registry,
                prepared.pack.entry_count,
                prepared.pack.unpacked_size,
                &action.provenance,
            ));
        } else {
            let result = publish_npm_package(
                project_dir,
                prepared.package,
                registry_override.as_deref(),
                action.userconfig.as_deref(),
                action.otp.as_deref(),
            )?;
            outputs.push(NpmPublishOutput::published(
                result,
                prepared.pack.entry_count,
                prepared.pack.unpacked_size,
                &action.provenance,
            ));
        }
    }

    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &outputs
                    .into_iter()
                    .map(NpmPublishOutput::into_json)
                    .collect::<Vec<_>>()
            )?
        );
    } else {
        for output in outputs {
            if output.dry_run {
                println!("+ {}@{} (dry-run)", output.name, output.version);
            } else {
                println!("+ {}@{}", output.name, output.version);
            }
        }
    }
    Ok(())
}

pub(crate) fn print_npm_unpublish(
    project_dir: &Path,
    action: NpmUnpublishAction,
) -> Result<(), OmcRegistryError> {
    let mut outputs = Vec::new();
    for target in npm_unpublish_targets(project_dir, &action)? {
        let spec = parse_package_spec(&target.spec, Some(Ecosystem::Npm))?;
        let result = unpublish_npm_package(
            project_dir,
            &spec,
            action.dry_run,
            action.force,
            target.registry.as_deref(),
            action.userconfig.as_deref(),
            action.otp.as_deref(),
        )?;
        outputs.push(result);
    }

    if action.json {
        println!("{}", serde_json::to_string_pretty(&outputs)?);
    } else {
        for output in &outputs {
            print_npm_unpublish_result(output);
        }
    }
    Ok(())
}

fn print_npm_unpublish_result(result: &NpmUnpublishResult) {
    let version = result
        .version
        .as_deref()
        .map(|version| format!("@{version}"))
        .unwrap_or_default();
    let dry_run = if result.dry_run { " (dry-run)" } else { "" };
    println!("- {}{}{dry_run}", result.package, version);
}

#[derive(Debug)]
struct NpmUnpublishTarget {
    spec: String,
    registry: Option<String>,
}

fn npm_unpublish_targets(
    project_dir: &Path,
    action: &NpmUnpublishAction,
) -> Result<Vec<NpmUnpublishTarget>, OmcRegistryError> {
    if let Some(spec) = &action.spec {
        if !action.workspaces.is_empty() || action.all_workspaces {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm unpublish accepts either a package spec or workspace selectors, not both"
                    .to_owned(),
            ));
        }
        return Ok(vec![NpmUnpublishTarget {
            spec: spec.clone(),
            registry: action.npm_registry.clone(),
        }]);
    }

    let targets = npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )?;
    targets
        .into_iter()
        .map(|target| npm_unpublish_target_from_package_json(&target, action))
        .collect()
}

fn npm_unpublish_target_from_package_json(
    target: &Path,
    action: &NpmUnpublishAction,
) -> Result<NpmUnpublishTarget, OmcRegistryError> {
    let manifest = read_npm_pkg_json(&target.join("package.json"))?;
    let name = npm_package_json_name(&manifest)?;
    let version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|version| !version.is_empty());
    let spec = if let Some(version) = version {
        format!("{name}@{version}")
    } else {
        if !action.force {
            return Err(OmcRegistryError::UnsupportedSpec(
                "Refusing to delete entire project.\nRun with --force to do this.".to_owned(),
            ));
        }
        name
    };
    Ok(NpmUnpublishTarget {
        spec,
        registry: action
            .npm_registry
            .clone()
            .or_else(|| npm_publish_config_registry(&manifest)),
    })
}

pub(crate) fn print_npm_deprecate(
    project_dir: &Path,
    action: NpmDeprecateAction,
) -> Result<(), OmcRegistryError> {
    let spec = PackageSpec::parse(&format!("npm:{}", action.spec))?;
    let result = deprecate_npm_package(
        project_dir,
        &spec,
        &action.message,
        action.dry_run,
        action.npm_registry.as_deref(),
        action.userconfig.as_deref(),
        action.otp.as_deref(),
    )?;
    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&npm_deprecate_json(&result))?
        );
    } else if result.versions.is_empty() {
        println!(
            "No versions matched {}@{}",
            result.package, result.requirement
        );
    } else {
        let action_name = if action.undeprecate {
            "Undeprecated"
        } else {
            "Deprecated"
        };
        let dry_run = if result.dry_run { " (dry-run)" } else { "" };
        println!(
            "{action_name} {}@{}: {}{dry_run}",
            result.package,
            result.requirement,
            result.versions.join(", ")
        );
    }
    Ok(())
}

fn npm_deprecate_json(result: &NpmDeprecateResult) -> serde_json::Value {
    serde_json::json!({
        "registry": result.registry,
        "package": result.package,
        "requirement": result.requirement,
        "message": result.message,
        "versions": result.versions,
        "dryRun": result.dry_run,
        "status": result.status,
        "response": result.response,
    })
}

fn npm_publish_sources(
    project_dir: &Path,
    action: &NpmPublishAction,
) -> Result<Vec<NpmPublishSource>, OmcRegistryError> {
    if let Some(package) = &action.package {
        if !action.workspaces.is_empty() || action.all_workspaces {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm publish accepts either a package path or workspace selectors, not both"
                    .to_owned(),
            ));
        }
        return Ok(vec![npm_publish_source_from_path(project_dir, package)?]);
    }

    let targets = npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )?;
    Ok(targets
        .into_iter()
        .map(NpmPublishSource::Directory)
        .collect())
}

fn npm_publish_source_from_path(
    project_dir: &Path,
    path: &Path,
) -> Result<NpmPublishSource, OmcRegistryError> {
    let path = absolutize_path(project_dir, path.to_path_buf());
    if path.is_dir() {
        Ok(NpmPublishSource::Directory(path))
    } else if path.is_file() && npm_publish_tarball_path(&path) {
        Ok(NpmPublishSource::Tarball(path))
    } else {
        Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm publish supports local package directories and .tgz/.tar.gz tarballs; unsupported package `{}`",
            path.display()
        )))
    }
}

fn npm_publish_tarball_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.ends_with(".tgz") || name.ends_with(".tar.gz"))
        .unwrap_or(false)
}

enum NpmPublishSource {
    Directory(PathBuf),
    Tarball(PathBuf),
}

struct PreparedNpmPublish {
    package: NpmPublishPackage,
    manifest: serde_json::Value,
    pack: NpmPublishPackSummary,
}

struct NpmPublishPackSummary {
    entry_count: usize,
    unpacked_size: u64,
}

#[derive(Debug)]
struct NpmPublishOutput {
    name: String,
    version: String,
    filename: String,
    registry: String,
    tag: String,
    access: Option<String>,
    dry_run: bool,
    status: Option<u16>,
    shasum: Option<String>,
    integrity: Option<String>,
    provenance: Option<String>,
    provenance_file: Option<String>,
    entry_count: usize,
    unpacked_size: u64,
}

impl NpmPublishOutput {
    fn dry_run(
        package: NpmPublishPackage,
        registry: String,
        entry_count: usize,
        unpacked_size: u64,
        provenance: &NpmPublishProvenance,
    ) -> Self {
        Self {
            name: package.name,
            version: package.version,
            filename: package.filename,
            registry,
            tag: package.tag,
            access: package.access,
            dry_run: true,
            status: None,
            shasum: None,
            integrity: None,
            provenance: npm_publish_provenance_json_label(provenance),
            provenance_file: npm_publish_provenance_file_label(provenance),
            entry_count,
            unpacked_size,
        }
    }

    fn published(
        result: NpmPublishResult,
        entry_count: usize,
        unpacked_size: u64,
        provenance: &NpmPublishProvenance,
    ) -> Self {
        Self {
            name: result.name,
            version: result.version,
            filename: result.filename,
            registry: result.registry,
            tag: result.tag,
            access: result.access,
            dry_run: false,
            status: Some(result.status),
            shasum: Some(result.shasum),
            integrity: Some(result.integrity),
            provenance: npm_publish_provenance_json_label(provenance),
            provenance_file: npm_publish_provenance_file_label(provenance),
            entry_count,
            unpacked_size,
        }
    }

    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "version": self.version,
            "filename": self.filename,
            "registry": self.registry,
            "tag": self.tag,
            "access": self.access,
            "dryRun": self.dry_run,
            "status": self.status,
            "shasum": self.shasum,
            "integrity": self.integrity,
            "provenance": self.provenance,
            "provenanceFile": self.provenance_file,
            "entryCount": self.entry_count,
            "unpackedSize": self.unpacked_size,
        })
    }
}

fn apply_npm_publish_provenance(
    package: &mut NpmPublishPackage,
    provenance: &NpmPublishProvenance,
    dry_run: bool,
) -> Result<(), OmcRegistryError> {
    match provenance {
        NpmPublishProvenance::None => Ok(()),
        NpmPublishProvenance::Generate if dry_run => Ok(()),
        NpmPublishProvenance::Generate => Err(OmcRegistryError::UnsupportedSpec(
            "npm publish --provenance generation is not implemented; use --provenance-file with a Sigstore bundle".to_owned(),
        )),
        NpmPublishProvenance::File(path) => {
            package.provenance = Some(read_npm_provenance_bundle(path, &package.tarball)?);
            Ok(())
        }
    }
}

fn read_npm_provenance_bundle(
    path: &Path,
    tarball: &[u8],
) -> Result<NpmProvenanceBundle, OmcRegistryError> {
    // batou:ignore file_read -- CLI tool: `path` is the user-supplied `npm publish --provenance-file` argument; reading it is the feature's purpose.
    let data = fs::read_to_string(path)?;
    let bundle: serde_json::Value = serde_json::from_str(&data)?;
    let media_type = bundle
        .get("mediaType")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm provenance file `{}` must contain a non-empty mediaType",
                path.display()
            ))
        })?
        .to_owned();
    let payload = bundle
        .pointer("/dsseEnvelope/payload")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm provenance file `{}` must contain a DSSE payload",
                path.display()
            ))
        })?;
    verify_npm_provenance_subject(path, payload, tarball)?;
    Ok(NpmProvenanceBundle { media_type, data })
}

fn verify_npm_provenance_subject(
    path: &Path,
    payload: &str,
    tarball: &[u8],
) -> Result<(), OmcRegistryError> {
    let decoded = BASE64_STANDARD.decode(payload).map_err(|error| {
        OmcRegistryError::UnsupportedSpec(format!(
            "npm provenance file `{}` has an invalid DSSE payload: {error}",
            path.display()
        ))
    })?;
    let statement: serde_json::Value = serde_json::from_slice(&decoded)?;
    let expected = sha512_hex(tarball);
    let subject_matches = statement
        .get("subject")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .any(|subject| {
            subject
                .pointer("/digest/sha512")
                .and_then(serde_json::Value::as_str)
                == Some(expected.as_str())
        });
    if !subject_matches {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm provenance file `{}` does not contain a subject sha512 matching the package tarball",
            path.display()
        )));
    }
    Ok(())
}

fn npm_publish_provenance_json_label(provenance: &NpmPublishProvenance) -> Option<String> {
    match provenance {
        NpmPublishProvenance::None => None,
        NpmPublishProvenance::Generate => Some("generate".to_owned()),
        NpmPublishProvenance::File(_) => Some("file".to_owned()),
    }
}

fn npm_publish_provenance_file_label(provenance: &NpmPublishProvenance) -> Option<String> {
    match provenance {
        NpmPublishProvenance::File(path) => Some(path.display().to_string()),
        NpmPublishProvenance::None | NpmPublishProvenance::Generate => None,
    }
}

pub(crate) fn sha512_hex(bytes: &[u8]) -> String {
    let mut digest = Sha512::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn prepare_npm_publish_package(
    source: &NpmPublishSource,
) -> Result<PreparedNpmPublish, OmcRegistryError> {
    match source {
        NpmPublishSource::Directory(root) => {
            let (pack, manifest, tarball) = npm_pack_package_for_publish(root)?;
            let tag = "latest".to_owned();
            let access = None;
            Ok(prepared_npm_publish_from_parts(
                manifest,
                pack.filename,
                tarball,
                tag,
                access,
                pack.files.len(),
                pack.unpacked_size,
            )?)
        }
        NpmPublishSource::Tarball(path) => {
            let tarball = fs::read(path)?;
            let manifest = npm_manifest_from_tarball(&tarball)?;
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("package.tgz")
                .to_owned();
            let files = npm_packed_files_from_tarball(&tarball)?;
            let unpacked_size = files.iter().map(|file| file.size).sum();
            Ok(prepared_npm_publish_from_parts(
                manifest,
                filename,
                tarball,
                "latest".to_owned(),
                None,
                files.len(),
                unpacked_size,
            )?)
        }
    }
}

fn prepared_npm_publish_from_parts(
    manifest: serde_json::Value,
    filename: String,
    tarball: Vec<u8>,
    tag: String,
    access: Option<String>,
    entry_count: usize,
    unpacked_size: u64,
) -> Result<PreparedNpmPublish, OmcRegistryError> {
    let name = npm_package_json_name(&manifest)?;
    let version = npm_package_json_version(&manifest)?;
    Ok(PreparedNpmPublish {
        package: NpmPublishPackage {
            name,
            version,
            manifest: manifest.clone(),
            filename,
            tarball,
            tag,
            access,
            provenance: None,
        },
        manifest,
        pack: NpmPublishPackSummary {
            entry_count,
            unpacked_size,
        },
    })
}

pub(crate) fn npm_pack_package_for_publish(
    root: &Path,
) -> Result<(NpmPackResult, serde_json::Value, Vec<u8>), OmcRegistryError> {
    if !root.is_dir() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm publish local path `{}` is not a directory",
            root.display()
        )));
    }
    let package_json = root.join("package.json");
    let package = read_npm_pkg_json(&package_json)?;
    let name = npm_package_json_name(&package)?;
    let version = npm_package_json_version(&package)?;
    let filename = npm_pack_filename(&name, &version);
    let files = collect_npm_pack_files(root)?;
    if files.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm publish local path `{}` has no files",
            root.display()
        )));
    }
    let tarball = npm_pack_tarball_bytes(&files)?;
    let unpacked_size = files.iter().map(|file| file.size).sum();
    let result = NpmPackResult {
        id: format!("{name}@{version}"),
        name,
        version,
        filename,
        size: tarball.len() as u64,
        unpacked_size,
        files: files
            .into_iter()
            .map(|file| NpmPackedFile {
                path: file.relative_path,
                size: file.size,
            })
            .collect(),
    };
    Ok((result, package, tarball))
}

fn npm_publish_config_registry(manifest: &serde_json::Value) -> Option<String> {
    manifest
        .get("publishConfig")
        .and_then(|value| value.get("registry"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn npm_manifest_bool_field(manifest: &serde_json::Value, field: &str) -> bool {
    manifest
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn npm_package_scope(name: &str) -> Option<String> {
    name.strip_prefix('@')
        .and_then(|rest| rest.split_once('/'))
        .map(|(scope, _)| format!("@{scope}"))
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
pub(crate) struct NpmPackResult {
    id: String,
    pub(crate) name: String,
    pub(crate) version: String,
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
pub(crate) struct NpmPackSourceFile {
    source: PathBuf,
    relative_path: String,
    archive_path: String,
    size: u64,
}

pub(crate) fn collect_npm_pack_files(root: &Path) -> Result<Vec<NpmPackSourceFile>, OmcRegistryError> {
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

pub(crate) fn write_npm_pack_tarball(
    tarball: &Path,
    files: &[NpmPackSourceFile],
) -> Result<(), OmcRegistryError> {
    fs::write(tarball, npm_pack_tarball_bytes(files)?)?;
    Ok(())
}

fn npm_pack_tarball_bytes(files: &[NpmPackSourceFile]) -> Result<Vec<u8>, OmcRegistryError> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
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
    Ok(encoder.finish()?)
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

pub(crate) fn parse_npm_pack_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
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

pub(crate) fn parse_npm_publish_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut package = None;
    let mut tag = "latest".to_owned();
    let mut access = None;
    let mut provenance = NpmPublishProvenance::None;
    let mut dry_run = false;
    let mut json = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
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
        } else if matches!(arg.as_str(), "--dry-run" | "--dry-run=true") {
            dry_run = true;
        } else if arg == "--dry-run=false" {
            dry_run = false;
        } else if arg == "--tag" {
            index += 1;
            tag = npm_publish_flag_value(args, index, arg)?;
        } else if let Some(value) = arg.strip_prefix("--tag=") {
            tag = value.to_owned();
        } else if arg == "--access" {
            index += 1;
            access = Some(parse_npm_publish_access(&npm_publish_flag_value(
                args, index, arg,
            )?)?);
        } else if let Some(value) = arg.strip_prefix("--access=") {
            access = Some(parse_npm_publish_access(value)?);
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_publish_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--workspace" | "-w") {
            index += 1;
            workspaces.push(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg
            .strip_prefix("--workspace=")
            .or_else(|| arg.strip_prefix("-w="))
        {
            workspaces.push(value.to_owned());
        } else if let Some(value) = npm_all_workspaces_flag_value(arg) {
            all_workspaces = value;
        } else if let Some(value) = npm_include_workspace_root_flag_value(arg) {
            include_workspace_root = value;
        } else if matches!(arg.as_str(), "--provenance" | "--provenance=true") {
            provenance = NpmPublishProvenance::Generate;
        } else if matches!(arg.as_str(), "--no-provenance" | "--provenance=false") {
            provenance = NpmPublishProvenance::None;
        } else if arg == "--provenance-file" {
            index += 1;
            provenance = NpmPublishProvenance::File(PathBuf::from(npm_publish_flag_value(
                args, index, arg,
            )?));
        } else if let Some(value) = arg.strip_prefix("--provenance-file=") {
            provenance = NpmPublishProvenance::File(PathBuf::from(value));
        } else if matches!(
            arg.as_str(),
            "--silent" | "-s" | "--ignore-scripts" | "--foreground-scripts"
        ) {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache" | "--registry") {
            index += 1;
            let _ = npm_publish_flag_value(args, index, arg)?;
        } else if npm_publish_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm publish", arg));
        } else if package.is_none() {
            package = Some(PathBuf::from(arg));
        } else {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm publish accepts at most one package path".to_owned(),
            ));
        }
        index += 1;
    }

    if tag.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm publish --tag cannot be empty".to_owned(),
        ));
    }

    Ok(NpmCompatAction::Publish {
        action: NpmPublishAction {
            package,
            tag,
            access,
            provenance,
            dry_run,
            json,
            npm_registry,
            userconfig,
            otp,
            workspaces,
            all_workspaces,
            include_workspace_root,
        },
    })
}

pub(crate) fn parse_npm_unpublish_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut spec = None;
    let mut dry_run = false;
    let mut force = false;
    let mut json = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
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
        } else if matches!(arg.as_str(), "--dry-run" | "--dry-run=true") {
            dry_run = true;
        } else if arg == "--dry-run=false" {
            dry_run = false;
        } else if matches!(arg.as_str(), "--force" | "-f" | "--force=true") {
            force = true;
        } else if arg == "--force=false" {
            force = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_publish_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--workspace" | "-w") {
            index += 1;
            workspaces.push(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg
            .strip_prefix("--workspace=")
            .or_else(|| arg.strip_prefix("-w="))
        {
            workspaces.push(value.to_owned());
        } else if let Some(value) = npm_all_workspaces_flag_value(arg) {
            all_workspaces = value;
        } else if let Some(value) = npm_include_workspace_root_flag_value(arg) {
            include_workspace_root = value;
        } else if matches!(arg.as_str(), "--silent" | "-s") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            let _ = npm_publish_flag_value(args, index, arg)?;
        } else if npm_unpublish_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm unpublish", arg));
        } else if spec.is_none() {
            spec = Some(arg.clone());
        } else {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm unpublish accepts at most one package spec".to_owned(),
            ));
        }
        index += 1;
    }

    Ok(NpmCompatAction::Unpublish {
        action: NpmUnpublishAction {
            spec,
            dry_run,
            force,
            json,
            npm_registry,
            userconfig,
            otp,
            workspaces,
            all_workspaces,
            include_workspace_root,
        },
    })
}

fn npm_unpublish_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache=", "--include-workspace-root="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn npm_publish_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

fn parse_npm_publish_access(value: &str) -> Result<String, OmcRegistryError> {
    match value {
        "public" | "restricted" => Ok(value.to_owned()),
        _ => Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm publish --access must be public or restricted, got `{value}`"
        ))),
    }
}

fn npm_publish_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn parse_npm_deprecate_args(
    undeprecate: bool,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut dry_run = false;
    let mut json = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--dry-run" | "--dry-run=true") {
            dry_run = true;
        } else if arg == "--dry-run=false" {
            dry_run = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_publish_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_publish_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(
            arg.as_str(),
            "--silent" | "-s" | "--ignore-scripts" | "--foreground-scripts"
        ) {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            let _ = npm_publish_flag_value(args, index, arg)?;
        } else if npm_deprecate_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            let command = if undeprecate {
                "npm undeprecate"
            } else {
                "npm deprecate"
            };
            return Err(unsupported_compat_arg(command, arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    let spec = positionals.first().cloned().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!(
            "{} needs a package spec",
            if undeprecate {
                "npm undeprecate"
            } else {
                "npm deprecate"
            }
        ))
    })?;
    let message = if undeprecate {
        if positionals.len() > 1 {
            return Err(unsupported_compat_arg("npm undeprecate", &positionals[1]));
        }
        String::new()
    } else {
        let Some(message) = positionals.get(1).cloned() else {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm deprecate needs a deprecation message".to_owned(),
            ));
        };
        if positionals.len() > 2 {
            return Err(unsupported_compat_arg("npm deprecate", &positionals[2]));
        }
        message
    };

    Ok(NpmCompatAction::Deprecate {
        action: NpmDeprecateAction {
            spec,
            message,
            dry_run,
            json,
            npm_registry,
            userconfig,
            otp,
            undeprecate,
        },
    })
}

fn npm_deprecate_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}
