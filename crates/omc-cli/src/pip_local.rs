//! pip local-path / cache handling: local-directory wheel building,
//! `pip cache` listing/info, and editable local-path package discovery.
//! Moved out of pip_cli.rs (module split).

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use omc_registry::{Ecosystem, OmcRegistryError, PackageSpec, PythonLocalRequirement};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipLocalWheelMetadata {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) requires_dist: Vec<String>,
    pub(crate) entry_points: Vec<PipLocalWheelEntryPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PipLocalWheelEntryPoint {
    group: String,
    name: String,
    target: String,
}

pub(crate) enum PipLocalWheelDependencySource {
    Local(PythonLocalRequirement),
    Skipped,
    Other,
}

pub(crate) fn build_pip_local_wheels(
    project_dir: &Path,
    destination: &Path,
    requirements: &[PythonLocalRequirement],
    include_dependencies: bool,
) -> Result<(), OmcRegistryError> {
    let mut built = 0usize;
    let mut seen = BTreeSet::new();
    for requirement in requirements {
        let package_dir = resolve_pip_local_wheel_path(project_dir, requirement)?;
        if !seen.insert(package_dir.clone()) {
            continue;
        }

        let mut metadata = read_pip_local_wheel_metadata(&package_dir, &requirement.extras)?;
        if !include_dependencies {
            metadata.requires_dist.clear();
        }
        let filename = pip_local_wheel_filename(&metadata);
        let target = destination.join(filename);
        write_pip_local_wheel(&package_dir, &metadata, &target)?;
        println!("Created {}", target.display());
        built += 1;
    }
    println!("Successfully built {built} local wheel(s)");
    Ok(())
}

pub(crate) fn collect_pip_local_wheel_dependencies(
    project_dir: &Path,
    requirements: &mut Vec<PythonLocalRequirement>,
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    let mut specs = Vec::new();
    let mut seen_paths = BTreeSet::new();
    let mut seen_specs = BTreeSet::new();
    let mut index = 0;
    while index < requirements.len() {
        let requirement = requirements[index].clone();
        index += 1;
        let package_dir = resolve_pip_local_wheel_path(project_dir, &requirement)?;
        if !seen_paths.insert((package_dir.clone(), requirement.extras.clone())) {
            continue;
        }

        let metadata = read_pip_local_wheel_metadata(&package_dir, &requirement.extras)?;
        for dependency in metadata.requires_dist {
            match pip_local_wheel_dependency_source(&dependency, &requirement.extras, &package_dir)?
            {
                PipLocalWheelDependencySource::Local(local_requirement) => {
                    requirements.push(local_requirement);
                }
                PipLocalWheelDependencySource::Skipped => {}
                PipLocalWheelDependencySource::Other => {
                    let spec = parse_package_spec(&dependency, Some(Ecosystem::Pypi))?;
                    if seen_specs.insert(spec.requested()) {
                        specs.push(spec);
                    }
                }
            }
        }
    }
    Ok(specs)
}

pub(crate) fn pip_local_wheel_dependency_source(
    dependency: &str,
    active_extras: &BTreeSet<String>,
    base_dir: &Path,
) -> Result<PipLocalWheelDependencySource, OmcRegistryError> {
    let mut parts = dependency.splitn(2, ';');
    let requirement = parts.next().unwrap_or_default().trim();
    if let Some(marker) = parts.next() {
        if !pypi_marker_applies(marker, active_extras) {
            return Ok(PipLocalWheelDependencySource::Skipped);
        }
    }

    let Some((name, source)) = requirement.split_once(" @ ") else {
        return Ok(PipLocalWheelDependencySource::Other);
    };
    let (_, extras) = pip_local_path_and_extras(name.trim());
    let source = source
        .trim()
        .split_once('#')
        .map(|(source, _)| source)
        .unwrap_or_else(|| source.trim());
    if source.is_empty() || source.starts_with("git+") || is_pip_archive_arg(source) {
        return Ok(PipLocalWheelDependencySource::Other);
    }

    let path = if source.contains("://") {
        let Ok(url) = reqwest::Url::parse(source) else {
            return Ok(PipLocalWheelDependencySource::Other);
        };
        if url.scheme() != "file" {
            return Ok(PipLocalWheelDependencySource::Other);
        }
        url.to_file_path().map_err(|_| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "local wheel dependency `{dependency}` uses an invalid file URL"
            ))
        })?
    } else {
        let source = source
            .strip_prefix("file:")
            .or_else(|| source.strip_prefix("link:"))
            .unwrap_or(source);
        let path = PathBuf::from(source);
        if path.is_absolute() {
            path
        } else {
            base_dir.join(path)
        }
    };

    if !path.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "local wheel dependency `{dependency}` must point to an existing directory"
        )));
    }
    Ok(PipLocalWheelDependencySource::Local(
        PythonLocalRequirement::new(path, extras),
    ))
}

pub(crate) fn resolve_pip_local_wheel_path(
    project_dir: &Path,
    requirement: &PythonLocalRequirement,
) -> Result<PathBuf, OmcRegistryError> {
    let package_dir = absolutize_path(project_dir, requirement.path.clone());
    let package_dir = fs::canonicalize(&package_dir).map_err(|error| {
        OmcRegistryError::UnsupportedRequirement(format!(
            "local wheel path `{}` could not be resolved: {error}",
            requirement.path.display()
        ))
    })?;
    if !package_dir.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "local wheel path `{}` must be a directory",
            package_dir.display()
        )));
    }
    Ok(package_dir)
}

pub(crate) fn read_pip_local_wheel_metadata(
    package_dir: &Path,
    extras: &BTreeSet<String>,
) -> Result<PipLocalWheelMetadata, OmcRegistryError> {
    if let Some(metadata) = read_pyproject_wheel_metadata(package_dir, extras)? {
        return Ok(metadata);
    }
    if let Some(metadata) = read_setup_cfg_wheel_metadata(package_dir, extras)? {
        return Ok(metadata);
    }
    Err(OmcRegistryError::UnsupportedRequirement(format!(
        "local wheel path `{}` must declare static name and version in pyproject.toml or setup.cfg",
        package_dir.display()
    )))
}

pub(crate) fn parse_pip_local_setup_cfg(
    content: &str,
) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut sections = BTreeMap::<String, BTreeMap<String, Vec<String>>>::new();
    let mut section = String::new();
    let mut key = None::<String>;
    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            key = None;
            sections.entry(section.clone()).or_default();
            continue;
        }
        if section.is_empty() {
            continue;
        }
        if let Some((parsed_key, value)) = setup_cfg_assignment(trimmed) {
            let parsed_key = parsed_key.to_ascii_lowercase();
            key = Some(parsed_key.clone());
            if !value.trim().is_empty() {
                sections
                    .entry(section.clone())
                    .or_default()
                    .entry(parsed_key)
                    .or_default()
                    .push(value.trim().to_owned());
            } else {
                sections
                    .entry(section.clone())
                    .or_default()
                    .entry(parsed_key)
                    .or_default();
            }
            continue;
        }
        if raw.chars().next().map(char::is_whitespace).unwrap_or(false) {
            if let Some(key) = key.as_ref() {
                sections
                    .entry(section.clone())
                    .or_default()
                    .entry(key.clone())
                    .or_default()
                    .push(trimmed.to_owned());
            }
        }
    }
    sections
}

pub(crate) fn pip_local_entry_point(group: &str, value: &str) -> Option<PipLocalWheelEntryPoint> {
    let (name, target) = value.split_once('=')?;
    pip_local_script_entry(group, name.trim(), target.trim())
}

pub(crate) fn pip_local_script_entry(
    group: &str,
    name: &str,
    target: &str,
) -> Option<PipLocalWheelEntryPoint> {
    (!name.is_empty() && !target.is_empty()).then(|| PipLocalWheelEntryPoint {
        group: group.to_owned(),
        name: name.to_owned(),
        target: target.to_owned(),
    })
}

pub(crate) fn pip_local_wheel_filename(metadata: &PipLocalWheelMetadata) -> String {
    format!(
        "{}-{}-py3-none-any.whl",
        python_wheel_component(&metadata.name),
        python_wheel_version_component(&metadata.version)
    )
}

pub(crate) fn write_pip_local_wheel(
    package_dir: &Path,
    metadata: &PipLocalWheelMetadata,
    target: &Path,
) -> Result<(), OmcRegistryError> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::File::create(target)?;
    let mut archive = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let import_root = pip_local_wheel_import_root(package_dir);
    let mut record_paths = Vec::new();

    for (archive_path, source) in pip_local_wheel_source_files(&import_root)? {
        let bytes = fs::read(source)?;
        write_wheel_file(&mut archive, &archive_path, &bytes, options)?;
        record_paths.push(archive_path);
    }

    let dist_info = format!(
        "{}-{}.dist-info",
        python_wheel_component(&metadata.name),
        python_wheel_version_component(&metadata.version)
    );
    let metadata_path = format!("{dist_info}/METADATA");
    let metadata_content = pip_local_wheel_metadata_content(package_dir, metadata)?;
    write_wheel_file(
        &mut archive,
        &metadata_path,
        metadata_content.as_bytes(),
        options,
    )?;
    record_paths.push(metadata_path);

    let wheel_path = format!("{dist_info}/WHEEL");
    write_wheel_file(
        &mut archive,
        &wheel_path,
        b"Wheel-Version: 1.0\nGenerator: omc\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        options,
    )?;
    record_paths.push(wheel_path);

    if !metadata.entry_points.is_empty() {
        let entry_points_path = format!("{dist_info}/entry_points.txt");
        write_wheel_file(
            &mut archive,
            &entry_points_path,
            pip_local_wheel_entry_points_content(&metadata.entry_points).as_bytes(),
            options,
        )?;
        record_paths.push(entry_points_path);
    }

    let record_path = format!("{dist_info}/RECORD");
    record_paths.sort();
    let mut record = record_paths
        .iter()
        .map(|path| format!("{path},,\n"))
        .collect::<String>();
    record.push_str(&format!("{record_path},,\n"));
    write_wheel_file(&mut archive, &record_path, record.as_bytes(), options)?;
    archive.finish()?;
    Ok(())
}

pub(crate) fn pip_local_wheel_import_root(package_dir: &Path) -> PathBuf {
    let src = package_dir.join("src");
    if src.is_dir() {
        src
    } else {
        package_dir.to_path_buf()
    }
}

pub(crate) fn pip_local_wheel_source_files(
    import_root: &Path,
) -> Result<Vec<(String, PathBuf)>, OmcRegistryError> {
    let mut files = Vec::new();
    collect_pip_local_wheel_source_files(import_root, import_root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

pub(crate) fn collect_pip_local_wheel_source_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), OmcRegistryError> {
    let mut entries = fs::read_dir(current)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if file_type.is_dir() {
            if pip_local_wheel_skip_dir(&name) {
                continue;
            }
            collect_pip_local_wheel_source_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            if !pip_local_wheel_include_file(relative) {
                continue;
            }
            files.push((wheel_archive_path(relative)?, path));
        }
    }
    Ok(())
}

pub(crate) fn pip_local_wheel_skip_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(
            name,
            "__pycache__" | "build" | "dist" | "venv" | ".venv" | ".omc"
        )
        || name.ends_with(".egg-info")
        || name.ends_with(".dist-info")
}

pub(crate) fn pip_local_wheel_include_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name.ends_with(".pyc")
        || name == "pyproject.toml"
        || name == "setup.cfg"
        || name == "setup.py"
    {
        return false;
    }
    true
}

pub(crate) fn pip_local_wheel_metadata_content(
    package_dir: &Path,
    metadata: &PipLocalWheelMetadata,
) -> Result<String, OmcRegistryError> {
    let mut content = format!(
        "Metadata-Version: 2.1\nName: {}\nVersion: {}\n",
        metadata.name, metadata.version
    );
    for requirement in &metadata.requires_dist {
        if let Some(requirement) = pip_local_wheel_metadata_requirement(package_dir, requirement)? {
            content.push_str("Requires-Dist: ");
            content.push_str(&requirement);
            content.push('\n');
        }
    }
    Ok(content)
}

pub(crate) fn pip_local_wheel_metadata_requirement(
    package_dir: &Path,
    requirement: &str,
) -> Result<Option<String>, OmcRegistryError> {
    match pip_local_wheel_dependency_source(requirement, &BTreeSet::new(), package_dir)? {
        PipLocalWheelDependencySource::Skipped => Ok(None),
        PipLocalWheelDependencySource::Other => Ok(Some(requirement.to_owned())),
        PipLocalWheelDependencySource::Local(local_requirement) => {
            let dependency_dir = fs::canonicalize(&local_requirement.path).map_err(|error| {
                OmcRegistryError::UnsupportedRequirement(format!(
                    "local wheel dependency `{}` could not be resolved: {error}",
                    local_requirement.path.display()
                ))
            })?;
            let dependency_metadata =
                read_pip_local_wheel_metadata(&dependency_dir, &local_requirement.extras)?;
            Ok(Some(pip_local_wheel_pinned_requirement(
                &dependency_metadata,
                &local_requirement.extras,
            )))
        }
    }
}

pub(crate) fn pip_local_wheel_pinned_requirement(
    metadata: &PipLocalWheelMetadata,
    extras: &BTreeSet<String>,
) -> String {
    let name = if extras.is_empty() {
        metadata.name.clone()
    } else {
        format!(
            "{}[{}]",
            metadata.name,
            extras.iter().cloned().collect::<Vec<_>>().join(",")
        )
    };
    format!("{name}=={}", metadata.version)
}

pub(crate) fn pip_local_wheel_entry_points_content(
    entry_points: &[PipLocalWheelEntryPoint],
) -> String {
    let mut by_group = BTreeMap::<String, Vec<&PipLocalWheelEntryPoint>>::new();
    for entry in entry_points {
        by_group.entry(entry.group.clone()).or_default().push(entry);
    }
    let mut content = String::new();
    for (group, mut entries) in by_group {
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        content.push('[');
        content.push_str(&group);
        content.push_str("]\n");
        for entry in entries {
            content.push_str(&entry.name);
            content.push_str(" = ");
            content.push_str(&entry.target);
            content.push('\n');
        }
        content.push('\n');
    }
    content
}

pub(crate) fn pip_cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".omc").join("cache").join("pypi")
}

pub(crate) fn pip_cache_arg_or_env(
    invocation_cwd: &Path,
    cache_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    cache_dir
        .or_else(pip_cache_dir_env)
        .map(|path| absolutize_path(invocation_cwd, path))
}

pub(crate) fn pip_cache_dir_env() -> Option<PathBuf> {
    env_path_from_any(["PIP_CACHE_DIR"])
}

pub(crate) fn pip_cache_list_lines(
    cache_dir: &Path,
    pattern: Option<&str>,
    format: PipCacheListFormat,
) -> Result<Vec<String>, OmcRegistryError> {
    let mut files = compat_cache_files(cache_dir)?;
    if let Some(pattern) = pattern {
        files.retain(|path| compat_cache_pattern_matches(path, cache_dir, pattern));
    }
    files.sort();
    if files.is_empty() && format == PipCacheListFormat::Human {
        return Ok(vec!["Nothing cached.".to_owned()]);
    }
    Ok(files
        .into_iter()
        .map(|path| pip_cache_list_display_path(&path, cache_dir, format))
        .collect())
}

pub(crate) fn pip_cache_info_lines(cache_dir: &Path) -> Result<Vec<String>, OmcRegistryError> {
    let files = compat_cache_files(cache_dir)?;
    let bytes = cache_files_size(&files)?;
    Ok(vec![
        format!(
            "Package index page cache location: {}",
            cache_dir.join("http").display()
        ),
        "Package index page cache size: 0 bytes".to_owned(),
        "Number of HTTP files: 0".to_owned(),
        format!("Wheels location: {}", cache_dir.display()),
        format!("Wheels size: {bytes} bytes"),
        format!("Number of wheels: {}", files.len()),
    ])
}

pub(crate) fn pip_cache_list_display_path(
    path: &Path,
    cache_dir: &Path,
    format: PipCacheListFormat,
) -> String {
    match format {
        PipCacheListFormat::Human => compat_cache_display_path(path, cache_dir),
        PipCacheListFormat::Abspath => path.display().to_string(),
    }
}

pub(crate) fn pip_local_editable_packages_from_file(
    local_paths_file: PathBuf,
    excluded: &BTreeSet<String>,
) -> Result<Vec<InstalledPythonPackage>, OmcRegistryError> {
    let content = match fs::read_to_string(&local_paths_file) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut packages = BTreeMap::new();
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let path = PathBuf::from(line);
        let Some(mut package) = pip_local_editable_package(&path)? else {
            continue;
        };
        package.install_location = pip_local_paths_install_location(&local_paths_file);
        if !pip_name_excluded(&package.name, excluded) {
            packages.insert(normalize_pip_show_name(&package.name), package);
        }
    }
    Ok(packages.into_values().collect())
}

pub(crate) fn pip_local_paths_install_location(local_paths_file: &Path) -> Option<PathBuf> {
    let parent = local_paths_file.parent()?;
    if local_paths_file.file_name().and_then(|name| name.to_str()) == Some("local-paths") {
        return Some(parent.join("site-packages"));
    }
    Some(parent.to_path_buf())
}

pub(crate) fn pip_local_editable_package(
    import_path: &Path,
) -> Result<Option<InstalledPythonPackage>, OmcRegistryError> {
    let project_root = pip_editable_project_root(import_path);
    let Some((name, version)) = read_python_project_identity(&project_root)? else {
        return Ok(None);
    };
    let metadata = read_python_project_show_metadata(&project_root)?;
    Ok(Some(InstalledPythonPackage {
        name,
        version,
        dependencies: if metadata.requires_dist.is_empty() {
            metadata.requires.clone()
        } else {
            metadata.requires_dist
        },
        install_location: None,
        metadata_location: None,
        editable_project_location: Some(import_path.to_path_buf()),
    }))
}
