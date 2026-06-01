//! PyPI wheel/sdist extraction, dependency parsing, and Python entry points.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;
use walkdir::WalkDir;
pub(crate) fn install_pypi_package(
    project_dir: &Path,
    package: &LockedPackage,
    site_packages: &Path,
    bin_dir: &Path,
    overwrite_existing: bool,
    bin_dir_existed: bool,
) -> Result<usize> {
    let archive_path = project_dir.join(&package.archive);
    if archive_path.extension().and_then(|ext| ext.to_str()) == Some("whl") {
        return install_pypi_wheel_package(
            project_dir,
            package,
            site_packages,
            bin_dir,
            overwrite_existing,
            bin_dir_existed,
        );
    }
    if archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(is_python_sdist_filename)
        .unwrap_or(false)
    {
        return install_pypi_sdist_package(
            project_dir,
            package,
            site_packages,
            bin_dir,
            overwrite_existing,
            bin_dir_existed,
        );
    }

    Err(OmcRegistryError::UnsupportedInstallArtifact(
        archive_path.display().to_string(),
    ))
}

pub(crate) fn install_pypi_wheel_package(
    project_dir: &Path,
    package: &LockedPackage,
    site_packages: &Path,
    bin_dir: &Path,
    overwrite_existing: bool,
    bin_dir_existed: bool,
) -> Result<usize> {
    let archive_path = project_dir.join(&package.archive);
    if archive_path.extension().and_then(|ext| ext.to_str()) != Some("whl") {
        return Err(OmcRegistryError::UnsupportedInstallArtifact(
            archive_path.display().to_string(),
        ));
    }

    let reader = Cursor::new(read_locked_archive(project_dir, package)?);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut entry_points = Vec::new();
    if overwrite_existing {
        let targets = wheel_install_top_level_targets(&mut archive)?;
        remove_existing_python_targets(site_packages, &targets)?;
    }
    let existing_top_level = if overwrite_existing {
        BTreeSet::new()
    } else {
        existing_top_level_targets(site_packages)?
    };
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let archive_path = Path::new(file.name());
        // F5: drop Python startup hooks (.pth / sitecustomize / usercustomize)
        // from the wheel so they cannot execute at interpreter startup.
        if is_python_startup_hook_path(archive_path) {
            continue;
        }
        if !overwrite_existing && wheel_path_has_existing_target(archive_path, &existing_top_level)
        {
            continue;
        }
        let output = checked_join(site_packages, archive_path)?;

        if file.is_dir() {
            fs::create_dir_all(output)?;
        } else {
            let name = file.name().to_owned();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(output, &bytes)?;

            if name.ends_with(".dist-info/entry_points.txt") {
                if let Ok(content) = String::from_utf8(bytes) {
                    entry_points.push(content);
                }
            }
        }
    }

    install_python_entry_points(&entry_points, bin_dir, overwrite_existing, bin_dir_existed)
}

pub(crate) fn install_pypi_sdist_package(
    project_dir: &Path,
    package: &LockedPackage,
    site_packages: &Path,
    bin_dir: &Path,
    overwrite_existing: bool,
    bin_dir_existed: bool,
) -> Result<usize> {
    let source_dir = project_dir
        .join(".omc")
        .join("python")
        .join("sdists")
        .join(safe_name(&package.name))
        .join(&package.version);
    remove_path_if_exists(&source_dir)?;
    fs::create_dir_all(&source_dir)?;

    let archive_path = project_dir.join(&package.archive);
    let archive_filename = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| OmcRegistryError::UnsupportedInstallArtifact(package.archive.clone()))?;
    unpack_python_sdist(
        &read_locked_archive(project_dir, package)?,
        archive_filename,
        &source_dir,
    )?;
    let import_root = if source_dir.join("src").is_dir() {
        source_dir.join("src")
    } else {
        source_dir.clone()
    };
    let installed_files =
        copy_python_sdist_import_tree(&import_root, site_packages, overwrite_existing)?;
    write_python_sdist_dist_info(site_packages, package, installed_files)?;
    let entry_points = read_python_local_entry_points(&source_dir)?;
    install_python_entry_point_scripts(&entry_points, bin_dir, overwrite_existing, bin_dir_existed)
}

pub(crate) fn write_python_sdist_dist_info(
    site_packages: &Path,
    package: &LockedPackage,
    mut installed_files: Vec<String>,
) -> Result<()> {
    let dist_info_name = format!(
        "{}-{}.dist-info",
        python_dist_info_component(&package.name),
        package.version
    );
    let dist_info = site_packages.join(&dist_info_name);
    fs::create_dir_all(&dist_info)?;
    let mut metadata = format!(
        "Metadata-Version: 2.1\nName: {}\nVersion: {}\n",
        package.name, package.version
    );
    for dependency in &package.dependencies {
        if let Some(requirement) = python_requires_dist_from_locked_dependency(dependency) {
            metadata.push_str("Requires-Dist: ");
            metadata.push_str(&requirement);
            metadata.push('\n');
        }
    }
    fs::write(dist_info.join("METADATA"), metadata)?;
    fs::write(dist_info.join("INSTALLER"), "omc\n")?;
    installed_files.push(format!("{dist_info_name}/METADATA"));
    installed_files.push(format!("{dist_info_name}/INSTALLER"));
    installed_files.push(format!("{dist_info_name}/RECORD"));
    installed_files.sort();
    let record = installed_files
        .into_iter()
        .map(|file| format!("{file},,\n"))
        .collect::<String>();
    fs::write(dist_info.join("RECORD"), record)?;
    Ok(())
}

pub(crate) fn python_requires_dist_from_locked_dependency(dependency: &str) -> Option<String> {
    let spec = PackageSpec::parse(dependency).ok()?;
    if spec.ecosystem != Ecosystem::Pypi {
        return None;
    }
    let mut name = spec.name;
    if !spec.extras.is_empty() {
        name.push('[');
        name.push_str(&spec.extras.into_iter().collect::<Vec<_>>().join(","));
        name.push(']');
    }
    if let Some(url) = spec.direct_url {
        Some(format!("{name} @ {url}"))
    } else if let Some(version) = spec.version {
        Some(format!("{name}{version}"))
    } else {
        Some(name)
    }
}

pub(crate) fn python_dist_info_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| if matches!(ch, '-' | '.') { '_' } else { ch })
        .collect()
}

pub(crate) fn unpack_python_sdist(bytes: &[u8], filename: &str, target: &Path) -> Result<()> {
    if filename.to_ascii_lowercase().ends_with(".zip") {
        return unpack_python_zip_sdist(bytes, target);
    }
    unpack_python_tar_sdist(bytes, target)
}

pub(crate) fn unpack_python_tar_sdist(bytes: &[u8], target: &Path) -> Result<()> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.to_string_lossy().into_owned();
        if is_ignorable_archive_metadata_path(&raw_path) {
            continue;
        }
        let Some(stripped) = strip_first_path_component(Path::new(&raw_path)) else {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            return Err(OmcRegistryError::UnsafeArchivePath(raw_path));
        };
        let output = checked_join(target, &stripped)?;

        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(output)?;
        } else if entry.header().entry_type().is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            entry.unpack(output)?;
        }
    }
    Ok(())
}

pub(crate) fn unpack_python_zip_sdist(bytes: &[u8], target: &Path) -> Result<()> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let raw_path = file.name().to_owned();
        if is_ignorable_archive_metadata_path(&raw_path) {
            continue;
        }
        let Some(stripped) = strip_first_path_component(Path::new(&raw_path)) else {
            if file.is_dir() {
                continue;
            }
            return Err(OmcRegistryError::UnsafeArchivePath(raw_path));
        };
        let output = checked_join(target, &stripped)?;
        if file.is_dir() {
            fs::create_dir_all(output)?;
        } else {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            fs::write(output, bytes)?;
        }
    }
    Ok(())
}

pub(crate) fn copy_python_sdist_import_tree(
    source: &Path,
    site_packages: &Path,
    overwrite_existing: bool,
) -> Result<Vec<String>> {
    let mut installed_files = Vec::new();
    if overwrite_existing {
        let targets = python_sdist_import_top_level_targets(source)?;
        remove_existing_python_targets(site_packages, &targets)?;
    }
    let existing_top_level = if overwrite_existing {
        BTreeSet::new()
    } else {
        existing_top_level_targets(site_packages)?
    };
    for entry in WalkDir::new(source)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(source).unwrap_or(entry.path());
        if !should_copy_python_sdist_path(relative) {
            continue;
        }
        if !overwrite_existing && sdist_path_has_existing_target(relative, &existing_top_level) {
            continue;
        }
        let output = checked_join(site_packages, relative)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), output)?;
        installed_files.push(relative.to_string_lossy().replace('\\', "/"));
    }
    installed_files.sort();
    Ok(installed_files)
}

pub(crate) fn wheel_install_top_level_targets<R: Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index)?;
        let path = Path::new(file.name());
        let Some(top_level) = top_level_archive_component(path) else {
            continue;
        };
        if !is_python_metadata_dir(top_level) {
            targets.insert(top_level.to_owned());
        }
    }
    Ok(targets)
}

pub(crate) fn python_sdist_import_top_level_targets(source: &Path) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    for entry in WalkDir::new(source)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(source).unwrap_or(entry.path());
        if !should_copy_python_sdist_path(relative) {
            continue;
        }
        if let Some(top_level) = top_level_archive_component(relative) {
            targets.insert(top_level.to_owned());
        }
    }
    Ok(targets)
}

pub(crate) fn remove_existing_python_targets(
    site_packages: &Path,
    targets: &BTreeSet<String>,
) -> Result<()> {
    for target in targets {
        let output = checked_join(site_packages, Path::new(target))?;
        remove_path_if_exists(&output)?;
    }
    Ok(())
}

pub(crate) fn existing_top_level_targets(site_packages: &Path) -> Result<BTreeSet<String>> {
    if !site_packages.exists() {
        return Ok(BTreeSet::new());
    }
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(site_packages)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            paths.insert(name.to_owned());
        }
    }
    Ok(paths)
}

pub(crate) fn wheel_path_has_existing_target(
    path: &Path,
    existing_top_level: &BTreeSet<String>,
) -> bool {
    let Some(top_level) = top_level_archive_component(path) else {
        return false;
    };
    if is_python_metadata_dir(top_level) {
        return false;
    }
    existing_top_level.contains(top_level)
}

pub(crate) fn sdist_path_has_existing_target(
    path: &Path,
    existing_top_level: &BTreeSet<String>,
) -> bool {
    let Some(top_level) = top_level_archive_component(path) else {
        return false;
    };
    existing_top_level.contains(top_level)
}

pub(crate) fn top_level_archive_component(path: &Path) -> Option<&str> {
    path.components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .filter(|component| !component.is_empty())
}

pub(crate) fn is_python_metadata_dir(name: &str) -> bool {
    name.ends_with(".dist-info") || name.ends_with(".egg-info")
}

pub(crate) fn should_copy_python_sdist_path(path: &Path) -> bool {
    // F5: never land Python startup-hook files in site-packages. `.pth` files
    // execute any `import ...` line at interpreter startup, and sitecustomize/
    // usercustomize run automatically — all amount to CPython startup RCE.
    if is_python_startup_hook_path(path) {
        return false;
    }
    let mut components = path.components();
    let Some(first) = components
        .next()
        .and_then(|component| component.as_os_str().to_str())
    else {
        return false;
    };
    if first.ends_with(".egg-info") || first.ends_with(".dist-info") {
        return false;
    }
    if components.next().is_none()
        && matches!(
            first,
            "PKG-INFO" | "pyproject.toml" | "setup.cfg" | "setup.py" | "setup_requires.py"
        )
    {
        return false;
    }
    true
}

/// F5 — true for Python interpreter startup hooks that must never be installed
/// into site-packages: any `*.pth` file (lines are executed at startup) and
/// `sitecustomize.py` / `usercustomize.py` (auto-imported by CPython at start).
pub(crate) fn is_python_startup_hook_path(path: &Path) -> bool {
    let Some(name) = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_ascii_lowercase)
    else {
        return false;
    };
    name.ends_with(".pth") || matches!(name.as_str(), "sitecustomize.py" | "usercustomize.py")
}

pub(crate) fn is_ignorable_archive_metadata_path(path: &str) -> bool {
    Path::new(path).components().any(|component| {
        let Some(name) = component.as_os_str().to_str() else {
            return false;
        };
        name == "__MACOSX" || name == "pax_global_header" || name.starts_with("._")
    })
}

pub(crate) fn pypi_wheel_dependencies(
    bytes: &[u8],
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut dependencies = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if !file.name().ends_with(".dist-info/METADATA") {
            continue;
        }
        let mut metadata = String::new();
        file.read_to_string(&mut metadata)?;
        dependencies.extend(pypi_metadata_dependencies(&metadata, active_extras));
        break;
    }
    Ok(dependencies)
}

pub(crate) fn pypi_sdist_dependencies(
    bytes: &[u8],
    filename: &str,
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    if filename.to_ascii_lowercase().ends_with(".zip") {
        return pypi_zip_sdist_dependencies(bytes, active_extras);
    }
    pypi_tar_sdist_dependencies(bytes, active_extras)
}

pub(crate) fn pypi_tar_sdist_dependencies(
    bytes: &[u8],
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut dependencies = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_BYTES {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        if is_ignorable_archive_metadata_path(&path)
            || !(path.ends_with("/PKG-INFO") || path.ends_with(".dist-info/METADATA"))
        {
            continue;
        }
        let mut metadata = String::new();
        entry.read_to_string(&mut metadata)?;
        dependencies.extend(pypi_metadata_dependencies(&metadata, active_extras));
        if !dependencies.is_empty() {
            break;
        }
    }
    Ok(dependencies)
}

pub(crate) fn pypi_zip_sdist_dependencies(
    bytes: &[u8],
    active_extras: &BTreeSet<String>,
) -> Result<Vec<PackageDependency>> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut dependencies = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if file.is_dir() || file.size() > MAX_FILE_BYTES {
            continue;
        }
        let path = file.name().to_owned();
        if is_ignorable_archive_metadata_path(&path)
            || !(path.ends_with("/PKG-INFO") || path.ends_with(".dist-info/METADATA"))
        {
            continue;
        }
        let mut metadata = String::new();
        file.read_to_string(&mut metadata)?;
        dependencies.extend(pypi_metadata_dependencies(&metadata, active_extras));
        if !dependencies.is_empty() {
            break;
        }
    }
    Ok(dependencies)
}

pub(crate) fn pypi_metadata_dependencies(
    metadata: &str,
    active_extras: &BTreeSet<String>,
) -> Vec<PackageDependency> {
    folded_metadata_lines(metadata)
        .into_iter()
        .filter_map(|line| {
            let requirement = line.strip_prefix("Requires-Dist:")?;
            parse_pypi_requirement_with_extras(requirement.trim(), active_extras).map(|spec| {
                PackageDependency {
                    spec,
                    optional: false,
                    peer: false,
                }
            })
        })
        .collect()
}

pub(crate) fn folded_metadata_lines(metadata: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in metadata.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(previous) = lines.last_mut() {
                previous.push(' ');
                previous.push_str(line.trim());
            }
        } else {
            lines.push(line.to_owned());
        }
    }
    lines
}

pub(crate) fn install_python_entry_points(
    entry_points: &[String],
    bin_dir: &Path,
    overwrite_existing: bool,
    bin_dir_existed: bool,
) -> Result<usize> {
    let entries = entry_points
        .iter()
        .flat_map(|content| parse_python_entry_points(content))
        .collect::<Vec<_>>();
    install_python_entry_point_scripts(&entries, bin_dir, overwrite_existing, bin_dir_existed)
}

pub(crate) fn install_python_entry_point_scripts(
    entry_points: &[PythonEntryPoint],
    bin_dir: &Path,
    overwrite_existing: bool,
    bin_dir_existed: bool,
) -> Result<usize> {
    if !overwrite_existing && bin_dir_existed {
        return Ok(0);
    }
    fs::create_dir_all(bin_dir)?;
    let mut installed = 0;

    for entry in entry_points {
        if !is_safe_script_name(&entry.name) {
            continue;
        }
        let target = bin_dir.join(&entry.name);
        if !overwrite_existing && target.exists() {
            continue;
        }
        remove_path_if_exists(&target)?;
        fs::write(&target, python_entry_point_script(entry))?;
        make_executable(&target)?;
        installed += 1;
    }

    Ok(installed)
}

pub(crate) fn read_python_local_entry_points(package_dir: &Path) -> Result<Vec<PythonEntryPoint>> {
    let mut entries = Vec::new();

    let pyproject = package_dir.join("pyproject.toml");
    if pyproject.exists() {
        let pyproject = toml::from_str::<PyProjectToml>(&fs::read_to_string(pyproject)?)?;
        if let Some(project) = pyproject.project {
            collect_python_script_entries(project.scripts, &mut entries);
            collect_python_script_entries(project.gui_scripts, &mut entries);
        }
        if let Some(poetry) = pyproject.tool.and_then(|tool| tool.poetry) {
            collect_poetry_script_entries(poetry.scripts, &mut entries);
        }
    }

    let setup_cfg = package_dir.join("setup.cfg");
    if setup_cfg.exists() {
        entries.extend(read_setup_cfg_entry_points(&setup_cfg)?);
    }

    let setup_py = package_dir.join("setup.py");
    if setup_py.exists() {
        entries.extend(read_setup_py_entry_points(&setup_py)?);
    }

    Ok(entries)
}

pub(crate) fn read_setup_cfg_entry_points(path: &Path) -> Result<Vec<PythonEntryPoint>> {
    Ok(parse_setup_cfg_entry_points(&fs::read_to_string(path)?))
}

pub(crate) fn read_setup_py_entry_points(path: &Path) -> Result<Vec<PythonEntryPoint>> {
    Ok(parse_setup_py_entry_points(&fs::read_to_string(path)?))
}

pub(crate) fn parse_setup_py_entry_points(content: &str) -> Vec<PythonEntryPoint> {
    let selected_groups = BTreeSet::from(["console-scripts".to_owned(), "gui-scripts".to_owned()]);
    let mut entries = Vec::new();

    for value in python_keyword_assignment_values(content, "entry_points") {
        entries.extend(
            python_string_dict_values(value, &selected_groups)
                .into_iter()
                .filter_map(|line| python_entry_point_from_assignment(&line)),
        );
        for entry_points_ini in python_string_literals(value) {
            entries.extend(parse_python_entry_points(&entry_points_ini));
        }
    }

    entries
}

pub(crate) fn parse_setup_cfg_entry_points(content: &str) -> Vec<PythonEntryPoint> {
    let mut in_entry_points = false;
    let mut in_supported_group = false;
    let mut entries = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_entry_points = line[1..line.len() - 1]
                .trim()
                .eq_ignore_ascii_case("options.entry_points");
            in_supported_group = false;
            continue;
        }
        if !in_entry_points {
            continue;
        }

        if let Some((key, value)) = setup_cfg_key_value(line) {
            if matches!(key.as_str(), "console_scripts" | "gui_scripts") {
                in_supported_group = true;
                if let Some(entry) = python_entry_point_from_assignment(value) {
                    entries.push(entry);
                }
                continue;
            }
        }

        let is_continuation = raw_line
            .chars()
            .next()
            .map(char::is_whitespace)
            .unwrap_or(false);
        if !in_supported_group || !is_continuation {
            continue;
        }
        if let Some(entry) = python_entry_point_from_assignment(line) {
            entries.push(entry);
        }
    }

    entries
}

pub(crate) fn collect_python_script_entries(
    scripts: BTreeMap<String, String>,
    entries: &mut Vec<PythonEntryPoint>,
) {
    entries.extend(
        scripts
            .into_iter()
            .filter_map(|(name, target)| python_entry_point_from_script(&name, &target)),
    );
}

pub(crate) fn collect_poetry_script_entries(
    scripts: BTreeMap<String, PoetryScript>,
    entries: &mut Vec<PythonEntryPoint>,
) {
    entries.extend(
        scripts
            .into_iter()
            .filter_map(|(name, script)| match script {
                PoetryScript::Target(target) => python_entry_point_from_script(&name, &target),
                PoetryScript::Table { callable } => {
                    callable.and_then(|target| python_entry_point_from_script(&name, &target))
                }
            }),
    );
}

pub(crate) fn parse_python_entry_points(content: &str) -> Vec<PythonEntryPoint> {
    let mut in_supported_scripts = false;
    let mut entries = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_supported_scripts = matches!(line, "[console_scripts]" | "[gui_scripts]");
            continue;
        }
        if !in_supported_scripts {
            continue;
        }

        if let Some(entry) = python_entry_point_from_assignment(line) {
            entries.push(entry);
        }
    }

    entries
}

pub(crate) fn python_entry_point_from_assignment(line: &str) -> Option<PythonEntryPoint> {
    let (name, target) = line.split_once('=')?;
    python_entry_point_from_script(name, target)
}

pub(crate) fn python_entry_point_from_script(name: &str, target: &str) -> Option<PythonEntryPoint> {
    let target = target.split('[').next().unwrap_or(target).trim();
    let (module, function) = target.split_once(':')?;
    let module = module.trim();
    let function = function.trim();
    if module.is_empty() || function.is_empty() {
        return None;
    }
    Some(PythonEntryPoint {
        name: name.trim().to_owned(),
        module: module.to_owned(),
        function: function.to_owned(),
    })
}

pub(crate) fn python_entry_point_script(entry: &PythonEntryPoint) -> String {
    format!(
        r#"#!/usr/bin/env python3
from pathlib import Path
import re
import sys

_python_dir = Path(__file__).resolve().parents[1]
_site_packages_dir = _python_dir / "site-packages"
_site_packages = str(_site_packages_dir if _site_packages_dir.exists() else _python_dir)
_project_paths = [_site_packages]
_local_paths_files = [_python_dir / "local-paths", _python_dir / ".omc-local-paths"]
for _local_paths in _local_paths_files:
    if not _local_paths.exists():
        continue
    _project_paths.extend(
        line.strip()
        for line in _local_paths.read_text().splitlines()
        if line.strip()
    )
sys.path = _project_paths + [
    path for path in sys.path
    if path not in _project_paths
    and "site-packages" not in path
    and "dist-packages" not in path
]

from {module} import {function}

if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    sys.exit({function}())
"#,
        module = entry.module,
        function = entry.function
    )
}
