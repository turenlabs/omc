//! Python local-path and VCS source resolution.
//!
//! Resolves editable/local-path Python requirements and `git+`-style VCS
//! requirements: detecting a source's name/version, cloning/checking out VCS
//! references, caching the checkout as a tarball, and restoring it from the
//! lockfile. Pure code movement out of `lib.rs`; behaviour is unchanged.

use crate::*;

use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;
use tar::Archive;
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub(crate) struct PythonVcsResolveResult {
    pub(crate) requirements: ProjectRequirements,
    pub(crate) locks: Vec<LockedPythonVcsDependency>,
}

pub(crate) fn python_local_source_compile_inputs(
    local_paths: &[PathBuf],
) -> Result<Vec<LocalSourceCompileInput>> {
    let mut inputs = Vec::new();
    for path in local_paths {
        let source_path = fs::canonicalize(path).map_err(|error| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` could not be resolved: {error}",
                path.display()
            ))
        })?;
        if !source_path.is_dir() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` must be a directory",
                source_path.display()
            )));
        }
        let (name, version) = python_local_source_name_version(&source_path)?;
        inputs.push(LocalSourceCompileInput {
            ecosystem: Ecosystem::Pypi,
            source_path,
            name,
            version,
        });
    }
    Ok(inputs)
}

fn python_local_source_name_version(package_dir: &Path) -> Result<(String, String)> {
    if let Some((name, version)) = python_local_pyproject_name_version(package_dir)? {
        return Ok((name, version));
    }
    if let Some((name, version)) = python_local_setup_cfg_name_version(package_dir)? {
        return Ok((name, version));
    }
    if let Some((name, version)) = python_local_setup_py_name_version(package_dir)? {
        return Ok((name, version));
    }

    let name = package_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(normalize_pypi_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "local-source".to_owned());
    Ok((name, "0.0.0".to_owned()))
}

fn python_local_pyproject_name_version(package_dir: &Path) -> Result<Option<(String, String)>> {
    let pyproject = package_dir.join("pyproject.toml");
    if !pyproject.exists() {
        return Ok(None);
    }
    let pyproject = toml::from_str::<PyProjectToml>(&fs::read_to_string(pyproject)?)?;
    if let Some(project) = pyproject.project {
        if let Some(name) = project.name.filter(|name| !name.trim().is_empty()) {
            let version = project
                .version
                .filter(|version| !version.trim().is_empty())
                .unwrap_or_else(|| "0.0.0".to_owned());
            return Ok(Some((normalize_pypi_name(&name), version)));
        }
    }
    if let Some(poetry) = pyproject.tool.and_then(|tool| tool.poetry) {
        if let Some(name) = poetry.name.filter(|name| !name.trim().is_empty()) {
            let version = poetry
                .version
                .filter(|version| !version.trim().is_empty())
                .unwrap_or_else(|| "0.0.0".to_owned());
            return Ok(Some((normalize_pypi_name(&name), version)));
        }
    }
    Ok(None)
}

fn python_local_setup_cfg_name_version(package_dir: &Path) -> Result<Option<(String, String)>> {
    let setup_cfg = package_dir.join("setup.cfg");
    if !setup_cfg.exists() {
        return Ok(None);
    }
    let sections = parse_setup_cfg_sections(&fs::read_to_string(setup_cfg)?);
    let Some(metadata) = sections.get("metadata") else {
        return Ok(None);
    };
    let Some(name) = metadata
        .get("name")
        .and_then(|values| values.iter().find(|value| !value.trim().is_empty()))
    else {
        return Ok(None);
    };
    let version = metadata
        .get("version")
        .and_then(|values| values.iter().find(|value| !value.trim().is_empty()))
        .cloned()
        .unwrap_or_else(|| "0.0.0".to_owned());
    Ok(Some((normalize_pypi_name(name), version)))
}

fn python_local_setup_py_name_version(package_dir: &Path) -> Result<Option<(String, String)>> {
    let setup_py = package_dir.join("setup.py");
    if !setup_py.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(setup_py)?;
    let name = python_keyword_assignment_values(&content, "name")
        .into_iter()
        .flat_map(python_string_literals)
        .find(|value| !value.trim().is_empty());
    let Some(name) = name else {
        return Ok(None);
    };
    let version = python_keyword_assignment_values(&content, "version")
        .into_iter()
        .flat_map(python_string_literals)
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "0.0.0".to_owned());
    Ok(Some((normalize_pypi_name(&name), version)))
}

pub(crate) fn resolve_python_local_requirements(
    requirements: &[PythonLocalRequirement],
    include_dependencies: bool,
) -> Result<ProjectRequirements> {
    let mut resolved = ProjectRequirements::default();
    let mut queue = requirements.to_vec();
    let mut seen = BTreeSet::new();

    while let Some(requirement) = queue.pop() {
        let path = fs::canonicalize(&requirement.path).map_err(|error| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` could not be resolved: {error}",
                requirement.path.display()
            ))
        })?;
        if !path.is_dir() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "editable path `{}` must be a directory",
                path.display()
            )));
        }
        let requirement = PythonLocalRequirement::new(path.clone(), requirement.extras);
        if !seen.insert(requirement.clone()) {
            continue;
        }

        if include_dependencies {
            let mut source_requirements =
                read_python_source_requirements(&path, &requirement.extras)?;
            queue.extend(source_requirements.python_local_requirements.clone());
            source_requirements.python_local_requirements.clear();
            extend_project_requirements(&mut resolved, source_requirements);
        }
        push_python_local_path(&mut resolved, path);
    }

    Ok(resolved)
}

pub(crate) fn resolve_python_vcs_requirements(
    project_dir: &Path,
    requirements: &[PythonVcsRequirement],
    locked: Option<&[LockedPythonVcsDependency]>,
) -> Result<PythonVcsResolveResult> {
    let mut resolved = ProjectRequirements::default();
    let mut locks = Vec::new();
    let mut queue = requirements.to_vec();
    let mut seen = BTreeSet::new();

    while let Some(requirement) = queue.pop() {
        if !seen.insert(requirement.clone()) {
            continue;
        }
        let (source_requirements, lock) =
            resolve_python_vcs_requirement(project_dir, &requirement, locked)?;
        queue.extend(source_requirements.python_vcs_requirements.clone());
        extend_project_requirements(&mut resolved, source_requirements);
        locks.push(lock);
    }

    Ok(PythonVcsResolveResult {
        requirements: resolved,
        locks,
    })
}

fn resolve_python_vcs_requirement(
    project_dir: &Path,
    requirement: &PythonVcsRequirement,
    locked: Option<&[LockedPythonVcsDependency]>,
) -> Result<(ProjectRequirements, LockedPythonVcsDependency)> {
    let checkout_dir = python_vcs_checkout_dir(project_dir, requirement);
    let locked_dependency = locked
        .map(|locks| find_locked_python_vcs_dependency(locks, requirement))
        .transpose()?
        .flatten();
    if locked.is_some() && locked_dependency.is_none() {
        return Err(OmcRegistryError::LockfileOutOfDate(format!(
            "pypi:{} @ git+{}",
            requirement.name, requirement.url
        )));
    }
    let restored_from_cache = locked_dependency
        .as_ref()
        .map(|dependency| restore_python_vcs_archive(project_dir, &checkout_dir, dependency))
        .transpose()?
        .unwrap_or(false);
    let resolved_commit = if restored_from_cache {
        locked_dependency
            .as_ref()
            .map(|dependency| dependency.resolved_commit.clone())
            .unwrap_or_default()
    } else {
        let checkout_reference = locked_dependency
            .as_ref()
            .map(|dependency| dependency.resolved_commit.as_str())
            .or(requirement.reference.as_deref());
        checkout_python_vcs_dependency(
            &checkout_dir,
            requirement,
            checkout_reference,
            locked.is_some(),
        )?;
        git_rev_parse_head(&checkout_dir, &requirement.name)?
    };

    let package_dir = if let Some(subdirectory) = requirement.subdirectory.as_deref() {
        checked_join(&checkout_dir, subdirectory)?
    } else {
        checkout_dir.clone()
    };
    if !package_dir.is_dir() {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "VCS dependency `{}` did not contain package directory `{}`",
            requirement.name,
            package_dir.display()
        )));
    }

    let mut resolved = read_python_source_requirements(&package_dir, &requirement.extras)?;
    push_python_local_path(&mut resolved, package_dir);
    let mut lock = locked_python_vcs_dependency(requirement, resolved_commit);
    if let Some(existing) = locked_dependency {
        lock.archive = existing.archive;
        lock.sha256 = existing.sha256;
    }
    if lock.archive.is_empty()
        || lock.sha256.is_empty()
        || !project_dir.join(&lock.archive).exists()
    {
        let (archive, sha256) = cache_python_vcs_checkout(
            project_dir,
            &checkout_dir,
            requirement,
            &lock.resolved_commit,
        )?;
        lock.archive = archive;
        lock.sha256 = sha256;
    }
    Ok((resolved, lock))
}

fn python_vcs_checkout_dir(project_dir: &Path, requirement: &PythonVcsRequirement) -> PathBuf {
    let extras = requirement
        .extras
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "{}\0{}\0{}\0{}\0{}",
        requirement.name,
        requirement.url,
        requirement.reference.as_deref().unwrap_or_default(),
        requirement
            .subdirectory
            .as_deref()
            .map(|path| path.to_string_lossy())
            .unwrap_or_default(),
        extras
    );
    let digest = sha256_hex(source.as_bytes());
    project_dir
        .join(".omc")
        .join("python")
        .join("vcs")
        .join(safe_name(&requirement.name))
        .join(&digest[..16])
}

fn cache_python_vcs_checkout(
    project_dir: &Path,
    checkout_dir: &Path,
    requirement: &PythonVcsRequirement,
    resolved_commit: &str,
) -> Result<(String, String)> {
    let archive_path = python_vcs_archive_path(project_dir, requirement, resolved_commit);
    if !archive_path.exists() {
        write_python_vcs_archive(checkout_dir, &archive_path)?;
    }
    let bytes = fs::read(&archive_path)?;
    let sha256 = sha256_hex(&bytes);
    Ok((relative_path(project_dir, &archive_path), sha256))
}

fn python_vcs_archive_path(
    project_dir: &Path,
    requirement: &PythonVcsRequirement,
    resolved_commit: &str,
) -> PathBuf {
    let source = format!(
        "{}\0{}\0{}",
        requirement.name, requirement.url, resolved_commit
    );
    let source_hash = sha256_hex(source.as_bytes());
    project_dir
        .join(".omc")
        .join("cache")
        .join("python-vcs")
        .join(safe_name(&requirement.name))
        .join(&source_hash[..16])
        .join(format!("{resolved_commit}.tar.gz"))
}

fn write_python_vcs_archive(checkout_dir: &Path, archive_path: &Path) -> Result<()> {
    if let Some(parent) = archive_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::File::create(archive_path)?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);

    for entry in WalkDir::new(checkout_dir)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != ".git")
    {
        let entry =
            entry.map_err(|error| OmcRegistryError::UnsupportedRequirement(error.to_string()))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(checkout_dir)
            .map_err(|error| OmcRegistryError::UnsupportedRequirement(error.to_string()))?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_dir() {
            archive.append_dir(relative, path)?;
        } else if entry.file_type().is_file() {
            archive.append_path_with_name(path, relative)?;
        }
    }

    archive.finish()?;
    Ok(())
}

fn restore_python_vcs_archive(
    project_dir: &Path,
    checkout_dir: &Path,
    dependency: &LockedPythonVcsDependency,
) -> Result<bool> {
    if dependency.archive.is_empty() {
        return Ok(false);
    }
    let archive_path = project_dir.join(&dependency.archive);
    if !archive_path.exists() {
        return Ok(false);
    }
    let bytes = fs::read(&archive_path)?;
    if !dependency.sha256.is_empty() {
        let actual = sha256_hex(&bytes);
        if !dependency.sha256.eq_ignore_ascii_case(&actual) {
            return Err(OmcRegistryError::DigestMismatch {
                name: dependency.name.clone(),
                expected: format!("sha256:{}", dependency.sha256),
                actual: format!("sha256:{actual}"),
            });
        }
    }

    remove_path_if_exists(checkout_dir)?;
    fs::create_dir_all(checkout_dir)?;
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let relative = entry.path()?.into_owned();
        let output = checked_join(checkout_dir, &relative)?;
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(output)?;
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(OmcRegistryError::UnsupportedRequirement(format!(
                "python VCS cache archive contains unsupported entry type for `{}`",
                relative.display()
            )));
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        entry.unpack(output)?;
    }
    Ok(true)
}

fn checkout_python_vcs_dependency(
    checkout_dir: &Path,
    requirement: &PythonVcsRequirement,
    reference: Option<&str>,
    locked: bool,
) -> Result<()> {
    if locked && checkout_dir.join(".git").is_dir() {
        if let Some(reference) = reference {
            if checkout_python_vcs_reference(checkout_dir, &requirement.name, reference).is_err() {
                let mut fetch = Command::new("git");
                fetch
                    .arg("-C")
                    .arg(checkout_dir)
                    .arg("fetch")
                    .arg("--quiet")
                    .arg("--all")
                    .arg("--tags");
                run_git_command(&mut fetch, &format!("fetch `{}`", requirement.name))?;
                checkout_python_vcs_reference(checkout_dir, &requirement.name, reference)?;
            }
        }
        return Ok(());
    }

    remove_path_if_exists(checkout_dir)?;
    fs::create_dir_all(checkout_dir.parent().ok_or_else(|| {
        OmcRegistryError::UnsupportedRequirement(format!(
            "VCS checkout path `{}` has no parent",
            checkout_dir.display()
        ))
    })?)?;

    let mut clone = Command::new("git");
    clone
        .arg("clone")
        .arg("--quiet")
        .arg(&requirement.url)
        .arg(checkout_dir);
    run_git_command(&mut clone, &format!("clone `{}`", requirement.url))?;

    if let Some(reference) = reference {
        checkout_python_vcs_reference(checkout_dir, &requirement.name, reference)?;
    }

    Ok(())
}

fn checkout_python_vcs_reference(checkout_dir: &Path, name: &str, reference: &str) -> Result<()> {
    let mut checkout = Command::new("git");
    checkout
        .arg("-C")
        .arg(checkout_dir)
        .arg("checkout")
        .arg("--quiet")
        .arg(reference);
    run_git_command(
        &mut checkout,
        &format!("checkout `{reference}` for `{name}`"),
    )?;
    Ok(())
}

pub(crate) fn git_rev_parse_head(checkout_dir: &Path, name: &str) -> Result<String> {
    let mut rev_parse = Command::new("git");
    rev_parse
        .arg("-C")
        .arg(checkout_dir)
        .arg("rev-parse")
        .arg("HEAD");
    let commit = run_git_command(&mut rev_parse, &format!("resolve HEAD for `{name}`"))?;
    if !is_git_commit_hash(&commit) {
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "git resolve HEAD for `{name}` returned invalid commit `{commit}`"
        )));
    }
    Ok(commit)
}

pub(crate) fn is_git_commit_hash(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn locked_python_vcs_dependency(
    requirement: &PythonVcsRequirement,
    resolved_commit: String,
) -> LockedPythonVcsDependency {
    LockedPythonVcsDependency {
        name: requirement.name.clone(),
        url: requirement.url.clone(),
        reference: requirement.reference.clone(),
        resolved_commit,
        archive: String::new(),
        sha256: String::new(),
        subdirectory: python_vcs_subdirectory_string(requirement.subdirectory.as_deref()),
        extras: requirement.extras.iter().cloned().collect(),
    }
}

fn find_locked_python_vcs_dependency(
    locks: &[LockedPythonVcsDependency],
    requirement: &PythonVcsRequirement,
) -> Result<Option<LockedPythonVcsDependency>> {
    for lock in locks {
        if !python_vcs_lock_matches_requirement(lock, requirement) {
            continue;
        }
        if !is_git_commit_hash(&lock.resolved_commit) {
            return Err(OmcRegistryError::LockfileOutOfDate(format!(
                "pypi:{} @ git+{}",
                requirement.name, requirement.url
            )));
        }
        return Ok(Some(lock.clone()));
    }
    Ok(None)
}

fn python_vcs_lock_matches_requirement(
    lock: &LockedPythonVcsDependency,
    requirement: &PythonVcsRequirement,
) -> bool {
    let extras = lock
        .extras
        .iter()
        .map(|extra| normalize_pypi_extra(extra))
        .filter(|extra| !extra.is_empty())
        .collect::<BTreeSet<_>>();
    lock.name == requirement.name
        && lock.url == requirement.url
        && lock.reference == requirement.reference
        && lock.subdirectory == python_vcs_subdirectory_string(requirement.subdirectory.as_deref())
        && extras == requirement.extras
}

pub(crate) fn python_vcs_lock_key(
    lock: &LockedPythonVcsDependency,
) -> (String, String, Option<String>, Option<String>, Vec<String>) {
    let extras = lock
        .extras
        .iter()
        .map(|extra| normalize_pypi_extra(extra))
        .filter(|extra| !extra.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    (
        lock.name.clone(),
        lock.url.clone(),
        lock.reference.clone(),
        lock.subdirectory.clone(),
        extras,
    )
}

fn python_vcs_subdirectory_string(path: Option<&Path>) -> Option<String> {
    path.map(|path| path.to_string_lossy().replace('\\', "/"))
        .filter(|path| !path.is_empty())
}

fn run_git_command(command: &mut Command, description: &str) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OmcRegistryError::UnsupportedRequirement(format!(
            "git {description} failed: {}",
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
