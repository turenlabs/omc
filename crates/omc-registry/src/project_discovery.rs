//! Project-root discovery + manifest detection — extracted verbatim from lib.rs.
//!
//! Walks a project directory, detects the package/lock manifests present
//! (package.json, package-lock.json, requirements.txt, Pipfile, pyproject.toml,
//! …) and aggregates their declared requirements into a single
//! [`ProjectRequirements`].

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_project_specs(project_dir: impl AsRef<Path>) -> Result<Vec<PackageSpec>> {
    Ok(discover_project_requirements(project_dir)?.specs)
}

pub fn read_package_scripts(project_dir: impl AsRef<Path>) -> Result<BTreeMap<String, String>> {
    let project_dir = project_dir.as_ref();
    let mut scripts = BTreeMap::new();

    let pipfile = project_dir.join("Pipfile");
    if pipfile.exists() {
        scripts.extend(read_pipfile_scripts(&pipfile)?);
    }

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(package_json)?)?;
        scripts.extend(package.scripts);
    }

    Ok(scripts)
}

pub fn discover_project_requirements(project_dir: impl AsRef<Path>) -> Result<ProjectRequirements> {
    discover_project_requirements_with_extras(project_dir, &BTreeSet::new())
}

pub fn discover_project_requirements_with_extras(
    project_dir: impl AsRef<Path>,
    project_extras: &BTreeSet<String>,
) -> Result<ProjectRequirements> {
    discover_project_requirements_with_options(project_dir, project_extras, true)
}

pub(crate) fn discover_project_requirements_with_options(
    project_dir: impl AsRef<Path>,
    project_extras: &BTreeSet<String>,
    include_dev_dependencies: bool,
) -> Result<ProjectRequirements> {
    discover_project_requirements_with_selection(
        project_dir,
        project_extras,
        DependencySelection::with_dev(include_dev_dependencies),
    )
}

pub(crate) fn discover_project_requirements_with_selection(
    project_dir: impl AsRef<Path>,
    project_extras: &BTreeSet<String>,
    selection: DependencySelection,
) -> Result<ProjectRequirements> {
    let project_dir = project_dir.as_ref();
    let mut project = ProjectRequirements::default();

    let package_json = project_dir.join("package.json");
    if package_json.exists() {
        let requirements = read_package_json_requirements(&package_json, selection)?;
        extend_project_requirements(&mut project, requirements);
    }

    for lockfile_name in ["package-lock.json", "npm-shrinkwrap.json"] {
        let lockfile = project_dir.join(lockfile_name);
        if lockfile.exists() {
            let lock_requirements = read_package_lock_requirements(&lockfile)?;
            extend_project_requirements(&mut project, lock_requirements);
        }
    }

    let yarn_lock = project_dir.join("yarn.lock");
    if yarn_lock.exists() {
        let lock_requirements = read_yarn_lock_requirements(&yarn_lock)?;
        extend_project_requirements(&mut project, lock_requirements);
    }

    let pnpm_lock = project_dir.join("pnpm-lock.yaml");
    if pnpm_lock.exists() {
        let lock_requirements = read_pnpm_lock_requirements(&pnpm_lock, selection)?;
        extend_project_requirements(&mut project, lock_requirements);
    }

    let requirements_files = project_requirements_files(project_dir, selection.dev);
    if !requirements_files.is_empty() {
        let requirements = read_requirements_files(&requirements_files)?;
        extend_project_requirements(&mut project, requirements);
    }

    let pipfile_lock = project_dir.join("Pipfile.lock");
    if pipfile_lock.exists() {
        let requirements = read_pipfile_lock_requirements(&pipfile_lock, selection.dev)?;
        extend_project_requirements(&mut project, requirements);
    }

    let pipfile = project_dir.join("Pipfile");
    if pipfile.exists() && !pipfile_lock.exists() {
        let requirements = read_pipfile_requirements(&pipfile, selection.dev)?;
        extend_project_requirements(&mut project, requirements);
    }

    let uv_lock = project_dir.join("uv.lock");
    if uv_lock.exists() {
        let requirements = read_uv_lock_requirements(&uv_lock, selection.dev)?;
        extend_project_requirements(&mut project, requirements);
    }

    for pylock_name in ["pylock.omc.toml", "pylock.toml"] {
        let pylock = project_dir.join(pylock_name);
        if pylock.exists() {
            let requirements = read_pylock_requirements(&pylock)?;
            extend_project_requirements(&mut project, requirements);
            break;
        }
    }

    let pyproject_toml = project_dir.join("pyproject.toml");
    if pyproject_toml.exists() {
        let requirements =
            read_pyproject_requirements(&pyproject_toml, project_extras, selection.dev)?;
        extend_project_requirements(&mut project, requirements);
    }

    let setup_cfg = project_dir.join("setup.cfg");
    if setup_cfg.exists() {
        let requirements = read_setup_cfg_requirements(&setup_cfg, project_extras)?;
        extend_project_requirements(&mut project, requirements);
    }

    let setup_py = project_dir.join("setup.py");
    if setup_py.exists() {
        let requirements = read_setup_py_requirements(&setup_py, project_extras)?;
        extend_project_requirements(&mut project, requirements);
    }

    if root_python_project_has_metadata(project_dir)? {
        push_python_local_path(&mut project, project_dir.to_path_buf());
    }

    let poetry_lock = project_dir.join("poetry.lock");
    if poetry_lock.exists() {
        let requirements = read_poetry_lock_requirements(&poetry_lock)?;
        extend_project_requirements(&mut project, requirements);
    }

    Ok(project)
}

fn project_requirements_files(project_dir: &Path, include_dev_dependencies: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    push_existing_requirement_file(&mut files, project_dir.join("requirements.txt"));
    push_existing_requirement_file(
        &mut files,
        project_dir.join("requirements").join("base.txt"),
    );

    if include_dev_dependencies {
        push_existing_requirement_file(&mut files, project_dir.join("requirements-dev.txt"));
        push_existing_requirement_file(&mut files, project_dir.join("dev-requirements.txt"));
        push_existing_requirement_file(
            &mut files,
            project_dir.join("requirements").join("dev.txt"),
        );
    }

    files
}

fn push_existing_requirement_file(files: &mut Vec<PathBuf>, path: PathBuf) {
    if path.exists() && !files.contains(&path) {
        files.push(path);
    }
}

#[cfg(test)]
pub(crate) fn read_package_json_specs(
    path: &Path,
    include_dev_dependencies: bool,
) -> Result<Vec<PackageSpec>> {
    Ok(read_package_json_requirements(
        path,
        DependencySelection::with_dev(include_dev_dependencies),
    )?
    .specs)
}

pub(crate) fn read_package_json_requirements(
    path: &Path,
    selection: DependencySelection,
) -> Result<ProjectRequirements> {
    let package = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(path)?)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let workspaces = package.workspaces.clone();
    let mut requirements = ProjectRequirements::default();
    collect_package_json_overrides(&package, &mut requirements.npm_overrides);
    requirements.specs.extend(package_json_dependency_specs(
        package.clone(),
        selection,
        base_dir,
    )?);
    collect_package_json_local_dependency_paths(
        &package,
        selection,
        base_dir,
        &mut requirements.npm_local_paths,
    )?;

    if let Some(workspaces) = workspaces {
        for package_json in workspace_package_json_paths(base_dir, &workspaces) {
            let workspace_base_dir = package_json.parent().unwrap_or(base_dir);
            let package =
                serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
            collect_package_json_overrides(&package, &mut requirements.npm_overrides);
            requirements.specs.extend(package_json_dependency_specs(
                package.clone(),
                selection,
                workspace_base_dir,
            )?);
            collect_package_json_local_dependency_paths(
                &package,
                selection,
                workspace_base_dir,
                &mut requirements.npm_local_paths,
            )?;
        }
    }

    Ok(requirements)
}

pub(crate) fn read_package_lock_requirements(path: &Path) -> Result<ProjectRequirements> {
    let lock = serde_json::from_str::<NpmPackageLock>(&fs::read_to_string(path)?)?;
    let mut versions = BTreeMap::<String, BTreeSet<String>>::new();
    let mut integrities = BTreeMap::<String, BTreeSet<String>>::new();
    let mut resolved = BTreeMap::<String, BTreeSet<String>>::new();

    for (path, package) in lock.packages {
        if path.is_empty() {
            continue;
        }
        let Some(name) = npm_package_name_from_lock_path(&path) else {
            continue;
        };
        if let Some(version) = package.version {
            versions.entry(name.clone()).or_default().insert(version);
        }
        if let Some(integrity) = package.integrity {
            integrities
                .entry(name.clone())
                .or_default()
                .insert(integrity);
        }
        if let Some(url) = package.resolved {
            resolved.entry(name).or_default().insert(url);
        }
    }

    collect_npm_lock_dependency_requirements(
        lock.dependencies,
        &mut versions,
        &mut integrities,
        &mut resolved,
    );

    Ok(npm_requirements_from_lock_maps(
        versions,
        integrities,
        resolved,
    ))
}
