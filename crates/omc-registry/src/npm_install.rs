//! npm tarball extraction + node_modules linking.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive;

pub(crate) fn install_npm_package(
    project_dir: &Path,
    package: &LockedPackage,
    node_modules: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let target = install_npm_package_to(project_dir, package, node_modules)?;
    install_npm_bins(&target, &package.name, bin_dir)
}

pub(crate) fn install_npm_package_to(
    project_dir: &Path,
    package: &LockedPackage,
    node_modules: &Path,
) -> Result<PathBuf> {
    let target = npm_install_target(node_modules, &package.name);

    // Link-mode install: extract the tarball ONCE into the shared content store
    // (`$OMC_HOME/store/...`), then hard-link its files into this project's
    // node_modules. N projects sharing a package version keep ~1 physical copy
    // on disk instead of a full per-project copy (the pnpm / uv model). When no
    // store is available (no resolvable $OMC_HOME), fall back to extracting the
    // tarball directly into node_modules.
    match store::package_store_dir(Ecosystem::Npm, &package.name, &package.sha256) {
        Some(store_dir) => {
            if !store_dir.exists() {
                let bytes = read_locked_archive(project_dir, package)?;
                store::ensure_npm_extracted(&store_dir, &bytes)?;
            }
            store::link_tree_into(&store_dir, &target)?;
        }
        None => {
            let bytes = read_locked_archive(project_dir, package)?;
            unpack_npm_tarball(&bytes, &target)?;
        }
    }
    Ok(target)
}

/// Extract an npm `.tgz` into `target`, stripping the leading `package/`
/// component. Deny-by-default against tar-slip: declared paths are validated
/// with `checked_join` (no `..`, no absolute) and symlink/hardlink entries are
/// never materialized, so no escaping link can exist for a later entry to be
/// written through. `target` is recreated fresh.
pub(crate) fn unpack_npm_tarball(bytes: &[u8], target: &Path) -> Result<()> {
    if target.exists() {
        fs::remove_dir_all(target)?;
    }
    fs::create_dir_all(target)?;

    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.to_string_lossy().into_owned();
        if is_ignorable_archive_metadata_path(&raw_path) {
            continue;
        }
        let entry_type = entry.header().entry_type();
        // Deny-by-default against tar-slip: never materialize symlink/hardlink
        // entries from an archive. A symlink that escapes the target dir would
        // let a *later* entry be written through it (classic path-traversal);
        // a hardlink could alias a file outside the tree. omc only ever creates
        // real directories and regular files, so no escaping link can exist on
        // disk for a subsequent entry to follow.
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }
        let Some(stripped) = strip_first_path_component(Path::new(&raw_path)) else {
            if entry_type.is_dir() {
                continue;
            }
            return Err(OmcRegistryError::UnsafeArchivePath(raw_path));
        };
        let output = checked_join(target, &stripped)?;

        if entry_type.is_dir() {
            fs::create_dir_all(output)?;
        } else if entry_type.is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            entry.unpack(output)?;
        }
    }
    Ok(())
}

pub(crate) fn install_nested_npm_dependencies(
    project_dir: &Path,
    lock: &OmcLock,
    node_modules: &Path,
) -> Result<()> {
    for package in lock
        .packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
    {
        let parent = npm_install_target(node_modules, &package.name);
        install_nested_npm_dependencies_for_package(
            project_dir,
            lock,
            &parent,
            package,
            &mut Vec::new(),
        )?;
    }
    Ok(())
}

pub(crate) fn install_npm_project_links(
    project_dir: &Path,
    node_modules: &Path,
    bin_dir: &Path,
    selection: DependencySelection,
) -> Result<usize> {
    Ok(install_npm_root_bins(project_dir, bin_dir)?
        + install_npm_workspace_links(project_dir, node_modules, bin_dir)?
        + install_npm_local_dependency_links(project_dir, node_modules, bin_dir, selection)?)
}

pub(crate) fn install_npm_direct_local_links(
    paths: &[PathBuf],
    node_modules: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let mut count = 0;
    let mut seen = BTreeSet::new();
    for path in paths {
        let source_path = fs::canonicalize(path).map_err(|error| {
            OmcRegistryError::UnsupportedRequirement(format!(
                "local npm path `{}` could not be resolved: {error}",
                path.display()
            ))
        })?;
        if !seen.insert(source_path.clone()) {
            continue;
        }
        if !source_path.is_dir() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` must point to an existing directory",
                source_path.display()
            )));
        }
        let package_json = source_path.join("package.json");
        if !package_json.exists() {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` must contain package.json",
                source_path.display()
            )));
        }
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let Some(name) = package.name.as_deref().filter(|name| !name.is_empty()) else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "local npm path `{}` package.json must declare name",
                source_path.display()
            )));
        };
        let target = npm_install_target(node_modules, name);
        if target_already_links_to_source(&target, &source_path) {
            continue;
        }
        remove_path_if_exists(&target)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        create_directory_link(&source_path, &target)?;
        count += install_npm_bins(&target, name, bin_dir)?;
    }
    Ok(count)
}

fn target_already_links_to_source(target: &Path, source: &Path) -> bool {
    target
        .exists()
        .then(|| fs::canonicalize(target).ok())
        .flatten()
        .as_deref()
        == Some(source)
}

fn install_npm_root_bins(project_dir: &Path, bin_dir: &Path) -> Result<usize> {
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(0);
    }

    let package =
        serde_json::from_str::<NpmInstalledPackageJson>(&fs::read_to_string(package_json)?)?;
    let package_name = package.name.as_deref().unwrap_or("");
    if package.bin.is_none() {
        return Ok(0);
    }

    install_npm_bins(project_dir, package_name, bin_dir)
}

fn install_npm_workspace_links(
    project_dir: &Path,
    node_modules: &Path,
    bin_dir: &Path,
) -> Result<usize> {
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(0);
    }

    let root = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
    let Some(workspaces) = root.workspaces else {
        return Ok(0);
    };

    let mut count = 0;
    for package_json in workspace_package_json_paths(project_dir, &workspaces) {
        let workspace_dir = package_json.parent().unwrap_or(project_dir);
        let workspace =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let Some(name) = workspace.name.as_deref().filter(|name| !name.is_empty()) else {
            continue;
        };
        let target = npm_install_target(node_modules, name);
        remove_path_if_exists(&target)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        create_directory_link(workspace_dir, &target)?;
        count += install_npm_bins(&target, name, bin_dir)?;
    }

    Ok(count)
}

fn install_npm_local_dependency_links(
    project_dir: &Path,
    node_modules: &Path,
    bin_dir: &Path,
    selection: DependencySelection,
) -> Result<usize> {
    let mut count = 0;
    for package_json in npm_project_package_jsons(project_dir)? {
        let base_dir = package_json.parent().unwrap_or(project_dir);
        let package =
            serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
        let mut links = Vec::new();
        collect_npm_local_dependency_links(&package, selection, base_dir, &mut links)?;
        for link in links {
            let target = npm_install_target(node_modules, &link.name);
            remove_path_if_exists(&target)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            create_directory_link(&link.path, &target)?;
            count += install_npm_bins(&target, &link.name, bin_dir)?;
        }
    }
    Ok(count)
}

pub(crate) fn npm_project_package_jsons(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok(Vec::new());
    }

    let root = serde_json::from_str::<ProjectPackageJson>(&fs::read_to_string(&package_json)?)?;
    let mut package_jsons = vec![package_json];
    if let Some(workspaces) = root.workspaces {
        package_jsons.extend(workspace_package_json_paths(project_dir, &workspaces));
    }
    Ok(package_jsons)
}

#[derive(Debug)]
pub(crate) struct NpmLocalLink {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
}

pub(crate) fn collect_npm_local_dependency_links(
    package: &ProjectPackageJson,
    selection: DependencySelection,
    base_dir: &Path,
    links: &mut Vec<NpmLocalLink>,
) -> Result<()> {
    collect_npm_local_dependency_links_from_map(&package.dependencies, base_dir, links)?;
    if selection.dev {
        collect_npm_local_dependency_links_from_map(&package.dev_dependencies, base_dir, links)?;
    }
    if selection.optional {
        collect_npm_local_dependency_links_from_map(
            &package.optional_dependencies,
            base_dir,
            links,
        )?;
    }
    if selection.peer {
        for (name, requirement) in &package.peer_dependencies {
            if package
                .peer_dependencies_meta
                .get(name)
                .map(|meta| meta.optional)
                .unwrap_or(false)
            {
                continue;
            }
            collect_npm_local_dependency_link(name, requirement, base_dir, links)?;
        }
    }
    Ok(())
}

fn collect_npm_local_dependency_links_from_map(
    dependencies: &BTreeMap<String, String>,
    base_dir: &Path,
    links: &mut Vec<NpmLocalLink>,
) -> Result<()> {
    for (name, requirement) in dependencies {
        collect_npm_local_dependency_link(name, requirement, base_dir, links)?;
    }
    Ok(())
}

fn collect_npm_local_dependency_link(
    name: &str,
    requirement: &str,
    base_dir: &Path,
    links: &mut Vec<NpmLocalLink>,
) -> Result<()> {
    let Some(path) = npm_local_directory_requirement_path(requirement.trim(), base_dir)? else {
        return Ok(());
    };
    links.push(NpmLocalLink {
        name: name.to_owned(),
        path,
    });
    Ok(())
}

fn install_nested_npm_dependencies_for_package(
    project_dir: &Path,
    lock: &OmcLock,
    installed_dir: &Path,
    package: &LockedPackage,
    stack: &mut Vec<String>,
) -> Result<()> {
    let key = format!("{}@{}", package.name, package.version);
    if stack.contains(&key) {
        return Ok(());
    }
    stack.push(key);

    let nested_node_modules = installed_dir.join("node_modules");
    for dependency in package
        .dependencies
        .iter()
        .chain(package.optional_dependencies.iter())
    {
        let Ok(spec) = PackageSpec::parse(dependency) else {
            continue;
        };
        if spec.ecosystem != Ecosystem::Npm {
            continue;
        }
        let Some(locked_dependency) = find_locked_npm_dependency(lock, &spec) else {
            continue;
        };
        let dependency_dir =
            install_npm_package_to(project_dir, locked_dependency, &nested_node_modules)?;
        install_nested_npm_dependencies_for_package(
            project_dir,
            lock,
            &dependency_dir,
            locked_dependency,
            stack,
        )?;
    }

    stack.pop();
    Ok(())
}

fn find_locked_npm_dependency<'a>(
    lock: &'a OmcLock,
    spec: &PackageSpec,
) -> Option<&'a LockedPackage> {
    let (_, requirement) = npm_registry_name_and_requirement(spec).ok()?;
    lock.packages
        .iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm && package.name == spec.name)
        .filter(|package| {
            requirement
                .as_deref()
                .map(|requirement| npm_version_satisfies(&package.version, requirement))
                .unwrap_or(true)
        })
        .max_by(|left, right| compare_npm_versions(&left.version, &right.version))
}

fn npm_install_target(node_modules: &Path, name: &str) -> PathBuf {
    if let Some((scope, package)) = name.split_once('/') {
        node_modules.join(scope).join(package)
    } else {
        node_modules.join(name)
    }
}

fn install_npm_bins(package_dir: &Path, package_name: &str, bin_dir: &Path) -> Result<usize> {
    let package_json = package_dir.join("package.json");
    if !package_json.exists() {
        return Ok(0);
    }

    let package =
        serde_json::from_str::<NpmInstalledPackageJson>(&fs::read_to_string(package_json)?)?;
    let Some(bin) = package.bin else {
        return Ok(0);
    };

    fs::create_dir_all(bin_dir)?;
    let bins = match bin {
        NpmBinField::String(path) => vec![(
            npm_default_bin_name(package.name.as_deref().unwrap_or(package_name)),
            path,
        )],
        NpmBinField::Map(map) => map.into_iter().collect(),
    };

    let mut installed = 0;
    for (name, relative) in bins {
        if !is_safe_script_name(&name) {
            continue;
        }
        let source = checked_join(package_dir, Path::new(&relative))?;
        if !source.exists() {
            continue;
        }
        make_executable(&source)?;
        let target = bin_dir.join(&name);
        remove_path_if_exists(&target)?;
        create_command_link(&source, &target)?;
        installed += 1;
    }

    Ok(installed)
}

fn npm_default_bin_name(package_name: &str) -> String {
    package_name
        .rsplit('/')
        .next()
        .unwrap_or(package_name)
        .to_owned()
}
