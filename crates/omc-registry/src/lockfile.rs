//! `omc.lock` reading, writing, and pruning.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Read and parse the project's `omc.lock`, returning an empty lock when the
/// file is absent.
pub fn read_lockfile(path: impl AsRef<Path>) -> Result<OmcLock> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(OmcLock::new());
    }
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

pub(crate) fn prune_lockfile(project_dir: &Path, retained: &BTreeSet<String>) -> Result<usize> {
    let lockfile = project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    let before = lock.packages.len();
    lock.packages
        .retain(|package| retained.contains(&locked_package_key(package)));
    let removed = before.saturating_sub(lock.packages.len());
    if removed > 0 || before == 0 {
        fs::write(lockfile, toml::to_string_pretty(&lock)?)?;
    }
    Ok(removed)
}

pub(crate) fn sync_python_vcs_lockfile(
    project_dir: &Path,
    dependencies: Vec<LockedPythonVcsDependency>,
) -> Result<()> {
    let lockfile = project_dir.join(LOCKFILE);
    let mut lock = read_lockfile(&lockfile)?;
    lock.replace_python_vcs(dependencies);
    fs::write(lockfile, toml::to_string_pretty(&lock)?)?;
    Ok(())
}

pub(crate) fn locked_package_key(package: &LockedPackage) -> String {
    format!("{}:{}@{}", package.ecosystem, package.name, package.version)
}

pub(crate) fn locked_reachable_package_keys(
    lock: &OmcLock,
    specs: &[PackageSpec],
    options: &LinkOptions,
) -> Result<BTreeSet<String>> {
    let mut retained = BTreeSet::new();
    for spec in specs {
        let package = find_locked_package_for_spec(
            lock,
            spec,
            &options.constraints,
            &options.npm_overrides,
            &options.hashes,
        )
        .ok_or_else(|| OmcRegistryError::LockfileOutOfDate(spec.requested()))?;
        collect_locked_dependencies(lock, package, options, &mut retained)?;
    }
    Ok(retained)
}

pub(crate) fn collect_locked_dependencies(
    lock: &OmcLock,
    package: &LockedPackage,
    options: &LinkOptions,
    retained: &mut BTreeSet<String>,
) -> Result<()> {
    if !retained.insert(locked_package_key(package)) {
        return Ok(());
    }

    if !should_follow_locked_dependencies(package, options) {
        return Ok(());
    }

    for dependency in &package.dependencies {
        let spec = PackageSpec::parse(dependency)?;
        let dependency = find_locked_package_for_spec(
            lock,
            &spec,
            &BTreeMap::new(),
            &options.npm_overrides,
            &BTreeMap::new(),
        )
        .ok_or_else(|| OmcRegistryError::LockfileOutOfDate(spec.requested()))?;
        collect_locked_dependencies(lock, dependency, options, retained)?;
    }
    if options.include_optional_dependencies {
        for dependency in &package.optional_dependencies {
            let spec = PackageSpec::parse(dependency)?;
            if let Some(dependency) = find_locked_package_for_spec(
                lock,
                &spec,
                &BTreeMap::new(),
                &options.npm_overrides,
                &BTreeMap::new(),
            ) {
                collect_locked_dependencies(lock, dependency, options, retained)?;
            }
        }
    }
    if options.include_peer_dependencies {
        for dependency in &package.peer_dependencies {
            let spec = PackageSpec::parse(dependency)?;
            let dependency = find_locked_package_for_spec(
                lock,
                &spec,
                &BTreeMap::new(),
                &options.npm_overrides,
                &BTreeMap::new(),
            )
            .ok_or_else(|| OmcRegistryError::LockfileOutOfDate(spec.requested()))?;
            collect_locked_dependencies(lock, dependency, options, retained)?;
        }
    }

    Ok(())
}
