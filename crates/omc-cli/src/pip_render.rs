//! pip-compat output/rendering: pip-side `print_*`/`pip_freeze_*` helpers
//! that format and emit freeze/list/show/check/outdated/inspect/cache/debug
//! output. Moved out of pip_cli.rs (module split).

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fs, io};

use omc_registry::{
    read_lockfile, Ecosystem, LockedPythonVcsDependency, OmcRegistryError, PypiCheckIssue,
};


pub(crate) fn print_pip_help(topic: Option<&str>) {
    print!("{}", pip_help_text(topic));
}

pub(crate) fn print_pip_completion(shell: Option<PipCompletionShell>) {
    match shell {
        Some(PipCompletionShell::Bash) => print!("{}", pip_bash_completion_script()),
        Some(PipCompletionShell::Zsh) => print!("{}", pip_zsh_completion_script()),
        Some(PipCompletionShell::Fish) => print!("{}", pip_fish_completion_script()),
        None => println!("ERROR: You must pass --bash or --fish or --zsh"),
    }
}

pub(crate) fn print_pip_auto_completion(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let words = pip_completion_words_from_env();
    let cword = env::var("COMP_CWORD")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| words.len().saturating_sub(1));
    for suggestion in pip_completion_suggestions(project_dir, &words, cword) {
        println!("{suggestion}");
    }
    Ok(())
}

pub(crate) fn print_pip_index_versions(
    project_dir: &Path,
    package: &str,
    options: PipIndexSearchOptions,
    json: bool,
) -> Result<(), OmcRegistryError> {
    let PipIndexSearchOptions {
        index_url,
        extra_index_urls,
        find_links,
        no_index,
        allow_prereleases,
        release_controls,
        uploaded_prior_to,
        compatibility,
    } = options;
    let listing = read_pypi_available_versions(
        project_dir,
        package,
        PypiAvailableVersionsOptions {
            index_url,
            extra_index_urls,
            find_links,
            no_index,
            allow_prereleases,
            release_controls,
            uploaded_prior_to,
            target_python: compatibility.python_version,
            target_implementation: compatibility.implementation,
            target_platforms: compatibility.platforms,
            target_abis: compatibility.abis,
        },
    )?;
    let latest = listing.versions.first().cloned().unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "name": listing.name,
                "latest": latest,
                "versions": listing.versions,
            }))?
        );
    } else {
        println!("{} ({latest})", listing.name);
        println!("Available versions: {}", listing.versions.join(", "));
    }
    Ok(())
}

pub(crate) fn print_pip_search_deprecated(query: Vec<String>) -> Result<ExitCode, OmcRegistryError> {
    if query.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip search needs at least one search term".to_owned(),
        ));
    }
    eprintln!("ERROR: XMLRPC request failed [code: -32500]");
    eprintln!(
        "RuntimeError: PyPI no longer supports 'pip search' (or XML-RPC search). Please use https://pypi.org/search (via a browser) instead. See https://warehouse.pypa.io/api-reference/xml-rpc.html#deprecated-methods for more information."
    );
    Ok(ExitCode::FAILURE)
}

pub(crate) fn print_pip_hash(
    project_dir: &Path,
    algorithm: PipHashAlgorithm,
    paths: Vec<PathBuf>,
) -> Result<(), OmcRegistryError> {
    for path in paths {
        let resolved = absolutize_path(project_dir, path.clone());
        let bytes = fs::read(&resolved)?;
        println!("{}:", path.display());
        println!(
            "--hash={}:{}",
            algorithm.name(),
            pip_hash_digest(algorithm, &bytes)
        );
    }
    Ok(())
}

pub(crate) fn print_pip_cache(
    project_dir: &Path,
    action: PipCacheAction,
    cache_dir: Option<&Path>,
) -> Result<ExitCode, OmcRegistryError> {
    let cache_dir = cache_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| pip_cache_dir(project_dir));
    match action {
        PipCacheAction::Dir => println!("{}", cache_dir.display()),
        PipCacheAction::Info => {
            for line in pip_cache_info_lines(&cache_dir)? {
                println!("{line}");
            }
        }
        PipCacheAction::List { pattern, format } => {
            for line in pip_cache_list_lines(&cache_dir, pattern.as_deref(), format)? {
                println!("{line}");
            }
        }
        PipCacheAction::Remove { pattern } => {
            let mut files = compat_cache_files(&cache_dir)?;
            files.retain(|path| compat_cache_pattern_matches(path, &cache_dir, &pattern));
            if files.is_empty() {
                eprintln!("ERROR: No matching packages");
                return Ok(ExitCode::FAILURE);
            }
            let count = remove_cache_files(&files)?;
            prune_empty_cache_dirs(&cache_dir)?;
            println!("Files removed: {count}");
        }
        PipCacheAction::Purge => {
            let count = compat_cache_files(&cache_dir)?.len();
            if cache_dir.exists() {
                fs::remove_dir_all(&cache_dir)?;
            }
            println!("Files removed: {count}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_pip_debug(
    project_dir: &Path,
    invocation_cwd: &Path,
    action: PipDebugAction,
) -> Result<(), OmcRegistryError> {
    print!(
        "{}",
        pip_debug_report(project_dir, invocation_cwd, &action)?
    );
    Ok(())
}

pub(crate) fn print_pip_path_freeze(
    project_dir: &Path,
    paths: &[PathBuf],
    exclude: &[String],
    exclude_editable: bool,
    requirements: &[PathBuf],
) -> Result<(), OmcRegistryError> {
    let excluded = pip_excluded_names(exclude);
    let entries = read_pip_path_packages(project_dir, paths, exclude, PipEditableMode::Exclude)?
        .into_iter()
        .map(|package| PipFrozenRequirement {
            name: Some(normalize_pip_show_name(&package.name)),
            line: format!("{}=={}", package.name, package.version),
        })
        .chain(if exclude_editable {
            Vec::new()
        } else {
            pip_freeze_path_local_entries(project_dir, paths, &excluded)?
        })
        .collect::<Vec<_>>();
    print_pip_freeze_output(pip_freeze_output(project_dir, entries, requirements)?);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PipFreezeOutput {
    pub(crate) warnings: Vec<String>,
    pub(crate) lines: Vec<String>,
}

pub(crate) fn pip_freeze_output(
    project_dir: &Path,
    entries: Vec<PipFrozenRequirement>,
    requirements: &[PathBuf],
) -> Result<PipFreezeOutput, OmcRegistryError> {
    if requirements.is_empty() {
        return Ok(PipFreezeOutput {
            warnings: Vec::new(),
            lines: entries.into_iter().map(|entry| entry.line).collect(),
        });
    }

    let mut by_name = BTreeMap::new();
    for entry in &entries {
        if let Some(name) = &entry.name {
            by_name.insert(name.clone(), entry.line.clone());
        }
    }

    let mut emitted = BTreeSet::new();
    let mut emitted_lines = BTreeSet::new();
    let mut output = PipFreezeOutput::default();
    for requirement in requirements {
        let path = absolutize_path(project_dir, requirement.clone());
        let content = fs::read_to_string(&path)?;
        for line in content.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                emitted_lines.insert(line.to_owned());
                output.lines.push(line.to_owned());
                continue;
            }

            let Some(name) = pip_requirement_line_name(line) else {
                emitted_lines.insert(line.to_owned());
                output.lines.push(line.to_owned());
                continue;
            };
            if let Some(frozen) = by_name.get(&name) {
                if emitted.insert(name) {
                    emitted_lines.insert(frozen.clone());
                    output.lines.push(frozen.clone());
                }
            } else {
                output.warnings.push(format!(
                    "WARNING: Requirement file [{}] contains {}, but package '{}' is not installed",
                    path.display(),
                    line.trim(),
                    name
                ));
            }
        }
    }

    let remaining = entries
        .into_iter()
        .filter(|entry| {
            if let Some(name) = entry.name.as_deref() {
                !emitted.contains(name) && !emitted_lines.contains(&entry.line)
            } else {
                !emitted_lines.contains(&entry.line)
            }
        })
        .map(|entry| entry.line)
        .collect::<Vec<_>>();
    if !remaining.is_empty() {
        output
            .lines
            .push("## The following requirements were added by pip freeze:".to_owned());
        output.lines.extend(remaining);
    }

    Ok(output)
}

pub(crate) fn print_pip_freeze_output(output: PipFreezeOutput) {
    for warning in output.warnings {
        eprintln!("{warning}");
    }
    for line in output.lines {
        println!("{line}");
    }
}

#[cfg(test)]
pub(crate) fn pip_freeze_local_path_requirements(project_dir: &Path) -> Result<Vec<String>, OmcRegistryError> {
    let local_paths_file = project_dir.join(".omc").join("python").join("local-paths");
    Ok(
        pip_freeze_local_path_entries_from_file(local_paths_file, &BTreeSet::new())?
            .into_iter()
            .map(|entry| entry.line)
            .collect(),
    )
}

pub(crate) fn pip_freeze_local_path_entries(
    project_dir: &Path,
    excluded: &BTreeSet<String>,
) -> Result<Vec<PipFrozenRequirement>, OmcRegistryError> {
    pip_freeze_local_path_entries_from_file(
        project_dir.join(".omc").join("python").join("local-paths"),
        excluded,
    )
}

pub(crate) fn pip_freeze_path_local_entries(
    project_dir: &Path,
    paths: &[PathBuf],
    excluded: &BTreeSet<String>,
) -> Result<Vec<PipFrozenRequirement>, OmcRegistryError> {
    let mut entries = Vec::new();
    for path in paths {
        let site_packages = absolutize_path(project_dir, path.clone());
        entries.extend(pip_freeze_local_path_entries_from_file(
            site_packages.join(".omc-local-paths"),
            excluded,
        )?);
    }
    entries.sort_by(|left, right| left.line.cmp(&right.line));
    entries.dedup_by(|left, right| left.line == right.line);
    Ok(entries)
}

pub(crate) fn pip_freeze_local_path_entries_from_file(
    local_paths_file: PathBuf,
    excluded: &BTreeSet<String>,
) -> Result<Vec<PipFrozenRequirement>, OmcRegistryError> {
    let content = match fs::read_to_string(local_paths_file) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut entries = Vec::new();
    for path in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<BTreeSet<_>>()
    {
        let import_path = Path::new(path);
        if pip_freeze_is_omc_vcs_import_path(import_path) {
            continue;
        }
        let name = pip_local_editable_package(import_path)?
            .map(|package| normalize_pip_show_name(&package.name));
        if name
            .as_ref()
            .is_some_and(|name| excluded.contains(name.as_str()))
        {
            continue;
        }
        entries.push(PipFrozenRequirement {
            name,
            line: format!("-e {path}"),
        });
    }
    Ok(entries)
}

pub(crate) fn pip_freeze_is_omc_vcs_import_path(path: &Path) -> bool {
    let mut state = 0;
    for component in path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
    {
        state = match (state, component) {
            (_, ".omc") => 1,
            (1, "python") => 2,
            (2, "vcs") => return true,
            _ => 0,
        };
    }
    false
}

pub(crate) fn pip_freeze_vcs_requirement(dependency: &LockedPythonVcsDependency) -> String {
    let mut name = dependency.name.clone();
    if !dependency.extras.is_empty() {
        name.push('[');
        name.push_str(&dependency.extras.join(","));
        name.push(']');
    }

    let reference = if dependency.resolved_commit.is_empty() {
        dependency.reference.as_deref().unwrap_or_default()
    } else {
        dependency.resolved_commit.as_str()
    };
    let mut url = format!("git+{}", dependency.url);
    if !reference.is_empty() {
        url.push('@');
        url.push_str(reference);
    }
    if let Some(subdirectory) = &dependency.subdirectory {
        if !subdirectory.is_empty() {
            url.push_str("#subdirectory=");
            url.push_str(subdirectory);
        }
    }

    format!("{name} @ {url}")
}

pub(crate) fn print_locked_pip_list(
    project_dir: &Path,
    format: PipListFormat,
    verbose: bool,
    exclude: &[String],
    editable: PipEditableMode,
    not_required: bool,
) -> Result<(), OmcRegistryError> {
    let mut packages = locked_pip_installed_packages(project_dir, exclude, editable)?;
    if not_required {
        packages = pip_not_required_packages(packages);
    }
    print_pip_installed_list(format, verbose, &packages)
}

pub(crate) fn print_pip_path_list(
    project_dir: &Path,
    format: PipListFormat,
    verbose: bool,
    paths: &[PathBuf],
    exclude: &[String],
    editable: PipEditableMode,
    not_required: bool,
) -> Result<(), OmcRegistryError> {
    let mut packages = read_pip_path_packages(project_dir, paths, exclude, editable)?;
    if not_required {
        packages = pip_not_required_packages(packages);
    }
    print_pip_installed_list(format, verbose, &packages)
}

pub(crate) fn print_pip_installed_list(
    format: PipListFormat,
    verbose: bool,
    packages: &[InstalledPythonPackage],
) -> Result<(), OmcRegistryError> {
    match format {
        PipListFormat::Columns => {
            if let Some(output) = pip_columns_list_output(packages, verbose) {
                print!("{output}");
            }
        }
        PipListFormat::Freeze => {
            for package in packages {
                println!("{}=={}", package.name, package.version);
            }
        }
        PipListFormat::Json => {
            println!("{}", pip_installed_list_json_output(packages, verbose)?);
        }
    }
    Ok(())
}

pub(crate) fn print_locked_pip_inspect(project_dir: &Path) -> Result<(), OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let mut installed = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .map(|package| {
            let metadata_location = match_dist_info_dir(&site_packages, &package)?
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| site_packages.display().to_string());
            Ok(serde_json::json!({
                "metadata": {
                    "name": package.name,
                    "version": package.version,
                },
                "metadata_location": metadata_location,
                "installer": "omc",
                "requested": false,
                "dependencies": package.dependencies,
            }))
        })
        .collect::<Result<Vec<_>, OmcRegistryError>>()?;
    installed.extend(
        pip_project_local_path_packages(project_dir, &[])?
            .into_iter()
            .map(pip_inspect_installed_package)
            .collect::<Vec<_>>(),
    );
    let value = serde_json::json!({
        "version": "1",
        "pip_version": format!("omc-{}", env!("CARGO_PKG_VERSION")),
        "installed": installed,
        "environment": {},
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) fn print_pip_path_inspect(project_dir: &Path, paths: &[PathBuf]) -> Result<(), OmcRegistryError> {
    let installed = pip_path_inspect_entries(project_dir, paths)?;
    let value = serde_json::json!({
        "version": "1",
        "pip_version": format!("omc-{}", env!("CARGO_PKG_VERSION")),
        "installed": installed,
        "environment": {},
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) fn print_pip_outdated(
    project_dir: &Path,
    options: PipOutdatedOptions<'_>,
) -> Result<(), OmcRegistryError> {
    if options.paths.is_empty() {
        return print_locked_pip_outdated(project_dir, options);
    }

    let mut packages = read_pip_path_packages(
        project_dir,
        options.paths,
        options.exclude,
        options.editable,
    )?;
    if options.not_required {
        packages = pip_not_required_packages(packages);
    }
    let mut rows = Vec::new();
    for package in packages {
        let listing = match read_pypi_available_versions(
            project_dir,
            &package.name,
            pypi_available_versions_options(
                options.index_url.clone(),
                options.extra_index_urls.clone(),
                options.find_links.clone(),
                options.no_index,
                options.allow_prereleases,
            ),
        ) {
            Ok(listing) => listing,
            Err(OmcRegistryError::PackageNotFound(_)) => continue,
            Err(error) => return Err(error),
        };
        let Some(latest_version) = listing.versions.first() else {
            continue;
        };
        if pip_version_status_matches(latest_version, &package.version, options.uptodate) {
            rows.push(PipOutdatedPackage {
                name: package.name,
                version: package.version,
                latest_version: latest_version.clone(),
                latest_filetype: "wheel".to_owned(),
                install_location: package.install_location,
                installer: "omc".to_owned(),
            });
        }
    }
    print_pip_outdated_rows(options.format, options.verbose, rows)
}

pub(crate) fn print_locked_pip_outdated(
    project_dir: &Path,
    options: PipOutdatedOptions<'_>,
) -> Result<(), OmcRegistryError> {
    let excluded = pip_excluded_names(options.exclude);
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let site_packages = project_dir
        .join(".omc")
        .join("python")
        .join("site-packages");
    let required = if options.not_required {
        lock.packages
            .iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .flat_map(|package| package.dependencies.iter())
            .filter_map(|dependency| pip_installed_dependency_name(dependency))
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let mut rows = Vec::new();
    if options.editable.includes_regular() {
        for package in lock
            .packages
            .into_iter()
            .filter(|package| package.ecosystem == Ecosystem::Pypi)
            .filter(|package| !pip_name_excluded(&package.name, &excluded))
            .filter(|package| {
                !options.not_required || !required.contains(&normalize_pip_show_name(&package.name))
            })
        {
            let listing = match read_pypi_available_versions(
                project_dir,
                &package.name,
                pypi_available_versions_options(
                    options.index_url.clone(),
                    options.extra_index_urls.clone(),
                    options.find_links.clone(),
                    options.no_index,
                    options.allow_prereleases,
                ),
            ) {
                Ok(listing) => listing,
                Err(OmcRegistryError::PackageNotFound(_)) => continue,
                Err(error) => return Err(error),
            };
            let Some(latest_version) = listing.versions.first() else {
                continue;
            };
            if pip_version_status_matches(latest_version, &package.version, options.uptodate) {
                let metadata_location = match_dist_info_dir(&site_packages, &package)?;
                let install_location = metadata_location
                    .as_deref()
                    .and_then(Path::parent)
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| site_packages.clone());
                rows.push(PipOutdatedPackage {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    latest_version: latest_version.clone(),
                    latest_filetype: pip_locked_package_filetype(&package).to_owned(),
                    install_location: Some(install_location),
                    installer: "omc".to_owned(),
                });
            }
        }
    }
    if options.editable.includes_editables() {
        for package in pip_project_local_path_packages(project_dir, options.exclude)? {
            if options.not_required && required.contains(&normalize_pip_show_name(&package.name)) {
                continue;
            }
            let listing = match read_pypi_available_versions(
                project_dir,
                &package.name,
                pypi_available_versions_options(
                    options.index_url.clone(),
                    options.extra_index_urls.clone(),
                    options.find_links.clone(),
                    options.no_index,
                    options.allow_prereleases,
                ),
            ) {
                Ok(listing) => listing,
                Err(OmcRegistryError::PackageNotFound(_)) => continue,
                Err(error) => return Err(error),
            };
            let Some(latest_version) = listing.versions.first() else {
                continue;
            };
            if pip_version_status_matches(latest_version, &package.version, options.uptodate) {
                rows.push(PipOutdatedPackage {
                    name: package.name,
                    version: package.version,
                    latest_version: latest_version.clone(),
                    latest_filetype: "editable".to_owned(),
                    install_location: package.install_location,
                    installer: "omc".to_owned(),
                });
            }
        }
    }
    print_pip_outdated_rows(options.format, options.verbose, rows)
}

pub(crate) fn print_pip_outdated_rows(
    format: PipListFormat,
    verbose: bool,
    mut rows: Vec<PipOutdatedPackage>,
) -> Result<(), OmcRegistryError> {
    rows.sort_by(|left, right| left.name.cmp(&right.name));

    match format {
        PipListFormat::Columns => {
            if !rows.is_empty() {
                let headers = if verbose {
                    vec![
                        "Package",
                        "Version",
                        "Latest",
                        "Type",
                        "Location",
                        "Installer",
                    ]
                } else {
                    vec!["Package", "Version", "Latest", "Type"]
                };
                let rows = rows
                    .into_iter()
                    .map(|row| {
                        let mut values = vec![
                            row.name,
                            row.version,
                            row.latest_version,
                            row.latest_filetype,
                        ];
                        if verbose {
                            values.push(
                                row.install_location
                                    .map(|path| path.display().to_string())
                                    .unwrap_or_default(),
                            );
                            values.push(row.installer);
                        }
                        values
                    })
                    .collect::<Vec<_>>();
                let widths = headers
                    .iter()
                    .enumerate()
                    .map(|(index, header)| {
                        rows.iter()
                            .map(|row| row[index].len())
                            .chain(std::iter::once(header.len()))
                            .max()
                            .unwrap_or(header.len())
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    pip_columns_join_row(
                        &headers
                            .iter()
                            .map(|value| value.to_string())
                            .collect::<Vec<_>>(),
                        &widths,
                    )
                );
                println!(
                    "{}",
                    pip_columns_join_row(
                        &widths
                            .iter()
                            .map(|width| "-".repeat(*width))
                            .collect::<Vec<_>>(),
                        &widths,
                    )
                );
                for row in rows {
                    println!("{}", pip_columns_join_row(&row, &widths));
                }
            }
        }
        PipListFormat::Json => {
            println!("{}", pip_outdated_rows_json_output(&rows, verbose)?);
        }
        PipListFormat::Freeze => {
            for row in rows {
                println!("{}=={}", row.name, row.version);
            }
        }
    }
    Ok(())
}

pub(crate) fn print_locked_pip_show(
    project_dir: &Path,
    specs: &[String],
    include_files: bool,
) -> Result<ExitCode, OmcRegistryError> {
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip show needs at least one package".to_owned(),
        ));
    }

    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let packages = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Pypi)
        .collect::<Vec<_>>();
    let editable_packages = pip_project_local_path_packages(project_dir, &[])?;
    let mut missing = Vec::new();
    let mut printed = false;
    for spec in specs {
        let normalized = normalize_pip_show_name(spec);
        if let Some(package) = packages
            .iter()
            .find(|package| normalize_pip_show_name(&package.name) == normalized)
        {
            if printed {
                println!("---");
            }
            print_pip_show_package(project_dir, package, &packages, include_files)?;
            printed = true;
            continue;
        }
        if let Some(package) = editable_packages
            .iter()
            .find(|package| normalize_pip_show_name(&package.name) == normalized)
        {
            if printed {
                println!("---");
            }
            print_pip_show_editable_package(package, &packages, include_files)?;
            printed = true;
            continue;
        }
        missing.push(spec.clone());
    }

    if !missing.is_empty() {
        eprintln!("WARNING: Package(s) not found: {}", missing.join(", "));
        return Ok(ExitCode::FAILURE);
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_pip_path_show(
    project_dir: &Path,
    paths: &[PathBuf],
    specs: &[String],
    include_files: bool,
) -> Result<ExitCode, OmcRegistryError> {
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "pip show needs at least one package".to_owned(),
        ));
    }

    let packages = read_pip_path_packages(project_dir, paths, &[], PipEditableMode::Include)?;
    let mut missing = Vec::new();
    let mut printed = false;
    for spec in specs {
        let normalized = normalize_pip_show_name(spec);
        if let Some(package) = packages
            .iter()
            .find(|package| normalize_pip_show_name(&package.name) == normalized)
        {
            if printed {
                println!("---");
            }
            print_pip_show_installed_package(package, &packages, include_files)?;
            printed = true;
        } else {
            missing.push(spec.clone());
        }
    }

    if !missing.is_empty() {
        eprintln!("WARNING: Package(s) not found: {}", missing.join(", "));
        return Ok(ExitCode::FAILURE);
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn print_locked_pip_check(project_dir: &Path) -> Result<ExitCode, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let issues = pip_check_installed_packages(project_dir, &lock)?;
    print_pip_check_issues(issues)
}

pub(crate) fn print_pip_path_check(
    project_dir: &Path,
    paths: &[PathBuf],
) -> Result<ExitCode, OmcRegistryError> {
    let packages = read_pip_path_packages(project_dir, paths, &[], PipEditableMode::Include)?;
    let issues = pip_check_installed_package_set(&packages);
    print_pip_check_issues(issues)
}

pub(crate) fn print_pip_check_issues(issues: Vec<PypiCheckIssue>) -> Result<ExitCode, OmcRegistryError> {
    if issues.is_empty() {
        println!("No broken requirements found.");
        return Ok(ExitCode::SUCCESS);
    }

    for issue in issues {
        match issue {
            PypiCheckIssue::Missing {
                package,
                version,
                requirement,
            } => {
                println!("{package} {version} requires {requirement}, which is not installed.");
            }
            PypiCheckIssue::Incompatible {
                package,
                version,
                requirement,
                installed_name,
                installed_version,
            } => {
                println!(
                    "{package} {version} has requirement {requirement}, but you have {installed_name} {installed_version}."
                );
            }
        }
    }
    Ok(ExitCode::FAILURE)
}

pub(crate) fn print_pip_show_package(
    project_dir: &Path,
    package: &LockedPackage,
    packages: &[LockedPackage],
    include_files: bool,
) -> Result<(), OmcRegistryError> {
    let site_packages = absolute_project_dir(project_dir)
        .join(".omc")
        .join("python")
        .join("site-packages");
    let metadata = read_pip_show_metadata(&site_packages, package)?;
    let requires = if metadata.requires.is_empty() {
        pip_dependency_names(package)
    } else {
        metadata.requires
    };
    println!("Name: {}", package.name);
    println!("Version: {}", package.version);
    println!("Summary: {}", metadata.summary.unwrap_or_default());
    println!(
        "Home-page: {}",
        metadata
            .home_page
            .unwrap_or_else(|| package.source_url.clone())
    );
    println!("Author: {}", metadata.author.unwrap_or_default());
    println!(
        "Author-email: {}",
        metadata.author_email.unwrap_or_default()
    );
    println!("License: {}", metadata.license.unwrap_or_default());
    println!("Location: {}", site_packages.display());
    println!("Requires: {}", requires.join(", "));
    println!(
        "Required-by: {}",
        pip_required_by_names(package, packages).join(", ")
    );
    if include_files {
        println!("Files:");
        for file in pip_installed_files(&site_packages, package)? {
            println!("  {file}");
        }
    }
    Ok(())
}

pub(crate) fn print_pip_show_editable_package(
    package: &InstalledPythonPackage,
    packages: &[LockedPackage],
    include_files: bool,
) -> Result<(), OmcRegistryError> {
    let location = package
        .editable_project_location
        .as_ref()
        .cloned()
        .unwrap_or_default();
    let metadata = read_python_project_show_metadata(&pip_editable_project_root(&location))?;
    let requires = if metadata.requires.is_empty() {
        package.dependencies.clone()
    } else {
        metadata.requires
    };
    println!("Name: {}", package.name);
    println!("Version: {}", package.version);
    println!("Summary: {}", metadata.summary.unwrap_or_default());
    println!("Home-page: {}", metadata.home_page.unwrap_or_default());
    println!("Author: {}", metadata.author.unwrap_or_default());
    println!(
        "Author-email: {}",
        metadata.author_email.unwrap_or_default()
    );
    println!("License: {}", metadata.license.unwrap_or_default());
    println!("Location: {}", location.display());
    println!("Requires: {}", requires.join(", "));
    println!(
        "Required-by: {}",
        pip_required_by_package_name(&package.name, packages).join(", ")
    );
    if include_files {
        println!("Files:");
        print_pip_show_files_or_missing(pip_editable_project_files(&location)?);
    }
    Ok(())
}

pub(crate) fn print_pip_show_installed_package(
    package: &InstalledPythonPackage,
    packages: &[InstalledPythonPackage],
    include_files: bool,
) -> Result<(), OmcRegistryError> {
    let metadata = if let Some(dist_info) = &package.metadata_location {
        read_pip_show_metadata_from_dist_info(dist_info)?
    } else if let Some(location) = &package.editable_project_location {
        read_python_project_show_metadata(&pip_editable_project_root(location))?
    } else {
        PipShowMetadata::default()
    };
    let requires = if metadata.requires.is_empty() {
        package
            .dependencies
            .iter()
            .filter_map(|dependency| pip_installed_dependency_name(dependency))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        metadata.requires
    };
    let location = package
        .metadata_location
        .as_ref()
        .and_then(|path| path.parent())
        .or(package.editable_project_location.as_deref())
        .map(Path::to_path_buf)
        .unwrap_or_default();
    println!("Name: {}", package.name);
    println!("Version: {}", package.version);
    println!("Summary: {}", metadata.summary.unwrap_or_default());
    println!("Home-page: {}", metadata.home_page.unwrap_or_default());
    println!("Author: {}", metadata.author.unwrap_or_default());
    println!(
        "Author-email: {}",
        metadata.author_email.unwrap_or_default()
    );
    println!("License: {}", metadata.license.unwrap_or_default());
    println!("Location: {}", location.display());
    println!("Requires: {}", requires.join(", "));
    println!(
        "Required-by: {}",
        pip_required_by_installed_package_name(&package.name, packages).join(", ")
    );
    if include_files {
        println!("Files:");
        if let Some(dist_info) = &package.metadata_location {
            for file in pip_installed_files_from_dist_info(dist_info)? {
                println!("  {file}");
            }
        } else if let Some(location) = &package.editable_project_location {
            print_pip_show_files_or_missing(pip_editable_project_files(location)?);
        } else {
            println!("Cannot locate RECORD or installed-files.txt");
        }
    }
    Ok(())
}

pub(crate) fn print_pip_show_files_or_missing(files: Vec<String>) {
    if files.is_empty() {
        println!("Cannot locate RECORD or installed-files.txt");
        return;
    }
    for file in files {
        println!("  {file}");
    }
}
