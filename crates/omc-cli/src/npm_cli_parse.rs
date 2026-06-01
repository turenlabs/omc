//! npm CLI compat: shared parse/print/path helpers.

use crate::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use omc_registry::{NpmDistTagMutationResult, OmcRegistryError};

use crate::args::{
    NpmCompatAction, NpmConfigLocation, NpmDistTagAction, NpmDoctorAction, NpmInitAction,
    NpmListAction, NpmPkgAction, NpmSbomAction, NpmSbomFormat, NpmSbomType, NpmVersionAction,
};

pub(crate) fn append_npm_save_location_default_args_from_env(args: &mut Vec<String>) {
    append_npm_save_location_default_arg_from_env(args, "save-prod", "--save-prod");
    append_npm_save_location_default_arg_from_env(args, "save-dev", "--save-dev");
    append_npm_save_location_default_arg_from_env(args, "save-optional", "--save-optional");
    append_npm_save_location_default_arg_from_env(args, "save-peer", "--save-peer");
}

pub(crate) fn append_npm_save_location_default_arg_from_env(
    args: &mut Vec<String>,
    key: &str,
    flag: &str,
) {
    if npm_config_env(key)
        .map(|value| config_bool(&value))
        .unwrap_or(false)
    {
        args.push(flag.to_owned());
    }
}

pub(crate) fn append_npm_bool_default_arg(
    args: &mut Vec<String>,
    key: &str,
    true_arg: &str,
    false_arg: &str,
) {
    if let Some(value) = npm_config_env(key) {
        if config_bool(&value) {
            args.push(true_arg.to_owned());
        } else if config_false(&value) {
            args.push(false_arg.to_owned());
        }
    }
}

pub(crate) fn parse_npm_cli_config_defaults_content(
    content: &str,
    values: &mut BTreeMap<String, String>,
) {
    for raw_line in content.lines() {
        let line = strip_npm_config_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if !npm_cli_default_config_key(&key) {
            continue;
        }
        let Some(value) = expand_npm_config_default_value(value.trim()) else {
            continue;
        };
        values.insert(key, value);
    }
}

pub(crate) fn append_npm_default_args_from_config(
    values: &BTreeMap<String, String>,
    args: &mut Vec<String>,
) {
    if values
        .get("production")
        .map(|value| config_bool(value))
        .unwrap_or(false)
    {
        args.push("--omit=dev".to_owned());
    } else if values
        .get("production")
        .map(|value| config_false(value))
        .unwrap_or(false)
    {
        args.push("--include=dev".to_owned());
    }

    if let Some(only) = values.get("only") {
        append_npm_only_default_args(only, args);
    }

    if let Some(optional) = values.get("optional") {
        if config_false(optional) {
            args.push("--omit=optional".to_owned());
        } else if config_bool(optional) {
            args.push("--include=optional".to_owned());
        }
    }

    if let Some(also) = values.get("also") {
        append_npm_also_default_args(also, args);
    }

    if let Some(omit) = values.get("omit").filter(|value| !value.trim().is_empty()) {
        args.push("--include=dev,optional,peer".to_owned());
        args.push(format!("--omit={omit}"));
    }
    if let Some(include) = values
        .get("include")
        .filter(|value| !value.trim().is_empty())
    {
        args.push(format!("--include={include}"));
    }
    append_npm_bool_arg_from_config(values, args, "global", "--global", "--global=false");
    append_npm_bool_arg_from_config(values, args, "dry-run", "--dry-run", "--dry-run=false");
    append_npm_bool_arg_from_config(
        values,
        args,
        "package-lock-only",
        "--package-lock-only",
        "--package-lock-only=false",
    );
    append_npm_bool_arg_from_config(
        values,
        args,
        "package-lock",
        "--package-lock",
        "--package-lock=false",
    );
    append_npm_bool_arg_from_config(
        values,
        args,
        "engine-strict",
        "--engine-strict",
        "--engine-strict=false",
    );
    append_npm_bool_arg_from_config(values, args, "offline", "--offline", "--offline=false");
    append_npm_save_location_default_args_from_config(values, args);
    if let Some(save_exact) = values.get("save-exact") {
        if config_bool(save_exact) {
            args.push("--save-exact".to_owned());
        } else if config_false(save_exact) {
            args.push("--save-exact=false".to_owned());
        }
    }
    append_npm_bool_arg_from_config(
        values,
        args,
        "save-bundle",
        "--save-bundle",
        "--save-bundle=false",
    );
    if let Some(save) = values.get("save") {
        if config_bool(save) {
            args.push("--save".to_owned());
        } else if config_false(save) {
            args.push("--no-save".to_owned());
        }
    }
    if let Some(save_prefix) = values
        .get("save-prefix")
        .filter(|value| !value.trim().is_empty())
    {
        args.push(format!("--save-prefix={save_prefix}"));
    }
    if let Some(min_release_age) = values
        .get("min-release-age")
        .filter(|value| !value.trim().is_empty())
    {
        args.push(format!("--min-release-age={min_release_age}"));
    }
    if let Some(before) = values
        .get("before")
        .filter(|value| !value.trim().is_empty())
    {
        args.push(format!("--before={before}"));
    }
}

pub(crate) fn append_npm_save_location_default_args_from_config(
    values: &BTreeMap<String, String>,
    args: &mut Vec<String>,
) {
    append_npm_save_location_default_arg_from_config(values, args, "save-prod", "--save-prod");
    append_npm_save_location_default_arg_from_config(values, args, "save-dev", "--save-dev");
    append_npm_save_location_default_arg_from_config(
        values,
        args,
        "save-optional",
        "--save-optional",
    );
    append_npm_save_location_default_arg_from_config(values, args, "save-peer", "--save-peer");
}

pub(crate) fn append_npm_save_location_default_arg_from_config(
    values: &BTreeMap<String, String>,
    args: &mut Vec<String>,
    key: &str,
    flag: &str,
) {
    if values
        .get(key)
        .map(|value| config_bool(value))
        .unwrap_or(false)
    {
        args.push(flag.to_owned());
    }
}

pub(crate) fn append_npm_only_default_args(value: &str, args: &mut Vec<String>) {
    if npm_dependency_set_contains(value, "production")
        || npm_dependency_set_contains(value, "prod")
    {
        args.push("--omit=dev".to_owned());
    } else if npm_dependency_set_contains(value, "development")
        || npm_dependency_set_contains(value, "dev")
    {
        args.push("--include=dev".to_owned());
    }
}

pub(crate) fn append_npm_also_default_args(value: &str, args: &mut Vec<String>) {
    let mut include = Vec::new();
    if npm_dependency_set_contains(value, "development")
        || npm_dependency_set_contains(value, "dev")
    {
        include.push("dev");
    }
    if npm_dependency_set_contains(value, "optional") {
        include.push("optional");
    }
    if npm_dependency_set_contains(value, "peer") {
        include.push("peer");
    }
    if !include.is_empty() {
        args.push(format!("--include={}", include.join(",")));
    }
}

pub(crate) fn append_npm_bool_arg_from_config(
    values: &BTreeMap<String, String>,
    args: &mut Vec<String>,
    key: &str,
    true_arg: &str,
    false_arg: &str,
) {
    if let Some(value) = values.get(key) {
        if config_bool(value) {
            args.push(true_arg.to_owned());
        } else if config_false(value) {
            args.push(false_arg.to_owned());
        }
    }
}

pub(crate) fn absolutize_npm_diff_action_paths(
    base_dir: &Path,
    action: &mut NpmDiffAction,
) -> Result<(), OmcRegistryError> {
    action.specs = std::mem::take(&mut action.specs)
        .into_iter()
        .map(|spec| absolutize_npm_diff_spec(base_dir, spec))
        .collect::<Result<Vec<_>, _>>()?;
    action.userconfig = action
        .userconfig
        .take()
        .map(|path| absolutize_path(base_dir, path));
    Ok(())
}

pub(crate) fn absolutize_npm_diff_spec(
    base_dir: &Path,
    spec: String,
) -> Result<String, OmcRegistryError> {
    if is_npm_local_directory_arg(&spec) {
        let path = absolutize_path(base_dir, npm_local_path_arg(&spec)?);
        return Ok(path.display().to_string());
    }
    if is_npm_archive_arg(&spec) {
        return Ok(absolutize_npm_archive_reference(base_dir, &spec));
    }
    Ok(spec)
}

pub(crate) fn absolutize_npm_dist_tag_action_paths(base_dir: &Path, action: &mut NpmDistTagAction) {
    match action {
        NpmDistTagAction::List { userconfig, .. }
        | NpmDistTagAction::Add { userconfig, .. }
        | NpmDistTagAction::Remove { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn print_npm_path(
    project_dir: &Path,
    kind: NpmPathKind,
    global: bool,
) -> Result<(), OmcRegistryError> {
    let project_dir = absolute_project_dir(project_dir);
    let path = if global {
        let prefix = npm_global_prefix_path();
        match kind {
            NpmPathKind::Bin => npm_global_bin_dir_from_prefix(&prefix),
            NpmPathKind::Root => npm_global_project_dir_from_prefix(&prefix).join("node_modules"),
            NpmPathKind::Prefix => prefix,
        }
    } else {
        match kind {
            NpmPathKind::Bin => project_dir.join("node_modules").join(".bin"),
            NpmPathKind::Root => project_dir.join("node_modules"),
            NpmPathKind::Prefix => project_dir,
        }
    };
    println!("{}", path.display());
    Ok(())
}

pub(crate) fn print_npm_help(topic: Option<&str>) {
    print!("{}", npm_help_text(topic));
}

pub(crate) fn print_npm_help_search(query: &[String], long: bool) -> Result<(), OmcRegistryError> {
    print!("{}", npm_help_search_text(query, long)?);
    Ok(())
}

pub(crate) fn print_npm_completion(
    project_dir: &Path,
    words: Option<Vec<String>>,
) -> Result<(), OmcRegistryError> {
    if let Some(words) = words {
        for suggestion in npm_completion_suggestions(project_dir, &words) {
            println!("{suggestion}");
        }
    } else {
        print!("{}", npm_completion_script());
    }
    Ok(())
}

pub(crate) fn print_npm_config(
    project_dir: &Path,
    action: NpmConfigAction,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
    globalconfig: Option<&Path>,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmConfigAction::Set {
            assignments,
            location,
        } => {
            write_npm_config_assignments(
                project_dir,
                userconfig,
                globalconfig,
                location,
                &assignments,
            )?;
            return Ok(());
        }
        NpmConfigAction::Delete { keys, location } => {
            delete_npm_config_keys(project_dir, userconfig, globalconfig, location, &keys)?;
            return Ok(());
        }
        NpmConfigAction::Get { .. } | NpmConfigAction::List { .. } => {}
    }

    let location = match &action {
        NpmConfigAction::Get { location, .. } | NpmConfigAction::List { location, .. } => *location,
        NpmConfigAction::Set { .. } | NpmConfigAction::Delete { .. } => unreachable!(),
    };
    let values = npm_config_values(
        project_dir,
        npm_registry,
        userconfig,
        globalconfig,
        location,
    )?;
    match action {
        NpmConfigAction::Get { keys, json, .. } => {
            if json {
                if keys.len() == 1 {
                    let value = npm_config_value_for_key(&values, &keys[0]);
                    println!("{}", serde_json::to_string_pretty(&value)?);
                } else {
                    let selected = keys
                        .into_iter()
                        .map(|key| {
                            let value = npm_config_value_for_key(&values, &key);
                            (key, value)
                        })
                        .collect::<BTreeMap<_, _>>();
                    println!("{}", serde_json::to_string_pretty(&selected)?);
                }
            } else {
                for key in keys {
                    println!("{}", npm_config_value_for_key(&values, &key));
                }
            }
        }
        NpmConfigAction::List { json, .. } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&values)?);
            } else {
                for (key, value) in values {
                    println!("{key} = {value}");
                }
            }
        }
        NpmConfigAction::Set { .. } | NpmConfigAction::Delete { .. } => unreachable!(),
    }
    Ok(())
}

pub(crate) fn absolutize_npm_archive_references(
    base_dir: &Path,
    references: Vec<String>,
) -> Vec<String> {
    references
        .into_iter()
        .map(|reference| absolutize_npm_archive_reference(base_dir, &reference))
        .collect()
}

pub(crate) fn absolutize_npm_archive_reference(base_dir: &Path, reference: &str) -> String {
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return reference.to_owned();
    }
    let (scheme, value) = reference
        .strip_prefix("file:")
        .map(|value| ("file:", value))
        .unwrap_or(("", reference));
    let (path, suffix) = split_npm_archive_suffix(value);
    if !npm_archive_reference_is_local(path) {
        return reference.to_owned();
    }
    let path = expand_cli_local_path(path, base_dir);
    format!("{scheme}{}{}", path.display(), suffix)
}

pub(crate) fn print_npm_metadata_url(
    project_dir: &Path,
    kind: NpmMetadataUrlKind,
    spec: Option<&str>,
    json: bool,
    npm_registry: Option<&str>,
) -> Result<(), OmcRegistryError> {
    let (package_name, manifest) = if let Some(spec) = spec {
        let spec = parse_package_spec(spec, Some(Ecosystem::Npm))?;
        let metadata = read_npm_package_metadata(project_dir, &spec, npm_registry)?;
        (Some(metadata.name), metadata.manifest)
    } else {
        let package = read_npm_pkg_json(&project_dir.join("package.json"))?;
        let name = package
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        (name, package)
    };
    let url = npm_metadata_url(kind, &manifest, package_name.as_deref())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "url": url }))?
        );
    } else {
        println!("{url}");
    }
    Ok(())
}

pub(crate) fn print_npm_dist_tag(
    project_dir: &Path,
    action: NpmDistTagAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmDistTagAction::List {
            spec,
            npm_registry,
            userconfig,
        } => {
            let spec = npm_dist_tag_package_spec(project_dir, spec.as_deref())?;
            let spec = parse_package_spec(&spec, Some(Ecosystem::Npm))?;
            let metadata = read_npm_package_metadata_with_userconfig(
                project_dir,
                &spec,
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            for (tag, version) in metadata.dist_tags {
                println!("{tag}: {version}");
            }
        }
        NpmDistTagAction::Add {
            spec,
            tag,
            npm_registry,
            userconfig,
            otp,
        } => {
            let (package, version) = npm_dist_tag_add_package_version(&spec)?;
            let result = add_npm_dist_tag(
                project_dir,
                &package,
                &version,
                &tag,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_dist_tag_mutation(&result, true);
        }
        NpmDistTagAction::Remove {
            spec,
            tag,
            npm_registry,
            userconfig,
            otp,
        } => {
            let package = npm_dist_tag_package_name(&spec)?;
            let result = remove_npm_dist_tag(
                project_dir,
                &package,
                &tag,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_dist_tag_mutation(&result, false);
        }
    }
    Ok(())
}

pub(crate) fn print_npm_dist_tag_mutation(result: &NpmDistTagMutationResult, added: bool) {
    if added {
        let version = result.version.as_deref().unwrap_or_default();
        println!("+ {}: {}@{}", result.tag, result.package, version);
    } else {
        println!("- {}: {}", result.tag, result.package);
    }
}

pub(crate) fn print_npm_sbom(
    project_dir: &Path,
    action: NpmSbomAction,
) -> Result<(), OmcRegistryError> {
    let context = npm_sbom_context(project_dir, action.sbom_type)?;
    let value = match action.format {
        NpmSbomFormat::CycloneDx => npm_cyclonedx_sbom(&context),
        NpmSbomFormat::Spdx => npm_spdx_sbom(&context),
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) fn print_npm_explain(
    project_dir: &Path,
    specs: &[String],
    json: bool,
) -> Result<ExitCode, OmcRegistryError> {
    let targets = specs
        .iter()
        .map(|spec| npm_explain_requested_name(spec))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let packages = listed_locked_packages(project_dir, Some(Ecosystem::Npm), &[])?;
    let root_dependencies = npm_root_dependency_names(project_dir)?;
    let root = npm_outdated_dependent(project_dir);
    let mut rows = Vec::new();

    for package in &packages {
        if !targets.contains(&package.name) {
            continue;
        }
        let mut dependents = BTreeSet::new();
        if root_dependencies.contains(&package.name) {
            dependents.insert(root.clone());
        }
        for parent in &packages {
            if parent.name == package.name && parent.version == package.version {
                continue;
            }
            if npm_lock_package_depends_on(parent, &package.name) {
                dependents.insert(format!("{}@{}", parent.name, parent.version));
            }
        }
        let dependents = if dependents.is_empty() {
            vec!["omc.lock".to_owned()]
        } else {
            dependents.into_iter().collect()
        };
        rows.push(NpmExplainPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            location: npm_outdated_location(project_dir, &package.name),
            dependents,
        });
    }

    rows.sort_by(|left, right| {
        (left.name.as_str(), left.version.as_str())
            .cmp(&(right.name.as_str(), right.version.as_str()))
    });

    if json {
        let value = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "name": row.name,
                    "version": row.version,
                    "location": row.location.display().to_string(),
                    "dependents": row.dependents,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        for row in &rows {
            println!("{}@{}", row.name, row.version);
            println!("{}", row.location.display());
            for dependent in &row.dependents {
                println!("  depended on by {dependent}");
            }
        }
    }

    if rows.is_empty() {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

pub(crate) fn print_npm_version(
    project_dir: &Path,
    action: NpmVersionAction,
) -> Result<(), OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let mut package = read_npm_pkg_json(&package_json)?;
    let current = npm_package_json_version(&package)?;
    match action {
        NpmVersionAction::Current { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": current,
                    }))?
                );
            } else {
                println!("v{current}");
            }
        }
        NpmVersionAction::Bump {
            spec,
            preid,
            allow_same_version,
            json,
        } => {
            let next = npm_next_version(&current, &spec, preid.as_deref())?;
            if next == current && !allow_same_version {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "Version not changed: {current}"
                )));
            }
            npm_pkg_set_path(
                &mut package,
                "version",
                serde_json::Value::String(next.clone()),
            )?;
            write_npm_pkg_json(&package_json, &package)?;
            update_npm_lockfile_root_version(project_dir, "package-lock.json", &next)?;
            update_npm_lockfile_root_version(project_dir, "npm-shrinkwrap.json", &next)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "old": current,
                        "new": next,
                    }))?
                );
            } else {
                println!("v{next}");
            }
        }
    }
    Ok(())
}

pub(crate) fn append_npm_package_lock_dependencies(
    entry: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    dependencies: &[String],
) {
    let dependencies = npm_package_lock_dependency_map(dependencies);
    if !dependencies.is_empty() {
        entry.insert(field.to_owned(), serde_json::Value::Object(dependencies));
    }
}

pub(crate) fn print_npm_cache(
    project_dir: &Path,
    action: NpmCacheAction,
    cache_dir: Option<&Path>,
) -> Result<(), OmcRegistryError> {
    let cache_dir = npm_compat_cache_dir(project_dir, cache_dir);
    match action {
        NpmCacheAction::Verify => {
            let files = compat_cache_files(&cache_dir)?;
            let bytes = cache_files_size(&files)?;
            let locked_verified = if cache_dir == npm_cache_dir(project_dir) {
                verify_npm_locked_cache(project_dir)?
            } else {
                0
            };
            println!("Cache verified and compressed ({})", cache_dir.display());
            println!("Content verified: {} ({bytes} bytes)", files.len());
            println!("Index entries: {}", files.len());
            if locked_verified > 0 {
                println!("OMC lock entries verified: {locked_verified}");
            }
        }
        NpmCacheAction::List { pattern } => {
            let mut files = compat_cache_files(&cache_dir)?;
            if let Some(pattern) = pattern {
                files.retain(|path| compat_cache_pattern_matches(path, &cache_dir, &pattern));
            }
            files.sort();
            for path in files {
                println!("{}", compat_cache_display_path(&path, &cache_dir));
            }
        }
        NpmCacheAction::Remove { pattern } => {
            let count = remove_npm_cache_entries(&cache_dir, &pattern)?;
            if count == 0 {
                eprintln!("npm warn cache Not Found: {pattern}");
            } else {
                println!("Files removed: {count}");
            }
        }
        NpmCacheAction::Clean => {
            let count = compat_cache_files(&cache_dir)?.len();
            if cache_dir.exists() {
                fs::remove_dir_all(&cache_dir)?;
            }
            println!("Files removed: {count}");
        }
    }
    Ok(())
}

pub(crate) fn print_npm_doctor(
    project_dir: &Path,
    action: NpmDoctorAction,
) -> Result<(), OmcRegistryError> {
    print!("{}", npm_doctor_report(project_dir, &action)?);
    Ok(())
}

pub(crate) fn collect_npm_funding_urls(value: &serde_json::Value, urls: &mut Vec<String>) {
    match value {
        serde_json::Value::String(url) => {
            let url = url.trim();
            if !url.is_empty() {
                urls.push(url.to_owned());
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(url) = object
                .get("url")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|url| !url.is_empty())
            {
                urls.push(url.to_owned());
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_npm_funding_urls(value, urls);
            }
        }
        _ => {}
    }
}

pub(crate) fn print_npm_init(
    project_dir: &Path,
    action: NpmInitAction,
) -> Result<(), OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let mut package = if package_json.exists() {
        read_npm_pkg_json(&package_json)?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    let name = action
        .name
        .clone()
        .unwrap_or_else(|| default_npm_package_name(project_dir, action.scope.as_deref()));
    npm_pkg_set_default_string(&mut package, "name", name)?;
    npm_pkg_set_default_string(
        &mut package,
        "version",
        action.version.unwrap_or_else(|| "1.0.0".to_owned()),
    )?;
    npm_pkg_set_default_string(
        &mut package,
        "description",
        action.description.unwrap_or_default(),
    )?;
    npm_pkg_set_default_string(
        &mut package,
        "main",
        action.main.unwrap_or_else(|| "index.js".to_owned()),
    )?;
    if npm_pkg_get_path(&package, "scripts.test").is_none() {
        npm_pkg_set_path(
            &mut package,
            "scripts.test",
            serde_json::Value::String("echo \"Error: no test specified\" && exit 1".to_owned()),
        )?;
    }
    if npm_pkg_get_path(&package, "keywords").is_none() {
        npm_pkg_set_path(
            &mut package,
            "keywords",
            serde_json::Value::Array(Vec::new()),
        )?;
    }
    npm_pkg_set_default_string(&mut package, "author", String::new())?;
    npm_pkg_set_default_string(
        &mut package,
        "license",
        action.license.unwrap_or_else(|| "ISC".to_owned()),
    )?;
    if action.private && npm_pkg_get_path(&package, "private").is_none() {
        npm_pkg_set_path(&mut package, "private", serde_json::Value::Bool(true))?;
    }
    if let Some(package_type) = action.package_type {
        npm_pkg_set_default_string(&mut package, "type", package_type)?;
    }

    write_npm_pkg_json(&package_json, &package)?;
    println!("Wrote to {}", package_json.display());
    Ok(())
}

pub(crate) fn print_npm_pkg(
    project_dir: &Path,
    action: NpmPkgAction,
) -> Result<(), OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let mut package = read_npm_pkg_json(&package_json)?;
    match action {
        NpmPkgAction::Get { fields } => {
            if fields.is_empty() {
                println!("{}", serde_json::to_string_pretty(&package)?);
            } else if fields.len() == 1 {
                let value = npm_pkg_get_path(&package, &fields[0])
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                let mut selected = serde_json::Map::new();
                for field in fields {
                    let value = npm_pkg_get_path(&package, &field)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    selected.insert(field, value);
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::Value::Object(selected))?
                );
            }
        }
        NpmPkgAction::Set { assignments } => {
            for (field, value) in assignments {
                npm_pkg_set_path(&mut package, &field, value)?;
            }
            write_npm_pkg_json(&package_json, &package)?;
        }
        NpmPkgAction::Delete { fields } => {
            for field in fields {
                npm_pkg_delete_path(&mut package, &field);
            }
            write_npm_pkg_json(&package_json, &package)?;
        }
    }
    Ok(())
}

pub(crate) fn print_npm_maintenance_report(
    command: NpmMaintenanceCommand,
    packages: &[String],
    install: &InstallReport,
    dry_run: bool,
    json: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command": npm_maintenance_command_name(command),
                "dryRun": dry_run,
                "packages": packages,
                "install": {
                    "npm": install.npm_packages,
                    "pypi": install.pypi_packages,
                    "localSourceArtifacts": install.local_source_artifacts,
                    "npmBins": install.npm_bins,
                    "pythonScripts": install.python_scripts,
                    "nodeModules": install.node_modules,
                    "npmBinDir": install.npm_bin_dir,
                    "pythonBinDir": install.python_bin_dir,
                    "pythonSitePackages": install.python_site_packages,
                }
            }))?
        );
        return Ok(());
    }

    match command {
        NpmMaintenanceCommand::Prune => {
            if dry_run {
                println!("dry-run: would prune OMC npm install state");
            } else {
                println!("pruned OMC npm install state");
            }
        }
        NpmMaintenanceCommand::Dedupe => {
            if dry_run {
                println!("dry-run: would dedupe OMC npm install state");
            } else {
                println!("deduped OMC npm install state");
            }
        }
        NpmMaintenanceCommand::Rebuild => {
            if packages.is_empty() {
                if dry_run {
                    println!(
                        "dry-run: would rebuild OMC npm install state without package lifecycle scripts"
                    );
                } else {
                    println!("rebuilt OMC npm install state without package lifecycle scripts");
                }
            } else if dry_run {
                println!(
                    "dry-run: would rebuild OMC npm package request without package lifecycle scripts: {}",
                    packages.join(", ")
                );
            } else {
                println!(
                    "rebuilt OMC npm package request without package lifecycle scripts: {}",
                    packages.join(", ")
                );
            }
        }
    }
    print_install_report(install);
    Ok(())
}

pub(crate) fn collect_npm_dependency_closure(
    name: &str,
    dependency_graph: &BTreeMap<String, BTreeSet<String>>,
    protected: &mut BTreeSet<String>,
) {
    let Some(dependencies) = dependency_graph.get(name) else {
        return;
    };
    for dependency_name in dependencies {
        if protected.insert(dependency_name.clone()) {
            collect_npm_dependency_closure(dependency_name, dependency_graph, protected);
        }
    }
}

pub(crate) fn print_npm_list(
    project_dir: &Path,
    action: &NpmListAction,
) -> Result<(), OmcRegistryError> {
    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&npm_list_json_tree(
                project_dir,
                &action.packages,
                action.depth,
            )?)?
        );
        return Ok(());
    }

    print_locked_packages(project_dir, Some(Ecosystem::Npm), false, &action.packages)
}

pub(crate) fn collect_npm_package_json_local_package_paths(
    package_dir: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), OmcRegistryError> {
    let package_json = package_dir.join("package.json");
    if !package_json.exists() {
        return Ok(());
    }
    let manifest = read_npm_pkg_json(&package_json)?;
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(dependencies) = manifest.get(field).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for requirement in dependencies.values().filter_map(serde_json::Value::as_str) {
            if let Some(path) = npm_package_json_local_directory_path(package_dir, requirement)? {
                paths.push(path);
            }
        }
    }
    Ok(())
}

pub(crate) fn collect_npm_package_bin_env(
    package: &serde_json::Value,
    vars: &mut BTreeMap<String, String>,
) {
    let Some(bin) = package.get("bin") else {
        return;
    };
    if let Some(path) = bin.as_str() {
        if let Some(name) = package.get("name").and_then(serde_json::Value::as_str) {
            if !name.is_empty() {
                vars.insert(
                    format!("npm_package_bin_{}", npm_package_bin_name(name)),
                    path.to_owned(),
                );
            }
        }
        return;
    }
    let Some(entries) = bin.as_object() else {
        return;
    };
    for (name, value) in entries {
        if let Some(path) = value.as_str() {
            vars.insert(format!("npm_package_bin_{name}"), path.to_owned());
        }
    }
}

pub(crate) fn collect_npm_package_config_env(
    prefix: &str,
    value: &serde_json::Value,
    vars: &mut BTreeMap<String, String>,
) {
    if let Some(entries) = value.as_object() {
        for (key, value) in entries {
            collect_npm_package_config_env(&format!("{prefix}_{key}"), value, vars);
        }
        return;
    }
    if let Some(value) = npm_package_env_value(value) {
        vars.insert(prefix.to_owned(), value);
    }
}

pub(crate) fn parse_npm_compat_action(
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let normalized = normalize_npm_global_args(args)?;
    let args = normalized.as_slice();
    if let Some(action) = parse_npm_help_request(args) {
        return Ok(action);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(NpmCompatAction::Install {
            specs: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        });
    };

    match command {
        "--version" | "-v" => Ok(NpmCompatAction::Version),
        "completion" => parse_npm_completion_args(&args[1..]),
        "help-search" => parse_npm_help_search_args(&args[1..]),
        "init" | "create" | "innit" => parse_npm_init_args(command, &args[1..]),
        "version" => parse_npm_version_args(&args[1..]),
        "link" | "ln" => parse_npm_link_args(&args[1..]),
        "install-test" | "it" => parse_npm_install_test_args(command, false, &args[1..]),
        "install-ci-test" | "cit" => parse_npm_install_test_args(command, true, &args[1..]),
        "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt" | "isnta"
        | "isntal" | "isntall" | "add" | "update" | "up" | "upgrade" | "udpate" => {
            parse_npm_install_args(command, &args[1..])
        }
        "ci" => {
            let CommonCompatFlags {
                omit_dev,
                omit_optional,
                omit_peer,
                dry_run,
                json,
                npm_engine_strict,
                npm_offline,
                allow,
                allow_flow,
                allow_all_host,
                workspaces,
                all_workspaces,
                include_workspace_root,
                positionals,
                ..
            } = parse_common_compat_flags(&args[1..], true)?;
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("npm ci", &positionals[0]));
            }
            Ok(NpmCompatAction::Ci {
                omit_dev,
                omit_optional,
                omit_peer,
                dry_run,
                json,
                npm_engine_strict,
                npm_offline,
                allow,
                allow_flow,
                allow_all_host,
                workspaces,
                all_workspaces,
                include_workspace_root,
            })
        }
        "remove" | "uninstall" | "unlink" | "rm" | "r" | "un" => {
            let mut global = false;
            let mut filtered = Vec::new();
            let mut index = 1;
            while index < args.len() {
                let arg = &args[index];
                if let Some(value) = npm_global_location_flag_value(args, &mut index, arg)? {
                    global = value;
                } else {
                    filtered.push(arg.clone());
                }
                index += 1;
            }
            let CommonCompatFlags {
                allow,
                allow_flow,
                allow_all_host,
                save,
                package_lock,
                lock_only,
                workspaces,
                all_workspaces,
                include_workspace_root,
                positionals,
                ..
            } = parse_common_compat_flags(&filtered, true)?;
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm remove needs at least one package".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Remove {
                specs: positionals,
                global,
                save,
                package_lock,
                lock_only,
                allow,
                allow_flow,
                allow_all_host,
                workspaces,
                all_workspaces,
                include_workspace_root,
            })
        }
        "prune" => {
            parse_npm_maintenance_args("npm prune", NpmMaintenanceCommand::Prune, &args[1..])
        }
        "dedupe" | "ddp" | "find-dupes" => {
            parse_npm_maintenance_args("npm dedupe", NpmMaintenanceCommand::Dedupe, &args[1..])
        }
        "rebuild" | "rb" => parse_npm_rebuild_args(&args[1..]),
        "run" | "run-script" => {
            let NpmRunArgs {
                name,
                args,
                if_present,
                json,
                workspaces,
                all_workspaces,
                include_workspace_root,
            } = parse_npm_run_args("npm run", &args[1..], None)?;
            if let Some(name) = name {
                Ok(NpmCompatAction::RunScript {
                    command: command.to_owned(),
                    name,
                    args,
                    if_present,
                    workspaces,
                    all_workspaces,
                    include_workspace_root,
                })
            } else {
                Ok(NpmCompatAction::RunList {
                    action: NpmRunListAction {
                        json,
                        workspaces,
                        all_workspaces,
                        include_workspace_root,
                    },
                })
            }
        }
        "test" | "start" | "stop" | "restart" => {
            let NpmRunArgs {
                name,
                args,
                if_present,
                json: _,
                workspaces,
                all_workspaces,
                include_workspace_root,
            } = parse_npm_run_args(command, &args[1..], Some(command))?;
            Ok(NpmCompatAction::RunScript {
                command: command.to_owned(),
                name: name.expect("implicit npm script command has a script name"),
                args,
                if_present,
                workspaces,
                all_workspaces,
                include_workspace_root,
            })
        }
        "exec" | "x" | "npx" => Ok(NpmCompatAction::Exec {
            action: parse_npm_exec_args(command, &args[1..])?,
        }),
        "explore" => parse_npm_explore_args(&args[1..]),
        "edit" => parse_npm_edit_args(&args[1..]),
        "bin" => {
            let global = parse_npm_path_args("npm bin", &args[1..])?;
            Ok(NpmCompatAction::Path {
                kind: NpmPathKind::Bin,
                global,
            })
        }
        "root" => {
            let global = parse_npm_path_args("npm root", &args[1..])?;
            Ok(NpmCompatAction::Path {
                kind: NpmPathKind::Root,
                global,
            })
        }
        "prefix" => {
            let global = parse_npm_path_args("npm prefix", &args[1..])?;
            Ok(NpmCompatAction::Path {
                kind: NpmPathKind::Prefix,
                global,
            })
        }
        "list" | "ls" | "ll" | "la" => parse_npm_list_args(&args[1..]),
        "query" => parse_npm_query_args(&args[1..]),
        "explain" | "why" => parse_npm_explain_args(&args[1..]),
        "outdated" => parse_npm_outdated_args(&args[1..]),
        "doctor" => parse_npm_doctor_args(&args[1..]),
        "audit" => parse_npm_audit_args(&args[1..]),
        "fund" => parse_npm_fund_args(&args[1..]),
        "cache" => parse_npm_cache_args(&args[1..]),
        "pkg" => parse_npm_pkg_args(&args[1..]),
        "shrinkwrap" => parse_npm_shrinkwrap_args(&args[1..]),
        "pack" => parse_npm_pack_args(&args[1..]),
        "publish" => parse_npm_publish_args(&args[1..]),
        "unpublish" => parse_npm_unpublish_args(&args[1..]),
        "deprecate" => parse_npm_deprecate_args(false, &args[1..]),
        "undeprecate" => parse_npm_deprecate_args(true, &args[1..]),
        "diff" => parse_npm_diff_args(&args[1..]),
        "search" | "s" | "se" | "find" => parse_npm_search_args(&args[1..]),
        "star" => parse_npm_star_args(true, &args[1..]),
        "unstar" => parse_npm_star_args(false, &args[1..]),
        "stars" => parse_npm_stars_args(&args[1..]),
        "ping" => parse_npm_ping_args(&args[1..]),
        "whoami" => parse_npm_whoami_args(&args[1..]),
        "login" | "adduser" | "add-user" => parse_npm_login_args(&args[1..]),
        "logout" => parse_npm_logout_args(&args[1..]),
        "token" => parse_npm_token_args(&args[1..]),
        "trust" => parse_npm_trust_args(&args[1..]),
        "profile" => parse_npm_profile_args(&args[1..]),
        "owner" => parse_npm_owner_args(&args[1..]),
        "access" => parse_npm_access_args(&args[1..]),
        "org" => parse_npm_org_args(&args[1..]),
        "team" => parse_npm_team_args(&args[1..]),
        "dist-tag" | "dist-tags" => parse_npm_dist_tag_args(&args[1..]),
        "sbom" => parse_npm_sbom_args(&args[1..]),
        "view" | "info" | "show" | "v" => parse_npm_view_args(&args[1..]),
        "docs" | "doc" => {
            parse_npm_metadata_url_args(command, NpmMetadataUrlKind::Docs, &args[1..])
        }
        "repo" | "repository" => {
            parse_npm_metadata_url_args(command, NpmMetadataUrlKind::Repo, &args[1..])
        }
        "bugs" => parse_npm_metadata_url_args(command, NpmMetadataUrlKind::Bugs, &args[1..]),
        "home" | "homepage" => {
            parse_npm_metadata_url_args(command, NpmMetadataUrlKind::Home, &args[1..])
        }
        "config" | "c" => parse_npm_config_args(&args[1..]),
        "get" => parse_npm_config_get_args(&args[1..]),
        "set" => parse_npm_config_set_args(&args[1..]),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm compatibility command `{other}`"
        ))),
    }
}

pub(crate) fn parse_npm_help_request(args: &[String]) -> Option<NpmCompatAction> {
    let command = args.first()?;
    if npm_help_flag(command) {
        return Some(NpmCompatAction::Help { topic: None });
    }
    if command == "help" {
        let topic = args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned();
        return Some(NpmCompatAction::Help { topic });
    }
    if matches!(command.as_str(), "exec" | "x" | "npx") {
        if args.get(1).is_some_and(|arg| npm_help_flag(arg)) {
            return Some(NpmCompatAction::Help {
                topic: Some("exec".to_owned()),
            });
        }
        return None;
    }
    if args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| npm_help_flag(arg))
    {
        return Some(NpmCompatAction::Help {
            topic: Some(command.clone()),
        });
    }
    None
}

pub(crate) fn parse_npm_path_args(
    command: &str,
    args: &[String],
) -> Result<bool, OmcRegistryError> {
    let mut global = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p") {
        } else if let Some(value) = npm_global_location_flag_value(args, &mut index, arg)? {
            global = value;
        } else {
            return Err(unsupported_compat_arg(command, arg));
        }
        index += 1;
    }
    Ok(global)
}

pub(crate) fn parse_npm_maintenance_args(
    _command: &str,
    maintenance: NpmMaintenanceCommand,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut filtered = Vec::new();
    let mut dry_run = false;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_bool_flag_value(arg, "--dry-run") {
            dry_run = value;
        } else if arg == "--no-dry-run" {
            dry_run = false;
        } else if let Some(value) = npm_bool_flag_value(arg, "--json") {
            json = value;
        } else if matches!(arg.as_str(), "--silent" | "-s") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_maintenance_equals_value_flag(arg) {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        omit_dev,
        omit_optional,
        omit_peer,
        allow,
        allow_flow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    Ok(NpmCompatAction::Maintenance {
        command: maintenance,
        packages: positionals,
        dry_run,
        json,
        omit_dev,
        omit_optional,
        omit_peer,
        allow,
        allow_flow,
        allow_all_host,
    })
}

pub(crate) fn parse_npm_rebuild_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut filtered = Vec::new();
    let mut dry_run = false;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_bool_flag_value(arg, "--dry-run") {
            dry_run = value;
        } else if arg == "--no-dry-run" {
            dry_run = false;
        } else if let Some(value) = npm_bool_flag_value(arg, "--json") {
            json = value;
        } else if matches!(
            arg.as_str(),
            "--silent"
                | "-s"
                | "--force"
                | "-f"
                | "--ignore-scripts"
                | "--foreground-scripts"
                | "--build-from-source"
                | "--bin-links"
                | "--no-bin-links"
                | "--install-links"
                | "--no-install-links"
                | "--audit"
                | "--audit=false"
                | "--fund"
                | "--fund=false"
        ) {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--cache" | "--install-strategy"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_rebuild_equals_value_flag(arg) {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        omit_dev,
        omit_optional,
        omit_peer,
        allow,
        allow_flow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;

    Ok(NpmCompatAction::Maintenance {
        command: NpmMaintenanceCommand::Rebuild,
        packages: positionals,
        dry_run,
        json,
        omit_dev,
        omit_optional,
        omit_peer,
        allow,
        allow_flow,
        allow_all_host,
    })
}

pub(crate) fn parse_npm_completion_args(
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    if args.is_empty() {
        return Ok(NpmCompatAction::Completion { words: None });
    }
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            return Ok(NpmCompatAction::Completion {
                words: Some(args[index + 1..].to_vec()),
            });
        } else if matches!(arg.as_str(), "--silent" | "-s") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_completion_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm completion", arg));
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }
    if filtered.is_empty() {
        Ok(NpmCompatAction::Completion { words: None })
    } else {
        Ok(NpmCompatAction::Completion {
            words: Some(filtered),
        })
    }
}

pub(crate) fn parse_npm_help_search_args(
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut long = false;
    let mut query = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_bool_flag_value(arg, "--long") {
            long = value;
        } else if arg == "-l" {
            long = true;
        } else if matches!(arg.as_str(), "--silent" | "-s") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_help_search_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm help-search", arg));
        } else {
            query.push(arg.clone());
        }
        index += 1;
    }
    Ok(NpmCompatAction::HelpSearch { query, long })
}

pub(crate) fn parse_npm_init_args(
    command: &str,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut action = NpmInitAction {
        name: None,
        version: None,
        description: None,
        main: None,
        license: None,
        scope: None,
        private: false,
        package_type: None,
    };
    let mut positionals = Vec::new();
    let mut create_args = Vec::new();
    let mut npm_registry = None;
    let mut allow = Vec::new();
    let mut allow_flow = Vec::new();
    let mut allow_all_host = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            create_args.extend(args[index + 1..].iter().cloned());
            break;
        } else if matches!(arg.as_str(), "-y" | "--yes" | "--force") {
        } else if arg == "--private" {
            action.private = true;
        } else if arg == "--name" {
            action.name = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--name=") {
            action.name = Some(value.to_owned());
        } else if arg == "--version" {
            action.version = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--version=") {
            action.version = Some(value.to_owned());
        } else if arg == "--description" {
            action.description = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--description=") {
            action.description = Some(value.to_owned());
        } else if arg == "--main" {
            action.main = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--main=") {
            action.main = Some(value.to_owned());
        } else if arg == "--license" {
            action.license = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--license=") {
            action.license = Some(value.to_owned());
        } else if arg == "--scope" {
            action.scope = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--scope=") {
            action.scope = Some(value.to_owned());
        } else if arg == "--type" {
            action.package_type = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--type=") {
            action.package_type = Some(value.to_owned());
        } else if arg == "--registry" {
            npm_registry = Some(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--allow" {
            allow.push(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--allow=") {
            allow.push(value.to_owned());
        } else if arg == "--allow-flow" {
            allow_flow.push(npm_init_flag_value(args, &mut index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--allow-flow=") {
            allow_flow.push(value.to_owned());
        } else if arg == "--allow-all-host" {
            allow_all_host = true;
        } else if matches!(arg.as_str(), "--silent" | "-s") {
        } else if npm_init_ignored_value_flag(arg) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_init_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm init", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }
    if let Some(initializer) = positionals.first() {
        create_args.splice(0..0, positionals[1..].iter().cloned());
        return Ok(NpmCompatAction::Create {
            action: NpmCreateAction {
                initializer: initializer.clone(),
                args: create_args,
                npm_registry,
                allow,
                allow_flow,
                allow_all_host,
            },
        });
    }
    if command != "init"
        && (npm_registry.is_some() || !allow.is_empty() || !allow_flow.is_empty() || allow_all_host)
    {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm {command} capability and registry flags need an initializer package"
        )));
    }
    if !create_args.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm {command} arguments after -- need an initializer package"
        )));
    }
    Ok(NpmCompatAction::Init { action })
}

pub(crate) fn parse_npm_version_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut allow_same_version = false;
    let mut preid = None;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--allow-same-version" {
            allow_same_version = true;
        } else if arg == "--preid" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--preid needs a value".to_owned(),
                ));
            };
            preid = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--preid=") {
            preid = Some(value.to_owned());
        } else if matches!(
            arg.as_str(),
            "--no-git-tag-version"
                | "--git-tag-version=false"
                | "--git-tag-version"
                | "--git-tag-version=true"
                | "--commit-hooks=false"
                | "--sign-git-tag=false"
                | "--silent"
                | "-s"
        ) {
        } else if matches!(arg.as_str(), "--message" | "-m" | "--tag-version-prefix") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_version_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm version", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    let action = if positionals.is_empty() {
        NpmVersionAction::Current { json }
    } else if positionals.len() == 1 {
        NpmVersionAction::Bump {
            spec: positionals.remove(0),
            preid,
            allow_same_version,
            json,
        }
    } else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm version accepts at most one version argument".to_owned(),
        ));
    };
    Ok(NpmCompatAction::PackageVersion { action })
}

pub(crate) fn parse_npm_install_args(
    command: &str,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    let mut global = false;
    let mut dry_run = false;
    let mut npm_tag = None;
    let mut npm_before = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_bool_flag_value(arg, "--dry-run") {
            dry_run = value;
        } else if arg == "--no-dry-run" {
            dry_run = false;
        } else if arg == "--tag" {
            index += 1;
            let Some(tag) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--tag needs a value".to_owned(),
                ));
            };
            npm_tag = Some(normalize_npm_install_tag(tag)?);
        } else if let Some(tag) = arg.strip_prefix("--tag=") {
            npm_tag = Some(normalize_npm_install_tag(tag)?);
        } else if arg == "--before" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--before needs a value".to_owned(),
                ));
            };
            npm_before = Some(normalize_npm_before(value)?);
        } else if let Some(value) = arg.strip_prefix("--before=") {
            npm_before = Some(normalize_npm_before(value)?);
        } else if arg == "--min-release-age" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--min-release-age needs a value".to_owned(),
                ));
            };
            npm_before = Some(npm_min_release_age_before(value)?);
        } else if let Some(value) = arg.strip_prefix("--min-release-age=") {
            npm_before = Some(npm_min_release_age_before(value)?);
        } else if let Some(value) = npm_global_location_flag_value(args, &mut index, arg)? {
            global = value;
        } else if is_npm_archive_arg(arg) || is_npm_github_dependency_arg(arg) {
            archive_references.push(arg.clone());
        } else if ignored_npm_value_flag(arg) {
            filtered.push(arg.clone());
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            filtered.push(value.clone());
        } else if is_npm_local_directory_arg(arg) {
            local_paths.push(npm_local_path_arg(arg)?);
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        dependency_kind,
        omit_dev,
        omit_optional,
        omit_peer,
        save,
        save_explicit,
        save_prefix,
        save_bundle,
        package_lock,
        lock_only,
        dry_run: _,
        json,
        npm_registry,
        npm_engine_strict,
        npm_offline,
        allow,
        allow_flow,
        allow_all_host,
        workspaces,
        all_workspaces,
        include_workspace_root,
        positionals,
    } = parse_common_compat_flags(&filtered, true)?;
    let specs = npm_install_specs_with_tag(positionals, npm_tag.as_deref())?;

    let explicit_no_save = save_explicit && !save;
    let save = if npm_update_defaults_to_no_save(command) && !save_explicit {
        false
    } else {
        save
    };
    let package_lock = (package_lock || lock_only) && !explicit_no_save;

    Ok(NpmCompatAction::Install {
        specs,
        archive_references,
        local_paths,
        global,
        save,
        save_prefix,
        save_bundle,
        dependency_kind,
        omit_dev,
        omit_optional,
        omit_peer,
        package_lock,
        lock_only,
        dry_run,
        json,
        npm_registry,
        npm_before,
        npm_engine_strict,
        npm_offline,
        allow,
        allow_flow,
        allow_all_host,
        workspaces,
        all_workspaces,
        include_workspace_root,
    })
}

pub(crate) fn parse_npm_link_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let explicit_save = npm_link_explicit_save(args);
    let mut archive_references = Vec::new();
    let mut local_paths = Vec::new();
    let mut dry_run = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_bool_flag_value(arg, "--dry-run") {
            dry_run = value;
        } else if arg == "--no-dry-run" {
            dry_run = false;
        } else if npm_global_location_flag_value(args, &mut index, arg)?.is_some() {
        } else if is_npm_archive_arg(arg) {
            archive_references.push(arg.clone());
        } else if ignored_npm_value_flag(arg) {
            filtered.push(arg.clone());
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            filtered.push(value.clone());
        } else if is_npm_local_directory_arg(arg) {
            local_paths.push(npm_local_path_arg(arg)?);
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        dependency_kind,
        omit_dev,
        omit_optional,
        omit_peer,
        save,
        save_bundle,
        lock_only,
        npm_registry,
        allow,
        allow_flow,
        allow_all_host,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;

    if positionals.is_empty() && archive_references.is_empty() && local_paths.is_empty() {
        return Ok(NpmCompatAction::Link {
            action: NpmLinkAction::Register { dry_run },
        });
    }

    Ok(NpmCompatAction::Link {
        action: NpmLinkAction::Install {
            names: positionals,
            archive_references,
            local_paths,
            save: explicit_save && save,
            save_bundle: explicit_save && save_bundle,
            dependency_kind,
            omit_dev,
            omit_optional,
            omit_peer,
            lock_only,
            dry_run,
            npm_registry,
            allow,
            allow_flow,
            allow_all_host,
        },
    })
}

pub(crate) fn parse_npm_install_test_args(
    command: &str,
    use_ci: bool,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut command_args = Vec::new();
    let mut test_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            test_args.extend(args[index + 1..].iter().cloned());
            break;
        }
        command_args.push(arg.clone());
        index += 1;
    }

    if use_ci {
        let CommonCompatFlags {
            omit_dev,
            omit_optional,
            omit_peer,
            dry_run,
            json,
            npm_engine_strict,
            npm_offline,
            allow,
            allow_flow,
            allow_all_host,
            workspaces,
            all_workspaces,
            include_workspace_root,
            positionals,
            ..
        } = parse_common_compat_flags(&command_args, true)?;
        if !positionals.is_empty() {
            return Err(unsupported_compat_arg(command, &positionals[0]));
        }
        return Ok(NpmCompatAction::InstallTest {
            command: command.to_owned(),
            use_ci,
            specs: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev,
            omit_optional,
            omit_peer,
            lock_only: false,
            package_lock: true,
            dry_run,
            json,
            npm_registry: None,
            npm_before: None,
            npm_engine_strict,
            npm_offline,
            allow,
            allow_flow,
            allow_all_host,
            workspaces,
            all_workspaces,
            include_workspace_root,
            test_args,
        });
    }

    let install = parse_npm_install_args("install", &command_args)?;
    let NpmCompatAction::Install {
        specs,
        archive_references,
        local_paths,
        global,
        save,
        save_prefix,
        save_bundle,
        dependency_kind,
        omit_dev,
        omit_optional,
        omit_peer,
        package_lock,
        lock_only,
        dry_run,
        json,
        npm_registry,
        npm_before,
        npm_engine_strict,
        npm_offline,
        allow,
        allow_flow,
        allow_all_host,
        workspaces,
        all_workspaces,
        include_workspace_root,
    } = install
    else {
        unreachable!("parse_npm_install_args only returns install actions")
    };
    if global {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm {command} does not support --global"
        )));
    }
    Ok(NpmCompatAction::InstallTest {
        command: command.to_owned(),
        use_ci,
        specs,
        archive_references,
        local_paths,
        save,
        save_prefix,
        save_bundle,
        dependency_kind,
        omit_dev,
        omit_optional,
        omit_peer,
        package_lock,
        lock_only,
        dry_run,
        json,
        npm_registry,
        npm_before,
        npm_engine_strict,
        npm_offline,
        allow,
        allow_flow,
        allow_all_host,
        workspaces,
        all_workspaces,
        include_workspace_root,
        test_args,
    })
}

pub(crate) fn parse_npm_doctor_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut checks = Vec::new();
    let mut npm_registry = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--registry" {
            index += 1;
            let Some(registry) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--registry needs a URL".to_owned(),
                ));
            };
            npm_registry = Some(registry.clone());
        } else if let Some(registry) = arg.strip_prefix("--registry=") {
            npm_registry = Some(registry.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_doctor_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm doctor", arg));
        } else {
            checks.push(arg.clone());
        }
        index += 1;
    }
    Ok(NpmCompatAction::Doctor {
        action: NpmDoctorAction {
            checks,
            npm_registry,
        },
    })
}

pub(crate) fn parse_npm_cache_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut force = false;
    let mut cache_dir = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--force" | "-f") {
            force = true;
        } else if matches!(
            arg.as_str(),
            "--json"
                | "--parseable"
                | "-p"
                | "--long"
                | "--silent"
                | "-s"
                | "--prefer-offline"
                | "--prefer-online"
                | "--offline"
        ) {
        } else if arg == "--cache" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--cache needs a path".to_owned(),
                ));
            };
            cache_dir = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--cache=") {
            cache_dir = Some(PathBuf::from(value));
        } else if arg == "--loglevel" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_cache_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm cache", arg));
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let Some(command) = filtered.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm cache needs a command such as verify, ls, rm, or clean".to_owned(),
        ));
    };
    let rest = &filtered[1..];
    let action = match command {
        "verify" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("npm cache verify", &rest[0]));
            }
            NpmCacheAction::Verify
        }
        "ls" | "list" => {
            if rest.len() > 1 {
                return Err(unsupported_compat_arg("npm cache ls", &rest[1]));
            }
            NpmCacheAction::List {
                pattern: rest.first().cloned(),
            }
        }
        "rm" | "remove" | "delete" => {
            if rest.len() != 1 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm cache rm needs exactly one pattern".to_owned(),
                ));
            }
            NpmCacheAction::Remove {
                pattern: rest[0].clone(),
            }
        }
        "clean" | "clear" => {
            if !rest.is_empty() {
                return Err(unsupported_compat_arg("npm cache clean", &rest[0]));
            }
            if !force {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm cache clean needs --force".to_owned(),
                ));
            }
            NpmCacheAction::Clean
        }
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported npm cache command `{other}`"
            )))
        }
    };
    Ok(NpmCompatAction::Cache { action, cache_dir })
}

pub(crate) fn parse_npm_pkg_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p")
            || npm_workspace_scope_ignored_flag(arg)
        {
        } else if matches!(arg.as_str(), "--workspace" | "-w" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_pkg_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm pkg", arg));
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let command = filtered.first().map(String::as_str).unwrap_or("get");
    let rest = if filtered.is_empty() {
        &[][..]
    } else {
        &filtered[1..]
    };
    let action = match command {
        "get" => NpmPkgAction::Get {
            fields: rest.to_vec(),
        },
        "set" => {
            if rest.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm pkg set needs at least one key=value assignment".to_owned(),
                ));
            }
            let mut assignments = Vec::new();
            for assignment in rest {
                let Some((key, value)) = assignment.split_once('=') else {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "npm pkg set assignment `{assignment}` needs key=value"
                    )));
                };
                if key.trim().is_empty() {
                    return Err(OmcRegistryError::UnsupportedSpec(
                        "npm pkg set key cannot be empty".to_owned(),
                    ));
                }
                let value = if json {
                    serde_json::from_str(value).map_err(|error| {
                        OmcRegistryError::UnsupportedSpec(format!(
                            "invalid JSON value for npm pkg set `{assignment}`: {error}"
                        ))
                    })?
                } else {
                    serde_json::Value::String(value.to_owned())
                };
                assignments.push((key.to_owned(), value));
            }
            NpmPkgAction::Set { assignments }
        }
        "delete" | "del" => {
            if rest.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm pkg delete needs at least one key".to_owned(),
                ));
            }
            NpmPkgAction::Delete {
                fields: rest.to_vec(),
            }
        }
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported npm pkg command `{other}`"
            )))
        }
    };
    Ok(NpmCompatAction::Pkg { action })
}

pub(crate) fn parse_npm_shrinkwrap_args(
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let CommonCompatFlags {
        workspaces,
        all_workspaces,
        include_workspace_root,
        ..
    } = parse_common_compat_flags(args, true)?;
    if !workspaces.is_empty() || all_workspaces || include_workspace_root {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm shrinkwrap does not support workspaces".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Shrinkwrap)
}

pub(crate) fn parse_npm_dist_tag_args(
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut positionals = Vec::new();
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut tag_option = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "--json"
                | "--silent"
                | "-s"
                | "--parseable"
                | "-p"
                | "--workspaces"
                | "--include-workspace-root"
        ) || npm_workspace_scope_ignored_flag(arg)
            || npm_dist_tag_ignored_equals_flag(arg)
        {
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_dist_tag_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_dist_tag_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_dist_tag_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if arg == "--tag" {
            index += 1;
            tag_option = Some(npm_dist_tag_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--tag=") {
            tag_option = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--loglevel" | "--workspace" | "-w") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    match positionals.first().map(String::as_str) {
        Some("add") => {
            positionals.remove(0);
            let Some(spec) = positionals.first().cloned() else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm dist-tag add needs a package spec with version".to_owned(),
                ));
            };
            let tag = positionals
                .get(1)
                .cloned()
                .or(tag_option)
                .unwrap_or_else(|| "latest".to_owned());
            if positionals.len() > 2 {
                return Err(unsupported_compat_arg("npm dist-tag add", &positionals[2]));
            }
            Ok(NpmCompatAction::DistTag {
                action: NpmDistTagAction::Add {
                    spec,
                    tag,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        Some("rm" | "remove" | "delete" | "del") => {
            positionals.remove(0);
            let Some(spec) = positionals.first().cloned() else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm dist-tag rm needs a package spec".to_owned(),
                ));
            };
            let Some(tag) = positionals.get(1).cloned().or(tag_option) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm dist-tag rm needs a tag".to_owned(),
                ));
            };
            if positionals.len() > 2 {
                return Err(unsupported_compat_arg("npm dist-tag rm", &positionals[2]));
            }
            Ok(NpmCompatAction::DistTag {
                action: NpmDistTagAction::Remove {
                    spec,
                    tag,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        Some("ls" | "list") => {
            positionals.remove(0);
            if positionals.len() > 1 {
                return Err(unsupported_compat_arg("npm dist-tag ls", &positionals[1]));
            }
            Ok(NpmCompatAction::DistTag {
                action: NpmDistTagAction::List {
                    spec: positionals.pop(),
                    npm_registry,
                    userconfig,
                },
            })
        }
        _ => {
            if positionals.len() > 1 {
                return Err(unsupported_compat_arg("npm dist-tag ls", &positionals[1]));
            }
            Ok(NpmCompatAction::DistTag {
                action: NpmDistTagAction::List {
                    spec: positionals.pop(),
                    npm_registry,
                    userconfig,
                },
            })
        }
    }
}

pub(crate) fn parse_npm_sbom_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut format = None;
    let mut sbom_type = NpmSbomType::Library;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--sbom-format" {
            index += 1;
            let value = args.get(index).ok_or_else(|| {
                OmcRegistryError::UnsupportedSpec("--sbom-format needs a value".to_owned())
            })?;
            format = Some(parse_npm_sbom_format(value)?);
        } else if let Some(value) = arg.strip_prefix("--sbom-format=") {
            format = Some(parse_npm_sbom_format(value)?);
        } else if arg == "--sbom-type" {
            index += 1;
            let value = args.get(index).ok_or_else(|| {
                OmcRegistryError::UnsupportedSpec("--sbom-type needs a value".to_owned())
            })?;
            sbom_type = parse_npm_sbom_type(value)?;
        } else if let Some(value) = arg.strip_prefix("--sbom-type=") {
            sbom_type = parse_npm_sbom_type(value)?;
        } else if matches!(
            arg.as_str(),
            "--json"
                | "--package-lock-only"
                | "--silent"
                | "-s"
                | "--workspaces"
                | "--include-workspace-root"
        ) || npm_workspace_scope_ignored_flag(arg)
            || npm_sbom_ignored_equals_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "--omit" | "--include" | "--workspace" | "-w" | "--loglevel"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm sbom", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    if !positionals.is_empty() {
        return Err(unsupported_compat_arg("npm sbom", &positionals[0]));
    }
    let Some(format) = format else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm sbom needs --sbom-format with one of: cyclonedx, spdx".to_owned(),
        ));
    };
    Ok(NpmCompatAction::Sbom {
        action: NpmSbomAction { format, sbom_type },
    })
}

pub(crate) fn parse_npm_sbom_format(value: &str) -> Result<NpmSbomFormat, OmcRegistryError> {
    match value {
        "cyclonedx" => Ok(NpmSbomFormat::CycloneDx),
        "spdx" => Ok(NpmSbomFormat::Spdx),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm sbom format `{other}`"
        ))),
    }
}

pub(crate) fn parse_npm_sbom_type(value: &str) -> Result<NpmSbomType, OmcRegistryError> {
    match value {
        "library" => Ok(NpmSbomType::Library),
        "application" => Ok(NpmSbomType::Application),
        "framework" => Ok(NpmSbomType::Framework),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm sbom type `{other}`"
        ))),
    }
}

pub(crate) fn parse_npm_registry_identity_args(
    command: &str,
    args: &[String],
) -> Result<(bool, Option<String>, Option<PathBuf>), OmcRegistryError> {
    let mut json = false;
    let mut userconfig = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable") {
        } else if arg == "--userconfig" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value")))?;
            userconfig = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--loglevel" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_registry_identity_equals_value_flag(arg) {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        npm_registry,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    if !positionals.is_empty() {
        return Err(unsupported_compat_arg(command, &positionals[0]));
    }
    Ok((json, npm_registry, userconfig))
}

pub(crate) fn parse_npm_explain_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut specs = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_json_flag_value(arg) {
            json = value;
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--long" | "--parseable") {
        } else if matches!(arg.as_str(), "--workspace" | "-w" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_explain_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm explain", arg));
        } else {
            specs.push(arg.clone());
        }
        index += 1;
    }
    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm explain needs at least one package".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Explain { specs, json })
}

pub(crate) fn parse_npm_config_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let NpmConfigArgs {
        editor,
        json,
        location,
        npm_registry,
        userconfig,
        globalconfig,
        mut positionals,
    } = parse_npm_config_common_args(args)?;
    let command = if positionals.is_empty() {
        "list".to_owned()
    } else {
        positionals.remove(0)
    };
    match command.as_str() {
        "get" => {
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm config get needs at least one key".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Config {
                action: NpmConfigAction::Get {
                    keys: positionals,
                    json,
                    location,
                },
                npm_registry,
                userconfig,
                globalconfig,
            })
        }
        "list" | "ls" => {
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("npm config list", &positionals[0]));
            }
            Ok(NpmCompatAction::Config {
                action: NpmConfigAction::List { json, location },
                npm_registry,
                userconfig,
                globalconfig,
            })
        }
        "edit" => {
            if !positionals.is_empty() {
                return Err(unsupported_compat_arg("npm config edit", &positionals[0]));
            }
            Ok(NpmCompatAction::ConfigEdit {
                location,
                editor,
                userconfig,
                globalconfig,
            })
        }
        "set" => {
            let assignments = parse_npm_config_assignments(positionals)?;
            Ok(NpmCompatAction::Config {
                action: NpmConfigAction::Set {
                    assignments,
                    location,
                },
                npm_registry,
                userconfig,
                globalconfig,
            })
        }
        "delete" | "del" | "rm" | "unset" => {
            if positionals.is_empty() {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm config delete needs at least one key".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Config {
                action: NpmConfigAction::Delete {
                    keys: positionals,
                    location,
                },
                npm_registry,
                userconfig,
                globalconfig,
            })
        }
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm config command `{other}`"
        ))),
    }
}

pub(crate) fn parse_npm_metadata_url_args(
    command: &str,
    kind: NpmMetadataUrlKind,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if matches!(
            arg.as_str(),
            "--browser" | "--browser=true" | "--browser=false"
        ) {
        } else if matches!(arg.as_str(), "--userconfig" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable")
            || npm_metadata_url_equals_value_flag(arg)
        {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        npm_registry,
        mut positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    if positionals.len() > 1 {
        return Err(unsupported_compat_arg(command, &positionals[1]));
    }
    Ok(NpmCompatAction::MetadataUrl {
        kind,
        spec: positionals.pop(),
        json,
        npm_registry,
    })
}

pub(crate) fn parse_npm_config_get_args(
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let NpmConfigArgs {
        json,
        location,
        npm_registry,
        userconfig,
        globalconfig,
        positionals,
        ..
    } = parse_npm_config_common_args(args)?;
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config get needs at least one key".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Config {
        action: NpmConfigAction::Get {
            keys: positionals,
            json,
            location,
        },
        npm_registry,
        userconfig,
        globalconfig,
    })
}

pub(crate) fn parse_npm_config_set_args(
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let NpmConfigArgs {
        location,
        npm_registry,
        userconfig,
        globalconfig,
        positionals,
        ..
    } = parse_npm_config_common_args(args)?;
    let assignments = parse_npm_config_assignments(positionals)?;
    Ok(NpmCompatAction::Config {
        action: NpmConfigAction::Set {
            assignments,
            location,
        },
        npm_registry,
        userconfig,
        globalconfig,
    })
}

pub(crate) fn parse_npm_config_assignments(
    positionals: Vec<String>,
) -> Result<Vec<(String, String)>, OmcRegistryError> {
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config set needs a key and value".to_owned(),
        ));
    }
    if positionals.iter().any(|value| value.contains('=')) {
        return positionals
            .into_iter()
            .map(|assignment| {
                let Some((key, value)) = assignment.split_once('=') else {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "npm config set mixed assignment formats at `{assignment}`"
                    )));
                };
                npm_config_assignment(key, value)
            })
            .collect();
    }
    if positionals.len() != 2 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm config set needs either KEY VALUE or KEY=VALUE".to_owned(),
        ));
    }
    npm_config_assignment(&positionals[0], &positionals[1]).map(|assignment| vec![assignment])
}

pub(crate) fn parse_npm_config_common_args(
    args: &[String],
) -> Result<NpmConfigArgs, OmcRegistryError> {
    let mut editor = None;
    let mut json = false;
    let mut location = NpmConfigLocation::User;
    let mut userconfig = None;
    let mut globalconfig = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--userconfig" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--userconfig needs a path".to_owned(),
                ));
            };
            userconfig = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(path));
        } else if arg == "--globalconfig" {
            index += 1;
            let Some(path) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--globalconfig needs a path".to_owned(),
                ));
            };
            globalconfig = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--globalconfig=") {
            globalconfig = Some(PathBuf::from(path));
        } else if matches!(arg.as_str(), "--global" | "-g") {
            location = NpmConfigLocation::Global;
        } else if arg == "--location" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--location needs a value".to_owned(),
                ));
            };
            location = parse_npm_config_location(value)?;
        } else if let Some(value) = arg.strip_prefix("--location=") {
            location = parse_npm_config_location(value)?;
        } else if arg == "--editor" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--editor needs a value".to_owned(),
                ));
            };
            editor = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--editor=") {
            editor = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--long" | "-l" | "--parseable") {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags {
        npm_registry,
        positionals,
        ..
    } = parse_common_compat_flags(&filtered, true)?;
    Ok(NpmConfigArgs {
        editor,
        json,
        location,
        npm_registry,
        userconfig,
        globalconfig,
        positionals,
    })
}

pub(crate) fn parse_npm_config_location(
    value: &str,
) -> Result<NpmConfigLocation, OmcRegistryError> {
    match value {
        "user" => Ok(NpmConfigLocation::User),
        "project" => Ok(NpmConfigLocation::Project),
        "global" => Ok(NpmConfigLocation::Global),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm config location `{other}`"
        ))),
    }
}

pub(crate) fn parse_npm_run_args(
    command: &str,
    args: &[String],
    implicit_name: Option<&str>,
) -> Result<NpmRunArgs, OmcRegistryError> {
    let mut name = implicit_name.map(str::to_owned);
    let mut script_args = Vec::new();
    let mut if_present = false;
    let mut json = false;
    let mut workspaces = Vec::new();
    let mut all_workspaces = false;
    let mut include_workspace_root = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            script_args.extend(args[index + 1..].iter().cloned());
            break;
        } else if matches!(
            arg.as_str(),
            "--if-present" | "--silent" | "-s" | "--loglevel=silent"
        ) {
            if arg == "--if-present" {
                if_present = true;
            }
        } else if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if let Some(value) = npm_all_workspaces_flag_value(arg) {
            all_workspaces = value;
        } else if let Some(value) = npm_include_workspace_root_flag_value(arg) {
            include_workspace_root = value;
        } else if matches!(arg.as_str(), "--workspace" | "-w") {
            index += 1;
            let Some(workspace) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a workspace"
                )));
            };
            workspaces.push(workspace.clone());
        } else if let Some(workspace) = arg
            .strip_prefix("--workspace=")
            .or_else(|| arg.strip_prefix("-w="))
        {
            workspaces.push(workspace.to_owned());
        } else if let Some(workspace) = npm_attached_short_value(arg, 'w') {
            workspaces.push(workspace.to_owned());
        } else if arg == "--loglevel" {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_run_equals_value_flag(arg) {
        } else if name.is_none() && !arg.starts_with('-') {
            name = Some(arg.clone());
        } else if name.is_some() {
            script_args.push(arg.clone());
        } else {
            return Err(unsupported_compat_arg(command, arg));
        }
        index += 1;
    }

    if name.is_none() && !script_args.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{command} needs a target"
        )));
    }
    Ok(NpmRunArgs {
        name,
        args: script_args,
        if_present,
        json,
        workspaces,
        all_workspaces,
        include_workspace_root,
    })
}

pub(crate) fn parse_npm_exec_args(
    command_name: &str,
    args: &[String],
) -> Result<NpmExecAction, OmcRegistryError> {
    let mut packages = Vec::new();
    let mut no_install = false;
    let mut npm_registry = None;
    let mut allow = Vec::new();
    let mut allow_flow = Vec::new();
    let mut allow_all_host = false;
    let mut workspaces = Vec::new();
    let mut all_workspaces = false;
    let mut include_workspace_root = false;
    let mut call = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            filtered.extend(args[index + 1..].iter().cloned());
            break;
        } else if matches!(
            arg.as_str(),
            "-y" | "--yes"
                | "--no"
                | "--ignore-existing"
                | "--foreground-scripts"
                | "--quiet"
                | "--silent"
        ) {
        } else if arg == "--no-install" {
            no_install = true;
        } else if matches!(arg.as_str(), "-c" | "--call") {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a command"
                )));
            };
            call = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--call=") {
            call = Some(value.to_owned());
        } else if matches!(arg.as_str(), "-p" | "--package") {
            index += 1;
            let Some(package) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            packages.push(package.clone());
        } else if let Some(package) = arg.strip_prefix("--package=") {
            packages.push(package.to_owned());
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
        } else if arg == "--allow" {
            index += 1;
            let Some(grant) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--allow needs a capability grant".to_owned(),
                ));
            };
            allow.push(grant.clone());
        } else if let Some(grant) = arg.strip_prefix("--allow=") {
            allow.push(grant.to_owned());
        } else if arg == "--allow-flow" {
            index += 1;
            let Some(flow) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--allow-flow needs a data-flow grant".to_owned(),
                ));
            };
            allow_flow.push(flow.clone());
        } else if let Some(flow) = arg.strip_prefix("--allow-flow=") {
            allow_flow.push(flow.to_owned());
        } else if arg == "--allow-all-host" {
            allow_all_host = true;
        } else if let Some(value) = npm_all_workspaces_flag_value(arg) {
            all_workspaces = value;
        } else if let Some(value) = npm_include_workspace_root_flag_value(arg) {
            include_workspace_root = value;
        } else if matches!(arg.as_str(), "--workspace" | "-w") {
            index += 1;
            let Some(workspace) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a workspace"
                )));
            };
            workspaces.push(workspace.clone());
        } else if let Some(workspace) = arg
            .strip_prefix("--workspace=")
            .or_else(|| arg.strip_prefix("-w="))
        {
            workspaces.push(workspace.to_owned());
        } else if let Some(workspace) = npm_attached_short_value(arg, 'w') {
            workspaces.push(workspace.to_owned());
        } else if ignored_npm_install_preference_flag(arg) {
        } else if matches!(arg.as_str(), "--cache" | "--userconfig" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_exec_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm exec", arg));
        } else {
            filtered.push(arg.clone());
            filtered.extend(args[index + 1..].iter().cloned());
            break;
        }
        index += 1;
    }
    let (command, args, prefer_project_bin) = if let Some(call) = call {
        if let Some(extra) = filtered.first() {
            return Err(unsupported_compat_arg("npm exec", extra));
        }
        let (command, args) = npm_exec_call_command(call);
        (command, args, false)
    } else {
        let (mut command, args) = split_first_position("npm exec", &filtered)?;
        let direct_package_command =
            packages.is_empty() && !no_install && npm_exec_direct_package_arg(&command);
        let prefer_project_bin = direct_package_command
            || (command_name == "npx"
                && packages.is_empty()
                && !no_install
                && npm_exec_should_infer_package(&command));
        if direct_package_command {
            packages.push(command.clone());
        } else if prefer_project_bin {
            let package = command.clone();
            command = npm_exec_inferred_bin_name(&package)?;
            packages.push(package);
        }
        (command, args, prefer_project_bin)
    };
    Ok(NpmExecAction {
        packages,
        command,
        args,
        no_install,
        prefer_project_bin,
        npm_registry,
        allow,
        allow_flow,
        allow_all_host,
        workspaces,
        all_workspaces,
        include_workspace_root,
    })
}

pub(crate) fn parse_npm_explore_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut package = None;
    let mut command = None;
    let mut command_args = Vec::new();
    let mut shell = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            let Some(command_arg) = args.get(index + 1) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm explore -- needs a command".to_owned(),
                ));
            };
            command = Some(command_arg.clone());
            command_args.extend(args[index + 2..].iter().cloned());
            break;
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p") {
        } else if arg == "--shell" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--shell needs a value".to_owned(),
                ));
            };
            shell = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--shell=") {
            shell = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--loglevel" | "--cache" | "--registry") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_explore_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm explore", arg));
        } else if package.is_none() {
            package = Some(arg.clone());
        } else {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm explore accepts one package before --".to_owned(),
            ));
        }
        index += 1;
    }

    let Some(package) = package else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm explore needs a package name".to_owned(),
        ));
    };
    Ok(NpmCompatAction::Explore {
        action: NpmExploreAction {
            package,
            command,
            args: command_args,
            shell,
        },
    })
}

pub(crate) fn parse_npm_edit_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut editor = None;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--editor" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--editor needs a value".to_owned(),
                ));
            };
            editor = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--editor=") {
            editor = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--loglevel" | "--cache" | "--registry") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_edit_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm edit", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    match positionals.as_slice() {
        [] => Err(OmcRegistryError::UnsupportedSpec(
            "npm edit needs a package".to_owned(),
        )),
        [target] => Ok(NpmCompatAction::Edit {
            target: target.clone(),
            editor,
        }),
        [_, extra, ..] => Err(unsupported_compat_arg("npm edit", extra)),
    }
}

pub(crate) fn parse_npm_list_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut depth = 0usize;
    let mut packages = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_json_flag_value(arg) {
            json = value;
        } else if let Some(value) = npm_list_all_flag_value(arg) {
            if value {
                depth = usize::MAX;
            } else {
                depth = 0;
            }
        } else if let Some(value) = npm_list_short_all_flag_value(arg) {
            if value {
                depth = usize::MAX;
            }
        } else if arg == "--depth" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "--depth needs a value".to_owned(),
                ));
            };
            depth = parse_npm_list_depth(value)?;
        } else if let Some(value) = arg.strip_prefix("--depth=") {
            depth = parse_npm_list_depth(value)?;
        } else if matches!(
            arg.as_str(),
            "--long"
                | "--parseable"
                | "-p"
                | "--production"
                | "--prod"
                | "--dev"
                | "--global"
                | "-g"
                | "--silent"
                | "-s"
                | "--color=false"
                | "--no-color"
        ) || npm_workspace_scope_ignored_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "--omit" | "--include" | "--loglevel" | "--workspace" | "-w"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_list_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm list", arg));
        } else {
            packages.push(arg.clone());
        }
        index += 1;
    }
    Ok(NpmCompatAction::List {
        action: NpmListAction {
            json,
            depth,
            packages,
        },
    })
}

pub(crate) fn parse_npm_list_depth(value: &str) -> Result<usize, OmcRegistryError> {
    if value.eq_ignore_ascii_case("infinity") {
        return Ok(usize::MAX);
    }
    value.parse::<usize>().map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!("unsupported npm list depth `{value}`"))
    })
}
