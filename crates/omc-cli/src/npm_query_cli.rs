//! npm view/diff/search/outdated/fund/audit query commands.
//!
//! Extracted from `lib.rs`: the `npm view`, `npm diff`, `npm search`,
//! `npm outdated`, `npm fund`, `npm audit`, and `npm query` subcommands —
//! their handlers, argument parsers, selector engine, and private helpers.

use crate::*;

use crate::args::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) fn print_npm_view(
    project_dir: &Path,
    spec: &str,
    fields: &[String],
    json: bool,
    npm_registry: Option<&str>,
) -> Result<(), OmcRegistryError> {
    let spec = parse_package_spec(spec, Some(Ecosystem::Npm))?;
    let metadata = read_npm_package_metadata(project_dir, &spec, npm_registry)?;
    if fields.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&npm_view_metadata_value(&metadata))?
            );
        } else {
            println!("{}@{}", metadata.name, metadata.version);
            if let Some(tarball) = npm_view_field_value(&metadata, "dist.tarball") {
                println!("dist.tarball = {}", npm_view_text_value(&tarball));
            }
            if !metadata.dist_tags.is_empty() {
                let tags = serde_json::to_value(&metadata.dist_tags)?;
                println!("dist-tags = {}", npm_view_text_value(&tags));
            }
        }
        return Ok(());
    }

    if json {
        if fields.len() == 1 {
            let value =
                npm_view_field_value(&metadata, &fields[0]).unwrap_or(serde_json::Value::Null);
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            let selected = fields
                .iter()
                .map(|field| {
                    (
                        field.clone(),
                        npm_view_field_value(&metadata, field).unwrap_or(serde_json::Value::Null),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            println!("{}", serde_json::to_string_pretty(&selected)?);
        }
    } else if fields.len() == 1 {
        let value = npm_view_field_value(&metadata, &fields[0]).unwrap_or(serde_json::Value::Null);
        println!("{}", npm_view_text_value(&value));
    } else {
        for field in fields {
            let value = npm_view_field_value(&metadata, field).unwrap_or(serde_json::Value::Null);
            println!("{field} = {}", npm_view_text_value(&value));
        }
    }

    Ok(())
}


pub(crate) fn print_npm_search(project_dir: &Path, action: NpmSearchAction) -> Result<(), OmcRegistryError> {
    let packages = read_npm_search(
        project_dir,
        &action.query,
        action.limit,
        action.npm_registry.as_deref(),
    )?;
    if action.json {
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else if action.parseable {
        for package in &packages {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                package.name,
                package.description.as_deref().unwrap_or_default(),
                npm_search_short_date(package),
                package.version,
                package.keywords.join(",")
            );
        }
    } else if packages.is_empty() {
        println!("No matches found for \"{}\"", action.query);
    } else {
        for package in &packages {
            println!("{}", package.name);
            if let Some(description) = &package.description {
                if !description.is_empty() {
                    println!("{description}");
                }
            }
            println!(
                "Version {} published {}{}",
                package.version,
                npm_search_short_date(package),
                npm_search_publisher_suffix(package)
            );
            let maintainers = npm_search_usernames(&package.maintainers);
            if !maintainers.is_empty() {
                println!("Maintainers: {}", maintainers.join(" "));
            }
            if !package.keywords.is_empty() {
                println!("Keywords: {}", package.keywords.join(" "));
            }
            println!("{}", npm_search_package_url(package));
            println!();
        }
    }
    Ok(())
}













fn npm_search_short_date(package: &NpmSearchPackage) -> &str {
    package
        .date
        .as_deref()
        .and_then(|date| date.get(..10))
        .unwrap_or("unknown")
}


fn npm_search_publisher_suffix(package: &NpmSearchPackage) -> String {
    package
        .publisher
        .as_ref()
        .and_then(npm_search_username)
        .map(|publisher| format!(" by {publisher}"))
        .unwrap_or_default()
}


fn npm_search_usernames(users: &[omc_registry::NpmSearchUser]) -> Vec<String> {
    users.iter().filter_map(npm_search_username).collect()
}


fn npm_search_username(user: &omc_registry::NpmSearchUser) -> Option<String> {
    user.username.clone().or_else(|| user.email.clone())
}


fn npm_search_package_url(package: &NpmSearchPackage) -> String {
    package
        .links
        .get("npm")
        .cloned()
        .unwrap_or_else(|| format!("https://npm.im/{}", package.name))
}


#[derive(Debug)]
pub(crate) struct NpmOutdatedPackage {
    name: String,
    current: String,
    wanted: String,
    latest: String,
    location: PathBuf,
    dependent: String,
}


pub(crate) fn print_npm_outdated(
    project_dir: &Path,
    json: bool,
    parseable: bool,
    packages: &[String],
    npm_registry: Option<&str>,
) -> Result<ExitCode, OmcRegistryError> {
    let filter_names = package_list_filter_names(packages, Some(Ecosystem::Npm))?;
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let dependent = npm_outdated_dependent(project_dir);
    let mut rows = Vec::new();
    for package in lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
        .filter(|package| filter_names.is_empty() || filter_names.contains(&package.name))
    {
        let spec = parse_package_spec(&package.name, Some(Ecosystem::Npm))?;
        let metadata = read_npm_package_metadata(project_dir, &spec, npm_registry)?;
        if compare_npm_versions(&metadata.version, &package.version).is_gt() {
            rows.push(NpmOutdatedPackage {
                location: npm_outdated_location(project_dir, &package.name),
                name: package.name.clone(),
                current: package.version.clone(),
                wanted: metadata.version.clone(),
                latest: metadata.version,
                dependent: dependent.clone(),
            });
        }
    }
    rows.sort_by(|left, right| left.name.cmp(&right.name));

    if json {
        let packages = rows
            .iter()
            .map(|row| {
                (
                    row.name.clone(),
                    serde_json::json!({
                        "current": row.current,
                        "wanted": row.wanted,
                        "latest": row.latest,
                        "dependent": row.dependent,
                        "location": row.location.display().to_string(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else if parseable {
        for row in &rows {
            println!(
                "{}:{}:{}:{}",
                row.location.display(),
                row.current,
                row.wanted,
                row.latest
            );
        }
    } else if !rows.is_empty() {
        println!("Package Current Wanted Latest Location Depended by");
        for row in &rows {
            println!(
                "{} {} {} {} {} {}",
                row.name,
                row.current,
                row.wanted,
                row.latest,
                row.location.display(),
                row.dependent
            );
        }
    }

    if rows.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}


pub(crate) fn npm_view_field_value(
    metadata: &omc_registry::NpmPackageMetadata,
    field: &str,
) -> Option<serde_json::Value> {
    let tokens = npm_view_selector_tokens(field)?;
    npm_view_select_value(&npm_view_metadata_value(metadata), &tokens, String::new())
}


#[derive(Debug, Clone, PartialEq, Eq)]
enum NpmViewSelectorToken {
    Field(String),
    Index(usize),
}


pub(crate) fn npm_view_metadata_value(metadata: &omc_registry::NpmPackageMetadata) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    if let serde_json::Value::Object(root) = &metadata.root {
        object.extend(root.clone());
    }
    if let serde_json::Value::Object(manifest) = &metadata.manifest {
        object.extend(manifest.clone());
    }
    object.insert(
        "name".to_owned(),
        serde_json::Value::String(metadata.name.clone()),
    );
    object.insert(
        "version".to_owned(),
        serde_json::Value::String(metadata.version.clone()),
    );
    if let Ok(versions) = serde_json::to_value(&metadata.versions) {
        object.insert("versions".to_owned(), versions);
    }
    if let Ok(dist_tags) = serde_json::to_value(&metadata.dist_tags) {
        object.insert("dist-tags".to_owned(), dist_tags.clone());
        object.insert("distTags".to_owned(), dist_tags);
    }
    serde_json::Value::Object(object)
}


fn npm_view_selector_tokens(field: &str) -> Option<Vec<NpmViewSelectorToken>> {
    if field.trim().is_empty() {
        return None;
    }

    let mut tokens = Vec::new();
    for segment in field.split('.') {
        if segment.is_empty() {
            return None;
        }
        npm_view_selector_segment_tokens(segment, &mut tokens)?;
    }
    Some(tokens)
}


fn npm_view_selector_segment_tokens(
    mut segment: &str,
    tokens: &mut Vec<NpmViewSelectorToken>,
) -> Option<()> {
    loop {
        let Some(bracket_start) = segment.find('[') else {
            if !segment.is_empty() {
                tokens.push(NpmViewSelectorToken::Field(segment.to_owned()));
            }
            return Some(());
        };

        let field = &segment[..bracket_start];
        if !field.is_empty() {
            tokens.push(NpmViewSelectorToken::Field(field.to_owned()));
        }

        let after_open = &segment[bracket_start + 1..];
        let bracket_end = after_open.find(']')?;
        let bracket = after_open[..bracket_end].trim();
        tokens.push(npm_view_bracket_token(bracket)?);

        segment = &after_open[bracket_end + 1..];
        if segment.is_empty() {
            return Some(());
        }
        if !segment.starts_with('[') {
            return None;
        }
    }
}


fn npm_view_bracket_token(raw: &str) -> Option<NpmViewSelectorToken> {
    let value = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            raw.strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(raw);
    if value.is_empty() {
        return None;
    }
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        return value.parse().ok().map(NpmViewSelectorToken::Index);
    }
    Some(NpmViewSelectorToken::Field(value.to_owned()))
}


fn npm_view_select_value(
    value: &serde_json::Value,
    tokens: &[NpmViewSelectorToken],
    path: String,
) -> Option<serde_json::Value> {
    let Some((token, rest)) = tokens.split_first() else {
        return Some(value.clone());
    };

    match (value, token) {
        (serde_json::Value::Object(object), NpmViewSelectorToken::Field(field)) => {
            object.get(field).and_then(|value| {
                npm_view_select_value(value, rest, npm_view_append_field(&path, field))
            })
        }
        (serde_json::Value::Array(values), NpmViewSelectorToken::Index(index)) => values
            .get(*index)
            .and_then(|value| npm_view_select_value(value, rest, format!("{path}[{index}]"))),
        (serde_json::Value::Object(object), NpmViewSelectorToken::Index(index)) => object
            .get(&index.to_string())
            .and_then(|value| npm_view_select_value(value, rest, format!("{path}[{index}]"))),
        (serde_json::Value::Array(values), NpmViewSelectorToken::Field(_)) => {
            let suffix = npm_view_selector_suffix(tokens);
            let mut projected = serde_json::Map::new();
            for (index, item) in values.iter().enumerate() {
                let item_path = format!("{path}[{index}]");
                if let Some(value) = npm_view_select_value(item, tokens, item_path.clone()) {
                    projected.insert(format!("{item_path}{suffix}"), value);
                }
            }
            (!projected.is_empty()).then_some(serde_json::Value::Object(projected))
        }
        _ => None,
    }
}


fn npm_view_append_field(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_owned()
    } else {
        format!("{path}.{field}")
    }
}


fn npm_view_selector_suffix(tokens: &[NpmViewSelectorToken]) -> String {
    let mut suffix = String::new();
    for token in tokens {
        match token {
            NpmViewSelectorToken::Field(field) => {
                suffix.push('.');
                suffix.push_str(field);
            }
            NpmViewSelectorToken::Index(index) => suffix.push_str(&format!("[{index}]")),
        }
    }
    suffix
}


fn npm_view_text_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "undefined".to_owned(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}


pub(crate) fn print_npm_fund(project_dir: &Path, action: NpmFundAction) -> Result<(), OmcRegistryError> {
    let report = collect_npm_fund_report(project_dir, &action)?;
    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&npm_fund_report_json(&report))?
        );
    } else {
        print_npm_fund_text(&report, action.package.as_deref());
    }
    Ok(())
}


#[derive(Debug, Clone)]
pub(crate) struct NpmFundReport {
    pub(crate) root: Option<NpmFundPackage>,
    pub(crate) dependencies: Vec<NpmFundPackage>,
}


#[derive(Debug, Clone)]
pub(crate) struct NpmFundPackage {
    pub(crate) name: String,
    version: Option<String>,
    funding: Option<serde_json::Value>,
    urls: Vec<String>,
}


impl NpmFundPackage {
    pub(crate) fn id(&self) -> String {
        match self.version.as_deref() {
            Some(version) if !version.is_empty() => format!("{}@{}", self.name, version),
            _ => self.name.clone(),
        }
    }
}


pub(crate) fn collect_npm_fund_report(
    project_dir: &Path,
    action: &NpmFundAction,
) -> Result<NpmFundReport, OmcRegistryError> {
    let target_dirs = npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )?;
    let report_root_dir = if target_dirs.len() == 1 {
        target_dirs[0].clone()
    } else {
        project_dir.to_path_buf()
    };
    let report_root_dir = absolute_project_dir(&report_root_dir);
    let package_filter = action.package.as_deref().map(npm_fund_filter_name);

    let mut root = None;
    let mut dependencies = BTreeMap::new();
    for target_dir in target_dirs {
        let target_dir = absolute_project_dir(&target_dir);
        let target_root = npm_fund_package_from_dir(&target_dir)?;
        let is_report_root = target_dir == report_root_dir;
        if is_report_root {
            root = Some(target_root.clone());
        } else {
            insert_npm_fund_dependency(&mut dependencies, target_root, package_filter.as_deref());
        }

        for package_json in npm_fund_installed_package_jsons(&target_dir)? {
            let package = npm_fund_package_from_package_json(&package_json)?;
            insert_npm_fund_dependency(&mut dependencies, package, package_filter.as_deref());
        }
    }

    if let Some(filter) = package_filter.as_deref() {
        if root
            .as_ref()
            .is_some_and(|package| !npm_fund_package_matches(package, filter))
        {
            root = None;
        }
    }

    Ok(NpmFundReport {
        root,
        dependencies: dependencies.into_values().collect(),
    })
}


fn insert_npm_fund_dependency(
    dependencies: &mut BTreeMap<String, NpmFundPackage>,
    package: NpmFundPackage,
    package_filter: Option<&str>,
) {
    if package_filter.is_some_and(|filter| !npm_fund_package_matches(&package, filter)) {
        return;
    }
    if package.funding.is_none() {
        return;
    }
    dependencies.entry(package.name.clone()).or_insert(package);
}


fn npm_fund_package_from_dir(dir: &Path) -> Result<NpmFundPackage, OmcRegistryError> {
    npm_fund_package_from_package_json(&dir.join("package.json"))
}


fn npm_fund_package_from_package_json(
    package_json: &Path,
) -> Result<NpmFundPackage, OmcRegistryError> {
    let package = read_npm_pkg_json(package_json)?;
    let name = npm_package_json_name(&package)?;
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty())
        .map(str::to_owned);
    let funding = package.get("funding").and_then(normalize_npm_funding);
    let urls = funding.as_ref().map(npm_funding_urls).unwrap_or_default();
    Ok(NpmFundPackage {
        name,
        version,
        funding,
        urls,
    })
}


fn npm_fund_installed_package_jsons(project_dir: &Path) -> Result<Vec<PathBuf>, OmcRegistryError> {
    let node_modules = project_dir.join("node_modules");
    if !node_modules.exists() {
        return Ok(Vec::new());
    }

    let mut package_jsons = Vec::new();
    for entry in fs::read_dir(&node_modules)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".bin" || name.starts_with('.') || !path.is_dir() {
            continue;
        }
        if name.starts_with('@') {
            for scoped_entry in fs::read_dir(&path)? {
                let scoped_entry = scoped_entry?;
                let scoped_path = scoped_entry.path();
                if scoped_path.is_dir() {
                    let package_json = scoped_path.join("package.json");
                    if package_json.exists() {
                        package_jsons.push(package_json);
                    }
                }
            }
        } else {
            let package_json = path.join("package.json");
            if package_json.exists() {
                package_jsons.push(package_json);
            }
        }
    }
    package_jsons.sort();
    Ok(package_jsons)
}


pub(crate) fn normalize_npm_funding(value: &serde_json::Value) -> Option<serde_json::Value> {
    match value {
        serde_json::Value::String(url) => npm_funding_url_value(url),
        serde_json::Value::Object(_) => {
            if npm_funding_urls(value).is_empty() {
                None
            } else {
                Some(value.clone())
            }
        }
        serde_json::Value::Array(values) => {
            let normalized = values
                .iter()
                .filter_map(normalize_npm_funding)
                .collect::<Vec<_>>();
            if normalized.is_empty() {
                None
            } else {
                Some(serde_json::Value::Array(normalized))
            }
        }
        _ => None,
    }
}


fn npm_funding_url_value(url: &str) -> Option<serde_json::Value> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    Some(serde_json::json!({ "url": url }))
}


pub(crate) fn npm_funding_urls(value: &serde_json::Value) -> Vec<String> {
    let mut urls = Vec::new();
    collect_npm_funding_urls(value, &mut urls);
    urls.sort();
    urls.dedup();
    urls
}


pub(crate) fn npm_fund_report_json(report: &NpmFundReport) -> serde_json::Value {
    let mut dependencies = serde_json::Map::new();
    for package in &report.dependencies {
        if package.funding.is_none() {
            continue;
        }
        dependencies.insert(package.name.clone(), npm_fund_package_json(package, false));
    }

    let mut object = serde_json::Map::new();
    object.insert(
        "length".to_owned(),
        serde_json::Value::Number(dependencies.len().into()),
    );
    if let Some(root) = &report.root {
        object.insert(
            "name".to_owned(),
            serde_json::Value::String(root.name.clone()),
        );
        if let Some(version) = &root.version {
            object.insert(
                "version".to_owned(),
                serde_json::Value::String(version.clone()),
            );
        }
        if let Some(funding) = &root.funding {
            object.insert("funding".to_owned(), funding.clone());
        }
    }
    object.insert(
        "dependencies".to_owned(),
        serde_json::Value::Object(dependencies),
    );
    serde_json::Value::Object(object)
}


fn npm_fund_package_json(package: &NpmFundPackage, include_name: bool) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    if include_name {
        object.insert(
            "name".to_owned(),
            serde_json::Value::String(package.name.clone()),
        );
    }
    if let Some(version) = &package.version {
        object.insert(
            "version".to_owned(),
            serde_json::Value::String(version.clone()),
        );
    }
    if let Some(funding) = &package.funding {
        object.insert("funding".to_owned(), funding.clone());
    }
    serde_json::Value::Object(object)
}


fn print_npm_fund_text(report: &NpmFundReport, package_filter: Option<&str>) {
    let package_filter = package_filter.map(npm_fund_filter_name);
    let mut packages_by_url = BTreeMap::<String, Vec<String>>::new();
    if let Some(root) = &report.root {
        if package_filter
            .as_deref()
            .is_none_or(|filter| npm_fund_package_matches(root, filter))
        {
            for url in &root.urls {
                packages_by_url
                    .entry(url.clone())
                    .or_default()
                    .push(root.id());
            }
        }
    }
    for package in &report.dependencies {
        for url in &package.urls {
            packages_by_url
                .entry(url.clone())
                .or_default()
                .push(package.id());
        }
    }

    if packages_by_url.is_empty() {
        if let Some(filter) = package_filter {
            println!("No funding information found for {filter}");
        } else if let Some(root) = &report.root {
            println!("{}", root.id());
        } else {
            println!("No funding information found");
        }
        return;
    }

    let mut first = true;
    for (url, mut package_ids) in packages_by_url {
        package_ids.sort();
        package_ids.dedup();
        if !first {
            println!();
        }
        first = false;
        println!("{url}");
        for package_id in package_ids {
            println!("  - {package_id}");
        }
    }
}


fn npm_fund_filter_name(spec: &str) -> String {
    npm_package_name_from_spec(spec)
}


fn npm_fund_package_matches(package: &NpmFundPackage, filter: &str) -> bool {
    package.name == filter || package.id() == filter
}


pub(crate) fn print_npm_diff(project_dir: &Path, action: NpmDiffAction) -> Result<(), OmcRegistryError> {
    let left = npm_diff_package_tarball(project_dir, &action.specs[0], &action)?;
    let right = npm_diff_package_tarball(project_dir, &action.specs[1], &action)?;
    let files = npm_diff_changed_files(&left, &right, &action)?;
    if action.name_only {
        for file in files {
            println!("{}", file.path);
        }
    } else {
        for file in files {
            print!("{}", npm_diff_file_patch(&left, &right, &file, &action)?);
        }
    }
    Ok(())
}


pub(crate) fn npm_diff_package_tarball(
    project_dir: &Path,
    input: &str,
    action: &NpmDiffAction,
) -> Result<NpmPackageTarball, OmcRegistryError> {
    if is_npm_local_directory_arg(input) {
        let path = absolutize_path(project_dir, npm_local_path_arg(input)?);
        if path.is_dir() {
            return npm_diff_local_package_tarball(&path);
        }
    }

    if let Some(spec) = parse_npm_direct_archive_reference(input, project_dir)? {
        return npm_diff_direct_tarball(&spec);
    }

    let spec = parse_package_spec(input, Some(Ecosystem::Npm))?;
    if let Some(direct_url) = spec.direct_url.as_deref() {
        if let Some(spec) = parse_npm_direct_archive_reference(direct_url, project_dir)? {
            return npm_diff_direct_tarball(&spec);
        }
        return npm_diff_tarball_from_url(direct_url);
    }

    download_npm_package_tarball(
        project_dir,
        &spec,
        action.npm_registry.as_deref(),
        action.userconfig.as_deref(),
    )
}


fn npm_diff_local_package_tarball(root: &Path) -> Result<NpmPackageTarball, OmcRegistryError> {
    let (pack, manifest, bytes) = npm_pack_package_for_publish(root)?;
    Ok(NpmPackageTarball {
        metadata: omc_registry::NpmPackageMetadata {
            name: pack.name,
            version: pack.version,
            dist_tags: BTreeMap::new(),
            versions: Vec::new(),
            root: serde_json::Value::Null,
            manifest,
        },
        bytes,
    })
}


fn npm_diff_direct_tarball(spec: &PackageSpec) -> Result<NpmPackageTarball, OmcRegistryError> {
    let Some(url) = spec.direct_url.as_deref() else {
        return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
    };
    npm_diff_tarball_from_url(url)
}


fn npm_diff_tarball_from_url(url: &str) -> Result<NpmPackageTarball, OmcRegistryError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|_| OmcRegistryError::UnsupportedSpec(url.to_owned()))?;
    let bytes = match parsed.scheme() {
        "file" => {
            let path = parsed.to_file_path().map_err(|_| {
                OmcRegistryError::UnsupportedSpec(format!(
                    "npm diff tarball URL `{url}` must use a valid file path"
                ))
            })?;
            fs::read(path)?
        }
        "http" | "https" => reqwest::blocking::get(url)?
            .error_for_status()?
            .bytes()?
            .to_vec(),
        _ => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "npm diff tarball URL `{url}` must use file, http, or https"
            )))
        }
    };
    npm_diff_tarball_from_bytes(bytes)
}


fn npm_diff_tarball_from_bytes(bytes: Vec<u8>) -> Result<NpmPackageTarball, OmcRegistryError> {
    let manifest = npm_manifest_from_tarball(&bytes)?;
    let name = npm_package_json_name(&manifest)?;
    let version = npm_package_json_version(&manifest)?;
    Ok(NpmPackageTarball {
        metadata: omc_registry::NpmPackageMetadata {
            name,
            version,
            dist_tags: BTreeMap::new(),
            versions: Vec::new(),
            root: serde_json::Value::Null,
            manifest,
        },
        bytes,
    })
}


#[derive(Debug)]
pub(crate) struct NpmDiffFile {
    pub(crate) path: String,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
}


pub(crate) fn npm_diff_changed_files(
    left: &NpmPackageTarball,
    right: &NpmPackageTarball,
    action: &NpmDiffAction,
) -> Result<Vec<NpmDiffFile>, OmcRegistryError> {
    let left_files = npm_diff_tarball_files(&left.bytes)?;
    let right_files = npm_diff_tarball_files(&right.bytes)?;
    let mut paths = left_files.keys().cloned().collect::<BTreeSet<_>>();
    paths.extend(right_files.keys().cloned());
    let mut changed = Vec::new();
    for path in paths {
        if !npm_diff_path_selected(&path, &action.paths) {
            continue;
        }
        let before = left_files.get(&path).map(Vec::as_slice);
        let after = right_files.get(&path).map(Vec::as_slice);
        if npm_diff_bytes_equal(before, after, action.ignore_all_space, action.text) {
            continue;
        }
        changed.push(NpmDiffFile {
            path,
            before: before.map(<[u8]>::to_vec),
            after: after.map(<[u8]>::to_vec),
        });
    }
    Ok(changed)
}


fn npm_diff_tarball_files(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, OmcRegistryError> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        let path = path
            .strip_prefix("package/")
            .unwrap_or(path.as_str())
            .to_owned();
        if path.is_empty() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        files.insert(path, bytes);
    }
    Ok(files)
}


fn npm_diff_path_selected(path: &str, filters: &[String]) -> bool {
    filters.is_empty()
        || filters.iter().any(|filter| {
            let filter = filter
                .trim_start_matches("./")
                .trim_start_matches('/')
                .trim_end_matches('/');
            !filter.is_empty() && (path == filter || path.starts_with(&format!("{filter}/")))
        })
}


fn npm_diff_bytes_equal(
    before: Option<&[u8]>,
    after: Option<&[u8]>,
    ignore_all_space: bool,
    text: bool,
) -> bool {
    match (before, after) {
        (Some(before), Some(after)) if before == after => true,
        (Some(before), Some(after)) if ignore_all_space => {
            let before = npm_diff_text(before, text);
            let after = npm_diff_text(after, text);
            before.zip(after).is_some_and(|(before, after)| {
                npm_diff_strip_all_space(&before) == npm_diff_strip_all_space(&after)
            })
        }
        _ => false,
    }
}


pub(crate) fn npm_diff_file_patch(
    left: &NpmPackageTarball,
    right: &NpmPackageTarball,
    file: &NpmDiffFile,
    action: &NpmDiffAction,
) -> Result<String, OmcRegistryError> {
    let old_path = npm_diff_prefixed_path(&file.path, &action.src_prefix, action.no_prefix);
    let new_path = npm_diff_prefixed_path(&file.path, &action.dst_prefix, action.no_prefix);
    let old_label = if file.before.is_some() {
        old_path.as_str()
    } else {
        "/dev/null"
    };
    let new_label = if file.after.is_some() {
        new_path.as_str()
    } else {
        "/dev/null"
    };

    let mut output = String::new();
    output.push_str(&format!("diff --git {old_path} {new_path}\n"));
    output.push_str(&format!(
        "index v{}..v{} 100644\n",
        left.metadata.version, right.metadata.version
    ));
    output.push_str(&format!("--- {old_label}\n"));
    output.push_str(&format!("+++ {new_label}\n"));

    let Some(before) = file
        .before
        .as_ref()
        .map(|bytes| npm_diff_text(bytes, action.text))
    else {
        output.push_str(&npm_diff_added_hunk(
            file.after.as_deref().unwrap_or_default(),
            action,
        ));
        return Ok(output);
    };
    let Some(after) = file
        .after
        .as_ref()
        .map(|bytes| npm_diff_text(bytes, action.text))
    else {
        output.push_str(&npm_diff_removed_hunk(
            file.before.as_deref().unwrap_or_default(),
            action,
        ));
        return Ok(output);
    };

    let Some((before, after)) = before.zip(after) else {
        output.push_str(&format!(
            "Binary files {old_label} and {new_label} differ\n"
        ));
        return Ok(output);
    };

    let before_lines = npm_diff_lines(&before);
    let after_lines = npm_diff_lines(&after);
    if before_lines.is_empty() && after_lines.is_empty() {
        return Ok(output);
    }
    output.push_str(&format!(
        "@@ -1,{} +1,{} @@\n",
        before_lines.len(),
        after_lines.len()
    ));
    let _context = action.unified;
    for line in before_lines {
        output.push('-');
        output.push_str(line);
        output.push('\n');
    }
    for line in after_lines {
        output.push('+');
        output.push_str(line);
        output.push('\n');
    }
    Ok(output)
}


fn npm_diff_added_hunk(bytes: &[u8], action: &NpmDiffAction) -> String {
    let Some(text) = npm_diff_text(bytes, action.text) else {
        return "Binary files /dev/null and added file differ\n".to_owned();
    };
    let lines = npm_diff_lines(&text);
    let mut output = format!("@@ -0,0 +1,{} @@\n", lines.len());
    for line in lines {
        output.push('+');
        output.push_str(line);
        output.push('\n');
    }
    output
}


fn npm_diff_removed_hunk(bytes: &[u8], action: &NpmDiffAction) -> String {
    let Some(text) = npm_diff_text(bytes, action.text) else {
        return "Binary files removed file and /dev/null differ\n".to_owned();
    };
    let lines = npm_diff_lines(&text);
    let mut output = format!("@@ -1,{} +0,0 @@\n", lines.len());
    for line in lines {
        output.push('-');
        output.push_str(line);
        output.push('\n');
    }
    output
}


fn npm_diff_prefixed_path(path: &str, prefix: &str, no_prefix: bool) -> String {
    if no_prefix {
        path.to_owned()
    } else {
        format!("{prefix}{path}")
    }
}


fn npm_diff_text(bytes: &[u8], force_text: bool) -> Option<String> {
    if force_text {
        Some(String::from_utf8_lossy(bytes).into_owned())
    } else {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}


fn npm_diff_lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}


fn npm_diff_strip_all_space(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}


#[derive(Debug, Clone, Default)]
struct NpmQueryKinds {
    root_direct: bool,
    prod: bool,
    dev: bool,
    optional: bool,
    peer: bool,
    workspace: bool,
}


#[derive(Debug, Clone)]
pub(crate) struct NpmQueryItem {
    package: serde_json::Value,
    pub(crate) name: String,
    version: String,
    location: String,
    path: PathBuf,
    realpath: PathBuf,
    resolved: String,
    from: Vec<String>,
    to: Vec<String>,
    kinds: NpmQueryKinds,
}


pub(crate) fn print_npm_query(
    project_dir: &Path,
    action: NpmQueryAction,
) -> Result<ExitCode, OmcRegistryError> {
    let items = npm_query_items(project_dir, &action)?;
    let mut selected = Vec::new();
    for item in items {
        if npm_query_selector_matches(&item, &action.selector)? {
            selected.push(npm_query_item_json(&item));
        }
    }
    println!("{}", serde_json::to_string_pretty(&selected)?);

    let count = selected.len();
    if let Some(expected) = action.expect_result_count {
        if count != expected {
            return Ok(ExitCode::from(1));
        }
    }
    if let Some(expect_results) = action.expect_results {
        if expect_results != (count > 0) {
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}


pub(crate) fn npm_query_items(
    project_dir: &Path,
    action: &NpmQueryAction,
) -> Result<Vec<NpmQueryItem>, OmcRegistryError> {
    let packages = listed_locked_packages(project_dir, Some(Ecosystem::Npm), &[])?;
    let target_dirs = npm_query_target_dirs(project_dir, action)?;
    let mut kinds = npm_query_dependency_kinds(project_dir, &target_dirs)?;
    let workspace_packages = if action.package_lock_only {
        Vec::new()
    } else {
        npm_query_workspace_packages(project_dir, &target_dirs)?
    };
    for workspace in &workspace_packages {
        if let Some(name) = &workspace.name {
            let entry = kinds.entry(name.clone()).or_default();
            entry.workspace = true;
            entry.root_direct = true;
            entry.prod = true;
        }
    }
    npm_query_mark_transitive_kinds(&mut kinds, &packages);

    let workspace_names = workspace_packages
        .iter()
        .filter_map(|workspace| workspace.name.clone())
        .collect::<BTreeSet<_>>();
    let mut items = Vec::new();
    for package in &packages {
        let mut package_kinds = kinds.get(&package.name).cloned().unwrap_or_default();
        package_kinds.workspace =
            package_kinds.workspace || workspace_names.contains(&package.name);
        let direct_query = action.workspaces.is_empty() && !action.all_workspaces;
        if !direct_query && !package_kinds.root_direct && !package_kinds.workspace {
            continue;
        }
        items.push(npm_query_locked_item(
            project_dir,
            package,
            package_kinds,
            &packages,
            action.package_lock_only,
        )?);
    }
    for workspace in workspace_packages {
        if let Some(item) = npm_query_workspace_item(project_dir, workspace, &kinds)? {
            if !items
                .iter()
                .any(|existing| existing.name == item.name && existing.kinds.workspace)
            {
                items.push(item);
            }
        }
    }
    items.sort_by(|left, right| {
        (
            left.location.as_str(),
            left.name.as_str(),
            left.version.as_str(),
        )
            .cmp(&(
                right.location.as_str(),
                right.name.as_str(),
                right.version.as_str(),
            ))
    });
    Ok(items)
}


fn npm_query_target_dirs(
    project_dir: &Path,
    action: &NpmQueryAction,
) -> Result<Vec<PathBuf>, OmcRegistryError> {
    if action.workspaces.is_empty() && !action.all_workspaces {
        return Ok(vec![project_dir.to_path_buf()]);
    }
    npm_script_target_dirs(
        project_dir,
        &action.workspaces,
        action.all_workspaces,
        action.include_workspace_root,
    )
}


fn npm_query_workspace_packages(
    project_dir: &Path,
    target_dirs: &[PathBuf],
) -> Result<Vec<NpmWorkspacePackage>, OmcRegistryError> {
    let workspaces = read_npm_workspace_packages(project_dir)?;
    if target_dirs.len() == 1
        && absolute_project_dir(&target_dirs[0]) == absolute_project_dir(project_dir)
    {
        return Ok(workspaces);
    }
    let target_dirs = target_dirs
        .iter()
        .map(|path| absolute_project_dir(path))
        .collect::<BTreeSet<_>>();
    Ok(workspaces
        .into_iter()
        .filter(|workspace| target_dirs.contains(&absolute_project_dir(&workspace.path)))
        .collect())
}


fn npm_query_dependency_kinds(
    project_dir: &Path,
    target_dirs: &[PathBuf],
) -> Result<BTreeMap<String, NpmQueryKinds>, OmcRegistryError> {
    let mut kinds = BTreeMap::<String, NpmQueryKinds>::new();
    for dir in target_dirs {
        npm_query_collect_package_json_kinds(dir, &mut kinds)?;
    }
    let include_root_manifest = target_dirs
        .iter()
        .any(|dir| absolute_project_dir(dir) == absolute_project_dir(project_dir));
    if !include_root_manifest {
        return Ok(kinds);
    }
    let manifest = read_manifest(project_dir.join("omc.toml"))?;
    for spec in manifest.dependencies.keys() {
        if let Ok(spec) = PackageSpec::parse(spec) {
            if spec.ecosystem == Ecosystem::Npm {
                let entry = kinds.entry(spec.name).or_default();
                entry.root_direct = true;
                entry.prod = true;
            }
        }
    }
    for spec in manifest.dev_dependencies.keys() {
        if let Ok(spec) = PackageSpec::parse(spec) {
            if spec.ecosystem == Ecosystem::Npm {
                let entry = kinds.entry(spec.name).or_default();
                entry.root_direct = true;
                entry.dev = true;
            }
        }
    }
    Ok(kinds)
}


fn npm_query_collect_package_json_kinds(
    dir: &Path,
    kinds: &mut BTreeMap<String, NpmQueryKinds>,
) -> Result<(), OmcRegistryError> {
    let package_json = dir.join("package.json");
    if !package_json.exists() {
        return Ok(());
    }
    let package = read_npm_pkg_json(&package_json)?;
    npm_query_mark_dependency_field(&package, "dependencies", kinds, |entry| {
        entry.prod = true;
    });
    npm_query_mark_dependency_field(&package, "devDependencies", kinds, |entry| {
        entry.dev = true;
    });
    npm_query_mark_dependency_field(&package, "optionalDependencies", kinds, |entry| {
        entry.optional = true;
    });
    npm_query_mark_dependency_field(&package, "peerDependencies", kinds, |entry| {
        entry.peer = true;
    });
    Ok(())
}


fn npm_query_mark_dependency_field(
    package: &serde_json::Value,
    field: &str,
    kinds: &mut BTreeMap<String, NpmQueryKinds>,
    mark: impl Fn(&mut NpmQueryKinds),
) {
    let Some(dependencies) = package.get(field).and_then(serde_json::Value::as_object) else {
        return;
    };
    for name in dependencies.keys() {
        let entry = kinds.entry(name.clone()).or_default();
        entry.root_direct = true;
        mark(entry);
    }
}


fn npm_query_mark_transitive_kinds(
    kinds: &mut BTreeMap<String, NpmQueryKinds>,
    packages: &[LockedPackage],
) {
    let mut queue = kinds
        .iter()
        .map(|(name, kinds)| (name.clone(), kinds.clone()))
        .collect::<VecDeque<_>>();
    while let Some((name, inherited)) = queue.pop_front() {
        for package in packages.iter().filter(|package| package.name == name) {
            for dependency in &package.dependencies {
                if let Some(dependency) = npm_dependency_name(dependency) {
                    if npm_query_merge_kinds(
                        kinds.entry(dependency.clone()).or_default(),
                        &inherited,
                    ) {
                        queue.push_back((dependency, inherited.clone()));
                    }
                }
            }
            for dependency in &package.optional_dependencies {
                if let Some(dependency) = npm_dependency_name(dependency) {
                    let mut optional = inherited.clone();
                    optional.optional = true;
                    if npm_query_merge_kinds(
                        kinds.entry(dependency.clone()).or_default(),
                        &optional,
                    ) {
                        queue.push_back((dependency, optional));
                    }
                }
            }
        }
    }
}


fn npm_query_merge_kinds(target: &mut NpmQueryKinds, source: &NpmQueryKinds) -> bool {
    let before = (
        target.prod,
        target.dev,
        target.optional,
        target.peer,
        target.workspace,
    );
    target.prod |= source.prod;
    target.dev |= source.dev;
    target.optional |= source.optional;
    target.peer |= source.peer;
    target.workspace |= source.workspace;
    before
        != (
            target.prod,
            target.dev,
            target.optional,
            target.peer,
            target.workspace,
        )
}


fn npm_query_locked_item(
    project_dir: &Path,
    package: &LockedPackage,
    kinds: NpmQueryKinds,
    packages: &[LockedPackage],
    package_lock_only: bool,
) -> Result<NpmQueryItem, OmcRegistryError> {
    let location = npm_node_modules_path(&package.name);
    let path = absolute_project_dir(project_dir).join(&location);
    let manifest = if package_lock_only {
        None
    } else {
        npm_query_installed_manifest(&path)
    }
    .unwrap_or_else(|| {
        serde_json::json!({
            "name": package.name,
            "version": package.version,
        })
    });
    let to = package
        .dependencies
        .iter()
        .chain(package.optional_dependencies.iter())
        .filter_map(|dependency| {
            npm_dependency_name(dependency).map(|name| npm_node_modules_path(&name))
        })
        .collect::<Vec<_>>();
    let mut from = npm_query_parent_locations(&package.name, packages);
    if kinds.root_direct && !from.iter().any(|location| location.is_empty()) {
        from.push(String::new());
    }
    from.sort();
    from.dedup();
    Ok(NpmQueryItem {
        package: manifest,
        name: package.name.clone(),
        version: package.version.clone(),
        location,
        realpath: path.clone(),
        path,
        resolved: package.source_url.clone(),
        from,
        to,
        kinds,
    })
}


fn npm_query_workspace_item(
    project_dir: &Path,
    workspace: NpmWorkspacePackage,
    kinds: &BTreeMap<String, NpmQueryKinds>,
) -> Result<Option<NpmQueryItem>, OmcRegistryError> {
    let package_json = workspace.path.join("package.json");
    if !package_json.exists() {
        return Ok(None);
    }
    let manifest = read_npm_pkg_json(&package_json)?;
    let Some(name) = workspace.name.or_else(|| {
        manifest
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }) else {
        return Ok(None);
    };
    let version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0.0.0")
        .to_owned();
    let location = workspace
        .path
        .strip_prefix(project_dir)
        .unwrap_or(workspace.path.as_path())
        .to_string_lossy()
        .into_owned();
    let mut item_kinds = kinds.get(&name).cloned().unwrap_or_default();
    item_kinds.workspace = true;
    item_kinds.root_direct = true;
    item_kinds.prod = true;
    let path = absolute_project_dir(&workspace.path);
    Ok(Some(NpmQueryItem {
        to: npm_query_manifest_dependency_locations(&manifest),
        package: manifest,
        name,
        version,
        location: location.clone(),
        realpath: path.clone(),
        path,
        resolved: format!("file:{location}"),
        from: vec![String::new()],
        kinds: item_kinds,
    }))
}


fn npm_query_installed_manifest(package_dir: &Path) -> Option<serde_json::Value> {
    read_npm_pkg_json(&package_dir.join("package.json")).ok()
}


fn npm_query_manifest_dependency_locations(manifest: &serde_json::Value) -> Vec<String> {
    ["dependencies", "optionalDependencies", "peerDependencies"]
        .into_iter()
        .filter_map(|field| manifest.get(field).and_then(serde_json::Value::as_object))
        .flat_map(|dependencies| dependencies.keys())
        .map(|name| npm_node_modules_path(name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}


fn npm_query_parent_locations(name: &str, packages: &[LockedPackage]) -> Vec<String> {
    packages
        .iter()
        .filter(|package| npm_lock_package_depends_on(package, name))
        .map(|package| npm_node_modules_path(&package.name))
        .collect()
}


fn npm_query_item_json(item: &NpmQueryItem) -> serde_json::Value {
    let mut value = item.package.clone();
    if !value.is_object() {
        value = serde_json::json!({});
    }
    let object = value.as_object_mut().expect("object assigned above");
    object.insert(
        "name".to_owned(),
        serde_json::Value::String(item.name.clone()),
    );
    object.insert(
        "version".to_owned(),
        serde_json::Value::String(item.version.clone()),
    );
    object.insert(
        "pkgid".to_owned(),
        serde_json::Value::String(format!("{}@{}", item.name, item.version)),
    );
    object.insert(
        "location".to_owned(),
        serde_json::Value::String(item.location.clone()),
    );
    object.insert(
        "path".to_owned(),
        serde_json::Value::String(item.path.display().to_string()),
    );
    object.insert(
        "realpath".to_owned(),
        serde_json::Value::String(item.realpath.display().to_string()),
    );
    object.insert(
        "resolved".to_owned(),
        serde_json::Value::String(item.resolved.clone()),
    );
    object.insert("from".to_owned(), serde_json::json!(item.from));
    object.insert("to".to_owned(), serde_json::json!(item.to));
    object.insert("dev".to_owned(), serde_json::Value::Bool(item.kinds.dev));
    object.insert(
        "optional".to_owned(),
        serde_json::Value::Bool(item.kinds.optional),
    );
    object.insert("peer".to_owned(), serde_json::Value::Bool(item.kinds.peer));
    object.insert(
        "prod".to_owned(),
        serde_json::Value::Bool(item.kinds.prod || !item.kinds.dev),
    );
    object.insert(
        "workspace".to_owned(),
        serde_json::Value::Bool(item.kinds.workspace),
    );
    object.insert("inBundle".to_owned(), serde_json::Value::Bool(false));
    object.insert(
        "deduped".to_owned(),
        serde_json::Value::Bool(item.from.len() > 1),
    );
    object.insert("overridden".to_owned(), serde_json::Value::Bool(false));
    object.insert(
        "queryContext".to_owned(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    value
}


pub(crate) fn npm_query_selector_matches(
    item: &NpmQueryItem,
    selector: &str,
) -> Result<bool, OmcRegistryError> {
    for selector in npm_query_selector_parts(selector) {
        if npm_query_single_selector_matches(item, selector)? {
            return Ok(true);
        }
    }
    Ok(false)
}


fn npm_query_selector_parts(selector: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in selector.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if paren_depth == 0 && bracket_depth == 0 => {
                let part = selector[start..index].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    let part = selector[start..].trim();
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}


fn npm_query_single_selector_matches(
    item: &NpmQueryItem,
    selector: &str,
) -> Result<bool, OmcRegistryError> {
    let selector = selector.split_whitespace().collect::<String>();
    if selector == "*" {
        return Ok(true);
    }
    let (direct_required, selector) = selector
        .strip_prefix(":root>")
        .map(|rest| (true, rest))
        .unwrap_or((false, selector.as_str()));
    if direct_required && !item.kinds.root_direct {
        return Ok(false);
    }
    let selector = if selector.is_empty() { "*" } else { selector };
    npm_query_compound_selector_matches(item, selector)
}


fn npm_query_compound_selector_matches(
    item: &NpmQueryItem,
    mut selector: &str,
) -> Result<bool, OmcRegistryError> {
    while !selector.is_empty() {
        if let Some(rest) = selector.strip_prefix('*') {
            selector = rest;
        } else if let Some(rest) = selector.strip_prefix('.') {
            let (class, rest) = npm_query_take_token(rest);
            if !npm_query_class_matches(item, class)? {
                return Ok(false);
            }
            selector = rest;
        } else if let Some(rest) = selector.strip_prefix('#') {
            let (id, rest) = npm_query_take_token(rest);
            if !npm_query_id_matches(item, id) {
                return Ok(false);
            }
            selector = rest;
        } else if let Some(rest) = selector.strip_prefix('[') {
            let Some(end) = rest.find(']') else {
                return Err(npm_query_unsupported(selector));
            };
            let attr = &rest[..end];
            if !npm_query_attr_selector_matches(item, attr)? {
                return Ok(false);
            }
            selector = &rest[end + 1..];
        } else if let Some(rest) = selector.strip_prefix(":not(") {
            let (inner, rest) = npm_query_take_function(rest, selector)?;
            if npm_query_compound_selector_matches(item, inner)? {
                return Ok(false);
            }
            selector = rest;
        } else if let Some(rest) = selector.strip_prefix(":has(*)") {
            if item.to.is_empty() {
                return Ok(false);
            }
            selector = rest;
        } else if let Some(rest) = selector.strip_prefix(":empty") {
            if !item.to.is_empty() {
                return Ok(false);
            }
            selector = rest;
        } else if let Some(rest) = selector.strip_prefix(":attr(") {
            let (inner, rest) = npm_query_take_function(rest, selector)?;
            if !npm_query_attr_function_matches(item, inner)? {
                return Ok(false);
            }
            selector = rest;
        } else {
            return Err(npm_query_unsupported(selector));
        }
    }
    Ok(true)
}


fn npm_query_take_token(value: &str) -> (&str, &str) {
    let end = value
        .char_indices()
        .find_map(|(index, ch)| matches!(ch, '.' | '#' | '[' | ':').then_some(index))
        .unwrap_or(value.len());
    (&value[..end], &value[end..])
}


fn npm_query_take_function<'a>(
    value: &'a str,
    selector: &str,
) -> Result<(&'a str, &'a str), OmcRegistryError> {
    let mut depth = 1usize;
    for (index, ch) in value.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&value[..index], &value[index + 1..]));
                }
            }
            _ => {}
        }
    }
    Err(npm_query_unsupported(selector))
}


fn npm_query_class_matches(item: &NpmQueryItem, class: &str) -> Result<bool, OmcRegistryError> {
    match class {
        "prod" => Ok(item.kinds.prod || !item.kinds.dev),
        "dev" => Ok(item.kinds.dev),
        "optional" => Ok(item.kinds.optional),
        "peer" => Ok(item.kinds.peer),
        "workspace" => Ok(item.kinds.workspace),
        _ => Err(npm_query_unsupported(&format!(".{class}"))),
    }
}


fn npm_query_id_matches(item: &NpmQueryItem, id: &str) -> bool {
    if item.name == id {
        return true;
    }
    if let Ok(spec) = PackageSpec::parse(id) {
        if spec.ecosystem != Ecosystem::Npm || spec.name != item.name {
            return false;
        }
        return spec
            .version
            .as_deref()
            .map(|version| version == item.version)
            .unwrap_or(true);
    }
    false
}


fn npm_query_attr_selector_matches(
    item: &NpmQueryItem,
    selector: &str,
) -> Result<bool, OmcRegistryError> {
    let Some((field, op, expected)) = npm_query_parse_attr_selector(selector) else {
        return Err(npm_query_unsupported(&format!("[{selector}]")));
    };
    let actual = match field {
        "name" => Some(item.name.as_str()),
        "version" => Some(item.version.as_str()),
        other => npm_query_manifest_string(&item.package, other),
    };
    Ok(actual
        .map(|actual| npm_query_attr_value_matches(actual, op, &expected))
        .unwrap_or(false))
}


fn npm_query_parse_attr_selector(selector: &str) -> Option<(&str, &str, String)> {
    for op in ["^=", "$=", "*=", "="] {
        if let Some((field, value)) = selector.split_once(op) {
            let field = field.trim();
            if field.is_empty() {
                return None;
            }
            return Some((field, op, npm_query_unquote(value.trim())));
        }
    }
    None
}


fn npm_query_unquote(value: &str) -> String {
    value.trim_matches('"').trim_matches('\'').trim().to_owned()
}


fn npm_query_manifest_string<'a>(package: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    package.get(field).and_then(|value| match value {
        serde_json::Value::String(value) => Some(value.as_str()),
        serde_json::Value::Object(object) => object.get("url").and_then(serde_json::Value::as_str),
        _ => None,
    })
}


fn npm_query_attr_value_matches(actual: &str, op: &str, expected: &str) -> bool {
    match op {
        "=" => actual == expected,
        "^=" => actual.starts_with(expected),
        "$=" => actual.ends_with(expected),
        "*=" => actual.contains(expected),
        _ => false,
    }
}


fn npm_query_attr_function_matches(
    item: &NpmQueryItem,
    inner: &str,
) -> Result<bool, OmcRegistryError> {
    let Some((field, nested)) = inner.split_once(',') else {
        return Err(npm_query_unsupported(&format!(":attr({inner})")));
    };
    let field = field.trim();
    let nested = nested.trim();
    let Some(key) = nested
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(npm_query_unsupported(&format!(":attr({inner})")));
    };
    let key = npm_query_unquote(key);
    Ok(item
        .package
        .get(field)
        .and_then(serde_json::Value::as_object)
        .map(|object| object.contains_key(&key))
        .unwrap_or(false))
}


fn npm_query_unsupported(selector: &str) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!(
        "unsupported npm query selector `{selector}`; OMC currently supports common package, class, attribute, :not, :empty, :has(*), and :attr selectors"
    ))
}


pub(crate) fn parse_npm_audit_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_json_flag_value(arg) {
            json = value;
        } else if matches!(arg.as_str(), "--audit-level" | "--audit-levels") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if matches!(arg.as_str(), "--parseable" | "--long")
            || npm_audit_equals_value_flag(arg)
        {
        } else {
            filtered.push(arg.clone());
        }
        index += 1;
    }

    let CommonCompatFlags { positionals, .. } = parse_common_compat_flags(&filtered, true)?;
    if !positionals.is_empty() {
        return Err(unsupported_compat_arg("npm audit", &positionals[0]));
    }

    Ok(NpmCompatAction::Audit { json })
}


pub(crate) fn parse_npm_fund_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut package = None;
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
        } else if let Some(value) = npm_all_workspaces_flag_value(arg) {
            all_workspaces = value;
        } else if let Some(value) = npm_include_workspace_root_flag_value(arg) {
            include_workspace_root = value;
        } else if matches!(
            arg.as_str(),
            "--silent"
                | "-s"
                | "--browser"
                | "--browser=true"
                | "--browser=false"
                | "--no-browser"
                | "--unicode"
                | "--unicode=true"
                | "--unicode=false"
                | "--no-unicode"
                | "--global"
                | "-g"
        ) {
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
        } else if matches!(arg.as_str(), "--which" | "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_fund_equals_value_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm fund", arg));
        } else if package.is_none() {
            package = Some(arg.clone());
        } else {
            return Err(OmcRegistryError::UnsupportedSpec(
                "npm fund accepts at most one package argument".to_owned(),
            ));
        }
        index += 1;
    }

    Ok(NpmCompatAction::Fund {
        action: NpmFundAction {
            json,
            package,
            workspaces,
            all_workspaces,
            include_workspace_root,
        },
    })
}


fn npm_fund_equals_value_flag(arg: &str) -> bool {
    [
        "--which=",
        "--loglevel=",
        "--cache=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}


pub(crate) fn parse_npm_diff_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut specs = Vec::new();
    let mut paths = Vec::new();
    let mut name_only = false;
    let mut unified = 3usize;
    let mut ignore_all_space = false;
    let mut no_prefix = false;
    let mut src_prefix = "a/".to_owned();
    let mut dst_prefix = "b/".to_owned();
    let mut text = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--diff" {
            index += 1;
            specs.push(npm_diff_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--diff=") {
            specs.push(value.to_owned());
        } else if matches!(arg.as_str(), "--diff-name-only" | "--diff-name-only=true") {
            name_only = true;
        } else if arg == "--diff-name-only=false" {
            name_only = false;
        } else if matches!(
            arg.as_str(),
            "--diff-ignore-all-space" | "--diff-ignore-all-space=true"
        ) {
            ignore_all_space = true;
        } else if arg == "--diff-ignore-all-space=false" {
            ignore_all_space = false;
        } else if matches!(arg.as_str(), "--diff-no-prefix" | "--diff-no-prefix=true") {
            no_prefix = true;
        } else if arg == "--diff-no-prefix=false" {
            no_prefix = false;
        } else if matches!(arg.as_str(), "--diff-text" | "--diff-text=true") {
            text = true;
        } else if arg == "--diff-text=false" {
            text = false;
        } else if arg == "--diff-unified" {
            index += 1;
            unified = parse_npm_diff_unified(&npm_diff_flag_value(args, index, arg)?)?;
        } else if let Some(value) = arg.strip_prefix("--diff-unified=") {
            unified = parse_npm_diff_unified(value)?;
        } else if arg == "--diff-src-prefix" {
            index += 1;
            src_prefix = npm_diff_flag_value(args, index, arg)?;
        } else if let Some(value) = arg.strip_prefix("--diff-src-prefix=") {
            src_prefix = value.to_owned();
        } else if arg == "--diff-dst-prefix" {
            index += 1;
            dst_prefix = npm_diff_flag_value(args, index, arg)?;
        } else if let Some(value) = arg.strip_prefix("--diff-dst-prefix=") {
            dst_prefix = value.to_owned();
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_diff_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_diff_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if matches!(
            arg.as_str(),
            "--silent" | "-s" | "--parseable" | "-p" | "--json" | "--json=true" | "--json=false"
        ) {
        } else if matches!(
            arg.as_str(),
            "--workspace" | "-w" | "--loglevel" | "--cache" | "--tag"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_diff_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm diff", arg));
        } else {
            paths.push(arg.clone());
        }
        index += 1;
    }
    if specs.len() != 2 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm diff compatibility needs exactly two --diff inputs".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Diff {
        action: NpmDiffAction {
            specs,
            paths,
            name_only,
            unified,
            ignore_all_space,
            no_prefix,
            src_prefix,
            dst_prefix,
            text,
            npm_registry,
            userconfig,
        },
    })
}


fn parse_npm_diff_unified(value: &str) -> Result<usize, OmcRegistryError> {
    value.parse::<usize>().map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!("invalid npm diff unified context `{value}`"))
    })
}


fn npm_diff_ignored_equals_flag(arg: &str) -> bool {
    [
        "--loglevel=",
        "--cache=",
        "--tag=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}


fn npm_diff_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}


pub(crate) fn parse_npm_search_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut parseable = false;
    let mut limit = 20usize;
    let mut npm_registry = None;
    let mut terms = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--parseable" | "-p" | "--parseable=true") {
            parseable = true;
        } else if arg == "--parseable=false" {
            parseable = false;
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
        } else if matches!(arg.as_str(), "--searchlimit" | "--limit") {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            };
            limit = parse_npm_search_limit(value)?;
        } else if let Some(value) = arg
            .strip_prefix("--searchlimit=")
            .or_else(|| arg.strip_prefix("--limit="))
        {
            limit = parse_npm_search_limit(value)?;
        } else if matches!(
            arg.as_str(),
            "--long"
                | "--description"
                | "--no-description"
                | "--color=false"
                | "--no-color"
                | "--silent"
                | "-s"
        ) {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--searchopts" | "--searchexclude"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_search_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm search", arg));
        } else {
            terms.push(arg.clone());
        }
        index += 1;
    }
    if terms.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm search needs search terms".to_owned(),
        ));
    }
    Ok(NpmCompatAction::Search {
        action: NpmSearchAction {
            query: terms.join(" "),
            json,
            parseable,
            limit,
            npm_registry,
        },
    })
}


fn parse_npm_search_limit(value: &str) -> Result<usize, OmcRegistryError> {
    value
        .parse::<usize>()
        .ok()
        .filter(|limit| *limit > 0)
        .map(|limit| limit.min(250))
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("invalid npm search limit `{value}`"))
        })
}


fn npm_search_ignored_equals_flag(arg: &str) -> bool {
    [
        "--loglevel=",
        "--searchopts=",
        "--searchexclude=",
        "--description=",
        "--parseable=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}



























































pub(crate) fn parse_npm_outdated_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut parseable = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_json_flag_value(arg) {
            json = value;
        } else if matches!(arg.as_str(), "--parseable" | "-p") {
            parseable = true;
        } else if matches!(
            arg.as_str(),
            "--all"
                | "--long"
                | "--silent"
                | "-s"
                | "--global"
                | "-g"
                | "--dev"
                | "--prod"
                | "--production"
                | "--color=false"
        ) || npm_all_long_short_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "--depth" | "--omit" | "--include" | "--loglevel" | "--userconfig"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_outdated_equals_value_flag(arg) {
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

    Ok(NpmCompatAction::Outdated {
        json,
        parseable,
        packages: positionals,
        npm_registry,
    })
}


fn npm_outdated_equals_value_flag(arg: &str) -> bool {
    [
        "--depth=",
        "--omit=",
        "--include=",
        "--loglevel=",
        "--userconfig=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}


pub(crate) fn parse_npm_view_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = npm_json_flag_value(arg) {
            json = value;
        } else if matches!(arg.as_str(), "--userconfig" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "--long")
            || npm_view_equals_value_flag(arg)
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
    if positionals.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm view needs a package".to_owned(),
        ));
    }
    let spec = positionals.remove(0);
    Ok(NpmCompatAction::View {
        spec,
        fields: positionals,
        json,
        npm_registry,
    })
}


fn npm_view_equals_value_flag(arg: &str) -> bool {
    ["--userconfig=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


fn npm_audit_equals_value_flag(arg: &str) -> bool {
    ["--audit-level=", "--audit-levels="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}


pub(crate) fn parse_npm_query_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut selector = None;
    let mut workspaces = Vec::new();
    let mut all_workspaces = false;
    let mut include_workspace_root = false;
    let mut package_lock_only = false;
    let mut expect_results = None;
    let mut expect_result_count = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "--json" | "--json=true" | "--json=false" | "--silent" | "-s" | "--parseable" | "-p"
        ) {
        } else if matches!(
            arg.as_str(),
            "--package-lock-only" | "--package-lock-only=true"
        ) {
            package_lock_only = true;
        } else if arg == "--package-lock-only=false" {
            package_lock_only = false;
        } else if let Some(value) = npm_all_workspaces_flag_value(arg) {
            all_workspaces = value;
        } else if let Some(value) = npm_include_workspace_root_flag_value(arg) {
            include_workspace_root = value;
        } else if matches!(arg.as_str(), "--expect-results" | "--expect-results=true") {
            expect_results = Some(true);
        } else if matches!(
            arg.as_str(),
            "--no-expect-results" | "--expect-results=false"
        ) {
            expect_results = Some(false);
        } else if arg == "--expect-result-count" {
            index += 1;
            expect_result_count = Some(parse_npm_query_expected_count(&npm_query_flag_value(
                args, index, arg,
            )?)?);
        } else if let Some(value) = arg.strip_prefix("--expect-result-count=") {
            expect_result_count = Some(parse_npm_query_expected_count(value)?);
        } else if matches!(arg.as_str(), "--workspace" | "-w") {
            index += 1;
            workspaces.push(npm_query_flag_value(args, index, arg)?);
        } else if let Some(value) = arg
            .strip_prefix("--workspace=")
            .or_else(|| arg.strip_prefix("-w="))
        {
            workspaces.push(value.to_owned());
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_query_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm query", arg));
        } else if selector.is_none() {
            selector = Some(arg.clone());
        } else {
            return Err(unsupported_compat_arg("npm query", arg));
        }
        index += 1;
    }
    let selector = selector.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("npm query needs a selector".to_owned())
    })?;
    Ok(NpmCompatAction::Query {
        action: NpmQueryAction {
            selector,
            workspaces,
            all_workspaces,
            include_workspace_root,
            package_lock_only,
            expect_results,
            expect_result_count,
        },
    })
}


fn parse_npm_query_expected_count(value: &str) -> Result<usize, OmcRegistryError> {
    value.parse::<usize>().map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!("invalid npm query expected count `{value}`"))
    })
}


fn npm_query_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}


fn npm_query_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache=", "--parseable="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

