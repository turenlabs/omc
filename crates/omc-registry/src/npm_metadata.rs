use crate::*;

use std::collections::BTreeMap;
use std::env;
use std::path::Path;

use reqwest::blocking::Client;
use semver::Version;

use crate::npm_config::{
    ensure_trailing_slash, npm_registry_package_url, npm_registry_package_version_url,
    read_npm_config_with_overrides, NpmConfig,
};

pub fn read_npm_package_metadata(
    project_dir: &Path,
    spec: &PackageSpec,
    registry_override: Option<&str>,
) -> Result<NpmPackageMetadata> {
    read_npm_package_metadata_with_userconfig(project_dir, spec, registry_override, None)
}

pub fn read_npm_package_metadata_with_userconfig(
    project_dir: &Path,
    spec: &PackageSpec,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmPackageMetadata> {
    if spec.ecosystem != Ecosystem::Npm || spec.direct_url.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
    }

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let (registry_name, version_requirement) = npm_registry_name_and_requirement(spec)?;
    let registry = npm_config.registry_for(&registry_name);
    let encoded = urlencoding::encode(&registry_name);
    let root_url = npm_registry_package_url(registry, &encoded);
    let root_value = npm_get(&client, &root_url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let root = serde_json::from_value::<NpmRoot>(root_value.clone())?;
    let version = match version_requirement.as_deref() {
        Some(requirement) if is_exact_npm_version(requirement) => requirement.to_owned(),
        Some(requirement) => choose_npm_version(&registry_name, requirement, &root, None)?,
        None => root.dist_tags.latest,
    };
    let version_url = npm_registry_package_version_url(registry, &encoded, &version);
    let response = npm_get(&client, &version_url, &npm_config).send()?;
    if response.status().as_u16() == 404 {
        return Err(OmcRegistryError::PackageNotFound(spec.requested()));
    }
    let manifest = response.error_for_status()?.json::<serde_json::Value>()?;
    let dist_tags = root_value
        .get("dist-tags")
        .and_then(serde_json::Value::as_object)
        .map(|tags| {
            tags.iter()
                .filter_map(|(tag, version)| {
                    version
                        .as_str()
                        .map(|version| (tag.clone(), version.to_owned()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    Ok(NpmPackageMetadata {
        name: registry_name,
        version,
        dist_tags,
        versions: root.versions.keys().cloned().collect(),
        root: root_value,
        manifest,
    })
}

pub fn download_npm_package_tarball(
    project_dir: &Path,
    spec: &PackageSpec,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmPackageTarball> {
    let metadata = read_npm_package_metadata_with_userconfig(
        project_dir,
        spec,
        registry_override,
        userconfig_override,
    )?;
    let tarball_url = metadata
        .manifest
        .pointer("/dist/tarball")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| OmcRegistryError::MissingArtifact(metadata.name.clone()))?
        .to_owned();
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let bytes = npm_get(&client, &tarball_url, &npm_config)
        .send()?
        .error_for_status()?
        .bytes()?
        .to_vec();
    Ok(NpmPackageTarball { metadata, bytes })
}

pub fn read_npm_ping(project_dir: &Path, registry_override: Option<&str>) -> Result<NpmPingResult> {
    read_npm_ping_with_userconfig(project_dir, registry_override, None)
}

pub fn read_npm_ping_with_userconfig(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmPingResult> {
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{registry}-/ping");
    let response = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()
        .unwrap_or_else(|_| serde_json::json!({ "ok": true }));
    Ok(NpmPingResult { registry, response })
}

pub fn read_npm_whoami(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmWhoamiResult> {
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{registry}-/whoami");
    let response = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let username = response
        .get("username")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "npm whoami response did not include username".to_owned(),
            )
        })?
        .to_owned();
    Ok(NpmWhoamiResult {
        registry,
        username,
        response,
    })
}

pub fn read_npm_trust(
    project_dir: &Path,
    package: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmTrustResult> {
    let package = npm_trust_package_name(package)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let url = npm_trust_url(&registry, &package);
    let response = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    Ok(NpmTrustResult {
        registry,
        package,
        configs: npm_trust_configs(&response),
        response,
    })
}

pub fn create_npm_trust(
    project_dir: &Path,
    package: &str,
    config: serde_json::Value,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTrustMutationResult> {
    let package = npm_trust_package_name(package)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let url = npm_trust_url(&registry, &package);
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm trust create needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }

    let mut request = npm_post(&client, &url, &npm_config).json(&vec![config]);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = response.json::<serde_json::Value>()?;
    Ok(NpmTrustMutationResult {
        registry,
        package,
        status,
        response,
    })
}

pub fn revoke_npm_trust(
    project_dir: &Path,
    package: &str,
    id: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTrustMutationResult> {
    let package = npm_trust_package_name(package)?;
    let id = id.trim();
    if id.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm trust revoke needs --id".to_owned(),
        ));
    }

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let url = format!(
        "{}/{}",
        npm_trust_url(&registry, &package),
        urlencoding::encode(id)
    );
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm trust revoke needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }

    let mut request = npm_delete(&client, &url, &npm_config);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = response
        .json::<serde_json::Value>()
        .unwrap_or_else(|_| serde_json::json!({ "ok": true }));
    Ok(NpmTrustMutationResult {
        registry,
        package,
        status,
        response,
    })
}

fn npm_trust_url(registry: &str, package: &str) -> String {
    format!(
        "{}-/package/{}/trust",
        ensure_trailing_slash(registry),
        urlencoding::encode(package)
    )
}

fn npm_trust_package_name(package: &str) -> Result<String> {
    let package = package.trim();
    if package.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm trust needs a package".to_owned(),
        ));
    }
    Ok(package.to_owned())
}

fn npm_trust_configs(response: &serde_json::Value) -> Vec<serde_json::Value> {
    match response {
        serde_json::Value::Array(items) => items.clone(),
        serde_json::Value::Null => Vec::new(),
        item => vec![item.clone()],
    }
}

pub fn read_npm_profile(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmProfileResult> {
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{registry}-/npm/v1/user");
    let profile = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    Ok(NpmProfileResult { registry, profile })
}

pub fn set_npm_profile_property(
    project_dir: &Path,
    property: &str,
    value: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmProfileMutationResult> {
    let property = property.trim().to_lowercase();
    if !NPM_PROFILE_WRITABLE_KEYS.contains(&property.as_str()) {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "\"{property}\" is not a property we can set"
        )));
    }
    if property == "password" {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm profile set password is interactive and is not implemented by OMC".to_owned(),
        ));
    }

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{registry}-/npm/v1/user");
    let current = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let mut body = serde_json::Map::new();
    for key in NPM_PROFILE_WRITABLE_KEYS {
        if *key == "password" {
            continue;
        }
        if let Some(value) = current.get(*key) {
            body.insert((*key).to_owned(), value.clone());
        }
    }
    let new_value = if value.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(value.to_owned())
    };
    body.insert(property.clone(), new_value.clone());

    let mut request = npm_post(&client, &url, &npm_config).json(&body);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = response.json::<serde_json::Value>()?;
    let value = response
        .get(&property)
        .cloned()
        .unwrap_or_else(|| new_value.clone());
    Ok(NpmProfileMutationResult {
        registry,
        property,
        value,
        status,
        response,
    })
}

pub fn read_npm_token_list(
    project_dir: &Path,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmTokenListResult> {
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{registry}-/npm/v1/tokens?perPage=1000");
    let response = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let tokens = response
        .get("objects")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "npm token list response did not include objects".to_owned(),
            )
        })?
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<std::result::Result<Vec<NpmAccessToken>, serde_json::Error>>()?;
    let total = response.get("total").and_then(serde_json::Value::as_u64);
    let urls = response
        .get("urls")
        .and_then(serde_json::Value::as_object)
        .map(|urls| {
            urls.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    Ok(NpmTokenListResult {
        registry,
        tokens,
        total,
        urls,
        response,
    })
}

pub fn create_npm_token(
    project_dir: &Path,
    options: NpmTokenCreateOptions,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTokenCreateResult> {
    let password = npm_token_create_password(options.password.as_deref())?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{registry}-/npm/v1/tokens");
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm token create needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }

    let mut request =
        npm_post(&client, &url, &npm_config).json(&npm_token_create_payload(&options, &password));
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = response.json::<serde_json::Value>()?;
    let token = npm_token_from_create_response(&response)?;
    Ok(NpmTokenCreateResult {
        registry,
        status,
        token,
        response,
    })
}

fn npm_token_create_password(explicit: Option<&str>) -> Result<String> {
    explicit
        .map(str::trim)
        .filter(|password| !password.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var("npm_config_password")
                .ok()
                .or_else(|| env::var("NPM_CONFIG_PASSWORD").ok())
                .map(|password| password.trim().to_owned())
                .filter(|password| !password.is_empty())
        })
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "npm token create needs a password; pass --password or set NPM_CONFIG_PASSWORD"
                    .to_owned(),
            )
        })
}

fn npm_token_create_payload(options: &NpmTokenCreateOptions, password: &str) -> serde_json::Value {
    let mut payload = serde_json::Map::new();
    payload.insert("password".to_owned(), serde_json::json!(password));
    payload.insert("name".to_owned(), serde_json::json!(options.name));
    if let Some(description) = &options.description {
        payload.insert("description".to_owned(), serde_json::json!(description));
    }
    if !options.packages.is_empty() {
        payload.insert("packages".to_owned(), serde_json::json!(options.packages));
    }
    if options.packages_all {
        payload.insert("packages_all".to_owned(), serde_json::json!(true));
    }
    if !options.scopes.is_empty() {
        payload.insert("scopes".to_owned(), serde_json::json!(options.scopes));
    }
    if !options.orgs.is_empty() {
        payload.insert("orgs".to_owned(), serde_json::json!(options.orgs));
    }
    let packages_and_scopes_permission = options
        .packages_and_scopes_permission
        .as_deref()
        .or_else(|| options.read_only.then_some("read-only"));
    if let Some(permission) = packages_and_scopes_permission {
        payload.insert(
            "packages_and_scopes_permission".to_owned(),
            serde_json::json!(permission),
        );
    }
    if let Some(permission) = &options.orgs_permission {
        payload.insert("orgs_permission".to_owned(), serde_json::json!(permission));
    }
    if let Some(expires) = options.expires {
        payload.insert("expires".to_owned(), serde_json::json!(expires));
    }
    if !options.cidr.is_empty() {
        payload.insert("cidr_whitelist".to_owned(), serde_json::json!(options.cidr));
    }
    if options.bypass_2fa {
        payload.insert("bypass_2fa".to_owned(), serde_json::json!(true));
    }
    serde_json::Value::Object(payload)
}

fn npm_token_from_create_response(response: &serde_json::Value) -> Result<NpmAccessToken> {
    let token_value = response.get("token").and_then(|value| {
        if value.is_object() {
            Some(value.clone())
        } else {
            None
        }
    });
    Ok(serde_json::from_value::<NpmAccessToken>(
        token_value.unwrap_or_else(|| response.clone()),
    )?)
}

pub fn revoke_npm_token(
    project_dir: &Path,
    token: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTokenRevokeResult> {
    let token = token.trim();
    if token.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm token revoke needs a token or token id".to_owned(),
        ));
    }
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let encoded = urlencoding::encode(token);
    let url = format!("{registry}-/npm/v1/tokens/token/{encoded}");
    let mut request = npm_delete(&client, &url, &npm_config);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?.error_for_status()?;
    let status = response.status().as_u16();
    Ok(NpmTokenRevokeResult {
        registry,
        token: token.to_owned(),
        status,
    })
}

pub fn add_npm_dist_tag(
    project_dir: &Path,
    package: &str,
    version: &str,
    tag: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmDistTagMutationResult> {
    let package = package.trim();
    let version = version.trim();
    let tag = tag.trim();
    if package.is_empty() || version.is_empty() || tag.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm dist-tag add needs package, version, and tag".to_owned(),
        ));
    }
    if Version::parse(version).is_err() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm dist-tag add needs an exact semver version, got `{version}`"
        )));
    }

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(package));
    let url = npm_dist_tag_url(&registry, package, tag);
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm dist-tag add needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let mut request = npm_put(&client, &url, &npm_config).json(version);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok(NpmDistTagMutationResult {
        registry,
        package: package.to_owned(),
        tag: tag.to_owned(),
        version: Some(version.to_owned()),
        status,
        response,
    })
}

pub fn remove_npm_dist_tag(
    project_dir: &Path,
    package: &str,
    tag: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmDistTagMutationResult> {
    let package = package.trim();
    let tag = tag.trim();
    if package.is_empty() || tag.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm dist-tag rm needs package and tag".to_owned(),
        ));
    }

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(package));
    let url = npm_dist_tag_url(&registry, package, tag);
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm dist-tag rm needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let mut request = npm_delete(&client, &url, &npm_config);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok(NpmDistTagMutationResult {
        registry,
        package: package.to_owned(),
        tag: tag.to_owned(),
        version: None,
        status,
        response,
    })
}

pub fn read_npm_package_owners(
    project_dir: &Path,
    spec: &PackageSpec,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmOwnerListResult> {
    if spec.ecosystem != Ecosystem::Npm || spec.direct_url.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
    }
    let (package, _) = npm_registry_name_and_requirement(spec)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let packument = npm_owner_packument(&client, &registry, &package, &npm_config)?;
    let owners = npm_packument_maintainers(&packument)?;
    Ok(NpmOwnerListResult {
        registry,
        package,
        owners,
    })
}

pub fn mutate_npm_package_owner(
    project_dir: &Path,
    spec: &PackageSpec,
    user: &str,
    added: bool,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmOwnerMutationResult> {
    if spec.ecosystem != Ecosystem::Npm || spec.direct_url.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
    }
    let user = user.trim();
    if user.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm owner mutation needs a username".to_owned(),
        ));
    }
    let (package, _) = npm_registry_name_and_requirement(spec)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let user_doc = npm_owner_user(&client, &registry, user, &npm_config)?;
    let username = user_doc.username.clone().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!("npm owner user `{user}` did not include a name"))
    })?;

    let packument = npm_owner_packument(&client, &registry, &package, &npm_config)?;
    let package_id = packument
        .get("_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&package)
        .to_owned();
    let revision = packument
        .get("_rev")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm registry response for `{package}` did not include _rev"
            ))
        })?
        .to_owned();
    let owners = npm_packument_maintainers(&packument)?;
    let existing = owners
        .iter()
        .any(|owner| owner.username.as_deref() == Some(username.as_str()));
    let (changed, owners) = if added {
        if existing {
            (false, owners)
        } else {
            let mut owners = owners;
            owners.push(user_doc);
            owners.sort_by(|left, right| left.username.cmp(&right.username));
            (true, owners)
        }
    } else if !existing {
        (false, owners)
    } else {
        let owners = owners
            .into_iter()
            .filter(|owner| owner.username.as_deref() != Some(username.as_str()))
            .collect::<Vec<_>>();
        if owners.is_empty() {
            return Err(OmcRegistryError::UnsupportedSpec(
                "Cannot remove all owners of a package. Add someone else first.".to_owned(),
            ));
        }
        (true, owners)
    };

    if !changed {
        return Ok(NpmOwnerMutationResult {
            registry,
            package,
            user: username.clone(),
            added,
            changed,
            owners,
            status: None,
            response: serde_json::json!({ "changed": false }),
        });
    }

    let encoded = urlencoding::encode(&package);
    let url = format!(
        "{}{}/-rev/{}",
        registry,
        encoded,
        urlencoding::encode(&revision)
    );
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm owner needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let body = serde_json::json!({
        "_id": package_id,
        "_rev": revision,
        "maintainers": owners.iter().map(npm_owner_json).collect::<Vec<_>>(),
    });
    let mut request = npm_put(&client, &url, &npm_config).json(&body);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok(NpmOwnerMutationResult {
        registry,
        package,
        user: username,
        added,
        changed,
        owners,
        status: Some(status),
        response,
    })
}

pub fn mutate_npm_package_star(
    project_dir: &Path,
    spec: &PackageSpec,
    starred: bool,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmStarMutationResult> {
    if spec.ecosystem != Ecosystem::Npm || spec.direct_url.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
    }
    let (package, _) = npm_registry_name_and_requirement(spec)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let whoami = read_npm_whoami(project_dir, Some(registry.as_str()), userconfig_override)?;
    let username = whoami.username;
    let packument = npm_owner_packument(&client, &registry, &package, &npm_config)?;
    let package_id = packument
        .get("_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&package)
        .to_owned();
    let revision = packument
        .get("_rev")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm registry response for `{package}` did not include _rev"
            ))
        })?
        .to_owned();
    let mut users = npm_packument_users(&packument)?;
    if starred {
        users.insert(username.clone(), true);
    } else {
        users.remove(&username);
    }

    let encoded = urlencoding::encode(&package);
    let url = format!("{registry}{encoded}");
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm star needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let body = serde_json::json!({
        "_id": package_id,
        "_rev": revision,
        "users": users,
    });
    let mut request = npm_put(&client, &url, &npm_config).json(&body);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok(NpmStarMutationResult {
        registry,
        package,
        user: username,
        starred,
        status,
        response,
    })
}

pub fn read_npm_stars(
    project_dir: &Path,
    user: Option<&str>,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmStarsResult> {
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let user = match user.map(str::trim).filter(|user| !user.is_empty()) {
        Some(user) => user.to_owned(),
        None => read_npm_whoami(project_dir, registry_override, userconfig_override)?.username,
    };
    let key_value = format!("\"{user}\"");
    let key = urlencoding::encode(&key_value);
    let url = format!("{registry}-/_view/starredByUser?key={key}");
    let response = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let packages = response
        .get("rows")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("npm stars response did not include rows".to_owned())
        })?
        .iter()
        .filter_map(|row| row.get("value").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Ok(NpmStarsResult {
        registry,
        user,
        packages,
        response,
    })
}

fn npm_owner_packument(
    client: &Client,
    registry: &str,
    package: &str,
    npm_config: &NpmConfig,
) -> Result<serde_json::Value> {
    let encoded = urlencoding::encode(package);
    let url = format!("{}{}?write=true", registry, encoded);
    Ok(npm_get(client, &url, npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?)
}

fn npm_owner_user(
    client: &Client,
    registry: &str,
    user: &str,
    npm_config: &NpmConfig,
) -> Result<NpmSearchUser> {
    let url = format!(
        "{}-/user/org.couchdb.user:{}",
        registry,
        urlencoding::encode(user)
    );
    let value = npm_get(client, &url, npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let mut user = serde_json::from_value::<NpmSearchUser>(value)?;
    if user
        .username
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .is_none()
    {
        user.username = None;
    }
    Ok(user)
}

fn npm_packument_maintainers(packument: &serde_json::Value) -> Result<Vec<NpmSearchUser>> {
    let Some(maintainers) = packument.get("maintainers") else {
        return Ok(Vec::new());
    };
    let maintainers = maintainers.as_array().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(
            "npm registry response maintainers field was not an array".to_owned(),
        )
    })?;
    let mut owners = Vec::new();
    for maintainer in maintainers {
        let owner = serde_json::from_value::<NpmSearchUser>(maintainer.clone())?;
        if owner.username.as_deref().unwrap_or_default().is_empty() {
            continue;
        }
        owners.push(owner);
    }
    owners.sort_by(|left, right| left.username.cmp(&right.username));
    Ok(owners)
}

fn npm_packument_users(packument: &serde_json::Value) -> Result<BTreeMap<String, bool>> {
    let Some(users) = packument.get("users") else {
        return Ok(BTreeMap::new());
    };
    let users = users.as_object().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(
            "npm registry response users field was not an object".to_owned(),
        )
    })?;
    Ok(users
        .iter()
        .filter_map(|(user, value)| value.as_bool().map(|starred| (user.clone(), starred)))
        .collect())
}

fn npm_owner_json(owner: &NpmSearchUser) -> serde_json::Value {
    serde_json::json!({
        "name": owner.username,
        "email": owner.email,
    })
}

pub fn read_npm_access_packages(
    project_dir: &Path,
    owner: &str,
    package_filter: Option<&str>,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmAccessMapResult> {
    let owner = owner.trim();
    if owner.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm access list packages needs an owner, scope, or team".to_owned(),
        ));
    }
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let (scope, team) = npm_access_scope_team(owner)?;
    let primary_url = if let Some(team) = team.as_deref() {
        format!(
            "{}-/team/{}/{}/package",
            registry,
            urlencoding::encode(&scope),
            urlencoding::encode(team)
        )
    } else {
        format!("{}-/org/{}/package", registry, urlencoding::encode(&scope))
    };
    let response = npm_get(&client, &primary_url, &npm_config).send()?;
    let value = if response.status().as_u16() == 404 && team.is_none() {
        let fallback_url = format!("{}-/user/{}/package", registry, urlencoding::encode(&scope));
        npm_get(&client, &fallback_url, &npm_config)
            .send()?
            .error_for_status()?
            .json::<serde_json::Value>()?
    } else {
        response.error_for_status()?.json::<serde_json::Value>()?
    };
    let items = npm_access_items(&value, package_filter)?;
    Ok(NpmAccessMapResult {
        registry,
        subject: owner.to_owned(),
        package: package_filter.map(str::to_owned),
        items,
    })
}

pub fn read_npm_access_collaborators(
    project_dir: &Path,
    package: &str,
    user_filter: Option<&str>,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmAccessMapResult> {
    let package = npm_access_package_name(package)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let url = npm_access_package_url(&registry, &package, "collaborators");
    let value = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let items = npm_access_items(&value, user_filter)?;
    Ok(NpmAccessMapResult {
        registry,
        subject: "collaborators".to_owned(),
        package: Some(package),
        items,
    })
}

pub fn read_npm_access_status(
    project_dir: &Path,
    package: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmAccessStatusResult> {
    let package = npm_access_package_name(package)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let url = npm_access_package_url(&registry, &package, "visibility");
    let response = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let public = response
        .get("public")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm access visibility response for `{package}` did not include public"
            ))
        })?;
    Ok(NpmAccessStatusResult {
        registry,
        package,
        status: if public { "public" } else { "private" }.to_owned(),
        response,
    })
}

pub fn set_npm_access_status(
    project_dir: &Path,
    package: &str,
    status: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmAccessMutationResult> {
    let package = npm_access_scoped_package_name(package)?;
    let access = match status {
        "public" => "public",
        "private" | "restricted" => "restricted",
        _ => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "npm access status must be public or private, got `{status}`"
            )))
        }
    };
    npm_access_post_package(
        project_dir,
        &package,
        "status",
        serde_json::json!({ "access": access }),
        registry_override,
        userconfig_override,
        otp,
    )
}

pub fn set_npm_access_mfa(
    project_dir: &Path,
    package: &str,
    level: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmAccessMutationResult> {
    let package = npm_access_package_name(package)?;
    let body = match level {
        "none" => serde_json::json!({ "publish_requires_tfa": false }),
        "publish" => serde_json::json!({
            "publish_requires_tfa": true,
            "automation_token_overrides_tfa": false,
        }),
        "automation" => serde_json::json!({
            "publish_requires_tfa": true,
            "automation_token_overrides_tfa": true,
        }),
        _ => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "npm access mfa must be none, publish, or automation, got `{level}`"
            )))
        }
    };
    npm_access_post_package(
        project_dir,
        &package,
        "mfa",
        body,
        registry_override,
        userconfig_override,
        otp,
    )
}

pub fn grant_npm_access(
    project_dir: &Path,
    scope_team: &str,
    package: &str,
    permission: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmAccessMutationResult> {
    if !matches!(permission, "read-only" | "read-write") {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm access grant permission must be read-only or read-write, got `{permission}`"
        )));
    }
    let package = npm_access_package_name(package)?;
    let (scope, team) = npm_access_scope_team(scope_team)?;
    let team = team.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("team must be in format `scope:team`".to_owned())
    })?;
    let (registry, status, response) = npm_access_team_request(
        project_dir,
        NpmAccessTeamRequest {
            scope: &scope,
            team: &team,
            method: "PUT",
            body: serde_json::json!({ "package": package, "permissions": permission }),
            registry_override,
            userconfig_override,
            otp,
        },
    )?;
    Ok(NpmAccessMutationResult {
        registry,
        package,
        action: "grant".to_owned(),
        scope_team: Some(scope_team.to_owned()),
        permission: Some(permission.to_owned()),
        status,
        response,
    })
}

pub fn revoke_npm_access(
    project_dir: &Path,
    scope_team: &str,
    package: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmAccessMutationResult> {
    let package = npm_access_package_name(package)?;
    let (scope, team) = npm_access_scope_team(scope_team)?;
    let team = team.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("team must be in format `scope:team`".to_owned())
    })?;
    let (registry, status, response) = npm_access_team_request(
        project_dir,
        NpmAccessTeamRequest {
            scope: &scope,
            team: &team,
            method: "DELETE",
            body: serde_json::json!({ "package": package }),
            registry_override,
            userconfig_override,
            otp,
        },
    )?;
    Ok(NpmAccessMutationResult {
        registry,
        package,
        action: "revoke".to_owned(),
        scope_team: Some(scope_team.to_owned()),
        permission: None,
        status,
        response,
    })
}

fn npm_access_package_url(registry: &str, package: &str, suffix: &str) -> String {
    format!(
        "{}-/package/{}/{}",
        registry,
        urlencoding::encode(package),
        suffix
    )
}

fn npm_access_post_package(
    project_dir: &Path,
    package: &str,
    action: &str,
    body: serde_json::Value,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmAccessMutationResult> {
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(package));
    let url = npm_access_package_url(&registry, package, "access");
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm access needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let mut request = npm_post(&client, &url, &npm_config).json(&body);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok(NpmAccessMutationResult {
        registry,
        package: package.to_owned(),
        action: action.to_owned(),
        scope_team: None,
        permission: None,
        status,
        response,
    })
}

struct NpmAccessTeamRequest<'a> {
    scope: &'a str,
    team: &'a str,
    method: &'a str,
    body: serde_json::Value,
    registry_override: Option<&'a str>,
    userconfig_override: Option<&'a Path>,
    otp: Option<&'a str>,
}

fn npm_access_team_request(
    project_dir: &Path,
    request: NpmAccessTeamRequest<'_>,
) -> Result<(String, u16, serde_json::Value)> {
    let client = Client::new();
    let npm_config = read_npm_config_with_overrides(
        project_dir,
        request.registry_override,
        request.userconfig_override,
    )?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!(
        "{}-/team/{}/{}/package",
        registry,
        urlencoding::encode(request.scope),
        urlencoding::encode(request.team)
    );
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm access needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let http_request = if request.method == "DELETE" {
        npm_delete(&client, &url, &npm_config).json(&request.body)
    } else {
        npm_put(&client, &url, &npm_config).json(&request.body)
    };
    let mut http_request = http_request;
    if let Some(otp) = request.otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        http_request = http_request.header("npm-otp", otp);
    }
    let response = http_request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok((registry, status, response))
}

fn npm_access_scope_team(value: &str) -> Result<(String, Option<String>)> {
    let value = value.trim().trim_start_matches('@');
    if value.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm access scope/team cannot be empty".to_owned(),
        ));
    }
    let (scope, team) = value
        .split_once(':')
        .map(|(scope, team)| (scope, Some(team)))
        .unwrap_or((value, None));
    if scope.is_empty() || team == Some("") {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm access scope/team `{value}`"
        )));
    }
    Ok((scope.to_owned(), team.map(str::to_owned)))
}

fn npm_access_package_name(value: &str) -> Result<String> {
    let spec = PackageSpec::parse(&format!("npm:{value}"))?;
    if spec.direct_url.is_some() || spec.version.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm access needs a package name, got `{value}`"
        )));
    }
    Ok(spec.name)
}

fn npm_access_scoped_package_name(value: &str) -> Result<String> {
    let package = npm_access_package_name(value)?;
    if !npm_access_package_is_scoped(&package) {
        return Err(OmcRegistryError::UnsupportedSpec(
            "This command is only available for scoped packages.".to_owned(),
        ));
    }
    Ok(package)
}

fn npm_access_package_is_scoped(package: &str) -> bool {
    package
        .strip_prefix('@')
        .and_then(|rest| rest.split_once('/'))
        .map(|(scope, name)| !scope.is_empty() && !name.is_empty())
        .unwrap_or(false)
}

fn npm_access_items(
    value: &serde_json::Value,
    limiter: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let object = value.as_object().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("npm access response was not an object".to_owned())
    })?;
    let mut items = BTreeMap::new();
    for (key, value) in object {
        if limiter.map(|limiter| limiter != key).unwrap_or(false) {
            continue;
        }
        let value = value
            .as_str()
            .map(npm_access_permission_text)
            .unwrap_or_else(|| value.to_string());
        items.insert(key.clone(), value);
    }
    Ok(items)
}

fn npm_access_permission_text(value: &str) -> String {
    match value {
        "read" => "read-only".to_owned(),
        "write" => "read-write".to_owned(),
        other => other.to_owned(),
    }
}

pub fn set_npm_org_user(
    project_dir: &Path,
    org: &str,
    user: &str,
    role: Option<&str>,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmOrgMutationResult> {
    let org = npm_org_name(org)?;
    let user = npm_org_user(user)?;
    let role = npm_org_role(role.unwrap_or("developer"))?;
    let body = serde_json::json!({ "user": user, "role": role });
    let (registry, status, response) = npm_org_request(
        project_dir,
        &org,
        "PUT",
        body,
        registry_override,
        userconfig_override,
        otp,
    )?;
    let org_name = response
        .get("org")
        .and_then(|org| org.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&org)
        .to_owned();
    let user = response
        .get("user")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&user)
        .to_owned();
    let role = response
        .get("role")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&role)
        .to_owned();
    let user_count = response
        .get("org")
        .and_then(|org| org.get("size"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|size| usize::try_from(size).ok());
    Ok(NpmOrgMutationResult {
        registry,
        action: "set".to_owned(),
        org: org_name,
        user,
        role: Some(role),
        user_count,
        status,
        response,
    })
}

pub fn remove_npm_org_user(
    project_dir: &Path,
    org: &str,
    user: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmOrgMutationResult> {
    let org = npm_org_name(org)?;
    let user = npm_org_user(user)?;
    let body = serde_json::json!({ "user": user });
    let (registry, status, response) = npm_org_request(
        project_dir,
        &org,
        "DELETE",
        body,
        registry_override,
        userconfig_override,
        otp,
    )?;
    let roster = read_npm_org_users(
        project_dir,
        &org,
        None,
        registry_override,
        userconfig_override,
    )?;
    Ok(NpmOrgMutationResult {
        registry,
        action: "rm".to_owned(),
        org,
        user,
        role: None,
        user_count: Some(roster.users.len()),
        status,
        response,
    })
}

pub fn read_npm_org_users(
    project_dir: &Path,
    org: &str,
    user: Option<&str>,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmOrgListResult> {
    let org = npm_org_name(org)?;
    let user = user.map(npm_org_user).transpose()?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{}-/org/{}/user", registry, urlencoding::encode(&org));
    let value = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let mut users = npm_org_user_map(&value)?;
    if let Some(user) = user {
        users.retain(|name, _| name == &user);
    }
    Ok(NpmOrgListResult {
        registry,
        org,
        users,
    })
}

fn npm_org_request(
    project_dir: &Path,
    org: &str,
    method: &str,
    body: serde_json::Value,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<(String, u16, serde_json::Value)> {
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!("{}-/org/{}/user", registry, urlencoding::encode(org));
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm org needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let mut request = match method {
        "DELETE" => npm_delete(&client, &url, &npm_config).json(&body),
        "PUT" => npm_put(&client, &url, &npm_config).json(&body),
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported npm org HTTP method `{other}`"
            )))
        }
    };
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok((registry, status, response))
}

fn npm_org_name(value: &str) -> Result<String> {
    let org = value.trim().trim_start_matches('@');
    if org.is_empty() || org.contains('/') || org.contains(':') {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm org `{value}`"
        )));
    }
    Ok(org.to_owned())
}

fn npm_org_user(value: &str) -> Result<String> {
    let user = value.trim().trim_start_matches(['@', '~']);
    if user.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm org user cannot be empty".to_owned(),
        ));
    }
    Ok(user.to_owned())
}

fn npm_org_role(value: &str) -> Result<String> {
    let role = value.trim();
    if !matches!(role, "owner" | "admin" | "developer") {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm org role must be owner, admin, or developer".to_owned(),
        ));
    }
    Ok(role.to_owned())
}

fn npm_org_user_map(value: &serde_json::Value) -> Result<BTreeMap<String, String>> {
    let object = value.as_object().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("npm org response was not an object".to_owned())
    })?;
    let mut users = BTreeMap::new();
    for (user, role) in object {
        if let Some(role) = role.as_str() {
            users.insert(user.clone(), role.to_owned());
        } else if let Some(role) = role
            .get("role")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
        {
            users.insert(user.clone(), role);
        }
    }
    Ok(users)
}

pub fn create_npm_team(
    project_dir: &Path,
    entity: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTeamMutationResult> {
    let (scope, team) = npm_team_entity(entity)?;
    let body = serde_json::json!({ "name": team, "description": null });
    let (registry, status, response) = npm_team_request(
        project_dir,
        NpmTeamRequest {
            scope: &scope,
            team: Some(&team),
            action: "create",
            method: "PUT",
            body,
            registry_override,
            userconfig_override,
            otp,
        },
    )?;
    Ok(NpmTeamMutationResult {
        registry,
        action: "create".to_owned(),
        scope,
        team,
        user: None,
        status,
        response,
    })
}

pub fn destroy_npm_team(
    project_dir: &Path,
    entity: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTeamMutationResult> {
    let (scope, team) = npm_team_entity(entity)?;
    let (registry, status, response) = npm_team_request(
        project_dir,
        NpmTeamRequest {
            scope: &scope,
            team: Some(&team),
            action: "destroy",
            method: "DELETE",
            body: serde_json::Value::Null,
            registry_override,
            userconfig_override,
            otp,
        },
    )?;
    Ok(NpmTeamMutationResult {
        registry,
        action: "destroy".to_owned(),
        scope,
        team,
        user: None,
        status,
        response,
    })
}

pub fn add_npm_team_user(
    project_dir: &Path,
    entity: &str,
    user: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTeamMutationResult> {
    let (scope, team) = npm_team_entity(entity)?;
    let user = npm_team_user(user)?;
    let (registry, status, response) = npm_team_request(
        project_dir,
        NpmTeamRequest {
            scope: &scope,
            team: Some(&team),
            action: "add",
            method: "PUT",
            body: serde_json::json!({ "user": user }),
            registry_override,
            userconfig_override,
            otp,
        },
    )?;
    Ok(NpmTeamMutationResult {
        registry,
        action: "add".to_owned(),
        scope,
        team,
        user: Some(user),
        status,
        response,
    })
}

pub fn remove_npm_team_user(
    project_dir: &Path,
    entity: &str,
    user: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmTeamMutationResult> {
    let (scope, team) = npm_team_entity(entity)?;
    let user = npm_team_user(user)?;
    let (registry, status, response) = npm_team_request(
        project_dir,
        NpmTeamRequest {
            scope: &scope,
            team: Some(&team),
            action: "rm",
            method: "DELETE",
            body: serde_json::json!({ "user": user }),
            registry_override,
            userconfig_override,
            otp,
        },
    )?;
    Ok(NpmTeamMutationResult {
        registry,
        action: "rm".to_owned(),
        scope,
        team,
        user: Some(user),
        status,
        response,
    })
}

pub fn read_npm_teams(
    project_dir: &Path,
    scope: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmTeamListResult> {
    let scope = npm_team_scope(scope)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!(
        "{}-/org/{}/team?format=cli",
        registry,
        urlencoding::encode(&scope)
    );
    let value = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    Ok(NpmTeamListResult {
        registry,
        scope,
        team: None,
        items: npm_team_list_items(&value)?,
    })
}

pub fn read_npm_team_users(
    project_dir: &Path,
    entity: &str,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
) -> Result<NpmTeamListResult> {
    let (scope, team) = npm_team_entity(entity)?;
    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = format!(
        "{}-/team/{}/{}/user?format=cli",
        registry,
        urlencoding::encode(&scope),
        urlencoding::encode(&team)
    );
    let value = npm_get(&client, &url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    Ok(NpmTeamListResult {
        registry,
        scope,
        team: Some(team),
        items: npm_team_list_items(&value)?,
    })
}

struct NpmTeamRequest<'a> {
    scope: &'a str,
    team: Option<&'a str>,
    action: &'a str,
    method: &'a str,
    body: serde_json::Value,
    registry_override: Option<&'a str>,
    userconfig_override: Option<&'a Path>,
    otp: Option<&'a str>,
}

fn npm_team_request(
    project_dir: &Path,
    request: NpmTeamRequest<'_>,
) -> Result<(String, u16, serde_json::Value)> {
    let client = Client::new();
    let npm_config = read_npm_config_with_overrides(
        project_dir,
        request.registry_override,
        request.userconfig_override,
    )?;
    let registry = ensure_trailing_slash(&npm_config.registry);
    let url = match request.action {
        "create" => format!(
            "{}-/org/{}/team",
            registry,
            urlencoding::encode(request.scope)
        ),
        "destroy" => format!(
            "{}-/team/{}/{}",
            registry,
            urlencoding::encode(request.scope),
            urlencoding::encode(request.team.unwrap_or_default())
        ),
        "add" | "rm" => format!(
            "{}-/team/{}/{}/user",
            registry,
            urlencoding::encode(request.scope),
            urlencoding::encode(request.team.unwrap_or_default())
        ),
        _ => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported npm team action `{}`",
                request.action
            )))
        }
    };
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm team needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let mut http_request = match request.method {
        "DELETE" => {
            if request.body.is_null() {
                npm_delete(&client, &url, &npm_config)
            } else {
                npm_delete(&client, &url, &npm_config).json(&request.body)
            }
        }
        "PUT" => npm_put(&client, &url, &npm_config).json(&request.body),
        other => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported npm team HTTP method `{other}`"
            )))
        }
    };
    if let Some(otp) = request.otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        http_request = http_request.header("npm-otp", otp);
    }
    let response = http_request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok((registry, status, response))
}

fn npm_team_scope(value: &str) -> Result<String> {
    let scope = value.trim().trim_start_matches('@');
    if scope.is_empty() || scope.contains(':') {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "invalid npm team scope `{value}`"
        )));
    }
    Ok(scope.to_owned())
}

fn npm_team_entity(value: &str) -> Result<(String, String)> {
    let (scope, team) = npm_access_scope_team(value)?;
    let Some(team) = team else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "team must be in format `scope:team`".to_owned(),
        ));
    };
    Ok((scope, team))
}

fn npm_team_user(value: &str) -> Result<String> {
    let user = value.trim();
    if user.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm team user cannot be empty".to_owned(),
        ));
    }
    Ok(user.to_owned())
}

fn npm_team_list_items(value: &serde_json::Value) -> Result<Vec<String>> {
    let mut items = Vec::new();
    if let Some(array) = value.as_array() {
        for item in array {
            if let Some(text) = npm_team_item_text(item) {
                items.push(text);
            }
        }
    } else if let Some(object) = value.as_object() {
        for (key, value) in object {
            if let Some(text) = value.as_str() {
                items.push(text.to_owned());
            } else if let Some(text) = npm_team_item_text(value) {
                items.push(text);
            } else {
                items.push(key.clone());
            }
        }
    } else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm team response was not a list or object".to_owned(),
        ));
    }
    items.sort();
    items.dedup();
    Ok(items)
}

fn npm_team_item_text(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            value
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            value
                .get("team")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            value
                .get("user")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
}

fn npm_dist_tag_url(registry: &str, package: &str, tag: &str) -> String {
    format!(
        "{}-/package/{}/dist-tags/{}",
        ensure_trailing_slash(registry),
        urlencoding::encode(package),
        urlencoding::encode(tag)
    )
}

pub fn deprecate_npm_package(
    project_dir: &Path,
    spec: &PackageSpec,
    message: &str,
    dry_run: bool,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmDeprecateResult> {
    if spec.ecosystem != Ecosystem::Npm || spec.direct_url.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
    }
    let (package, requirement) = npm_registry_name_and_requirement(spec)?;
    let requirement = requirement.unwrap_or_else(|| "*".to_owned());
    if !npm_deprecate_valid_requirement(&requirement) {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm deprecate got invalid version range `{requirement}`"
        )));
    }

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let encoded = urlencoding::encode(&package);
    let package_url = npm_registry_package_url(&registry, &encoded);
    let read_url = format!("{package_url}?write=true");
    let mut packument = npm_get(&client, &read_url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;

    let versions = npm_deprecate_matching_versions(&packument, &requirement)?;
    if !versions.is_empty() {
        let versions_map = packument
            .get_mut("versions")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                OmcRegistryError::UnsupportedSpec(format!(
                    "npm registry response for `{package}` did not include versions"
                ))
            })?;
        for version in &versions {
            let version_doc = versions_map
                .get_mut(version)
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| {
                    OmcRegistryError::UnsupportedSpec(format!(
                        "npm registry response for `{package}` had invalid version `{version}`"
                    ))
                })?;
            version_doc.insert(
                "deprecated".to_owned(),
                serde_json::Value::String(message.to_owned()),
            );
        }
    }

    if dry_run || versions.is_empty() {
        return Ok(NpmDeprecateResult {
            registry,
            package,
            requirement,
            message: message.to_owned(),
            versions,
            dry_run,
            status: None,
            response: serde_json::json!({ "dryRun": dry_run }),
        });
    }

    if npm_config.auth_token_for_url(&package_url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm deprecate needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }
    let mut request = npm_put(&client, &package_url, &npm_config).json(&packument);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;
    Ok(NpmDeprecateResult {
        registry,
        package,
        requirement,
        message: message.to_owned(),
        versions,
        dry_run,
        status: Some(status),
        response,
    })
}

fn npm_deprecate_valid_requirement(requirement: &str) -> bool {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return false;
    }
    if requirement == "*" {
        return true;
    }
    if Version::parse(requirement).is_ok() {
        return true;
    }
    let parts = requirement
        .replace(',', " ")
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parts.len() > 1 {
        return parts
            .iter()
            .all(|part| npm_deprecate_valid_requirement(part));
    }
    if requirement
        .strip_prefix('^')
        .and_then(parse_partial_npm_version)
        .is_some()
        || requirement
            .strip_prefix('~')
            .and_then(parse_partial_npm_version)
            .is_some()
    {
        return true;
    }
    npm_deprecate_comparator_valid(requirement)
}

fn npm_deprecate_comparator_valid(comparator: &str) -> bool {
    for op in [">=", "<=", ">", "<", "="] {
        if let Some(raw) = comparator.strip_prefix(op) {
            return parse_partial_npm_version(raw).is_some();
        }
    }
    if comparator.eq_ignore_ascii_case("x") {
        return true;
    }
    if let Some(prefix) = comparator
        .strip_suffix(".x")
        .or_else(|| comparator.strip_suffix(".*"))
    {
        return parse_partial_npm_version(prefix).is_some();
    }
    parse_partial_npm_version(comparator).is_some()
}

fn npm_deprecate_matching_versions(
    packument: &serde_json::Value,
    requirement: &str,
) -> Result<Vec<String>> {
    let versions = packument
        .get("versions")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "npm registry response did not include versions".to_owned(),
            )
        })?;
    let mut matching = versions
        .keys()
        .filter(|version| npm_version_satisfies(version, requirement))
        .cloned()
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| compare_npm_versions(left, right));
    Ok(matching)
}

fn npm_optional_json_response(response: reqwest::blocking::Response) -> Result<serde_json::Value> {
    let text = response.text()?;
    if text.trim().is_empty() {
        Ok(serde_json::Value::Null)
    } else {
        Ok(serde_json::from_str(&text).unwrap_or_else(|_| {
            serde_json::json!({
                "text": text,
            })
        }))
    }
}

pub fn unpublish_npm_package(
    project_dir: &Path,
    spec: &PackageSpec,
    dry_run: bool,
    force: bool,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmUnpublishResult> {
    if spec.ecosystem != Ecosystem::Npm || spec.direct_url.is_some() {
        return Err(OmcRegistryError::UnsupportedSpec(spec.requested()));
    }
    let (package, requested_version) = npm_registry_name_and_requirement(spec)?;
    let version = match requested_version.as_deref() {
        Some("*") | None => None,
        Some(version) if Version::parse(version).is_ok() => Some(version.to_owned()),
        Some(requirement) => {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "Can only unpublish a single version, or the entire project. Tags and ranges are not supported: `{requirement}`"
            )))
        }
    };

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package));
    let encoded = urlencoding::encode(&package);
    let package_url = npm_registry_package_url(&registry, &encoded);
    let read_url = format!("{package_url}?write=true");
    let response = npm_get(&client, &read_url, &npm_config).send()?;
    if response.status().as_u16() == 404 {
        let whole_package = version.is_none();
        return Ok(NpmUnpublishResult {
            registry,
            package,
            version,
            removed_versions: Vec::new(),
            dry_run,
            force,
            whole_package,
            changed: false,
            status: None,
            tarball_status: None,
            response: serde_json::json!({ "missing": true }),
        });
    }
    response.error_for_status_ref()?;
    let mut packument = response.json::<serde_json::Value>()?;
    let plan = npm_unpublish_plan(&packument, &package, version.as_deref(), force)?;

    if dry_run || !plan.changed {
        return Ok(NpmUnpublishResult {
            registry,
            package,
            version,
            removed_versions: plan.removed_versions,
            dry_run,
            force,
            whole_package: plan.whole_package,
            changed: plan.changed,
            status: None,
            tarball_status: None,
            response: serde_json::json!({
                "dryRun": dry_run,
                "changed": plan.changed,
            }),
        });
    }

    if npm_config.auth_token_for_url(&package_url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm unpublish needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }

    if plan.whole_package {
        let rev = npm_packument_rev(&packument, &package)?;
        let url = format!("{package_url}/-rev/{}", urlencoding::encode(&rev));
        let mut request = npm_delete(&client, &url, &npm_config);
        if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
            request = request.header("npm-otp", otp);
        }
        let response = request.send()?;
        response.error_for_status_ref()?;
        let status = response.status().as_u16();
        let response = npm_optional_json_response(response)?;
        return Ok(NpmUnpublishResult {
            registry,
            package,
            version,
            removed_versions: plan.removed_versions,
            dry_run,
            force,
            whole_package: true,
            changed: true,
            status: Some(status),
            tarball_status: None,
            response,
        });
    }

    let version = version.as_deref().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec("npm unpublish missing version".to_owned())
    })?;
    let tarball = npm_unpublish_remove_version(&mut packument, &package, version)?;
    let rev = npm_packument_rev(&packument, &package)?;
    let url = format!("{package_url}/-rev/{}", urlencoding::encode(&rev));
    let mut request = npm_put(&client, &url, &npm_config).json(&packument);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;

    let fresh = npm_get(&client, &read_url, &npm_config)
        .send()?
        .error_for_status()?
        .json::<serde_json::Value>()?;
    let fresh_rev = npm_packument_rev(&fresh, &package)?;
    let tarball_path = npm_unpublish_tarball_path(&tarball, &registry)?;
    let tarball_url = format!(
        "{}{}/-rev/{}",
        registry,
        tarball_path,
        urlencoding::encode(&fresh_rev)
    );
    let mut request = npm_delete(&client, &tarball_url, &npm_config);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let tarball_response = request.send()?;
    tarball_response.error_for_status_ref()?;
    let tarball_status = tarball_response.status().as_u16();

    Ok(NpmUnpublishResult {
        registry,
        package,
        version: Some(version.to_owned()),
        removed_versions: plan.removed_versions,
        dry_run,
        force,
        whole_package: false,
        changed: true,
        status: Some(status),
        tarball_status: Some(tarball_status),
        response,
    })
}

#[derive(Debug)]
struct NpmUnpublishPlan {
    removed_versions: Vec<String>,
    whole_package: bool,
    changed: bool,
}

fn npm_unpublish_plan(
    packument: &serde_json::Value,
    package: &str,
    version: Option<&str>,
    force: bool,
) -> Result<NpmUnpublishPlan> {
    let versions = npm_packument_version_keys(packument, package)?;
    let no_versions = versions.is_empty();
    let Some(version) = version else {
        if !force {
            return Err(OmcRegistryError::UnsupportedSpec(
                "Refusing to delete entire project.\nRun with --force to do this.".to_owned(),
            ));
        }
        return Ok(NpmUnpublishPlan {
            removed_versions: versions,
            whole_package: true,
            changed: true,
        });
    };

    let has_version = versions.iter().any(|candidate| candidate == version);
    if !has_version && !no_versions {
        return Ok(NpmUnpublishPlan {
            removed_versions: Vec::new(),
            whole_package: false,
            changed: false,
        });
    }
    if versions.len() == 1 && has_version && !force {
        return Err(OmcRegistryError::UnsupportedSpec(
            "Refusing to delete the last version of the package.\nIt will block from republishing a new version for 24 hours.\nRun with --force to do this."
                .to_owned(),
        ));
    }
    let whole_package = no_versions || versions.len() == 1;
    let removed_versions = if no_versions {
        Vec::new()
    } else if versions.len() == 1 {
        versions
    } else {
        vec![version.to_owned()]
    };
    Ok(NpmUnpublishPlan {
        removed_versions,
        whole_package,
        changed: true,
    })
}

fn npm_packument_version_keys(packument: &serde_json::Value, package: &str) -> Result<Vec<String>> {
    let Some(versions) = packument.get("versions") else {
        return Ok(Vec::new());
    };
    let versions = versions.as_object().ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!(
            "npm registry response for `{package}` had invalid versions"
        ))
    })?;
    let mut versions = versions.keys().cloned().collect::<Vec<_>>();
    versions.sort_by(|left, right| compare_npm_versions(left, right));
    Ok(versions)
}

fn npm_packument_rev(packument: &serde_json::Value, package: &str) -> Result<String> {
    packument
        .get("_rev")
        .and_then(serde_json::Value::as_str)
        .filter(|rev| !rev.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm registry response for `{package}` did not include _rev"
            ))
        })
}

fn npm_unpublish_remove_version(
    packument: &mut serde_json::Value,
    package: &str,
    version: &str,
) -> Result<String> {
    let versions = packument
        .get_mut("versions")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm registry response for `{package}` did not include versions"
            ))
        })?;
    let version_doc = versions.remove(version).ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!(
            "npm registry response for `{package}` did not include version `{version}`"
        ))
    })?;
    let tarball = version_doc
        .get("dist")
        .and_then(|dist| dist.get("tarball"))
        .and_then(serde_json::Value::as_str)
        .filter(|tarball| !tarball.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "npm registry response for `{package}` version `{version}` did not include dist.tarball"
            ))
        })?;
    let remaining_versions = versions.keys().cloned().collect::<Vec<_>>();

    if let Some(dist_tags) = packument
        .get_mut("dist-tags")
        .and_then(serde_json::Value::as_object_mut)
    {
        let latest_was_removed =
            dist_tags.get("latest").and_then(serde_json::Value::as_str) == Some(version);
        let tags_to_remove = dist_tags
            .iter()
            .filter(|(_, value)| value.as_str() == Some(version))
            .map(|(tag, _)| tag.clone())
            .collect::<Vec<_>>();
        for tag in tags_to_remove {
            dist_tags.remove(&tag);
        }
        if latest_was_removed {
            if let Some(latest) = remaining_versions
                .iter()
                .max_by(|left, right| compare_npm_versions(left, right))
                .cloned()
            {
                dist_tags.insert("latest".to_owned(), serde_json::Value::String(latest));
            }
        }
    }

    if let Some(object) = packument.as_object_mut() {
        object.remove("_revisions");
        object.remove("_attachments");
    }

    Ok(tarball)
}

fn npm_unpublish_tarball_path(tarball: &str, registry: &str) -> Result<String> {
    let registry_url = reqwest::Url::parse(registry)
        .map_err(|_| OmcRegistryError::UnsupportedSpec(registry.to_owned()))?;
    let tarball_url = reqwest::Url::parse(tarball)
        .map_err(|_| OmcRegistryError::UnsupportedSpec(tarball.to_owned()))?;
    let registry_path = registry_url.path().trim_start_matches('/');
    let mut tarball_path = tarball_url.path().trim_start_matches('/').to_owned();
    if !registry_path.is_empty() && tarball_path.starts_with(registry_path) {
        tarball_path = tarball_path[registry_path.len()..]
            .trim_start_matches('/')
            .to_owned();
    }
    if tarball_path.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm tarball URL `{tarball}` did not include a path"
        )));
    }
    Ok(tarball_path)
}

pub fn publish_npm_package(
    project_dir: &Path,
    package: NpmPublishPackage,
    registry_override: Option<&str>,
    userconfig_override: Option<&Path>,
    otp: Option<&str>,
) -> Result<NpmPublishResult> {
    if package.name.trim().is_empty() || package.version.trim().is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm publish needs package name and version".to_owned(),
        ));
    }
    if package.filename.trim().is_empty() || package.tarball.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm publish needs a non-empty package tarball".to_owned(),
        ));
    }

    let client = Client::new();
    let npm_config =
        read_npm_config_with_overrides(project_dir, registry_override, userconfig_override)?;
    let registry = ensure_trailing_slash(npm_config.registry_for(&package.name));
    let encoded = urlencoding::encode(&package.name);
    let url = npm_registry_package_url(&registry, &encoded);
    if npm_config.auth_token_for_url(&url).is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm publish needs authentication; run npm login or configure a registry _authToken"
                .to_owned(),
        ));
    }

    let shasum = sha1_hex(&package.tarball);
    let integrity = npm_publish_integrity(&package.tarball);
    let document = npm_publish_document(&registry, &package, &shasum, &integrity)?;
    let mut request = npm_put(&client, &url, &npm_config).json(&document);
    if let Some(otp) = otp.map(str::trim).filter(|otp| !otp.is_empty()) {
        request = request.header("npm-otp", otp);
    }
    let response = request.send()?;
    response.error_for_status_ref()?;
    let status = response.status().as_u16();
    let response = npm_optional_json_response(response)?;

    Ok(NpmPublishResult {
        registry,
        name: package.name,
        version: package.version,
        filename: package.filename,
        tag: package.tag,
        access: package.access,
        status,
        shasum,
        integrity,
        response,
    })
}
