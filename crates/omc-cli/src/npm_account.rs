//! npm account/auth/registry-admin commands: token, owner, access, org, team,
//! star, ping, whoami, profile, trust, login, logout. Extracted from lib.rs.

use crate::*;

use std::collections::BTreeSet;
use std::env;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use omc_registry::{
    add_npm_team_user, create_npm_team, create_npm_token, create_npm_trust, destroy_npm_team,
    grant_npm_access, mutate_npm_package_owner, mutate_npm_package_star,
    read_npm_access_collaborators, read_npm_access_packages, read_npm_access_status,
    read_npm_org_users, read_npm_package_owners, read_npm_ping_with_userconfig, read_npm_profile,
    read_npm_stars, read_npm_team_users, read_npm_teams, read_npm_token_list, read_npm_trust,
    read_npm_whoami, remove_npm_org_user, remove_npm_team_user, revoke_npm_access,
    revoke_npm_token, revoke_npm_trust, set_npm_access_mfa, set_npm_access_status,
    set_npm_org_user, set_npm_profile_property, Ecosystem, NpmAccessMapResult,
    NpmAccessMutationResult, NpmAccessStatusResult, NpmAccessToken, NpmOrgListResult,
    NpmOrgMutationResult, NpmOwnerListResult, NpmOwnerMutationResult, NpmPingResult,
    NpmProfileMutationResult, NpmProfileResult, NpmStarMutationResult, NpmStarsResult,
    NpmTeamListResult, NpmTeamMutationResult, NpmTokenCreateOptions, NpmTokenCreateResult,
    NpmTokenListResult, NpmTokenRevokeResult, NpmWhoamiResult, OmcRegistryError,
};

use crate::args::*;

pub(crate) fn absolutize_npm_star_action_paths(base_dir: &Path, action: &mut NpmStarAction) {
    match action {
        NpmStarAction::Mutate { userconfig, .. } | NpmStarAction::List { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn absolutize_npm_login_action_paths(base_dir: &Path, action: &mut NpmLoginAction) {
    absolutize_optional_path(base_dir, &mut action.userconfig);
}

pub(crate) fn absolutize_npm_logout_action_paths(base_dir: &Path, action: &mut NpmLogoutAction) {
    absolutize_optional_path(base_dir, &mut action.userconfig);
}

pub(crate) fn absolutize_npm_token_action_paths(base_dir: &Path, action: &mut NpmTokenAction) {
    match action {
        NpmTokenAction::List { userconfig, .. }
        | NpmTokenAction::Create { userconfig, .. }
        | NpmTokenAction::Revoke { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn absolutize_npm_trust_action_paths(base_dir: &Path, action: &mut NpmTrustAction) {
    match action {
        NpmTrustAction::List { userconfig, .. }
        | NpmTrustAction::Revoke { userconfig, .. }
        | NpmTrustAction::Create { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn absolutize_npm_profile_action_paths(base_dir: &Path, action: &mut NpmProfileAction) {
    match action {
        NpmProfileAction::Get { userconfig, .. } | NpmProfileAction::Set { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn absolutize_npm_owner_action_paths(base_dir: &Path, action: &mut NpmOwnerAction) {
    match action {
        NpmOwnerAction::List { userconfig, .. }
        | NpmOwnerAction::Add { userconfig, .. }
        | NpmOwnerAction::Remove { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn absolutize_npm_access_action_paths(base_dir: &Path, action: &mut NpmAccessAction) {
    match action {
        NpmAccessAction::ListPackages { userconfig, .. }
        | NpmAccessAction::ListCollaborators { userconfig, .. }
        | NpmAccessAction::GetStatus { userconfig, .. }
        | NpmAccessAction::SetStatus { userconfig, .. }
        | NpmAccessAction::SetMfa { userconfig, .. }
        | NpmAccessAction::Grant { userconfig, .. }
        | NpmAccessAction::Revoke { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn absolutize_npm_org_action_paths(base_dir: &Path, action: &mut NpmOrgAction) {
    match action {
        NpmOrgAction::Set { userconfig, .. }
        | NpmOrgAction::Remove { userconfig, .. }
        | NpmOrgAction::List { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn absolutize_npm_team_action_paths(base_dir: &Path, action: &mut NpmTeamAction) {
    match action {
        NpmTeamAction::Create { userconfig, .. }
        | NpmTeamAction::Destroy { userconfig, .. }
        | NpmTeamAction::Add { userconfig, .. }
        | NpmTeamAction::Remove { userconfig, .. }
        | NpmTeamAction::List { userconfig, .. } => {
            absolutize_optional_path(base_dir, userconfig);
        }
    }
}

pub(crate) fn print_npm_star(
    project_dir: &Path,
    action: NpmStarAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmStarAction::Mutate {
            specs,
            starred,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let mut results = Vec::new();
            for raw in specs {
                let spec = parse_package_spec(&raw, Some(Ecosystem::Npm))?;
                results.push(mutate_npm_package_star(
                    project_dir,
                    &spec,
                    starred,
                    npm_registry.as_deref(),
                    userconfig.as_deref(),
                    otp.as_deref(),
                )?);
            }
            print_npm_star_mutation_results(&results, json)?;
        }
        NpmStarAction::List {
            user,
            json,
            npm_registry,
            userconfig,
        } => {
            let result = read_npm_stars(
                project_dir,
                user.as_deref(),
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            print_npm_stars_result(&result, json)?;
        }
    }
    Ok(())
}

fn print_npm_star_mutation_results(
    results: &[NpmStarMutationResult],
    json: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!("{}", serde_json::to_string_pretty(results)?);
    } else {
        for result in results {
            let action = if result.starred {
                "starred"
            } else {
                "unstarred"
            };
            println!("{action} {}", result.package);
        }
    }
    Ok(())
}

fn print_npm_stars_result(result: &NpmStarsResult, json: bool) -> Result<(), OmcRegistryError> {
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else {
        for package in &result.packages {
            println!("{package}");
        }
    }
    Ok(())
}

pub(crate) fn print_npm_ping(
    project_dir: &Path,
    json: bool,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
) -> Result<(), OmcRegistryError> {
    let ping = read_npm_ping_with_userconfig(project_dir, npm_registry, userconfig)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&npm_ping_json(&ping))?);
    } else {
        println!("pong {}", ping.registry);
    }
    Ok(())
}

fn npm_ping_json(ping: &NpmPingResult) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "registry": ping.registry,
        "response": ping.response,
    })
}

pub(crate) fn print_npm_whoami(
    project_dir: &Path,
    json: bool,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
) -> Result<(), OmcRegistryError> {
    let whoami = read_npm_whoami(project_dir, npm_registry, userconfig)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&npm_whoami_json(&whoami))?
        );
    } else {
        println!("{}", whoami.username);
    }
    Ok(())
}

fn npm_whoami_json(whoami: &NpmWhoamiResult) -> serde_json::Value {
    serde_json::json!({
        "username": whoami.username,
        "registry": whoami.registry,
        "response": whoami.response,
    })
}

pub(crate) fn print_npm_login(
    project_dir: &Path,
    action: NpmLoginAction,
) -> Result<(), OmcRegistryError> {
    let token = npm_login_token(action.token.as_deref())?;
    let target = npm_auth_target(
        project_dir,
        action.npm_registry.as_deref(),
        action.userconfig.as_deref(),
        action.scope.as_deref(),
    )?;
    let written =
        write_npm_login_credentials(project_dir, action.userconfig.as_deref(), &target, &token)?;
    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "registry": target.registry,
                "scope": target.scope,
                "written": written,
            }))?
        );
    } else {
        println!("Logged in to {}", target.registry);
    }
    Ok(())
}

fn npm_login_token(explicit: Option<&str>) -> Result<String, OmcRegistryError> {
    let token = explicit
        .map(str::to_owned)
        .or_else(|| env::var("NODE_AUTH_TOKEN").ok())
        .or_else(|| env::var("NPM_TOKEN").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "npm login compatibility needs a token; pass --token/--auth-token or set NODE_AUTH_TOKEN/NPM_TOKEN. Interactive web and legacy prompts are not supported by OMC".to_owned(),
            )
        })?;
    Ok(token)
}

fn write_npm_login_credentials(
    project_dir: &Path,
    userconfig: Option<&Path>,
    target: &NpmAuthTarget,
    token: &str,
) -> Result<usize, OmcRegistryError> {
    let path = npm_config_write_path(project_dir, userconfig, None, NpmConfigLocation::User);
    let mut lines = read_npm_config_lines(&path)?;
    let mut written = 0usize;
    if let Some(scope) = &target.scope {
        upsert_npm_config_line(&mut lines, &format!("{scope}:registry"), &target.registry);
        written += 1;
    }
    let prefix = npm_registry_auth_key_prefix(&target.registry).ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(format!("invalid npm registry `{}`", target.registry))
    })?;
    upsert_npm_config_line(&mut lines, &format!("{prefix}_authToken"), token);
    written += 1;
    write_npm_config_lines(&path, &lines)?;
    Ok(written)
}

pub(crate) fn print_npm_logout(
    project_dir: &Path,
    action: NpmLogoutAction,
) -> Result<(), OmcRegistryError> {
    let target = npm_auth_target(
        project_dir,
        action.npm_registry.as_deref(),
        action.userconfig.as_deref(),
        action.scope.as_deref(),
    )?;
    let removed = clear_npm_logout_credentials(project_dir, action.userconfig.as_deref(), &target)?;
    if action.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "registry": target.registry,
                "scope": target.scope,
                "removed": removed,
            }))?
        );
    } else {
        println!("Logged out of {}", target.registry);
    }
    Ok(())
}

fn clear_npm_logout_credentials(
    project_dir: &Path,
    userconfig: Option<&Path>,
    target: &NpmAuthTarget,
) -> Result<usize, OmcRegistryError> {
    let path = npm_config_write_path(project_dir, userconfig, None, NpmConfigLocation::User);
    let mut lines = read_npm_config_lines(&path)?;
    if lines.is_empty() && !path.exists() {
        return Ok(0);
    }
    let auth_keys = npm_logout_auth_keys(&target.registry, target.scope.as_deref());
    let before = lines.len();
    lines.retain(|line| {
        let Some(key) = npm_config_line_key(line) else {
            return true;
        };
        !auth_keys.contains(key)
    });
    let removed = before.saturating_sub(lines.len());
    if removed > 0 || path.exists() {
        write_npm_config_lines(&path, &lines)?;
    }
    Ok(removed)
}

fn npm_logout_auth_keys(registry: &str, scope: Option<&str>) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    if let Some(scope) = scope {
        keys.insert(format!("{scope}:registry"));
    }
    if scope.is_none() {
        keys.extend(
            ["_authToken", "_auth", "username", "_password", "email"]
                .into_iter()
                .map(str::to_owned),
        );
    }
    if let Some(prefix) = npm_registry_auth_key_prefix(registry) {
        keys.extend(
            [
                "_authToken",
                "_auth",
                "username",
                "_password",
                "email",
                "always-auth",
            ]
            .into_iter()
            .map(|suffix| format!("{prefix}{suffix}")),
        );
    }
    keys
}

pub(crate) fn print_npm_token(
    project_dir: &Path,
    action: NpmTokenAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmTokenAction::List {
            json,
            parseable,
            npm_registry,
            userconfig,
        } => {
            let list =
                read_npm_token_list(project_dir, npm_registry.as_deref(), userconfig.as_deref())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&npm_token_list_json(&list))?
                );
            } else if parseable {
                print_npm_token_list_parseable(&list);
            } else {
                print_npm_token_list_text(&list);
            }
        }
        NpmTokenAction::Create {
            options,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let created = create_npm_token(
                project_dir,
                *options,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&npm_token_create_json(&created))?
                );
            } else if parseable {
                print_npm_token_create_parseable(&created);
            } else {
                let token = created.token.token.as_deref().unwrap_or_default();
                println!("Created token {token}");
                if !created.token.cidr.is_empty() {
                    println!("with IP whitelist: {}", created.token.cidr.join(","));
                }
                if let Some(expires) = created.token.expiry.as_deref() {
                    println!("expires: {expires}");
                }
            }
        }
        NpmTokenAction::Revoke {
            token,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let revoked = revoke_npm_token(
                project_dir,
                &token,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&npm_token_revoke_json(&revoked))?
                );
            } else {
                println!("Removed 1 token");
            }
        }
    }
    Ok(())
}

pub(crate) fn print_npm_trust(
    project_dir: &Path,
    action: NpmTrustAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmTrustAction::List {
            package,
            json,
            npm_registry,
            userconfig,
        } => {
            let package = npm_trust_package_arg(project_dir, package)?;
            let result = read_npm_trust(
                project_dir,
                &package,
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result.response)?);
            } else {
                print_npm_trust_configs(&result.package, &result.configs)?;
            }
        }
        NpmTrustAction::Revoke {
            package,
            id,
            dry_run,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let package = npm_trust_package_arg(project_dir, package)?;
            if dry_run {
                let output = serde_json::json!({
                    "dry_run": true,
                    "package": package,
                    "id": id,
                    "action": "revoke",
                });
                if json {
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "dry-run: would revoke trusted publishing configuration {id} for {package}"
                    );
                }
                return Ok(());
            }
            let result = revoke_npm_trust(
                project_dir,
                &package,
                &id,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result.response)?);
            } else {
                println!(
                    "Revoked trusted configuration for {} with id {}",
                    result.package, id
                );
            }
        }
        NpmTrustAction::Create {
            provider,
            package,
            config,
            dry_run,
            json,
            yes,
            npm_registry,
            userconfig,
            otp,
        } => {
            let package = npm_trust_package_arg(project_dir, package)?;
            let config = resolve_npm_trust_create_config(project_dir, provider, &package, config)?;
            if dry_run {
                let output = serde_json::json!({
                    "dry_run": true,
                    "package": package,
                    "provider": npm_trust_provider_name(provider),
                    "config": config,
                });
                if json {
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!(
                        "dry-run: would create trusted publishing configuration for {package}"
                    );
                    print_npm_trust_config(&config)?;
                }
                return Ok(());
            }
            if !yes {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm trust create is non-interactive in OMC; pass --yes or --dry-run"
                        .to_owned(),
                ));
            }
            let result = create_npm_trust(
                project_dir,
                &package,
                config,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result.response)?);
            } else {
                println!(
                    "Trust configuration created successfully for {}",
                    result.package
                );
                print_npm_trust_configs(
                    &result.package,
                    &npm_trust_response_configs(&result.response),
                )?;
            }
        }
    }
    Ok(())
}

fn npm_trust_package_arg(
    project_dir: &Path,
    package: Option<String>,
) -> Result<String, OmcRegistryError> {
    if let Some(package) = package
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    {
        return Ok(package);
    }
    let package_json = read_npm_pkg_json(&project_dir.join("package.json"))?;
    package_json
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "Package name must be specified either as an argument or in package.json"
                    .to_owned(),
            )
        })
}

fn print_npm_trust_configs(
    package: &str,
    configs: &[serde_json::Value],
) -> Result<(), OmcRegistryError> {
    if configs.is_empty() {
        println!("No trust configurations found for package ({package})");
        return Ok(());
    }
    for config in configs {
        print_npm_trust_config(config)?;
    }
    Ok(())
}

fn resolve_npm_trust_create_config(
    project_dir: &Path,
    provider: NpmTrustProvider,
    package: &str,
    mut config: serde_json::Value,
) -> Result<serde_json::Value, OmcRegistryError> {
    let Some(claim_key) = npm_trust_provider_entity_claim(provider) else {
        return Ok(config);
    };
    if npm_trust_claim_string(&config, claim_key).is_some() {
        return Ok(config);
    }
    let entity = infer_npm_trust_provider_entity(project_dir, provider, package)?;
    npm_trust_insert_claim(&mut config, claim_key, entity)?;
    Ok(config)
}

fn npm_trust_provider_entity_claim(provider: NpmTrustProvider) -> Option<&'static str> {
    match provider {
        NpmTrustProvider::GitHub => Some("repository"),
        NpmTrustProvider::GitLab => Some("project_path"),
        NpmTrustProvider::CircleCi => None,
    }
}

fn npm_trust_claim_string<'a>(config: &'a serde_json::Value, claim_key: &str) -> Option<&'a str> {
    config
        .get("claims")
        .and_then(serde_json::Value::as_object)
        .and_then(|claims| claims.get(claim_key))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn npm_trust_insert_claim(
    config: &mut serde_json::Value,
    claim_key: &str,
    value: String,
) -> Result<(), OmcRegistryError> {
    let claims = config
        .get_mut("claims")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(
                "npm trust provider config is missing claims".to_owned(),
            )
        })?;
    claims.insert(claim_key.to_owned(), serde_json::json!(value));
    Ok(())
}

fn infer_npm_trust_provider_entity(
    project_dir: &Path,
    provider: NpmTrustProvider,
    package: &str,
) -> Result<String, OmcRegistryError> {
    let package_json = read_npm_pkg_json(&project_dir.join("package.json")).map_err(|_| {
        OmcRegistryError::UnsupportedSpec(npm_trust_missing_entity_message(provider).to_owned())
    })?;
    let manifest_name = npm_manifest_string_field(&package_json, "name");
    if manifest_name.as_deref() != Some(package) {
        return Err(OmcRegistryError::UnsupportedSpec(
            npm_trust_missing_entity_message(provider).to_owned(),
        ));
    }
    let Some(repository) = npm_trust_repository_from_manifest(&package_json, provider) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            npm_trust_missing_entity_message(provider).to_owned(),
        ));
    };
    Ok(repository)
}

fn npm_trust_missing_entity_message(provider: NpmTrustProvider) -> &'static str {
    match provider {
        NpmTrustProvider::GitHub => {
            "GitHub repository must be specified with --repo or --repository or inferred from package.json repository"
        }
        NpmTrustProvider::GitLab => {
            "GitLab project must be specified with --project, --repo, or --repository or inferred from package.json repository"
        }
        NpmTrustProvider::CircleCi => "CircleCI repository origin must be specified with --vcs-origin",
    }
}

fn npm_trust_repository_from_manifest(
    manifest: &serde_json::Value,
    provider: NpmTrustProvider,
) -> Option<String> {
    let repository = manifest.get("repository")?;
    let raw = repository
        .as_str()
        .or_else(|| repository.get("url").and_then(serde_json::Value::as_str))?;
    npm_trust_repository_slug(raw, provider)
}

fn npm_trust_repository_slug(raw: &str, provider: NpmTrustProvider) -> Option<String> {
    let mut repository = raw.trim();
    if repository.is_empty() {
        return None;
    }
    if let Some(rest) = repository.strip_prefix("git+") {
        repository = rest;
    }
    let path = match provider {
        NpmTrustProvider::GitHub => npm_trust_repository_path(
            repository,
            "github.com",
            &["github:", "git@github.com:", "ssh://git@github.com/"],
        )?,
        NpmTrustProvider::GitLab => npm_trust_repository_path(
            repository,
            "gitlab.com",
            &["gitlab:", "git@gitlab.com:", "ssh://git@gitlab.com/"],
        )?,
        NpmTrustProvider::CircleCi => return None,
    };
    let mut segments = path
        .trim_matches('/')
        .trim_end_matches(".git")
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 2 {
        return None;
    }
    if provider == NpmTrustProvider::GitHub {
        segments.truncate(2);
    }
    Some(segments.join("/"))
}

fn npm_trust_repository_path(repository: &str, host: &str, prefixes: &[&str]) -> Option<String> {
    for prefix in prefixes {
        if let Some(path) = repository.strip_prefix(prefix) {
            return Some(path.to_owned());
        }
    }
    if let Ok(url) = reqwest::Url::parse(repository) {
        if url.host_str() == Some(host) {
            return Some(url.path().to_owned());
        }
    }
    None
}

fn print_npm_trust_config(config: &serde_json::Value) -> Result<(), OmcRegistryError> {
    if let Some(id) = config.get("id").and_then(serde_json::Value::as_str) {
        println!("id: {id}");
    }
    if let Some(kind) = config.get("type").and_then(serde_json::Value::as_str) {
        println!("type: {kind}");
    }
    if let Some(claims) = config.get("claims").and_then(serde_json::Value::as_object) {
        for (key, value) in claims {
            if let Some(value) = value.as_str() {
                println!("{key}: {value}");
            } else {
                println!("{key}: {}", serde_json::to_string(value)?);
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(config)?);
    }
    Ok(())
}

fn npm_trust_response_configs(response: &serde_json::Value) -> Vec<serde_json::Value> {
    match response {
        serde_json::Value::Array(items) => items.clone(),
        serde_json::Value::Null => Vec::new(),
        item => vec![item.clone()],
    }
}

fn npm_trust_provider_name(provider: NpmTrustProvider) -> &'static str {
    match provider {
        NpmTrustProvider::GitHub => "github",
        NpmTrustProvider::GitLab => "gitlab",
        NpmTrustProvider::CircleCi => "circleci",
    }
}

pub(crate) fn print_npm_profile(
    project_dir: &Path,
    action: NpmProfileAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmProfileAction::Get {
            keys,
            json,
            parseable,
            npm_registry,
            userconfig,
        } => {
            let profile =
                read_npm_profile(project_dir, npm_registry.as_deref(), userconfig.as_deref())?;
            print_npm_profile_get(profile, &keys, json, parseable)?;
        }
        NpmProfileAction::Set {
            property,
            value,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let result = set_npm_profile_property(
                project_dir,
                &property,
                &value,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_profile_set(result, json, parseable)?;
        }
    }
    Ok(())
}

fn print_npm_profile_get(
    result: NpmProfileResult,
    keys: &[String],
    json: bool,
    parseable: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result.profile)?);
        return Ok(());
    }

    let cleaned = npm_profile_cleaned(&result.profile);
    if !keys.is_empty() {
        let values = keys
            .iter()
            .flat_map(|key| key.split(','))
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(|key| {
                npm_profile_cleaned_get(&cleaned, key)
                    .map(npm_profile_display_value)
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        println!("{}", values.join("\t"));
    } else if parseable {
        if let Some(object) = result.profile.as_object() {
            for (key, value) in object {
                let display = if key == "tfa" {
                    npm_profile_cleaned_get(&cleaned, "two-factor auth")
                        .map(npm_profile_display_value)
                        .unwrap_or_default()
                } else {
                    npm_profile_display_value(value)
                };
                println!("{key}\t{display}");
            }
        }
    } else {
        for (key, value) in cleaned {
            println!("{key}: {}", npm_profile_display_value(&value));
        }
    }
    Ok(())
}

fn print_npm_profile_set(
    result: NpmProfileMutationResult,
    json: bool,
    parseable: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                result.property.clone(): result.value.clone(),
            }))?
        );
    } else if parseable {
        println!(
            "{}\t{}",
            result.property,
            npm_profile_display_value(&result.value)
        );
    } else if !result.value.is_null() {
        println!(
            "Set {} to {}",
            result.property,
            npm_profile_display_value(&result.value)
        );
    } else {
        println!("Set {}", result.property);
    }
    Ok(())
}

fn npm_profile_cleaned(profile: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
    let mut cleaned = Vec::new();
    for key in NPM_PROFILE_KNOWN_KEYS {
        cleaned.push((
            (*key).to_owned(),
            profile
                .get(*key)
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        ));
    }

    if let Some(object) = profile.as_object() {
        for (key, value) in object {
            if npm_profile_cleaned_get(&cleaned, key).is_none()
                && key != "tfa"
                && key != "email_verified"
            {
                cleaned.push((key.clone(), value.clone()));
            }
        }
    }

    let email = profile
        .get("email")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let suffix = if profile
        .get("email_verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        " (verified)"
    } else {
        "(unverified)"
    };
    npm_profile_cleaned_set(
        &mut cleaned,
        "email",
        serde_json::Value::String(format!("{email}{suffix}")),
    );

    let tfa_mode = profile
        .get("tfa")
        .and_then(serde_json::Value::as_object)
        .filter(|tfa| {
            !tfa.get("pending")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .and_then(|tfa| tfa.get("mode"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("disabled");
    npm_profile_cleaned_set(
        &mut cleaned,
        "two-factor auth",
        serde_json::Value::String(tfa_mode.to_owned()),
    );
    cleaned
}

fn npm_profile_cleaned_get<'a>(
    cleaned: &'a [(String, serde_json::Value)],
    key: &str,
) -> Option<&'a serde_json::Value> {
    cleaned
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
}

fn npm_profile_cleaned_set(
    cleaned: &mut [(String, serde_json::Value)],
    key: &str,
    value: serde_json::Value,
) {
    if let Some((_, existing)) = cleaned
        .iter_mut()
        .find(|(candidate, _)| candidate.as_str() == key)
    {
        *existing = value;
    }
}

fn npm_profile_display_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

pub(crate) fn print_npm_access(
    project_dir: &Path,
    action: NpmAccessAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmAccessAction::ListPackages {
            owner,
            package,
            json,
            npm_registry,
            userconfig,
        } => {
            let owner = match owner {
                Some(owner) => owner,
                None => {
                    read_npm_whoami(project_dir, npm_registry.as_deref(), userconfig.as_deref())?
                        .username
                }
            };
            let result = read_npm_access_packages(
                project_dir,
                &owner,
                package.as_deref(),
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            print_npm_access_map(result, json)?;
        }
        NpmAccessAction::ListCollaborators {
            package,
            user,
            json,
            npm_registry,
            userconfig,
        } => {
            let package = npm_access_package_arg(project_dir, package.as_deref())?;
            let result = read_npm_access_collaborators(
                project_dir,
                &package,
                user.as_deref(),
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            print_npm_access_map(result, json)?;
        }
        NpmAccessAction::GetStatus {
            package,
            json,
            npm_registry,
            userconfig,
        } => {
            let package = npm_access_package_arg(project_dir, package.as_deref())?;
            let result = read_npm_access_status(
                project_dir,
                &package,
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            print_npm_access_status(result, json)?;
        }
        NpmAccessAction::SetStatus {
            package,
            status,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let package = npm_access_package_arg(project_dir, package.as_deref())?;
            let result = set_npm_access_status(
                project_dir,
                &package,
                &status,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_access_mutation(result, json)?;
        }
        NpmAccessAction::SetMfa {
            package,
            level,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let package = npm_access_package_arg(project_dir, package.as_deref())?;
            let result = set_npm_access_mfa(
                project_dir,
                &package,
                &level,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_access_mutation(result, json)?;
        }
        NpmAccessAction::Grant {
            permission,
            scope_team,
            package,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let package = npm_access_package_arg(project_dir, package.as_deref())?;
            let result = grant_npm_access(
                project_dir,
                &scope_team,
                &package,
                &permission,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_access_mutation(result, json)?;
        }
        NpmAccessAction::Revoke {
            scope_team,
            package,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let package = npm_access_package_arg(project_dir, package.as_deref())?;
            let result = revoke_npm_access(
                project_dir,
                &scope_team,
                &package,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_access_mutation(result, json)?;
        }
    }
    Ok(())
}

fn print_npm_access_map(result: NpmAccessMapResult, json: bool) -> Result<(), OmcRegistryError> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result.items)?);
    } else {
        for (item, value) in result.items {
            println!("{item}: {value}");
        }
    }
    Ok(())
}

fn print_npm_access_status(
    result: NpmAccessStatusResult,
    json: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                result.package: result.status,
            }))?
        );
    } else {
        println!("{}: {}", result.package, result.status);
    }
    Ok(())
}

fn print_npm_access_mutation(
    result: NpmAccessMutationResult,
    json: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        match result.action.as_str() {
            "grant" => println!(
                "+ {} {} {}",
                result.permission.as_deref().unwrap_or_default(),
                result.scope_team.as_deref().unwrap_or_default(),
                result.package
            ),
            "revoke" => println!(
                "- {} {}",
                result.scope_team.as_deref().unwrap_or_default(),
                result.package
            ),
            action => println!("{action} {}", result.package),
        }
    }
    Ok(())
}

fn npm_access_package_arg(
    project_dir: &Path,
    package: Option<&str>,
) -> Result<String, OmcRegistryError> {
    if let Some(package) = package.map(str::trim).filter(|package| !package.is_empty()) {
        return Ok(package.to_owned());
    }
    let package = read_npm_pkg_json(&project_dir.join("package.json"))?;
    npm_package_json_name(&package)
}

pub(crate) fn print_npm_org(
    project_dir: &Path,
    action: NpmOrgAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmOrgAction::Set {
            org,
            user,
            role,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let result = set_npm_org_user(
                project_dir,
                &org,
                &user,
                role.as_deref(),
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_org_mutation(result, json, parseable)?;
        }
        NpmOrgAction::Remove {
            org,
            user,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let result = remove_npm_org_user(
                project_dir,
                &org,
                &user,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_org_mutation(result, json, parseable)?;
        }
        NpmOrgAction::List {
            org,
            user,
            json,
            parseable,
            npm_registry,
            userconfig,
        } => {
            let result = read_npm_org_users(
                project_dir,
                &org,
                user.as_deref(),
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            print_npm_org_list(result, json, parseable)?;
        }
    }
    Ok(())
}

fn print_npm_org_list(
    result: NpmOrgListResult,
    json: bool,
    parseable: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result.users)?);
    } else if parseable {
        println!("user\trole");
        for (user, role) in result.users {
            println!("{user}\t{role}");
        }
    } else {
        for (user, role) in result.users {
            println!("{user} - {role}");
        }
    }
    Ok(())
}

fn print_npm_org_mutation(
    result: NpmOrgMutationResult,
    json: bool,
    parseable: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        let value = match result.action.as_str() {
            "set" => serde_json::json!({
                "org": {
                    "name": result.org,
                    "size": result.user_count,
                },
                "user": result.user,
                "role": result.role.as_deref().unwrap_or("developer"),
            }),
            "rm" => serde_json::json!({
                "user": result.user,
                "org": result.org,
                "userCount": result.user_count.unwrap_or_default(),
                "deleted": true,
            }),
            _ => serde_json::to_value(&result)?,
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if parseable {
        match result.action.as_str() {
            "set" => {
                println!("org\torgsize\tuser\trole");
                println!(
                    "{}\t{}\t{}\t{}",
                    result.org,
                    result.user_count.unwrap_or_default(),
                    result.user,
                    result.role.as_deref().unwrap_or("developer")
                );
            }
            "rm" => {
                println!("user\torg\tuserCount\tdeleted");
                println!(
                    "{}\t{}\t{}\ttrue",
                    result.user,
                    result.org,
                    result.user_count.unwrap_or_default()
                );
            }
            action => println!("{}\t{}", result.user, action),
        }
    } else {
        match result.action.as_str() {
            "set" => println!(
                "Added {} as {} to {}.\nYou now have {} member{} in this org.",
                result.user,
                result.role.as_deref().unwrap_or("developer"),
                result.org,
                result.user_count.unwrap_or_default(),
                if result.user_count == Some(1) {
                    ""
                } else {
                    "s"
                }
            ),
            "rm" => println!(
                "Successfully removed {} from {}.\nYou now have {} member{} in this org.",
                result.user,
                result.org,
                result.user_count.unwrap_or_default(),
                if result.user_count == Some(1) {
                    ""
                } else {
                    "s"
                }
            ),
            action => println!("{action} {} in {}", result.user, result.org),
        }
    }
    Ok(())
}

pub(crate) fn print_npm_team(
    project_dir: &Path,
    action: NpmTeamAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmTeamAction::Create {
            scope_team,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let result = create_npm_team(
                project_dir,
                &scope_team,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_team_mutation(result, json, parseable)?;
        }
        NpmTeamAction::Destroy {
            scope_team,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let result = destroy_npm_team(
                project_dir,
                &scope_team,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_team_mutation(result, json, parseable)?;
        }
        NpmTeamAction::Add {
            scope_team,
            user,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let result = add_npm_team_user(
                project_dir,
                &scope_team,
                &user,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_team_mutation(result, json, parseable)?;
        }
        NpmTeamAction::Remove {
            scope_team,
            user,
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        } => {
            let result = remove_npm_team_user(
                project_dir,
                &scope_team,
                &user,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            print_npm_team_mutation(result, json, parseable)?;
        }
        NpmTeamAction::List {
            scope_or_team,
            json,
            parseable,
            npm_registry,
            userconfig,
        } => {
            let result = if scope_or_team.contains(':') {
                read_npm_team_users(
                    project_dir,
                    &scope_or_team,
                    npm_registry.as_deref(),
                    userconfig.as_deref(),
                )?
            } else {
                read_npm_teams(
                    project_dir,
                    &scope_or_team,
                    npm_registry.as_deref(),
                    userconfig.as_deref(),
                )?
            };
            print_npm_team_list(result, json, parseable)?;
        }
    }
    Ok(())
}

fn print_npm_team_list(
    result: NpmTeamListResult,
    json: bool,
    parseable: bool,
) -> Result<(), OmcRegistryError> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result.items)?);
    } else if parseable {
        for item in result.items {
            println!("{item}");
        }
    } else if let Some(team) = result.team.as_deref() {
        let plural = if result.items.len() == 1 { "" } else { "s" };
        let more = if result.items.is_empty() { "" } else { ":" };
        println!(
            "@{}:{} has {} user{}{}",
            result.scope,
            team,
            result.items.len(),
            plural,
            more
        );
        for item in result.items {
            println!("{item}");
        }
    } else {
        let plural = if result.items.len() == 1 { "" } else { "s" };
        let more = if result.items.is_empty() { "" } else { ":" };
        println!(
            "@{} has {} team{}{}",
            result.scope,
            result.items.len(),
            plural,
            more
        );
        for item in result.items {
            println!("@{item}");
        }
    }
    Ok(())
}

fn print_npm_team_mutation(
    result: NpmTeamMutationResult,
    json: bool,
    parseable: bool,
) -> Result<(), OmcRegistryError> {
    let entity = format!("{}:{}", result.scope, result.team);
    if json {
        let value = match result.action.as_str() {
            "create" => serde_json::json!({ "created": true, "team": entity }),
            "destroy" => serde_json::json!({ "deleted": true, "team": entity }),
            "add" => serde_json::json!({
                "added": true,
                "team": entity,
                "user": result.user.as_deref().unwrap_or_default(),
            }),
            "rm" => serde_json::json!({
                "removed": true,
                "team": entity,
                "user": result.user.as_deref().unwrap_or_default(),
            }),
            _ => serde_json::to_value(&result)?,
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if parseable {
        match result.action.as_str() {
            "create" => println!("{entity}\tcreated"),
            "destroy" => println!("{entity}\tdeleted"),
            "add" => println!(
                "{}\t{}\tadded",
                result.user.as_deref().unwrap_or_default(),
                entity
            ),
            "rm" => println!(
                "{}\t{}\tremoved",
                result.user.as_deref().unwrap_or_default(),
                entity
            ),
            action => println!("{entity}\t{action}"),
        }
    } else {
        match result.action.as_str() {
            "create" => println!("+@{entity}"),
            "destroy" => println!("-@{entity}"),
            "add" => println!(
                "{} added to @{}",
                result.user.as_deref().unwrap_or_default(),
                entity
            ),
            "rm" => println!(
                "{} removed from @{}",
                result.user.as_deref().unwrap_or_default(),
                entity
            ),
            action => println!("{action} @{entity}"),
        }
    }
    Ok(())
}

pub(crate) fn print_npm_owner(
    project_dir: &Path,
    action: NpmOwnerAction,
) -> Result<(), OmcRegistryError> {
    match action {
        NpmOwnerAction::List {
            spec,
            json,
            npm_registry,
            userconfig,
        } => {
            let spec = npm_owner_package_spec(project_dir, spec.as_deref())?;
            let spec = parse_package_spec(&spec, Some(Ecosystem::Npm))?;
            let result = read_npm_package_owners(
                project_dir,
                &spec,
                npm_registry.as_deref(),
                userconfig.as_deref(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_npm_owner_list_text(&result);
            }
        }
        NpmOwnerAction::Add {
            user,
            spec,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let spec = npm_owner_package_spec(project_dir, spec.as_deref())?;
            let spec = parse_package_spec(&spec, Some(Ecosystem::Npm))?;
            let result = mutate_npm_package_owner(
                project_dir,
                &spec,
                &user,
                true,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_npm_owner_mutation_text(&result);
            }
        }
        NpmOwnerAction::Remove {
            user,
            spec,
            json,
            npm_registry,
            userconfig,
            otp,
        } => {
            let spec = npm_owner_package_spec(project_dir, spec.as_deref())?;
            let spec = parse_package_spec(&spec, Some(Ecosystem::Npm))?;
            let result = mutate_npm_package_owner(
                project_dir,
                &spec,
                &user,
                false,
                npm_registry.as_deref(),
                userconfig.as_deref(),
                otp.as_deref(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_npm_owner_mutation_text(&result);
            }
        }
    }
    Ok(())
}

fn print_npm_owner_list_text(result: &NpmOwnerListResult) {
    if result.owners.is_empty() {
        println!("no admin found");
        return;
    }
    for owner in &result.owners {
        println!("{}", npm_owner_text(owner));
    }
}

fn print_npm_owner_mutation_text(result: &NpmOwnerMutationResult) {
    if result.changed {
        let prefix = if result.added { '+' } else { '-' };
        println!("{prefix} {} ({})", result.user, result.package);
    } else if result.added {
        println!("{} is already an owner of {}", result.user, result.package);
    } else {
        println!("{} is not an owner of {}", result.user, result.package);
    }
}

fn npm_owner_text(owner: &omc_registry::NpmSearchUser) -> String {
    let username = owner.username.as_deref().unwrap_or_default();
    match owner.email.as_deref() {
        Some(email) if !email.is_empty() => format!("{username} <{email}>"),
        _ => username.to_owned(),
    }
}

fn npm_owner_package_spec(
    project_dir: &Path,
    spec: Option<&str>,
) -> Result<String, OmcRegistryError> {
    if let Some(spec) = spec {
        return Ok(spec.to_owned());
    }
    let package = read_npm_pkg_json(&project_dir.join("package.json"))?;
    let Some(name) = package.get("name").and_then(serde_json::Value::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm owner needs a package or package.json name".to_owned(),
        ));
    };
    Ok(name.to_owned())
}

fn npm_token_list_json(list: &NpmTokenListResult) -> serde_json::Value {
    serde_json::json!({
        "registry": list.registry,
        "tokens": list.tokens,
        "total": list.total.unwrap_or(list.tokens.len() as u64),
        "urls": list.urls,
        "response": list.response,
    })
}

fn npm_token_revoke_json(revoked: &NpmTokenRevokeResult) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "registry": revoked.registry,
        "token": revoked.token,
        "status": revoked.status,
    })
}

fn npm_token_create_json(created: &NpmTokenCreateResult) -> serde_json::Value {
    let mut value = created.response.clone();
    npm_token_create_scrub_output(&mut value);
    value
}

fn print_npm_token_create_parseable(created: &NpmTokenCreateResult) {
    let mut value = created.response.clone();
    npm_token_create_scrub_output(&mut value);
    if let serde_json::Value::Object(fields) = value {
        for (key, value) in fields {
            println!("{key}\t{}", npm_json_parseable_value(&value));
        }
    }
}

fn npm_token_create_scrub_output(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(fields) = value {
        fields.remove("key");
        fields.remove("updated");
        if let Some(token) = fields.get_mut("token") {
            npm_token_create_scrub_output(token);
        }
    }
}

fn print_npm_token_list_parseable(list: &NpmTokenListResult) {
    println!("key\ttoken\tcreated\treadonly\tcidr");
    for token in &list.tokens {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            npm_token_key(token),
            npm_token_token(token),
            token.created.as_deref().unwrap_or_default(),
            npm_token_readonly(token),
            npm_token_cidr(token)
        );
    }
}

fn print_npm_token_list_text(list: &NpmTokenListResult) {
    println!("key\ttoken\tcreated\treadonly\tcidr");
    for token in &list.tokens {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            npm_token_key(token),
            npm_token_token(token),
            token.created.as_deref().unwrap_or_default(),
            npm_token_readonly(token),
            npm_token_cidr(token)
        );
    }
}

fn npm_token_key(token: &NpmAccessToken) -> &str {
    token.key.as_deref().unwrap_or_default()
}

fn npm_token_token(token: &NpmAccessToken) -> &str {
    token.token.as_deref().unwrap_or_default()
}

fn npm_token_readonly(token: &NpmAccessToken) -> &'static str {
    if token.readonly.unwrap_or(false) {
        "yes"
    } else {
        "no"
    }
}

fn npm_token_cidr(token: &NpmAccessToken) -> String {
    token.cidr.join(",")
}

pub(crate) fn parse_npm_star_args(
    starred: bool,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut specs = Vec::new();
    let command = if starred { "npm star" } else { "npm unstar" };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_star_flag_value(args, index, arg)?);
        } else if let Some(registry) = arg.strip_prefix("--registry=") {
            npm_registry = Some(registry.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_star_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_star_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_star_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg(command, arg));
        } else {
            specs.push(arg.clone());
        }
        index += 1;
    }

    if specs.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{command} needs at least one package spec"
        )));
    }
    Ok(NpmCompatAction::Star {
        action: NpmStarAction::Mutate {
            specs,
            starred,
            json,
            npm_registry,
            userconfig,
            otp,
        },
    })
}

pub(crate) fn parse_npm_stars_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_star_flag_value(args, index, arg)?);
        } else if let Some(registry) = arg.strip_prefix("--registry=") {
            npm_registry = Some(registry.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_star_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p") {
        } else if matches!(arg.as_str(), "--loglevel" | "--cache") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_star_ignored_equals_flag(arg) {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm stars", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    if positionals.len() > 1 {
        return Err(unsupported_compat_arg("npm stars", &positionals[1]));
    }
    Ok(NpmCompatAction::Star {
        action: NpmStarAction::List {
            user: positionals.pop(),
            json,
            npm_registry,
            userconfig,
        },
    })
}

fn npm_star_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--parseable=",
        "--loglevel=",
        "--cache=",
        "--color=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_star_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

pub(crate) fn parse_npm_ping_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let (json, npm_registry, userconfig) = parse_npm_registry_identity_args("npm ping", args)?;
    Ok(NpmCompatAction::Ping {
        json,
        npm_registry,
        userconfig,
    })
}

pub(crate) fn parse_npm_whoami_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let (json, npm_registry, userconfig) = parse_npm_registry_identity_args("npm whoami", args)?;
    Ok(NpmCompatAction::Whoami {
        json,
        npm_registry,
        userconfig,
    })
}

pub(crate) fn parse_npm_login_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut userconfig = None;
    let mut scope = None;
    let mut token = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--scope" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value")))?;
            scope = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--scope=") {
            scope = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--token" | "--auth-token") {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value")))?;
            token = Some(value.clone());
        } else if let Some(value) = arg
            .strip_prefix("--token=")
            .or_else(|| arg.strip_prefix("--auth-token="))
        {
            token = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value")))?;
            userconfig = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if matches!(arg.as_str(), "--auth-type" | "--otp" | "--loglevel") {
            index += 1;
            if args.get(index).is_none() {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "{arg} needs a value"
                )));
            }
        } else if npm_workspace_scope_ignored_flag(arg)
            || npm_login_ignored_equals_flag(arg)
            || matches!(
                arg.as_str(),
                "--silent" | "-s" | "--always-auth" | "--no-always-auth" | "--workspace" | "-w"
            )
        {
            if matches!(arg.as_str(), "--workspace" | "-w") {
                index += 1;
                if args.get(index).is_none() {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "{arg} needs a value"
                    )));
                }
            }
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
        return Err(unsupported_compat_arg("npm login", &positionals[0]));
    }
    Ok(NpmCompatAction::Login {
        action: NpmLoginAction {
            scope,
            json,
            npm_registry,
            userconfig,
            token,
        },
    })
}

fn npm_login_ignored_equals_flag(arg: &str) -> bool {
    [
        "--userconfig=",
        "--auth-type=",
        "--otp=",
        "--loglevel=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
        "--always-auth=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn parse_npm_logout_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut userconfig = None;
    let mut scope = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--scope" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value")))?;
            scope = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--scope=") {
            scope = Some(value.to_owned());
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
        } else if npm_workspace_scope_ignored_flag(arg)
            || npm_logout_ignored_equals_flag(arg)
            || matches!(arg.as_str(), "--silent" | "-s" | "--workspace" | "-w")
        {
            if matches!(arg.as_str(), "--workspace" | "-w") {
                index += 1;
                if args.get(index).is_none() {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "{arg} needs a value"
                    )));
                }
            }
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
        return Err(unsupported_compat_arg("npm logout", &positionals[0]));
    }
    Ok(NpmCompatAction::Logout {
        action: NpmLogoutAction {
            scope,
            json,
            npm_registry,
            userconfig,
        },
    })
}

fn npm_logout_ignored_equals_flag(arg: &str) -> bool {
    [
        "--userconfig=",
        "--loglevel=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn parse_npm_token_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut command = None;
    let mut command_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if command.is_none() && !arg.starts_with('-') {
            command = Some(arg.as_str());
        } else {
            command_args.push(arg.clone());
            if npm_token_presubcommand_value_flag(arg) {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value"))
                })?;
                command_args.push(value.clone());
            }
        }
        index += 1;
    }
    let command = command.unwrap_or("list");
    match command {
        "list" | "ls" => {
            let mut parseable = false;
            let mut filtered = Vec::new();
            for arg in command_args {
                if matches!(arg.as_str(), "--parseable" | "-p") {
                    parseable = true;
                } else {
                    filtered.push(arg.clone());
                }
            }
            let (json, npm_registry, userconfig) =
                parse_npm_registry_identity_args("npm token list", &filtered)?;
            Ok(NpmCompatAction::Token {
                action: NpmTokenAction::List {
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                },
            })
        }
        "revoke" | "rm" | "delete" | "del" => parse_npm_token_revoke_args(command, &command_args),
        "create" => parse_npm_token_create_args(&command_args),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm token command `{other}`"
        ))),
    }
}

pub(crate) fn parse_npm_trust_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut command = None;
    let mut command_args = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if command.is_none() && !arg.starts_with('-') {
            command = Some(arg.as_str());
        } else {
            command_args.push(arg.clone());
            if npm_trust_presubcommand_value_flag(arg) {
                index += 1;
                let value = args.get(index).ok_or_else(|| {
                    OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value"))
                })?;
                command_args.push(value.clone());
            }
        }
        index += 1;
    }

    match command.unwrap_or("list") {
        "list" | "ls" => parse_npm_trust_list_args(&command_args),
        "revoke" | "rm" => parse_npm_trust_revoke_args(&command_args),
        "github" => parse_npm_trust_create_args(NpmTrustProvider::GitHub, &command_args),
        "gitlab" => parse_npm_trust_create_args(NpmTrustProvider::GitLab, &command_args),
        "circleci" => parse_npm_trust_create_args(NpmTrustProvider::CircleCi, &command_args),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm trust command `{other}`"
        ))),
    }
}

fn npm_trust_presubcommand_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--registry"
            | "--userconfig"
            | "--loglevel"
            | "--cache"
            | "--otp"
            | "--id"
            | "--file"
            | "--repo"
            | "--repository"
            | "--project"
            | "--env"
            | "--environment"
            | "--org-id"
            | "--project-id"
            | "--pipeline-definition-id"
            | "--vcs-origin"
            | "--context-id"
    )
}

#[derive(Debug, Default)]
struct NpmTrustArgs {
    json: bool,
    dry_run: bool,
    yes: bool,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
    otp: Option<String>,
    id: Option<String>,
    file: Option<String>,
    repository: Option<String>,
    project: Option<String>,
    environment: Option<String>,
    org_id: Option<String>,
    project_id: Option<String>,
    pipeline_definition_id: Option<String>,
    vcs_origin: Option<String>,
    context_ids: Vec<String>,
    positionals: Vec<String>,
}

fn parse_npm_trust_common_args(
    command: &str,
    args: &[String],
) -> Result<NpmTrustArgs, OmcRegistryError> {
    let mut parsed = NpmTrustArgs::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            parsed.json = true;
        } else if matches!(arg.as_str(), "--json=false" | "--no-json") {
            parsed.json = false;
        } else if matches!(arg.as_str(), "--dry-run" | "--dry-run=true") {
            parsed.dry_run = true;
        } else if matches!(arg.as_str(), "--no-dry-run" | "--dry-run=false") {
            parsed.dry_run = false;
        } else if matches!(arg.as_str(), "--yes" | "-y" | "--yes=true") {
            parsed.yes = true;
        } else if matches!(arg.as_str(), "--no-yes" | "--yes=false") {
            parsed.yes = false;
        } else if arg == "--registry" {
            index += 1;
            parsed.npm_registry = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            parsed.npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            parsed.userconfig = Some(PathBuf::from(npm_trust_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            parsed.userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            parsed.otp = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            parsed.otp = Some(value.to_owned());
        } else if arg == "--id" {
            index += 1;
            parsed.id = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--id=") {
            parsed.id = Some(value.to_owned());
        } else if arg == "--file" {
            index += 1;
            parsed.file = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--file=") {
            parsed.file = Some(value.to_owned());
        } else if arg == "--repo" || arg == "--repository" {
            index += 1;
            parsed.repository = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg
            .strip_prefix("--repo=")
            .or_else(|| arg.strip_prefix("--repository="))
        {
            parsed.repository = Some(value.to_owned());
        } else if arg == "--project" {
            index += 1;
            parsed.project = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--project=") {
            parsed.project = Some(value.to_owned());
        } else if arg == "--env" || arg == "--environment" {
            index += 1;
            parsed.environment = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg
            .strip_prefix("--env=")
            .or_else(|| arg.strip_prefix("--environment="))
        {
            parsed.environment = Some(value.to_owned());
        } else if arg == "--org-id" {
            index += 1;
            parsed.org_id = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--org-id=") {
            parsed.org_id = Some(value.to_owned());
        } else if arg == "--project-id" {
            index += 1;
            parsed.project_id = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--project-id=") {
            parsed.project_id = Some(value.to_owned());
        } else if arg == "--pipeline-definition-id" {
            index += 1;
            parsed.pipeline_definition_id = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--pipeline-definition-id=") {
            parsed.pipeline_definition_id = Some(value.to_owned());
        } else if arg == "--vcs-origin" {
            index += 1;
            parsed.vcs_origin = Some(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--vcs-origin=") {
            parsed.vcs_origin = Some(value.to_owned());
        } else if arg == "--context-id" {
            index += 1;
            parsed
                .context_ids
                .push(npm_trust_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--context-id=") {
            parsed.context_ids.push(value.to_owned());
        } else if arg == "--loglevel" || arg == "--cache" {
            index += 1;
            let _ = npm_trust_flag_value(args, index, arg)?;
        } else if npm_trust_ignored_equals_flag(arg)
            || matches!(
                arg.as_str(),
                "--silent" | "-s" | "--no-color" | "--color=false"
            )
        {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg(command, arg));
        } else {
            parsed.positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(parsed)
}

fn parse_npm_trust_list_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let parsed = parse_npm_trust_common_args("npm trust list", args)?;
    if parsed.positionals.len() > 1 {
        return Err(unsupported_compat_arg(
            "npm trust list",
            &parsed.positionals[1],
        ));
    }
    Ok(NpmCompatAction::Trust {
        action: NpmTrustAction::List {
            package: parsed.positionals.into_iter().next(),
            json: parsed.json,
            npm_registry: parsed.npm_registry,
            userconfig: parsed.userconfig,
        },
    })
}

fn parse_npm_trust_revoke_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let parsed = parse_npm_trust_common_args("npm trust revoke", args)?;
    if parsed.positionals.len() > 1 {
        return Err(unsupported_compat_arg(
            "npm trust revoke",
            &parsed.positionals[1],
        ));
    }
    let id = parsed.id.ok_or_else(|| {
        OmcRegistryError::UnsupportedSpec(
            "ID of the trusted relationship to revoke must be specified with the --id option"
                .to_owned(),
        )
    })?;
    Ok(NpmCompatAction::Trust {
        action: NpmTrustAction::Revoke {
            package: parsed.positionals.into_iter().next(),
            id,
            dry_run: parsed.dry_run,
            json: parsed.json,
            npm_registry: parsed.npm_registry,
            userconfig: parsed.userconfig,
            otp: parsed.otp,
        },
    })
}

fn parse_npm_trust_create_args(
    provider: NpmTrustProvider,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let command = format!("npm trust {}", npm_trust_provider_name(provider));
    let parsed = parse_npm_trust_common_args(&command, args)?;
    if parsed.positionals.len() > 1 {
        return Err(unsupported_compat_arg(&command, &parsed.positionals[1]));
    }
    let config = match provider {
        NpmTrustProvider::GitHub => npm_trust_github_config(&parsed)?,
        NpmTrustProvider::GitLab => npm_trust_gitlab_config(&parsed)?,
        NpmTrustProvider::CircleCi => npm_trust_circleci_config(&parsed)?,
    };
    Ok(NpmCompatAction::Trust {
        action: NpmTrustAction::Create {
            provider,
            package: parsed.positionals.into_iter().next(),
            config,
            dry_run: parsed.dry_run,
            json: parsed.json,
            yes: parsed.yes,
            npm_registry: parsed.npm_registry,
            userconfig: parsed.userconfig,
            otp: parsed.otp,
        },
    })
}

fn npm_trust_github_config(args: &NpmTrustArgs) -> Result<serde_json::Value, OmcRegistryError> {
    let file = npm_trust_workflow_file(args.file.as_deref(), "GitHub Actions workflow")?;
    if let Some(repository) = args.repository.as_deref() {
        let parts = repository.split('/').collect::<Vec<_>>();
        if parts.len() != 2 || parts.iter().any(|part| part.is_empty()) {
            return Err(OmcRegistryError::UnsupportedSpec(
                "GitHub repository must be specified in the format owner/repository".to_owned(),
            ));
        }
    }
    let mut claims = serde_json::Map::new();
    if let Some(repository) = args.repository.as_deref() {
        claims.insert("repository".to_owned(), serde_json::json!(repository));
    }
    claims.insert(
        "workflow_ref".to_owned(),
        serde_json::json!({
            "file": file,
        }),
    );
    if let Some(environment) = &args.environment {
        claims.insert("environment".to_owned(), serde_json::json!(environment));
    }
    Ok(serde_json::json!({
        "type": "github",
        "claims": claims,
    }))
}

fn npm_trust_gitlab_config(args: &NpmTrustArgs) -> Result<serde_json::Value, OmcRegistryError> {
    let file = npm_trust_workflow_file(args.file.as_deref(), "GitLab CI/CD pipeline file")?;
    let project = args.project.as_deref().or(args.repository.as_deref());
    if let Some(project) = project {
        let parts = project.split('/').collect::<Vec<_>>();
        if parts.len() < 2 || parts.iter().any(|part| part.is_empty()) {
            return Err(OmcRegistryError::UnsupportedSpec(
                "GitLab project must be specified in the format group/project or group/subgroup/project"
                    .to_owned(),
            ));
        }
    }
    let mut claims = serde_json::Map::new();
    if let Some(project) = project {
        claims.insert("project_path".to_owned(), serde_json::json!(project));
    }
    claims.insert(
        "ci_config_ref_uri".to_owned(),
        serde_json::json!({
            "file": file,
        }),
    );
    if let Some(environment) = &args.environment {
        claims.insert("environment".to_owned(), serde_json::json!(environment));
    }
    Ok(serde_json::json!({
        "type": "gitlab",
        "claims": claims,
    }))
}

fn npm_trust_circleci_config(args: &NpmTrustArgs) -> Result<serde_json::Value, OmcRegistryError> {
    let org_id = npm_trust_required_uuid(args.org_id.as_deref(), "org-id")?;
    let project_id = npm_trust_required_uuid(args.project_id.as_deref(), "project-id")?;
    let pipeline_definition_id = npm_trust_required_uuid(
        args.pipeline_definition_id.as_deref(),
        "pipeline-definition-id",
    )?;
    let vcs_origin = args
        .vcs_origin
        .as_deref()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec("vcs-origin is required".to_owned()))?;
    if vcs_origin.contains("://") || vcs_origin.split('/').count() < 3 {
        return Err(OmcRegistryError::UnsupportedSpec(
            "vcs-origin must be in format 'provider/owner/repo' without a scheme".to_owned(),
        ));
    }
    for context_id in &args.context_ids {
        npm_trust_validate_uuid(context_id, "context-id")?;
    }
    let mut claims = serde_json::json!({
        "oidc.circleci.com/org-id": org_id,
        "oidc.circleci.com/project-id": project_id,
        "oidc.circleci.com/pipeline-definition-id": pipeline_definition_id,
        "oidc.circleci.com/vcs-origin": vcs_origin,
    });
    if !args.context_ids.is_empty() {
        claims["oidc.circleci.com/context-ids"] = serde_json::json!(args.context_ids);
    }
    Ok(serde_json::json!({
        "type": "circleci",
        "claims": claims,
    }))
}

fn npm_trust_workflow_file(value: Option<&str>, label: &str) -> Result<String, OmcRegistryError> {
    let file = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!("{label} must be specified with --file"))
        })?;
    if !(file.ends_with(".yml") || file.ends_with(".yaml")) {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{label} must end in .yml or .yaml"
        )));
    }
    let path = Path::new(file);
    if path.file_name().and_then(|name| name.to_str()) != Some(file) {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "{label} must be just a file not a path"
        )));
    }
    Ok(file.to_owned())
}

fn npm_trust_required_uuid(value: Option<&str>, field: &str) -> Result<String, OmcRegistryError> {
    let value =
        value.ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{field} is required")))?;
    npm_trust_validate_uuid(value, field)?;
    Ok(value.to_owned())
}

fn npm_trust_validate_uuid(value: &str, field: &str) -> Result<(), OmcRegistryError> {
    let parts = value.split('-').collect::<Vec<_>>();
    let valid = parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .all(|(len, part)| part.len() == *len && part.chars().all(|ch| ch.is_ascii_hexdigit()));
    if valid {
        Ok(())
    } else {
        Err(OmcRegistryError::UnsupportedSpec(format!(
            "{field} must be a valid UUID"
        )))
    }
}

fn npm_trust_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

fn npm_trust_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache=", "--color="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn npm_token_presubcommand_value_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--registry"
            | "--userconfig"
            | "--loglevel"
            | "--cache"
            | "--otp"
            | "--name"
            | "--token-description"
            | "--expires"
            | "--packages"
            | "--scopes"
            | "--orgs"
            | "--packages-and-scopes-permission"
            | "--orgs-permission"
            | "--cidr"
            | "--password"
    )
}

fn parse_npm_token_create_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut options = NpmTokenCreateOptions::default();
    let mut json = false;
    let mut parseable = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--parseable" | "-p" | "--parseable=true") {
            parseable = true;
        } else if matches!(arg.as_str(), "--parseable=false" | "--no-parseable") {
            parseable = false;
        } else if matches!(arg.as_str(), "--read-only" | "--read-only=true") {
            options.read_only = true;
        } else if matches!(arg.as_str(), "--no-read-only" | "--read-only=false") {
            options.read_only = false;
        } else if matches!(arg.as_str(), "--packages-all" | "--packages-all=true") {
            options.packages_all = true;
        } else if matches!(arg.as_str(), "--no-packages-all" | "--packages-all=false") {
            options.packages_all = false;
        } else if matches!(arg.as_str(), "--bypass-2fa" | "--bypass-2fa=true") {
            options.bypass_2fa = true;
        } else if matches!(arg.as_str(), "--no-bypass-2fa" | "--bypass-2fa=false") {
            options.bypass_2fa = false;
        } else if arg == "--name" {
            index += 1;
            options.name = Some(npm_token_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--name=") {
            options.name = Some(value.to_owned());
        } else if arg == "--token-description" {
            index += 1;
            options.description = Some(npm_token_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--token-description=") {
            options.description = Some(value.to_owned());
        } else if arg == "--expires" {
            index += 1;
            options.expires = Some(parse_npm_token_expires(&npm_token_flag_value(
                args, index, arg,
            )?)?);
        } else if let Some(value) = arg.strip_prefix("--expires=") {
            options.expires = Some(parse_npm_token_expires(value)?);
        } else if arg == "--packages" {
            index += 1;
            options
                .packages
                .extend(npm_token_list_values(&npm_token_flag_value(
                    args, index, arg,
                )?));
        } else if let Some(value) = arg.strip_prefix("--packages=") {
            options.packages.extend(npm_token_list_values(value));
        } else if arg == "--scopes" {
            index += 1;
            options
                .scopes
                .extend(npm_token_list_values(&npm_token_flag_value(
                    args, index, arg,
                )?));
        } else if let Some(value) = arg.strip_prefix("--scopes=") {
            options.scopes.extend(npm_token_list_values(value));
        } else if arg == "--orgs" {
            index += 1;
            options
                .orgs
                .extend(npm_token_list_values(&npm_token_flag_value(
                    args, index, arg,
                )?));
        } else if let Some(value) = arg.strip_prefix("--orgs=") {
            options.orgs.extend(npm_token_list_values(value));
        } else if arg == "--packages-and-scopes-permission" {
            index += 1;
            options.packages_and_scopes_permission = Some(parse_npm_token_permission(
                "--packages-and-scopes-permission",
                &npm_token_flag_value(args, index, arg)?,
            )?);
        } else if let Some(value) = arg.strip_prefix("--packages-and-scopes-permission=") {
            options.packages_and_scopes_permission = Some(parse_npm_token_permission(
                "--packages-and-scopes-permission",
                value,
            )?);
        } else if arg == "--orgs-permission" {
            index += 1;
            options.orgs_permission = Some(parse_npm_token_permission(
                "--orgs-permission",
                &npm_token_flag_value(args, index, arg)?,
            )?);
        } else if let Some(value) = arg.strip_prefix("--orgs-permission=") {
            options.orgs_permission = Some(parse_npm_token_permission("--orgs-permission", value)?);
        } else if arg == "--cidr" {
            index += 1;
            options
                .cidr
                .extend(parse_npm_token_cidr_list(&npm_token_flag_value(
                    args, index, arg,
                )?)?);
        } else if let Some(value) = arg.strip_prefix("--cidr=") {
            options.cidr.extend(parse_npm_token_cidr_list(value)?);
        } else if arg == "--password" {
            index += 1;
            options.password = Some(npm_token_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--password=") {
            options.password = Some(value.to_owned());
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_token_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_token_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_token_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if arg == "--loglevel" || arg == "--cache" {
            index += 1;
            let _ = npm_token_flag_value(args, index, arg)?;
        } else if matches!(
            arg.as_str(),
            "--silent" | "-s" | "--no-color" | "--color=false"
        ) || npm_token_create_ignored_equals_flag(arg)
        {
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm token create", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    if !positionals.is_empty() {
        return Err(unsupported_compat_arg("npm token create", &positionals[0]));
    }

    Ok(NpmCompatAction::Token {
        action: NpmTokenAction::Create {
            options: Box::new(options),
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        },
    })
}

fn npm_token_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

fn parse_npm_token_expires(value: &str) -> Result<u64, OmcRegistryError> {
    value.parse::<u64>().map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!(
            "npm token create --expires needs a number of days, got `{value}`"
        ))
    })
}

fn parse_npm_token_permission(flag: &str, value: &str) -> Result<String, OmcRegistryError> {
    match value {
        "read-only" | "read-write" | "no-access" => Ok(value.to_owned()),
        _ => Err(OmcRegistryError::UnsupportedSpec(format!(
            "{flag} must be read-only, read-write, or no-access, got `{value}`"
        ))),
    }
}

fn npm_token_list_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_npm_token_cidr_list(value: &str) -> Result<Vec<String>, OmcRegistryError> {
    let cidrs = npm_token_list_values(value);
    for cidr in &cidrs {
        validate_npm_token_cidr(cidr)?;
    }
    Ok(cidrs)
}

fn validate_npm_token_cidr(value: &str) -> Result<(), OmcRegistryError> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "CIDR whitelist contains invalid CIDR entry: {value}"
        )));
    };
    if ip.parse::<Ipv4Addr>().is_err() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "CIDR whitelist contains invalid CIDR entry: {value}"
        )));
    }
    let prefix = prefix.parse::<u8>().map_err(|_| {
        OmcRegistryError::UnsupportedSpec(format!(
            "CIDR whitelist contains invalid CIDR entry: {value}"
        ))
    })?;
    if prefix > 32 {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "CIDR whitelist contains invalid CIDR entry: {value}"
        )));
    }
    Ok(())
}

fn npm_token_create_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache=", "--color="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

fn parse_npm_token_revoke_args(
    command: &str,
    args: &[String],
) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut json = false;
    let mut otp = None;
    let mut userconfig = None;
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" {
            json = true;
        } else if arg == "--otp" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{arg} needs a value")))?;
            otp = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
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
        } else if npm_registry_identity_equals_value_flag(arg)
            || matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p")
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
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm token {command} needs a token or token id"
        )));
    }
    if positionals.len() > 1 {
        return Err(unsupported_compat_arg("npm token revoke", &positionals[1]));
    }
    Ok(NpmCompatAction::Token {
        action: NpmTokenAction::Revoke {
            token: positionals.remove(0),
            json,
            npm_registry,
            userconfig,
            otp,
        },
    })
}

pub(crate) fn parse_npm_profile_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut positionals = Vec::new();
    let mut json = false;
    let mut parseable = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" || arg == "--no-json" {
            json = false;
        } else if matches!(arg.as_str(), "--parseable" | "-p" | "--parseable=true") {
            parseable = true;
        } else if matches!(arg.as_str(), "--parseable=false" | "--no-parseable") {
            parseable = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_profile_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_profile_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_profile_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s")
            || npm_workspace_scope_ignored_flag(arg)
            || npm_profile_ignored_equals_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--cache" | "--workspace" | "-w"
        ) {
            index += 1;
            let _ = npm_profile_flag_value(args, index, arg)?;
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm profile", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    let Some(command) = positionals.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm profile needs a command".to_owned(),
        ));
    };

    match command {
        "get" => Ok(NpmCompatAction::Profile {
            action: NpmProfileAction::Get {
                keys: positionals[1..].to_vec(),
                json,
                parseable,
                npm_registry,
                userconfig,
            },
        }),
        "set" => parse_npm_profile_set_args(
            &positionals[1..],
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        ),
        "enable-2fa" | "enable-tfa" | "enable2fa" | "enabletfa" | "disable-2fa" | "disable-tfa"
        | "disable2fa" | "disabletfa" => Err(OmcRegistryError::UnsupportedSpec(format!(
            "npm profile {command} is interactive and is not implemented by OMC"
        ))),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm profile command `{other}`"
        ))),
    }
}

fn parse_npm_profile_set_args(
    args: &[String],
    json: bool,
    parseable: bool,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
    otp: Option<String>,
) -> Result<NpmCompatAction, OmcRegistryError> {
    let Some(property) = args.first().map(|value| value.to_lowercase()) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm profile set <property> <value>".to_owned(),
        ));
    };
    if property == "password" {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm profile set password is interactive and is not implemented by OMC".to_owned(),
        ));
    }
    if !NPM_PROFILE_WRITABLE_KEYS.contains(&property.as_str()) {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "\"{property}\" is not a property we can set. Valid properties are: {}",
            NPM_PROFILE_WRITABLE_KEYS.join(", ")
        )));
    }
    let value = args
        .get(1..)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec("npm profile set <property> <value>".to_owned())
        })?;
    Ok(NpmCompatAction::Profile {
        action: NpmProfileAction::Set {
            property,
            value: value.join(" "),
            json,
            parseable,
            npm_registry,
            userconfig,
            otp,
        },
    })
}

fn npm_profile_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--loglevel=",
        "--cache=",
        "--parseable=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_profile_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

pub(crate) fn parse_npm_owner_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut positionals = Vec::new();
    let mut json = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_owner_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_owner_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_owner_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p")
            || npm_workspace_scope_ignored_flag(arg)
            || npm_owner_ignored_equals_flag(arg)
        {
        } else if matches!(arg.as_str(), "--loglevel" | "--workspace" | "-w") {
            index += 1;
            let _ = npm_owner_flag_value(args, index, arg)?;
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm owner", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    match positionals.first().map(String::as_str) {
        Some("ls" | "list") => {
            positionals.remove(0);
            if positionals.len() > 1 {
                return Err(unsupported_compat_arg("npm owner ls", &positionals[1]));
            }
            Ok(NpmCompatAction::Owner {
                action: NpmOwnerAction::List {
                    spec: positionals.pop(),
                    json,
                    npm_registry,
                    userconfig,
                },
            })
        }
        Some("add") => {
            positionals.remove(0);
            let Some(user) = positionals.first().cloned() else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm owner add needs a username".to_owned(),
                ));
            };
            let spec = positionals.get(1).cloned();
            if positionals.len() > 2 {
                return Err(unsupported_compat_arg("npm owner add", &positionals[2]));
            }
            Ok(NpmCompatAction::Owner {
                action: NpmOwnerAction::Add {
                    user,
                    spec,
                    json,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        Some("rm" | "remove" | "delete" | "del") => {
            positionals.remove(0);
            let Some(user) = positionals.first().cloned() else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm owner rm needs a username".to_owned(),
                ));
            };
            let spec = positionals.get(1).cloned();
            if positionals.len() > 2 {
                return Err(unsupported_compat_arg("npm owner rm", &positionals[2]));
            }
            Ok(NpmCompatAction::Owner {
                action: NpmOwnerAction::Remove {
                    user,
                    spec,
                    json,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        Some(other) => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm owner command `{other}`"
        ))),
        None => Ok(NpmCompatAction::Owner {
            action: NpmOwnerAction::List {
                spec: None,
                json,
                npm_registry,
                userconfig,
            },
        }),
    }
}

fn npm_owner_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--loglevel=",
        "--parseable=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_owner_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

pub(crate) fn parse_npm_access_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut positionals = Vec::new();
    let mut json = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_access_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_access_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_access_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s" | "--parseable" | "-p")
            || npm_workspace_scope_ignored_flag(arg)
            || npm_access_ignored_equals_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--cache" | "--workspace" | "-w"
        ) {
            index += 1;
            let _ = npm_access_flag_value(args, index, arg)?;
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm access", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    let Some(command) = positionals.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm access needs a command".to_owned(),
        ));
    };

    match command {
        "list" | "ls" => {
            parse_npm_access_list_args(&positionals[1..], json, npm_registry, userconfig)
        }
        "ls-packages" => {
            if positionals.len() > 3 {
                return Err(unsupported_compat_arg(
                    "npm access ls-packages",
                    &positionals[3],
                ));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::ListPackages {
                    owner: positionals.get(1).cloned(),
                    package: positionals.get(2).cloned(),
                    json,
                    npm_registry,
                    userconfig,
                },
            })
        }
        "ls-collaborators" => {
            if positionals.len() > 3 {
                return Err(unsupported_compat_arg(
                    "npm access ls-collaborators",
                    &positionals[3],
                ));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::ListCollaborators {
                    package: positionals.get(1).cloned(),
                    user: positionals.get(2).cloned(),
                    json,
                    npm_registry,
                    userconfig,
                },
            })
        }
        "get" => {
            if positionals.get(1).map(String::as_str) != Some("status") {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "get {} is not a valid access command",
                    positionals.get(1).map(String::as_str).unwrap_or("")
                )));
            }
            if positionals.len() > 3 {
                return Err(unsupported_compat_arg(
                    "npm access get status",
                    &positionals[3],
                ));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::GetStatus {
                    package: positionals.get(2).cloned(),
                    json,
                    npm_registry,
                    userconfig,
                },
            })
        }
        "set" => {
            let Some(setting) = positionals.get(1).map(String::as_str) else {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm access set needs a setting".to_owned(),
                ));
            };
            if positionals.len() > 3 {
                return Err(unsupported_compat_arg("npm access set", &positionals[3]));
            }
            parse_npm_access_set_action(
                setting,
                positionals.get(2).cloned(),
                json,
                npm_registry,
                userconfig,
                otp,
            )
        }
        "public" => npm_access_status_action(
            "public",
            positionals.get(1).cloned(),
            &positionals,
            json,
            npm_registry,
            userconfig,
            otp,
        ),
        "restricted" | "private" => npm_access_status_action(
            "private",
            positionals.get(1).cloned(),
            &positionals,
            json,
            npm_registry,
            userconfig,
            otp,
        ),
        "2fa-required" => npm_access_mfa_action(
            "publish",
            positionals.get(1).cloned(),
            &positionals,
            json,
            npm_registry,
            userconfig,
            otp,
        ),
        "2fa-not-required" => npm_access_mfa_action(
            "none",
            positionals.get(1).cloned(),
            &positionals,
            json,
            npm_registry,
            userconfig,
            otp,
        ),
        "grant" => {
            if positionals.len() < 3 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm access grant needs a permission and scope:team".to_owned(),
                ));
            }
            if !matches!(positionals[1].as_str(), "read-only" | "read-write") {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "grant must be either `read-only` or `read-write`".to_owned(),
                ));
            }
            if positionals.len() > 4 {
                return Err(unsupported_compat_arg("npm access grant", &positionals[4]));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::Grant {
                    permission: positionals[1].clone(),
                    scope_team: positionals[2].clone(),
                    package: positionals.get(3).cloned(),
                    json,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "revoke" => {
            if positionals.len() < 2 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm access revoke needs a scope:team".to_owned(),
                ));
            }
            if positionals.len() > 3 {
                return Err(unsupported_compat_arg("npm access revoke", &positionals[3]));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::Revoke {
                    scope_team: positionals[1].clone(),
                    package: positionals.get(2).cloned(),
                    json,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "edit" => Err(OmcRegistryError::UnsupportedSpec(
            "npm access edit is not implemented".to_owned(),
        )),
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "{other} is not a valid access command"
        ))),
    }
}

fn parse_npm_access_list_args(
    args: &[String],
    json: bool,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
) -> Result<NpmCompatAction, OmcRegistryError> {
    match args.first().map(String::as_str) {
        Some("packages") => {
            if args.len() > 3 {
                return Err(unsupported_compat_arg("npm access list packages", &args[3]));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::ListPackages {
                    owner: args.get(1).cloned(),
                    package: args.get(2).cloned(),
                    json,
                    npm_registry,
                    userconfig,
                },
            })
        }
        Some("collaborators") => {
            if args.len() > 3 {
                return Err(unsupported_compat_arg(
                    "npm access list collaborators",
                    &args[3],
                ));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::ListCollaborators {
                    package: args.get(1).cloned(),
                    user: args.get(2).cloned(),
                    json,
                    npm_registry,
                    userconfig,
                },
            })
        }
        Some(other) => Err(OmcRegistryError::UnsupportedSpec(format!(
            "list {other} is not a valid access command"
        ))),
        None => Err(OmcRegistryError::UnsupportedSpec(
            "npm access list needs packages or collaborators".to_owned(),
        )),
    }
}

fn parse_npm_access_set_action(
    setting: &str,
    package: Option<String>,
    json: bool,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
    otp: Option<String>,
) -> Result<NpmCompatAction, OmcRegistryError> {
    let Some((key, value)) = setting.split_once('=') else {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "set {setting} is not a valid access command"
        )));
    };
    match key {
        "status" => {
            let status = match value {
                "public" => "public",
                "private" | "restricted" => "private",
                _ => {
                    return Err(OmcRegistryError::UnsupportedSpec(format!(
                        "set {setting} is not a valid access command"
                    )))
                }
            };
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::SetStatus {
                    package,
                    status: status.to_owned(),
                    json,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "mfa" | "2fa" => {
            if !matches!(value, "none" | "publish" | "automation") {
                return Err(OmcRegistryError::UnsupportedSpec(format!(
                    "set {setting} is not a valid access command"
                )));
            }
            Ok(NpmCompatAction::Access {
                action: NpmAccessAction::SetMfa {
                    package,
                    level: value.to_owned(),
                    json,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        _ => Err(OmcRegistryError::UnsupportedSpec(format!(
            "set {setting} is not a valid access command"
        ))),
    }
}

fn npm_access_status_action(
    status: &str,
    package: Option<String>,
    positionals: &[String],
    json: bool,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
    otp: Option<String>,
) -> Result<NpmCompatAction, OmcRegistryError> {
    if positionals.len() > 2 {
        return Err(unsupported_compat_arg("npm access", &positionals[2]));
    }
    Ok(NpmCompatAction::Access {
        action: NpmAccessAction::SetStatus {
            package,
            status: status.to_owned(),
            json,
            npm_registry,
            userconfig,
            otp,
        },
    })
}

fn npm_access_mfa_action(
    level: &str,
    package: Option<String>,
    positionals: &[String],
    json: bool,
    npm_registry: Option<String>,
    userconfig: Option<PathBuf>,
    otp: Option<String>,
) -> Result<NpmCompatAction, OmcRegistryError> {
    if positionals.len() > 2 {
        return Err(unsupported_compat_arg("npm access", &positionals[2]));
    }
    Ok(NpmCompatAction::Access {
        action: NpmAccessAction::SetMfa {
            package,
            level: level.to_owned(),
            json,
            npm_registry,
            userconfig,
            otp,
        },
    })
}

fn npm_access_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--loglevel=",
        "--cache=",
        "--parseable=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_access_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

pub(crate) fn parse_npm_org_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut positionals = Vec::new();
    let mut json = false;
    let mut parseable = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--parseable" | "-p" | "--parseable=true") {
            parseable = true;
        } else if matches!(arg.as_str(), "--parseable=false" | "--no-parseable") {
            parseable = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_org_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_org_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_org_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s")
            || npm_workspace_scope_ignored_flag(arg)
            || npm_org_ignored_equals_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--cache" | "--workspace" | "-w"
        ) {
            index += 1;
            let _ = npm_org_flag_value(args, index, arg)?;
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm org", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    let Some(command) = positionals.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm org needs a command".to_owned(),
        ));
    };
    match command {
        "set" | "add" => {
            if positionals.len() < 3 || positionals.len() > 4 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm org set needs an org, username, and optional role".to_owned(),
                ));
            }
            let role = positionals.get(3).cloned();
            if let Some(role) = role.as_deref() {
                npm_org_role_arg(role)?;
            }
            Ok(NpmCompatAction::Org {
                action: NpmOrgAction::Set {
                    org: positionals[1].clone(),
                    user: positionals[2].clone(),
                    role,
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "rm" | "remove" | "delete" | "del" => {
            if positionals.len() != 3 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm org rm needs an org and username".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Org {
                action: NpmOrgAction::Remove {
                    org: positionals[1].clone(),
                    user: positionals[2].clone(),
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "ls" | "list" => {
            if positionals.len() < 2 || positionals.len() > 3 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm org ls needs an org and optional username".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Org {
                action: NpmOrgAction::List {
                    org: positionals[1].clone(),
                    user: positionals.get(2).cloned(),
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                },
            })
        }
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm org command `{other}`"
        ))),
    }
}

fn npm_org_role_arg(value: &str) -> Result<(), OmcRegistryError> {
    if matches!(value, "owner" | "admin" | "developer") {
        Ok(())
    } else {
        Err(OmcRegistryError::UnsupportedSpec(
            "npm org role must be owner, admin, or developer".to_owned(),
        ))
    }
}

fn npm_org_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--loglevel=",
        "--cache=",
        "--parseable=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_org_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}

pub(crate) fn parse_npm_team_args(args: &[String]) -> Result<NpmCompatAction, OmcRegistryError> {
    let mut positionals = Vec::new();
    let mut json = false;
    let mut parseable = false;
    let mut npm_registry = None;
    let mut userconfig = None;
    let mut otp = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--json" || arg == "--json=true" {
            json = true;
        } else if arg == "--json=false" {
            json = false;
        } else if matches!(arg.as_str(), "--parseable" | "-p" | "--parseable=true") {
            parseable = true;
        } else if matches!(arg.as_str(), "--parseable=false" | "--no-parseable") {
            parseable = false;
        } else if arg == "--registry" {
            index += 1;
            npm_registry = Some(npm_team_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--registry=") {
            npm_registry = Some(value.to_owned());
        } else if arg == "--userconfig" {
            index += 1;
            userconfig = Some(PathBuf::from(npm_team_flag_value(args, index, arg)?));
        } else if let Some(value) = arg.strip_prefix("--userconfig=") {
            userconfig = Some(PathBuf::from(value));
        } else if arg == "--otp" {
            index += 1;
            otp = Some(npm_team_flag_value(args, index, arg)?);
        } else if let Some(value) = arg.strip_prefix("--otp=") {
            otp = Some(value.to_owned());
        } else if matches!(arg.as_str(), "--silent" | "-s")
            || npm_workspace_scope_ignored_flag(arg)
            || npm_team_ignored_equals_flag(arg)
        {
        } else if matches!(
            arg.as_str(),
            "--loglevel" | "--cache" | "--workspace" | "-w"
        ) {
            index += 1;
            let _ = npm_team_flag_value(args, index, arg)?;
        } else if arg.starts_with('-') {
            return Err(unsupported_compat_arg("npm team", arg));
        } else {
            positionals.push(arg.clone());
        }
        index += 1;
    }

    let Some(command) = positionals.first().map(String::as_str) else {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm team needs a command".to_owned(),
        ));
    };
    match command {
        "create" => {
            if positionals.len() != 2 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm team create needs exactly one scope:team".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Team {
                action: NpmTeamAction::Create {
                    scope_team: positionals[1].clone(),
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "destroy" | "delete" | "del" => {
            if positionals.len() != 2 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm team destroy needs exactly one scope:team".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Team {
                action: NpmTeamAction::Destroy {
                    scope_team: positionals[1].clone(),
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "add" => {
            if positionals.len() != 3 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm team add needs a scope:team and username".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Team {
                action: NpmTeamAction::Add {
                    scope_team: positionals[1].clone(),
                    user: positionals[2].clone(),
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "rm" | "remove" => {
            if positionals.len() != 3 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm team rm needs a scope:team and username".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Team {
                action: NpmTeamAction::Remove {
                    scope_team: positionals[1].clone(),
                    user: positionals[2].clone(),
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                    otp,
                },
            })
        }
        "ls" | "list" => {
            if positionals.len() != 2 {
                return Err(OmcRegistryError::UnsupportedSpec(
                    "npm team ls needs a scope or scope:team".to_owned(),
                ));
            }
            Ok(NpmCompatAction::Team {
                action: NpmTeamAction::List {
                    scope_or_team: positionals[1].clone(),
                    json,
                    parseable,
                    npm_registry,
                    userconfig,
                },
            })
        }
        other => Err(OmcRegistryError::UnsupportedSpec(format!(
            "unsupported npm team command `{other}`"
        ))),
    }
}

fn npm_team_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--loglevel=",
        "--cache=",
        "--parseable=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

fn npm_team_flag_value(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<String, OmcRegistryError> {
    args.get(index)
        .cloned()
        .ok_or_else(|| OmcRegistryError::UnsupportedSpec(format!("{flag} needs a value")))
}
