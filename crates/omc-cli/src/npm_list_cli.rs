//! npm list/ls, sbom, explain/why, and help/dependency-tree commands.
//!
//! Extracted from `lib.rs`: the `npm list`/`ls`, `npm sbom` (CycloneDX + SPDX),
//! `npm explain`/`why` dependency-graph, and `npm help`/`help-search` subcommands
//! along with their private rendering helpers and flag parsers.

use crate::*;

use crate::args::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) fn npm_help_search_text(
    query: &[String],
    long: bool,
) -> Result<String, OmcRegistryError> {
    let terms = query
        .iter()
        .map(|term| term.trim())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "npm help-search needs a search term".to_owned(),
        ));
    }

    let mut topics = NPM_COMPLETION_COMMANDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    topics.extend(["get", "help-search"]);

    let mut hits = Vec::new();
    for topic in topics {
        let help = npm_help_text(Some(topic));
        if help.contains("No focused OMC help is available") {
            continue;
        }
        let topic_lower = topic.to_ascii_lowercase();
        let help_lower = help.to_ascii_lowercase();
        if !terms
            .iter()
            .all(|term| topic_lower.contains(term) || help_lower.contains(term))
        {
            continue;
        }
        let score = terms
            .iter()
            .map(|term| {
                count_substrings(&topic_lower, term) * 5 + count_substrings(&help_lower, term)
            })
            .sum::<usize>();
        let excerpts = if long {
            npm_help_search_excerpts(&help, &terms)
        } else {
            Vec::new()
        };
        hits.push((topic.to_owned(), score, excerpts));
    }
    hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let query_display = query.join(" ");
    let mut output = String::new();
    if hits.is_empty() {
        output.push_str(&format!("No matches for \"{query_display}\"\n"));
        return Ok(output);
    }

    output.push_str(&format!("Top hits for \"{query_display}\"\n"));
    output.push_str("------------------------------------------------------------\n");
    for (topic, _score, excerpts) in hits.into_iter().take(10) {
        output.push_str(&format!("npm help {topic}\n"));
        for excerpt in excerpts {
            output.push_str("  ");
            output.push_str(&excerpt);
            output.push('\n');
        }
    }
    if !long {
        output.push_str("(run with -l or --long to see matching help text)\n");
    }
    Ok(output)
}

fn npm_help_search_excerpts(help: &str, terms: &[String]) -> Vec<String> {
    help.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            terms.iter().any(|term| lower.contains(term))
        })
        .take(3)
        .map(str::to_owned)
        .collect()
}

pub(crate) fn npm_help_text(topic: Option<&str>) -> String {
    match topic.and_then(npm_help_topic) {
        None => npm_general_help_text(),
        Some("help-search") => npm_command_help(
            "npm help-search <term...>",
            &[
                "Search OMC's npm compatibility help topics.",
                "Supports -l and --long for matching help excerpts.",
            ],
        ),
        Some("install") => npm_command_help(
            "npm install [<package-spec>...]",
            &[
                "Resolve, verify, lock, and install npm packages with OMC.",
                "Aliases: i, add, update, up, upgrade, udpate.",
                "Common flags: --save, --no-save, --save-dev, --save-optional, --save-peer, --only=prod|dev, --also=dev, --no-optional, --omit=dev|optional|peer, --include=dev|optional|peer, --workspace, --workspaces/--ws, --include-workspace-root, --package-lock-only, --prefer-offline, --prefer-online, --prefer-dedupe, --dry-run, --json, --tag, --before, --min-release-age, --engine-strict, --offline, --install-links, --registry, --allow, --allow-all-host.",
                "Direct local inputs are supported for .tgz archives and local package directories.",
                "Workspace installs save dependencies into selected workspace package.json files and install the root OMC graph.",
            ],
        ),
        Some("link") => npm_command_help(
            "npm link [<package-name>|<local-dir>|<tarball>...]",
            &[
                "Register or install local npm package links through OMC's link store.",
                "`npm link` registers the current package; `npm link ../pkg` registers and links a local directory; `npm link <name>` links a previously registered package; `npm link ./pkg.tgz` installs a local tarball through OMC's archive verifier.",
                "Links are not saved by default. Use --save, --save-dev, --save-optional, or --save-peer to record a local path or tarball dependency.",
                "Supports --dry-run, --offline, --package-lock-only, omit/include flags for dev/optional/peer dependencies, --registry for dependency refreshes, --allow, and --allow-all-host.",
            ],
        ),
        Some("ci") => npm_command_help(
            "npm ci",
            &[
                "Install the exact OMC lockfile state.",
                "Common flags: --dry-run, --json, --only=prod|dev, --also=dev, --no-optional, --prefer-offline, --prefer-online, --omit=dev|optional|peer, --include=dev|optional|peer, --allow, --allow-all-host.",
            ],
        ),
        Some("install-test") => npm_command_help(
            "npm install-test [<package-spec>...] [-- <test-args>...]",
            &[
                "Run OMC npm install, then run the root package's test script.",
                "Alias: it.",
            ],
        ),
        Some("install-ci-test") => npm_command_help(
            "npm install-ci-test [-- <test-args>...]",
            &[
                "Run OMC npm ci, then run the root package's test script.",
                "Supports --dry-run for the ci step.",
                "Alias: cit.",
            ],
        ),
        Some("run") => npm_command_help(
            "npm run [<script>] [-- <args>...]",
            &[
                "Run package.json scripts with OMC npm/Python bins and imports on PATH.",
                "Without a script, lists scripts in text or JSON mode.",
                "Common flags: --if-present, --workspace, --workspaces/--ws, --include-workspace-root, --json, --silent.",
                "Aliases: run-script. Also supports npm test/start/stop/restart.",
            ],
        ),
        Some("exec") => npm_command_help(
            "npm exec <command> [-- <args>...]",
            &[
                "Run a project-local executable with OMC runtime paths.",
                "--package installs verified packages into a temporary OMC project before running the command; --call/-c runs a shell command with the same OMC runtime paths.",
                "Aliases: x, npx. Common flags: --yes, --no-install, --package, --call, --workspace, --workspaces/--ws, --include-workspace-root, --cache, --registry, --allow, --allow-all-host.",
            ],
        ),
        Some("completion") => npm_command_help(
            "npm completion",
            &[
                "Print an OMC npm shell-completion script.",
                "The generated script asks `npm completion -- ...` for command, script, and locked package suggestions.",
            ],
        ),
        Some("explore") => npm_command_help(
            "npm explore <package> [-- <command> [args...]]",
            &[
                "Run a command from an installed package directory with OMC npm/Python bins and imports on PATH.",
                "Without a command, opens the configured shell in the package directory.",
                "Supports --shell for the interactive shell path.",
            ],
        ),
        Some("edit") => npm_command_help(
            "npm edit <package>[/<subpath>]",
            &[
                "Open an installed package directory or safe subpath in an editor.",
                "Supports --editor, VISUAL, and EDITOR. OMC does not run package lifecycle scripts after editing.",
            ],
        ),
        Some("remove") => npm_command_help(
            "npm remove <package-spec>...",
            &[
                "Remove OMC-managed npm dependencies and reinstall the remaining graph.",
                "Aliases: uninstall, unlink, rm, r, un.",
            ],
        ),
        Some("list") => npm_command_help(
            "npm list [<package-spec>...]",
            &[
                "List locked npm packages.",
                "Aliases: ls, ll, la. Common flags: --json, --depth, --omit, --include.",
            ],
        ),
        Some("query") => npm_command_help(
            "npm query <selector>",
            &[
                "Return dependency objects from omc.lock and installed package metadata as JSON.",
                "Supports common selectors: *, :root > *, #name, [name=...], [version=...], .prod, .dev, .optional, .peer, .workspace, :empty, :has(*), :not(...), and :attr(scripts, [name]).",
                "Supports --workspace, --workspaces, --include-workspace-root, --package-lock-only, --expect-results, and --expect-result-count.",
            ],
        ),
        Some("explain") => npm_command_help(
            "npm explain <package-spec>...",
            &[
                "Explain why locked npm packages are present.",
                "Alias: why. Supports --json.",
            ],
        ),
        Some("audit") => npm_command_help(
            "npm audit",
            &["Print OMC verifier and capability findings. Supports --json."],
        ),
        Some("doctor") => npm_command_help(
            "npm doctor [connection] [registry] [versions] [environment] [permissions] [cache]",
            &[
                "Print OMC npm compatibility health checks for the current project.",
                "OMC doctor is offline by design and does not probe the registry network.",
                "Supports --registry.",
            ],
        ),
        Some("outdated") => npm_command_help(
            "npm outdated",
            &["Compare locked npm packages to registry versions. Supports --json and --parseable."],
        ),
        Some("fund") => npm_command_help(
            "npm fund [<package-spec>]",
            &[
                "Show funding metadata from root/workspace package.json and installed packages.",
                "Supports --json, --workspace, --workspaces, and --include-workspace-root.",
            ],
        ),
        Some("rebuild") => npm_command_help(
            "npm rebuild [<package-spec>...]",
            &[
                "Refresh OMC's locked install state without running package lifecycle scripts.",
                "Alias: rb.",
            ],
        ),
        Some("maintenance") => npm_command_help(
            "npm <prune|dedupe>",
            &[
                "Refresh OMC's locked install state for common npm maintenance workflows.",
                "Aliases: ddp, find-dupes.",
            ],
        ),
        Some("pack") => npm_command_help(
            "npm pack [<package-spec>|<local-dir>...]",
            &[
                "Create local package tarballs or download registry tarballs.",
                "Common flags: --pack-destination, --json, --dry-run, --registry.",
            ],
        ),
        Some("publish") => npm_command_help(
            "npm publish [<local-dir>|<tarball>]",
            &[
                "Pack and publish a local npm package through the configured registry.",
                "Supports --dry-run, --json, --registry, --userconfig, --tag, --access, --otp, --provenance-file, and workspace selectors.",
                "Automatic --provenance generation needs trusted publishing/OIDC and is currently limited to dry-run reporting.",
                "Remote package specs and git URLs are not implemented yet.",
            ],
        ),
        Some("unpublish") => npm_command_help(
            "npm unpublish [<package-spec>]",
            &[
                "Remove one published npm package version or, with --force, an entire package.",
                "Supports --dry-run, --force, --json, --registry, --userconfig, --otp, and workspace selectors.",
                "Tags and semver ranges are rejected to match npm's single-version unpublish constraint.",
            ],
        ),
        Some("deprecate") => npm_command_help(
            "npm deprecate <package-spec> <message>",
            &[
                "Set deprecation warnings on all published versions matching a package semver range.",
                "Supports --dry-run, --json, --registry, --userconfig, and --otp.",
                "Use npm undeprecate <package-spec> to clear matching deprecation warnings.",
            ],
        ),
        Some("diff") => npm_command_help(
            "npm diff --diff=<spec-a> --diff=<spec-b> [<paths>...]",
            &[
                "Compare two npm package inputs and print unified patches.",
                "Each --diff input can be a registry package spec, local package directory, or npm tarball.",
                "Supports --diff-name-only, --diff-unified, --diff-ignore-all-space, --diff-no-prefix, --diff-src-prefix, --diff-dst-prefix, --diff-text, --registry, and --userconfig.",
            ],
        ),
        Some("search") => npm_command_help(
            "npm search <terms...>",
            &["Search the configured npm registry. Aliases: s, se, find. Supports --json, --parseable, --searchlimit."],
        ),
        Some("star") => npm_command_help(
            "npm <star|unstar|stars> [<package-spec>|<user>]",
            &[
                "Star or unstar npm registry packages, or list packages starred by a user.",
                "star and unstar accept one or more package specs. stars accepts zero or one username.",
                "Supports --json, --registry, --userconfig, and --otp for star mutations.",
            ],
        ),
        Some("ping") => npm_command_help(
            "npm ping",
            &["Check configured npm registry reachability. Supports --json, --registry, and --userconfig."],
        ),
        Some("whoami") => npm_command_help(
            "npm whoami",
            &[
                "Print the authenticated npm username for the configured registry.",
                "Supports --json, --registry, and --userconfig.",
            ],
        ),
        Some("login") => npm_command_help(
            "npm login",
            &[
                "Write an npm registry auth token to OMC's writable .npmrc.",
                "Supports --json, --registry, --scope, --userconfig, and OMC's --token / --auth-token.",
                "Without --token / --auth-token, OMC reads NODE_AUTH_TOKEN or NPM_TOKEN. Interactive web and legacy prompts are not implemented.",
                "Aliases: adduser, add-user.",
            ],
        ),
        Some("logout") => npm_command_help(
            "npm logout",
            &[
                "Remove npm auth credentials for the configured registry from OMC's writable .npmrc.",
                "Supports --json, --registry, --scope, and --userconfig.",
            ],
        ),
        Some("token") => npm_command_help(
            "npm token <list|create|revoke>",
            &[
                "List redacted npm access tokens for the authenticated registry account.",
                "Create granular npm access tokens with explicit package/scope/org permissions.",
                "Revoke tokens by full token or token id.",
                "Create supports --password, --name, --token-description, --expires, --packages, --packages-all, --scopes, --orgs, permission flags, --cidr, --bypass-2fa, --otp, --registry, and --userconfig.",
                "OMC does not prompt interactively; pass --password or set NPM_CONFIG_PASSWORD.",
            ],
        ),
        Some("trust") => npm_command_help(
            "npm trust <github|gitlab|circleci|list|revoke> ...",
            &[
                "Manage npm trusted publishing relationships through the configured registry.",
                "Supports list [package], revoke [package] --id, github/gitlab create flows, and circleci create flows.",
                "Create/revoke support --dry-run, --json, --registry, --userconfig, --otp, and noninteractive --yes for real mutations.",
            ],
        ),
        Some("profile") => npm_command_help(
            "npm profile <get|set> ...",
            &[
                "Read or update noninteractive npm registry profile fields through the configured registry.",
                "Supports get [key...] and set <email|fullname|homepage|freenode|twitter|github> <value>.",
                "Supports --json, --parseable, --registry, --userconfig, and --otp for set.",
                "Interactive password and 2FA profile commands are reported as unsupported.",
            ],
        ),
        Some("owner") => npm_command_help(
            "npm owner <ls|add|rm> ...",
            &[
                "List, add, or remove owners for an npm registry package.",
                "Supports ls [package], add <user> [package], and rm <user> [package].",
                "Supports --json, --registry, --userconfig, and --otp for owner mutations.",
            ],
        ),
        Some("access") => npm_command_help(
            "npm access <list|get|set|grant|revoke> ...",
            &[
                "Manage npm package visibility, publish MFA, and team package access through the configured registry.",
                "Supports list packages, list collaborators, get status, set status=public|private, set mfa=none|publish|automation, grant, and revoke.",
                "Legacy aliases public, restricted, 2fa-required, 2fa-not-required, ls-packages, and ls-collaborators are accepted.",
                "Supports --json, --registry, --userconfig, and --otp for mutations.",
            ],
        ),
        Some("org") => npm_command_help(
            "npm org <set|rm|ls> ...",
            &[
                "Manage npm organization membership through the configured registry.",
                "Supports set <org> <user> [developer|admin|owner], rm <org> <user>, and ls <org> [user].",
                "Alias: add for set. Supports --json, --parseable, --registry, --userconfig, and --otp for mutations.",
            ],
        ),
        Some("team") => npm_command_help(
            "npm team <create|destroy|add|rm|ls> ...",
            &[
                "Manage npm organization teams and team membership through the configured registry.",
                "Supports create <scope:team>, destroy <scope:team>, add <scope:team> <user>, rm <scope:team> <user>, and ls <scope|scope:team>.",
                "Supports --json, --parseable, --registry, --userconfig, and --otp for mutations.",
            ],
        ),
        Some("dist-tag") => npm_command_help(
            "npm dist-tag <add|rm|ls> ...",
            &[
                "Add, remove, or list npm registry distribution tags for a package.",
                "Supports add <package-spec-with-version> [tag], rm <package-spec> <tag>, and ls [package-spec].",
                "Alias: dist-tags. Supports --registry, --userconfig, --tag, and --otp.",
            ],
        ),
        Some("sbom") => npm_command_help(
            "npm sbom --sbom-format <cyclonedx|spdx>",
            &[
                "Generate a Software Bill of Materials from the verified OMC npm lockfile.",
                "Supports --sbom-format, --sbom-type, --package-lock-only, omit flags, and workspace flags.",
            ],
        ),
        Some("shrinkwrap") => npm_command_help(
            "npm shrinkwrap",
            &[
                "Repurpose package-lock.json as npm-shrinkwrap.json, or create a publishable shrinkwrap from package.json and the OMC lockfile.",
                "This command does not support workspaces.",
            ],
        ),
        Some("view") => npm_command_help(
            "npm view <package-spec> [field...]",
            &["Read package metadata from the configured npm registry. Aliases: info, show, v. Supports --json."],
        ),
        Some("metadata-url") => npm_command_help(
            "npm <docs|repo|bugs|home> [package-spec]",
            &[
                "Print package metadata URLs from the npm registry or current package.json.",
                "Supports --json and --registry. OMC prints URLs instead of launching a browser.",
            ],
        ),
        Some("config") => npm_command_help(
            "npm config <get|set|delete|list|edit> ...",
            &[
                "Read, update, and edit npm registry config used by OMC.",
                "Aliases: c, npm get. Supports --json, --registry, --userconfig, --globalconfig, --global, --location, and --editor where relevant.",
            ],
        ),
        Some("cache") => npm_command_help(
            "npm cache <verify|ls|rm|clean>",
            &["Inspect or clear OMC's npm cache. cache clean requires --force."],
        ),
        Some("pkg") => npm_command_help(
            "npm pkg <get|set|delete> ...",
            &["Read and update package.json fields."],
        ),
        Some("version") => npm_command_help(
            "npm version [<newversion>|major|minor|patch|pre...]",
            &["Read or bump package.json version. Supports --json, --preid, --allow-same-version, and --no-git-tag-version."],
        ),
        Some("init") => npm_command_help(
            "npm init [-y] [<initializer>] [-- <args>...]",
            &[
                "Create or update package.json with npm-compatible defaults.",
                "With an initializer, OMC resolves and installs the matching create-* package in an isolated temp project, then runs its bin with the current project as cwd.",
                "Aliases: create, innit. Supports --registry, --allow, and --allow-all-host for initializer package resolution.",
            ],
        ),
        Some("path") => npm_command_help(
            "npm <bin|root|prefix>",
            &["Print OMC project bin, node_modules, or project prefix paths."],
        ),
        Some(_) => npm_command_help(
            "npm help [command]",
            &["No focused OMC help is available for that topic yet."],
        ),
    }
}

fn npm_general_help_text() -> String {
    npm_command_help(
        "npm <command>",
        &[
            "OMC npm compatibility runs supported npm workflows through OMC's verifier, lockfile, cache, and project-local runtime paths.",
            "Supported commands: install, link, install-test, ci, install-ci-test, remove, uninstall, unlink, run, test, start, stop, restart, exec, explore, edit, completion, help-search, list, query, explain, audit, doctor, outdated, fund, prune, dedupe, rebuild, cache, pkg, version, shrinkwrap, pack, publish, unpublish, deprecate, undeprecate, diff, search, star, unstar, stars, ping, whoami, login, adduser, logout, token, trust, profile, owner, access, org, team, dist-tag, sbom, view, docs, repo, bugs, home, config, get, set, init, create, bin, root, prefix.",
            "Use `npm help <command>` for focused OMC compatibility notes.",
        ],
    )
}

fn npm_command_help(usage: &str, lines: &[&str]) -> String {
    let mut output = format!("OMC npm compatibility\n\nUsage: {usage}\n");
    if !lines.is_empty() {
        output.push('\n');
        for line in lines {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn npm_help_topic(topic: &str) -> Option<&'static str> {
    match topic {
        "help" | "--help" | "-h" => None,
        "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt" | "isnta"
        | "isntal" | "isntall" | "add" | "update" | "up" | "upgrade" | "udpate" => Some("install"),
        "link" | "ln" => Some("link"),
        "install-test" | "it" => Some("install-test"),
        "ci" => Some("ci"),
        "install-ci-test" | "cit" => Some("install-ci-test"),
        "run" | "run-script" | "test" | "start" | "stop" | "restart" => Some("run"),
        "exec" | "x" | "npx" => Some("exec"),
        "completion" => Some("completion"),
        "help-search" => Some("help-search"),
        "explore" => Some("explore"),
        "edit" => Some("edit"),
        "remove" | "uninstall" | "unlink" | "rm" | "r" | "un" => Some("remove"),
        "list" | "ls" | "ll" | "la" => Some("list"),
        "query" => Some("query"),
        "explain" | "why" => Some("explain"),
        "audit" => Some("audit"),
        "doctor" => Some("doctor"),
        "outdated" => Some("outdated"),
        "fund" => Some("fund"),
        "prune" | "dedupe" | "ddp" | "find-dupes" => Some("maintenance"),
        "rebuild" | "rb" => Some("rebuild"),
        "pack" => Some("pack"),
        "publish" => Some("publish"),
        "unpublish" => Some("unpublish"),
        "deprecate" | "undeprecate" => Some("deprecate"),
        "diff" => Some("diff"),
        "search" | "s" | "se" | "find" => Some("search"),
        "star" | "unstar" | "stars" => Some("star"),
        "ping" => Some("ping"),
        "whoami" => Some("whoami"),
        "login" | "adduser" | "add-user" => Some("login"),
        "logout" => Some("logout"),
        "token" => Some("token"),
        "trust" => Some("trust"),
        "profile" => Some("profile"),
        "owner" => Some("owner"),
        "access" => Some("access"),
        "org" => Some("org"),
        "team" => Some("team"),
        "dist-tag" | "dist-tags" => Some("dist-tag"),
        "sbom" => Some("sbom"),
        "shrinkwrap" => Some("shrinkwrap"),
        "view" | "info" | "show" | "v" => Some("view"),
        "docs" | "doc" | "repo" | "repository" | "bugs" | "home" | "homepage" => {
            Some("metadata-url")
        }
        "config" | "c" | "get" | "set" => Some("config"),
        "cache" => Some("cache"),
        "pkg" => Some("pkg"),
        "version" => Some("version"),
        "init" | "create" | "innit" => Some("init"),
        "bin" | "root" | "prefix" => Some("path"),
        _ => Some("unknown"),
    }
}

#[derive(Debug)]
pub(crate) struct NpmSbomContext {
    pub(crate) root: NpmSbomRoot,
    pub(crate) packages: Vec<LockedPackage>,
    pub(crate) root_dependencies: BTreeSet<String>,
    pub(crate) timestamp: String,
    pub(crate) serial_uuid: String,
    pub(crate) sbom_type: NpmSbomType,
}

#[derive(Debug)]
pub(crate) struct NpmSbomRoot {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) license: Option<String>,
    pub(crate) homepage: Option<String>,
    pub(crate) description: Option<String>,
}

pub(crate) fn npm_sbom_context(
    project_dir: &Path,
    sbom_type: NpmSbomType,
) -> Result<NpmSbomContext, OmcRegistryError> {
    let lock = read_lockfile(project_dir.join("omc.lock"))?;
    let mut packages = lock
        .packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| {
        (left.name.as_str(), left.version.as_str())
            .cmp(&(right.name.as_str(), right.version.as_str()))
    });
    let root = npm_sbom_root(project_dir)?;
    let serial_uuid = npm_sbom_uuid(&root, &packages);
    Ok(NpmSbomContext {
        root,
        packages,
        root_dependencies: npm_root_dependency_names(project_dir)?,
        timestamp: current_utc_timestamp(),
        serial_uuid,
        sbom_type,
    })
}

fn npm_sbom_root(project_dir: &Path) -> Result<NpmSbomRoot, OmcRegistryError> {
    let package_json = project_dir.join("package.json");
    let package = if package_json.exists() {
        read_npm_pkg_json(&package_json)?
    } else {
        serde_json::json!({})
    };
    let name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| npm_outdated_dependent(project_dir));
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| "0.0.0".to_owned());
    Ok(NpmSbomRoot {
        name,
        version,
        license: package
            .get("license")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned),
        homepage: package
            .get("homepage")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned),
        description: package
            .get("description")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned),
    })
}

pub(crate) fn npm_cyclonedx_sbom(context: &NpmSbomContext) -> serde_json::Value {
    let root_ref = npm_root_bom_ref(&context.root);
    serde_json::json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", context.serial_uuid),
        "version": 1,
        "metadata": {
            "timestamp": context.timestamp,
            "lifecycles": [{ "phase": "build" }],
            "tools": [{
                "vendor": "turenio",
                "name": "omc",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "component": npm_cyclonedx_root_component(context, &root_ref),
        },
        "components": context.packages.iter().map(npm_cyclonedx_component).collect::<Vec<_>>(),
        "dependencies": npm_cyclonedx_dependencies(context, &root_ref),
    })
}

fn npm_cyclonedx_root_component(context: &NpmSbomContext, root_ref: &str) -> serde_json::Value {
    let mut component = serde_json::json!({
        "bom-ref": root_ref,
        "type": context.sbom_type.cyclonedx_type(),
        "name": context.root.name,
        "version": context.root.version,
        "scope": "required",
        "purl": npm_purl(&context.root.name, &context.root.version),
        "properties": [{
            "name": "cdx:npm:package:path",
            "value": "",
        }],
        "externalReferences": [],
    });
    if let Some(description) = &context.root.description {
        component["description"] = serde_json::Value::String(description.clone());
    }
    if let Some(homepage) = &context.root.homepage {
        component["externalReferences"] = serde_json::json!([{
            "type": "website",
            "url": homepage,
        }]);
    }
    if let Some(license) = &context.root.license {
        component["licenses"] = serde_json::json!([npm_cyclonedx_license(license)]);
    }
    component
}

fn npm_cyclonedx_component(package: &LockedPackage) -> serde_json::Value {
    let mut component = serde_json::json!({
        "bom-ref": npm_package_bom_ref(package),
        "type": "library",
        "name": package.name,
        "version": package.version,
        "scope": "required",
        "purl": npm_purl(&package.name, &package.version),
        "properties": [
            {
                "name": "cdx:npm:package:path",
                "value": npm_node_modules_path(&package.name),
            },
            {
                "name": "omc:behavior",
                "value": behavior_label(package.behavior),
            },
            {
                "name": "omc:verdict",
                "value": verdict_label(package.verdict),
            },
        ],
        "externalReferences": [{
            "type": "distribution",
            "url": npm_package_download_location(package),
        }],
    });
    if !package.sha256.is_empty() {
        component["hashes"] = serde_json::json!([{
            "alg": "SHA-256",
            "content": package.sha256,
        }]);
    }
    component
}

fn npm_cyclonedx_license(license: &str) -> serde_json::Value {
    if npm_license_id_like(license) {
        serde_json::json!({ "license": { "id": license } })
    } else {
        serde_json::json!({ "license": { "name": license } })
    }
}

fn npm_cyclonedx_dependencies(context: &NpmSbomContext, root_ref: &str) -> Vec<serde_json::Value> {
    let refs_by_name = npm_package_refs_by_name(&context.packages);
    let mut dependencies = Vec::new();
    dependencies.push(serde_json::json!({
        "ref": root_ref,
        "dependsOn": npm_dependency_refs(&context.root_dependencies, &refs_by_name),
    }));
    for package in &context.packages {
        let names = package
            .dependencies
            .iter()
            .chain(package.optional_dependencies.iter())
            .filter_map(|dependency| npm_dependency_name(dependency))
            .collect::<BTreeSet<_>>();
        dependencies.push(serde_json::json!({
            "ref": npm_package_bom_ref(package),
            "dependsOn": npm_dependency_refs(&names, &refs_by_name),
        }));
    }
    dependencies
}

pub(crate) fn npm_spdx_sbom(context: &NpmSbomContext) -> serde_json::Value {
    let root_id = npm_root_spdx_id(&context.root);
    let package_ids = npm_package_spdx_ids(&context.packages);
    let mut packages = Vec::new();
    packages.push(npm_spdx_root_package(context, &root_id));
    packages.extend(
        context
            .packages
            .iter()
            .map(|package| npm_spdx_package(package, &package_ids[&npm_package_key(package)])),
    );
    serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{}@{}", context.root.name, context.root.version),
        "documentNamespace": format!(
            "http://spdx.org/spdxdocs/{}-{}",
            npm_sbom_id_segment(&context.root.name),
            context.serial_uuid
        ),
        "creationInfo": {
            "created": context.timestamp,
            "creators": [format!("Tool: omc/{}", env!("CARGO_PKG_VERSION"))],
        },
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": npm_spdx_relationships(context, &root_id, &package_ids),
    })
}

fn npm_spdx_root_package(context: &NpmSbomContext, spdx_id: &str) -> serde_json::Value {
    let mut package = serde_json::json!({
        "name": context.root.name,
        "SPDXID": spdx_id,
        "versionInfo": context.root.version,
        "packageFileName": "",
        "primaryPackagePurpose": context.sbom_type.spdx_purpose(),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "homepage": context.root.homepage.as_deref().unwrap_or("NOASSERTION"),
        "licenseDeclared": context.root.license.as_deref().unwrap_or("NOASSERTION"),
        "externalRefs": [npm_spdx_purl_ref(&context.root.name, &context.root.version)],
    });
    if let Some(description) = &context.root.description {
        package["description"] = serde_json::Value::String(description.clone());
    }
    package
}

fn npm_spdx_package(package: &LockedPackage, spdx_id: &str) -> serde_json::Value {
    let mut value = serde_json::json!({
        "name": package.name,
        "SPDXID": spdx_id,
        "versionInfo": package.version,
        "packageFileName": npm_node_modules_path(&package.name),
        "downloadLocation": npm_package_download_location(package),
        "filesAnalyzed": false,
        "homepage": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "externalRefs": [npm_spdx_purl_ref(&package.name, &package.version)],
    });
    if !package.sha256.is_empty() {
        value["checksums"] = serde_json::json!([{
            "algorithm": "SHA256",
            "checksumValue": package.sha256,
        }]);
    }
    value
}

fn npm_spdx_purl_ref(name: &str, version: &str) -> serde_json::Value {
    serde_json::json!({
        "referenceCategory": "PACKAGE-MANAGER",
        "referenceType": "purl",
        "referenceLocator": npm_purl(name, version),
    })
}

fn npm_spdx_relationships(
    context: &NpmSbomContext,
    root_id: &str,
    package_ids: &BTreeMap<String, String>,
) -> Vec<serde_json::Value> {
    let refs_by_name = npm_spdx_refs_by_name(&context.packages, package_ids);
    let mut relationships = Vec::new();
    relationships.push(serde_json::json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": root_id,
        "relationshipType": "DESCRIBES",
    }));
    for dependency_id in npm_dependency_refs(&context.root_dependencies, &refs_by_name) {
        relationships.push(serde_json::json!({
            "spdxElementId": root_id,
            "relatedSpdxElement": dependency_id,
            "relationshipType": "DEPENDS_ON",
        }));
    }
    for package in &context.packages {
        let package_id = &package_ids[&npm_package_key(package)];
        let names = package
            .dependencies
            .iter()
            .chain(package.optional_dependencies.iter())
            .filter_map(|dependency| npm_dependency_name(dependency))
            .collect::<BTreeSet<_>>();
        for dependency_id in npm_dependency_refs(&names, &refs_by_name) {
            relationships.push(serde_json::json!({
                "spdxElementId": package_id,
                "relatedSpdxElement": dependency_id,
                "relationshipType": "DEPENDS_ON",
            }));
        }
    }
    relationships
}

fn npm_package_refs_by_name(packages: &[LockedPackage]) -> BTreeMap<String, Vec<String>> {
    let mut refs = BTreeMap::<String, Vec<String>>::new();
    for package in packages {
        refs.entry(package.name.clone())
            .or_default()
            .push(npm_package_bom_ref(package));
    }
    refs
}

fn npm_spdx_refs_by_name(
    packages: &[LockedPackage],
    package_ids: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    let mut refs = BTreeMap::<String, Vec<String>>::new();
    for package in packages {
        refs.entry(package.name.clone())
            .or_default()
            .push(package_ids[&npm_package_key(package)].clone());
    }
    refs
}

fn npm_dependency_refs(
    names: &BTreeSet<String>,
    refs_by_name: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    names
        .iter()
        .flat_map(|name| refs_by_name.get(name).into_iter().flatten().cloned())
        .collect()
}

fn npm_package_spdx_ids(packages: &[LockedPackage]) -> BTreeMap<String, String> {
    packages
        .iter()
        .map(|package| (npm_package_key(package), npm_package_spdx_id(package)))
        .collect()
}

fn npm_package_key(package: &LockedPackage) -> String {
    format!("{}@{}", package.name, package.version)
}

fn npm_root_bom_ref(root: &NpmSbomRoot) -> String {
    format!("{}@{}", root.name, root.version)
}

fn npm_package_bom_ref(package: &LockedPackage) -> String {
    format!("{}@{}", package.name, package.version)
}

fn npm_root_spdx_id(root: &NpmSbomRoot) -> String {
    format!(
        "SPDXRef-Package-{}-{}",
        npm_sbom_id_segment(&root.name),
        npm_sbom_id_segment(&root.version)
    )
}

fn npm_package_spdx_id(package: &LockedPackage) -> String {
    format!(
        "SPDXRef-Package-{}-{}",
        npm_sbom_id_segment(&package.name),
        npm_sbom_id_segment(&package.version)
    )
}

fn npm_sbom_id_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    segment.trim_matches('-').to_owned()
}

pub(crate) fn npm_package_name_from_spec(spec: &str) -> String {
    let spec = spec.strip_prefix("npm:").unwrap_or(spec);
    let spec = spec.split_once('#').map(|(base, _)| base).unwrap_or(spec);
    if let Some(index) = spec.rfind('@') {
        if index > 0 {
            return spec[..index].to_owned();
        }
    }
    spec.to_owned()
}

pub(crate) fn npm_package_relative_path(name: &str) -> Option<PathBuf> {
    if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped.split_once('/')?;
        if !npm_package_path_segment_valid(scope)
            || !npm_package_path_segment_valid(package)
            || package.contains('/')
        {
            return None;
        }
        return Some(PathBuf::from(format!("@{scope}")).join(package));
    }
    if name.contains('/') || !npm_package_path_segment_valid(name) {
        return None;
    }
    Some(PathBuf::from(name))
}

fn npm_package_path_segment_valid(segment: &str) -> bool {
    !segment.is_empty() && segment != "." && segment != ".."
}

fn npm_package_download_location(package: &LockedPackage) -> String {
    if package.source_url.is_empty() {
        "NOASSERTION".to_owned()
    } else {
        package.source_url.clone()
    }
}

fn npm_purl(name: &str, version: &str) -> String {
    format!("pkg:npm/{name}@{version}")
}

fn npm_license_id_like(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+'))
}

impl NpmSbomType {
    fn cyclonedx_type(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Application => "application",
            Self::Framework => "framework",
        }
    }

    fn spdx_purpose(self) -> &'static str {
        match self {
            Self::Library => "LIBRARY",
            Self::Application => "APPLICATION",
            Self::Framework => "FRAMEWORK",
        }
    }
}

fn npm_sbom_uuid(root: &NpmSbomRoot, packages: &[LockedPackage]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(root.name.as_bytes());
    hasher.update([0]);
    hasher.update(root.version.as_bytes());
    for package in packages {
        hasher.update([0]);
        hasher.update(package.name.as_bytes());
        hasher.update([0]);
        hasher.update(package.version.as_bytes());
        hasher.update([0]);
        hasher.update(package.sha256.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

pub(crate) fn npm_dependency_name(dependency: &str) -> Option<String> {
    let spec = PackageSpec::parse(dependency).ok()?;
    (spec.ecosystem == Ecosystem::Npm).then_some(spec.name)
}

pub(crate) fn npm_dependency_graph_from_omc_lock(
    lock: OmcLock,
) -> BTreeMap<String, BTreeSet<String>> {
    lock.packages
        .into_iter()
        .filter(|package| package.ecosystem == Ecosystem::Npm)
        .map(|package| {
            let dependencies = package
                .dependencies
                .iter()
                .chain(&package.optional_dependencies)
                .filter_map(|dependency| npm_dependency_name_from_key(dependency))
                .collect();
            (package.name, dependencies)
        })
        .collect()
}

pub(crate) fn npm_dependency_graph_from_package_lock(
    project_dir: &Path,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    let package_lock = read_npm_pkg_json(&project_dir.join("package-lock.json")).ok()?;
    let packages = package_lock.get("packages")?.as_object()?;
    let mut graph = BTreeMap::new();
    for (path, entry) in packages {
        let Some(name) = npm_package_name_from_package_lock_path(path) else {
            continue;
        };
        let dependencies = ["dependencies", "optionalDependencies"]
            .into_iter()
            .filter_map(|field| entry.get(field).and_then(serde_json::Value::as_object))
            .flat_map(|dependencies| dependencies.keys().cloned())
            .collect();
        graph.insert(name, dependencies);
    }
    Some(graph)
}

fn npm_package_name_from_package_lock_path(path: &str) -> Option<String> {
    if !path.contains("node_modules/") {
        return None;
    }
    let mut parts = path.rsplit("node_modules/");
    let name = parts.next()?;
    if name.is_empty() || name.contains("/node_modules/") {
        return None;
    }
    if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped.split_once('/')?;
        if package.contains('/') {
            return None;
        }
        return Some(format!("@{scope}/{package}"));
    }
    if name.contains('/') {
        return None;
    }
    Some(name.to_owned())
}

fn npm_dependency_name_from_key(dependency: &str) -> Option<String> {
    parse_package_specs(&[dependency.to_owned()], Some(Ecosystem::Npm))
        .ok()
        .and_then(|specs| specs.into_iter().next())
        .filter(|spec| spec.ecosystem == Ecosystem::Npm)
        .map(|spec| spec.name)
}

pub(crate) fn npm_list_json_tree(
    project_dir: &Path,
    filters: &[String],
    depth: usize,
) -> Result<serde_json::Value, OmcRegistryError> {
    let packages = listed_locked_packages(project_dir, Some(Ecosystem::Npm), &[])?;
    let mut packages_by_name = BTreeMap::new();
    for package in &packages {
        packages_by_name
            .entry(package.name.clone())
            .or_insert(package);
    }

    let filter_names = package_list_filter_names(filters, Some(Ecosystem::Npm))?;
    let mut root_dependencies = if filter_names.is_empty() {
        npm_root_dependency_names(project_dir)?
    } else {
        filter_names
    };
    if root_dependencies.is_empty() && filters.is_empty() {
        root_dependencies.extend(packages.iter().map(|package| package.name.clone()));
    }

    let (name, version) = npm_list_root_metadata(project_dir)?;
    let mut root = serde_json::Map::new();
    root.insert("version".to_owned(), serde_json::Value::String(version));
    root.insert("name".to_owned(), serde_json::Value::String(name));

    let mut dependencies = serde_json::Map::new();
    for dependency in root_dependencies {
        if let Some(package) = packages_by_name.get(&dependency) {
            let mut visiting = BTreeSet::new();
            dependencies.insert(
                dependency,
                npm_list_package_json(package, &packages_by_name, &mut visiting, depth),
            );
        }
    }
    if !dependencies.is_empty() {
        root.insert(
            "dependencies".to_owned(),
            serde_json::Value::Object(dependencies),
        );
    }

    Ok(serde_json::Value::Object(root))
}

fn npm_list_root_metadata(project_dir: &Path) -> Result<(String, String), OmcRegistryError> {
    let fallback_name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("omc-project")
        .to_owned();
    let package_json = project_dir.join("package.json");
    if !package_json.exists() {
        return Ok((fallback_name, "0.0.0".to_owned()));
    }

    let package = read_npm_pkg_json(&package_json)?;
    let name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(&fallback_name)
        .to_owned();
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty())
        .unwrap_or("0.0.0")
        .to_owned();
    Ok((name, version))
}

fn npm_list_package_json(
    package: &LockedPackage,
    packages_by_name: &BTreeMap<String, &LockedPackage>,
    visiting: &mut BTreeSet<(String, String)>,
    remaining_depth: usize,
) -> serde_json::Value {
    let mut item = serde_json::Map::new();
    item.insert(
        "version".to_owned(),
        serde_json::Value::String(package.version.clone()),
    );
    if !package.source_url.is_empty() {
        item.insert(
            "resolved".to_owned(),
            serde_json::Value::String(package.source_url.clone()),
        );
    }
    item.insert("overridden".to_owned(), serde_json::Value::Bool(false));

    let visit_key = (package.name.clone(), package.version.clone());
    if remaining_depth > 0 && visiting.insert(visit_key.clone()) {
        let mut dependencies = serde_json::Map::new();
        for dependency in package
            .dependencies
            .iter()
            .chain(package.optional_dependencies.iter())
            .chain(package.peer_dependencies.iter())
            .filter_map(|dependency| npm_dependency_name(dependency))
        {
            if let Some(dependency_package) = packages_by_name.get(&dependency) {
                dependencies.insert(
                    dependency,
                    npm_list_package_json(
                        dependency_package,
                        packages_by_name,
                        visiting,
                        remaining_depth.saturating_sub(1),
                    ),
                );
            }
        }
        if !dependencies.is_empty() {
            item.insert(
                "dependencies".to_owned(),
                serde_json::Value::Object(dependencies),
            );
        }
        visiting.remove(&visit_key);
    }

    serde_json::Value::Object(item)
}

pub(crate) fn npm_help_flag(arg: &str) -> bool {
    matches!(arg, "--help" | "-h")
}

pub(crate) fn npm_help_search_ignored_equals_flag(arg: &str) -> bool {
    ["--loglevel=", "--cache="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn npm_pkg_ignored_equals_flag(arg: &str) -> bool {
    ["--workspace=", "--loglevel="]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn npm_sbom_ignored_equals_flag(arg: &str) -> bool {
    [
        "--json=",
        "--package-lock-only=",
        "--omit=",
        "--include=",
        "--workspace=",
        "-w=",
        "--workspaces=",
        "--include-workspace-root=",
        "--loglevel=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}

pub(crate) fn npm_list_all_flag_value(arg: &str) -> Option<bool> {
    match arg {
        "--all" | "--all=true" => Some(true),
        "--all=false" | "--no-all" => Some(false),
        _ => None,
    }
}

pub(crate) fn npm_list_short_all_flag_value(arg: &str) -> Option<bool> {
    let rest = arg.strip_prefix('-')?;
    if rest.is_empty() || rest.starts_with('-') {
        return None;
    }
    rest.chars()
        .all(|ch| matches!(ch, 'a' | 'l'))
        .then(|| rest.contains('a'))
}

pub(crate) fn npm_list_ignored_equals_flag(arg: &str) -> bool {
    [
        "--depth=",
        "--omit=",
        "--include=",
        "--loglevel=",
        "--workspace=",
        "--userconfig=",
        "--parseable=",
    ]
    .iter()
    .any(|prefix| arg.starts_with(prefix))
}
