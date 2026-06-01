use super::*;
use crate::*;

#[test]
fn parses_npm_install_compat_flags() {
    assert_eq!(
        parse_npm_compat_action(&args(&["--version"])).unwrap(),
        NpmCompatAction::Version
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--silent", "--version"])).unwrap(),
        NpmCompatAction::Version
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--help"])).unwrap(),
        NpmCompatAction::Help { topic: None }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["help", "install"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("install".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["install", "--help"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("install".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["unlink", "--help"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("unlink".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["completion"])).unwrap(),
        NpmCompatAction::Completion { words: None }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["completion", "--", "npm", "expl"])).unwrap(),
        NpmCompatAction::Completion {
            words: Some(vec!["npm".to_owned(), "expl".to_owned()]),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["help-search", "cache", "--long"])).unwrap(),
        NpmCompatAction::HelpSearch {
            query: vec!["cache".to_owned()],
            long: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "doctor",
            "environment",
            "cache",
        ]))
        .unwrap(),
        NpmCompatAction::Doctor {
            action: NpmDoctorAction {
                checks: vec!["environment".to_owned(), "cache".to_owned()],
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            },
        }
    );
    assert!(npm_help_text(None).contains("Supported commands: install"));
    assert!(npm_help_text(Some("help-search")).contains("npm help-search"));
    assert!(npm_help_text(Some("doctor")).contains("npm doctor"));
    let help_search = npm_help_search_text(&args(&["cache"]), false).unwrap();
    assert!(help_search.contains("Top hits for \"cache\""));
    assert!(help_search.contains("npm help cache"));
    assert!(npm_help_text(Some("fund")).contains("npm fund [<package-spec>]"));
    assert!(npm_help_text(Some("install-test")).contains("npm install-test"));
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--silent",
            "--registry",
            "https://registry.example.invalid/npm",
            "install",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
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
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--json", "view", "left-pad", "version"])).unwrap(),
        NpmCompatAction::View {
            spec: "left-pad".to_owned(),
            fields: vec!["version".to_owned()],
            json: true,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["view", "left-pad", "version", "-j"])).unwrap(),
        NpmCompatAction::View {
            spec: "left-pad".to_owned(),
            fields: vec!["version".to_owned()],
            json: true,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["-j", "view", "left-pad", "version"])).unwrap(),
        NpmCompatAction::View {
            spec: "left-pad".to_owned(),
            fields: vec!["version".to_owned()],
            json: true,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["why", "left-pad", "-j"])).unwrap(),
        NpmCompatAction::Explain {
            specs: vec!["left-pad".to_owned()],
            json: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "run",
            "build",
        ]))
        .unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: Vec::new(),
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "init",
            "-y",
            "--scope",
            "@scope",
            "--private",
            "--type=module",
        ]))
        .unwrap(),
        NpmCompatAction::Init {
            action: NpmInitAction {
                name: None,
                version: None,
                description: None,
                main: None,
                license: None,
                scope: Some("@scope".to_owned()),
                private: true,
                package_type: Some("module".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["init", "react-app"])).unwrap(),
        NpmCompatAction::Create {
            action: NpmCreateAction {
                initializer: "react-app".to_owned(),
                args: Vec::new(),
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "create",
            "vite@latest",
            "my-app",
            "--allow=fs.write:*",
            "--allow-all-host",
            "--",
            "--template",
            "react",
        ]))
        .unwrap(),
        NpmCompatAction::Create {
            action: NpmCreateAction {
                initializer: "vite@latest".to_owned(),
                args: vec![
                    "my-app".to_owned(),
                    "--template".to_owned(),
                    "react".to_owned(),
                ],
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: vec!["fs.write:*".to_owned()],
                allow_flow: Vec::new(),
                allow_all_host: true,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["version", "--json"])).unwrap(),
        NpmCompatAction::PackageVersion {
            action: NpmVersionAction::Current { json: true },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "version",
            "patch",
            "--no-git-tag-version",
            "--allow-same-version",
        ]))
        .unwrap(),
        NpmCompatAction::PackageVersion {
            action: NpmVersionAction::Bump {
                spec: "patch".to_owned(),
                preid: None,
                allow_same_version: true,
                json: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["version", "preminor", "--preid", "rc", "--json",]))
            .unwrap(),
        NpmCompatAction::PackageVersion {
            action: NpmVersionAction::Bump {
                spec: "preminor".to_owned(),
                preid: Some("rc".to_owned()),
                allow_same_version: false,
                json: true,
            },
        }
    );

    assert_eq!(npm_next_version("1.2.3", "patch", None).unwrap(), "1.2.4");
    assert_eq!(
        npm_next_version("1.2.3", "preminor", Some("rc")).unwrap(),
        "1.3.0-rc.0"
    );
    assert_eq!(
        npm_next_version("1.2.3", "prerelease", None).unwrap(),
        "1.2.4-0"
    );
    assert_eq!(
        npm_next_version("1.2.3-rc.0", "prerelease", Some("rc")).unwrap(),
        "1.2.3-rc.1"
    );
    assert_eq!(
        npm_next_version("1.2.3-alpha.0", "prerelease", Some("rc")).unwrap(),
        "1.2.3-rc.0"
    );
    assert_eq!(
        npm_next_version("v2.0.0+build.7", "2.0.0", None).unwrap(),
        "2.0.0"
    );

    let action = parse_npm_compat_action(&args(&[
        "install",
        "-D",
        "--omit=dev",
        "--install-strategy",
        "hoisted",
        "--cache=/tmp/npm-cache",
        "--registry",
        "https://registry.example.invalid/npm",
        "--package-lock=false",
        "--no-fund",
        "--silent",
        "--loglevel",
        "warn",
        "--no-progress",
        "--progress=false",
        "--color",
        "false",
        "--legacy-peer-deps=true",
        "--legacy-peer-deps=false",
        "--strict-peer-deps=false",
        "--strict-peer-deps=true",
        "--ignore-scripts=true",
        "--prefer-offline",
        "--prefer-offline=true",
        "--prefer-online",
        "--prefer-online=false",
        "--prefer-dedupe",
        "--prefer-dedupe=false",
        "--no-prefer-dedupe",
        "--foreground-scripts=true",
        "--audit=true",
        "--fund=true",
        "--bin-links=false",
        "--global-style",
        "--legacy-bundling",
        "--dry-run",
        "--allow-all-host",
        "left-pad@1.3.0",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad@1.3.0".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Dev,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: false,
            lock_only: false,
            dry_run: true,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: true,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    let action =
        parse_npm_compat_action(&args(&["--location=global", "install", "left-pad"])).unwrap();
    let NpmCompatAction::Install { global, specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(global);
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action = parse_npm_compat_action(&args(&[
        "--prefer-dedupe",
        "--ignore-scripts=true",
        "--bin-links=false",
        "install",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action =
        parse_npm_compat_action(&args(&["install", "--location", "project", "left-pad"])).unwrap();
    let NpmCompatAction::Install { global, specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!global);
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--allow=env:API_TOKEN",
        "--allow-flow",
        "env:API_TOKEN->network:api.example.com",
        "flow-client",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        allow, allow_flow, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(allow, vec!["env:API_TOKEN".to_owned()]);
    assert_eq!(
        allow_flow,
        vec!["env:API_TOKEN->network:api.example.com".to_owned()]
    );

    let exact = parse_npm_compat_action(&args(&["install", "--save-exact", "left-pad"])).unwrap();
    let NpmCompatAction::Install { save_prefix, .. } = exact else {
        panic!("expected npm install action");
    };
    assert_eq!(save_prefix, "");

    let tilde =
        parse_npm_compat_action(&args(&["--save-prefix=~", "install", "left-pad"])).unwrap();
    let NpmCompatAction::Install { save_prefix, .. } = tilde else {
        panic!("expected npm install action");
    };
    assert_eq!(save_prefix, "~");

    let bundled = parse_npm_compat_action(&args(&["in", "-B", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        save,
        save_bundle,
        specs,
        ..
    } = bundled
    else {
        panic!("expected npm install action");
    };
    assert!(save);
    assert!(save_bundle);
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let unbundled = parse_npm_compat_action(&args(&[
        "install",
        "--save-bundle",
        "--no-save-bundle",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { save_bundle, .. } = unbundled else {
        panic!("expected npm install action");
    };
    assert!(!save_bundle);

    let save_dev_false =
        parse_npm_compat_action(&args(&["install", "--save-dev=false", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        dependency_kind, ..
    } = save_dev_false
    else {
        panic!("expected npm install action");
    };
    assert_eq!(dependency_kind, ManifestDependencyKind::Production);

    let save_peer_true =
        parse_npm_compat_action(&args(&["install", "--save-peer=true", "react"])).unwrap();
    let NpmCompatAction::Install {
        dependency_kind, ..
    } = save_peer_true
    else {
        panic!("expected npm install action");
    };
    assert_eq!(dependency_kind, ManifestDependencyKind::Peer);

    assert_eq!(
        parse_npm_compat_action(&args(&["install", "--save-optional", "fsevents"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["fsevents".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Optional,
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
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&["install", "--save-peer", "react"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["react".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Peer,
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
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "install",
        "./pkg.tgz",
        "file:../other.tgz",
        "../local-pkg",
        "@scope/runtime",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["@scope/runtime".to_owned()],
            archive_references: vec!["./pkg.tgz".to_owned(), "file:../other.tgz".to_owned()],
            local_paths: vec![PathBuf::from("../local-pkg")],
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
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&["link"])).unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Register { dry_run: false },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--location=global", "link"])).unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Register { dry_run: false },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["link", "--dry-run", "../local-pkg"])).unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Install {
                names: Vec::new(),
                archive_references: Vec::new(),
                local_paths: vec![PathBuf::from("../local-pkg")],
                save: false,
                save_bundle: false,
                dependency_kind: ManifestDependencyKind::Production,
                omit_dev: false,
                omit_optional: false,
                omit_peer: false,
                lock_only: false,
                dry_run: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--save-dev",
            "link",
            "@scope/local-pkg",
            "--omit=dev",
            "--registry=https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Install {
                names: vec!["@scope/local-pkg".to_owned()],
                archive_references: Vec::new(),
                local_paths: Vec::new(),
                save: true,
                save_bundle: false,
                dependency_kind: ManifestDependencyKind::Dev,
                omit_dev: true,
                omit_optional: false,
                omit_peer: false,
                lock_only: false,
                dry_run: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "link",
            "--dry-run",
            "./pkg.tgz",
            "file:../other.tgz",
        ]))
        .unwrap(),
        NpmCompatAction::Link {
            action: NpmLinkAction::Install {
                names: Vec::new(),
                archive_references: vec!["./pkg.tgz".to_owned(), "file:../other.tgz".to_owned()],
                local_paths: Vec::new(),
                save: false,
                save_bundle: false,
                dependency_kind: ManifestDependencyKind::Production,
                omit_dev: false,
                omit_optional: false,
                omit_peer: false,
                lock_only: false,
                dry_run: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
            },
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--no-save",
        "--omit=optional,peer",
        "--omit",
        "dev",
        "--include=dev",
        "left-pad",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: false,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: true,
            omit_peer: true,
            package_lock: false,
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
        }
    );

    let action = parse_npm_compat_action(&args(&["install", "--no-optional", "left-pad"])).unwrap();
    let NpmCompatAction::Install { omit_optional, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(omit_optional);

    let action =
        parse_npm_compat_action(&args(&["install", "--only", "prod", "left-pad"])).unwrap();
    let NpmCompatAction::Install { omit_dev, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(omit_dev);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--production",
        "--also=dev",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { omit_dev, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!omit_dev);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--optional=false",
        "--include=optional",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install { omit_optional, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!omit_optional);

    let action =
        parse_npm_compat_action(&args(&["install", "--package-lock-only", "left-pad"])).unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
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
            lock_only: true,
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
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "--dry-run",
        "--package-lock-only",
        "install",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        specs,
        dry_run,
        lock_only,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert!(dry_run);
    assert!(lock_only);

    let action =
        parse_npm_compat_action(&args(&["install", "--dry-run", "--json", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        specs,
        dry_run,
        json,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert!(dry_run);
    assert!(json);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "github:turenio/omc#main",
        "turenio/omc#v1.0.0",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        specs,
        archive_references,
        local_paths,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert_eq!(
        archive_references,
        vec![
            "github:turenio/omc#main".to_owned(),
            "turenio/omc#v1.0.0".to_owned()
        ]
    );
    assert!(local_paths.is_empty());

    let action = parse_npm_compat_action(&args(&["install", "--tag", "beta", "left-pad"])).unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad@beta".to_owned()]);

    let action = parse_npm_compat_action(&args(&[
        "--tag=beta",
        "install",
        "@scope/pkg",
        "left-pad@1.3.0",
    ]))
    .unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(
        specs,
        vec!["@scope/pkg@beta".to_owned(), "left-pad@1.3.0".to_owned()]
    );

    let action =
        parse_npm_compat_action(&args(&["install", "--before", "2025-01-01", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        specs, npm_before, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);
    assert_eq!(npm_before.as_deref(), Some("2025-01-01"));

    let action =
        parse_npm_compat_action(&args(&["--before=2025-01-01", "install", "left-pad"])).unwrap();
    let NpmCompatAction::Install { npm_before, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(npm_before.as_deref(), Some("2025-01-01"));

    let before_parse = Utc::now();
    let action =
        parse_npm_compat_action(&args(&["install", "--min-release-age=7", "left-pad"])).unwrap();
    let after_parse = Utc::now();
    let NpmCompatAction::Install { npm_before, .. } = action else {
        panic!("expected npm install action");
    };
    let cutoff = chrono::DateTime::parse_from_rfc3339(npm_before.as_deref().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!(cutoff >= before_parse - Duration::days(7) - Duration::seconds(1));
    assert!(cutoff <= after_parse - Duration::days(7) + Duration::seconds(1));

    let error = parse_npm_compat_action(&args(&["install", "--min-release-age=7d", "left-pad"]))
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported npm --min-release-age value"));

    let action =
        parse_npm_compat_action(&args(&["install", "--engine-strict", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        npm_engine_strict, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(npm_engine_strict);

    let action =
        parse_npm_compat_action(&args(&["--engine-strict=true", "ci", "--omit=dev"])).unwrap();
    let NpmCompatAction::Ci {
        npm_engine_strict, ..
    } = action
    else {
        panic!("expected npm ci action");
    };
    assert!(npm_engine_strict);

    let action = parse_npm_compat_action(&args(&["install", "--offline", "left-pad"])).unwrap();
    let NpmCompatAction::Install { npm_offline, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(npm_offline);

    let action =
        parse_npm_compat_action(&args(&["install", "--offline", "--no-offline", "left-pad"]))
            .unwrap();
    let NpmCompatAction::Install { npm_offline, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!npm_offline);

    let action = parse_npm_compat_action(&args(&["--offline=true", "ci", "--omit=dev"])).unwrap();
    let NpmCompatAction::Ci { npm_offline, .. } = action else {
        panic!("expected npm ci action");
    };
    assert!(npm_offline);

    let action =
        parse_npm_compat_action(&args(&["install", "--install-links=false", "left-pad"])).unwrap();
    let NpmCompatAction::Install { specs, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(specs, vec!["left-pad".to_owned()]);

    let action =
        parse_npm_compat_action(&args(&["--json", "install", "--dry-run", "left-pad"])).unwrap();
    let NpmCompatAction::Install { dry_run, json, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(dry_run);
    assert!(json);

    let action =
        parse_npm_compat_action(&args(&["install", "--json", "--no-json", "left-pad"])).unwrap();
    let NpmCompatAction::Install { json, .. } = action else {
        panic!("expected npm install action");
    };
    assert!(!json);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--dry-run=true",
        "--package-lock-only=true",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        dry_run, lock_only, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(dry_run);
    assert!(lock_only);

    let action = parse_npm_compat_action(&args(&[
        "--dry-run=false",
        "--package-lock-only=false",
        "install",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        dry_run, lock_only, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(!dry_run);
    assert!(!lock_only);

    let action = parse_npm_compat_action(&args(&["--dry-run", "ci", "--omit=dev"])).unwrap();
    let NpmCompatAction::Ci {
        dry_run,
        omit_dev,
        workspaces,
        all_workspaces,
        include_workspace_root,
        ..
    } = action
    else {
        panic!("expected npm ci action");
    };
    assert!(dry_run);
    assert!(omit_dev);
    assert!(workspaces.is_empty());
    assert!(!all_workspaces);
    assert!(!include_workspace_root);

    let action = parse_npm_compat_action(&args(&["ci", "--json", "--dry-run"])).unwrap();
    let NpmCompatAction::Ci { dry_run, json, .. } = action else {
        panic!("expected npm ci action");
    };
    assert!(dry_run);
    assert!(json);

    let action = parse_npm_compat_action(&args(&[
        "ci",
        "--workspace",
        "@demo/lib",
        "--include-workspace-root",
    ]))
    .unwrap();
    let NpmCompatAction::Ci {
        workspaces,
        all_workspaces,
        include_workspace_root,
        ..
    } = action
    else {
        panic!("expected npm ci action");
    };
    assert_eq!(workspaces, vec!["@demo/lib"]);
    assert!(!all_workspaces);
    assert!(include_workspace_root);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--save=false",
        "--package-lock=true",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        save, package_lock, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(!save);
    assert!(!package_lock);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--save=false",
        "--save=true",
        "left-pad",
    ]))
    .unwrap();
    let NpmCompatAction::Install {
        save, package_lock, ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(save);
    assert!(package_lock);

    let action = parse_npm_compat_action(&args(&[
        "install",
        "--workspace",
        "@demo/lib",
        "--include-workspace-root",
        "left-pad",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
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
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: true,
        }
    );

    let action = parse_npm_compat_action(&args(&["install", "-w@demo/lib", "left-pad"])).unwrap();
    let NpmCompatAction::Install { workspaces, .. } = action else {
        panic!("expected npm install action");
    };
    assert_eq!(workspaces, vec!["@demo/lib"]);

    let action = parse_npm_compat_action(&args(&["install", "-ws", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        workspaces,
        all_workspaces,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert!(workspaces.is_empty());
    assert!(all_workspaces);

    let action =
        parse_npm_compat_action(&args(&["install", "--workspace=true", "left-pad"])).unwrap();
    let NpmCompatAction::Install {
        workspaces,
        all_workspaces,
        ..
    } = action
    else {
        panic!("expected npm install action");
    };
    assert_eq!(workspaces, vec!["true"]);
    assert!(!all_workspaces);

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "remove",
            "--package-lock-only",
            "left-pad",
            "--workspace",
            "@demo/lib",
            "--include-workspace-root=false",
        ]))
        .unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: false,
            save: true,
            package_lock: true,
            lock_only: true,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--location=global",
            "remove",
            "left-pad",
            "--location",
            "project",
        ]))
        .unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: false,
            save: true,
            package_lock: true,
            lock_only: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--workspace=@demo/lib",
            "unlink",
            "left-pad",
            "--no-save",
        ]))
        .unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: false,
            save: false,
            package_lock: true,
            lock_only: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--location=global", "r", "left-pad"])).unwrap(),
        NpmCompatAction::Remove {
            specs: vec!["left-pad".to_owned()],
            global: true,
            save: true,
            package_lock: true,
            lock_only: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "it",
            "--omit=dev",
            "left-pad",
            "--",
            "--watch",
        ]))
        .unwrap(),
        NpmCompatAction::InstallTest {
            command: "it".to_owned(),
            use_ci: false,
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: false,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
            test_args: vec!["--watch".to_owned()],
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&[
            "cit",
            "--dry-run",
            "--omit=dev",
            "--",
            "--runInBand",
        ]))
        .unwrap(),
        NpmCompatAction::InstallTest {
            command: "cit".to_owned(),
            use_ci: true,
            specs: Vec::new(),
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: true,
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
            test_args: vec!["--runInBand".to_owned()],
        }
    );

    let action = parse_npm_compat_action(&args(&[
        "update",
        "--package-lock-only",
        "--omit=dev",
        "--registry=https://registry.example.invalid/npm",
        "left-pad",
    ]))
    .unwrap();

    assert_eq!(
        action,
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: false,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: true,
            dry_run: false,
            json: false,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            npm_before: None,
            npm_engine_strict: false,
            npm_offline: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );

    assert_eq!(
        parse_npm_compat_action(&args(&["up", "--save-dev", "left-pad"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: true,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Dev,
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
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["udpate", "--dry-run", "left-pad"])).unwrap(),
        NpmCompatAction::Install {
            specs: vec!["left-pad".to_owned()],
            archive_references: Vec::new(),
            local_paths: Vec::new(),
            global: false,
            save: false,
            save_prefix: DEFAULT_NPM_SAVE_PREFIX.to_owned(),
            save_bundle: false,
            dependency_kind: ManifestDependencyKind::Production,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            package_lock: true,
            lock_only: false,
            dry_run: true,
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
        }
    );
}

#[test]
fn parses_npm_run_and_exec_compat_commands() {
    assert_eq!(
        parse_npm_compat_action(&args(&["run"])).unwrap(),
        NpmCompatAction::RunList {
            action: NpmRunListAction {
                json: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--json", "--workspace", "@demo/lib", "run",])).unwrap(),
        NpmCompatAction::RunList {
            action: NpmRunListAction {
                json: true,
                workspaces: vec!["@demo/lib".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["run", "test", "--", "--watch"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "test".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["test", "--", "--watch"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "test".to_owned(),
            name: "test".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["run", "--if-present", "--silent", "build"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: Vec::new(),
            if_present: true,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["test", "--if-present", "--", "--watch"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "test".to_owned(),
            name: "test".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: true,
            workspaces: Vec::new(),
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["-w@demo/lib", "run", "build", "--", "--watch",])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: vec!["--watch".to_owned()],
            if_present: false,
            workspaces: vec!["@demo/lib".to_owned()],
            all_workspaces: false,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "test",
            "--workspaces=true",
            "--include-workspace-root=false",
            "--if-present",
        ]))
        .unwrap(),
        NpmCompatAction::RunScript {
            command: "test".to_owned(),
            name: "test".to_owned(),
            args: Vec::new(),
            if_present: true,
            workspaces: Vec::new(),
            all_workspaces: true,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--ws", "run", "build"])).unwrap(),
        NpmCompatAction::RunScript {
            command: "run".to_owned(),
            name: "build".to_owned(),
            args: Vec::new(),
            if_present: false,
            workspaces: Vec::new(),
            all_workspaces: true,
            include_workspace_root: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["exec", "eslint", "--", "."])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: Vec::new(),
                command: "eslint".to_owned(),
                args: vec![".".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["exec", "--help"])).unwrap(),
        NpmCompatAction::Help {
            topic: Some("exec".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["exec", "eslint", "--help"])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: Vec::new(),
                command: "eslint".to_owned(),
                args: vec!["--help".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--yes",
            "--package",
            "eslint",
            "--cache=/tmp/npm-cache",
            "--loglevel=warn",
            "--ignore-scripts=true",
            "--prefer-offline",
            "--prefer-dedupe",
            "--bin-links=false",
            "--audit=false",
            "--fund=false",
            "eslint",
            "--",
            ".",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["eslint".to_owned()],
                command: "eslint".to_owned(),
                args: vec![".".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    let (call_command, call_args) = npm_exec_call_command("node -e \"console.log(1)\"".to_owned());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--package",
            "typescript",
            "--call",
            "node -e \"console.log(1)\"",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["typescript".to_owned()],
                command: call_command,
                args: call_args,
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "npx",
            "-y",
            "-p",
            "typescript",
            "tsc",
            "--version",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["typescript".to_owned()],
                command: "tsc".to_owned(),
                args: vec!["--version".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["npx", "semver@7.6.3", "1.2.3"])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["semver@7.6.3".to_owned()],
                command: "semver".to_owned(),
                args: vec!["1.2.3".to_owned()],
                no_install: false,
                prefer_project_bin: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["npx", "@scope/tool@1.2.3", "--help"])).unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["@scope/tool@1.2.3".to_owned()],
                command: "tool".to_owned(),
                args: vec!["--help".to_owned()],
                no_install: false,
                prefer_project_bin: true,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--package=@scope/tool@1.2.3",
            "--registry",
            "https://registry.example",
            "--allow=env:TOOL_TOKEN",
            "--allow-all-host",
            "--",
            "tool",
            "--help",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["@scope/tool@1.2.3".to_owned()],
                command: "tool".to_owned(),
                args: vec!["--help".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: Some("https://registry.example".to_owned()),
                allow: vec!["env:TOOL_TOKEN".to_owned()],
                allow_flow: Vec::new(),
                allow_all_host: true,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "-ws",
            "exec",
            "--include-workspace-root=false",
            "--",
            "node",
            "-e",
            "console.log(process.cwd())",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: Vec::new(),
                command: "node".to_owned(),
                args: vec!["-e".to_owned(), "console.log(process.cwd())".to_owned()],
                no_install: false,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: true,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "exec",
            "--no-install",
            "--package",
            "eslint",
            "eslint",
        ]))
        .unwrap(),
        NpmCompatAction::Exec {
            action: NpmExecAction {
                packages: vec!["eslint".to_owned()],
                command: "eslint".to_owned(),
                args: Vec::new(),
                no_install: true,
                prefer_project_bin: false,
                npm_registry: None,
                allow: Vec::new(),
                allow_flow: Vec::new(),
                allow_all_host: false,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--shell",
            "zsh",
            "explore",
            "@scope/pkg@1.2.3",
            "--",
            "pwd",
            "-P",
        ]))
        .unwrap(),
        NpmCompatAction::Explore {
            action: NpmExploreAction {
                package: "@scope/pkg@1.2.3".to_owned(),
                command: Some("pwd".to_owned()),
                args: vec!["-P".to_owned()],
                shell: Some("zsh".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--editor",
            "true",
            "edit",
            "@scope/pkg/package.json",
        ]))
        .unwrap(),
        NpmCompatAction::Edit {
            target: "@scope/pkg/package.json".to_owned(),
            editor: Some("true".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["bin", "--silent"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Bin,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["root"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Root,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["prefix", "--parseable"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Prefix,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--global", "bin"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Bin,
            global: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--location", "global", "prefix"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Prefix,
            global: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["root", "--location=project"])).unwrap(),
        NpmCompatAction::Path {
            kind: NpmPathKind::Root,
            global: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "pack",
            "--pack-destination",
            "dist",
            "--json",
            "--dry-run",
            ".",
        ]))
        .unwrap(),
        NpmCompatAction::Pack {
            action: NpmPackAction {
                packages: vec![NpmPackInput::Local(PathBuf::from("."))],
                destination: PathBuf::from("dist"),
                json: true,
                dry_run: true,
                npm_registry: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "pack",
            "left-pad@1.3.0",
        ]))
        .unwrap(),
        NpmCompatAction::Pack {
            action: NpmPackAction {
                packages: vec![NpmPackInput::Registry("left-pad@1.3.0".to_owned())],
                destination: PathBuf::from("."),
                json: false,
                dry_run: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json=true",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "publish",
            "--tag=beta",
            "--access",
            "public",
            "--workspace",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Publish {
            action: NpmPublishAction {
                package: None,
                tag: "beta".to_owned(),
                access: Some("public".to_owned()),
                provenance: NpmPublishProvenance::None,
                dry_run: false,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
                workspaces: vec!["@demo/pkg".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "publish",
            "./pkg.tgz",
            "--dry-run",
            "--no-provenance",
        ]))
        .unwrap(),
        NpmCompatAction::Publish {
            action: NpmPublishAction {
                package: Some(PathBuf::from("./pkg.tgz")),
                tag: "latest".to_owned(),
                access: None,
                provenance: NpmPublishProvenance::None,
                dry_run: true,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "publish",
            "--dry-run",
            "--provenance-file=build.sigstore",
            "--provenance=false",
            "--provenance",
        ]))
        .unwrap(),
        NpmCompatAction::Publish {
            action: NpmPublishAction {
                package: None,
                tag: "latest".to_owned(),
                access: None,
                provenance: NpmPublishProvenance::Generate,
                dry_run: true,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "--force",
            "unpublish",
            "@scope/pkg@1.2.3",
            "--dry-run",
        ]))
        .unwrap(),
        NpmCompatAction::Unpublish {
            action: NpmUnpublishAction {
                spec: Some("@scope/pkg@1.2.3".to_owned()),
                dry_run: true,
                force: true,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
                workspaces: Vec::new(),
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["unpublish", "--workspace", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Unpublish {
            action: NpmUnpublishAction {
                spec: None,
                dry_run: false,
                force: false,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                workspaces: vec!["@demo/pkg".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["unpublish", "a", "b"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "deprecate",
            "demo-pkg@1.x",
            "old line",
            "--dry-run",
        ]))
        .unwrap(),
        NpmCompatAction::Deprecate {
            action: NpmDeprecateAction {
                spec: "demo-pkg@1.x".to_owned(),
                message: "old line".to_owned(),
                dry_run: true,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
                undeprecate: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["undeprecate", "demo-pkg@1.0.0"])).unwrap(),
        NpmCompatAction::Deprecate {
            action: NpmDeprecateAction {
                spec: "demo-pkg@1.0.0".to_owned(),
                message: String::new(),
                dry_run: false,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
                undeprecate: true,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["deprecate", "demo-pkg@1.0.0"])).is_err());
    assert!(parse_npm_compat_action(&args(&["undeprecate", "demo-pkg@1.0.0", "extra"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "prune",
            "--omit=dev",
            "--loglevel=silent",
            "--allow-all-host",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Maintenance {
            command: NpmMaintenanceCommand::Prune,
            packages: vec!["left-pad".to_owned()],
            dry_run: false,
            json: false,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: true,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "dedupe",
            "--dry-run",
            "--json",
            "--cache",
            "/tmp/npm-cache",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Maintenance {
            command: NpmMaintenanceCommand::Dedupe,
            packages: vec!["left-pad".to_owned()],
            dry_run: true,
            json: true,
            omit_dev: false,
            omit_optional: false,
            omit_peer: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--omit=dev",
            "rebuild",
            "node-sass",
            "--ignore-scripts",
            "--build-from-source",
            "--dry-run",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Maintenance {
            command: NpmMaintenanceCommand::Rebuild,
            packages: vec!["node-sass".to_owned()],
            dry_run: true,
            json: true,
            omit_dev: true,
            omit_optional: false,
            omit_peer: false,
            allow: Vec::new(),
            allow_flow: Vec::new(),
            allow_all_host: false,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "audit",
            "--json",
            "--audit-level=high",
            "--omit",
            "dev",
            "--registry",
            "https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Audit { json: true }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["audit", "-j"])).unwrap(),
        NpmCompatAction::Audit { json: true }
    );
    assert!(parse_npm_compat_action(&args(&["audit", "fix"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--workspace",
            "@demo/lib",
            "fund",
            "left-pad@1.3.0",
            "--browser=false",
        ]))
        .unwrap(),
        NpmCompatAction::Fund {
            action: NpmFundAction {
                json: true,
                package: Some("left-pad@1.3.0".to_owned()),
                workspaces: vec!["@demo/lib".to_owned()],
                all_workspaces: false,
                include_workspace_root: false,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "fund",
            "--ws",
            "--include-workspace-root",
            "--which",
            "1",
        ]))
        .unwrap(),
        NpmCompatAction::Fund {
            action: NpmFundAction {
                json: false,
                package: None,
                workspaces: Vec::new(),
                all_workspaces: true,
                include_workspace_root: true,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["fund", "left-pad", "chalk"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "verify", "--cache=/tmp/npm-cache"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Verify,
            cache_dir: Some(PathBuf::from("/tmp/npm-cache")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--cache", ".npm-cache", "cache", "verify"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Verify,
            cache_dir: Some(PathBuf::from(".npm-cache")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "ls", "left-pad"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::List {
                pattern: Some("left-pad".to_owned()),
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "rm", "left-pad"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Remove {
                pattern: "left-pad".to_owned(),
            },
            cache_dir: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["cache", "clean", "--force"])).unwrap(),
        NpmCompatAction::Cache {
            action: NpmCacheAction::Clean,
            cache_dir: None,
        }
    );
    assert!(parse_npm_compat_action(&args(&["cache", "clean"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&["pkg", "get", "name", "version", "--json"])).unwrap(),
        NpmCompatAction::Pkg {
            action: NpmPkgAction::Get {
                fields: vec!["name".to_owned(), "version".to_owned()],
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "pkg",
            "set",
            "scripts.test=\"vitest\"",
            "private=true",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Pkg {
            action: NpmPkgAction::Set {
                assignments: vec![
                    (
                        "scripts.test".to_owned(),
                        serde_json::Value::String("vitest".to_owned()),
                    ),
                    ("private".to_owned(), serde_json::Value::Bool(true)),
                ],
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["pkg", "delete", "scripts.pretest"])).unwrap(),
        NpmCompatAction::Pkg {
            action: NpmPkgAction::Delete {
                fields: vec!["scripts.pretest".to_owned()],
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["shrinkwrap", "--dry-run", "ignored"])).unwrap(),
        NpmCompatAction::Shrinkwrap
    );
    assert!(parse_npm_compat_action(&args(&["shrinkwrap", "--workspace", "@demo/lib"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "outdated",
            "--json",
            "--parseable",
            "--depth=0",
            "--registry",
            "https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: true,
            packages: Vec::new(),
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "outdated",
            "left-pad@1.1.0",
            "@demo/pkg",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: false,
            packages: vec!["left-pad@1.1.0".to_owned(), "@demo/pkg".to_owned()],
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["outdated", "-al", "--json"])).unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: false,
            packages: Vec::new(),
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["outdated", "-j"])).unwrap(),
        NpmCompatAction::Outdated {
            json: true,
            parseable: false,
            packages: Vec::new(),
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--searchlimit=3",
            "--json",
            "search",
            "--registry",
            "https://registry.example.invalid/npm",
            "left",
            "pad",
        ]))
        .unwrap(),
        NpmCompatAction::Search {
            action: NpmSearchAction {
                query: "left pad".to_owned(),
                json: true,
                parseable: false,
                limit: 3,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["find", "left-pad", "--parseable", "--limit=500"]))
            .unwrap(),
        NpmCompatAction::Search {
            action: NpmSearchAction {
                query: "left-pad".to_owned(),
                json: false,
                parseable: true,
                limit: 250,
                npm_registry: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--diff=left-pad@1.1.0",
            "--diff",
            "left-pad@1.3.0",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "diff",
            "--diff-name-only",
            "--diff-unified=5",
            "--diff-ignore-all-space",
            "--diff-src-prefix=old/",
            "--diff-dst-prefix",
            "new/",
            "index.js",
        ]))
        .unwrap(),
        NpmCompatAction::Diff {
            action: NpmDiffAction {
                specs: vec!["left-pad@1.1.0".to_owned(), "left-pad@1.3.0".to_owned()],
                paths: vec!["index.js".to_owned()],
                name_only: true,
                unified: 5,
                ignore_all_space: true,
                no_prefix: false,
                src_prefix: "old/".to_owned(),
                dst_prefix: "new/".to_owned(),
                text: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "star",
            "left-pad",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Star {
            action: NpmStarAction::Mutate {
                specs: vec!["left-pad".to_owned(), "@demo/pkg".to_owned()],
                starred: true,
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["unstar", "left-pad", "--otp=123456"])).unwrap(),
        NpmCompatAction::Star {
            action: NpmStarAction::Mutate {
                specs: vec!["left-pad".to_owned()],
                starred: false,
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry=https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "stars",
            "alice",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Star {
            action: NpmStarAction::List {
                user: Some("alice".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "ping",
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Ping {
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "whoami",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Whoami {
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: Some(PathBuf::from("ci.npmrc")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--scope",
            "@demo",
            "login",
            "--auth-type=legacy",
            "--token",
            "npm_abc123",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Login {
            action: NpmLoginAction {
                scope: Some("@demo".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                token: Some("npm_abc123".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["adduser", "--scope=demo", "--auth-token=npm_xyz"]))
            .unwrap(),
        NpmCompatAction::Login {
            action: NpmLoginAction {
                scope: Some("demo".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                token: Some("npm_xyz".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--scope",
            "@demo",
            "logout",
            "--loglevel=silent",
        ]))
        .unwrap(),
        NpmCompatAction::Logout {
            action: NpmLogoutAction {
                scope: Some("@demo".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["logout", "--scope=demo"])).unwrap(),
        NpmCompatAction::Logout {
            action: NpmLogoutAction {
                scope: Some("demo".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "token",
            "list",
            "--parseable",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::List {
                json: true,
                parseable: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "token",
            "revoke",
            "a1b2c3",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::Revoke {
                token: "a1b2c3".to_owned(),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "token",
            "create",
            "--password",
            "correct-horse",
            "--name=ci-publish",
            "--token-description",
            "publish from CI",
            "--expires=30",
            "--packages=@demo/pkg",
            "--packages-all=false",
            "--scopes",
            "@demo",
            "--orgs=demo-org",
            "--packages-and-scopes-permission=read-write",
            "--orgs-permission",
            "read-only",
            "--cidr=192.0.2.0/24,198.51.100.0/24",
            "--bypass-2fa",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::Create {
                options: Box::new(NpmTokenCreateOptions {
                    password: Some("correct-horse".to_owned()),
                    name: Some("ci-publish".to_owned()),
                    description: Some("publish from CI".to_owned()),
                    expires: Some(30),
                    packages: vec!["@demo/pkg".to_owned()],
                    packages_all: false,
                    scopes: vec!["@demo".to_owned()],
                    orgs: vec!["demo-org".to_owned()],
                    packages_and_scopes_permission: Some("read-write".to_owned()),
                    orgs_permission: Some("read-only".to_owned()),
                    cidr: vec!["192.0.2.0/24".to_owned(), "198.51.100.0/24".to_owned()],
                    bypass_2fa: true,
                    read_only: false,
                }),
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--password=correct-horse",
            "--name",
            "ci-publish",
            "token",
            "create",
        ]))
        .unwrap(),
        NpmCompatAction::Token {
            action: NpmTokenAction::Create {
                options: Box::new(NpmTokenCreateOptions {
                    password: Some("correct-horse".to_owned()),
                    name: Some("ci-publish".to_owned()),
                    ..NpmTokenCreateOptions::default()
                }),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["token", "create", "--cidr=2001:db8::/32"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "trust",
            "list",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Trust {
            action: NpmTrustAction::List {
                package: Some("@demo/pkg".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--dry-run",
            "trust",
            "github",
            "@demo/pkg",
            "--file",
            "release.yml",
            "--repo",
            "turenio/omc",
            "--env=prod",
        ]))
        .unwrap(),
        NpmCompatAction::Trust {
            action: NpmTrustAction::Create {
                provider: NpmTrustProvider::GitHub,
                package: Some("@demo/pkg".to_owned()),
                config: serde_json::json!({
                    "type": "github",
                    "claims": {
                        "repository": "turenio/omc",
                        "workflow_ref": {
                            "file": "release.yml",
                        },
                        "environment": "prod",
                    },
                }),
                dry_run: true,
                json: true,
                yes: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "profile",
            "get",
            "name,email",
            "github",
        ]))
        .unwrap(),
        NpmCompatAction::Profile {
            action: NpmProfileAction::Get {
                keys: vec!["name,email".to_owned(), "github".to_owned()],
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--parseable",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "--otp",
            "123456",
            "profile",
            "set",
            "fullname",
            "Alice",
            "Example",
        ]))
        .unwrap(),
        NpmCompatAction::Profile {
            action: NpmProfileAction::Set {
                property: "fullname".to_owned(),
                value: "Alice Example".to_owned(),
                json: false,
                parseable: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["profile", "set", "name", "alice"])).is_err());
    assert!(parse_npm_compat_action(&args(&["profile", "enable-2fa"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "owner",
            "ls",
            "left-pad",
        ]))
        .unwrap(),
        NpmCompatAction::Owner {
            action: NpmOwnerAction::List {
                spec: Some("left-pad".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "--otp",
            "123456",
            "owner",
            "add",
            "alice",
            "@scope/pkg",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Owner {
            action: NpmOwnerAction::Add {
                user: "alice".to_owned(),
                spec: Some("@scope/pkg".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["owner", "rm", "alice", "left-pad"])).unwrap(),
        NpmCompatAction::Owner {
            action: NpmOwnerAction::Remove {
                user: "alice".to_owned(),
                spec: Some("left-pad".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["owner", "add"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "access",
            "list",
            "packages",
            "@demo:publishers",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::ListPackages {
                owner: Some("@demo:publishers".to_owned()),
                package: Some("@demo/pkg".to_owned()),
                json: true,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "ls-collaborators", "@demo/pkg", "alice"]))
            .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::ListCollaborators {
                package: Some("@demo/pkg".to_owned()),
                user: Some("alice".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "get", "status", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::GetStatus {
                package: Some("@demo/pkg".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--otp=123456",
            "access",
            "set",
            "status=public",
            "@demo/pkg",
            "--json",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::SetStatus {
                package: Some("@demo/pkg".to_owned()),
                status: "public".to_owned(),
                json: true,
                npm_registry: None,
                userconfig: None,
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "restricted", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::SetStatus {
                package: Some("@demo/pkg".to_owned()),
                status: "private".to_owned(),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["access", "set", "mfa=automation", "@demo/pkg"])).unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::SetMfa {
                package: Some("@demo/pkg".to_owned()),
                level: "automation".to_owned(),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "access",
            "grant",
            "read-write",
            "@demo:publishers",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::Grant {
                permission: "read-write".to_owned(),
                scope_team: "@demo:publishers".to_owned(),
                package: Some("@demo/pkg".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "access",
            "revoke",
            "@demo:publishers",
            "@demo/pkg",
        ]))
        .unwrap(),
        NpmCompatAction::Access {
            action: NpmAccessAction::Revoke {
                scope_team: "@demo:publishers".to_owned(),
                package: Some("@demo/pkg".to_owned()),
                json: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["access", "grant", "write"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "org",
            "set",
            "@demo",
            "alice",
            "admin",
        ]))
        .unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::Set {
                org: "@demo".to_owned(),
                user: "alice".to_owned(),
                role: Some("admin".to_owned()),
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["org", "add", "demo", "bob", "--parseable",])).unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::Set {
                org: "demo".to_owned(),
                user: "bob".to_owned(),
                role: None,
                json: false,
                parseable: true,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["org", "rm", "demo", "alice"])).unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::Remove {
                org: "demo".to_owned(),
                user: "alice".to_owned(),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["org", "ls", "demo", "alice"])).unwrap(),
        NpmCompatAction::Org {
            action: NpmOrgAction::List {
                org: "demo".to_owned(),
                user: Some("alice".to_owned()),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["org", "set", "demo", "alice", "writer"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--json",
            "--registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
            "--otp",
            "123456",
            "team",
            "create",
            "@demo:publishers",
        ]))
        .unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::Create {
                scope_team: "@demo:publishers".to_owned(),
                json: true,
                parseable: false,
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "team",
            "add",
            "@demo:publishers",
            "alice",
            "--parseable",
        ]))
        .unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::Add {
                scope_team: "@demo:publishers".to_owned(),
                user: "alice".to_owned(),
                json: false,
                parseable: true,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["team", "rm", "@demo:publishers", "alice"])).unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::Remove {
                scope_team: "@demo:publishers".to_owned(),
                user: "alice".to_owned(),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["team", "ls", "@demo:publishers"])).unwrap(),
        NpmCompatAction::Team {
            action: NpmTeamAction::List {
                scope_or_team: "@demo:publishers".to_owned(),
                json: false,
                parseable: false,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["team", "add", "@demo:publishers"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "dist-tag",
            "ls",
            "left-pad",
            "--json",
            "--workspace",
            "@demo/app",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::List {
                spec: Some("left-pad".to_owned()),
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["dist-tags", "react"])).unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::List {
                spec: Some("react".to_owned()),
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["dist-tag"])).unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::List {
                spec: None,
                npm_registry: None,
                userconfig: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig",
            "ci.npmrc",
            "--otp",
            "123456",
            "dist-tag",
            "add",
            "left-pad@1.3.0",
            "beta",
        ]))
        .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::Add {
                spec: "left-pad@1.3.0".to_owned(),
                tag: "beta".to_owned(),
                npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
                userconfig: Some(PathBuf::from("ci.npmrc")),
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["dist-tag", "add", "left-pad@1.3.0", "--tag=next",]))
            .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::Add {
                spec: "left-pad@1.3.0".to_owned(),
                tag: "next".to_owned(),
                npm_registry: None,
                userconfig: None,
                otp: None,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "dist-tag",
            "rm",
            "left-pad",
            "beta",
            "--otp=123456",
        ]))
        .unwrap(),
        NpmCompatAction::DistTag {
            action: NpmDistTagAction::Remove {
                spec: "left-pad".to_owned(),
                tag: "beta".to_owned(),
                npm_registry: None,
                userconfig: None,
                otp: Some("123456".to_owned()),
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "sbom",
            "--sbom-format=cyclonedx",
            "--sbom-type",
            "application",
            "--package-lock-only",
            "--omit=dev",
            "--workspace",
            "@demo/app",
        ]))
        .unwrap(),
        NpmCompatAction::Sbom {
            action: NpmSbomAction {
                format: NpmSbomFormat::CycloneDx,
                sbom_type: NpmSbomType::Application,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["--json", "sbom", "--sbom-format", "spdx"])).unwrap(),
        NpmCompatAction::Sbom {
            action: NpmSbomAction {
                format: NpmSbomFormat::Spdx,
                sbom_type: NpmSbomType::Library,
            },
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "--sbom-format",
            "spdx",
            "--sbom-type=framework",
            "sbom",
        ]))
        .unwrap(),
        NpmCompatAction::Sbom {
            action: NpmSbomAction {
                format: NpmSbomFormat::Spdx,
                sbom_type: NpmSbomType::Framework,
            },
        }
    );
    assert!(parse_npm_compat_action(&args(&["sbom"])).is_err());
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "view",
            "left-pad@1.3.0",
            "version",
            "dist.tarball",
            "--json",
            "--registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::View {
            spec: "left-pad@1.3.0".to_owned(),
            fields: vec!["version".to_owned(), "dist.tarball".to_owned()],
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["info", "@scope/pkg", "versions"])).unwrap(),
        NpmCompatAction::View {
            spec: "@scope/pkg".to_owned(),
            fields: vec!["versions".to_owned()],
            json: false,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "repo",
            "left-pad",
            "--browser=false",
            "--json",
            "--registry=https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::MetadataUrl {
            kind: NpmMetadataUrlKind::Repo,
            spec: Some("left-pad".to_owned()),
            json: true,
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["docs", "--browser=false"])).unwrap(),
        NpmCompatAction::MetadataUrl {
            kind: NpmMetadataUrlKind::Docs,
            spec: None,
            json: false,
            npm_registry: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "get",
            "registry",
            "--json",
            "--userconfig",
            "ci.npmrc",
            "--location=project",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Get {
                keys: vec!["registry".to_owned()],
                json: true,
                location: NpmConfigLocation::Project,
            },
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "get",
            "prefix",
            "--registry",
            "https://registry.example.invalid/npm",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Get {
                keys: vec!["prefix".to_owned()],
                json: false,
                location: NpmConfigLocation::User,
            },
            npm_registry: Some("https://registry.example.invalid/npm".to_owned()),
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["config", "list", "--json", "--long"])).unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::List {
                json: true,
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "edit",
            "--location=project",
            "--editor",
            "true",
        ]))
        .unwrap(),
        NpmCompatAction::ConfigEdit {
            location: NpmConfigLocation::Project,
            editor: Some("true".to_owned()),
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "--location=project",
            "--editor=true",
            "edit",
        ]))
        .unwrap(),
        NpmCompatAction::ConfigEdit {
            location: NpmConfigLocation::Project,
            editor: Some("true".to_owned()),
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["config", "set", "registry", "x"])).unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![("registry".to_owned(), "x".to_owned())],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "set",
            "registry",
            "https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![(
                    "registry".to_owned(),
                    "https://registry.example.invalid/npm".to_owned(),
                )],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "set",
            "@scope:registry=https://registry.example.invalid/npm",
            "--userconfig=ci.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![(
                    "@scope:registry".to_owned(),
                    "https://registry.example.invalid/npm".to_owned(),
                )],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: Some(PathBuf::from("ci.npmrc")),
            globalconfig: None,
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&[
            "config",
            "set",
            "registry",
            "https://global.example.invalid/npm",
            "--location=global",
            "--globalconfig",
            "global.npmrc",
        ]))
        .unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Set {
                assignments: vec![(
                    "registry".to_owned(),
                    "https://global.example.invalid/npm".to_owned(),
                )],
                location: NpmConfigLocation::Global,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: Some(PathBuf::from("global.npmrc")),
        }
    );
    assert_eq!(
        parse_npm_compat_action(&args(&["config", "delete", "registry"])).unwrap(),
        NpmCompatAction::Config {
            action: NpmConfigAction::Delete {
                keys: vec!["registry".to_owned()],
                location: NpmConfigLocation::User,
            },
            npm_registry: None,
            userconfig: None,
            globalconfig: None,
        }
    );
}
