use super::*;
use crate::*;

#[test]
fn detects_direct_compat_binaries() {
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/node").as_os_str())),
        Some(DirectCompatMode::Node)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/npm").as_os_str())),
        Some(DirectCompatMode::Npm)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/npx").as_os_str())),
        Some(DirectCompatMode::Npx)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/pip3").as_os_str())),
        Some(DirectCompatMode::Pip)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/python").as_os_str())),
        Some(DirectCompatMode::Python)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/python3").as_os_str())),
        Some(DirectCompatMode::Python)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/twine").as_os_str())),
        Some(DirectCompatMode::Twine)
    );
    assert_eq!(
        direct_compat_mode(Some(Path::new("/tmp/omc").as_os_str())),
        None
    );
}

#[test]
fn parses_compile_command_and_infers_source_metadata() {
    let cli = Cli::try_parse_from(args(&[
        "omc",
        "compile",
        "--npm",
        "--name",
        "date-helper",
        "--version",
        "1.2.4",
        "--output",
        "dist/date-helper.omc.json",
        "--store",
        "--allow",
        "env:NPM_TOKEN",
        "--allow-flow",
        "env:NPM_TOKEN->network:api.example.com",
        "src/index.js",
    ]))
    .unwrap();

    match cli.command {
        Command::Compile {
            npm,
            pypi,
            source,
            name,
            version,
            output,
            store,
            allow,
            allow_flow,
            allow_all_host,
        } => {
            assert!(npm);
            assert!(!pypi);
            assert_eq!(source, PathBuf::from("src/index.js"));
            assert_eq!(name.as_deref(), Some("date-helper"));
            assert_eq!(version, "1.2.4");
            assert_eq!(output, Some(PathBuf::from("dist/date-helper.omc.json")));
            assert!(store);
            assert_eq!(allow, vec!["env:NPM_TOKEN"]);
            assert_eq!(allow_flow, vec!["env:NPM_TOKEN->network:api.example.com"]);
            assert!(!allow_all_host);
        }
        other => panic!("expected compile command, got {other:?}"),
    }

    let dir = test_dir("compile-infer");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("package.json"), "{}").unwrap();
    assert_eq!(
        infer_compile_ecosystem(&dir, false, false).unwrap(),
        Ecosystem::Npm
    );
    fs::remove_file(dir.join("package.json")).unwrap();
    fs::write(dir.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
    assert_eq!(
        infer_compile_ecosystem(&dir, false, false).unwrap(),
        Ecosystem::Pypi
    );
    assert_eq!(
        compile_source_default_name(Path::new("pkg-1.0.0.tar.gz")),
        "pkg-1.0.0"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn run_and_script_forward_help_flags_to_targets() {
    let cli = Cli::try_parse_from(args(&["omc", "run", "rich", "--help"])).unwrap();
    match cli.command {
        Command::Run {
            command,
            args: command_args,
        } => {
            assert_eq!(command, "rich");
            assert_eq!(command_args, args(&["--help"]));
        }
        other => panic!("expected run command, got {other:?}"),
    }

    let cli = Cli::try_parse_from(args(&["omc", "script", "build", "--help"])).unwrap();
    match cli.command {
        Command::Script {
            name,
            args: script_args,
        } => {
            assert_eq!(name, "build");
            assert_eq!(script_args, args(&["--help"]));
        }
        other => panic!("expected script command, got {other:?}"),
    }
}

#[test]
fn relative_project_paths_resolve_user_paths_from_current_directory() {
    let vendor = pip_rooted_project_path(Path::new("."), None, PathBuf::from("vendor"));

    assert!(vendor.is_absolute());
    assert_eq!(
        vendor.file_name().and_then(|name| name.to_str()),
        Some("vendor")
    );
}

#[test]
fn parses_direct_compat_project_dir_prefix() {
    let cwd = env::current_dir().unwrap();
    let npm_root = test_dir("direct-compat-npm-root");
    let npm_workspace = npm_root.join("packages").join("lib");
    let npm_nested = npm_workspace.join("src");
    fs::create_dir_all(&npm_nested).unwrap();
    fs::write(npm_root.join("package.json"), r#"{"name":"root"}"#).unwrap();
    fs::write(
        npm_workspace.join("package.json"),
        r#"{"name":"@demo/lib"}"#,
    )
    .unwrap();
    assert_eq!(
        discover_direct_compat_project_dir_from(DirectCompatMode::Npm, &npm_nested),
        Some(npm_workspace.clone())
    );

    let pip_root = test_dir("direct-compat-pip-root");
    let pip_nested = pip_root.join("src").join("demo");
    fs::create_dir_all(&pip_nested).unwrap();
    fs::write(
        pip_root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    assert_eq!(
        discover_direct_compat_project_dir_from(DirectCompatMode::Pip, &pip_nested),
        Some(pip_root.clone())
    );
    assert_eq!(
        discover_direct_compat_project_dir_from(
            DirectCompatMode::Python,
            &test_dir("direct-compat-no-root")
        ),
        None
    );

    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Npm,
            os_args(&["--project-dir", "/tmp/project", "install", "left-pad",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["install", "left-pad"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Pip,
            os_args(&["--omc-project-dir=/tmp/project", "show", "requests",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["show", "requests"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Npm,
            os_args(&["--prefix=/tmp/project", "test", "--", "--watch",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["test", "--", "--watch"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Npx,
            os_args(&["--prefix=/tmp/project", "eslint", "--", "."])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["eslint", "--", "."]),
        }
    );
    assert_eq!(
        npx_compat_args(args(&["eslint", "--", "."])),
        args(&["npx", "eslint", "--", "."])
    );
    assert_eq!(npx_compat_args(args(&["--version"])), args(&["--version"]));
    assert_eq!(npx_compat_args(args(&["-v"])), args(&["-v"]));
    assert_eq!(
        npm_project_dir_from_prefix_args(
            Path::new("/tmp/root"),
            &args(&["install", "--prefix=packages/app", "left-pad"])
        )
        .unwrap(),
        (
            PathBuf::from("/tmp/root/packages/app"),
            args(&["install", "left-pad"]),
        )
    );
    assert_eq!(
        npm_project_dir_from_prefix_args(
            Path::new("/tmp/root"),
            &args(&["run", "build", "--", "--prefix", "script-arg"])
        )
        .unwrap(),
        (
            PathBuf::from("/tmp/root"),
            args(&["run", "build", "--", "--prefix", "script-arg"]),
        )
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Node,
            os_args(&["--omc-project-dir", "/tmp/project", "-e", "console.log(1)",])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["-e", "console.log(1)"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Python,
            os_args(&[
                "--omc-project-dir",
                "/tmp/project",
                "-m",
                "pip",
                "install",
                "requests",
            ])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd: cwd.clone(),
            args: args(&["-m", "pip", "install", "requests"]),
        }
    );
    assert_eq!(
        parse_direct_compat_invocation(
            DirectCompatMode::Twine,
            os_args(&[
                "--omc-project-dir",
                "/tmp/project",
                "upload",
                "--repository",
                "testpypi",
                "dist/pkg.whl",
            ])
        )
        .unwrap(),
        DirectCompatInvocation {
            project_dir: PathBuf::from("/tmp/project"),
            cwd,
            args: args(&["upload", "--repository", "testpypi", "dist/pkg.whl"]),
        }
    );
}
