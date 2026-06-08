//! `pypi_install` domain tests, extracted from the original monolithic tests.rs.

use super::*;

#[test]
fn installs_explicit_requirement_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    let local = dir.path().join("vendor").join("localpkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("localpkg")).unwrap();
    fs::write(
        src.join("localpkg").join("__init__.py"),
        "VALUE = 'explicit'\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("requirements").join("prod.txt"),
        "-e ../vendor/localpkg\n",
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    options
        .requirement_files
        .push(dir.path().join("requirements").join("prod.txt"));
    let report = install_project(&options).unwrap();
    assert_eq!(report.pypi_packages, 0);

    let local_paths =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(
        local_paths.trim(),
        fs::canonicalize(src).unwrap().to_string_lossy()
    );
}

#[test]
fn applies_explicit_constraint_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("requirements.txt"), "idna>=2\n").unwrap();
    fs::write(dir.path().join("constraints.txt"), "idna==3.7\n").unwrap();

    let mut options = LinkOptions::new(dir.path());
    options
        .requirement_files
        .push(dir.path().join("requirements.txt"));
    options
        .constraint_files
        .push(dir.path().join("constraints.txt"));
    let specs = project_requested_specs(&mut options, false).unwrap();

    assert!(specs
        .iter()
        .any(|spec| spec.name == "idna" && spec.version.as_deref() == Some(">=2")));
    assert_eq!(
        options.constraints.get("pypi:idna").map(String::as_str),
        Some("==3.7")
    );
}

#[test]
fn installs_pure_python_sdist_archives() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = python_sdist_for_test(&[
        (
            "pyproject.toml",
            r#"
                [project]
                name = "pure-sdist"
                version = "1.0.0"

                [project.scripts]
                pure-sdist-cli = "puresdist.cli:main"
                "#,
        ),
        ("src/puresdist/__init__.py", "VALUE = 'sdist-ok'\n"),
        (
            "src/puresdist/cli.py",
            "from puresdist import VALUE\n\ndef main():\n    print(VALUE)\n",
        ),
    ]);
    let archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("pure-sdist-1.0.0.tar.gz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-sdist", "1.0.0");
    package.source_url = "https://example.invalid/pure-sdist-1.0.0.tar.gz".to_owned();
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    let report = install_lock(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(report.pypi_packages, 1);
    assert!(dir
        .path()
        .join(".omc/python/site-packages/puresdist/__init__.py")
        .exists());

    let output = Command::new(dir.path().join(".omc/python/bin/pure-sdist-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "sdist-ok");
}

#[test]
fn installs_pure_python_archives_into_target_directory() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = python_sdist_for_test(&[
        (
            "pyproject.toml",
            r#"
                [project]
                name = "pure-target"
                version = "1.0.0"

                [project.scripts]
                pure-target-cli = "puretarget.cli:main"
                "#,
        ),
        ("src/puretarget/__init__.py", "VALUE = 'target-ok'\n"),
        (
            "src/puretarget/cli.py",
            "from puretarget import VALUE\n\ndef main():\n    print(VALUE)\n",
        ),
    ]);
    let archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("pure-target-1.0.0.tar.gz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-target", "1.0.0");
    package.source_url = "https://example.invalid/pure-target-1.0.0.tar.gz".to_owned();
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    let target = dir.path().join("vendor");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("keep.txt"), "keep\n").unwrap();

    let report = install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        true,
        InstallMode::Clean,
    )
    .unwrap();
    assert_eq!(report.pypi_packages, 1);
    assert_eq!(report.python_site_packages, target);
    assert!(dir
        .path()
        .join("vendor")
        .join("puretarget")
        .join("__init__.py")
        .exists());
    assert!(dir.path().join("vendor").join("keep.txt").exists());

    let output = Command::new(dir.path().join("vendor/bin/pure-target-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "target-ok");
}

/// SECURITY regression: with `pip install --target <ABS>`, the python local-paths
/// marker resolves to `<ABS>/.omc-local-paths`. If a *directory* already exists
/// there (pre-existing user content), the pre-install marker cleanup must NOT
/// recursively delete it — only an OMC-written marker FILE is ever removed. Before
/// the fix this used `remove_path_if_exists`, which would `remove_dir_all` the
/// colliding directory and let `--target` wipe content under the user's dir.
#[test]
fn target_install_does_not_recursively_delete_external_local_paths_dir() {
    let dir = tempfile::tempdir().unwrap(); // project_dir
    let target_root = tempfile::tempdir().unwrap(); // external --target, OUTSIDE project_dir
    let target = target_root.path().to_path_buf();

    // A user directory colliding with the OMC marker name, holding content that
    // must survive the install.
    let marker_dir = target.join(".omc-local-paths");
    fs::create_dir_all(marker_dir.join("inner")).unwrap();
    fs::write(marker_dir.join("inner").join("victim.txt"), "do not delete\n").unwrap();

    let bytes = python_sdist_for_test(&[
        (
            "pyproject.toml",
            r#"
                [project]
                name = "ext-target"
                version = "1.0.0"
                "#,
        ),
        ("src/exttarget/__init__.py", "VALUE = 'ext-ok'\n"),
    ]);
    let archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("ext-target-1.0.0.tar.gz");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "ext-target", "1.0.0");
    package.source_url = "https://example.invalid/ext-target-1.0.0.tar.gz".to_owned();
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        true,
        InstallMode::Clean,
    )
    .unwrap();

    // The package still installed into the external target...
    assert!(target.join("exttarget").join("__init__.py").exists());
    // ...and the pre-existing user directory at the marker path is UNTOUCHED.
    assert!(
        marker_dir.join("inner").join("victim.txt").exists(),
        "content under an external .omc-local-paths directory must not be recursively deleted by --target"
    );
}

/// Unit test of the marker-removal invariant: removes regular files, never
/// recurses into a directory, and is a no-op when absent.
#[test]
fn remove_marker_file_if_present_never_recurses_into_directories() {
    let dir = tempfile::tempdir().unwrap();

    // A regular-file marker is removed.
    let file_marker = dir.path().join("local-paths");
    fs::write(&file_marker, "x").unwrap();
    remove_marker_file_if_present(&file_marker).unwrap();
    assert!(!file_marker.exists());

    // A directory at the marker path is left intact (never recursively deleted).
    let dir_marker = dir.path().join(".omc-local-paths");
    fs::create_dir_all(dir_marker.join("inner")).unwrap();
    fs::write(dir_marker.join("inner").join("keep.txt"), "keep").unwrap();
    remove_marker_file_if_present(&dir_marker).unwrap();
    assert!(dir_marker.join("inner").join("keep.txt").exists());

    // A missing path is a no-op.
    remove_marker_file_if_present(&dir.path().join("absent")).unwrap();
}

#[test]
fn target_upgrade_removes_stale_wheel_files() {
    let dir = tempfile::tempdir().unwrap();
    let old_wheel = python_package_wheel_for_test(
        "wheel-stale-pkg",
        "1.0.0",
        &[
            ("wheel_stale_pkg/__init__.py", "VALUE = 'old'\n"),
            ("wheel_stale_pkg/extra.py", "EXTRA = True\n"),
        ],
    );
    let new_wheel = python_package_wheel_for_test(
        "wheel-stale-pkg",
        "1.1.0",
        &[("wheel_stale_pkg/__init__.py", "VALUE = 'new'\n")],
    );
    let old_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("wheel_stale_pkg-1.0.0-py3-none-any.whl");
    let new_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("wheel_stale_pkg-1.1.0-py3-none-any.whl");
    fs::create_dir_all(old_archive.parent().unwrap()).unwrap();
    fs::write(&old_archive, &old_wheel).unwrap();
    fs::write(&new_archive, &new_wheel).unwrap();

    let mut old_package = locked_package_for_test(Ecosystem::Pypi, "wheel-stale-pkg", "1.0.0");
    old_package.source_url =
        "https://example.invalid/wheel_stale_pkg-1.0.0-py3-none-any.whl".to_owned();
    old_package.archive = relative_path(dir.path(), &old_archive);
    old_package.sha256 = sha256_hex(&old_wheel);
    old_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &old_package);

    let mut new_package = locked_package_for_test(Ecosystem::Pypi, "wheel-stale-pkg", "1.1.0");
    new_package.source_url =
        "https://example.invalid/wheel_stale_pkg-1.1.0-py3-none-any.whl".to_owned();
    new_package.archive = relative_path(dir.path(), &new_archive);
    new_package.sha256 = sha256_hex(&new_wheel);
    new_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &new_package);

    let target = dir.path().join("vendor");
    install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![old_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        true,
        InstallMode::Clean,
    )
    .unwrap();
    install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![new_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        true,
        InstallMode::Clean,
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(target.join("wheel_stale_pkg").join("__init__.py")).unwrap(),
        "VALUE = 'new'\n"
    );
    assert!(!target.join("wheel_stale_pkg").join("extra.py").exists());
    assert!(target
        .join("wheel_stale_pkg-1.0.0.dist-info")
        .join("METADATA")
        .exists());
    assert!(target
        .join("wheel_stale_pkg-1.1.0.dist-info")
        .join("METADATA")
        .exists());
}

#[test]
fn target_no_upgrade_skips_scripts_when_bin_dir_exists() {
    let dir = tempfile::tempdir().unwrap();
    let old_wheel = python_package_wheel_with_entry_points_for_test(
        "script-stale-pkg",
        "1.0.0",
        &[(
            "script_stale_pkg/__init__.py",
            "def main():\n    print('ok')\n",
        )],
        "[console_scripts]\nold-cli = script_stale_pkg:main\n",
    );
    let new_wheel = python_package_wheel_with_entry_points_for_test(
        "script-stale-pkg",
        "1.1.0",
        &[(
            "script_stale_pkg/__init__.py",
            "def main():\n    print('ok')\n",
        )],
        "[console_scripts]\nnew-cli = script_stale_pkg:main\n",
    );
    let old_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("script_stale_pkg-1.0.0-py3-none-any.whl");
    let new_archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("script_stale_pkg-1.1.0-py3-none-any.whl");
    fs::create_dir_all(old_archive.parent().unwrap()).unwrap();
    fs::write(&old_archive, &old_wheel).unwrap();
    fs::write(&new_archive, &new_wheel).unwrap();

    let mut old_package = locked_package_for_test(Ecosystem::Pypi, "script-stale-pkg", "1.0.0");
    old_package.source_url =
        "https://example.invalid/script_stale_pkg-1.0.0-py3-none-any.whl".to_owned();
    old_package.archive = relative_path(dir.path(), &old_archive);
    old_package.sha256 = sha256_hex(&old_wheel);
    old_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &old_package);

    let mut new_package = locked_package_for_test(Ecosystem::Pypi, "script-stale-pkg", "1.1.0");
    new_package.source_url =
        "https://example.invalid/script_stale_pkg-1.1.0-py3-none-any.whl".to_owned();
    new_package.archive = relative_path(dir.path(), &new_archive);
    new_package.sha256 = sha256_hex(&new_wheel);
    new_package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &new_package);

    let target = dir.path().join("vendor");
    let report = install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![old_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        false,
        InstallMode::Clean,
    )
    .unwrap();
    assert_eq!(report.python_scripts, 1);
    assert!(target.join("bin").join("old-cli").exists());

    install_lock_with_python_target(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![new_package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
        Some(&target),
        None,
        false,
        InstallMode::Clean,
    )
    .unwrap();

    assert!(target.join("bin").join("old-cli").exists());
    assert!(!target.join("bin").join("new-cli").exists());
    assert!(target
        .join("script_stale_pkg-1.1.0.dist-info")
        .join("entry_points.txt")
        .exists());
}

#[test]
fn installs_pure_python_zip_sdist_archives() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = python_zip_sdist_for_test(&[
        (
            "pyproject.toml",
            r#"
                [project]
                name = "pure-sdist"
                version = "1.0.0"

                [project.scripts]
                pure-sdist-cli = "puresdist.cli:main"
                "#,
        ),
        ("src/puresdist/__init__.py", "VALUE = 'zip-sdist-ok'\n"),
        (
            "src/puresdist/cli.py",
            "from puresdist import VALUE\n\ndef main():\n    print(VALUE)\n",
        ),
    ]);
    let archive = dir
        .path()
        .join(".omc")
        .join("cache")
        .join("pure-sdist-1.0.0.zip");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, &bytes).unwrap();

    let mut package = locked_package_for_test(Ecosystem::Pypi, "pure-sdist", "1.0.0");
    package.source_url = "https://example.invalid/pure-sdist-1.0.0.zip".to_owned();
    package.archive = relative_path(dir.path(), &archive);
    package.sha256 = sha256_hex(&bytes);
    package.artifact_sha256 = write_signed_artifact_for_test(dir.path(), &package);

    let report = install_lock(
        dir.path(),
        &OmcLock {
            version: 1,
            signing_key: Some(project_signing_public_key(dir.path()).unwrap()),
            packages: vec![package],
            local_sources: Vec::new(),
            python_vcs: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(report.pypi_packages, 1);

    let output = Command::new(dir.path().join(".omc/python/bin/pure-sdist-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "zip-sdist-ok"
    );
}

#[test]
fn reads_requirements_local_editable_paths() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    let file_url_pkg = dir.path().join("vendor/file-url-edit");
    let file_url = reqwest::Url::from_directory_path(&file_url_pkg)
        .unwrap()
        .to_string();
    fs::write(
        &requirements,
        format!("-e .\n--editable ./vendor/pkg[dev]\n-e {file_url}\n"),
    )
    .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert_eq!(
        discovered.python_local_requirements,
        vec![
            PythonLocalRequirement::new(dir.path().join("."), BTreeSet::new()),
            PythonLocalRequirement::new(
                dir.path().join("./vendor/pkg"),
                BTreeSet::from(["dev".to_owned()])
            ),
            PythonLocalRequirement::new(file_url_pkg, BTreeSet::new())
        ]
    );

    let project = discover_project_requirements(dir.path()).unwrap();
    assert_eq!(
        project.python_local_requirements,
        discovered.python_local_requirements
    );
}

#[test]
fn reads_requirements_local_direct_paths() {
    let dir = tempfile::tempdir().unwrap();
    let requirements = dir.path().join("requirements.txt");
    let local_pkg = dir.path().join("vendor/local-pkg");
    let file_url_pkg = dir.path().join("vendor/file-url-pkg");
    let bare_pkg = dir.path().join("vendor/bare-pkg");
    let bare_file_url_pkg = dir.path().join("vendor/bare-file-url-pkg");
    fs::create_dir_all(&local_pkg).unwrap();
    fs::create_dir_all(&file_url_pkg).unwrap();
    fs::create_dir_all(&bare_pkg).unwrap();
    fs::create_dir_all(&bare_file_url_pkg).unwrap();
    let file_url = reqwest::Url::from_directory_path(&file_url_pkg)
        .unwrap()
        .to_string();
    let bare_file_url = reqwest::Url::from_directory_path(&bare_file_url_pkg)
        .unwrap()
        .to_string();
    fs::write(
            &requirements,
            format!(
                "local-pkg @ file:./vendor/local-pkg\nfile-url-pkg @ {file_url}\nlink:./vendor/bare-pkg[dev]\n{bare_file_url}\n./missing-bare; sys_platform == 'win32'\nskipped-local @ ./missing; sys_platform == 'definitely-not' and (python_version < '0' or python_version >= '3')\n"
            ),
        )
        .unwrap();

    let discovered = read_requirements_file(&requirements).unwrap();
    assert!(discovered.python_local_requirements.is_empty());
    assert_eq!(
        discovered.python_local_directory_requirements,
        vec![
            PythonLocalRequirement::new(local_pkg, BTreeSet::new()),
            PythonLocalRequirement::new(file_url_pkg, BTreeSet::new()),
            PythonLocalRequirement::new(bare_pkg, BTreeSet::from(["dev".to_owned()])),
            PythonLocalRequirement::new(bare_file_url_pkg, BTreeSet::new())
        ]
    );

    let project = discover_project_requirements(dir.path()).unwrap();
    assert_eq!(
        project.python_local_directory_requirements,
        discovered.python_local_directory_requirements
    );
}

#[test]
fn installs_python_vcs_requirement_as_local_path() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("gitpkg-repo");
    let src = repo.join("src").join("gitpkg");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("__init__.py"), "").unwrap();
    fs::write(src.join("cli.py"), "def main():\n    print('git-vcs-ok')\n").unwrap();
    fs::write(
        repo.join("pyproject.toml"),
        r#"
            [project]
            name = "gitpkg"

            [project.scripts]
            git-vcs-cli = "gitpkg.cli:main"
            "#,
    )
    .unwrap();
    commit_git_repo(&repo);

    let project = dir.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let repo_url = reqwest::Url::from_directory_path(&repo)
        .unwrap()
        .to_string();
    fs::write(
        project.join("requirements.txt"),
        format!("gitpkg @ git+{repo_url}@HEAD\n"),
    )
    .unwrap();

    let requirements =
        discover_project_requirements_with_options(&project, &BTreeSet::new(), false).unwrap();
    assert_eq!(requirements.python_vcs_requirements.len(), 1);

    let report = install_project(&LinkOptions::new(&project)).unwrap();
    assert_eq!(report.python_scripts, 1);
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert_eq!(lock.python_vcs.len(), 1);
    assert_eq!(lock.python_vcs[0].name, "gitpkg");
    assert_eq!(lock.python_vcs[0].reference.as_deref(), Some("HEAD"));
    assert!(is_git_commit_hash(&lock.python_vcs[0].resolved_commit));
    assert!(lock.python_vcs[0].archive.ends_with(".tar.gz"));
    assert!(project.join(&lock.python_vcs[0].archive).exists());
    assert_eq!(lock.python_vcs[0].sha256.len(), 64);
    let local_paths = fs::read_to_string(project.join(".omc/python/local-paths")).unwrap();
    assert!(local_paths.contains(".omc/python/vcs/gitpkg/"));

    let output = Command::new(project.join(".omc/python/bin/git-vcs-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "git-vcs-ok");
}

#[test]
fn locked_python_vcs_install_uses_pinned_commit() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("gitpkg-repo");
    let src = repo.join("src").join("gitpkg");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("__init__.py"), "").unwrap();
    fs::write(src.join("cli.py"), "def main():\n    print('v1')\n").unwrap();
    fs::write(
        repo.join("pyproject.toml"),
        r#"
            [project]
            name = "gitpkg"

            [project.scripts]
            git-vcs-cli = "gitpkg.cli:main"
            "#,
    )
    .unwrap();
    commit_git_repo(&repo);
    let first_commit = git_rev_parse_head(&repo, "gitpkg").unwrap();

    let project = dir.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let repo_url = reqwest::Url::from_directory_path(&repo)
        .unwrap()
        .to_string();
    fs::write(
        project.join("requirements.txt"),
        format!("gitpkg @ git+{repo_url}@HEAD\n"),
    )
    .unwrap();

    install_project(&LinkOptions::new(&project)).unwrap();
    let lock = read_lockfile(project.join("omc.lock")).unwrap();
    assert_eq!(lock.python_vcs.len(), 1);
    assert_eq!(lock.python_vcs[0].resolved_commit, first_commit);

    fs::write(src.join("cli.py"), "def main():\n    print('v2')\n").unwrap();
    assert!(Command::new("git")
        .arg("-C")
        .arg(&repo)
        .arg("add")
        .arg(".")
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .arg("-C")
        .arg(&repo)
        .arg("-c")
        .arg("user.email=omc@example.invalid")
        .arg("-c")
        .arg("user.name=omc test")
        .arg("commit")
        .arg("--quiet")
        .arg("-m")
        .arg("second")
        .status()
        .unwrap()
        .success());
    assert_ne!(git_rev_parse_head(&repo, "gitpkg").unwrap(), first_commit);
    remove_path_if_exists(&repo).unwrap();
    remove_path_if_exists(&project.join(".omc/python/vcs")).unwrap();

    install_locked_project(&LinkOptions::new(&project)).unwrap();
    let output = Command::new(project.join(".omc/python/bin/git-vcs-cli"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "v1");
}

#[test]
fn locked_python_vcs_install_requires_lock_entry() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("requirements.txt"),
        "gitpkg @ git+https://example.invalid/gitpkg.git@main\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock::new()).unwrap(),
    )
    .unwrap();

    let error = install_locked_project(&LinkOptions::new(dir.path())).unwrap_err();
    assert!(matches!(error, OmcRegistryError::LockfileOutOfDate(_)));
}

#[test]
fn installs_editable_python_local_paths_preferring_src_layout() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("localpkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("localpkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("localpkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("localpkg").join("cli.py"),
        "def main():\n    print('local-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
            [project]
            name = "localpkg"

            [project.scripts]
            local-cli = "localpkg.cli:main"

            [project.gui-scripts]
            local-gui = "localpkg.gui:main"
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 2);

    let expected = fs::canonicalize(src).unwrap();
    let content =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(content.trim(), expected.to_string_lossy());
    let script = fs::read_to_string(bin_dir.join("local-cli")).unwrap();
    assert!(script.contains("from localpkg.cli import main"));
    let script = fs::read_to_string(bin_dir.join("local-gui")).unwrap();
    assert!(script.contains("from localpkg.gui import main"));

    let output = Command::new(bin_dir.join("local-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "local-cli-ok"
    );
}

#[test]
fn local_python_install_extras_resolve_optional_local_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    let local = dir.path().join("localpkg");
    let dep = dir.path().join("deppkg");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(local.join("src/localpkg")).unwrap();
    fs::create_dir_all(dep.join("src/deppkg")).unwrap();
    fs::write(
        local.join("pyproject.toml"),
        format!(
            r#"
                [project]
                name = "localpkg"
                version = "0.1.0"

                [project.optional-dependencies]
                dev = ["deppkg @ {}"]
                "#,
            dep.display()
        ),
    )
    .unwrap();
    fs::write(local.join("src/localpkg/__init__.py"), "VALUE = 'local'\n").unwrap();
    fs::write(
        dep.join("pyproject.toml"),
        r#"
            [project]
            name = "deppkg"
            version = "0.1.0"
            "#,
    )
    .unwrap();
    fs::write(dep.join("src/deppkg/__init__.py"), "VALUE = 'dep'\n").unwrap();

    let mut options = LinkOptions::new(&project);
    options
        .python_local_requirements
        .push(PythonLocalRequirement::new(
            local.clone(),
            BTreeSet::from(["dev".to_owned()]),
        ));
    let report = install_project(&options).unwrap();

    let local_paths =
        fs::read_to_string(project.join(".omc").join("python").join("local-paths")).unwrap();
    assert!(local_paths.contains(&local.join("src").to_string_lossy().to_string()));
    assert!(local_paths.contains(&dep.join("src").to_string_lossy().to_string()));
    assert_eq!(report.pypi_packages, 0);
}

#[test]
fn installs_setup_cfg_python_local_entry_points() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("setuppkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("setuppkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("setuppkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("setuppkg").join("cli.py"),
        "def main():\n    print('setup-cfg-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("setup.cfg"),
        r#"
            [metadata]
            name = setuppkg

            [options.entry_points]
            console_scripts =
                setup-cli = setuppkg.cli:main
            gui_scripts =
                setup-gui = setuppkg.gui:main
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 2);

    let script = fs::read_to_string(bin_dir.join("setup-cli")).unwrap();
    assert!(script.contains("from setuppkg.cli import main"));
    let script = fs::read_to_string(bin_dir.join("setup-gui")).unwrap();
    assert!(script.contains("from setuppkg.gui import main"));

    let output = Command::new(bin_dir.join("setup-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "setup-cfg-cli-ok"
    );
}

#[test]
fn installs_setup_py_python_local_entry_points() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("setuppkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("setuppkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("setuppkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("setuppkg").join("cli.py"),
        "def main():\n    print('setup-py-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("setup.py"),
        r#"
            from setuptools import setup

            NOTE = "entry_points={'console_scripts': ['ignored-string = ignored:main']}"
            # entry_points={"console_scripts": ["ignored-comment = ignored:main"]}

            setup(
                name="setuppkg",
                entry_points={
                    "console_scripts": [
                        "setup-cli = setuppkg.cli:main",
                    ],
                    "gui_scripts": ["setup-gui = setuppkg.gui:main"],
                    "pytest11": ["ignored = ignored:plugin"],
                },
            )
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 2);

    let script = fs::read_to_string(bin_dir.join("setup-cli")).unwrap();
    assert!(script.contains("from setuppkg.cli import main"));
    let script = fs::read_to_string(bin_dir.join("setup-gui")).unwrap();
    assert!(script.contains("from setuppkg.gui import main"));
    assert!(!bin_dir.join("ignored").exists());
    assert!(!bin_dir.join("ignored-string").exists());
    assert!(!bin_dir.join("ignored-comment").exists());

    let output = Command::new(bin_dir.join("setup-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "setup-py-cli-ok"
    );
}

#[test]
fn installs_root_python_project_as_local_path() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(src.join("rootpkg")).unwrap();
    fs::write(
        src.join("rootpkg").join("__init__.py"),
        "VALUE = 'root-ok'\n",
    )
    .unwrap();
    fs::write(
        src.join("rootpkg").join("cli.py"),
        "from rootpkg import VALUE\n\ndef main():\n    print(VALUE)\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        r#"
            [project]
            name = "rootpkg"
            version = "0.1.0"

            [project.scripts]
            root-cli = "rootpkg.cli:main"
            "#,
    )
    .unwrap();

    let report = install_project(&LinkOptions::new(dir.path())).unwrap();
    assert_eq!(report.python_scripts, 1);

    let expected = fs::canonicalize(src).unwrap();
    let content =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(content.trim(), expected.to_string_lossy());

    let output = Command::new(
        dir.path()
            .join(".omc")
            .join("python")
            .join("bin")
            .join("root-cli"),
    )
    .output()
    .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "root-ok");
}

#[test]
fn locked_install_restores_root_python_project_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(src.join("rootpkg")).unwrap();
    fs::write(
        src.join("rootpkg").join("__init__.py"),
        "VALUE = 'locked-root-ok'\n",
    )
    .unwrap();
    fs::write(
        src.join("rootpkg").join("cli.py"),
        "from rootpkg import VALUE\n\ndef main():\n    print(VALUE)\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        r#"
            [project]
            name = "rootpkg"
            version = "0.1.0"

            [project.scripts]
            root-cli = "rootpkg.cli:main"
            "#,
    )
    .unwrap();
    fs::write(
        dir.path().join("omc.lock"),
        toml::to_string_pretty(&OmcLock::new()).unwrap(),
    )
    .unwrap();

    let report = install_locked_packages(dir.path()).unwrap();
    assert_eq!(report.python_scripts, 1);

    let expected = fs::canonicalize(src).unwrap();
    let content =
        fs::read_to_string(dir.path().join(".omc").join("python").join("local-paths")).unwrap();
    assert_eq!(content.trim(), expected.to_string_lossy());

    let output = Command::new(
        dir.path()
            .join(".omc")
            .join("python")
            .join("bin")
            .join("root-cli"),
    )
    .output()
    .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "locked-root-ok"
    );
}

#[test]
fn installs_poetry_table_python_local_entry_points() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("poetrypkg");
    let src = local.join("src");
    fs::create_dir_all(src.join("poetrypkg")).unwrap();
    let site_packages = dir.path().join(".omc").join("python").join("site-packages");
    let bin_dir = dir.path().join(".omc").join("python").join("bin");
    fs::create_dir_all(&site_packages).unwrap();
    fs::write(src.join("poetrypkg").join("__init__.py"), "").unwrap();
    fs::write(
        src.join("poetrypkg").join("cli.py"),
        "def main():\n    print('poetry-table-cli-ok')\n",
    )
    .unwrap();
    fs::write(
        local.join("pyproject.toml"),
        r#"
            [tool.poetry]
            name = "poetrypkg"
            version = "0.1.0"

            [tool.poetry.scripts]
            poetry-cli = { callable = "poetrypkg.cli:main" }
            ignored-file = { reference = "scripts/run.py", type = "file" }
            "#,
    )
    .unwrap();

    let scripts =
        install_python_local_paths(std::slice::from_ref(&local), &site_packages, &bin_dir).unwrap();
    assert_eq!(scripts, 1);

    let script = fs::read_to_string(bin_dir.join("poetry-cli")).unwrap();
    assert!(script.contains("from poetrypkg.cli import main"));
    assert!(!bin_dir.join("ignored-file").exists());

    let output = Command::new(bin_dir.join("poetry-cli")).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "poetry-table-cli-ok"
    );
}
