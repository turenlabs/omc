//! `config` domain tests, extracted from the original monolithic tests.rs.

use super::*;

#[test]
fn applies_pypi_environment_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = LinkOptions::new(dir.path());
    apply_pypi_environment_values(
            &mut options,
            dir.path(),
            PypiEnvironmentValues {
                index_url: Some("https://env.example/simple"),
                extra_index_urls: Some(
                    "https://extra.example/simple 'https://quoted.example/simple' https://extra.example/simple",
                ),
                find_links: Some("./wheelhouse https://files.example/packages"),
                requirement_files: None,
                constraint_files: None,
                no_binary: Some(":all:"),
                only_binary: Some("idna"),
                all_releases: Some("previewed"),
                only_final: Some("stable-only"),
                uploaded_prior_to: Some("P7D"),
                no_index: true,
                allow_prereleases: true,
                override_index: true,
            },
        );

    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://env.example/simple/")
    );
    assert_eq!(
        options.pypi_extra_index_urls,
        vec![
            "https://extra.example/simple/".to_owned(),
            "https://quoted.example/simple/".to_owned(),
        ]
    );
    assert_eq!(
        options.pypi_find_links,
        vec![
            dir.path()
                .join(".")
                .join("wheelhouse")
                .to_string_lossy()
                .into_owned(),
            "https://files.example/packages".to_owned(),
        ]
    );
    assert_eq!(options.pypi_binary_all, Some(PypiBinaryMode::Source));
    assert_eq!(
        options.pypi_binary_packages.get("idna"),
        Some(&PypiBinaryMode::Binary)
    );
    assert!(options.pypi_no_index);
    assert!(options.pypi_allow_prereleases);
    assert!(options
        .pypi_release_controls
        .all_releases
        .packages
        .contains("previewed"));
    assert!(options
        .pypi_release_controls
        .only_final
        .packages
        .contains("stable-only"));
    assert_eq!(options.pypi_uploaded_prior_to.as_deref(), Some("P7D"));

    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            index_url: Some("https://ignored.example/simple"),
            extra_index_urls: Some("https://another.example/simple"),
            find_links: Some("./wheelhouse"),
            ..PypiEnvironmentValues::default()
        },
    );
    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://env.example/simple/")
    );
    assert_eq!(
        options.pypi_extra_index_urls,
        vec![
            "https://extra.example/simple/".to_owned(),
            "https://quoted.example/simple/".to_owned(),
            "https://another.example/simple/".to_owned(),
        ]
    );

    let mut options = LinkOptions::new(dir.path());
    options.pypi_index_url = Some("https://pip-config.example/simple/".to_owned());
    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            override_index: true,
            ..PypiEnvironmentValues::default()
        },
    );
    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://pip-config.example/simple/")
    );
    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            index_url: Some("https://env-override.example/simple"),
            override_index: true,
            ..PypiEnvironmentValues::default()
        },
    );
    assert_eq!(
        options.pypi_index_url.as_deref(),
        Some("https://env-override.example/simple/")
    );
}

#[test]
fn applies_pypi_environment_requirement_and_constraint_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("requirements")).unwrap();
    fs::create_dir_all(dir.path().join("constraints")).unwrap();
    fs::write(
        dir.path().join("requirements").join("base.txt"),
        "idna>=2\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("requirements").join("dev.txt"),
        "certifi==2024.2.2\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("constraints").join("prod constraints.txt"),
        "idna==3.7\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("constraints").join("base.txt"),
        "certifi==2024.2.2\n",
    )
    .unwrap();

    let mut options = LinkOptions::new(dir.path());
    apply_pypi_environment_values(
        &mut options,
        dir.path(),
        PypiEnvironmentValues {
            requirement_files: Some(
                "requirements/base.txt requirements/dev.txt requirements/base.txt",
            ),
            constraint_files: Some("'constraints/prod constraints.txt' constraints/base.txt"),
            ..PypiEnvironmentValues::default()
        },
    );

    assert_eq!(
        options.requirement_files,
        vec![
            dir.path().join("requirements").join("base.txt"),
            dir.path().join("requirements").join("dev.txt"),
        ]
    );
    assert_eq!(
        options.constraint_files,
        vec![
            dir.path().join("constraints").join("prod constraints.txt"),
            dir.path().join("constraints").join("base.txt"),
        ]
    );

    let specs = project_requested_specs(&mut options, false).unwrap();
    assert!(has_spec(&specs, "idna", ">=2"));
    assert!(has_spec(&specs, "certifi", "==2024.2.2"));
    assert_eq!(
        options.constraints.get("pypi:idna").map(String::as_str),
        Some("==3.7")
    );
    assert_eq!(
        options.constraints.get("pypi:certifi").map(String::as_str),
        Some("==2024.2.2")
    );
}

#[test]
fn parses_pip_config_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = PipConfig::default();
    parse_pip_config_content(
        r#"
            [global]
            index-url = https://global.example/simple
            extra-index-url = https://extra.example/simple 'https://quoted.example/simple'
            find-links = ./wheelhouse
            requirement = requirements/base.txt 'requirements/dev requirements.txt'
            constraint = constraints/base.txt

            [install]
            extra-index-url =
                https://install-extra.example/simple
                https://extra.example/simple
            find-links =
                https://files.example/packages
                ./wheelhouse
            constraint =
                constraints/prod.txt
                constraints/base.txt
            no-binary = :all:
            only-binary = idna
            no-index = true
            pre = true
            all-releases = previewed
            only-final = stable-only
            uploaded-prior-to = P3D

            [download]
            index-url = https://ignored.example/simple
            "#,
        dir.path(),
        &mut config,
    );

    assert_eq!(
        config.index_url.as_deref(),
        Some("https://global.example/simple/")
    );
    assert_eq!(
        config.extra_index_urls,
        vec![
            "https://extra.example/simple/".to_owned(),
            "https://quoted.example/simple/".to_owned(),
            "https://install-extra.example/simple/".to_owned(),
        ]
    );
    assert_eq!(
        config.find_links,
        vec![
            dir.path()
                .join(".")
                .join("wheelhouse")
                .to_string_lossy()
                .into_owned(),
            "https://files.example/packages".to_owned(),
        ]
    );
    assert_eq!(
        config.requirement_files,
        vec![
            dir.path().join("requirements").join("base.txt"),
            dir.path().join("requirements").join("dev requirements.txt"),
        ]
    );
    assert_eq!(
        config.constraint_files,
        vec![
            dir.path().join("constraints").join("base.txt"),
            dir.path().join("constraints").join("prod.txt"),
        ]
    );
    assert_eq!(config.binary_all, Some(PypiBinaryMode::Source));
    assert_eq!(
        config.binary_packages.get("idna"),
        Some(&PypiBinaryMode::Binary)
    );
    assert!(config.no_index);
    assert!(config.allow_prereleases);
    assert!(config
        .release_controls
        .all_releases
        .packages
        .contains("previewed"));
    assert!(config
        .release_controls
        .only_final
        .packages
        .contains("stable-only"));
    assert_eq!(config.uploaded_prior_to.as_deref(), Some("P3D"));
}

#[test]
fn reads_xdg_and_project_relative_pip_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    let home = dir.path().join("home");
    let xdg = dir.path().join("xdg");
    fs::create_dir_all(project.join("ci")).unwrap();
    fs::create_dir_all(home.join(".config").join("pip")).unwrap();
    fs::create_dir_all(xdg.join("pip")).unwrap();

    fs::write(
            xdg.join("pip").join("pip.conf"),
            "[global]\nextra-index-url = https://xdg-extra.example/simple\nfind-links = ./xdg-wheelhouse\n",
        )
        .unwrap();
    fs::write(
        project.join("pip.conf"),
        "[global]\nindex-url = https://project.example/simple\n",
    )
    .unwrap();
    fs::write(
            project.join("ci").join("pip.conf"),
            "[global]\nindex-url = https://override.example/simple\nconstraint = constraints/prod.txt\n",
        )
        .unwrap();

    with_env_values(
        &[
            ("HOME", Some(home.to_str().unwrap())),
            ("XDG_CONFIG_HOME", Some(xdg.to_str().unwrap())),
            ("PIP_CONFIG_FILE", Some("ci/pip.conf")),
        ],
        || {
            let config = read_pip_config(&project).unwrap();
            assert_eq!(
                config.index_url.as_deref(),
                Some("https://override.example/simple/")
            );
            assert!(config
                .extra_index_urls
                .contains(&"https://xdg-extra.example/simple/".to_owned()));
            assert!(config.find_links.contains(
                &xdg.join("pip")
                    .join(".")
                    .join("xdg-wheelhouse")
                    .to_string_lossy()
                    .into_owned()
            ));
            assert!(config
                .constraint_files
                .contains(&project.join("ci").join("constraints").join("prod.txt")));
        },
    );
}
