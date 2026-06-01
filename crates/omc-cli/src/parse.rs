use std::fmt;
use std::path::Path;

use omc_registry::{
    parse_npm_direct_archive_reference, parse_pypi_direct_archive_reference, LinkOptions,
    OmcRegistryError, PackageSpec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmSemver {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

pub(crate) fn npm_next_version(
    current: &str,
    spec: &str,
    preid: Option<&str>,
) -> Result<String, OmcRegistryError> {
    let current = parse_npm_semver(current)?;
    let next = match spec {
        "major" => NpmSemver {
            major: current.major + 1,
            minor: 0,
            patch: 0,
            prerelease: None,
        },
        "minor" => NpmSemver {
            major: current.major,
            minor: current.minor + 1,
            patch: 0,
            prerelease: None,
        },
        "patch" => NpmSemver {
            major: current.major,
            minor: current.minor,
            patch: current.patch + 1,
            prerelease: None,
        },
        "premajor" => NpmSemver {
            major: current.major + 1,
            minor: 0,
            patch: 0,
            prerelease: Some(npm_initial_prerelease(preid)),
        },
        "preminor" => NpmSemver {
            major: current.major,
            minor: current.minor + 1,
            patch: 0,
            prerelease: Some(npm_initial_prerelease(preid)),
        },
        "prepatch" => NpmSemver {
            major: current.major,
            minor: current.minor,
            patch: current.patch + 1,
            prerelease: Some(npm_initial_prerelease(preid)),
        },
        "prerelease" | "pre" => npm_increment_prerelease(current, preid),
        exact => return normalize_npm_exact_version(exact),
    };
    Ok(next.to_string())
}

fn npm_initial_prerelease(preid: Option<&str>) -> String {
    match preid.filter(|value| !value.is_empty()) {
        Some(preid) => format!("{preid}.0"),
        None => "0".to_owned(),
    }
}

fn npm_increment_prerelease(mut version: NpmSemver, preid: Option<&str>) -> NpmSemver {
    if let Some(prerelease) = version.prerelease.as_deref() {
        let mut parts = prerelease.split('.').map(str::to_owned).collect::<Vec<_>>();
        if let Some(preid) = preid.filter(|value| !value.is_empty()) {
            if parts.first().is_none_or(|part| part != preid) {
                version.prerelease = Some(format!("{preid}.0"));
                return version;
            }
        }
        if let Some(last) = parts.last_mut() {
            if let Ok(number) = last.parse::<u64>() {
                *last = (number + 1).to_string();
                version.prerelease = Some(parts.join("."));
                return version;
            }
        }
        version.prerelease = Some(format!("{prerelease}.0"));
        return version;
    }
    version.patch += 1;
    version.prerelease = Some(npm_initial_prerelease(preid));
    version
}

fn normalize_npm_exact_version(value: &str) -> Result<String, OmcRegistryError> {
    Ok(parse_npm_semver(value)?.to_string())
}

pub(crate) fn parse_npm_semver(value: &str) -> Result<NpmSemver, OmcRegistryError> {
    let value = value.trim().trim_start_matches('v');
    let value = value.split_once('+').map(|(base, _)| base).unwrap_or(value);
    let (core, prerelease) = value
        .split_once('-')
        .map(|(core, prerelease)| (core, Some(prerelease.to_owned())))
        .unwrap_or((value, None));
    let mut parts = core.split('.');
    let major = parse_npm_version_number(parts.next(), value)?;
    let minor = parse_npm_version_number(parts.next(), value)?;
    let patch = parse_npm_version_number(parts.next(), value)?;
    if parts.next().is_some()
        || prerelease
            .as_deref()
            .is_some_and(|part| part.is_empty() || part.contains('+'))
    {
        return Err(invalid_npm_version(value));
    }
    Ok(NpmSemver {
        major,
        minor,
        patch,
        prerelease,
    })
}

pub(crate) fn parse_npm_version_number(
    value: Option<&str>,
    raw: &str,
) -> Result<u64, OmcRegistryError> {
    let Some(value) = value else {
        return Err(invalid_npm_version(raw));
    };
    if value.is_empty() || value.starts_with('-') {
        return Err(invalid_npm_version(raw));
    }
    value.parse().map_err(|_| invalid_npm_version(raw))
}

fn invalid_npm_version(value: &str) -> OmcRegistryError {
    OmcRegistryError::UnsupportedSpec(format!("invalid npm package version `{value}`"))
}

impl fmt::Display for NpmSemver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(prerelease) = &self.prerelease {
            write!(formatter, "-{prerelease}")?;
        }
        Ok(())
    }
}

pub(crate) fn parse_pip_archive_references(
    project_dir: &Path,
    references: &[String],
    options: &mut LinkOptions,
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    let mut specs = Vec::new();
    for reference in references {
        let Some((spec, hashes)) = parse_pypi_direct_archive_reference(reference, project_dir)?
        else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported direct PyPI archive `{reference}`"
            )));
        };
        if !hashes.is_empty() {
            options
                .hashes
                .entry(spec.package_key())
                .or_default()
                .extend(hashes);
        }
        specs.push(spec);
    }
    Ok(specs)
}

pub(crate) fn parse_npm_archive_references(
    project_dir: &Path,
    references: &[String],
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    let mut specs = Vec::new();
    for reference in references {
        let Some(spec) = parse_npm_direct_archive_reference(reference, project_dir)? else {
            return Err(OmcRegistryError::UnsupportedSpec(format!(
                "unsupported direct npm archive `{reference}`"
            )));
        };
        specs.push(spec);
    }
    Ok(specs)
}
