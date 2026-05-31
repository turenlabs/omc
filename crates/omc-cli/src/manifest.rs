//! Manifest spec helpers — parse/normalize package specs and dependency kinds
//! for init/add/remove operations against `omc.toml`.

use crate::*;

use omc_registry::{Ecosystem, ManifestDependencyKind, OmcRegistryError, PackageSpec};

pub(crate) fn parse_package_specs(
    specs: &[String],
    ecosystem_hint: Option<Ecosystem>,
) -> Result<Vec<PackageSpec>, OmcRegistryError> {
    specs
        .iter()
        .map(|spec| parse_package_spec(spec, ecosystem_hint))
        .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn parse_package_spec(
    spec: &str,
    ecosystem_hint: Option<Ecosystem>,
) -> Result<PackageSpec, OmcRegistryError> {
    if package_spec_has_ecosystem_prefix(spec) {
        return PackageSpec::parse(spec);
    }

    let Some(ecosystem) = ecosystem_hint else {
        return PackageSpec::parse(spec);
    };

    PackageSpec::parse(&format!("{ecosystem}:{spec}"))
}

pub(crate) fn package_spec_has_ecosystem_prefix(spec: &str) -> bool {
    spec.split_once(':')
        .map(|(prefix, _)| matches!(prefix, "npm" | "pypi" | "py" | "python"))
        .unwrap_or(false)
}

pub(crate) fn ecosystem_hint(npm: bool, pypi: bool) -> Option<Ecosystem> {
    if npm {
        Some(Ecosystem::Npm)
    } else if pypi {
        Some(Ecosystem::Pypi)
    } else {
        None
    }
}

pub(crate) fn dependency_kind_from_booleans(
    dev: bool,
    optional: bool,
    peer: bool,
) -> ManifestDependencyKind {
    if dev {
        ManifestDependencyKind::Dev
    } else if optional {
        ManifestDependencyKind::Optional
    } else if peer {
        ManifestDependencyKind::Peer
    } else {
        ManifestDependencyKind::Production
    }
}
