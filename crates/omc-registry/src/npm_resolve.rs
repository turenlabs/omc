//! npm spec parse + registry resolution: npm packument/version data types.

use crate::*;

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct NpmRoot {
    #[serde(rename = "dist-tags")]
    pub(crate) dist_tags: NpmDistTags,
    #[serde(default)]
    pub(crate) time: BTreeMap<String, String>,
    pub(crate) versions: BTreeMap<String, NpmVersion>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NpmDistTags {
    pub(crate) latest: String,
    #[serde(flatten)]
    pub(crate) tags: BTreeMap<String, String>,
}

impl NpmDistTags {
    pub(crate) fn get(&self, tag: &str) -> Option<&str> {
        if tag == "latest" {
            Some(&self.latest)
        } else {
            self.tags.get(tag).map(String::as_str)
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct NpmVersion {
    pub(crate) version: String,
    pub(crate) dist: NpmDist,
    #[serde(default)]
    pub(crate) os: Option<NpmStringList>,
    #[serde(default)]
    pub(crate) cpu: Option<NpmStringList>,
    #[serde(default)]
    pub(crate) libc: Option<NpmStringList>,
    #[serde(default, deserialize_with = "deserialize_lenient_engines")]
    pub(crate) engines: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub(crate) scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub(crate) dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "optionalDependencies")]
    pub(crate) optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "bundleDependencies")]
    pub(crate) bundle_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "bundledDependencies")]
    pub(crate) bundled_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "peerDependencies")]
    pub(crate) peer_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "peerDependenciesMeta")]
    pub(crate) peer_dependencies_meta: Option<BTreeMap<String, NpmPeerDependencyMeta>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NpmSearchResponse {
    #[serde(default)]
    pub(crate) objects: Vec<NpmSearchObject>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NpmSearchObject {
    pub(crate) package: NpmSearchPackage,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NpmPackageManifest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) os: Option<NpmStringList>,
    #[serde(default)]
    pub(crate) cpu: Option<NpmStringList>,
    #[serde(default)]
    pub(crate) libc: Option<NpmStringList>,
    #[serde(default, deserialize_with = "deserialize_lenient_engines")]
    pub(crate) engines: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub(crate) scripts: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub(crate) dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "optionalDependencies")]
    pub(crate) optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "bundleDependencies")]
    pub(crate) bundle_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "bundledDependencies")]
    pub(crate) bundled_dependencies: Option<NpmStringList>,
    #[serde(default, rename = "peerDependencies")]
    pub(crate) peer_dependencies: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "peerDependenciesMeta")]
    pub(crate) peer_dependencies_meta: Option<BTreeMap<String, NpmPeerDependencyMeta>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum NpmStringList {
    One(String),
    Many(Vec<String>),
    Bool(bool),
}

impl NpmStringList {
    pub(crate) fn values(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
            Self::Bool(_) => Vec::new(),
        }
    }

    pub(crate) fn bool_value(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct NpmPeerDependencyMeta {
    #[serde(default)]
    pub(crate) optional: bool,
}

/// Leniently parse an npm `engines` field. The modern form is an object
/// (`{"node": ">=18"}`), but ancient package versions on the registry use an
/// array (`["node", "rhino"]`, e.g. early lodash) or a bare string
/// (`">=0.10.40"`, e.g. early qs). A single legacy version with one of those
/// shapes must NOT fail deserialization of the whole packument — that would make
/// the package (every version of it) uninstallable. We keep the object form and
/// treat the legacy array/string/bool/null forms as "no engine constraint".
pub(crate) fn deserialize_lenient_engines<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<BTreeMap<String, String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::Object(map) => {
            let engines = map
                .into_iter()
                .map(|(key, val)| {
                    let rendered = match val {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    (key, rendered)
                })
                .collect();
            Some(engines)
        }
        // Legacy array/string/bool, or explicit null: no usable constraint.
        _ => None,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct NpmDist {
    pub(crate) tarball: String,
    #[serde(default)]
    pub(crate) shasum: Option<String>,
    #[serde(default)]
    pub(crate) integrity: Option<String>,
}
