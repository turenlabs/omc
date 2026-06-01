//! PyPI distribution publish/upload (twine-facing helpers).
//!
//! Building the multipart upload form, extracting metadata from wheels and
//! sdists, and the `twine upload` / `twine check` entry points.

use crate::*;

use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use flate2::read::GzDecoder;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use tar::Archive;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PypiUploadResult {
    pub repository_url: String,
    pub filename: String,
    pub name: String,
    pub version: String,
    pub filetype: String,
    pub pyversion: String,
    pub status: u16,
    pub sha256_digest: String,
    pub skipped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PypiDistributionCheckResult {
    pub filename: String,
    pub name: String,
    pub version: String,
    pub strict: bool,
    pub passed: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PypiUploadOptions<'a> {
    pub skip_existing: bool,
    pub comment: Option<&'a str>,
    pub cert: Option<&'a Path>,
    pub client_cert: Option<&'a Path>,
    pub signature: Option<PypiUploadSignature<'a>>,
    pub attestations: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct PypiUploadSignature<'a> {
    pub filename: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PypiUploadDistribution {
    filename: String,
    name: String,
    version: String,
    filetype: String,
    pyversion: String,
    metadata: BTreeMap<String, Vec<String>>,
    description: Option<String>,
    sha256_digest: String,
    bytes: Vec<u8>,
}

type PypiUploadMetadata = (BTreeMap<String, Vec<String>>, Option<String>);

pub fn upload_pypi_distribution(
    repository_url: &str,
    username: &str,
    password: &str,
    path: &Path,
    options: PypiUploadOptions<'_>,
) -> Result<PypiUploadResult> {
    let repository_url = repository_url.trim();
    if repository_url.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine upload needs a repository URL".to_owned(),
        ));
    }
    if username.trim().is_empty() && password.is_empty() && options.client_cert.is_none() {
        return Err(OmcRegistryError::UnsupportedSpec(
            "twine upload needs authentication; pass --username/--password, set TWINE_USERNAME/TWINE_PASSWORD, configure .pypirc, or pass --client-cert".to_owned(),
        ));
    }

    let distribution = prepare_pypi_upload_distribution(path)?;
    let form = pypi_upload_form(
        &distribution,
        options.comment,
        options.signature,
        options.attestations,
    )?;
    let client = pypi_upload_client(options.cert, options.client_cert)?;
    let mut request = client.post(repository_url);
    if !username.trim().is_empty() || !password.is_empty() {
        request = request.basic_auth(username, Some(password));
    }
    let response = request.multipart(form).send()?;
    let status = response.status();
    let status_code = status.as_u16();
    let text = response.text()?;
    let skipped = options.skip_existing && pypi_upload_response_is_existing(status_code, &text);
    if !status.is_success() && !skipped {
        let detail = text.trim();
        let message = if detail.is_empty() {
            format!(
                "twine upload failed for {}: HTTP {status_code}",
                distribution.filename
            )
        } else {
            format!(
                "twine upload failed for {}: HTTP {status_code}: {detail}",
                distribution.filename
            )
        };
        return Err(OmcRegistryError::UnsupportedSpec(message));
    }

    Ok(PypiUploadResult {
        repository_url: repository_url.to_owned(),
        filename: distribution.filename,
        name: distribution.name,
        version: distribution.version,
        filetype: distribution.filetype,
        pyversion: distribution.pyversion,
        status: status_code,
        sha256_digest: distribution.sha256_digest,
        skipped,
        response_text: (!text.trim().is_empty()).then_some(text),
    })
}

pub fn check_pypi_distribution(path: &Path, strict: bool) -> Result<PypiDistributionCheckResult> {
    let distribution = prepare_pypi_upload_distribution(path)?;
    let warnings = pypi_distribution_check_warnings(&distribution);
    let passed = warnings.is_empty() || !strict;
    Ok(PypiDistributionCheckResult {
        filename: distribution.filename,
        name: distribution.name,
        version: distribution.version,
        strict,
        passed,
        warnings,
    })
}

fn pypi_distribution_check_warnings(distribution: &PypiUploadDistribution) -> Vec<String> {
    let mut warnings = Vec::new();
    let content_type =
        pypi_upload_metadata_value(&distribution.metadata, "description_content_type")
            .map(str::trim)
            .filter(|value| !value.is_empty());
    if content_type.is_none() {
        warnings.push(
            "`long_description_content_type` missing. defaulting to `text/x-rst`.".to_owned(),
        );
    }

    let description = distribution
        .description
        .as_deref()
        .or_else(|| pypi_upload_metadata_value(&distribution.metadata, "description"))
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if description
        .map(|value| value.eq_ignore_ascii_case("UNKNOWN"))
        .unwrap_or(true)
    {
        warnings.push("`long_description` missing.".to_owned());
    }

    if let Some(content_type) = content_type {
        let media_type = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase();
        if !matches!(
            media_type.as_str(),
            "text/plain" | "text/x-rst" | "text/markdown"
        ) {
            warnings.push(format!(
                "`long_description_content_type` `{content_type}` is not one of text/plain, text/x-rst, or text/markdown."
            ));
        }
    }

    warnings
}

fn pypi_upload_client(cert: Option<&Path>, client_cert: Option<&Path>) -> Result<Client> {
    let mut builder = Client::builder().user_agent("omc-prototype/0.1");
    if let Some(cert) = cert {
        let bytes = fs::read(cert)?;
        for cert in Certificate::from_pem_bundle(&bytes)? {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(client_cert) = client_cert {
        let bytes = fs::read(client_cert)?;
        builder = builder.identity(Identity::from_pem(&bytes)?);
    }
    Ok(builder.build()?)
}

fn prepare_pypi_upload_distribution(path: &Path) -> Result<PypiUploadDistribution> {
    let bytes = fs::read(path)?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload path `{}` does not have a valid UTF-8 filename",
                path.display()
            ))
        })?
        .to_owned();
    let (filetype, pyversion, fallback_name, fallback_version) =
        pypi_upload_filename_parts(&filename)?;
    let (metadata, description) = pypi_upload_metadata_from_archive(&bytes, &filename)?;
    let name = pypi_upload_metadata_value(&metadata, "name")
        .unwrap_or(&fallback_name)
        .trim()
        .to_owned();
    let version = pypi_upload_metadata_value(&metadata, "version")
        .unwrap_or(&fallback_version)
        .trim()
        .to_owned();
    if name.is_empty() || version.is_empty() {
        return Err(OmcRegistryError::UnsupportedSpec(format!(
            "twine upload could not determine name and version for `{filename}`"
        )));
    }

    Ok(PypiUploadDistribution {
        filename,
        name,
        version,
        filetype,
        pyversion,
        metadata,
        description,
        sha256_digest: sha256_hex(&bytes),
        bytes,
    })
}

fn pypi_upload_filename_parts(filename: &str) -> Result<(String, String, String, String)> {
    if filename.ends_with(".whl") {
        let (name, version) = parse_wheel_name_and_version(filename).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload could not parse wheel filename `{filename}`"
            ))
        })?;
        let pyversion = pypi_wheel_pyversion(filename).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload could not parse wheel Python tag `{filename}`"
            ))
        })?;
        Ok((
            "bdist_wheel".to_owned(),
            pyversion,
            name.replace('-', "_"),
            version,
        ))
    } else if is_python_sdist_filename(filename) {
        let (name, version) = parse_sdist_name_and_version(filename).ok_or_else(|| {
            OmcRegistryError::UnsupportedSpec(format!(
                "twine upload could not parse sdist filename `{filename}`"
            ))
        })?;
        Ok(("sdist".to_owned(), "source".to_owned(), name, version))
    } else {
        Err(OmcRegistryError::UnsupportedSpec(format!(
            "twine upload supports .whl, .tar.gz, .tgz, and .zip distributions; unsupported `{filename}`"
        )))
    }
}

fn pypi_wheel_pyversion(filename: &str) -> Option<String> {
    let filename = filename.strip_suffix(".whl")?;
    let parts = filename.split('-').collect::<Vec<_>>();
    (parts.len() >= 5).then(|| parts[parts.len() - 3].to_owned())
}

fn pypi_upload_metadata_from_archive(bytes: &[u8], filename: &str) -> Result<PypiUploadMetadata> {
    if filename.ends_with(".whl") {
        return pypi_upload_zip_metadata(bytes, ".dist-info/METADATA");
    }
    if filename.to_ascii_lowercase().ends_with(".zip") {
        return pypi_upload_zip_metadata(bytes, "/PKG-INFO");
    }
    pypi_upload_tar_metadata(bytes)
}

fn pypi_upload_zip_metadata(bytes: &[u8], suffix: &str) -> Result<PypiUploadMetadata> {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        if file.is_dir() || file.size() > MAX_FILE_BYTES {
            continue;
        }
        let path = file.name().to_owned();
        if is_ignorable_archive_metadata_path(&path) || !path.ends_with(suffix) {
            continue;
        }
        let mut metadata = String::new();
        file.read_to_string(&mut metadata)?;
        return Ok(parse_pypi_upload_metadata(&metadata));
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "twine upload distribution did not contain package metadata".to_owned(),
    ))
}

fn pypi_upload_tar_metadata(bytes: &[u8]) -> Result<PypiUploadMetadata> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_FILE_BYTES {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        if is_ignorable_archive_metadata_path(&path)
            || !(path.ends_with("/PKG-INFO") || path.ends_with(".dist-info/METADATA"))
        {
            continue;
        }
        let mut metadata = String::new();
        entry.read_to_string(&mut metadata)?;
        return Ok(parse_pypi_upload_metadata(&metadata));
    }
    Err(OmcRegistryError::UnsupportedSpec(
        "twine upload distribution did not contain package metadata".to_owned(),
    ))
}

fn parse_pypi_upload_metadata(metadata: &str) -> (BTreeMap<String, Vec<String>>, Option<String>) {
    let (headers, body) = split_metadata_headers_and_body(metadata);
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    for line in folded_metadata_lines(headers) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = pypi_upload_metadata_key(key);
        let value = value.trim();
        if !key.is_empty() && !value.is_empty() {
            fields.entry(key).or_default().push(value.to_owned());
        }
    }
    let trimmed_body = body.trim();
    let description = (!trimmed_body.is_empty()).then(|| trimmed_body.to_owned());
    (fields, description)
}

fn split_metadata_headers_and_body(metadata: &str) -> (&str, &str) {
    metadata
        .split_once("\r\n\r\n")
        .or_else(|| metadata.split_once("\n\n"))
        .unwrap_or((metadata, ""))
}

fn pypi_upload_metadata_key(key: &str) -> String {
    key.trim()
        .chars()
        .map(|ch| if ch == '-' { '_' } else { ch })
        .collect::<String>()
        .to_ascii_lowercase()
}

fn pypi_upload_metadata_value<'a>(
    metadata: &'a BTreeMap<String, Vec<String>>,
    key: &str,
) -> Option<&'a str> {
    metadata
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn pypi_upload_form(
    distribution: &PypiUploadDistribution,
    comment: Option<&str>,
    signature: Option<PypiUploadSignature<'_>>,
    attestations: Option<&str>,
) -> Result<Form> {
    let metadata_version = pypi_upload_metadata_value(&distribution.metadata, "metadata_version")
        .unwrap_or("2.1")
        .to_owned();
    let mut form = Form::new()
        .text(":action", "file_upload")
        .text("protocol_version", "1")
        .text("metadata_version", metadata_version)
        .text("name", distribution.name.clone())
        .text("version", distribution.version.clone())
        .text("filetype", distribution.filetype.clone())
        .text("pyversion", distribution.pyversion.clone())
        .text("sha256_digest", distribution.sha256_digest.clone());

    for (key, values) in &distribution.metadata {
        if matches!(
            key.as_str(),
            "metadata_version" | "name" | "version" | "filetype" | "pyversion" | "sha256_digest"
        ) {
            continue;
        }
        for value in values {
            form = form.text(key.clone(), value.clone());
        }
    }
    if let Some(description) = distribution
        .description
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        form = form.text("description", description.to_owned());
    }
    if let Some(comment) = comment.map(str::trim).filter(|value| !value.is_empty()) {
        form = form.text("comment", comment.to_owned());
    }
    if let Some(attestations) = attestations
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        form = form.text("attestations", attestations.to_owned());
    }

    let content = Part::bytes(distribution.bytes.clone())
        .file_name(distribution.filename.clone())
        .mime_str("application/octet-stream")?;
    let mut form = form.part("content", content);
    if let Some(signature) = signature {
        let signature_part = Part::bytes(signature.bytes.to_vec())
            .file_name(signature.filename.to_owned())
            .mime_str("application/octet-stream")?;
        form = form.part("gpg_signature", signature_part);
    }
    Ok(form)
}

pub(crate) fn pypi_upload_response_is_existing(status: u16, text: &str) -> bool {
    if status == 409 {
        return true;
    }
    if status != 400 {
        return false;
    }
    let text = text.to_ascii_lowercase();
    text.contains("already exist")
        || text.contains("already been uploaded")
        || text.contains("file already exists")
        || text.contains("filename has already been used")
}
