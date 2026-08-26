use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dae_product_core::{product_civil_from_days, product_iso8601_utc};
use serde_json::{Value, json};

use crate::{GeodataKind, advise_file_dontneed, sha256_file, summarize_geodata_file};

pub fn geodata_dir_for_web_root(web_root: &Path) -> PathBuf {
    web_root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| web_root.to_path_buf())
}

pub fn geodata_resource_status(dir: &Path, kind: GeodataKind) -> Value {
    match geodata_resource_status_result(dir, kind) {
        Ok(value) => value,
        Err(error) => geodata_resource_unavailable_status(kind, error),
    }
}

pub fn geodata_resource_status_result(dir: &Path, kind: GeodataKind) -> io::Result<Value> {
    let path = dir.join(kind.file_name());
    let summary = summarize_geodata_file(kind, &path)?;
    let sha256 = sha256_file(&path)?;
    let _ = advise_file_dontneed(&path);
    geodata_resource_status_from_parts(dir, kind, summary, sha256)
}

pub fn geodata_resource_status_from_parts(
    dir: &Path,
    kind: GeodataKind,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
) -> io::Result<Value> {
    let metadata = fs::metadata(dir.join(kind.file_name()))?;
    Ok(geodata_resource_status_value(
        dir, kind, &metadata, summary, sha256,
    ))
}

pub fn geodata_resource_status_from_staged_parts(
    path: &Path,
    kind: GeodataKind,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
    version: &str,
) -> io::Result<Value> {
    if !is_valid_geodata_release_version(version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata release version: {version}"),
        ));
    }
    let metadata = fs::metadata(path)?;
    Ok(geodata_resource_status_value_with_version(
        kind, &metadata, summary, sha256, version,
    ))
}

fn geodata_resource_unavailable_status(kind: GeodataKind, error: io::Error) -> Value {
    let mut value = json!({
        "available": false,
        "version": "",
        "categoryCount": 0,
        "fileSize": 0,
        "sha256": null,
        "updatedAt": null,
        "lastError": error.to_string(),
    });
    if let Some(object) = value.as_object_mut() {
        match kind {
            GeodataKind::Geosite => {
                object.insert("ruleCount".to_owned(), json!(0));
            }
            GeodataKind::Geoip => {
                object.insert("cidrCount".to_owned(), json!(0));
            }
        }
    }
    value
}

fn geodata_resource_status_value(
    dir: &Path,
    kind: GeodataKind,
    metadata: &fs::Metadata,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
) -> Value {
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let version =
        read_geodata_release_version(dir, kind).unwrap_or_else(|| system_time_date(modified));
    geodata_resource_status_value_with_version(kind, metadata, summary, sha256, &version)
}

fn geodata_resource_status_value_with_version(
    kind: GeodataKind,
    metadata: &fs::Metadata,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
    version: &str,
) -> Value {
    let updated_at = system_time_iso8601(metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH));
    let mut value = json!({
        "available": true,
        "version": version,
        "categoryCount": summary.category_count,
        "fileSize": metadata.len(),
        "sha256": sha256,
        "updatedAt": updated_at,
        "lastError": null,
    });
    if let Some(object) = value.as_object_mut() {
        match kind {
            GeodataKind::Geosite => {
                object.insert("ruleCount".to_owned(), json!(summary.item_count));
            }
            GeodataKind::Geoip => {
                object.insert("cidrCount".to_owned(), json!(summary.item_count));
            }
        }
    }
    value
}

fn read_geodata_release_version(dir: &Path, kind: GeodataKind) -> Option<String> {
    let value = fs::read_to_string(dir.join(kind.version_file_name())).ok()?;
    let value = value.trim();
    is_valid_geodata_release_version(value).then(|| value.to_owned())
}

pub fn is_valid_geodata_release_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn system_time_iso8601(time: SystemTime) -> String {
    let timestamp = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    product_iso8601_utc(timestamp)
}

fn system_time_date(time: SystemTime) -> String {
    let timestamp = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (timestamp as i64).div_euclid(86_400);
    let (year, month, day) = product_civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}
