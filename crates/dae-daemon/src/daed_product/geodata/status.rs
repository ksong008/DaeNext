use super::file::{advise_file_dontneed, sha256_file, summarize_geodata_file};
use super::time::{system_time_date, system_time_iso8601};
use super::types::GeodataKind;
use super::*;

pub(in crate::daed_product) fn geodata_status(app: &AppState) -> io::Result<Value> {
    let dir = geodata_dir(app);
    Ok(json!({
        "geosite": geodata_resource_status_cached(app, &dir, GeodataKind::Geosite),
        "geoip": geodata_resource_status_cached(app, &dir, GeodataKind::Geoip),
    }))
}

#[cfg(test)]
pub(super) fn geodata_status_for_dir(dir: &Path) -> io::Result<Value> {
    Ok(json!({
        "geosite": geodata_resource_status(dir, GeodataKind::Geosite),
        "geoip": geodata_resource_status(dir, GeodataKind::Geoip),
    }))
}

pub(super) fn geodata_dir(app: &AppState) -> PathBuf {
    app.web_root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| app.web_root.clone())
}

fn geodata_resource_status(dir: &Path, kind: GeodataKind) -> Value {
    match geodata_resource_status_result(dir, kind) {
        Ok(value) => value,
        Err(err) => geodata_resource_unavailable_status(kind, err),
    }
}

fn geodata_resource_status_cached(app: &AppState, dir: &Path, kind: GeodataKind) -> Value {
    let Ok(mut cache) = app.geodata_status_cache.lock() else {
        return geodata_resource_status(dir, kind);
    };
    let slot = match kind {
        GeodataKind::Geosite => &mut cache.geosite,
        GeodataKind::Geoip => &mut cache.geoip,
    };
    if let Some(value) = slot.as_ref() {
        return value.clone();
    }

    let value = geodata_resource_status(dir, kind);
    *slot = Some(value.clone());
    value
}

fn geodata_resource_unavailable_status(kind: GeodataKind, err: io::Error) -> Value {
    let mut value = json!({
    "available": false,
    "version": "",
    "categoryCount": 0,
    "fileSize": 0,
    "sha256": null,
    "updatedAt": null,
    "lastError": err.to_string(),
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

fn geodata_resource_status_result(dir: &Path, kind: GeodataKind) -> io::Result<Value> {
    let path = dir.join(kind.file_name());
    let summary = summarize_geodata_file(kind, &path)?;
    let sha256 = sha256_file(&path)?;
    let _ = advise_file_dontneed(&path);
    geodata_resource_status_from_parts(dir, kind, summary, sha256)
}

pub(super) fn geodata_resource_status_from_parts(
    dir: &Path,
    kind: GeodataKind,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
) -> io::Result<Value> {
    let path = dir.join(kind.file_name());
    let metadata = fs::metadata(&path)?;

    Ok(geodata_resource_status_value(
        dir, kind, &metadata, summary, sha256,
    ))
}

fn geodata_resource_status_value(
    dir: &Path,
    kind: GeodataKind,
    metadata: &fs::Metadata,
    summary: dae_geodata::GeoDataSummary,
    sha256: String,
) -> Value {
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let updated_at = system_time_iso8601(modified);
    let version =
        read_geodata_release_version(dir, kind).unwrap_or_else(|| system_time_date(modified));

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
    if is_valid_geodata_release_version(value) {
        Some(value.to_owned())
    } else {
        None
    }
}

pub(super) fn write_geodata_release_version(
    dir: &Path,
    kind: GeodataKind,
    version: &str,
) -> io::Result<()> {
    if !is_valid_geodata_release_version(version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata release version: {version}"),
        ));
    }
    let path = dir.join(kind.version_file_name());
    let tmp_path = dir.join(format!(
        ".{}.version.tmp.{}.{}",
        kind.file_name(),
        std::process::id(),
        unix_now()
    ));
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(version.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        err
    })
}

pub(super) fn is_valid_geodata_release_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn set_geodata_resource_status_cache(app: &AppState, kind: GeodataKind, value: Value) {
    let Ok(mut cache) = app.geodata_status_cache.lock() else {
        return;
    };
    match kind {
        GeodataKind::Geosite => cache.geosite = Some(value),
        GeodataKind::Geoip => cache.geoip = Some(value),
    }
}

pub(super) fn update_geodata_resource_status_cache(
    app: &AppState,
    kind: GeodataKind,
    value: Value,
) {
    set_geodata_resource_status_cache(app, kind, value);
}
