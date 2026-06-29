use super::file::{advise_file_dontneed, summarize_geodata_file};
use super::http::{fetch_geodata_latest_release, fetch_geodata_url_to_file};
use super::source::geodata_source;
use super::status::{
    geodata_dir, geodata_resource_status_from_parts, update_geodata_resource_status_cache,
    write_geodata_release_version,
};
use super::types::{GeodataKind, GeodataRelease, GeodataSourceMode};
use super::*;

pub(super) fn update_geodata(app: &AppState, kind: GeodataKind) -> io::Result<Value> {
    let dir = geodata_dir(app);
    fs::create_dir_all(&dir)?;
    let source = geodata_source(&app.state, kind)?;
    let proxy_config = if source.use_proxy {
        Some(product_default_proxy_config(&app.state)?)
    } else {
        None
    };
    let release = match source.mode {
        GeodataSourceMode::ReleaseApi => {
            fetch_geodata_latest_release(kind, &source.url, proxy_config.as_ref())?
        }
        GeodataSourceMode::DirectFile => {
            direct_geodata_release(kind, &source.url, proxy_config.as_ref())
        }
    };
    let path = dir.join(kind.file_name());
    let tmp_path = dir.join(format!(
        ".{}.tmp.{}.{}",
        kind.file_name(),
        std::process::id(),
        unix_now()
    ));
    let download =
        match fetch_geodata_url_to_file(&release.download_url, &tmp_path, proxy_config.as_ref()) {
            Ok(download) => download,
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(err);
            }
        };
    let summary = match summarize_geodata_file(kind, &tmp_path) {
        Ok(summary) => summary,
        Err(err) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
    };
    if summary.category_count == 0 || summary.item_count == 0 {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded geodata is empty",
        ));
    }
    if download.bytes == 0 {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded geodata is empty",
        ));
    }
    fs::rename(&tmp_path, &path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        err
    })?;
    let version = release
        .version
        .unwrap_or_else(|| geodata_sha256_version(&download.sha256));
    write_geodata_release_version(&dir, kind, &version)?;
    let _ = advise_file_dontneed(&path);
    let status = geodata_resource_status_from_parts(&dir, kind, summary, download.sha256)?;
    update_geodata_resource_status_cache(app, kind, status.clone());
    let runtime_reload_required = bump_runtime_external_input_if_running(app)?;
    let mut response_object = serde_json::Map::new();
    response_object.insert(kind.response_key().to_owned(), status);
    response_object.insert("updated".to_owned(), json!(kind.response_key()));
    if runtime_reload_required {
        response_object.insert("runtimeReloadRequired".to_owned(), json!(true));
    }
    Ok(Value::Object(response_object))
}

fn geodata_sha256_version(sha256: &str) -> String {
    sha256.chars().take(10).collect()
}

fn direct_geodata_release(
    kind: GeodataKind,
    source_url: &url::Url,
    proxy_config: Option<&Config>,
) -> GeodataRelease {
    let version = if source_url.as_str() == kind.default_source_url() {
        default_direct_geodata_version(kind, proxy_config)
    } else {
        None
    };
    GeodataRelease {
        version,
        download_url: source_url.clone(),
    }
}

fn default_direct_geodata_version(
    kind: GeodataKind,
    proxy_config: Option<&Config>,
) -> Option<String> {
    let api_url = url::Url::parse(kind.legacy_release_api_url()).ok()?;
    fetch_geodata_latest_release(kind, &api_url, proxy_config)
        .ok()?
        .version
}

fn bump_runtime_external_input_if_running(app: &AppState) -> io::Result<bool> {
    let running = app
        .runtime
        .inner
        .lock()
        .map(|inner| inner.runtime.is_some())
        .unwrap_or(false);
    if running {
        bump_runtime_external_input_version(&app.state)?;
    }
    Ok(running)
}
