use super::{GeodataKind, GeodataSource, GeodataSourceMode};
use dae_product_persistence::{
    ensure_state_schema, get_metadata, open_state_connection, set_metadata_with_connection,
};
use rusqlite::TransactionBehavior;
use serde_json::{Value, json};
use std::io;
use std::path::Path;

const GEODATA_SOURCE_URL_MAX_LEN: usize = 2048;

pub enum GeodataSourceUrlUpdate<'a> {
    Keep,
    RestoreDefault,
    Set(&'a str),
}

pub fn geodata_sources_status(state: &Path) -> io::Result<Value> {
    Ok(json!({
        "geosite": geodata_source_status(state, GeodataKind::Geosite)?,
        "geoip": geodata_source_status(state, GeodataKind::Geoip)?,
    }))
}

pub fn geodata_source_status(state: &Path, kind: GeodataKind) -> io::Result<Value> {
    let default_url = kind.default_source_url();
    let custom_url = geodata_custom_source_url(state, kind)?;
    let url = custom_url.as_deref().unwrap_or(default_url);
    let parsed_url = parse_geodata_source_url(url)?;
    let source_type = geodata_source_mode(kind, &parsed_url)?;
    let use_proxy = geodata_source_use_proxy(state, kind)?;
    Ok(json!({
        "kind": kind.response_key(),
        "url": url,
        "defaultUrl": default_url,
        "usingDefault": custom_url.is_none(),
        "sourceType": source_type.response_key(),
        "useProxy": use_proxy,
    }))
}

pub fn geodata_source(state: &Path, kind: GeodataKind) -> io::Result<GeodataSource> {
    let raw_url = geodata_custom_source_url(state, kind)?
        .unwrap_or_else(|| kind.default_source_url().to_owned());
    let url = parse_geodata_source_url(&raw_url)?;
    let mode = geodata_source_mode(kind, &url)?;
    let use_proxy = geodata_source_use_proxy(state, kind)?;
    Ok(GeodataSource {
        url,
        mode,
        use_proxy,
    })
}

pub fn set_geodata_source_url(state: &Path, kind: GeodataKind, raw_url: &str) -> io::Result<Value> {
    update_geodata_source_settings(state, kind, GeodataSourceUrlUpdate::Set(raw_url), None)
}

pub fn set_geodata_source_use_proxy(
    state: &Path,
    kind: GeodataKind,
    use_proxy: bool,
) -> io::Result<Value> {
    update_geodata_source_settings(state, kind, GeodataSourceUrlUpdate::Keep, Some(use_proxy))
}

pub fn reset_geodata_source_url(state: &Path, kind: GeodataKind) -> io::Result<Value> {
    update_geodata_source_settings(state, kind, GeodataSourceUrlUpdate::RestoreDefault, None)
}

pub fn update_geodata_source_settings(
    state: &Path,
    kind: GeodataKind,
    url_update: GeodataSourceUrlUpdate<'_>,
    use_proxy: Option<bool>,
) -> io::Result<Value> {
    let source_url = match url_update {
        GeodataSourceUrlUpdate::Keep => None,
        GeodataSourceUrlUpdate::RestoreDefault => Some(String::new()),
        GeodataSourceUrlUpdate::Set(raw_url) => {
            let url = normalize_geodata_source_url(raw_url)?;
            reject_obviously_wrong_geodata_source(kind, &url)?;
            Some(if url == kind.default_source_url() {
                String::new()
            } else {
                url
            })
        }
    };
    if source_url.is_none() && use_proxy.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "geodata source url or useProxy is required",
        ));
    }
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(io::Error::other)?;
    if let Some(source_url) = source_url.as_deref() {
        set_metadata_with_connection(&tx, &geodata_source_metadata_key(kind), source_url)?;
    }
    if let Some(use_proxy) = use_proxy {
        set_metadata_with_connection(
            &tx,
            &geodata_source_use_proxy_metadata_key(kind),
            if use_proxy { "true" } else { "false" },
        )?;
    }
    tx.commit().map_err(io::Error::other)?;
    geodata_source_status(state, kind)
}

fn geodata_custom_source_url(state: &Path, kind: GeodataKind) -> io::Result<Option<String>> {
    let Some(value) = get_metadata(state, &geodata_source_metadata_key(kind))? else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let url = normalize_geodata_source_url(value)?;
    reject_obviously_wrong_geodata_source(kind, &url)?;
    Ok(Some(url))
}

fn geodata_source_use_proxy(state: &Path, kind: GeodataKind) -> io::Result<bool> {
    let Some(value) = get_metadata(state, &geodata_source_use_proxy_metadata_key(kind))? else {
        return Ok(false);
    };
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" | "" => Ok(false),
        value => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata use proxy value: {value}"),
        )),
    }
}

fn normalize_geodata_source_url(raw_url: &str) -> io::Result<String> {
    let url = parse_geodata_source_url(raw_url)?;
    Ok(url.as_str().to_owned())
}

fn parse_geodata_source_url(raw_url: &str) -> io::Result<url::Url> {
    let raw_url = raw_url.trim();
    if raw_url.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "geodata source url is empty",
        ));
    }
    if raw_url.len() > GEODATA_SOURCE_URL_MAX_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "geodata source url is too long",
        ));
    }
    let url = url::Url::parse(raw_url).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid geodata source url: {err}"),
        )
    })?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported geodata source url scheme: {scheme}"),
            ));
        }
    }
    if url.host_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing geodata source url host",
        ));
    }
    if url.port_or_known_default().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing geodata source url port",
        ));
    }
    Ok(url)
}

fn reject_obviously_wrong_geodata_source(kind: GeodataKind, url: &str) -> io::Result<()> {
    let other = other_geodata_kind(kind);
    let own_release_api_url = kind.legacy_release_api_url();
    let other_release_api_url = other.legacy_release_api_url();
    let uses_other_only_release_api =
        other_release_api_url != own_release_api_url && url == other_release_api_url;
    if url == other.default_source_url() || uses_other_only_release_api {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} source cannot use {} default update url",
                kind.response_key(),
                other.response_key()
            ),
        ));
    }
    let parsed = parse_geodata_source_url(url)?;
    let _ = geodata_source_mode(kind, &parsed)?;
    Ok(())
}

fn geodata_source_mode(kind: GeodataKind, url: &url::Url) -> io::Result<GeodataSourceMode> {
    if url.as_str() == kind.legacy_release_api_url() {
        return Ok(GeodataSourceMode::ReleaseApi);
    }
    let last_segment = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .unwrap_or_default();
    if last_segment.eq_ignore_ascii_case(kind.file_name()) {
        return Ok(GeodataSourceMode::DirectFile);
    }
    let other = other_geodata_kind(kind);
    if last_segment.eq_ignore_ascii_case(other.file_name()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} source cannot use {} data file url",
                kind.response_key(),
                other.response_key()
            ),
        ));
    }
    if looks_like_release_api_url(url) {
        return Ok(GeodataSourceMode::ReleaseApi);
    }
    Ok(GeodataSourceMode::DirectFile)
}

fn looks_like_release_api_url(url: &url::Url) -> bool {
    let Some(segments) = url.path_segments() else {
        return false;
    };
    let mut segments = segments.rev();
    matches!(
        (segments.next(), segments.next()),
        (Some("latest"), Some("releases"))
    )
}

fn other_geodata_kind(kind: GeodataKind) -> GeodataKind {
    match kind {
        GeodataKind::Geosite => GeodataKind::Geoip,
        GeodataKind::Geoip => GeodataKind::Geosite,
    }
}

fn geodata_source_metadata_key(kind: GeodataKind) -> String {
    format!("geodata_{}_source_url", kind.response_key())
}

fn geodata_source_use_proxy_metadata_key(kind: GeodataKind) -> String {
    format!("geodata_{}_use_proxy", kind.response_key())
}
