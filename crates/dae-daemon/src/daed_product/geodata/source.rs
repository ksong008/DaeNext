use super::types::GeodataKind;
use super::*;

const GEODATA_SOURCE_URL_MAX_LEN: usize = 2048;

pub(super) fn geodata_sources_status(state: &Path) -> io::Result<Value> {
    Ok(json!({
        "geosite": geodata_source_status(state, GeodataKind::Geosite)?,
        "geoip": geodata_source_status(state, GeodataKind::Geoip)?,
    }))
}

pub(super) fn geodata_source_status(state: &Path, kind: GeodataKind) -> io::Result<Value> {
    let default_url = kind.release_api_url();
    let custom_url = geodata_custom_source_url(state, kind)?;
    let url = custom_url.as_deref().unwrap_or(default_url);
    Ok(json!({
        "kind": kind.response_key(),
        "url": url,
        "defaultUrl": default_url,
        "usingDefault": custom_url.is_none(),
    }))
}

pub(super) fn geodata_source_url(state: &Path, kind: GeodataKind) -> io::Result<url::Url> {
    let raw_url = geodata_custom_source_url(state, kind)?
        .unwrap_or_else(|| kind.release_api_url().to_owned());
    parse_geodata_source_url(&raw_url)
}

pub(super) fn set_geodata_source_url(
    state: &Path,
    kind: GeodataKind,
    raw_url: &str,
) -> io::Result<Value> {
    let url = normalize_geodata_source_url(raw_url)?;
    reject_obviously_wrong_geodata_source(kind, &url)?;
    let value = if url == kind.release_api_url() {
        ""
    } else {
        url.as_str()
    };
    set_metadata(state, &geodata_source_metadata_key(kind), value)?;
    geodata_source_status(state, kind)
}

pub(super) fn reset_geodata_source_url(state: &Path, kind: GeodataKind) -> io::Result<Value> {
    set_metadata(state, &geodata_source_metadata_key(kind), "")?;
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
    if url == other.release_api_url() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} source cannot use {} default update url",
                kind.response_key(),
                other.response_key()
            ),
        ));
    }
    Ok(())
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
