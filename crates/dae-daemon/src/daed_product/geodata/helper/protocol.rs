use super::*;

pub(super) const GEODATA_HELPER_SCHEMA_VERSION: u64 = 1;
pub(super) const GEODATA_HELPER_MAX_REQUEST_BYTES: usize = 64 * 1024;
pub(super) const GEODATA_HELPER_MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::daed_product::geodata) struct GeodataPreparedDownload {
    pub(in crate::daed_product::geodata) version: String,
    pub(in crate::daed_product::geodata) summary: dae_geodata::GeoDataSummary,
    pub(in crate::daed_product::geodata) sha256: String,
    pub(in crate::daed_product::geodata) download_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GeodataHelperRequest {
    pub(super) state: PathBuf,
    pub(super) output: PathBuf,
    pub(super) response: PathBuf,
    pub(super) kind: GeodataKind,
}

pub(super) fn encode_geodata_helper_request(request: &GeodataHelperRequest) -> io::Result<Vec<u8>> {
    let state = utf8_path(&request.state, "state")?;
    let output = utf8_path(&request.output, "output")?;
    let response = utf8_path(&request.response, "response")?;
    serde_json::to_vec(&json!({
        "schemaVersion": GEODATA_HELPER_SCHEMA_VERSION,
        "statePath": state,
        "outputPath": output,
        "responsePath": response,
        "kind": request.kind.response_key(),
    }))
    .map_err(|error| io::Error::other(format!("encode geodata helper request: {error}")))
}

pub(super) fn decode_geodata_helper_request(input: &[u8]) -> io::Result<GeodataHelperRequest> {
    if input.len() > GEODATA_HELPER_MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata helper request exceeds {GEODATA_HELPER_MAX_REQUEST_BYTES} bytes"),
        ));
    }
    let value: Value = serde_json::from_slice(input).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode geodata helper request: {error}"),
        )
    })?;
    require_schema(&value)?;
    Ok(GeodataHelperRequest {
        state: PathBuf::from(required_string(&value, "statePath")?),
        output: PathBuf::from(required_string(&value, "outputPath")?),
        response: PathBuf::from(required_string(&value, "responsePath")?),
        kind: decode_kind(required_string(&value, "kind")?)?,
    })
}

pub(super) fn encode_geodata_helper_success(
    kind: GeodataKind,
    prepared: &GeodataPreparedDownload,
) -> Value {
    json!({
        "schemaVersion": GEODATA_HELPER_SCHEMA_VERSION,
        "status": "pass",
        "kind": kind.response_key(),
        "version": prepared.version,
        "summary": {
            "categoryCount": prepared.summary.category_count.to_string(),
            "itemCount": prepared.summary.item_count.to_string(),
        },
        "sha256": prepared.sha256,
        "downloadBytes": prepared.download_bytes.to_string(),
    })
}

pub(super) fn encode_geodata_helper_failure(kind: GeodataKind, error: &str) -> Value {
    let error = error.chars().take(4096).collect::<String>();
    json!({
        "schemaVersion": GEODATA_HELPER_SCHEMA_VERSION,
        "status": "fail",
        "kind": kind.response_key(),
        "error": error,
    })
}

pub(super) fn decode_geodata_helper_response(
    input: &[u8],
    expected_kind: GeodataKind,
) -> io::Result<GeodataPreparedDownload> {
    if input.len() > GEODATA_HELPER_MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata helper response exceeds {GEODATA_HELPER_MAX_RESPONSE_BYTES} bytes"),
        ));
    }
    let value: Value = serde_json::from_slice(input).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode geodata helper response: {error}"),
        )
    })?;
    require_schema(&value)?;
    let response_kind = decode_kind(required_string(&value, "kind")?)?;
    if response_kind != expected_kind {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "geodata helper response kind does not match request",
        ));
    }
    match required_string(&value, "status")? {
        "fail" => {
            let message = required_string(&value, "error")?;
            Err(io::Error::other(format!(
                "{} helper failed: {message}",
                expected_kind.response_key()
            )))
        }
        "pass" => decode_success(&value),
        status => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported geodata helper response status: {status}"),
        )),
    }
}

fn decode_success(value: &Value) -> io::Result<GeodataPreparedDownload> {
    let version = required_string(value, "version")?.to_owned();
    if version.is_empty() || version.len() > 512 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "geodata helper response has invalid version",
        ));
    }
    let sha256 = required_string(value, "sha256")?.to_owned();
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "geodata helper response has invalid sha256",
        ));
    }
    let summary = value.get("summary").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "geodata helper response is missing summary",
        )
    })?;
    let category_count = parse_usize_string(summary, "categoryCount")?;
    let item_count = parse_usize_string(summary, "itemCount")?;
    let download_bytes = parse_u64_string(value, "downloadBytes")?;
    if category_count == 0 || item_count == 0 || download_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "geodata helper response describes an empty asset",
        ));
    }
    Ok(GeodataPreparedDownload {
        version,
        summary: dae_geodata::GeoDataSummary {
            category_count,
            item_count,
        },
        sha256,
        download_bytes,
    })
}

fn require_schema(value: &Value) -> io::Result<()> {
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(GEODATA_HELPER_SCHEMA_VERSION) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported geodata helper schema version",
        ));
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata helper JSON is missing {key}"),
        )
    })
}

fn parse_usize_string(value: &Value, key: &str) -> io::Result<usize> {
    let parsed = parse_u64_string(value, key)?;
    usize::try_from(parsed).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata helper {key} does not fit usize"),
        )
    })
}

fn parse_u64_string(value: &Value, key: &str) -> io::Result<u64> {
    required_string(value, key)?.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse geodata helper {key}: {error}"),
        )
    })
}

fn decode_kind(value: &str) -> io::Result<GeodataKind> {
    match value {
        "geosite" => Ok(GeodataKind::Geosite),
        "geoip" => Ok(GeodataKind::Geoip),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported geodata helper kind: {value}"),
        )),
    }
}

fn utf8_path<'a>(path: &'a Path, name: &str) -> io::Result<&'a str> {
    path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("geodata helper {name} path is not UTF-8"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_protocol_round_trips_a_valid_prepared_download() {
        let prepared = GeodataPreparedDownload {
            version: "v1.2.3".to_owned(),
            summary: dae_geodata::GeoDataSummary {
                category_count: 12,
                item_count: 345,
            },
            sha256: "a".repeat(64),
            download_bytes: 4096,
        };
        let encoded = serde_json::to_vec(&encode_geodata_helper_success(
            GeodataKind::Geosite,
            &prepared,
        ))
        .unwrap();
        assert_eq!(
            decode_geodata_helper_response(&encoded, GeodataKind::Geosite).unwrap(),
            prepared
        );
    }

    #[test]
    fn helper_protocol_rejects_kind_mismatch_and_empty_assets() {
        let response = json!({
            "schemaVersion": GEODATA_HELPER_SCHEMA_VERSION,
            "status": "pass",
            "kind": "geoip",
            "version": "v1",
            "summary": {"categoryCount":"1","itemCount":"1"},
            "sha256": "b".repeat(64),
            "downloadBytes": "1",
        });
        let encoded = serde_json::to_vec(&response).unwrap();
        assert!(
            decode_geodata_helper_response(&encoded, GeodataKind::Geosite)
                .unwrap_err()
                .to_string()
                .contains("kind")
        );

        let empty = json!({
            "schemaVersion": GEODATA_HELPER_SCHEMA_VERSION,
            "status": "pass",
            "kind": "geoip",
            "version": "v1",
            "summary": {"categoryCount":"0","itemCount":"1"},
            "sha256": "b".repeat(64),
            "downloadBytes": "1",
        });
        assert!(
            decode_geodata_helper_response(
                &serde_json::to_vec(&empty).unwrap(),
                GeodataKind::Geoip
            )
            .unwrap_err()
            .to_string()
            .contains("empty")
        );
    }
}
