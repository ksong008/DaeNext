use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::{GeodataKind, ProductGeodataUpdateCoordinator};

pub const GEODATA_PREPARE_HELPER_SO_MARK_ENV: &str = "DAED_CONTROL_HELPER_SO_MARK";
pub const GEODATA_HELPER_SCHEMA_VERSION: u64 = 1;
pub const GEODATA_HELPER_MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const GEODATA_HELPER_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const GEODATA_HELPER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const GEODATA_HELPER_WAIT_INTERVAL: Duration = Duration::from_millis(20);
const GEODATA_HELPER_CONTROL_SO_MARK: u32 = 0x100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeodataPreparedDownload {
    pub version: String,
    pub summary: dae_geodata::GeoDataSummary,
    pub sha256: String,
    pub download_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeodataHelperRequest {
    pub state: PathBuf,
    pub output: PathBuf,
    pub response: PathBuf,
    pub kind: GeodataKind,
}

pub fn encode_geodata_helper_request(request: &GeodataHelperRequest) -> io::Result<Vec<u8>> {
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

pub fn decode_geodata_helper_request(input: &[u8]) -> io::Result<GeodataHelperRequest> {
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

pub fn encode_geodata_helper_success(
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

pub fn encode_geodata_helper_failure(kind: GeodataKind, error: &str) -> Value {
    let error = error.chars().take(4096).collect::<String>();
    json!({
        "schemaVersion": GEODATA_HELPER_SCHEMA_VERSION,
        "status": "fail",
        "kind": kind.response_key(),
        "error": error,
    })
}

pub fn decode_geodata_helper_response(
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
        "fail" => Err(io::Error::other(format!(
            "{} helper failed: {}",
            expected_kind.response_key(),
            required_string(&value, "error")?
        ))),
        "pass" => decode_success(&value),
        status => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported geodata helper response status: {status}"),
        )),
    }
}

pub fn prepare_geodata_with_helper(
    coordinator: &ProductGeodataUpdateCoordinator,
    state: &Path,
    dir: &Path,
    kind: GeodataKind,
    output: &Path,
) -> io::Result<GeodataPreparedDownload> {
    let response = coordinator.reserve_staging_path(dir, kind, "helper-response")?;
    let _response_cleanup = HelperResponseCleanup(response.clone());
    let request = encode_geodata_helper_request(&GeodataHelperRequest {
        state: state.to_path_buf(),
        output: output.to_path_buf(),
        response: response.clone(),
        kind,
    })?;
    let executable = std::env::current_exe()
        .map_err(|error| io::Error::other(format!("resolve geodata helper executable: {error}")))?;
    let mut child = Command::new(executable)
        .args(["geodata-prepare-helper", "--stdin-json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env(
            GEODATA_PREPARE_HELPER_SO_MARK_ENV,
            GEODATA_HELPER_CONTROL_SO_MARK.to_string(),
        )
        .spawn()
        .map(GeodataHelperChild::new)
        .map_err(|error| io::Error::other(format!("spawn geodata helper: {error}")))?;
    let mut stdin = child
        .child_mut()
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("open geodata helper stdin: unavailable"))?;
    stdin
        .write_all(&request)
        .map_err(|error| io::Error::other(format!("write geodata helper request: {error}")))?;
    drop(stdin);

    let deadline = Instant::now()
        .checked_add(GEODATA_HELPER_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let status = loop {
        if let Some(status) = child
            .child_mut()
            .try_wait()
            .map_err(|error| io::Error::other(format!("wait geodata helper: {error}")))?
        {
            child.mark_reaped();
            break status;
        }
        if Instant::now() >= deadline {
            child.terminate_and_wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} geodata helper timed out", kind.response_key()),
            ));
        }
        thread::sleep(GEODATA_HELPER_WAIT_INTERVAL);
    };

    let response_bytes = read_bounded_response(&response)?;
    let decoded = decode_geodata_helper_response(&response_bytes, kind);
    if !status.success() {
        return match decoded {
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::other(format!(
                "{} geodata helper exited with status {status}",
                kind.response_key()
            ))),
        };
    }
    decoded
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

fn read_bounded_response(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut response = Vec::new();
    file.take((GEODATA_HELPER_MAX_RESPONSE_BYTES as u64) + 1)
        .read_to_end(&mut response)?;
    if response.len() > GEODATA_HELPER_MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("geodata helper response exceeds {GEODATA_HELPER_MAX_RESPONSE_BYTES} bytes"),
        ));
    }
    Ok(response)
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
    usize::try_from(parse_u64_string(value, key)?).map_err(|_| {
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

struct HelperResponseCleanup(PathBuf);

impl Drop for HelperResponseCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct GeodataHelperChild {
    child: std::process::Child,
    reaped: bool,
}

impl GeodataHelperChild {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn child_mut(&mut self) -> &mut std::process::Child {
        &mut self.child
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
    }

    fn terminate_and_wait(&mut self) {
        let _ = self.child.kill();
        self.reaped = self.child.wait().is_ok();
    }
}

impl Drop for GeodataHelperChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.terminate_and_wait();
        }
    }
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
    fn bounded_response_rejects_oversized_files() {
        let path = std::env::temp_dir().join(format!(
            "dae-geodata-helper-oversized-response-{}",
            fastrand::u64(..)
        ));
        fs::write(&path, vec![b'x'; GEODATA_HELPER_MAX_RESPONSE_BYTES + 1]).unwrap();
        assert_eq!(
            read_bounded_response(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_file(path).unwrap();
    }
}
