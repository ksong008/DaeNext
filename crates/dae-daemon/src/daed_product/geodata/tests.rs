use super::http::{
    GeodataHttpFileResult, read_geodata_http_response, read_geodata_http_response_to_file,
};
use super::source::{
    geodata_source_status, geodata_source_url, reset_geodata_source_url, set_geodata_source_url,
};
use super::status::geodata_status_for_dir;
use super::types::{GEOIP_FILE, GEOSITE_FILE};
use super::*;

#[test]
fn geodata_status_reports_counts_from_actual_files() {
    let dir = std::env::temp_dir().join(format!("daed-product-geodata-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(GEOSITE_FILE),
        message([
            field_message(
                1,
                message([
                    field_string(1, "geosite:alpha"),
                    field_message(2, message([field_string(2, "example.com")])),
                ]),
            ),
            field_message(
                1,
                message([
                    field_string(1, "geosite:beta"),
                    field_message(2, message([field_string(2, "example.org")])),
                    field_message(2, message([field_string(2, "example.net")])),
                ]),
            ),
        ]),
    )
    .unwrap();
    fs::write(
        dir.join(GeodataKind::Geosite.version_file_name()),
        "202606222314\n",
    )
    .unwrap();
    fs::write(
        dir.join(GEOIP_FILE),
        message([
            field_message(
                1,
                message([
                    field_string(1, "geoip:alpha"),
                    field_message(
                        2,
                        message([field_bytes(1, &[10, 0, 0, 0]), field_varint(2, 8)]),
                    ),
                ]),
            ),
            field_message(
                1,
                message([
                    field_string(1, "geoip:beta"),
                    field_message(
                        2,
                        message([field_bytes(1, &[192, 168, 0, 0]), field_varint(2, 16)]),
                    ),
                    field_message(
                        2,
                        message([field_bytes(1, &[172, 16, 0, 0]), field_varint(2, 12)]),
                    ),
                ]),
            ),
        ]),
    )
    .unwrap();
    fs::write(
        dir.join(GeodataKind::Geoip.version_file_name()),
        "202606182327\n",
    )
    .unwrap();

    let status = geodata_status_for_dir(&dir).unwrap();
    assert_eq!(status["geosite"]["version"], json!("202606222314"));
    assert_eq!(status["geosite"]["categoryCount"], json!(2));
    assert_eq!(status["geosite"]["ruleCount"], json!(3));
    assert_eq!(status["geoip"]["version"], json!("202606182327"));
    assert_eq!(status["geoip"]["categoryCount"], json!(2));
    assert_eq!(status["geoip"]["cidrCount"], json!(3));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_status_reuses_cached_values_after_first_read() {
    let dir =
        std::env::temp_dir().join(format!("daed-product-geodata-cache-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(GEOSITE_FILE),
        message([field_message(
            1,
            message([
                field_string(1, "geosite:cached"),
                field_message(2, message([field_string(2, "cached.example")])),
            ]),
        )]),
    )
    .unwrap();
    fs::write(
        dir.join(GEOIP_FILE),
        message([field_message(
            1,
            message([
                field_string(1, "geoip:cached"),
                field_message(
                    2,
                    message([field_bytes(1, &[10, 0, 0, 0]), field_varint(2, 8)]),
                ),
            ]),
        )]),
    )
    .unwrap();
    let app = AppState {
        config_dir: dir.clone(),
        state: dir.join("daed.db"),
        web_root: dir.join("web"),
        api_only: true,
        runtime: Arc::new(ProductRuntimeManager::new()),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
    };

    let first = geodata_status(&app).unwrap();
    assert_eq!(first["geosite"]["ruleCount"], json!(1));
    assert_eq!(first["geoip"]["cidrCount"], json!(1));

    fs::remove_file(dir.join(GEOSITE_FILE)).unwrap();
    fs::remove_file(dir.join(GEOIP_FILE)).unwrap();

    let cached = geodata_status(&app).unwrap();
    assert_eq!(cached["geosite"]["available"], json!(true));
    assert_eq!(cached["geosite"]["ruleCount"], json!(1));
    assert_eq!(cached["geoip"]["available"], json!(true));
    assert_eq!(cached["geoip"]["cidrCount"], json!(1));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_status_keeps_missing_resources_unavailable() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-missing-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();

    let status = geodata_status_for_dir(&dir).unwrap();
    assert_eq!(status["geosite"]["available"], json!(false));
    assert_eq!(status["geosite"]["categoryCount"], json!(0));
    assert_eq!(status["geoip"]["available"], json!(false));
    assert_eq!(status["geoip"]["categoryCount"], json!(0));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_source_settings_default_custom_and_reset_urls() {
    let dir =
        std::env::temp_dir().join(format!("daed-product-geodata-source-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("daed.db");

    let geosite = geodata_source_status(&state, GeodataKind::Geosite).unwrap();
    assert_eq!(geosite["kind"], json!("geosite"));
    assert_eq!(geosite["usingDefault"], json!(true));
    assert_eq!(
        geosite["url"],
        json!(GeodataKind::Geosite.release_api_url())
    );

    let custom_url = "https://mirror.example.test/geosite/releases/latest";
    let geosite = set_geodata_source_url(&state, GeodataKind::Geosite, custom_url).unwrap();
    assert_eq!(geosite["url"], json!(custom_url));
    assert_eq!(geosite["usingDefault"], json!(false));
    assert_eq!(
        geodata_source_url(&state, GeodataKind::Geosite)
            .unwrap()
            .as_str(),
        custom_url
    );

    let geosite = reset_geodata_source_url(&state, GeodataKind::Geosite).unwrap();
    assert_eq!(geosite["usingDefault"], json!(true));
    assert_eq!(
        geosite["url"],
        json!(GeodataKind::Geosite.release_api_url())
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_source_settings_rejects_swapped_default_urls() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-source-guard-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("daed.db");

    let err = set_geodata_source_url(
        &state,
        GeodataKind::Geosite,
        GeodataKind::Geoip.release_api_url(),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("geosite source cannot use geoip default update url")
    );
    let err = set_geodata_source_url(
        &state,
        GeodataKind::Geoip,
        GeodataKind::Geosite.release_api_url(),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("geoip source cannot use geosite default update url")
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_source_settings_rejects_invalid_urls() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-source-invalid-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("daed.db");

    for raw_url in ["", "   ", "ftp://example.test/geosite/releases/latest"] {
        let err = set_geodata_source_url(&state, GeodataKind::Geosite, raw_url).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_http_reader_accepts_unexpected_eof_after_response_bytes() {
    let mut reader = UnexpectedEofAfterData {
        data: b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest".as_slice(),
        eof_sent: false,
    };

    let response = read_geodata_http_response(&mut reader).unwrap();
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest"
    );
}

#[test]
fn geodata_http_reader_streams_response_body_to_file() {
    let dir =
        std::env::temp_dir().join(format!("daed-product-geodata-stream-{}", fastrand::u64(..)));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("geosite.dat");
    let mut reader = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest".as_slice();
    let base_url = url::Url::parse("https://example.com/geosite.dat").unwrap();

    let result = read_geodata_http_response_to_file(&base_url, &mut reader, &path).unwrap();
    let GeodataHttpFileResult::Body(download) = result else {
        panic!("expected streamed body");
    };
    assert_eq!(download.bytes, 4);
    assert_eq!(download.sha256, hex_encode(&Sha256::digest(b"test")));
    assert_eq!(fs::read(&path).unwrap(), b"test");

    let _ = fs::remove_dir_all(&dir);
}

struct UnexpectedEofAfterData<'a> {
    data: &'a [u8],
    eof_sent: bool,
}

impl Read for UnexpectedEofAfterData<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.data.is_empty() {
            if self.eof_sent {
                return Ok(0);
            }
            self.eof_sent = true;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing close_notify",
            ));
        }
        let len = self.data.len().min(buf.len());
        buf[..len].copy_from_slice(&self.data[..len]);
        self.data = &self.data[len..];
        Ok(len)
    }
}

fn message(fields: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    fields.into_iter().flatten().collect()
}

fn field_string(field: u64, value: &str) -> Vec<u8> {
    field_bytes(field, value.as_bytes())
}

fn field_message(field: u64, value: Vec<u8>) -> Vec<u8> {
    field_bytes(field, &value)
}

fn field_bytes(field: u64, value: &[u8]) -> Vec<u8> {
    let mut out = encode_varint((field << 3) | 2);
    out.extend(encode_varint(value.len() as u64));
    out.extend_from_slice(value);
    out
}

fn field_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = encode_varint(field << 3);
    out.extend(encode_varint(value));
    out
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
