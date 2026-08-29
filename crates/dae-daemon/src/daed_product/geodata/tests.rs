use super::status::{
    geodata_status_for_dir, geodata_status_parse_count, reset_geodata_status_parse_count,
};
use super::*;
use super::{GEOIP_FILE, GEOSITE_FILE, GeodataSourceMode};
use dae_product_geodata::{
    GeodataHttpFileResult, read_geodata_http_response, read_geodata_http_response_to_file,
};
use dae_product_geodata::{
    GeodataSourceUrlUpdate, geodata_source, geodata_source_status, reset_geodata_source_url,
    set_geodata_source_url, set_geodata_source_use_proxy, update_geodata_source_settings,
};
use sha2::{Digest, Sha256};

mod status_cache;
mod transaction;
mod update;

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
    assert_eq!(geosite["sourceType"], json!("direct"));
    assert_eq!(geosite["useProxy"], json!(false));
    assert_eq!(
        geosite["url"],
        json!(GeodataKind::Geosite.default_source_url())
    );

    let custom_url = "https://mirror.example.test/download/geosite-data";
    let geosite = set_geodata_source_url(&state, GeodataKind::Geosite, custom_url).unwrap();
    assert_eq!(geosite["url"], json!(custom_url));
    assert_eq!(geosite["usingDefault"], json!(false));
    assert_eq!(geosite["sourceType"], json!("direct"));
    assert_eq!(
        geodata_source(&state, GeodataKind::Geosite)
            .unwrap()
            .url
            .as_str(),
        custom_url
    );

    let legacy_api_url = GeodataKind::Geosite.legacy_release_api_url();
    let geosite = set_geodata_source_url(&state, GeodataKind::Geosite, legacy_api_url).unwrap();
    assert_eq!(geosite["url"], json!(legacy_api_url));
    assert_eq!(geosite["usingDefault"], json!(false));
    assert_eq!(geosite["sourceType"], json!("release"));
    assert_eq!(
        geodata_source(&state, GeodataKind::Geosite).unwrap().mode,
        GeodataSourceMode::ReleaseApi
    );

    let geosite = reset_geodata_source_url(&state, GeodataKind::Geosite).unwrap();
    assert_eq!(geosite["usingDefault"], json!(true));
    assert_eq!(
        geosite["url"],
        json!(GeodataKind::Geosite.default_source_url())
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_source_settings_use_cdn_v2ray_rules_defaults() {
    assert_eq!(
        GeodataKind::Geosite.default_source_url(),
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
    );
    assert_eq!(
        GeodataKind::Geoip.default_source_url(),
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
    );
    assert_eq!(
        GeodataKind::Geosite.legacy_release_api_url(),
        "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"
    );
    assert_eq!(
        GeodataKind::Geoip.legacy_release_api_url(),
        "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"
    );
}

#[test]
fn geodata_source_settings_accept_direct_files_and_use_proxy() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-source-direct-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("daed.db");

    let direct_url = "https://mirror.example.test/data/geoip.dat";
    let geoip = set_geodata_source_url(&state, GeodataKind::Geoip, direct_url).unwrap();
    assert_eq!(geoip["url"], json!(direct_url));
    assert_eq!(geoip["sourceType"], json!("direct"));
    assert_eq!(geoip["useProxy"], json!(false));

    let geoip = set_geodata_source_use_proxy(&state, GeodataKind::Geoip, true).unwrap();
    assert_eq!(geoip["sourceType"], json!("direct"));
    assert_eq!(geoip["useProxy"], json!(true));

    let source = geodata_source(&state, GeodataKind::Geoip).unwrap();
    assert_eq!(source.mode, GeodataSourceMode::DirectFile);
    assert!(source.use_proxy);
    assert_eq!(source.url.as_str(), direct_url);

    let geoip = reset_geodata_source_url(&state, GeodataKind::Geoip).unwrap();
    assert_eq!(geoip["usingDefault"], json!(true));
    assert_eq!(geoip["sourceType"], json!("direct"));
    assert_eq!(geoip["useProxy"], json!(true));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_source_url_and_proxy_setting_roll_back_together() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-source-transaction-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("daed.db");
    ensure_state_schema(&state).unwrap();
    open_state_connection(&state)
        .unwrap()
        .execute_batch(
            r#"
            CREATE TRIGGER reject_geodata_proxy_setting
            BEFORE INSERT ON daed_product_metadata
            WHEN NEW.key = 'geodata_geoip_use_proxy'
            BEGIN
                SELECT RAISE(ABORT, 'injected geodata proxy setting failure');
            END;
            "#,
        )
        .unwrap();

    let error = update_geodata_source_settings(
        &state,
        GeodataKind::Geoip,
        GeodataSourceUrlUpdate::Set("https://mirror.example.test/data/geoip.dat"),
        Some(true),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected geodata proxy setting failure")
    );
    let status = geodata_source_status(&state, GeodataKind::Geoip).unwrap();
    assert_eq!(status["usingDefault"], json!(true));
    assert_eq!(status["useProxy"], json!(false));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn geodata_source_settings_accepts_shared_release_api_url_for_both_kinds() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-source-shared-release-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let state = dir.join("daed.db");
    let release_api_url = GeodataKind::Geosite.legacy_release_api_url();

    let geosite = set_geodata_source_url(&state, GeodataKind::Geosite, release_api_url).unwrap();
    assert_eq!(geosite["sourceType"], json!("release"));
    let geoip = set_geodata_source_url(&state, GeodataKind::Geoip, release_api_url).unwrap();
    assert_eq!(geoip["sourceType"], json!("release"));

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
        GeodataKind::Geoip.default_source_url(),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("geosite source cannot use geoip default update url")
    );
    let err = set_geodata_source_url(
        &state,
        GeodataKind::Geoip,
        GeodataKind::Geosite.default_source_url(),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("geoip source cannot use geosite default update url")
    );

    let err = set_geodata_source_url(
        &state,
        GeodataKind::Geoip,
        "https://mirror.example.test/data/geosite.dat",
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("geoip source cannot use geosite data file url")
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

#[test]
fn geodata_https_redirect_rejects_plain_http_downgrade() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-redirect-downgrade-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("geosite.dat");
    let mut reader = b"HTTP/1.1 302 Found\r\nLocation: http://example.test/geosite.dat\r\nContent-Length: 0\r\n\r\n"
        .as_slice();
    let base_url = url::Url::parse("https://example.test/geosite.dat").unwrap();

    let Err(error) = read_geodata_http_response_to_file(&base_url, &mut reader, &path) else {
        panic!("HTTPS to HTTP redirect was admitted");
    };

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("HTTPS to HTTP redirect"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn geodata_redirect_preserves_safe_relative_and_upgrade_targets() {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-safe-redirect-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("geosite.dat");
    for (base, location, expected) in [
        (
            "https://example.test/releases/latest",
            "/assets/geosite.dat",
            "https://example.test/assets/geosite.dat",
        ),
        (
            "http://example.test/geosite.dat",
            "https://cdn.example.test/geosite.dat",
            "https://cdn.example.test/geosite.dat",
        ),
    ] {
        let response =
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
        let mut reader = response.as_bytes();
        let base_url = url::Url::parse(base).unwrap();
        let result = read_geodata_http_response_to_file(&base_url, &mut reader, &path).unwrap();
        let GeodataHttpFileResult::Redirect(next) = result else {
            panic!("expected safe geodata redirect");
        };
        assert_eq!(next.as_str(), expected);
    }
    fs::remove_dir_all(dir).unwrap();
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
