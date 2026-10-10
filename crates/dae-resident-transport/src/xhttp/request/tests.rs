use super::*;
use std::collections::BTreeMap;

#[test]
fn xhttp_browser_aliases_reach_each_request_encoder() {
    for alias in [
        None,
        Some("chrome"),
        Some("edge"),
        Some("firefox"),
        Some("safari"),
        Some("curl"),
        Some("golang"),
        Some("Custom-UA/1"),
        Some("Chrome"),
        Some(""),
    ] {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        if let Some(ua) = alias {
            settings.headers.insert("uSeR-aGeNt".into(), ua.into());
            settings
                .headers
                .insert("user-agent".into(), "shadowed-ua".into());
        }
        settings
            .headers
            .insert("Accept".into(), "application/test".into());
        settings.headers.insert("priority".into(), "u=7".into());
        settings
            .headers
            .insert("Accept-Language".into(), "custom-language".into());
        let endpoint = test_xhttp_endpoint(settings);
        let payload = Bytes::from_static(b"payload");
        let raw = xhttp_h1_packet_up_request_bytes(&endpoint, "s", 0, payload.clone()).unwrap();
        let end = raw.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
        assert_eq!(&raw[end + 4..], b"payload");
        assert_eq!(
            std::str::from_utf8(&raw[..end])
                .unwrap()
                .lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("user-agent:"))
                .count(),
            usize::from(alias != Some(""))
        );
        let h1 = std::str::from_utf8(&raw[..end])
            .unwrap()
            .lines()
            .skip(1)
            .map(|line| {
                let (key, value) = line.split_once(':').unwrap();
                (key.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect::<BTreeMap<_, _>>();
        let (h2, body2) = xhttp_h2_packet_up_request(&endpoint, "s", 0, payload.clone()).unwrap();
        let (h3, body3) = xhttp_h3_packet_up_request(&endpoint, "s", 0, payload.clone()).unwrap();
        assert_eq!(body2, Some(payload.clone()));
        assert_eq!(body3, Some(payload));
        for headers in [h2.headers(), h3.headers()] {
            assert_eq!(
                headers.get_all("user-agent").iter().count(),
                usize::from(alias != Some(""))
            );
        }
        let maps = [
            h1,
            h2.headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                .collect(),
            h3.headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                .collect(),
        ];
        for (version, headers) in maps.iter().enumerate() {
            let ua = headers
                .get("user-agent")
                .map(String::as_str)
                .unwrap_or_default();
            let browser = alias.unwrap_or("chrome");
            assert_eq!(headers.contains_key("user-agent"), alias != Some(""));
            match browser {
                "chrome" | "edge" => {
                    assert!(ua.contains("Chrome/"));
                    assert_eq!(ua.contains("Edg/"), browser == "edge");
                    let major = ua
                        .split("Chrome/")
                        .nth(1)
                        .unwrap()
                        .split('.')
                        .next()
                        .unwrap();
                    assert!(headers["sec-ch-ua"].contains(&format!("v=\"{major}\"")));
                    assert_eq!(headers["sec-ch-ua-platform"], "\"Windows\"");
                }
                "firefox" => {
                    assert!(ua.contains("Firefox/"));
                    assert_eq!(headers["accept-language"], "en-US,en;q=0.5");
                }
                "safari" => assert!(
                    ua.contains("Version/") && ua.contains("Safari/") && !ua.contains("Chrome/")
                ),
                "curl" => assert!(ua.starts_with("curl/8.")),
                "golang" => assert_eq!(
                    ua,
                    ["Go-http-client/1.1", "Go-http-client/2.0", "quic-go HTTP/3"][version]
                ),
                custom => assert_eq!(ua, custom),
            }
            let masqueraded = matches!(browser, "chrome" | "edge" | "firefox" | "safari");
            assert_eq!(
                headers.get("sec-fetch-mode").map(String::as_str),
                masqueraded.then_some("cors")
            );
            assert_eq!(headers["accept"], "application/test");
            assert_eq!(headers["priority"], "u=7");
            assert!(!headers.contains_key("content-type"));
            assert!(headers.contains_key("referer"));
            if browser != "golang" {
                assert_eq!(headers.get("user-agent"), maps[0].get("user-agent"));
            }
        }
    }
}

#[test]
fn xhttp_h1_packet_reuse_respects_explicit_connection_policy() {
    let mut endpoint = test_xhttp_endpoint(ResidentXhttpSettingsPlan::official_default());
    let request = String::from_utf8(
        xhttp_h1_packet_up_request_bytes(&endpoint, "s", 0, Bytes::new()).unwrap(),
    )
    .unwrap();
    assert!(request.contains("Connection: keep-alive\r\n"));
    assert!(!request.contains("Connection: close"));
    endpoint
        .settings
        .headers
        .insert("connection".into(), "close".into());
    let request = String::from_utf8(
        xhttp_h1_packet_up_request_bytes(&endpoint, "s", 0, Bytes::new()).unwrap(),
    )
    .unwrap();
    assert!(request.contains("connection: close\r\n"));
    assert!(!request.contains("Connection: keep-alive"));
}

#[test]
fn xhttp_default_session_is_uuid_v4() {
    for _ in 0..32 {
        let id = new_xhttp_uuid_session_id().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }
}

#[test]
fn xhttp_payload_chunks_sample_each_boundary_and_reassemble() {
    let mut settings = ResidentXhttpSettingsPlan::official_default();
    settings.uplink_chunk_size = Some((64, 128));
    let payload = Bytes::from(vec![42; 8192]);
    let chunks = xhttp_encoded_payload_chunks("X-Data", '-', &settings, &payload);
    assert!(
        chunks
            .iter()
            .take(chunks.len() - 1)
            .all(|(_, v)| (64..=128).contains(&v.len()))
    );
    assert!(chunks.windows(2).any(|c| c[0].1.len() != c[1].1.len()));
    let encoded = chunks.iter().map(|(_, v)| v.as_str()).collect::<String>();
    assert_eq!(
        general_purpose::URL_SAFE_NO_PAD.decode(encoded).unwrap(),
        payload
    );
    assert!(
        random_ascii(b"abc", 4096)
            .bytes()
            .all(|b| b"abc".contains(&b))
    );
}

#[test]
fn packet_up_content_type_is_consistent_across_http_versions() {
    for configured in [None, Some("application/octet-stream")] {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        if let Some(value) = configured {
            settings
                .headers
                .insert("Content-Type".to_owned(), value.to_owned());
        }
        let endpoint = test_xhttp_endpoint(settings);
        let payload = Bytes::from_static(b"packet");
        let h1 = String::from_utf8(
            xhttp_h1_packet_up_request_bytes(&endpoint, "session", 0, payload.clone()).unwrap(),
        )
        .unwrap();
        let (h2, h2_body) =
            xhttp_h2_packet_up_request(&endpoint, "session", 0, payload.clone()).unwrap();
        let (h3, h3_body) =
            xhttp_h3_packet_up_request(&endpoint, "session", 0, payload.clone()).unwrap();
        assert_eq!(
            h1.to_ascii_lowercase().contains("content-type:"),
            configured.is_some()
        );
        for request in [h2, h3] {
            assert_eq!(
                request
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .map(|value| value.to_str().unwrap()),
                configured
            );
        }
        assert_eq!(h2_body, Some(payload.clone()));
        assert_eq!(h3_body, Some(payload));
    }
}

#[test]
fn stream_upload_grpc_header_remains_optional() {
    for no_grpc_header in [false, true] {
        let mut settings = ResidentXhttpSettingsPlan::official_default();
        settings.no_grpc_header = no_grpc_header;
        let endpoint = test_xhttp_endpoint(settings);
        let request = xhttp_h2_request(http::Method::POST, &endpoint, "", true).unwrap();
        assert_eq!(
            request
                .headers()
                .get(http::header::CONTENT_TYPE)
                .map(|value| value.to_str().unwrap()),
            (!no_grpc_header).then_some("application/grpc")
        );
    }
}

#[test]
fn generated_metadata_replaces_existing_query_values() {
    let mut settings = ResidentXhttpSettingsPlan::official_default();
    settings.session_id_placement = ResidentXhttpMetaPlacement::Query;
    settings.seq_placement = ResidentXhttpMetaPlacement::Query;
    settings.x_padding_obfs_mode = true;
    settings.x_padding_placement = ResidentXhttpPaddingPlacement::Query;
    settings.x_padding_bytes = Some((4, 4));
    let mut endpoint = test_xhttp_endpoint(settings);
    endpoint.stream_path =
        "/xhttp?token=a%20b&x_session=old&x%5Fsession=older&x_seq=99&x_padding=old".to_owned();
    let (request, _) = xhttp_h2_packet_up_request(&endpoint, "current", 7, Bytes::new()).unwrap();
    let query = request.uri().query().unwrap();
    assert!(query.starts_with("token=a%20b&"));
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    for (key, expected) in [
        ("x_session", "current"),
        ("x_seq", "7"),
        ("x_padding", "XXXX"),
    ] {
        let values = pairs
            .iter()
            .filter(|(name, _)| name == key)
            .map(|(_, value)| value.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(values, [expected]);
    }
    assert_eq!(
        xhttp_join_query(
            "same=old",
            &[
                ("same".to_owned(), "padding".to_owned()),
                ("same".to_owned(), "session".to_owned())
            ]
        ),
        "same=session"
    );
}

#[test]
fn tokenish_padding_tracks_hpack_target_within_two_bytes() {
    for target in [1, 2, 7, 32, 127, 900] {
        let padding = xhttp_generate_padding(ResidentXhttpPaddingMethod::Tokenish, target);
        assert!(!padding.is_empty());
        assert!(hpack_huffman_len(padding.as_bytes()).abs_diff(target) <= 2);
    }
}

fn test_xhttp_endpoint(settings: ResidentXhttpSettingsPlan) -> ResidentXhttpEndpointPlan {
    ResidentXhttpEndpointPlan {
        server_host: "server.invalid".to_owned(),
        server_port: 443,
        server_name: "server.invalid".to_owned(),
        alpn: vec!["h2".to_owned()],
        stream_host: "stream.invalid".to_owned(),
        stream_path: "/x?ed=2048".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings,
        xmux: None,
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
    }
}

#[test]
fn xhttp_packet_up_request_applies_header_query_extended_settings() {
    let mut settings = ResidentXhttpSettingsPlan::official_default();
    settings
        .headers
        .insert("X-Test".to_owned(), "alpha".to_owned());
    settings.x_padding_bytes = Some((4, 4));
    settings.x_padding_obfs_mode = true;
    settings.x_padding_key = "pad".to_owned();
    settings.x_padding_placement = ResidentXhttpPaddingPlacement::Query;
    settings.session_id_placement = ResidentXhttpMetaPlacement::Header;
    settings.session_id_key = "X-Sid".to_owned();
    settings.seq_placement = ResidentXhttpMetaPlacement::Query;
    settings.seq_key = "seq".to_owned();
    settings.uplink_data_placement = ResidentXhttpUplinkDataPlacement::Header;
    settings.uplink_data_key = "X-Body".to_owned();
    settings.uplink_chunk_size = Some((64, 64));
    let endpoint = test_xhttp_endpoint(settings);

    let (request, body) =
        xhttp_h2_packet_up_request(&endpoint, "sid-1", 7, Bytes::from_static(b"hello")).unwrap();

    assert!(body.is_none());
    assert_eq!(
        request.uri().path_and_query().unwrap().as_str(),
        "/x?ed=2048&pad=XXXX&seq=7"
    );
    assert_eq!(request.headers()["X-Test"], "alpha");
    assert_eq!(request.headers()["X-Sid"], "sid-1");
    assert_eq!(request.headers()["X-Body-0"], "aGVsbG8");
    assert!(!request.headers().contains_key(http::header::CONTENT_TYPE));
}

#[test]
fn xhttp_packet_up_request_applies_cookie_extended_settings() {
    let mut settings = ResidentXhttpSettingsPlan::official_default();
    settings.x_padding_bytes = Some((3, 3));
    settings.x_padding_obfs_mode = true;
    settings.x_padding_placement = ResidentXhttpPaddingPlacement::Cookie;
    settings.session_id_placement = ResidentXhttpMetaPlacement::Cookie;
    settings.session_id_key = "x_session".to_owned();
    settings.seq_placement = ResidentXhttpMetaPlacement::Cookie;
    settings.seq_key = "x_seq".to_owned();
    settings.uplink_data_placement = ResidentXhttpUplinkDataPlacement::Cookie;
    settings.uplink_data_key = "x_data".to_owned();
    settings.uplink_chunk_size = Some((64, 64));
    let endpoint = test_xhttp_endpoint(settings);

    let bytes =
        xhttp_h1_packet_up_request_bytes(&endpoint, "sid-2", 5, Bytes::from_static(b"hi")).unwrap();
    let request = String::from_utf8(bytes).unwrap();

    assert!(request.starts_with("POST /x?ed=2048 HTTP/1.1\r\n"));
    assert!(request.contains("cookie: x_data_0=aGk; x_padding=XXX; x_session=sid-2; x_seq=5\r\n"));
    assert!(!request.contains("Content-Type: application/grpc\r\n"));
    assert!(!request.contains("Content-Length:"));
}

struct ShortWriter {
    bytes: Vec<u8>,
    interrupted: bool,
    zero: bool,
    pending: bool,
    flushed: bool,
}
impl tokio::io::AsyncWrite for ShortWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.pending && !self.bytes.is_empty() {
            return std::task::Poll::Pending;
        }
        if self.interrupted {
            self.interrupted = false;
            return std::task::Poll::Ready(Err(std::io::ErrorKind::Interrupted.into()));
        }
        if self.zero {
            return std::task::Poll::Ready(Ok(0));
        }
        let size = bytes.len().min(2);
        self.bytes.extend_from_slice(&bytes[..size]);
        std::task::Poll::Ready(Ok(size))
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.flushed = true;
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn h1_vectored_chunks_handle_interruption_short_writes_and_write_zero() {
    let mut writer = ShortWriter {
        bytes: Vec::new(),
        interrupted: true,
        zero: false,
        pending: false,
        flushed: false,
    };
    write_xhttp_h1_chunk(&mut writer, &Bytes::from_static(b"hello"), true, "short")
        .await
        .unwrap();
    assert_eq!(writer.bytes, b"5\r\nhello\r\n0\r\n\r\n");
    assert!(writer.flushed);
    writer.zero = true;
    assert!(
        write_xhttp_h1_chunk(&mut writer, &Bytes::from_static(b"x"), false, "zero")
            .await
            .unwrap_err()
            .contains("write")
    );
}

#[tokio::test]
async fn h1_chunk_cancellation_does_not_flush_or_emit_a_successful_final_chunk() {
    let mut writer = ShortWriter {
        bytes: Vec::new(),
        interrupted: false,
        zero: false,
        pending: true,
        flushed: false,
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(5),
            write_xhttp_h1_chunk(&mut writer, &Bytes::from_static(b"hello"), true, "cancel")
        )
        .await
        .is_err()
    );
    assert_eq!(writer.bytes, b"5\r");
    assert!(!writer.flushed);
}
