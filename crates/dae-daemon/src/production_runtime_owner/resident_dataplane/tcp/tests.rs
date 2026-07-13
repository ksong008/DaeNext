use super::*;
use crate::production_runtime_owner::resident_dataplane::ResidentConnectUdpRuntimePlan;
use crate::production_runtime_owner::resident_dataplane::plan::resident_tcp_check_network_type;
use dae_outbound::NetworkType;
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

const FLOW_DIAL_TARGET: &str = "flow-dial-target";
const FLOW_OUTBOUND: &str = "flow-outbound";
const FLOW_POLICY: &str = "fixed";
const FLOW_DIALER: &str = "flow-dialer";
const FLOW_PROCESS: &str = "flow-process";
const FLOW_MAC: &str = "flow-mac";
const FLOW_SNIFFED_DOMAIN: &str = "flow-sniffed-domain";
const FLOW_INITIAL_OUTBOUND: u8 = 7;
const FLOW_FINAL_OUTBOUND: u8 = 9;
const FLOW_FINAL_MARK: u32 = 0x55;
const FLOW_PID: u32 = 1;
const FLOW_DSCP: u8 = 2;

#[test]
fn accepted_ipv4_mapped_tcp_endpoints_use_the_ipv4_health_dimension() {
    let ipv4 = Ipv4Addr::new(198, 51, 100, 20);
    let mapped = SocketAddrV6::new(ipv4.to_ipv6_mapped(), 443, 0, 0).into();
    let expected = SocketAddrV4::new(ipv4, 443).into();

    let normalized = resident_tcp_accepted_endpoint(mapped);

    assert_eq!(normalized, expected);
    assert_eq!(
        resident_tcp_check_network_type(normalized.ip()),
        NetworkType::TCP4
    );
    assert_eq!(resident_tcp_network_name(normalized), "tcp4");
}

fn flow_route_selection() -> TcpRouteSelection {
    TcpRouteSelection {
        initial_outbound: FLOW_INITIAL_OUTBOUND,
        final_outbound: FLOW_FINAL_OUTBOUND,
        final_mark: FLOW_FINAL_MARK,
        userspace_route_executed: true,
        userspace_route_must: false,
        dial_target: FLOW_DIAL_TARGET.to_owned(),
        dial_ip: false,
        log_metadata: TcpRoutingLogMetadata {
            pid: FLOW_PID,
            dscp: FLOW_DSCP,
            pname: FLOW_PROCESS.to_owned(),
            mac: FLOW_MAC.to_owned(),
        },
    }
}

struct TestAsyncRead {
    bytes: Vec<u8>,
    offset: usize,
}

impl TestAsyncRead {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl AsyncRead for TestAsyncRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset >= self.bytes.len() {
            return Poll::Ready(Ok(()));
        }
        let remaining = &self.bytes[self.offset..];
        let len = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..len]);
        self.offset += len;
        Poll::Ready(Ok(()))
    }
}

#[test]
fn resident_upload_relay_treats_peer_close_as_graceful_end() {
    assert!(is_graceful_stream_close_error(&std::io::Error::from(
        ErrorKind::BrokenPipe
    )));
    assert!(is_graceful_stream_close_error(&std::io::Error::from(
        ErrorKind::ConnectionReset
    )));
    assert!(is_graceful_stream_close_error(&std::io::Error::from(
        ErrorKind::ConnectionAborted
    )));
    assert!(!is_graceful_stream_close_error(&std::io::Error::from(
        ErrorKind::TimedOut
    )));
    assert!(is_graceful_tls_plain_close_error(&std::io::Error::other(
        "peer closed connection without sending TLS close_notify",
    )));
}

#[test]
fn vless_websocket_tls_close_error_is_graceful_only_after_response_progress() {
    let boringssl_close =
        || std::io::Error::other("[BAD_DECRYPT] [DECRYPTION_FAILED_OR_BAD_RECORD_MAC]");
    assert!(!is_graceful_vless_response_tls_plain_close_error(
        &boringssl_close(),
        &RelayStats::default(),
    ));

    let stripped = RelayStats {
        response_header_stripped: true,
        ..RelayStats::default()
    };
    assert!(is_graceful_vless_response_tls_plain_close_error(
        &boringssl_close(),
        &stripped,
    ));

    let downloaded = RelayStats {
        proxy_to_client: 1,
        ..RelayStats::default()
    };
    assert!(is_graceful_vless_response_tls_plain_close_error(
        &boringssl_close(),
        &downloaded,
    ));
    assert!(!is_graceful_vless_response_tls_plain_close_error(
        &std::io::Error::other("certificate verify failed"),
        &downloaded,
    ));
}

#[test]
fn resident_tcp_probe_http_request_uses_configured_method_path_and_host() {
    let request = String::from_utf8(resident_tcp_probe_http_request(
        "HEAD",
        "/generate_204",
        "check.fixture.invalid",
    ))
    .unwrap();
    assert!(request.starts_with("HEAD /generate_204 HTTP/1.1\r\n"));
    assert!(request.contains("Host: check.fixture.invalid\r\n"));
    assert!(request.contains("Connection: close\r\n"));
}

#[test]
fn resident_tcp_probe_status_matches_compatible_http_check_rules() {
    assert!(resident_tcp_probe_status_ok("/generate_204", 204));
    assert!(!resident_tcp_probe_status_ok("/generate_204", 200));
    assert!(resident_tcp_probe_status_ok("/", 204));
    assert!(resident_tcp_probe_status_ok("/", 404));
    assert!(!resident_tcp_probe_status_ok("/", 500));
}

#[test]
fn tcp_route_chosen_event_exposes_route_decision_fields() {
    let route = flow_route_selection();
    let selection = TcpSelection::Direct(TcpDirectSelection { route, mptcp: true });
    let sniff = TcpSniffReport {
        payload: Vec::new(),
        domain: FLOW_SNIFFED_DOMAIN.to_owned(),
        error: None,
    };
    let peer = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100).into();
    let original_dst = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443).into();

    let event = tcp_route_chosen_event(peer, original_dst, &selection, &sniff, "domain");

    assert_eq!(event["event"], TCP_ROUTE_CHOSEN_EVENT);
    assert_eq!(event["dial_mode"], "domain");
    assert_eq!(event["outbound_kind"], TCP_OUTBOUND_KIND_DIRECT);
    assert_eq!(event["mptcp"], true);
    assert_eq!(event["initial_outbound"], FLOW_INITIAL_OUTBOUND);
    assert_eq!(event["final_outbound"], FLOW_FINAL_OUTBOUND);
    assert_eq!(event["final_mark"], FLOW_FINAL_MARK);
    assert_eq!(event["dial_target"], FLOW_DIAL_TARGET);
    assert_eq!(event["network"], resident_tcp_network_name(original_dst));
    assert_eq!(event["outbound"], TCP_OUTBOUND_KIND_DIRECT);
    assert_eq!(event["policy"], TCP_FIXED_POLICY);
    assert_eq!(event["dialer"], TCP_DIRECT_DIALER);
    assert_eq!(event["sniffed"], FLOW_SNIFFED_DOMAIN);
    assert_eq!(event["pid"], FLOW_PID);
    assert_eq!(event["dscp"], FLOW_DSCP);
    assert_eq!(event["pname"], FLOW_PROCESS);
    assert_eq!(event["mac"], FLOW_MAC);

    let v6_original_dst =
        SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20), 443, 0, 0).into();
    let v6_event = tcp_route_chosen_event(
        SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10), 43100, 0, 0).into(),
        v6_original_dst,
        &selection,
        &sniff,
        "domain",
    );
    assert_eq!(
        v6_event["network"],
        resident_tcp_network_name(v6_original_dst)
    );
    assert_ne!(event["network"], v6_event["network"]);
}

#[test]
fn tcp_route_log_fields_use_generic_network_for_unparseable_destination() {
    let route = flow_route_selection();
    let mut event = json!({
        "original_dst": "unparseable-destination",
        "sniffed_domain": FLOW_SNIFFED_DOMAIN,
    });

    append_tcp_route_log_fields(&mut event, &route, FLOW_OUTBOUND, FLOW_POLICY, FLOW_DIALER);

    assert_eq!(event["network"], "tcp");
    assert_eq!(event["outbound"], FLOW_OUTBOUND);
    assert_eq!(event["policy"], FLOW_POLICY);
    assert_eq!(event["dialer"], FLOW_DIALER);
}

#[tokio::test(flavor = "current_thread")]
async fn resident_tcp_handler_join_uses_short_grace_after_exchange_failure() {
    let mut handle = tokio::spawn(async { std::future::pending::<Result<Value, String>>().await });
    let started = Instant::now();
    let err =
        join_resident_tcp_handler_after_exchange_async(&mut handle, Duration::from_secs(30), true)
            .await
            .unwrap_err();

    assert!(err.contains("timeout after exchange failure"));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "failed TCP probe waited too long for handler cleanup: {:?}",
        started.elapsed()
    );
    assert!(handle.is_finished());
}

#[test]
fn simple_obfs_http_status_accepts_ok_or_switching_protocols() {
    assert!(validate_simple_obfs_http_response_status(b"HTTP/1.1 200 OK\r\n\r\n").is_ok());
    assert!(
        validate_simple_obfs_http_response_status(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            .is_ok()
    );
    assert!(validate_simple_obfs_http_response_status(b"HTTP/1.1 404 Not Found\r\n\r\n").is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn simple_obfs_tls_app_data_reader_unwraps_followup_frames() {
    let frame = simple_obfs_tls_application_data_frame(b"tail").unwrap();
    let mut stream = TestAsyncRead::new(frame);
    let mut reader = AsyncSimpleObfsTlsAppDataReader::new(b"head".to_vec(), &mut stream);
    let mut out = [0_u8; 8];
    reader.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, b"headtail");
}

#[tokio::test(flavor = "current_thread")]
async fn prefix_tcp_reader_drains_prefix_then_stream() {
    let mut stream = TestAsyncRead::new(b"tail".to_vec());
    let mut reader = AsyncPrefixTcpReader::new(b"head".to_vec(), &mut stream);
    let mut out = [0_u8; 8];
    reader.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, b"headtail");
}

#[test]
fn xhttp_h2_uri_uses_path_session_placement() {
    let mut proxy = dummy_proxy_plan();
    proxy.net = "xhttp".to_owned();
    proxy.server_name = "tls.name.invalid".to_owned();
    proxy.stream_host = "edge.transport.invalid".to_owned();
    proxy.stream_path = "/resource?ed=2048".to_owned();

    assert_eq!(
        xhttp_uri(&proxy, &xhttp_session_path_suffix("session-id", None)),
        "https://edge.transport.invalid/resource/session-id?ed=2048"
    );
    assert_eq!(
        xhttp_uri(&proxy, &xhttp_session_path_suffix("session-id", Some(7))),
        "https://edge.transport.invalid/resource/session-id/7?ed=2048"
    );
}

#[test]
fn xhttp_h2_request_uses_default_referer_padding() {
    let mut proxy = dummy_proxy_plan();
    proxy.net = "xhttp".to_owned();
    proxy.server_name = "tls.name.invalid".to_owned();
    proxy.stream_host = "edge.transport.invalid".to_owned();
    proxy.stream_path = "/resource?ed=2048".to_owned();

    let request = xhttp_h2_request(
        http::Method::GET,
        &proxy,
        &xhttp_session_path_suffix("session-id", None),
        false,
    )
    .unwrap();
    assert_eq!(
        request.uri().to_string(),
        "https://edge.transport.invalid/resource/session-id?ed=2048"
    );
    let referer = request
        .headers()
        .get(http::header::REFERER)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(referer.starts_with("https://edge.transport.invalid/resource/?x_padding="));
    let padding = referer.split_once("x_padding=").unwrap().1;
    assert!((100..=1000).contains(&padding.len()));
    assert!(padding.bytes().all(|byte| byte == b'X'));
}

#[test]
fn xhttp_h1_request_uses_official_packet_up_shape() {
    let mut proxy = dummy_proxy_plan();
    proxy.net = "xhttp".to_owned();
    proxy.server_name = "tls.name.invalid".to_owned();
    proxy.stream_host = "edge.transport.invalid".to_owned();
    proxy.stream_path = "/resource?ed=2048".to_owned();
    let payload = Bytes::from_static(b"hello");

    let request = xhttp_h1_request_bytes(
        http::Method::POST,
        &proxy,
        &xhttp_session_path_suffix("session-id", Some(7)),
        Some(&payload),
    );
    let request = String::from_utf8(request).unwrap();

    assert!(request.starts_with("POST /resource/session-id/7?ed=2048 HTTP/1.1\r\n"));
    assert!(request.contains("Host: edge.transport.invalid\r\n"));
    assert!(request.contains("content-type: application/grpc\r\n"));
    assert!(request.contains("Content-Length: 5\r\n"));
    assert!(request.contains("Connection: close\r\n"));
    assert!(request.ends_with("\r\n\r\nhello"));
    let referer = request
        .lines()
        .find_map(|line| {
            line.strip_prefix("Referer: ")
                .or_else(|| line.strip_prefix("referer: "))
        })
        .unwrap();
    assert!(referer.starts_with("https://edge.transport.invalid/resource/?x_padding="));
    let padding = referer.split_once("x_padding=").unwrap().1;
    assert!((100..=1000).contains(&padding.len()));
    assert!(padding.bytes().all(|byte| byte == b'X'));
}

#[test]
fn runtime_generation_reaches_primary_and_download_xmux_keys() {
    let mut proxy = dummy_proxy_plan();
    proxy.xhttp_xmux = Some(ResidentXhttpXmuxPlan::official_default());
    proxy.xhttp_download = Some(ResidentXhttpEndpointPlan::from_proxy(&proxy));

    proxy.apply_runtime_generation(73, ResidentConnectUdpRuntimePlan::standalone());

    assert_eq!(proxy.xhttp_xmux.as_ref().unwrap().runtime_generation, 73);
    assert_eq!(
        proxy
            .xhttp_download
            .as_ref()
            .unwrap()
            .xmux
            .as_ref()
            .unwrap()
            .runtime_generation,
        73
    );
}

#[test]
fn grpc_h2_request_declares_identity_encoding() {
    let mut proxy = dummy_proxy_plan();
    proxy.server_name = "tls.name.invalid".to_owned();
    proxy.stream_host = "edge.transport.invalid".to_owned();
    proxy.stream_path = "/GunService".to_owned();

    let request = grpc_h2_request(&proxy).unwrap();

    assert_eq!(
        request.uri().to_string(),
        "https://edge.transport.invalid/GunService/Tun"
    );
    assert_eq!(
        request.headers().get(http::header::CONTENT_TYPE).unwrap(),
        GRPC_CONTENT_TYPE_APPLICATION
    );
    assert_eq!(
        request.headers().get(GRPC_TE_HEADER).unwrap(),
        GRPC_TE_TRAILERS
    );
    assert_eq!(
        request.headers().get(GRPC_ENCODING_HEADER).unwrap(),
        GRPC_IDENTITY_ENCODING
    );
    assert_eq!(
        request.headers().get(GRPC_ACCEPT_ENCODING_HEADER).unwrap(),
        GRPC_IDENTITY_ENCODING
    );
}

#[test]
fn grpc_hunk_read_buffer_rejects_compressed_frames() {
    let mut buffer = GrpcHunkReadBuffer::default();
    buffer.extend_from_slice(&[1, 0, 0, 0, 0]);

    let err = buffer.pop_payload().unwrap_err();

    assert!(err.contains("compressed gRPC hunk"));
}

#[test]
fn grpc_hunk_read_buffer_rejects_oversized_message_before_buffering_payload() {
    let mut buffer = GrpcHunkReadBuffer::default();
    let oversized = RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES as u32 + 1;
    let mut header = vec![0];
    header.extend_from_slice(&oversized.to_be_bytes());
    buffer.extend_from_slice(&header);

    let err = buffer.pop_payload().unwrap_err();
    assert!(err.contains("gRPC hunk exceeds"));
}

#[test]
fn resident_vless_response_stripper_handles_split_header() {
    let mut stripper = VlessResponseStripper::default();
    assert!(stripper.consume(&[0]).unwrap().is_empty());
    assert!(stripper.consume(&[3, b'a']).unwrap().is_empty());
    assert_eq!(stripper.consume(b"bcOK").unwrap(), b"OK");
    assert!(stripper.done);
    assert_eq!(stripper.consume(b"NEXT").unwrap(), b"NEXT");
}

#[test]
fn resident_websocket_decoder_treats_close_frame_as_eof() {
    let mut decoder = WebSocketBinaryFrameDecoder::default();
    let frames = decoder
        .push(&[0x82, 0x03, b'o', b'n', b'e', 0x88, 0x00])
        .unwrap();
    assert_eq!(frames, vec![b"one".to_vec()]);
    assert!(decoder.is_closed());
    let responses = decoder.take_control_responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(
        decode_client_websocket_control_frame(&responses[0]),
        (8, Vec::new())
    );
    assert!(
        decoder
            .push(&[0x82, 0x03, b't', b'w', b'o'])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn resident_websocket_decoder_reassembles_fragmented_binary_messages() {
    let mut decoder = WebSocketBinaryFrameDecoder::default();

    assert!(
        decoder
            .push(&[0x02, 0x03, b'o', b'n', b'e'])
            .unwrap()
            .is_empty()
    );
    assert!(
        decoder
            .push(&[0x00, 0x03, b't', b'w', b'o'])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        decoder
            .push(&[0x80, 0x05, b't', b'h', b'r', b'e', b'e'])
            .unwrap(),
        vec![b"onetwothree".to_vec()]
    );
}

#[test]
fn resident_websocket_decoder_accepts_control_frames_between_fragments() {
    let mut decoder = WebSocketBinaryFrameDecoder::default();

    assert!(
        decoder
            .push(&[0x02, 0x03, b'o', b'n', b'e'])
            .unwrap()
            .is_empty()
    );
    assert!(
        decoder
            .push(&[0x89, 0x04, b'p', b'i', b'n', b'g'])
            .unwrap()
            .is_empty()
    );
    assert!(
        decoder
            .push(&[0x8a, 0x04, b'p', b'o', b'n', b'g'])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        decoder.push(&[0x80, 0x03, b't', b'w', b'o']).unwrap(),
        vec![b"onetwo".to_vec()]
    );
    let responses = decoder.take_control_responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(
        decode_client_websocket_control_frame(&responses[0]),
        (10, b"ping".to_vec())
    );
}

#[test]
fn resident_websocket_decoder_accepts_bounded_64_bit_payload_length() {
    let payload = vec![0x5a; u16::MAX as usize + 1];
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.extend_from_slice(&[0x82, 0x7f]);
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);

    let mut decoder = WebSocketBinaryFrameDecoder::default();
    assert_eq!(decoder.push(&frame).unwrap(), vec![payload]);
}

#[test]
fn resident_websocket_decoder_rejects_invalid_fragment_state_and_oversize() {
    let mut decoder = WebSocketBinaryFrameDecoder::default();
    assert!(
        decoder
            .push(&[0x80, 0x01, b'x'])
            .unwrap_err()
            .contains("continuation without")
    );

    let mut decoder = WebSocketBinaryFrameDecoder::default();
    decoder.push(&[0x02, 0x01, b'a']).unwrap();
    assert!(
        decoder
            .push(&[0x82, 0x01, b'b'])
            .unwrap_err()
            .contains("before fragmented message completed")
    );

    let mut decoder = WebSocketBinaryFrameDecoder::default();
    assert!(
        decoder
            .push(&[0x09, 0x00])
            .unwrap_err()
            .contains("invalid websocket control frame")
    );

    let oversized = RESIDENT_WEBSOCKET_MAX_MESSAGE_BYTES as u64 + 1;
    let mut frame = vec![0x82, 0x7f];
    frame.extend_from_slice(&oversized.to_be_bytes());
    let mut decoder = WebSocketBinaryFrameDecoder::default();
    assert!(decoder.push(&frame).unwrap_err().contains("frame exceeds"));
}

#[tokio::test(flavor = "current_thread")]
async fn async_websocket_payload_reader_writes_pong_and_delivers_binary_data() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        server
            .write_all(&[0x89, 0x04, b'p', b'i', b'n', b'g'])
            .await
            .unwrap();
        let mut pong = [0_u8; 10];
        server.read_exact(&mut pong).await.unwrap();
        server
            .write_all(&[0x02, 0x03, b'o', b'n', b'e', 0x80, 0x03, b't', b'w', b'o'])
            .await
            .unwrap();
        pong
    });

    let mut state = AsyncWebSocketPayloadState::default();
    let mut reader = AsyncWebSocketPayloadReader::new(&mut client, &mut state);
    let mut payload = [0_u8; 6];
    reader.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"onetwo");

    let pong = server_task.await.unwrap();
    assert_eq!(
        decode_client_websocket_control_frame(&pong),
        (10, b"ping".to_vec())
    );
}

fn decode_client_websocket_control_frame(frame: &[u8]) -> (u8, Vec<u8>) {
    assert!(frame.len() >= 6);
    assert_ne!(frame[0] & 0x80, 0);
    assert_ne!(frame[1] & 0x80, 0);
    let opcode = frame[0] & 0x0f;
    let payload_len = (frame[1] & 0x7f) as usize;
    assert_eq!(frame.len(), 6 + payload_len);
    let mask = [frame[2], frame[3], frame[4], frame[5]];
    let payload = frame[6..]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % mask.len()])
        .collect();
    (opcode, payload)
}

#[test]
fn proxy_failure_event_carries_relay_diagnostics() {
    let selection = TcpProxySelection {
        mark: 0x55,
        mptcp: false,
        route: TcpRouteSelection {
            initial_outbound: 7,
            final_outbound: 7,
            final_mark: 0x55,
            userspace_route_executed: true,
            userspace_route_must: false,
            dial_target: FLOW_DIAL_TARGET.to_owned(),
            dial_ip: false,
            log_metadata: TcpRoutingLogMetadata {
                pid: 1,
                dscp: 2,
                pname: FLOW_PROCESS.to_owned(),
                mac: FLOW_MAC.to_owned(),
            },
        },
        proxy: Arc::new(dummy_proxy_plan()),
    };
    let sniff = TcpSniffReport {
        payload: Vec::new(),
        domain: FLOW_SNIFFED_DOMAIN.to_owned(),
        error: None,
    };
    let stats = RelayStats {
        client_to_proxy: 128,
        proxy_to_client: 64,
        response_header_stripped: true,
        vision_unpadding_blocks: 2,
        vision_direct_command_seen: false,
        vision_raw_direct_recovered: false,
        vision_downlink_direct_active: false,
    };
    let err = RelayError::new("read proxy plaintext: sample failure", &stats);

    let event = proxy_tcp_failed_event(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100)),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443)),
        &selection,
        &sniff,
        "boringssl",
        &err,
        "async-proxy-tls",
    );

    assert_eq!(event["event"], "tcp_connection_failed");
    assert_eq!(event["tls_underlay"], "boringssl");
    assert!(event.get("execution").is_none());
    assert_eq!(event["executionDescriptor"]["schemaVersion"], 1);
    assert_eq!(event["executionDescriptor"]["executor"], "tcp-relay");
    assert_eq!(
        event["executionDescriptor"]["capability"],
        "stream-transport"
    );
    assert_eq!(event["executionDescriptor"]["network"], "tcp");
    assert_eq!(
        event["executionDescriptor"]["securityUnderlay"],
        "boringssl"
    );
    assert_eq!(event["executionDescriptor"]["protocolFraming"], "vless");
    assert_eq!(
        event["executionDescriptor"]["graphId"],
        "resident-graph:test-flow"
    );
    assert_eq!(event["error"], "read proxy plaintext: sample failure");
    assert_eq!(event["bytes_client_to_proxy"], 128);
    assert_eq!(event["bytes_proxy_to_client"], 64);
    assert_eq!(event["response_header_stripped"], true);
    assert_eq!(event["vision_unpadding_blocks"], 2);
    assert_eq!(event["vision_direct_command_seen"], false);
    assert_eq!(event["vision_raw_direct_recovered"], false);
    assert_eq!(event["vision_downlink_direct_active"], false);
    assert_eq!(event["proxy_group"], FLOW_OUTBOUND);
    assert_eq!(event["group_policy"], FLOW_POLICY);
    assert_eq!(event["node_tag"], FLOW_DIALER);
    assert_eq!(event["sniffed_domain"], FLOW_SNIFFED_DOMAIN);
}

#[test]
fn resident_tcp_selection_allows_builtin_direct_without_proxy_plan() {
    let router = tcp_router_for_test(fallback_matcher("user:2", 0), TcpDialMode::DomainPlusPlus);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443));
    let selection = router
        .select_from_routing_result(
            peer,
            dst,
            "www.fixture.invalid",
            BpfRoutingResult {
                outbound: OUTBOUND_DIRECT,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Direct(selection) = selection else {
        panic!("expected direct selection");
    };
    assert_eq!(selection.route.initial_outbound, OUTBOUND_DIRECT);
    assert_eq!(selection.route.final_outbound, OUTBOUND_DIRECT);
    assert_eq!(selection.route.final_mark, 0x1234);
    assert_eq!(selection.route.dial_target, dst.to_string());
    assert!(selection.route.dial_ip);
    assert!(!selection.route.userspace_route_executed);
    assert!(selection.mptcp);
}

#[test]
fn resident_tcp_selection_defaults_zero_mark_to_control_plane_mark() {
    let mut proxies = BTreeMap::new();
    proxies.insert(
        OutboundIndex::USER_DEFINED_MIN.value(),
        ResidentProxyGroupPlan::fixed_single_for_test(dummy_proxy_plan()),
    );
    let router = ResidentTcpRouter::new_for_test(
        proxies,
        fallback_matcher("direct", 0),
        TcpDialMode::Ip,
        Duration::from_millis(100),
        0,
        true,
    )
    .unwrap();
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443));
    let selection = router
        .select_from_routing_result(
            peer,
            dst,
            "",
            BpfRoutingResult {
                outbound: OUTBOUND_DIRECT,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Direct(selection) = selection else {
        panic!("expected direct selection");
    };
    assert_eq!(
        selection.route.final_mark,
        super::super::plan::RESIDENT_CONTROL_PLANE_SO_MARK
    );
}

#[test]
fn resident_tcp_selection_reroutes_control_plane_result_to_direct() {
    let router = tcp_router_for_test(
        fallback_matcher("direct", 0x77),
        TcpDialMode::DomainPlusPlus,
    );
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 99), 443));
    let selection = router
        .select_from_routing_result(
            peer,
            dst,
            "www.reroute.test",
            BpfRoutingResult {
                outbound: OUTBOUND_CONTROL_PLANE_ROUTING,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Direct(selection) = selection else {
        panic!("expected direct selection after userspace reroute");
    };
    assert_eq!(
        selection.route.initial_outbound,
        OUTBOUND_CONTROL_PLANE_ROUTING
    );
    assert_eq!(selection.route.final_outbound, OUTBOUND_DIRECT);
    assert_eq!(selection.route.final_mark, 0x77);
    assert_eq!(selection.route.dial_target, dst.to_string());
    assert!(selection.route.userspace_route_executed);
}

#[test]
fn resident_tcp_selection_returns_block_without_proxy_plan() {
    let router = tcp_router_for_test(fallback_matcher("user:2", 0), TcpDialMode::Ip);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443));
    let selection = router
        .select_from_routing_result(
            peer,
            dst,
            "",
            BpfRoutingResult {
                outbound: OUTBOUND_BLOCK,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Block(selection) = selection else {
        panic!("expected block selection");
    };
    assert_eq!(selection.route.final_outbound, OUTBOUND_BLOCK);
    assert_eq!(selection.route.final_mark, 0x1234);
}

#[test]
fn resident_tcp_selection_still_rejects_missing_user_proxy_plan() {
    let router = tcp_router_for_test(fallback_matcher("user:2", 0), TcpDialMode::Ip);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443));
    let err = router
        .select_from_routing_result(
            peer,
            dst,
            "",
            BpfRoutingResult {
                outbound: 9,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap_err();
    assert!(err.contains("no Rust proxy plan is available"));
    assert!(err.contains("unsupported protocol"));
}

#[test]
fn resident_tcp_selection_keeps_ip_target_when_domain_plus_plus_has_no_sniffed_domain() {
    let router = tcp_router_for_test(
        fallback_matcher("direct", 0x77),
        TcpDialMode::DomainPlusPlus,
    );
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(91, 108, 56, 177), 443));
    let selection = router
        .select_from_routing_result(
            peer,
            dst,
            "",
            BpfRoutingResult {
                outbound: OutboundIndex::USER_DEFINED_MIN.value(),
                mark: 0x55,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Proxy(selection) = selection else {
        panic!("expected proxy selection");
    };
    assert_eq!(
        selection.route.initial_outbound,
        OutboundIndex::USER_DEFINED_MIN.value()
    );
    assert_eq!(
        selection.route.final_outbound,
        OutboundIndex::USER_DEFINED_MIN.value()
    );
    assert_eq!(selection.route.dial_target, dst.to_string());
    assert!(selection.route.dial_ip);
    assert!(!selection.route.userspace_route_executed);
    assert_eq!(selection.route.final_mark, 0x55);
}

#[test]
fn resident_tcp_selection_domain_mode_requires_real_domain() {
    let router = tcp_router_for_test(fallback_matcher("direct", 0x77), TcpDialMode::Domain);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(91, 108, 56, 177), 443));
    let initial = BpfRoutingResult {
        outbound: OutboundIndex::USER_DEFINED_MIN.value(),
        mark: 0x55,
        ..BpfRoutingResult::default()
    };

    let selection = router
        .select_from_routing_result(peer, dst, "www.example.com", initial)
        .unwrap();
    let TcpSelection::Proxy(selection) = selection else {
        panic!("expected proxy selection");
    };
    assert_eq!(selection.route.dial_target, dst.to_string());
    assert!(selection.route.dial_ip);

    let selection = router
        .select_from_routing_result_with_domain_real(peer, dst, "www.example.com", initial, true)
        .unwrap();
    let TcpSelection::Proxy(selection) = selection else {
        panic!("expected proxy selection");
    };
    assert_eq!(selection.route.dial_target, "www.example.com:443");
    assert!(!selection.route.dial_ip);
    assert!(!selection.route.userspace_route_executed);
    assert_eq!(selection.route.final_mark, 0x55);
}

#[test]
fn resident_tcp_selection_uses_destination_ip_family_for_proxy_group() {
    let sections = dae_config::parser::parse_config(
        r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks5://127.0.0.1:1080'
        node_b: 'socks5://127.0.0.2:1080'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
        }
        }
        routing {
        fallback: proxy
        }
        "#,
    )
    .unwrap();
    let config = dae_config::schema::build_config(&sections).unwrap();
    let plan = super::super::plan::build_resident_dataplane_plan(&config).unwrap();
    let group = plan.default_proxy_group().unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(20), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(200), 2)
        .unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP6, Some(300), 3)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP6, Some(50), 4)
        .unwrap();
    let router = ResidentTcpRouter::new_for_test(
        plan.proxies.clone(),
        fallback_matcher("direct", 0),
        TcpDialMode::Ip,
        Duration::from_millis(100),
        0x1234,
        true,
    )
    .unwrap();
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let v4_dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443));
    let v6_dst = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20),
        443,
        0,
        0,
    ));

    let v4_selection = router
        .select_from_routing_result(
            peer,
            v4_dst,
            "",
            BpfRoutingResult {
                outbound: OutboundIndex::USER_DEFINED_MIN.value(),
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Proxy(v4_selection) = v4_selection else {
        panic!("expected IPv4 proxy selection");
    };
    assert_eq!(v4_selection.proxy.node_tag, "node_a");

    let v6_selection = router
        .select_from_routing_result(
            peer,
            v6_dst,
            "",
            BpfRoutingResult {
                outbound: OutboundIndex::USER_DEFINED_MIN.value(),
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Proxy(v6_selection) = v6_selection else {
        panic!("expected IPv6 proxy selection");
    };
    assert_eq!(v6_selection.proxy.node_tag, "node_b");
}

#[test]
fn resident_tcp_router_and_runtime_summary_share_group_selector_state() {
    let sections = dae_config::parser::parse_config(
        r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks5://127.0.0.1:1080'
        node_b: 'socks5://127.0.0.2:1080'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: min
        }
        }
        routing {
        fallback: proxy
        }
        "#,
    )
    .unwrap();
    let config = dae_config::schema::build_config(&sections).unwrap();
    let plan = super::super::plan::build_resident_dataplane_plan(&config).unwrap();
    let default_outbound = plan.default_outbound.unwrap();
    let shared_groups = share_resident_proxy_groups(plan.proxies);
    let group = shared_groups.get(&default_outbound).unwrap();
    group
        .record_check_result("node_a", NetworkType::TCP4, Some(200), 1)
        .unwrap();
    group
        .record_check_result("node_b", NetworkType::TCP4, Some(20), 2)
        .unwrap();
    let router = ResidentTcpRouter::new_for_test_shared(
        Arc::clone(&shared_groups),
        fallback_matcher("direct", 0),
        TcpDialMode::Ip,
        Duration::from_millis(100),
        0x1234,
        true,
    )
    .unwrap();
    let runtime_groups = shared_groups.values().cloned().collect::<Vec<_>>();
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 43100));
    let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443));

    let selection = router
        .select_from_routing_result(
            peer,
            dst,
            "",
            BpfRoutingResult {
                outbound: default_outbound,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Proxy(selection) = selection else {
        panic!("expected proxy selection");
    };
    assert_eq!(selection.proxy.node_tag, "node_b");
    let snapshot = super::super::resident_group_selector_snapshot_map(&runtime_groups);
    assert_eq!(snapshot["proxy"]["selectedNodeTag"], json!("node_b"));

    group
        .record_check_result("node_a", NetworkType::TCP4, Some(10), 3)
        .unwrap();
    let selection = router
        .select_from_routing_result(
            peer,
            dst,
            "",
            BpfRoutingResult {
                outbound: default_outbound,
                ..BpfRoutingResult::default()
            },
        )
        .unwrap();
    let TcpSelection::Proxy(selection) = selection else {
        panic!("expected proxy selection");
    };
    assert_eq!(selection.proxy.node_tag, "node_a");
    let snapshot = super::super::resident_group_selector_snapshot_map(&runtime_groups);
    assert_eq!(snapshot["proxy"]["selectedNodeTag"], json!("node_a"));
}

fn tcp_router_for_test(
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
) -> ResidentTcpRouter {
    let mut proxies = BTreeMap::new();
    proxies.insert(
        OutboundIndex::USER_DEFINED_MIN.value(),
        ResidentProxyGroupPlan::fixed_single_for_test(dummy_proxy_plan()),
    );
    ResidentTcpRouter::new_for_test(
        proxies,
        routing_matcher,
        dial_mode,
        Duration::from_millis(100),
        0x1234,
        true,
    )
    .unwrap()
}

fn fallback_matcher(outbound: &str, mark: u32) -> RoutingMatcher {
    RoutingMatcher::from_fixture_value(&json!({
        "matches": [
            {
                "type": "fallback",
                "outbound": outbound,
                "mark": mark
            }
        ],
        "domain_sets": [],
        "lpm_sets": []
    }))
    .unwrap()
}

fn dummy_proxy_plan() -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "resident-graph:test-flow".to_owned(),
        graph_link_hash: "sha256:test-flow".to_owned(),
        redacted_link_source: "vless:<redacted>#flow".to_owned(),
        protocol: "vless",
        group_name: FLOW_OUTBOUND.to_owned(),
        group_policy: FLOW_POLICY.to_owned(),
        node_tag: FLOW_DIALER.to_owned(),
        server_host: "127.0.0.1".to_owned(),
        server_port: 443,
        server_name: "fixture.invalid".to_owned(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        tls: "tls".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}

#[test]
fn plain_http_connect_preserves_tunneled_bytes_read_with_response_head() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nearly")
                .await
                .unwrap();
        });

        let mut client = TokioTcpStream::connect(address).await.unwrap();
        http_proxy_connect_plain_async(
            &mut client,
            "target.fixture.invalid:443",
            "",
            "",
            false,
            "",
            "",
        )
        .await
        .unwrap();
        let mut payload = [0_u8; 5];
        time::timeout(Duration::from_secs(1), client.read_exact(&mut payload))
            .await
            .expect("early tunneled bytes must remain readable")
            .unwrap();
        assert_eq!(&payload, b"early");
        server.await.unwrap();
    });
}
