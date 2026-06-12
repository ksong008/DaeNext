use super::*;
use serde_json::json;
use std::net::SocketAddrV4;

const FLOW_DIAL_TARGET: &str = "flow-dial-target";
const FLOW_OUTBOUND: &str = "flow-outbound";
const FLOW_POLICY: &str = "fixed";
const FLOW_DIALER: &str = "flow-dialer";
const FLOW_PROCESS: &str = "flow-process";
const FLOW_MAC: &str = "flow-mac";
const FLOW_SNIFFED_DOMAIN: &str = "flow-sniffed-domain";

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
    assert_eq!(padding.len(), 128);
    assert!(padding.bytes().all(|byte| byte == b'X'));
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
    assert!(
        decoder
            .push(&[0x82, 0x03, b't', b'w', b'o'])
            .unwrap()
            .is_empty()
    );
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

fn tcp_router_for_test(
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
) -> ResidentTcpRouter {
    let mut proxies = BTreeMap::new();
    proxies.insert(
        OutboundIndex::USER_DEFINED_MIN.value(),
        ResidentProxyGroupPlan::fixed_single_for_test(dummy_proxy_plan()),
    );
    ResidentTcpRouter::new(
        proxies,
        Some(1),
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
        protocol: "vless".to_owned(),
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
        tls: "tls".to_owned(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        reality: None,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] },
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}
