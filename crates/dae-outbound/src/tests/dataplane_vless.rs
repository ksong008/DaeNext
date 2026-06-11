use super::*;

#[test]
fn case_vless_tcp_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless.fixture.invalid:443";
    let payload = b"fixture-vless-tcp-ping";
    let (proxy, handle) = spawn_vless_tcp_echo_server(key, payload.len());
    let report = vless::tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(accepted.version, vless::VLESS_VERSION);
    assert_eq!(accepted.key, key);
    assert_eq!(accepted.addons_len, 0);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn case_vless_udp_over_tcp_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "1.2.3.4:53";
    let payload = b"fixture-vless-udp-ping";
    let (proxy, handle) = spawn_vless_udp_over_tcp_echo_server(key);
    let report = vless::udp_over_tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Udp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.packet_len, 2 + payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert_eq!(accepted.version, vless::VLESS_VERSION);
    assert_eq!(accepted.key, key);
    assert_eq!(accepted.addons_len, 0);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Udp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload_len, payload.len());
    assert_eq!(accepted.packet_len, 2 + payload.len());
    assert_eq!(accepted.payload, payload);
}

#[test]
fn case_vless_mux_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-mux.fixture.invalid:443";
    let payload = b"fixture-vless-mux-ping";
    let mux_id = [0x64, 0x01];
    let (proxy, handle) = spawn_vless_mux_echo_server(key, mux_id, target.to_owned());
    let report = vless::mux_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        mux_id,
        target,
        "tcp",
        payload,
    )
    .unwrap();
    let (request, new_frame, data_frame, end_frame) = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Mux.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.new_frame_validated);
    assert!(report.data_frame_validated);
    assert!(report.end_frame_sent);
    assert_eq!(request.version, vless::VLESS_VERSION);
    assert_eq!(request.key, key);
    assert_eq!(request.addons_len, 0);
    assert_eq!(request.command, crate::vmess::VMessNetwork::Mux.byte());
    assert_eq!(new_frame.id, mux_id);
    assert_eq!(new_frame.status, shared_transport::mux::SESSION_STATUS_NEW);
    assert_eq!(data_frame.id, mux_id);
    assert_eq!(
        data_frame.status,
        shared_transport::mux::SESSION_STATUS_KEEP
    );
    assert_eq!(data_frame.option, shared_transport::mux::OPTION_DATA);
    assert_eq!(data_frame.payload, payload);
    assert_eq!(end_frame.id, mux_id);
    assert_eq!(end_frame.status, shared_transport::mux::SESSION_STATUS_END);
}

#[test]
fn case_vless_websocket_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-ws.fixture.invalid:443";
    let ws_host = "fixture-vless-proxy.fixture.invalid";
    let ws_path = "/dae-vless-ws";
    let payload = b"fixture-vless-ws-ping";
    let (proxy, handle) = spawn_vless_websocket_echo_server(
        key,
        target.to_owned(),
        ws_host.to_owned(),
        ws_path.to_owned(),
        payload.len(),
    );
    let report = vless::tcp_exchange_over_websocket_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        ws_host,
        ws_path,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.ws_host, ws_host);
    assert_eq!(report.ws_path, ws_path);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.websocket_handshake_validated);
    assert!(report.websocket_binary_frame_validated);
    assert!(report.websocket_request_frame_len > report.request_header_len);
    assert!(report.websocket_response_frame_len > report.response_header_len);
    assert_eq!(accepted.request.version, vless::VLESS_VERSION);
    assert_eq!(accepted.request.key, key);
    assert_eq!(accepted.request.addons_len, 0);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.websocket_request_frame_len > accepted.request.header_len);
}

#[test]
fn case_vless_httpupgrade_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-httpupgrade.fixture.invalid:443";
    let httpupgrade_host = "fixture-vless-upgrade.fixture.invalid";
    let httpupgrade_path = "/dae-vless-httpupgrade";
    let payload = b"fixture-vless-httpupgrade-ping";
    let (proxy, handle) = spawn_vless_httpupgrade_echo_server(
        key,
        target.to_owned(),
        httpupgrade_host.to_owned(),
        httpupgrade_path.to_owned(),
        payload.len(),
    );
    let report = vless::tcp_exchange_over_httpupgrade_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        httpupgrade_host,
        httpupgrade_path,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.httpupgrade_host, httpupgrade_host);
    assert_eq!(report.httpupgrade_path, httpupgrade_path);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.httpupgrade_handshake_validated);
    assert!(report.httpupgrade_request_len > httpupgrade_path.len());
    assert!(report.httpupgrade_response_head_len > 0);
    assert_eq!(accepted.version, vless::VLESS_VERSION);
    assert_eq!(accepted.key, key);
    assert_eq!(accepted.addons_len, 0);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn case_vless_grpc_hunk_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-grpc.fixture.invalid:443";
    let grpc_service_name = "dae-fixture-grpc";
    let payload = b"fixture-vless-grpc-ping";
    let (proxy, handle) = spawn_vless_grpc_hunk_echo_server(
        key,
        target.to_owned(),
        grpc_service_name.to_owned(),
        payload.len(),
    );
    let grpc_options = shared_transport::GrpcLifecycleOptions::new(
        &proxy,
        grpc_service_name,
        "fixture-vless-grpc-sni.fixture.invalid",
        "fixture-vless-grpc-dialer",
        true,
        1234,
        true,
    );
    let report = vless::tcp_exchange_over_grpc_hunk_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        &grpc_options,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.grpc_service_name, grpc_service_name);
    assert_eq!(report.grpc_cache_key, grpc_options.cache_key());
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.grpc_stream_preface_validated);
    assert!(report.grpc_hunk_frame_validated);
    assert!(report.cache_key_route_context_validated);
    assert!(!report.full_grpc_http2_stack);
    assert!(report.grpc_preface_len > grpc_service_name.len());
    assert!(report.grpc_request_hunk_len > report.request_header_len);
    assert!(report.grpc_response_hunk_len > report.response_header_len);
    assert_eq!(accepted.request.version, vless::VLESS_VERSION);
    assert_eq!(accepted.request.key, key);
    assert_eq!(accepted.request.addons_len, 0);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.grpc_request_hunk_len > accepted.request.header_len);
}

#[test]
fn case_vless_meek_polling_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-meek.fixture.invalid:443";
    let meek_options = shared_transport::MeekRoundTripOptions::from_https_url(
        "https://front.fixture.invalid/dae-fixture-meek",
        b"dae-fixture-meek".to_vec(),
    )
    .unwrap();
    let payload = b"fixture-vless-meek-ping";
    let (proxy, handle) = spawn_vless_meek_polling_echo_server(
        key,
        target.to_owned(),
        meek_options.clone(),
        payload.len(),
    );
    let report = vless::tcp_exchange_over_meek_polling_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        &meek_options,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.meek_url, meek_options.url);
    assert_eq!(report.meek_host, meek_options.host);
    assert_eq!(report.meek_path, meek_options.path);
    assert_eq!(report.meek_session_id, meek_options.session_id());
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.meek_polling_validated);
    assert!(report.meek_session_id_validated);
    assert!(!report.full_https_round_tripper);
    assert!(report.meek_request_len > report.meek_request_body_len);
    assert!(report.meek_response_head_len > 0);
    assert_eq!(
        report.meek_response_body_len,
        report.response_header_len + payload.len()
    );
    assert_eq!(accepted.request.version, vless::VLESS_VERSION);
    assert_eq!(accepted.request.key, key);
    assert_eq!(accepted.request.addons_len, 0);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.meek_session_id_validated);
    assert_eq!(
        accepted.meek_request_body_len,
        accepted.request.header_len + payload.len()
    );
}

#[test]
fn case_vless_http_transport_put_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-http-target.fixture.invalid:443";
    let payload = b"fixture-vless-http-put-ping";
    let mut options = crate::http_proxy::HttpConnectOptions::connect(
        "fixture-vless-http-proxy.fixture.invalid:443",
    );
    options.host_override = "fixture-vless-http.fixture.invalid".to_owned();
    options.transport.enabled = true;
    options.transport.path = "/dae-fixture-http".to_owned();
    let (proxy, handle) = spawn_vless_http_transport_echo_server(
        key,
        target.to_owned(),
        options.clone(),
        payload.len(),
    );

    let report = vless::tcp_exchange_over_http_transport_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        &options,
        payload,
    )
    .unwrap();
    let (head, accepted) = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(!report.full_http2_stack);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(
        report.http_transport_host,
        "fixture-vless-http.fixture.invalid"
    );
    assert_eq!(report.http_transport_path, "/dae-fixture-http");
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.http_transport_put_validated);
    assert_eq!(report.request_header_len, accepted.header_len);
    assert_eq!(report.http_transport_request_len, head.request_head_len);
    assert!(report.http_transport_request_len > report.request_header_len);
    assert!(report.http_transport_response_head_len > 0);
    assert_eq!(head.method, "PUT");
    assert_eq!(
        head.request_uri,
        "http://fixture-vless-http.fixture.invalid/dae-fixture-http"
    );
    assert_eq!(head.host, "fixture-vless-http.fixture.invalid");
    assert!(head.transport_enabled);
    assert_eq!(accepted.version, vless::VLESS_VERSION);
    assert_eq!(accepted.key, key);
    assert_eq!(accepted.addons_len, 0);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn case_vless_xhttp_packet_dataplane_echoes_payload() {
    let key = vless::password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    let target = "fixture-vless-xhttp-target.fixture.invalid:443";
    let payload = b"fixture-vless-xhttp-ping";
    let options = shared_transport::XHttpLifecycleOptions::new(
        "fixture-vless-xhttp.fixture.invalid",
        "/dae-fixture-xhttp",
        "packet-up",
        "tls",
        "h2",
        "dae-fixture-xhttp",
        79,
    )
    .unwrap();
    let (proxy, handle) = spawn_vless_xhttp_packet_echo_server(
        key,
        target.to_owned(),
        options.clone(),
        payload.len(),
    );

    let report = vless::tcp_exchange_over_xhttp_packet_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        &key,
        target,
        &options,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(!report.full_h2_h3_stack);
    assert!(!report.xhttp_xmux_enabled);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.target, target);
    assert_eq!(report.xhttp_host, "fixture-vless-xhttp.fixture.invalid");
    assert_eq!(report.xhttp_path, "/dae-fixture-xhttp/");
    assert_eq!(
        report.xhttp_request_path,
        "/dae-fixture-xhttp/?session=dae-fixture-xhttp&seq=79"
    );
    assert_eq!(report.xhttp_mode, "packet-up");
    assert_eq!(report.xhttp_alpn, "h2");
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.response_header_len, 2);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.xhttp_packet_up_validated);
    assert_eq!(
        report.xhttp_request_body_len,
        report.request_header_len + payload.len()
    );
    assert_eq!(
        report.xhttp_response_body_len,
        report.response_header_len + payload.len()
    );
    assert_eq!(accepted.request.version, vless::VLESS_VERSION);
    assert_eq!(accepted.request.key, key);
    assert_eq!(accepted.request.addons_len, 0);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.xhttp_packet_up_validated);
    assert_eq!(
        accepted.xhttp_request_body_len,
        accepted.request.header_len + payload.len()
    );
    assert_eq!(
        accepted.xhttp_request_path,
        "/dae-fixture-xhttp/?session=dae-fixture-xhttp&seq=79"
    );
}
