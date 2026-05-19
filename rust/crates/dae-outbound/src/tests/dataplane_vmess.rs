use super::*;

#[test]
fn stage65_vmess_aead_tcp_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage65-vmess.example:443";
    let payload = b"stage65-vmess-aead-ping";
    let (proxy, handle) = spawn_vmess_aead_tcp_echo_server(uuid.to_owned());
    let report = vmess::aead_tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.request_header_len > 58);
    assert!(report.request_chunk_len > payload.len() + 16);
    assert_eq!(report.response_header_len, 38);
    assert!(report.response_chunk_len > payload.len() + 16);
    assert_eq!(accepted.version, 1);
    assert!(accepted.eauth_crc_validated);
    assert_eq!(accepted.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}

#[test]
fn stage66_vmess_aead_udp_over_tcp_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "1.2.3.4:53";
    let payload = b"stage66-vmess-udp-ping";
    let (proxy, handle) = spawn_vmess_aead_udp_over_tcp_echo_server(uuid.to_owned());
    let report = vmess::aead_udp_over_tcp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Udp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.packet_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.request_header_len > 58);
    assert!(report.request_chunk_len > payload.len() + 16);
    assert_eq!(report.response_header_len, 38);
    assert!(report.response_chunk_len > payload.len() + 16);
    assert_eq!(accepted.request.version, 1);
    assert!(accepted.request.eauth_crc_validated);
    assert_eq!(
        accepted.request.security,
        vmess::VMESS_AEAD_SECURITY_AES_128_GCM
    );
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Udp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert_eq!(accepted.packet_len, payload.len());
}

#[test]
fn stage67_vmess_packet_addr_udp_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let packet_target = "1.2.3.4:53";
    let payload = b"stage67-vmess-packet-addr-ping";
    let (proxy, handle) = spawn_vmess_packet_addr_udp_echo_server(uuid.to_owned());
    let report = vmess::aead_packet_addr_udp_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        packet_target,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Udp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(
        report.request_target,
        format!("{}:53", vmess::VMESS_PACKET_ADDR_MAGIC_ADDRESS)
    );
    assert_eq!(report.packet_target, packet_target);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.packet_addr_len, 7);
    assert_eq!(report.packet_len, payload.len() + 7);
    assert_eq!(report.echoed_payload, payload);
    assert!(report.request_header_len > 58);
    assert!(report.request_chunk_len > payload.len() + 7 + 16);
    assert_eq!(report.response_header_len, 38);
    assert!(report.response_chunk_len > payload.len() + 7 + 16);
    assert_eq!(accepted.request.version, 1);
    assert!(accepted.request.eauth_crc_validated);
    assert_eq!(
        accepted.request.security,
        vmess::VMESS_AEAD_SECURITY_AES_128_GCM
    );
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Udp.byte()
    );
    assert_eq!(
        accepted.request.target,
        format!("{}:53", vmess::VMESS_PACKET_ADDR_MAGIC_ADDRESS)
    );
    assert_eq!(accepted.packet_target, packet_target);
    assert_eq!(accepted.packet_addr_len, 7);
    assert_eq!(accepted.packet_payload, payload);
}

#[test]
fn stage68_vmess_aead_mux_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage68-vmess-mux.example:443";
    let payload = b"stage68-vmess-mux-ping";
    let mux_id = [0x68, 0x01];
    let (proxy, handle) =
        spawn_vmess_aead_mux_echo_server(uuid.to_owned(), mux_id, target.to_owned());
    let report = vmess::aead_mux_exchange_over_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        mux_id,
        target,
        "tcp",
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Mux.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.request_target, "0.0.0.0:0");
    assert_eq!(report.mux_target, target);
    assert_eq!(report.mux_id_hex, "6801");
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.new_frame_validated);
    assert!(report.data_frame_validated);
    assert!(report.end_frame_sent);
    assert_eq!(accepted.request.version, 1);
    assert!(accepted.request.eauth_crc_validated);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Mux.byte()
    );
    assert_eq!(accepted.request.target, "0.0.0.0:0");
    assert_eq!(accepted.new_frame.id, mux_id);
    assert_eq!(
        accepted.new_frame.status,
        shared_transport::mux::SESSION_STATUS_NEW
    );
    assert_eq!(accepted.data_frame.id, mux_id);
    assert_eq!(
        accepted.data_frame.status,
        shared_transport::mux::SESSION_STATUS_KEEP
    );
    assert_eq!(
        accepted.data_frame.option,
        shared_transport::mux::OPTION_DATA
    );
    assert_eq!(accepted.data_frame.payload, payload);
    assert_eq!(accepted.end_frame.id, mux_id);
    assert_eq!(
        accepted.end_frame.status,
        shared_transport::mux::SESSION_STATUS_END
    );
}

#[test]
fn stage69_vmess_aead_websocket_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage69-vmess-ws.example:443";
    let ws_host = "stage69-vmess-proxy.example";
    let ws_path = "/dae-vmess-ws";
    let payload = b"stage69-vmess-ws-ping";
    let (proxy, handle) = spawn_vmess_aead_websocket_echo_server(
        uuid.to_owned(),
        target.to_owned(),
        ws_host.to_owned(),
        ws_path.to_owned(),
    );
    let report = vmess::aead_tcp_exchange_over_websocket_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        ws_host,
        ws_path,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.ws_host, ws_host);
    assert_eq!(report.ws_path, ws_path);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.websocket_handshake_validated);
    assert!(report.websocket_binary_frame_validated);
    assert!(report.websocket_request_frame_len > report.request_header_len);
    assert!(report.websocket_response_frame_len > report.response_header_len);
    assert_eq!(accepted.request.version, 1);
    assert!(accepted.request.eauth_crc_validated);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.websocket_request_frame_len > accepted.request.request_header_len);
}

#[test]
fn stage70_vmess_aead_httpupgrade_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage70-vmess-httpupgrade.example:443";
    let httpupgrade_host = "stage70-vmess-proxy.example";
    let httpupgrade_path = "/dae-vmess-httpupgrade";
    let payload = b"stage70-vmess-httpupgrade-ping";
    let (proxy, handle) = spawn_vmess_aead_httpupgrade_echo_server(
        uuid.to_owned(),
        target.to_owned(),
        httpupgrade_host.to_owned(),
        httpupgrade_path.to_owned(),
    );
    let report = vmess::aead_tcp_exchange_over_httpupgrade_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        httpupgrade_host,
        httpupgrade_path,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.httpupgrade_host, httpupgrade_host);
    assert_eq!(report.httpupgrade_path, httpupgrade_path);
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.httpupgrade_handshake_validated);
    assert!(report.httpupgrade_tunnel_validated);
    assert!(report.httpupgrade_request_len > httpupgrade_path.len());
    assert!(report.httpupgrade_response_head_len > 0);
    assert_eq!(accepted.request.version, 1);
    assert!(accepted.request.eauth_crc_validated);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.httpupgrade_tunnel_validated);
}

#[test]
fn stage71_vmess_aead_grpc_hunk_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage71-vmess-grpc.example:443";
    let service_name = "dae-stage71-grpc";
    let payload = b"stage71-vmess-grpc-ping";
    let (proxy, handle) = spawn_vmess_aead_grpc_hunk_echo_server(
        uuid.to_owned(),
        target.to_owned(),
        service_name.to_owned(),
    );
    let options = shared_transport::GrpcLifecycleOptions::new(
        &proxy,
        service_name,
        "stage71-vmess-grpc-sni.example",
        "stage71-dialer",
        true,
        1234,
        true,
    );
    let without_mptcp = shared_transport::GrpcLifecycleOptions {
        mptcp: false,
        ..options.clone()
    };
    assert_ne!(options.cache_key(), without_mptcp.cache_key());

    let report = vmess::aead_tcp_exchange_over_grpc_hunk_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        &options,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert!(!report.full_grpc_http2_stack);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.grpc_service_name, service_name);
    assert_eq!(report.grpc_cache_key, options.cache_key());
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.grpc_stream_preface_validated);
    assert!(report.grpc_hunk_frame_validated);
    assert!(report.cache_key_route_context_validated);
    assert!(report.grpc_preface_len > service_name.len());
    assert!(report.grpc_request_hunk_len > report.request_header_len);
    assert!(report.grpc_response_hunk_len > report.response_header_len);
    assert_eq!(accepted.request.version, 1);
    assert!(accepted.request.eauth_crc_validated);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.grpc_request_hunk_len > accepted.request.request_header_len);
}

#[test]
fn stage72_vmess_aead_meek_polling_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage72-vmess-meek.example:443";
    let meek_url = "https://front.example/dae-stage72-meek";
    let payload = b"stage72-vmess-meek-ping";
    let options = shared_transport::MeekRoundTripOptions::from_https_url(
        meek_url,
        b"dae-stage72-meek".to_vec(),
    )
    .unwrap();
    let (proxy, handle) = spawn_vmess_aead_meek_polling_echo_server(
        uuid.to_owned(),
        target.to_owned(),
        options.clone(),
    );

    let report = vmess::aead_tcp_exchange_over_meek_polling_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        &options,
        payload,
    )
    .unwrap();
    let accepted = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert!(!report.full_https_round_tripper);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.meek_url, meek_url);
    assert_eq!(report.meek_host, "front.example");
    assert_eq!(report.meek_path, "/dae-stage72-meek");
    assert_eq!(report.meek_session_id, options.session_id());
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.meek_polling_validated);
    assert!(report.meek_request_len > report.meek_request_body_len);
    assert_eq!(
        report.meek_request_body_len,
        report.request_header_len + report.request_chunk_len
    );
    assert_eq!(
        report.meek_response_body_len,
        report.response_header_len + report.response_chunk_len
    );
    assert_eq!(accepted.request.version, 1);
    assert!(accepted.request.eauth_crc_validated);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Tcp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert!(accepted.meek_session_id_validated);
    assert_eq!(
        accepted.meek_request_body_len,
        accepted.request.request_header_len + accepted.request.request_chunk_len
    );
}

#[test]
fn stage73_vmess_aead_http_transport_put_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "stage73-vmess-http-target.example:443";
    let payload = b"stage73-vmess-http-put-ping";
    let mut options =
        crate::http_proxy::HttpConnectOptions::connect("stage73-vmess-http-proxy.example:443");
    options.host_override = "stage73-vmess-http.example".to_owned();
    options.transport.enabled = true;
    options.transport.path = "/dae-stage73-http".to_owned();
    let (proxy, handle) = spawn_vmess_aead_http_transport_echo_server(
        uuid.to_owned(),
        target.to_owned(),
        options.clone(),
    );

    let report = vmess::aead_tcp_exchange_over_http_transport_stream(
        &mut TcpStream::connect(&proxy).unwrap(),
        &proxy,
        uuid,
        target,
        &options,
        payload,
    )
    .unwrap();
    let (head, accepted) = handle.join().unwrap();

    assert!(report.true_dataplane);
    assert!(report.default_go_path);
    assert!(!report.full_http2_stack);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.http_transport_host, "stage73-vmess-http.example");
    assert_eq!(report.http_transport_path, "/dae-stage73-http");
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.http_transport_put_validated);
    assert!(report.http_transport_request_len > report.request_header_len);
    assert!(report.http_transport_response_head_len > 0);
    assert_eq!(head.method, "PUT");
    assert_eq!(
        head.request_uri,
        "http://stage73-vmess-http.example/dae-stage73-http"
    );
    assert_eq!(head.host, "stage73-vmess-http.example");
    assert!(head.transport_enabled);
    assert_eq!(accepted.version, 1);
    assert!(accepted.eauth_crc_validated);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}
