use super::*;

#[test]
fn case_vmess_aead_tcp_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess.fixture.invalid:443";
    let payload = b"fixture-vmess-aead-ping";
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
fn vmess_aead_tcp_session_empty_initial_payload_writes_header_only() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-empty.fixture.invalid:443";
    let session = vmess::aead_tcp_client_session_start(uuid, target, &[]).unwrap();

    assert_eq!(session.request.target, target);
    assert_eq!(session.request.payload, b"");
    assert_eq!(session.request.request_chunk_len, 0);
    assert_eq!(
        session.first_write.len(),
        session.request.request_header_len,
        "empty initial payload must not emit an empty VMess body chunk"
    );
}

#[test]
fn vmess_explicit_aes_body_security_emits_official_wire_value() {
    let session = vmess::aead_tcp_client_session_start_with_security(
        "7c12c745-63a5-433d-9e60-022e469b5bd4",
        "fixture-vmess-security.fixture.invalid:443",
        b"fixture-vmess-security-payload",
        vmess::VMessBodySecurity::Aes128Gcm,
    )
    .unwrap();

    assert_eq!(
        session.request.security,
        vmess::VMESS_AEAD_SECURITY_AES_128_GCM
    );
    assert_eq!(vmess::VMESS_AEAD_SECURITY_AES_128_GCM, 3);
}

#[test]
fn vmess_body_security_modes_roundtrip_request_and_response_payloads() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-security.fixture.invalid:443";
    let payload = b"fixture-vmess-security-payload";
    for (security, wire, options) in [
        (
            vmess::VMessBodySecurity::Aes128Gcm,
            vmess::VMESS_AEAD_SECURITY_AES_128_GCM,
            0x0d,
        ),
        (
            vmess::VMessBodySecurity::Chacha20Poly1305,
            vmess::VMESS_AEAD_SECURITY_CHACHA20_POLY1305,
            0x0d,
        ),
        (
            vmess::VMessBodySecurity::None,
            vmess::VMESS_AEAD_SECURITY_NONE,
            0x05,
        ),
        (
            vmess::VMessBodySecurity::Zero,
            vmess::VMESS_AEAD_SECURITY_NONE,
            0,
        ),
    ] {
        let session =
            vmess::aead_tcp_client_session_start_with_security(uuid, target, payload, security)
                .unwrap();
        assert_eq!(session.request.security, wire);
        assert_eq!(session.request.request_options, options);

        let mut request_bytes = std::io::Cursor::new(session.first_write.clone());
        let accepted = vmess::read_aead_tcp_request_from_stream(&mut request_bytes, uuid).unwrap();
        assert_eq!(accepted.security, wire);
        assert_eq!(accepted.payload, payload);

        let mut response = vmess::aead_tcp_response_packet(&session.request, payload).unwrap();
        let mut reader =
            vmess::aead_tcp_response_reader_from_buffer(&mut response, &session.request)
                .unwrap()
                .unwrap();
        assert_eq!(
            reader.try_read_chunk_from_buffer(&mut response).unwrap(),
            Some(payload.to_vec())
        );
    }
}

#[test]
fn vmess_zero_body_security_rejects_udp_without_packet_framing() {
    let result = vmess::aead_udp_over_tcp_client_session_start_with_security(
        "7c12c745-63a5-433d-9e60-022e469b5bd4",
        "fixture-vmess-udp.fixture.invalid:53",
        b"packet",
        vmess::VMessBodySecurity::Zero,
    );
    let Err(error) = result else {
        panic!("VMess zero body security must reject UDP without packet framing");
    };
    assert!(error.to_string().contains("has no UDP packet boundary"));
}

#[test]
fn vmess_aead_udp_over_tcp_session_start_uses_udp_command() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "vmess-udp-target.fixture.invalid:53";
    let payload = b"vmess-aead-udp-session-ping";
    let (proxy, handle) = spawn_vmess_aead_udp_over_tcp_echo_server(uuid.to_owned());
    let mut stream = TcpStream::connect(&proxy).unwrap();
    let session = vmess::aead_udp_over_tcp_client_session_start(uuid, target, payload).unwrap();

    stream.write_all(&session.first_write).unwrap();
    let mut response =
        vmess::aead_tcp_response_reader_from_stream(&mut stream, &session.request).unwrap();
    let echoed = response.read_chunk_from_stream(&mut stream).unwrap();
    let accepted = handle.join().unwrap();

    assert_eq!(
        session.request.command,
        crate::vmess::VMessNetwork::Udp.byte()
    );
    assert_eq!(session.request.target, target);
    assert_eq!(session.request.payload, payload);
    assert_eq!(
        accepted.request.command,
        crate::vmess::VMessNetwork::Udp.byte()
    );
    assert_eq!(accepted.request.target, target);
    assert_eq!(accepted.request.payload, payload);
    assert_eq!(echoed, payload);
}

#[test]
fn vmess_aead_response_reader_from_buffer_waits_for_complete_header_and_chunk() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "vmess-buffer-target.fixture.invalid:53";
    let payload = b"vmess-aead-buffered-response";
    let session = vmess::aead_udp_over_tcp_client_session_start(uuid, target, payload).unwrap();
    let response = vmess::aead_tcp_response_packet(&session.request, payload).unwrap();

    let mut input = Vec::new();
    input.extend_from_slice(&response[..17]);
    assert!(
        vmess::aead_tcp_response_reader_from_buffer(&mut input, &session.request)
            .unwrap()
            .is_none()
    );
    assert_eq!(input.len(), 17);

    input.extend_from_slice(&response[17..38]);
    let mut reader = vmess::aead_tcp_response_reader_from_buffer(&mut input, &session.request)
        .unwrap()
        .expect("complete VMess response header should initialize the reader");
    assert_eq!(reader.response_header_len, 38);
    assert!(input.is_empty());

    input.extend_from_slice(&response[38..40]);
    assert_eq!(reader.try_read_chunk_from_buffer(&mut input).unwrap(), None);
    assert!(input.is_empty());

    input.extend_from_slice(&response[40..response.len() - 1]);
    assert_eq!(reader.try_read_chunk_from_buffer(&mut input).unwrap(), None);

    input.push(*response.last().unwrap());
    assert_eq!(
        reader.try_read_chunk_from_buffer(&mut input).unwrap(),
        Some(payload.to_vec())
    );
    assert!(input.is_empty());
}

#[test]
fn case_vmess_aead_udp_over_tcp_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "1.2.3.4:53";
    let payload = b"fixture-vmess-udp-ping";
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
fn case_vmess_packet_addr_udp_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let packet_target = "1.2.3.4:53";
    let payload = b"fixture-vmess-packet-addr-ping";
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
fn case_vmess_aead_mux_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-mux.fixture.invalid:443";
    let payload = b"fixture-vmess-mux-ping";
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
fn case_vmess_aead_websocket_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-ws.fixture.invalid:443";
    let ws_host = "fixture-vmess-proxy.fixture.invalid";
    let ws_path = "/dae-vmess-ws";
    let payload = b"fixture-vmess-ws-ping";
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
fn case_vmess_aead_httpupgrade_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-httpupgrade.fixture.invalid:443";
    let httpupgrade_host = "fixture-vmess-proxy.fixture.invalid";
    let httpupgrade_path = "/dae-vmess-httpupgrade";
    let payload = b"fixture-vmess-httpupgrade-ping";
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
fn case_vmess_aead_grpc_hunk_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-grpc.fixture.invalid:443";
    let service_name = "dae-fixture-grpc";
    let payload = b"fixture-vmess-grpc-ping";
    let (proxy, handle) = spawn_vmess_aead_grpc_hunk_echo_server(
        uuid.to_owned(),
        target.to_owned(),
        service_name.to_owned(),
    );
    let options = shared_transport::GrpcLifecycleOptions::new(
        &proxy,
        service_name,
        "fixture-vmess-grpc-sni.fixture.invalid",
        "fixture-dialer",
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
fn case_vmess_aead_meek_polling_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-meek.fixture.invalid:443";
    let meek_url = "https://front.fixture.invalid/dae-fixture-meek";
    let payload = b"fixture-vmess-meek-ping";
    let options = shared_transport::MeekRoundTripOptions::from_https_url(
        meek_url,
        b"dae-fixture-meek".to_vec(),
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
    assert!(!report.full_https_round_tripper);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(report.meek_url, meek_url);
    assert_eq!(report.meek_host, "front.fixture.invalid");
    assert_eq!(report.meek_path, "/dae-fixture-meek");
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
fn case_vmess_aead_http_transport_put_dataplane_echoes_payload() {
    let uuid = "7c12c745-63a5-433d-9e60-022e469b5bd4";
    let target = "fixture-vmess-http-target.fixture.invalid:443";
    let payload = b"fixture-vmess-http-put-ping";
    let mut options = crate::http_proxy::HttpConnectOptions::connect(
        "fixture-vmess-http-proxy.fixture.invalid:443",
    );
    options.host_override = "fixture-vmess-http.fixture.invalid".to_owned();
    options.transport.enabled = true;
    options.transport.path = "/dae-fixture-http".to_owned();
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
    assert!(!report.full_http2_stack);
    assert_eq!(report.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(report.security, vmess::VMESS_AEAD_SECURITY_AES_128_GCM);
    assert_eq!(report.target, target);
    assert_eq!(
        report.http_transport_host,
        "fixture-vmess-http.fixture.invalid"
    );
    assert_eq!(report.http_transport_path, "/dae-fixture-http");
    assert_eq!(report.payload_len, payload.len());
    assert_eq!(report.echoed_payload, payload);
    assert!(report.http_transport_put_validated);
    assert!(report.http_transport_request_len > report.request_header_len);
    assert!(report.http_transport_response_head_len > 0);
    assert_eq!(head.method, "PUT");
    assert_eq!(
        head.request_uri,
        "http://fixture-vmess-http.fixture.invalid/dae-fixture-http"
    );
    assert_eq!(head.host, "fixture-vmess-http.fixture.invalid");
    assert!(head.transport_enabled);
    assert_eq!(accepted.version, 1);
    assert!(accepted.eauth_crc_validated);
    assert_eq!(accepted.command, crate::vmess::VMessNetwork::Tcp.byte());
    assert_eq!(accepted.target, target);
    assert_eq!(accepted.payload, payload);
}
