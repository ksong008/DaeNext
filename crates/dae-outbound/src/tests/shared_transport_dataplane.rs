use super::*;

#[test]
fn case_httpupgrade_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_foundation.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (endpoint, handle) = spawn_httpupgrade_echo_server();
    let options = shared_transport::HttpUpgradeOptions::new(
        fixture["httpupgrade"]["host"].as_str().unwrap(),
        fixture["httpupgrade"]["path"].as_str().unwrap(),
    );
    let report = shared_transport::http_upgrade_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.transport, "httpupgrade");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_websocket_dataplane_echoes_binary_frame() {
    let fixture = fixture("outbound/protocol/shared_transport_foundation.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (endpoint, handle) = spawn_websocket_echo_server();
    let options = shared_transport::HttpUpgradeOptions::new(
        fixture["websocket"]["host"].as_str().unwrap(),
        fixture["websocket"]["path"].as_str().unwrap(),
    );
    let report =
        shared_transport::websocket_exchange(&endpoint, &options, payload, Duration::from_secs(2))
            .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.transport, "websocket");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_websocket_client_material_is_runtime_generated() {
    let options = shared_transport::HttpUpgradeOptions::new("ws.fixture.invalid", "/ws");
    let keys = (0..4)
        .map(|_| shared_transport::websocket_client_handshake_key().unwrap())
        .collect::<Vec<_>>();
    assert!(
        keys.iter()
            .all(|key| STANDARD.decode(key).unwrap().len() == 16)
    );
    assert!(
        keys.iter()
            .any(|key| key != shared_transport::DEFAULT_WS_KEY)
    );

    let request = shared_transport::websocket_client_handshake_request(&options).unwrap();
    let request = String::from_utf8(request).unwrap();
    assert!(request.contains("Host: ws.fixture.invalid\r\n"));
    assert!(request.contains("Sec-WebSocket-Key: "));
    assert!(!request.contains(shared_transport::DEFAULT_WS_KEY));

    let masks = (0..4)
        .map(|_| shared_transport::websocket_client_mask_key().unwrap())
        .collect::<Vec<_>>();
    assert!(
        masks
            .iter()
            .any(|mask| *mask != shared_transport::WS_MASK_KEY)
    );

    let payload = b"hello";
    let frame = shared_transport::websocket_client_binary_frame_with_random_mask(payload).unwrap();
    assert_eq!(frame[0], 0x82);
    assert_eq!(frame[1], 0x80 | payload.len() as u8);
    let mask_key = [frame[2], frame[3], frame[4], frame[5]];
    let decoded = frame[6..]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask_key[index % 4])
        .collect::<Vec<_>>();
    assert_eq!(decoded, payload);
}

#[test]
fn websocket_handshake_binds_server_accept_to_the_client_nonce() {
    let options = shared_transport::HttpUpgradeOptions::new("ws.fixture.invalid", "/ws");
    let handshake = shared_transport::websocket_client_handshake(&options).unwrap();
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        handshake.expected_accept
    );
    shared_transport::validate_websocket_handshake_response(
        response.as_bytes(),
        &handshake.expected_accept,
    )
    .unwrap();

    let mismatch = response.replace(
        &handshake.expected_accept,
        shared_transport::WS_ACCEPT_SAMPLE,
    );
    let different_expected = shared_transport::websocket_accept_for_key("different-client-key");
    let error = shared_transport::validate_websocket_handshake_response(
        mismatch.as_bytes(),
        &different_expected,
    )
    .unwrap_err();
    assert!(error.to_string().contains("Sec-WebSocket-Accept mismatch"));
}

#[test]
fn case_simpleobfs_http_dataplane_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_foundation.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let (endpoint, handle) = spawn_simpleobfs_http_echo_server();
    let options = shared_transport::SimpleObfsHttpOptions::new(
        fixture["simpleobfs_http"]["host"].as_str().unwrap(),
        fixture["simpleobfs_http"]["path"].as_str().unwrap(),
    );
    let report = shared_transport::simpleobfs_http_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.true_dataplane);
    assert_eq!(report.transport, "simpleobfs-http");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_reality_mutation_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_deep_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let reality = &fixture["reality"];
    let options = shared_transport::RealityMutationOptions::new(
        reality["server_name"].as_str().unwrap(),
        reality["fingerprint"].as_str().unwrap(),
        reality["sid_hex"].as_str().unwrap(),
        reality["pbk_input"].as_str().unwrap(),
        reality["spider_x"].as_str().unwrap(),
        reality["unix_seconds"].as_u64().unwrap() as u32,
        reality["entropy_hex"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex_encode(&options.public_key),
        reality["pbk_decoded_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex_encode(&shared_transport::reality_session_id(&options)),
        reality["session_id_hex"].as_str().unwrap()
    );
    let (endpoint, handle) =
        spawn_reality_mutation_echo_server(shared_transport::reality_session_id(&options));
    let report = shared_transport::reality_mutation_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.mutation_harness);
    assert!(!report.full_utls_stack);
    assert_eq!(report.transport, "reality-mutation");
    assert_eq!(
        report.session_id_hex,
        reality["session_id_hex"].as_str().unwrap()
    );
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_xhttp_packet_lifecycle_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_deep_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let xhttp = &fixture["xhttp"];
    let options = shared_transport::XHttpLifecycleOptions::new(
        xhttp["host"].as_str().unwrap(),
        xhttp["path"].as_str().unwrap(),
        xhttp["mode"].as_str().unwrap(),
        xhttp["security"].as_str().unwrap(),
        xhttp["alpn_h3"].as_str().unwrap(),
        xhttp["session_id"].as_str().unwrap(),
        xhttp["seq"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        shared_transport::xhttp_request_path(&options),
        xhttp["request_path"].as_str().unwrap()
    );
    let h3 = shared_transport::ir::validate_xhttp_alpn("tls", xhttp["alpn_h3"].as_str().unwrap());
    assert_eq!(h3.use_h3, xhttp["h3_tls_allowed"].as_bool().unwrap());
    let reality_h3 =
        shared_transport::ir::validate_xhttp_alpn("reality", xhttp["alpn_h3"].as_str().unwrap());
    assert_eq!(
        reality_h3.ok,
        xhttp["reality_h3_allowed"].as_bool().unwrap()
    );

    let (endpoint, handle) =
        spawn_xhttp_packet_echo_server(xhttp["request_path"].as_str().unwrap().to_owned());
    let report = shared_transport::xhttp_packet_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.lifecycle_harness);
    assert!(!report.full_h2_h3_stack);
    assert!(report.use_h3);
    assert_eq!(report.transport, "xhttp-packet");
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_grpc_cache_and_stream_lifecycle_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_deep_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let grpc = &fixture["grpc"];
    let options = shared_transport::GrpcLifecycleOptions::new(
        grpc["address"].as_str().unwrap(),
        grpc["service_name"].as_str().unwrap(),
        grpc["server_name"].as_str().unwrap(),
        grpc["dialer_id"].as_str().unwrap(),
        grpc["allow_insecure"].as_bool().unwrap(),
        grpc["mark"].as_u64().unwrap() as u32,
        grpc["mptcp"].as_bool().unwrap(),
    );
    let mut cache = shared_transport::GrpcLifecycleCache::default();
    let first = cache.get_or_insert(&options);
    let second = cache.get_or_insert(&options);
    assert!(!first.reused);
    assert!(second.reused);
    assert_eq!(second.live_entries, 1);
    assert_eq!(cache.clean(), 1);
    assert_eq!(cache.closed_entries(), 1);

    let mut without_mptcp = options.clone();
    without_mptcp.mptcp = false;
    assert_ne!(options.cache_key(), without_mptcp.cache_key());

    let (endpoint, handle) = spawn_grpc_hunk_echo_server(grpc["service_name"].as_str().unwrap());
    let report =
        shared_transport::grpc_hunk_exchange(&endpoint, &options, payload, Duration::from_secs(2))
            .unwrap();
    handle.join().unwrap();

    assert!(report.stream_harness);
    assert!(!report.full_grpc_http2_stack);
    assert_eq!(report.transport, "grpc-hunk");
    assert_eq!(report.service_name, grpc["service_name"].as_str().unwrap());
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_meek_polling_roundtripper_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_deep_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let meek = &fixture["meek"];
    let options = shared_transport::MeekRoundTripOptions::from_https_url(
        meek["url"].as_str().unwrap(),
        hex_decode(meek["session_tag_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(options.host, meek["host"].as_str().unwrap());
    assert_eq!(options.path, meek["path"].as_str().unwrap());
    assert_eq!(options.session_id(), meek["session_id"].as_str().unwrap());

    let (endpoint, handle) = spawn_meek_roundtripper_echo_server(
        meek["path"].as_str().unwrap().to_owned(),
        meek["session_id"].as_str().unwrap().to_owned(),
        meek["round_trips"].as_u64().unwrap() as usize,
    );
    let empty_poll: &[u8] = b"";
    let writes = [payload, empty_poll];
    let report = shared_transport::meek_polling_exchange(
        &endpoint,
        &options,
        &writes,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.polling_harness);
    assert!(!report.full_https_round_tripper);
    assert_eq!(report.transport, "meek-polling");
    assert_eq!(report.round_trips, 2);
    assert_eq!(report.echoed_payloads[0], payload);
    assert_eq!(report.echoed_payloads[1], b"poll-ok");
}

#[test]
fn case_mux_frame_lifecycle_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_deep_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let mux = &fixture["mux"];
    let id = [0_u8, 0_u8];
    let options = shared_transport::MuxFrameOptions::new(
        id,
        mux["host"].as_str().unwrap(),
        mux["port"].as_u64().unwrap() as u16,
        mux["network"].as_str().unwrap(),
    );
    assert_eq!(
        shared_transport::mux::SESSION_STATUS_NEW,
        mux["status_new"].as_u64().unwrap() as u8
    );
    assert_eq!(
        shared_transport::mux::SESSION_STATUS_KEEP,
        mux["status_keep"].as_u64().unwrap() as u8
    );
    assert_eq!(
        shared_transport::mux::SESSION_STATUS_END,
        mux["status_end"].as_u64().unwrap() as u8
    );
    assert_eq!(
        shared_transport::mux::OPTION_DATA,
        mux["option_data"].as_u64().unwrap() as u8
    );

    let (endpoint, handle) = spawn_mux_frame_echo_server(id);
    let report =
        shared_transport::mux_frame_exchange(&endpoint, &options, payload, Duration::from_secs(2))
            .unwrap();
    handle.join().unwrap();

    assert!(report.multiplexing_harness);
    assert!(!report.full_mux_runtime_stack);
    assert_eq!(report.transport, "mux-frame");
    assert_eq!(report.id_hex, mux["id_hex"].as_str().unwrap());
    assert_eq!(report.echoed_payload, payload);
}

#[test]
fn case_quic_h3_datagram_harness_echoes_payload() {
    let fixture = fixture("outbound/protocol/shared_transport_deep_harness.json");
    let payload = fixture["payload_ascii"].as_str().unwrap().as_bytes();
    let quic = &fixture["quic_h3"];
    let options = shared_transport::QuicH3HarnessOptions::new(
        quic["flow_id"].as_u64().unwrap() as u32,
        quic["datagram_id"].as_u64().unwrap() as u32,
        quic["alpn"].as_str().unwrap(),
        quic["mark"].as_u64().unwrap() as u32,
        quic["mptcp"].as_bool().unwrap(),
    );
    let packet = shared_transport::quic_h3_datagram_packet(&options, payload).unwrap();
    let parsed = shared_transport::parse_quic_h3_datagram(&packet).unwrap();
    assert_eq!(parsed.payload, payload);

    let (endpoint, handle) = spawn_quic_h3_datagram_echo_server();
    let report = shared_transport::quic_h3_datagram_exchange(
        &endpoint,
        &options,
        payload,
        Duration::from_secs(2),
    )
    .unwrap();
    handle.join().unwrap();

    assert!(report.udp_datagram_harness);
    assert!(!report.full_quic_h3_stack);
    assert_eq!(report.transport, "quic-h3-datagram");
    assert_eq!(report.alpn, quic["alpn"].as_str().unwrap());
    assert_eq!(report.echoed_payload, payload);
}
