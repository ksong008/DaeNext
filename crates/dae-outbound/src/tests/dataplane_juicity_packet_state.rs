use super::*;

#[test]
fn case_juicity_packet_state_selects_port_zero_and_stream_routes() {
    let port_zero = juicity::select_udp_packet_conn("fixture-zero.fixture.invalid:0").unwrap();
    assert_eq!(
        port_zero.kind,
        juicity::JuicityUdpPacketConnKind::TransportPacketConn
    );
    assert_eq!(port_zero.kind.as_str(), "transport_packet_conn");
    assert!(port_zero.requires_dialauth);
    assert!(port_zero.requires_underlay_key);
    assert!(!port_zero.uses_stream_packet_frame);

    let stream = juicity::select_udp_packet_conn("fixture-stream.fixture.invalid:5353").unwrap();
    assert_eq!(
        stream.kind,
        juicity::JuicityUdpPacketConnKind::StreamPacketConn
    );
    assert_eq!(stream.kind.as_str(), "stream_packet_conn");
    assert!(!stream.requires_dialauth);
    assert!(!stream.requires_underlay_key);
    assert!(stream.uses_stream_packet_frame);
}

#[test]
fn case_juicity_dialauth_record_matches_native_pack_order_contract() {
    let record =
        juicity::build_dialauth_record_for_port_zero("fixture-zero.fixture.invalid:0").unwrap();
    assert_eq!(record.metadata_port, 0);
    assert_eq!(record.iv.len(), juicity::JUICITY_UNDERLAY_AUTH_IV_LEN);
    assert_eq!(record.psk.len(), juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN);
    assert_eq!(record.iv[0], 0);
    assert_eq!(record.iv[1], 0);
    assert!(record.iv_zero_prefix_valid);
    assert!(record.psk_nonzero);
    assert_eq!(record.underlay_auth_channel_capacity, 64);
    assert_eq!(record.transport_packet_conn_cipher, "chacha20-poly1305");
    assert_eq!(
        record.transport_packet_conn_reused_info,
        "juicity reused info"
    );
    assert_eq!(
        record.packed.len(),
        juicity::JUICITY_UNDERLAY_AUTH_IV_LEN
            + juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN
            + record.metadata_len
    );
    assert_eq!(
        &record.packed[..juicity::JUICITY_UNDERLAY_AUTH_IV_LEN],
        record.iv.as_slice()
    );
    assert_eq!(
        &record.packed[juicity::JUICITY_UNDERLAY_AUTH_IV_LEN
            ..juicity::JUICITY_UNDERLAY_AUTH_IV_LEN + juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN],
        record.psk.as_slice()
    );
}

#[test]
fn case_juicity_stream_packet_frame_roundtrips_without_trojan_crlf() {
    let payload = b"fixture-udp-payload";
    let frame =
        juicity::seal_stream_packet_frame("fixture-stream.fixture.invalid:5353", payload).unwrap();
    let decoded = juicity::decode_stream_packet_frame(&frame.encoded).unwrap();

    assert_eq!(frame.target, "fixture-stream.fixture.invalid:5353");
    assert_eq!(frame.payload_len, payload.len());
    assert_eq!(decoded.target, frame.target);
    assert_eq!(decoded.payload(), payload);
    assert_eq!(decoded.metadata_len, frame.metadata_len);
    assert_eq!(decoded.encoded, frame.encoded);
    assert_eq!(
        &frame.encoded[frame.metadata_len..frame.metadata_len + 2],
        &(payload.len() as u16).to_be_bytes()
    );
    assert_ne!(
        &frame.encoded[frame.metadata_len..frame.metadata_len + 2],
        b"\r\n"
    );
}

#[test]
fn case_juicity_packet_state_smoke_keeps_true_dataplane_closed() {
    let report = juicity::packet_state_smoke(
        "fixture-zero.fixture.invalid:0",
        "fixture-stream.fixture.invalid:5353",
        b"fixture-udp-payload",
    )
    .unwrap();

    assert_eq!(report.port_zero_kind, "transport_packet_conn");
    assert_eq!(report.stream_kind, "stream_packet_conn");
    assert!(report.dialauth_iv_zero_prefix_valid);
    assert!(report.dialauth_psk_nonzero);
    assert_eq!(
        report.dialauth_packed_len,
        juicity::JUICITY_UNDERLAY_AUTH_IV_LEN
            + juicity::JUICITY_UNDERLAY_AUTH_PSK_LEN
            + report.dialauth_metadata_len
    );
    assert!(report.stream_packet_payload_len_prefix_valid);
    assert!(report.stream_packet_roundtrip_validated);
    assert!(report.juicity_dialauth_record_protocol_state_admitted);
    assert!(report.juicity_udp_port_zero_transport_packet_conn_route_admitted);
    assert!(report.juicity_stream_packet_conn_frame_admitted);

    assert!(!report.juicity_dialauth_over_h3_admitted);
    assert!(!report.juicity_transport_packet_conn_dataplane_admitted);
    assert!(!report.juicity_stream_packet_conn_dataplane_admitted);
    assert!(!report.juicity_true_quic_h3_dataplane_admitted);
}
