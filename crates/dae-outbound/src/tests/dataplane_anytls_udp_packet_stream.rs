use super::*;

#[test]
fn case_anytls_udp_packet_first_write_matches_native_packet_stream() {
    let target = "fixture-udp.fixture.invalid:5353";
    let payload = b"fixture-first-packet";
    let encoded = anytls::link::packet_first_write(target, payload).unwrap();
    let decoded = anytls::decode_packet_first_write(&encoded).unwrap();

    assert_eq!(encoded[0], 1);
    assert_eq!(decoded.target.as_deref(), Some(target));
    assert_eq!(decoded.payload, payload);
    assert_eq!(
        encoded.len(),
        1 + anytls::link::socks_addr(target).unwrap().len() + 2 + payload.len()
    );
}

#[test]
fn case_anytls_udp_packet_next_write_carries_only_length_and_payload() {
    let payload = b"fixture-next-packet";
    let encoded = anytls::link::packet_next_write(payload);
    let decoded = anytls::decode_packet_next_write(&encoded).unwrap();

    assert_eq!(
        u16::from_be_bytes([encoded[0], encoded[1]]) as usize,
        payload.len()
    );
    assert_eq!(decoded.target, None);
    assert_eq!(decoded.payload, payload);
    assert_eq!(encoded.len(), 2 + payload.len());
}

#[test]
fn case_anytls_udp_packet_stream_uses_magic_domain_and_tcp_underlay() {
    let original_target = "fixture-udp.fixture.invalid:5353";
    let session_target = anytls::link::udp_stream_target(original_target).unwrap();
    let stream_target_addr = anytls::link::socks_addr(&session_target).unwrap();
    let first_write = anytls::link::packet_first_write(original_target, b"fixture-first").unwrap();
    let next_write = anytls::link::packet_next_write(b"fixture-next");
    let psh_stream_target = anytls::link::frame(anytls::contract::CMD_PSH, 1, &stream_target_addr);
    let psh_first = anytls::link::frame(anytls::contract::CMD_PSH, 1, &first_write);
    let psh_next = anytls::link::frame(anytls::contract::CMD_PSH, 1, &next_write);
    let underlay = anytls::link::underlay_contract("udp", 1234, true);

    assert_eq!(session_target, "sp.v2.udp-over-tcp.arpa:5353");
    assert_eq!(
        anytls::decode_frame(&psh_stream_target).unwrap().cmd,
        anytls::contract::CMD_PSH
    );
    assert_eq!(
        anytls::decode_packet_first_write(&anytls::decode_frame(&psh_first).unwrap().data)
            .unwrap()
            .target
            .as_deref(),
        Some(original_target)
    );
    assert_eq!(
        anytls::decode_packet_next_write(&anytls::decode_frame(&psh_next).unwrap().data)
            .unwrap()
            .payload,
        b"fixture-next"
    );
    assert_eq!(underlay.underlay_network, "tcp");
    assert_eq!(underlay.underlay_mark, 1234);
    assert!(underlay.underlay_mptcp);
}
