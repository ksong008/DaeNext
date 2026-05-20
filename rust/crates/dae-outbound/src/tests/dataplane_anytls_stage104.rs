use super::*;

#[test]
fn stage104_anytls_frame_roundtrip_decodes_header_and_payload() {
    let settings = anytls::link::settings_bytes();
    let frame = anytls::link::frame(anytls::contract::CMD_SETTINGS, 7, &settings);
    let decoded = anytls::decode_frame(&frame).unwrap();

    assert_eq!(decoded.cmd, anytls::contract::CMD_SETTINGS);
    assert_eq!(decoded.sid, 7);
    assert_eq!(decoded.data, settings);
    assert_eq!(decoded.data_len(), anytls::link::settings_bytes().len());
}

#[test]
fn stage104_anytls_tcp_first_flight_matches_go_session_order() {
    let auth = "stage104-auth";
    let target = "stage104-anytls-target.example:443";
    let payload = b"stage104-anytls-payload";

    let auth_handshake = anytls::link::handshake_auth_bytes(auth);
    assert_eq!(auth_handshake.len(), 34);
    assert_eq!(&auth_handshake[32..], &[0, 0]);

    let settings_frame = anytls::link::frame(
        anytls::contract::CMD_SETTINGS,
        1,
        &anytls::link::settings_bytes(),
    );
    let syn_frame = anytls::link::frame(anytls::contract::CMD_SYN, 1, &[]);
    let target_addr = anytls::link::socks_addr(target).unwrap();
    let psh_addr_frame = anytls::link::frame(anytls::contract::CMD_PSH, 1, &target_addr);
    let psh_payload_frame = anytls::link::frame(anytls::contract::CMD_PSH, 1, payload);

    let settings = anytls::decode_frame(&settings_frame).unwrap();
    let syn = anytls::decode_frame(&syn_frame).unwrap();
    let psh_addr = anytls::decode_frame(&psh_addr_frame).unwrap();
    let psh_payload = anytls::decode_frame(&psh_payload_frame).unwrap();

    assert_eq!(settings.cmd, anytls::contract::CMD_SETTINGS);
    assert_eq!(syn.cmd, anytls::contract::CMD_SYN);
    assert_eq!(psh_addr.cmd, anytls::contract::CMD_PSH);
    assert_eq!(psh_payload.cmd, anytls::contract::CMD_PSH);
    assert_eq!(settings.sid, 1);
    assert_eq!(syn.sid, 1);
    assert_eq!(psh_addr.sid, 1);
    assert_eq!(psh_payload.sid, 1);
    assert!(syn.data.is_empty());
    assert_eq!(psh_addr.data, target_addr);
    assert_eq!(psh_payload.data, payload);
}

#[test]
fn stage104_anytls_udp_magic_domain_and_underlay_preserve_go_boundary() {
    let stream_target = anytls::link::udp_stream_target("1.2.3.4:53").unwrap();
    let underlay = anytls::link::underlay_contract("udp", 1234, true);

    assert_eq!(stream_target, "sp.v2.udp-over-tcp.arpa:53");
    assert_eq!(underlay.underlay_network, "tcp");
    assert_eq!(underlay.underlay_mark, 1234);
    assert!(underlay.underlay_mptcp);
}
