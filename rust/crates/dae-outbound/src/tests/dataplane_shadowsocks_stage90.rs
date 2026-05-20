use super::*;

const AES_CIPHER: &str = "2022-blake3-aes-128-gcm";
const AES_PASSWORD: &str = "AQIDBAUGBwgJCgsMDQ4PEA==:ERITFBUWFxgZGhscHR4fIA==";
const CHACHA_CIPHER: &str = "2022-blake3-chacha20-poly1305";
const CHACHA_PASSWORD: &str = "MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY=";
const TARGET: &str = "stage90-ss2022-udp.example:5353";
const RESPONSE_TARGET: &str = "8.8.8.8:53";
const TIMESTAMP: u64 = 1_765_000_090;

#[test]
fn stage90_ss2022_udp_aes_separate_header_replay_roundtrips_payload() {
    let payload = b"stage90-ss2022-udp-aes-ping".to_vec();
    let client_session = *b"client90";
    let server_session = *b"srv90aes";
    let mut codec =
        shadowsocks::Ss2022UdpCodec::new(AES_CIPHER, AES_PASSWORD, client_session).expect("codec");
    let packet = codec
        .encode_client_packet(TARGET, &payload, TIMESTAMP, None)
        .expect("client packet");
    assert_eq!(packet.packet_id, 0);
    assert_eq!(packet.separate_header_len, 16);
    assert_eq!(packet.identity_header_count, 1);
    assert_eq!(packet.identity_header_bytes_len, 16);

    let decoded = shadowsocks::decode_ss2022_udp_client_packet(
        AES_CIPHER,
        AES_PASSWORD,
        &packet.wire,
        TIMESTAMP,
    )
    .expect("server decode");
    assert_eq!(
        decoded.packet_type,
        shadowsocks::ss2022::HEADER_TYPE_CLIENT_PACKET
    );
    assert_eq!(decoded.packet_id, 0);
    assert_eq!(decoded.session_id, client_session);
    assert_eq!(decoded.target, TARGET);
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.identity_header_count, 1);
    assert!(decoded.identity_header_validated);

    let response = shadowsocks::encode_ss2022_udp_server_packet(
        AES_CIPHER,
        AES_PASSWORD,
        server_session,
        0,
        codec.session_id(),
        RESPONSE_TARGET,
        &decoded.payload,
        TIMESTAMP,
        None,
    )
    .expect("server response");
    let response_decoded = codec
        .decode_server_packet(&response.wire, TIMESTAMP)
        .expect("client response decode");
    assert_eq!(
        response_decoded.packet_type,
        shadowsocks::ss2022::HEADER_TYPE_SERVER_PACKET
    );
    assert_eq!(response_decoded.session_id, server_session);
    assert_eq!(response_decoded.client_session_id, Some(client_session));
    assert_eq!(response_decoded.target, RESPONSE_TARGET);
    assert_eq!(response_decoded.payload, payload);

    let duplicate = codec
        .decode_server_packet(&response.wire, TIMESTAMP)
        .unwrap_err();
    assert!(duplicate.to_string().contains("replay"));

    let stale_session = *b"stale90a";
    let high = shadowsocks::encode_ss2022_udp_server_packet(
        AES_CIPHER,
        AES_PASSWORD,
        stale_session,
        shadowsocks::ss2022::UDP_REPLAY_WINDOW_SIZE as u64 + 1,
        client_session,
        RESPONSE_TARGET,
        b"new",
        TIMESTAMP,
        None,
    )
    .expect("high packet");
    codec
        .decode_server_packet(&high.wire, TIMESTAMP)
        .expect("high packet decode");
    let old = shadowsocks::encode_ss2022_udp_server_packet(
        AES_CIPHER,
        AES_PASSWORD,
        stale_session,
        0,
        client_session,
        RESPONSE_TARGET,
        b"old",
        TIMESTAMP,
        None,
    )
    .expect("old packet");
    let too_old = codec
        .decode_server_packet(&old.wire, TIMESTAMP)
        .unwrap_err();
    assert!(too_old.to_string().contains("replay"));
}

#[test]
fn stage90_ss2022_udp_chacha_merged_header_roundtrips_payload() {
    let payload = b"stage90-ss2022-udp-chacha-ping".to_vec();
    let client_session = *b"client9c";
    let server_session = *b"srv90cha";
    let client_nonce = [0x07_u8; 24];
    let server_nonce = [0x17_u8; 24];
    let mut codec =
        shadowsocks::Ss2022UdpCodec::new(CHACHA_CIPHER, CHACHA_PASSWORD, client_session)
            .expect("codec");
    let packet = codec
        .encode_client_packet(TARGET, &payload, TIMESTAMP, Some(&client_nonce))
        .expect("client packet");
    assert_eq!(packet.packet_id, 0);
    assert_eq!(packet.separate_header_len, 0);
    assert_eq!(packet.packet_nonce_len, 24);
    assert_eq!(packet.branch, "merged-header-xchacha20-poly1305");

    let decoded = shadowsocks::decode_ss2022_udp_client_packet(
        CHACHA_CIPHER,
        CHACHA_PASSWORD,
        &packet.wire,
        TIMESTAMP,
    )
    .expect("server decode");
    assert_eq!(decoded.packet_id, 0);
    assert_eq!(decoded.session_id, client_session);
    assert_eq!(decoded.target, TARGET);
    assert_eq!(decoded.payload, payload);

    let response = shadowsocks::encode_ss2022_udp_server_packet(
        CHACHA_CIPHER,
        CHACHA_PASSWORD,
        server_session,
        0,
        codec.session_id(),
        RESPONSE_TARGET,
        &decoded.payload,
        TIMESTAMP,
        Some(&server_nonce),
    )
    .expect("server response");
    let response_decoded = codec
        .decode_server_packet(&response.wire, TIMESTAMP)
        .expect("client response decode");
    assert_eq!(response_decoded.session_id, server_session);
    assert_eq!(response_decoded.client_session_id, Some(client_session));
    assert_eq!(response_decoded.target, RESPONSE_TARGET);
    assert_eq!(response_decoded.payload, payload);
}

#[test]
fn stage90_ss2022_udp_rejects_future_timestamp() {
    let mut codec =
        shadowsocks::Ss2022UdpCodec::new(AES_CIPHER, AES_PASSWORD, *b"client90").expect("codec");
    let packet = codec
        .encode_client_packet(TARGET, b"future", TIMESTAMP + 31, None)
        .expect("client packet");
    let err = shadowsocks::decode_ss2022_udp_client_packet(
        AES_CIPHER,
        AES_PASSWORD,
        &packet.wire,
        TIMESTAMP,
    )
    .unwrap_err();
    assert!(err.to_string().contains("timestamp"));
}
