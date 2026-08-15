use super::*;

const AES_CIPHER: &str = "2022-blake3-aes-128-gcm";
const AES_PASSWORD: &str = "AQIDBAUGBwgJCgsMDQ4PEA==:ERITFBUWFxgZGhscHR4fIA==";
const CHACHA_CIPHER: &str = "2022-blake3-chacha20-poly1305";
const CHACHA_PASSWORD: &str = "MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY=";
const TARGET: &str = "fixture-ss2022-udp.fixture.invalid:5353";
const RESPONSE_TARGET: &str = "8.8.8.8:53";
const TIMESTAMP: u64 = 1_765_000_090;

#[test]
fn case_ss2022_udp_aes_separate_header_replay_roundtrips_payload() {
    let payload = b"fixture-ss2022-udp-aes-ping".to_vec();
    let client_session = *b"client90";
    let server_session = *b"srv90aes";
    let mut codec =
        shadowsocks::Ss2022UdpCodec::new(AES_CIPHER, AES_PASSWORD, client_session).expect("codec");
    assert!(codec.client_payload_cipher_cached());
    assert_eq!(codec.cached_server_payload_session(), None);
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
    assert_eq!(codec.cached_server_payload_session(), Some(server_session));

    let duplicate = codec
        .decode_server_packet(&response.wire, TIMESTAMP)
        .unwrap_err();
    assert!(duplicate.to_string().contains("replay"));
    assert_eq!(codec.cached_server_payload_session(), Some(server_session));

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
    assert_eq!(codec.cached_server_payload_session(), Some(stale_session));
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
fn case_ss2022_udp_chacha_merged_header_roundtrips_payload() {
    let payload = b"fixture-ss2022-udp-chacha-ping".to_vec();
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
fn case_ss2022_udp_rejects_future_timestamp() {
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

#[test]
fn case_ss2022_udp_codec_bounds_server_session_churn_and_recovers_after_retention() {
    let client_session = *b"client91";
    let policy = shadowsocks::Ss2022UdpReplayPolicy::new(64, 2, 3, 64 * 1024, 10).unwrap();
    let mut codec = shadowsocks::Ss2022UdpCodec::new_with_replay_policy(
        AES_CIPHER,
        AES_PASSWORD,
        client_session,
        policy,
    )
    .unwrap();

    for (session_id, packet_id) in [
        (*b"server01", 0),
        (*b"server02", 0),
        (*b"server01", 1),
        (*b"server03", 0),
    ] {
        let response = shadowsocks::encode_ss2022_udp_server_packet(
            AES_CIPHER,
            AES_PASSWORD,
            session_id,
            packet_id,
            client_session,
            RESPONSE_TARGET,
            b"response",
            TIMESTAMP,
            None,
        )
        .unwrap();
        codec
            .decode_server_packet(&response.wire, TIMESTAMP)
            .unwrap();
    }

    let quarantined = shadowsocks::encode_ss2022_udp_server_packet(
        AES_CIPHER,
        AES_PASSWORD,
        *b"server02",
        1,
        client_session,
        RESPONSE_TARGET,
        b"quarantined",
        TIMESTAMP,
        None,
    )
    .unwrap();
    assert!(
        codec
            .decode_server_packet(&quarantined.wire, TIMESTAMP)
            .unwrap_err()
            .to_string()
            .contains("replay")
    );

    let saturated = shadowsocks::encode_ss2022_udp_server_packet(
        AES_CIPHER,
        AES_PASSWORD,
        *b"server04",
        0,
        client_session,
        RESPONSE_TARGET,
        b"saturated",
        TIMESTAMP,
        None,
    )
    .unwrap();
    assert!(
        codec
            .decode_server_packet(&saturated.wire, TIMESTAMP)
            .unwrap_err()
            .to_string()
            .contains("saturated")
    );
    let saturated_snapshot = codec.replay_metrics_snapshot();
    assert_eq!(saturated_snapshot.active_windows, 2);
    assert_eq!(saturated_snapshot.quarantined_sessions, 1);
    assert_eq!(saturated_snapshot.retained_sessions, 3);
    assert_eq!(saturated_snapshot.lru_evictions, 1);
    assert_eq!(saturated_snapshot.replay_rejections, 1);
    assert_eq!(saturated_snapshot.saturation_rejections, 1);
    assert!(saturated_snapshot.estimated_bytes <= policy.estimated_byte_limit());

    codec.prune_expired_replay_sessions(TIMESTAMP + policy.retention_secs());
    let expired_snapshot = codec.replay_metrics_snapshot();
    assert_eq!(expired_snapshot.active_windows, 0);
    assert_eq!(expired_snapshot.quarantined_sessions, 0);
    assert_eq!(expired_snapshot.retained_sessions, 0);
    assert_eq!(expired_snapshot.estimated_bytes, 0);
    assert_eq!(expired_snapshot.ttl_expirations, 3);
    codec
        .decode_server_packet(&saturated.wire, TIMESTAMP + policy.retention_secs())
        .unwrap();
}

#[test]
fn case_ss2022_udp_public_replay_tracker_uses_the_same_bounded_policy() {
    let policy = shadowsocks::Ss2022UdpReplayPolicy::new(64, 1, 2, 64 * 1024, 10).unwrap();
    let mut tracker = shadowsocks::Ss2022UdpReplayTracker::with_policy(policy).unwrap();
    tracker.check_at(*b"server01", 0, 1).unwrap();
    tracker.check_at(*b"server02", 0, 2).unwrap();
    assert!(tracker.check_at(*b"server01", 1, 3).is_err());
    assert!(tracker.check_at(*b"server03", 0, 3).is_err());
    let snapshot = tracker.replay_metrics_snapshot();
    assert_eq!(snapshot.active_windows, 1);
    assert_eq!(snapshot.quarantined_sessions, 1);
    assert_eq!(snapshot.retained_sessions, 2);
    assert_eq!(snapshot.lru_evictions, 1);
    assert_eq!(snapshot.saturation_rejections, 1);
    tracker.prune_expired(12);
    assert_eq!(tracker.replay_metrics_snapshot().retained_sessions, 0);
}
