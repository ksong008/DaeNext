use super::*;

#[test]
fn aead_udp_numeric_target_preserves_address_family_and_omits_ipv6_scope() {
    let codec = AeadUdpCodec::new("aes-128-gcm", "address-test").unwrap();
    let salt = [7; 16];
    for target in ["192.0.2.1:53", "[2001:db8::1]:53", "[::ffff:192.0.2.1]:53"] {
        let address = target.parse().unwrap();
        assert_eq!(
            codec
                .encode_packet(&salt, &shadowsocks_udp_target(address), b"query")
                .unwrap(),
            encode_udp_packet("aes-128-gcm", "address-test", &salt, target, b"query").unwrap()
        );
    }
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        53,
        17,
        3,
    ));
    let target = shadowsocks_udp_target(scoped);
    assert!(matches!(target, Socks5Address::Ipv6 { .. }));
    assert_eq!(
        codec.encode_packet(&salt, &target, b"query").unwrap(),
        encode_udp_packet(
            "aes-128-gcm",
            "address-test",
            &salt,
            "[fe80::1]:53",
            b"query"
        )
        .unwrap()
    );
}

const SS2022_CIPHER: &str = "2022-blake3-aes-128-gcm";
const SS2022_PASSWORD: &str = "AQIDBAUGBwgJCgsMDQ4PEA==:ERITFBUWFxgZGhscHR4fIA==";

#[test]
fn ss2022_poll_without_a_response_does_not_require_an_initialized_codec() {
    let mut session = Shadowsocks2022DatagramSession::new(
        SS2022_CIPHER.to_owned(),
        SS2022_PASSWORD.to_owned(),
        0,
    );

    assert!(session.poll_response().unwrap().is_none());
}

#[test]
fn aead_response_source_is_verified_at_the_consumer_boundary() {
    let cipher = "aes-128-gcm";
    let password = "fixed-target-password";
    let salt = [0x31_u8; 16];
    let expected: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
    let packet =
        encode_udp_packet(cipher, password, &salt, &other.to_string(), b"response").unwrap();
    let session =
        ShadowsocksAeadDatagramSession::new(cipher.to_owned(), password.to_owned(), salt.len());
    let mut response = session.decode_response(&packet).unwrap();
    let expectation = response.fixed_target_expectation(expected);
    assert_eq!(
        response.take_fixed_target_payload(expectation).validation(),
        UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
    );
}

#[test]
fn ss2022_response_source_and_client_session_are_verified() {
    let client_session = *b"client90";
    let server_session = *b"server90";
    let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let now = ss2022_udp_unix_timestamp_now();
    let codec = Ss2022UdpCodec::new(SS2022_CIPHER, SS2022_PASSWORD, client_session).unwrap();
    let packet = dae_outbound_stream::shadowsocks::encode_ss2022_udp_server_packet(
        SS2022_CIPHER,
        SS2022_PASSWORD,
        server_session,
        0,
        client_session,
        &target.to_string(),
        b"response",
        now,
        None,
    )
    .unwrap();
    let mut session = Shadowsocks2022DatagramSession::new(
        SS2022_CIPHER.to_owned(),
        SS2022_PASSWORD.to_owned(),
        0,
    );
    session.codec = Some(codec);
    let mut response = session.decode_response(&packet.wire).unwrap();
    let expectation = response.fixed_target_expectation(target);
    assert_eq!(
        response.take_fixed_target_payload(expectation).validation(),
        UdpFixedTargetValidation::Validated
    );
}

#[test]
fn ss2022_replay_metrics_release_current_state_with_the_udp_session() {
    let client_session = *b"client92";
    let server_session = *b"server92";
    let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let now = ss2022_udp_unix_timestamp_now();
    let packet = dae_outbound_stream::shadowsocks::encode_ss2022_udp_server_packet(
        SS2022_CIPHER,
        SS2022_PASSWORD,
        server_session,
        0,
        client_session,
        &target.to_string(),
        b"response",
        now,
        None,
    )
    .unwrap();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    {
        let mut session = Shadowsocks2022DatagramSession::new(
            SS2022_CIPHER.to_owned(),
            SS2022_PASSWORD.to_owned(),
            0,
        );
        session.codec =
            Some(Ss2022UdpCodec::new(SS2022_CIPHER, SS2022_PASSWORD, client_session).unwrap());
        session.set_runtime_metrics(Arc::clone(&metrics));
        session.decode_response(&packet.wire).unwrap();
        assert!(session.decode_response(&packet.wire).is_err());
        let live = metrics.snapshot();
        assert_eq!(live["ss2022Replay"]["activeWindowsCurrent"], 1);
        assert_eq!(live["ss2022Replay"]["retainedSessionsCurrent"], 1);
        assert!(
            live["ss2022Replay"]["estimatedBytesCurrent"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(live["ss2022Replay"]["replayRejections"], 1);
    }
    let closed = metrics.snapshot();
    assert_eq!(closed["ss2022Replay"]["activeWindowsCurrent"], 0);
    assert_eq!(closed["ss2022Replay"]["retainedSessionsCurrent"], 0);
    assert_eq!(closed["ss2022Replay"]["estimatedBytesCurrent"], 0);
    assert_eq!(closed["ss2022Replay"]["replayRejections"], 1);
}
