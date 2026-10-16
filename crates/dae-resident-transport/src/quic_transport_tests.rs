use super::*;

#[test]
fn quic_bind_addr_follows_remote_ip_family() {
    let v4_remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let v6_remote = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443);

    assert!(quic_bind_addr_for_remote(v4_remote).is_ipv4());
    assert!(quic_bind_addr_for_remote(v6_remote).is_ipv6());
}

#[test]
fn hysteria2_initial_port_selection_is_bounded_independently_of_port_set_size() {
    let addresses = vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
    for port_count in [2, 3_001, 4_001] {
        let plan = Hysteria2ResolvedRemotePlan {
            addresses: addresses.clone(),
            ports: Arc::new(
                (0..port_count)
                    .map(|offset| 10_000 + offset as u16)
                    .collect(),
            ),
            port_hopping: true,
        };
        let candidates = hysteria2_initial_remote_candidates_with(&plan, 4, |_| 0).unwrap();
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0], "192.0.2.1:10000".parse().unwrap());
        assert_eq!(candidates[1], "[2001:db8::1]:10000".parse().unwrap());
        assert_eq!(candidates[2], "192.0.2.1:10001".parse().unwrap());
        assert_eq!(candidates[3], "[2001:db8::1]:10001".parse().unwrap());
    }
}

#[test]
fn hysteria2_fixed_port_keeps_every_resolved_address() {
    let plan = Hysteria2ResolvedRemotePlan {
        addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        ports: Arc::new(vec![443]),
        port_hopping: false,
    };
    let candidates = hysteria2_initial_remote_candidates_with(&plan, 1, |_| {
        panic!("fixed-port selection must not request randomness")
    })
    .unwrap();
    assert_eq!(
        candidates,
        vec![
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ]
    );
}

#[test]
fn hysteria2_tls_failures_are_terminal_and_redacted() {
    let certificate = quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
        error_code: quinn::TransportErrorCode::crypto(TLS_ALERT_UNKNOWN_CA),
        frame_type: None,
        reason: Bytes::from_static(b"private.example certificate canary"),
    });
    let certificate = classify_hysteria2_connection_error(&certificate, true, true);
    assert_eq!(certificate.class(), Hysteria2FailureClass::TlsCertificate);
    assert_eq!(
        certificate.retry_disposition(),
        Hysteria2RetryDisposition::Terminal
    );
    assert!(!certificate.to_string().contains("private.example"));

    let pin = quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
        error_code: quinn::TransportErrorCode::crypto(TLS_ALERT_ACCESS_DENIED),
        frame_type: None,
        reason: Bytes::from_static(b"0123456789abcdef pin canary"),
    });
    let pin = classify_hysteria2_connection_error(&pin, true, true);
    assert_eq!(pin.class(), Hysteria2FailureClass::TlsPin);
    assert_eq!(pin.retry_disposition(), Hysteria2RetryDisposition::Terminal);
    assert!(!pin.to_string().contains("0123456789abcdef"));
}

#[test]
fn hysteria2_network_port_failure_is_the_only_handshake_retry_class() {
    let failure =
        classify_hysteria2_connection_error(&quinn::ConnectionError::TimedOut, false, true);
    assert_eq!(failure.class(), Hysteria2FailureClass::NetworkPort);
    assert_eq!(failure.retry_disposition(), Hysteria2RetryDisposition::Port);
    assert!(failure.allows_candidate_retry());

    let cancelled =
        classify_hysteria2_connection_error(&quinn::ConnectionError::LocallyClosed, false, true);
    assert_eq!(cancelled.class(), Hysteria2FailureClass::Cancelled);
    assert!(!cancelled.allows_candidate_retry());
}

#[test]
fn hysteria2_salamander_packet_wrapper_roundtrips_payload() {
    let key = b"obfs-secret";
    let payload = b"fixture-quic-packet";
    assert_eq!(ResidentHysteria2ObfsPlan::none().udp_packet_overhead(), 0);
    assert_eq!(
        ResidentHysteria2ObfsPlan::salamander("fixture-key".to_owned()).udp_packet_overhead(),
        HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD
    );
    let packet = salamander_obfuscate_packet(key, payload);
    assert_eq!(
        packet.len(),
        HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD + payload.len()
    );
    assert_ne!(&packet[HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD..], payload);

    let mut storage = packet;
    let len = storage.len();
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [udp::RecvMeta {
        len,
        stride: len,
        ..Default::default()
    }];
    assert!(salamander_deobfuscate_received(
        key, &mut bufs, &mut meta, 1
    ));
    assert_eq!(meta[0].len, payload.len());
    assert_eq!(&bufs[0][..payload.len()], payload);
}

#[tokio::test]
async fn salamander_endpoint_charge_uses_wrapped_receive_segment_count() {
    let generation = dae_runtime_control::OwnerGeneration::new(8_204);
    let context = QuicEndpointOpenContext::from_identity_parts(
        QuicEndpointProtocol::Hysteria2,
        QuicEndpointCallerClass::BackgroundHealth,
        generation,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[b"salamander-charge-test"],
    );
    let cancellation = OwnerCancellationSignal::new();
    let endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
        0,
        &ResidentHysteria2ObfsPlan::salamander("test-obfs-key".to_owned()),
        None,
        "127.0.0.1:443".parse().unwrap(),
        context,
        AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(1)),
        &cancellation,
    )
    .await
    .unwrap();
    endpoint.mark_ready();
    let snapshot = quic_endpoint_metrics_snapshot(generation.get());
    let charge = &snapshot["endpoints"][0]["chargedBytes"];
    assert_eq!(charge["receiveSegments"], 1);
    assert_eq!(
        charge["receiveSlab"],
        quinn_boring::helpers::default_endpoint_config()
            .get_max_udp_payload_size()
            .min(64 * 1024)
            * quinn::udp::BATCH_SIZE as u64
    );
    endpoint.close(0_u32.into(), b"salamander charge test complete");
    endpoint.wait_idle().await;
    drop(endpoint);
}

#[tokio::test]
async fn salamander_port_hopping_charges_three_udp_sockets_but_one_quic_owner() {
    let generation = dae_runtime_control::OwnerGeneration::new(8_205);
    let context = QuicEndpointOpenContext::from_identity_parts(
        QuicEndpointProtocol::Hysteria2,
        QuicEndpointCallerClass::BackgroundHealth,
        generation,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[b"salamander-port-hopping-charge-test"],
    );
    let cancellation = OwnerCancellationSignal::new();
    let metrics = Arc::new(Hysteria2PortHoppingMetrics::default());
    let resources =
        Hysteria2OwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
    let port_hopping = Hysteria2PortHoppingRuntimeConfig::new(
        vec!["127.0.0.1".parse().unwrap()],
        Arc::new(vec![443, 8443]),
        Duration::from_secs(30),
        0,
        resources.port_hop_transition_socket_limit(),
        Arc::clone(&metrics),
    )
    .unwrap();
    let endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
        0,
        &ResidentHysteria2ObfsPlan::salamander("test-obfs-key".to_owned()),
        Some(port_hopping),
        "127.0.0.1:443".parse().unwrap(),
        context,
        AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(1)),
        &cancellation,
    )
    .await
    .unwrap();
    endpoint.mark_ready();
    let snapshot = quic_endpoint_metrics_snapshot(generation.get());
    assert_eq!(snapshot["liveStates"]["total"], 1);
    assert_eq!(
        snapshot["endpoints"][0]["underlay"],
        "salamander-port-hopping"
    );
    let charge = &snapshot["endpoints"][0]["chargedBytes"];
    assert_eq!(charge["receiveSegments"], 1);
    assert_eq!(charge["udpSocketCount"], 3);
    assert_eq!(metrics.snapshot()["activeSockets"], 1);

    endpoint.close(0_u32.into(), b"port hopping charge test complete");
    endpoint.wait_idle().await;
    drop(endpoint);
    tokio::task::yield_now().await;
    assert_eq!(metrics.snapshot()["activeSockets"], 0);
}
