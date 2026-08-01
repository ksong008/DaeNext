use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn juicity_stream_packet_writes_progress_before_reordered_responses() {
    let server = JuicityTestServer::start_buffering_udp_responses(4, true).await;
    let generation = 8_108;
    let proxy = juicity_proxy(server.addr, generation);
    let stop = ResidentStopSignal::shared();
    let (registry, owner_thread) = start_juicity_owner_registry(
        generation,
        Arc::clone(&stop),
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
    )
    .unwrap();
    let target: SocketAddr = TEST_UDP_TARGET.parse().unwrap();

    let (_, responses) = time::timeout(
        Duration::from_secs(2),
        exercise_juicity_udp_stream_session(
            proxy,
            registry.clone(),
            target,
            &[b"packet-1", b"packet-2", b"packet-3", b"packet-4"],
        ),
    )
    .await
    .expect("Juicity stream writes must not wait for one response per request")
    .unwrap();

    assert_eq!(
        responses,
        [
            b"packet-4".to_vec(),
            b"packet-3".to_vec(),
            b"packet-2".to_vec(),
            b"packet-1".to_vec(),
        ]
    );
    assert_eq!(
        server
            .observation
            .udp_packets_before_first_response
            .load(Ordering::Relaxed),
        4
    );

    assert!(
        stop_juicity_owner_registry(stop, owner_thread).await
            < RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE
    );
    assert_juicity_owner_resources_released(&registry, generation);
    server.stop().await;
}
