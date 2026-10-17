use super::*;

/// Real maintained servers are supplied by an external fixture; no lab address
/// or credentials are embedded in this test or its commit metadata.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires DAE_PROXY_DNS_LIVE_LINK and DAE_PROXY_DNS_LIVE_TARGET"]
async fn maintained_proxy_dns_actor_reuses_sends_and_drains_concurrent_queries() {
    use dae_resident_transport::{
        start_anytls_owner_registry_on, start_h2_carrier_generation_owner_on,
        start_hysteria2_owner_registry_on, start_juicity_owner_registry_on,
        start_meek_transport_generation_owner_on, start_tuic_owner_registry_on,
        start_vless_mux_generation_owner_on,
    };
    let link = std::env::var("DAE_PROXY_DNS_LIVE_LINK").expect("external proxy link");
    let target: SocketAddr = std::env::var("DAE_PROXY_DNS_LIVE_TARGET")
        .expect("external DNS target")
        .parse()
        .unwrap();
    let config = dae_config::Config {
        global: dae_config::Global::default(),
        subscription: Vec::new(),
        node: Vec::new(),
        group: Vec::new(),
        routing: dae_config::Routing::default(),
        dns: dae_config::Dns::default(),
    };
    let mut plan = crate::plan::build_resident_proxy_plan_for_node(
        &config,
        "dns-live".to_owned(),
        "dns-live-node".to_owned(),
        link,
    )
    .unwrap();
    plan.materialize_execution();
    let binding = ResidentProxyBinding::resident(
        Arc::new(plan),
        dae_runtime_control::OwnerGeneration::new(9701),
    )
    .unwrap();
    let request_scoped = binding.execution().udp.uses_request_scoped_exchange();
    let stop = dae_resident_core::ResidentStopSignal::shared();
    let runtime = tokio::runtime::Handle::current();
    let (_h2, h2_task) =
        start_h2_carrier_generation_owner_on(&runtime, 9701, Arc::clone(&stop), 4).unwrap();
    let (_meek, meek_task) =
        start_meek_transport_generation_owner_on(&runtime, 9701, Arc::clone(&stop), 4).unwrap();
    let (_mux, mux_task) =
        start_vless_mux_generation_owner_on(&runtime, 9701, Arc::clone(&stop), 4).unwrap();
    let (xmux, xmux_task) =
        crate::tcp::start_xhttp_xmux_generation_owner_on(&runtime, 9701, 4).unwrap();
    let (hy2, hy2_task) = start_hysteria2_owner_registry_on(&runtime, 9701, Arc::clone(&stop));
    let (tuic, tuic_task) = start_tuic_owner_registry_on(&runtime, 9701, Arc::clone(&stop));
    let (juicity, juicity_task) =
        start_juicity_owner_registry_on(&runtime, 9701, Arc::clone(&stop));
    let (anytls, anytls_task) = start_anytls_owner_registry_on(&runtime, 9701, Arc::clone(&stop));
    let owners = ResidentTransportOwnerRegistries::new(Some(hy2), Some(tuic), Some(juicity))
        .with_anytls(Some(anytls));
    let selected = crate::ResidentRuntimeResourceConfig::from_config(&config);
    let profile = selected.runtime_profile.profile;
    let payload =
        ResidentUdpPayloadAdmission::new(9701, profile.udp_queued_payload_bytes_default());
    let mut resources = crate::ResidentUdpRuntimeConfig::from_resources(9701, &selected, payload)
        .dns_udp_runtime_config();
    // Exercise many pending queries on one physical session in every profile.
    resources.proxy_actor_limit = 1;
    resources.attempts = 1;
    resources.attempt_timeout = Duration::from_secs(10);
    let resource_evidence = json!({
        "queueDepth":resources.queue_depth,"pendingLimit":resources.pending_limit,
        "inflightWindow":resources.inflight_window,"sendBatchLimit":resources.send_batch_limit,
        "actorLimit":resources.proxy_actor_limit,
    });
    let admission = resources.payload_admission.clone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let executor = Arc::new(ResidentDnsUdpActorExecutor::new(
        resources.clone(),
        Arc::clone(&metrics),
    ));
    let forwarder = Arc::new(
        ResidentProxyDnsUdpForwarder::new_with_optional_transport_owner(
            binding,
            target,
            resources,
            Arc::clone(&metrics),
            Arc::clone(&executor),
            owners,
        )
        .unwrap(),
    );
    for id in 1..=8 {
        let query = dns_query(id, "sequential.external.test");
        let answer = forwarder.exchange(&query).await.unwrap();
        dae_dns::validate_dns_packet_response_for_request(&query, Some(&answer), true).unwrap();
        assert_eq!(&answer[..2], &id.to_be_bytes());
    }
    let mut queries = tokio::task::JoinSet::new();
    for id in 100..132 {
        let forwarder = Arc::clone(&forwarder);
        queries.spawn(async move {
            let query = dns_query(id, &format!("concurrent{id}.external.test"));
            let answer = forwarder.exchange(&query).await.unwrap();
            dae_dns::validate_dns_packet_response_for_request(&query, Some(&answer), true).unwrap();
            assert_eq!(&answer[..2], &id.to_be_bytes());
        });
    }
    while let Some(query) = queries.join_next().await {
        query.unwrap();
    }
    let active = metrics.snapshot();
    if !request_scoped {
        assert_eq!(active["proxyDnsUdpExecutorsOpened"], 1);
        assert!(active["proxyDnsUdpExecutorsReused"].as_u64().unwrap() >= 39);
    }
    assert_eq!(active["proxyDnsUdpExecutorsReset"], 0);
    let closed = forwarder
        .shutdown(time::Instant::now() + Duration::from_secs(5))
        .await;
    drop(forwarder);
    stop.store(true, Ordering::Release);
    tokio::task::spawn_blocking(move || {
        crate::tcp::stop_xhttp_xmux_generation_owner(&xmux, Duration::from_secs(5))
    })
    .await
    .unwrap();
    for task in [
        hy2_task,
        tuic_task,
        juicity_task,
        anytls_task,
        h2_task,
        meek_task,
        mux_task,
        xmux_task,
    ] {
        time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }
    let snapshot = metrics.snapshot();
    for name in [
        "proxyDnsUdpPendingCurrent",
        "proxyDnsUdpQueuedCurrent",
        "proxyDnsUdpPendingBytesCurrent",
        "proxyDnsUdpPendingMetadataBytesCurrent",
        "proxyDnsUdpResponseBytesCurrent",
    ] {
        assert_eq!(snapshot[name], 0, "{name}");
    }
    assert_eq!(admission.current(), 0);
    println!(
        "{}",
        json!({"profile":profile.name(),"resources":resource_evidence,"queries":40,"requestScoped":request_scoped,"active":active,"closed":closed,"final":snapshot,"payloadBytes":admission.current()})
    );
}
