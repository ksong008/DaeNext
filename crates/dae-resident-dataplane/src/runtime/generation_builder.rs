use super::plan::effective_so_mark_from_dae;
use super::*;

pub(super) struct ResidentGenerationBuildContext<'a> {
    pub(super) owner: &'a mut ResidentRuntimeOwner,
    pub(super) config: Arc<Config>,
    pub(super) prepared: ResidentPreparedDataplane,
    pub(super) routing_tuple_map_id: Option<u32>,
    pub(super) domain_routing_map_id: Option<u32>,
    pub(super) domain_routing_fence: Arc<dns::ResidentDomainRoutingGenerationFence>,
    pub(super) latency_seed: &'a [Value],
    pub(super) dns_reload_snapshot: Option<&'a ResidentDnsReloadSnapshot>,
}

pub(super) struct BuiltResidentDataplaneGeneration {
    pub(super) generation: Arc<ResidentDataplaneGeneration>,
    pub(super) default_proxy: Arc<plan::ResidentProxyPlan>,
    pub(super) default_group: Arc<plan::ResidentProxyGroupPlan>,
    pub(super) health_scheduler_report: Value,
    pub(super) health_group_count: usize,
    pub(super) health_worker_count: usize,
    pub(super) manual_probe_plan_count: usize,
    pub(super) manual_probe_unavailable_count: usize,
    pub(super) dns_reload_restore: Value,
    pub(super) tcp_flow_stack_bytes: usize,
    pub(super) udp_runtime_config: ResidentUdpRuntimeConfig,
}

pub(super) fn build_resident_dataplane_generation(
    context: ResidentGenerationBuildContext<'_>,
) -> Result<BuiltResidentDataplaneGeneration, String> {
    let ResidentGenerationBuildContext {
        owner,
        config,
        prepared,
        routing_tuple_map_id,
        domain_routing_map_id,
        domain_routing_fence,
        latency_seed,
        dns_reload_snapshot,
    } = context;
    let ResidentPreparedDataplane {
        plan,
        routing_matcher,
        protocol_owner_specs,
    } = prepared;
    owner.reap_finished_generation_tasks();
    if !plan.enabled {
        return Err(plan
            .unsupported_reason
            .unwrap_or_else(|| "resident dataplane generation is disabled".to_owned()));
    }
    let reload_generation = owner.physical_generation();
    let physical_runtime_id = PhysicalRuntimeId::new(reload_generation);
    let mut resource_config = ResidentRuntimeResourceConfig::from_config(&config);
    let process_resources = owner.resource_config();
    resource_config.tcp_flow_stack_bytes = process_resources.tcp_flow_stack_bytes.clone();
    resource_config.tcp_runtime_workers = process_resources.tcp_runtime_workers.clone();
    resource_config.event_queue_depth = process_resources.event_queue_depth.clone();
    let so_mark_from_dae = effective_so_mark_from_dae(config.global.so_mark_from_dae);
    let default_outbound = plan.default_outbound.ok_or_else(|| {
        "resident dataplane plan is enabled without a default outbound id".to_owned()
    })?;
    let tcp_dial_mode = plan.tcp_dial_mode;
    let sniffing_timeout = plan.sniffing_timeout;
    let dns_plan = plan.dns;
    let mut proxy_groups = plan.proxies;
    proxy_groups
        .values_mut()
        .try_for_each(|group| group.apply_runtime_generation(reload_generation))?;
    let default_proxy = proxy_groups
        .get(&default_outbound)
        .and_then(|group| group.default_proxy_snapshot())
        .ok_or_else(|| {
            "resident dataplane plan is enabled without an admitted default proxy candidate"
                .to_owned()
        })?;
    plan::apply_health_seed_snapshots(&proxy_groups, latency_seed);
    let proxy_groups = plan::share_resident_proxy_groups(proxy_groups);
    let default_group = proxy_groups
        .get(&default_outbound)
        .cloned()
        .ok_or_else(|| {
            "resident dataplane plan is enabled without a default proxy group plan".to_owned()
        })?;

    owner.ensure_protocol_owner_registries(protocol_owner_specs)?;
    let mut udp_runtime_config = ResidentUdpRuntimeConfig::from_resources(
        reload_generation,
        &resource_config,
        owner.udp_payload_admission(),
    );
    udp_runtime_config.runtime_worker_threads = owner.data_plane_worker_threads();
    let metrics = owner.metrics();
    let manual_probe_index = Arc::new(ResidentManualProbeIndex::lazy(
        Arc::clone(&config),
        reload_generation,
    ));
    let manual_probe_plan_count = manual_probe_index.cached_plan_count();
    let manual_probe_unavailable_count = 0;
    let runtime_groups = proxy_groups.values().cloned().collect::<Vec<_>>();
    let health_groups = runtime_groups.clone();
    let health_group_count = health_groups.len();
    let health_candidate_count = health_groups
        .iter()
        .map(|group| group.admitted_candidate_count())
        .fold(0_usize, usize::saturating_add);
    let health_check_concurrency = resource_config.health_check_concurrency.value();
    let health_runtime_config = ResidentHealthRuntimeConfig::detect(
        health_group_count,
        health_check_concurrency,
        health_candidate_count,
    );
    let health_worker_count = if health_group_count > 0 {
        health_runtime_config.os_thread_count()
    } else {
        0
    };
    let health_bootstrap_concurrency = health_runtime_config
        .bootstrap_concurrency(health_candidate_count, health_check_concurrency);
    let mut health_scheduler_report = resident_health_scheduler_value(
        health_group_count,
        health_check_concurrency,
        health_bootstrap_concurrency,
        health_runtime_config,
    );
    health_scheduler_report["osThreadCount"] = json!(0);
    health_scheduler_report["maximumOsThreadCount"] = json!(0);
    health_scheduler_report["sharedDataPlaneWorkerThreads"] =
        json!(owner.data_plane_worker_threads());
    health_scheduler_report["runtime"]["executor"] = json!("process-owned-shared-multi-thread");
    let (health_resuscitation, health_resuscitation_rx) =
        resident_health_resuscitation_channel(Arc::clone(&metrics));
    let health_resuscitation: Arc<dyn ResidentHealthResuscitation> = Arc::new(health_resuscitation);
    let udp_proxy_groups = Arc::clone(&proxy_groups);
    let generation_id = next_resident_dataplane_generation_id();
    let generation_token = GenerationToken::new(physical_runtime_id, generation_id);
    let dns_domain_routing = domain_routing_map_id.map(|map_id| {
        Arc::new(dns::ResidentDnsDomainRouting::new_for_generation(
            map_id,
            generation_token,
            routing_matcher.clone(),
            Arc::clone(&domain_routing_fence),
        ))
    });
    let dns_upstream_router = Arc::new(dns::ResidentDnsUpstreamRouter::new(
        routing_matcher.clone(),
        crate::plan::ResidentDnsProxyGroupSelector::shared(Arc::clone(&udp_proxy_groups)),
        so_mark_from_dae,
        Some(Arc::clone(&health_resuscitation)),
    ));
    let dns_udp_runtime = udp_runtime_config.dns_udp_runtime_config();
    let dns_udp_executor = Arc::new(dns::ResidentDnsUdpActorExecutor::new_on(
        dns_udp_runtime.clone(),
        Arc::clone(&metrics),
        owner.data_plane_handle(),
    ));
    let dns_transport_owners = ResidentTransportOwnerRegistries::new(
        owner.hysteria2_owner_registry(),
        owner.tuic_owner_registry(),
        owner.juicity_owner_registry(),
    )
    .with_anytls(owner.anytls_owner_registry());
    let dns_proxy_tcp_transport = resident_dns_proxy_tcp_transport(dns_transport_owners.clone());
    let dns_proxy_udp_transport = resident_dns_proxy_udp_transport(
        dns_udp_runtime.clone(),
        Arc::clone(&metrics),
        Arc::clone(&dns_udp_executor),
        dns_transport_owners,
    );
    let dns = Arc::new(
        dns_plan
            .with_udp_runtime_resources_and_transports(
                dns_udp_runtime,
                Arc::clone(&metrics),
                owner.data_plane_handle(),
                dns_udp_executor,
                dae_resident_dns::ResidentDnsTransportPorts::new(
                    dns_proxy_tcp_transport,
                    dns_proxy_udp_transport,
                    Arc::new(crate::transport::quic_endpoint::ResidentDnsQuicEndpointPolicy),
                ),
            )
            .with_domain_routing(dns_domain_routing.clone())
            .with_upstream_routing(Some(dns_upstream_router)),
    );
    let dns_reload_restore = match dns_reload_snapshot {
        Some(snapshot) => dns
            .restore_reload_snapshot(snapshot)
            .map_err(|error| format!("restore resident DNS reload snapshot: {error}"))?
            .to_value(),
        None => json!({
            "status": "skipped",
            "reason": "no resident DNS reload snapshot provided",
        }),
    };
    let dns_reload_handle = dns.reload_handle();
    let tcp_router = Arc::new(ResidentTcpRouter::new(
        plan::ResidentTcpProxyGroupSelector::shared(Arc::clone(&proxy_groups)),
        routing_tuple_map_id,
        routing_matcher.clone(),
        tcp::ResidentTcpDnsResolverPort::shared(dns::ResidentDnsResolver::new(Arc::clone(&dns))),
        tcp_dial_mode,
        sniffing_timeout,
        so_mark_from_dae,
        config.global.mptcp,
        Arc::clone(&health_resuscitation),
        owner.hysteria2_owner_registry(),
        owner.tuic_owner_registry(),
        owner.juicity_owner_registry(),
        owner.anytls_owner_registry(),
    )?);
    let domain_routing_maintenance = match dns_domain_routing.as_ref() {
        Some(domain_routing) => {
            let (maintenance, thread) = domain_routing.start_maintenance()?;
            owner.register_generation_thread(
                "dns-domain-routing-maintenance",
                "dns-domain-routing-maintenance",
                thread,
            );
            Some(maintenance)
        }
        None => None,
    };
    let tcp_flow_stack_bytes = resource_config.tcp_flow_stack_bytes.value();
    let tcp_runtime_config = ResidentTcpRuntimeConfig::new(
        resource_config.tcp_runtime_workers.value(),
        resource_config.tcp_connection_limit.value(),
        tcp_flow_stack_bytes,
    );
    let generation_stop = ResidentStopSignal::shared();
    let generation_drain_control =
        ResidentGenerationDrainControl::new(generation_id, Arc::clone(&generation_stop));
    let manual_probe_handle =
        owner.manual_probe_handle(&runtime_groups, &manual_probe_index, &resource_config);
    let udp_generation_plan = udp::ResidentUdpGenerationPlan::new(
        udp_proxy_groups,
        default_outbound,
        routing_tuple_map_id,
        routing_matcher,
        tcp_dial_mode,
        so_mark_from_dae,
        dns::ResidentDnsDispatcher::new(Arc::clone(&dns)),
        udp_runtime_config.clone(),
        health_resuscitation,
        owner.hysteria2_owner_registry(),
        owner.tuic_owner_registry(),
        owner.juicity_owner_registry(),
        owner.anytls_owner_registry(),
    )?;
    if let Some(task) = dns.take_target_refresh_owner_task(Arc::clone(&generation_stop))? {
        owner.spawn_generation_async_task("dns-target-refresh-owner", "dns-target-refresh", task);
    }
    let generation = Arc::new(ResidentDataplaneGeneration {
        _lifetime: ResidentDataplaneGenerationLifetime::register(),
        id: generation_id,
        reload_generation: physical_runtime_id,
        tcp_router,
        tcp_admission: tcp::ResidentTcpAdmission::new(
            tcp_runtime_config.connection_limit(),
            Arc::clone(&metrics),
        ),
        tcp_runtime_config,
        dns: Arc::clone(&dns),
        udp: udp_generation_plan,
        drain_control: generation_drain_control,
        metrics,
        groups: runtime_groups,
        manual_probe_handle,
        dns_reload_handle,
        domain_routing_maintenance,
    });
    if !health_groups.is_empty() {
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let health_proxy_groups = Arc::clone(&proxy_groups);
        let metrics = owner.metrics();
        let health_dns = Arc::clone(&dns);
        let hysteria2_owner_registry = owner.hysteria2_owner_registry();
        let tuic_owner_registry = owner.tuic_owner_registry();
        let juicity_owner_registry = owner.juicity_owner_registry();
        let anytls_owner_registry = owner.anytls_owner_registry();
        owner.spawn_generation_async_task(
            "health-check-scheduler",
            "health-check-scheduler",
            resident_health_scheduler_async(
                health_groups,
                health_proxy_groups,
                health_resuscitation_rx,
                generation_stop,
                event_file,
                event_lock,
                metrics,
                health_dns,
                health_check_concurrency,
                health_bootstrap_concurrency,
                health_runtime_config,
                Some(owner.data_plane_worker_threads()),
                hysteria2_owner_registry,
                tuic_owner_registry,
                juicity_owner_registry,
                anytls_owner_registry,
            ),
        );
    } else {
        drop(health_resuscitation_rx);
    }

    Ok(BuiltResidentDataplaneGeneration {
        generation,
        default_proxy: Arc::clone(default_proxy.shared_plan()),
        default_group,
        health_scheduler_report,
        health_group_count,
        health_worker_count,
        manual_probe_plan_count,
        manual_probe_unavailable_count,
        dns_reload_restore,
        tcp_flow_stack_bytes,
        udp_runtime_config,
    })
}
