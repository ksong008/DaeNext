use super::plan::effective_so_mark_from_dae;
use super::*;

pub(crate) struct ResidentDataplaneStartContext<'a> {
    pub(crate) handoff: &'a LiveLoadedTproxyListenSocketMap,
    pub(crate) reload_generation: u64,
    pub(crate) config: &'a Config,
    pub(crate) artifact_dir: &'a Path,
    pub(crate) routing_tuple_map_id: Option<u32>,
    pub(crate) domain_routing_map_id: Option<u32>,
    pub(crate) geodata: &'a ResidentGeodataStore,
    pub(crate) latency_seed: &'a [Value],
    pub(crate) dns_reload_snapshot: Option<&'a ResidentDnsReloadSnapshot>,
}

pub(crate) fn start_resident_dataplane_workers(
    context: ResidentDataplaneStartContext<'_>,
) -> (Value, Option<ResidentDataplaneRuntime>) {
    let ResidentDataplaneStartContext {
        handoff,
        reload_generation,
        config,
        artifact_dir,
        routing_tuple_map_id,
        domain_routing_map_id,
        geodata,
        latency_seed,
        dns_reload_snapshot,
    } = context;
    let event_file = artifact_dir.join("resident-production-dataplane-events.jsonl");
    let plan = match build_resident_dataplane_plan_with_geodata(config, geodata) {
        Ok(plan) => plan,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": false,
                    "error": err,
                    "event_file": Value::Null,
                    "event_file_status": "disabled",
                    "event_log": "product-log-sink",
                }),
                None,
            );
        }
    };
    if !plan.enabled {
        return (
            json!({
                "status": "pass",
                "enabled": false,
                "reason": plan.unsupported_reason,
                "event_file": Value::Null,
                "event_file_status": "disabled",
                "event_log": "product-log-sink",
            }),
            None,
        );
    }
    let resource_config = ResidentRuntimeResourceConfig::from_config(config);
    let so_mark_from_dae = effective_so_mark_from_dae(config.global.so_mark_from_dae);
    let default_outbound = plan.default_outbound;
    let tcp_dial_mode = plan.tcp_dial_mode;
    let sniffing_timeout = plan.sniffing_timeout;
    let dns_plan = plan.dns;
    let mut proxy_groups = plan.proxies;
    for group in proxy_groups.values_mut() {
        group.apply_runtime_generation(reload_generation);
    }
    let Some(default_outbound) = default_outbound else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without a default outbound id",
                "event_file": Value::Null,
                "event_file_status": "disabled",
                "event_log": "product-log-sink",
            }),
            None,
        );
    };
    let Some(default_proxy) = proxy_groups
        .get(&default_outbound)
        .and_then(|group| group.default_proxy_snapshot())
    else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without an admitted default proxy candidate",
                "event_file": Value::Null,
                "event_file_status": "disabled",
                "event_log": "product-log-sink",
            }),
            None,
        );
    };
    plan::apply_health_seed_snapshots(&proxy_groups, latency_seed);
    let proxy_groups = plan::share_resident_proxy_groups(proxy_groups);
    let Some(default_group) = proxy_groups.get(&default_outbound).cloned() else {
        return (
            json!({
                "status": "fail",
                "enabled": true,
                "error": "resident dataplane plan is enabled without a default proxy group plan",
                "event_file": Value::Null,
                "event_file_status": "disabled",
                "event_log": "product-log-sink",
            }),
            None,
        );
    };
    let routing_matcher =
        match build_resident_userspace_routing_matcher_with_geodata(config, geodata) {
            Ok(matcher) => matcher,
            Err(err) => {
                return (
                    json!({
                        "status": "fail",
                        "enabled": true,
                        "error": err,
                        "event_file": Value::Null,
                        "event_file_status": "disabled",
                        "event_log": "product-log-sink",
                    }),
                    None,
                );
            }
        };

    let tcp_listener = match handoff.listeners.tcp_listener.try_clone() {
        Ok(listener) => listener,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": format!("clone resident TCP listener: {err}"),
                    "event_file": Value::Null,
                    "event_file_status": "disabled",
                    "event_log": "product-log-sink",
                }),
                None,
            );
        }
    };
    let udp_socket = match handoff.listeners.udp_socket.try_clone() {
        Ok(socket) => socket,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": format!("clone resident UDP socket: {err}"),
                    "event_file": Value::Null,
                    "event_file_status": "disabled",
                    "event_log": "product-log-sink",
                }),
                None,
            );
        }
    };
    let dns_bind_listener = match prepare_resident_dns_bind_listener(&config.dns.bind) {
        Ok(listener) => listener,
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": err,
                    "event_file": Value::Null,
                    "event_file_status": "disabled",
                    "event_log": "product-log-sink",
                }),
                None,
            );
        }
    };
    let dns_bind_listener_report = dns_bind_listener
        .as_ref()
        .map(ResidentDnsBindListener::report)
        .unwrap_or_else(disabled_dns_bind_listener_report);

    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let udp_payload_admission = ResidentUdpPayloadAdmission::new(
        reload_generation,
        resource_config
            .runtime_profile
            .profile
            .udp_queued_payload_bytes_default(),
    );
    let udp_runtime_config = ResidentUdpRuntimeConfig::from_resources(
        reload_generation,
        &resource_config,
        udp_payload_admission.clone(),
    );
    apply_resident_udp_socket_buffer_tuning(&udp_socket);
    let udp_sessions_active = Arc::new(AtomicUsize::new(0));
    let event_lock = Arc::new(Mutex::new(()));
    let mut owner = ResidentRuntimeOwner::new(
        event_file.clone(),
        Arc::clone(&event_lock),
        reload_generation,
        Arc::clone(&metrics),
        Arc::clone(&udp_sessions_active),
        resource_config.clone(),
        udp_payload_admission,
    );
    let (hysteria2_owner_registry, hysteria2_owner_thread) = match start_hysteria2_owner_registry(
        reload_generation,
        owner.stop_handle(),
        resource_config.tcp_flow_stack_bytes.value(),
    ) {
        Ok(runtime) => runtime,
        Err(err) => {
            let cleanup = owner.shutdown();
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": err,
                    "cleanup": cleanup,
                    "event_file": Value::Null,
                    "event_file_status": "disabled",
                    "event_log": "product-log-sink",
                }),
                None,
            );
        }
    };
    owner.install_hysteria2_owner_registry(hysteria2_owner_registry, hysteria2_owner_thread);
    let requires_tuic_owner = proxy_groups
        .values()
        .any(|group| group.requires_tuic_transport_owner());
    if requires_tuic_owner {
        let (tuic_owner_registry, tuic_owner_thread) = match start_tuic_owner_registry(
            reload_generation,
            owner.stop_handle(),
            resource_config.tcp_flow_stack_bytes.value(),
        ) {
            Ok(runtime) => runtime,
            Err(err) => {
                let cleanup = owner.shutdown();
                return (
                    json!({
                        "status": "fail",
                        "enabled": true,
                        "error": err,
                        "cleanup": cleanup,
                        "event_file": Value::Null,
                        "event_file_status": "disabled",
                        "event_log": "product-log-sink",
                    }),
                    None,
                );
            }
        };
        owner.install_tuic_owner_registry(tuic_owner_registry, tuic_owner_thread);
    }
    let requires_juicity_owner = proxy_groups
        .values()
        .any(|group| group.requires_juicity_transport_owner());
    if requires_juicity_owner {
        let (juicity_owner_registry, juicity_owner_thread) = match start_juicity_owner_registry(
            reload_generation,
            owner.stop_handle(),
            resource_config.tcp_flow_stack_bytes.value(),
        ) {
            Ok(runtime) => runtime,
            Err(err) => {
                let cleanup = owner.shutdown();
                return (
                    json!({
                        "status": "fail",
                        "enabled": true,
                        "error": err,
                        "cleanup": cleanup,
                        "event_file": Value::Null,
                        "event_file_status": "disabled",
                        "event_log": "product-log-sink",
                    }),
                    None,
                );
            }
        };
        owner.install_juicity_owner_registry(juicity_owner_registry, juicity_owner_thread);
    }
    let requires_xhttp_xmux_owner = proxy_groups
        .values()
        .any(|group| group.requires_xhttp_xmux_owner());
    if requires_xhttp_xmux_owner {
        let (xhttp_xmux_owner, xhttp_xmux_owner_thread) =
            match tcp::start_xhttp_xmux_generation_owner(
                reload_generation,
                resource_config.tcp_flow_stack_bytes.value(),
            ) {
                Ok(runtime) => runtime,
                Err(err) => {
                    let cleanup = owner.shutdown();
                    return (
                        json!({
                            "status": "fail",
                            "enabled": true,
                            "error": err,
                            "cleanup": cleanup,
                            "event_file": Value::Null,
                            "event_file_status": "disabled",
                            "event_log": "product-log-sink",
                        }),
                        None,
                    );
                }
            };
        owner.install_xhttp_xmux_generation_owner(xhttp_xmux_owner, xhttp_xmux_owner_thread);
    }
    let proxy = Arc::new(default_proxy);
    let proxy_group = Arc::clone(&default_group);
    let mut manual_probe_plans = plan::build_resident_manual_probe_plans(config);
    for probe in manual_probe_plans
        .values_mut()
        .filter_map(|probe| probe.as_mut().ok())
    {
        probe.apply_runtime_generation(reload_generation);
    }
    let manual_probe_plan_count = manual_probe_plans
        .values()
        .filter(|plan| plan.is_ok())
        .count();
    let manual_probe_unavailable_count = manual_probe_plans
        .len()
        .saturating_sub(manual_probe_plan_count);
    let manual_probe_index = Arc::new(ResidentManualProbeIndex::new(manual_probe_plans));
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
    let health_bootstrap_concurrency = health_runtime_config
        .bootstrap_concurrency(health_candidate_count, health_check_concurrency);
    let health_scheduler_report = resident_health_scheduler_value(
        health_group_count,
        health_check_concurrency,
        health_bootstrap_concurrency,
        health_runtime_config,
    );
    let (health_resuscitation, health_resuscitation_rx) =
        resident_health_resuscitation_channel(Arc::clone(&metrics));
    let udp_proxy_groups = Arc::clone(&proxy_groups);
    let dns_domain_routing = domain_routing_map_id.map(|map_id| {
        Arc::new(dns::ResidentDnsDomainRouting::new(
            map_id,
            routing_matcher.clone(),
        ))
    });
    let dns_upstream_router = Arc::new(dns::ResidentDnsUpstreamRouter::new(
        routing_matcher.clone(),
        Arc::clone(&udp_proxy_groups),
        so_mark_from_dae,
        Some(health_resuscitation.clone()),
    ));
    let dns = Arc::new(
        dns_plan
            .with_udp_runtime_resources_and_transport_owner(
                udp_runtime_config.dns_udp_runtime_config(),
                Arc::clone(&metrics),
                owner.hysteria2_owner_registry().expect(
                    "Hysteria2 owner registry is installed before DNS runtime construction",
                ),
                owner.tuic_owner_registry(),
                owner.juicity_owner_registry(),
            )
            .with_domain_routing(dns_domain_routing.clone())
            .with_upstream_routing(Some(dns_upstream_router)),
    );
    let dns_reload_restore = match dns_reload_snapshot {
        Some(snapshot) => match dns.restore_reload_snapshot(snapshot) {
            Ok(report) => report.to_value(),
            Err(err) => {
                return (
                    json!({
                        "status": "fail",
                        "enabled": true,
                        "error": format!("restore resident DNS reload snapshot: {err}"),
                        "event_file": Value::Null,
                        "event_file_status": "disabled",
                        "event_log": "product-log-sink",
                    }),
                    None,
                );
            }
        },
        None => json!({
            "status": "skipped",
            "reason": "no resident DNS reload snapshot provided",
        }),
    };
    let dns_reload_handle = dns.reload_handle();
    let udp_routing_matcher = routing_matcher.clone();
    let udp_dial_mode = tcp_dial_mode;
    let udp_so_mark_from_dae = so_mark_from_dae;
    let tcp_router = match ResidentTcpRouter::new(
        Arc::clone(&proxy_groups),
        routing_tuple_map_id,
        routing_matcher,
        dns_domain_routing.clone(),
        Arc::clone(&dns),
        tcp_dial_mode,
        sniffing_timeout,
        so_mark_from_dae,
        config.global.mptcp,
        health_resuscitation.clone(),
        owner
            .hysteria2_owner_registry()
            .expect("Hysteria2 owner registry is installed before TCP router construction"),
        owner.tuic_owner_registry(),
        owner.juicity_owner_registry(),
    ) {
        Ok(router) => Arc::new(router),
        Err(err) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": err,
                    "event_file": Value::Null,
                    "event_file_status": "disabled",
                    "event_log": "product-log-sink",
                }),
                None,
            );
        }
    };
    let domain_routing_maintenance = match dns_domain_routing.as_ref() {
        Some(domain_routing) => match domain_routing.start_maintenance() {
            Ok((maintenance, thread)) => {
                owner.register_thread(
                    "dns-domain-routing-maintenance",
                    "dns-domain-routing-maintenance",
                    thread,
                );
                Some(maintenance)
            }
            Err(err) => {
                let cleanup = owner.shutdown();
                return (
                    json!({
                        "status": "fail",
                        "enabled": true,
                        "error": err,
                        "cleanup": cleanup,
                        "event_file": Value::Null,
                        "event_file_status": "disabled",
                        "event_log": "product-log-sink",
                    }),
                    None,
                );
            }
        },
        None => None,
    };
    let tcp_flow_stack_bytes = resource_config.tcp_flow_stack_bytes.value();
    let tcp_runtime_config = ResidentTcpRuntimeConfig::new(
        resource_config.tcp_runtime_workers.value(),
        resource_config.tcp_connection_limit.value(),
        tcp_flow_stack_bytes,
    );
    let udp_session_limit = udp_runtime_config.session_limit;
    let udp_session_queue_depth = udp_runtime_config.session_queue_depth;
    {
        let stop = owner.stop_handle();
        let tcp_router = Arc::clone(&tcp_router);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        owner.spawn_thread_with_stack(
            "tcp-accept-loop",
            "tcp-accept",
            tcp_flow_stack_bytes,
            move || {
                resident_tcp_accept_loop(
                    tcp_listener,
                    tcp_router,
                    stop,
                    event_file,
                    event_lock,
                    metrics,
                    tcp_runtime_config,
                )
            },
        );
    }
    if !health_groups.is_empty() {
        let stop = owner.stop_handle();
        let health_proxy_groups = Arc::clone(&proxy_groups);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        let hysteria2_owner_registry = owner
            .hysteria2_owner_registry()
            .expect("Hysteria2 owner registry is installed before health scheduler construction");
        let tuic_owner_registry = owner.tuic_owner_registry();
        let juicity_owner_registry = owner.juicity_owner_registry();
        owner.spawn_thread(
            "health-check-scheduler",
            "health-check-scheduler",
            move || {
                resident_health_scheduler_loop(
                    health_groups,
                    health_proxy_groups,
                    health_resuscitation_rx,
                    stop,
                    event_file,
                    event_lock,
                    metrics,
                    health_check_concurrency,
                    health_bootstrap_concurrency,
                    health_runtime_config,
                    Some(hysteria2_owner_registry),
                    tuic_owner_registry,
                    juicity_owner_registry,
                )
            },
        );
    } else {
        drop(health_resuscitation_rx);
    }
    {
        let stop = owner.stop_handle();
        let udp_proxy_groups = Arc::clone(&udp_proxy_groups);
        let routing_matcher = udp_routing_matcher;
        let dns = Arc::clone(&dns);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        let active_sessions = owner.udp_sessions_active();
        let udp_runtime_config = udp_runtime_config.clone();
        let hysteria2_owner_registry = owner
            .hysteria2_owner_registry()
            .expect("Hysteria2 owner registry is installed before UDP manager construction");
        let tuic_owner_registry = owner.tuic_owner_registry();
        let juicity_owner_registry = owner.juicity_owner_registry();
        let cleanup_reporter = owner.cleanup_reporter("udp-session-manager");
        owner.spawn_thread("udp-session-manager", "udp-session-manager", move || {
            let report = resident_udp_loop(
                udp_socket,
                udp_proxy_groups,
                default_outbound,
                routing_tuple_map_id,
                routing_matcher,
                udp_dial_mode,
                udp_so_mark_from_dae,
                dns,
                stop,
                event_file,
                event_lock,
                metrics,
                active_sessions,
                udp_runtime_config,
                health_resuscitation,
                hysteria2_owner_registry,
                tuic_owner_registry,
                juicity_owner_registry,
            );
            cleanup_reporter.finish(report);
        });
    }
    if let Some(dns_bind_listener) = dns_bind_listener {
        let stop = owner.stop_handle();
        let dns = Arc::clone(&dns);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        owner.spawn_thread("dns-bind-listener", "dns-bind-listener", move || {
            resident_dns_bind_listener_loop(
                dns_bind_listener,
                dns,
                stop,
                event_file,
                event_lock,
                metrics,
            )
        });
    }
    let default_proxy_utls = proxy.utls_fingerprint.as_ref().map(|fingerprint| {
        json!({
            "source": fingerprint.source,
            "requested": &fingerprint.requested,
            "name": &fingerprint.name,
            "canonical": &fingerprint.canonical,
            "family": &fingerprint.family,
            "client": &fingerprint.client,
            "randomized": fingerprint.randomized,
            "alpn_policy": &fingerprint.alpn_policy,
        })
    });
    let mut start_map = serde_json::Map::new();
    start_map.insert("status".to_owned(), json!("pass"));
    start_map.insert("enabled".to_owned(), json!(true));
    start_map.insert("tcp_worker_started".to_owned(), json!(true));
    start_map.insert("udp_session_manager_started".to_owned(), json!(true));
    start_map.insert(
        "dns_bind_listener_started".to_owned(),
        json!(
            dns_bind_listener_report["enabled"]
                .as_bool()
                .unwrap_or(false)
        ),
    );
    start_map.insert(
        "dns_bind_listener".to_owned(),
        dns_bind_listener_report.clone(),
    );
    start_map.insert("resources".to_owned(), resource_config.json());
    start_map.insert(
        "udp_runtime".to_owned(),
        udp_runtime_config.resource_inventory(),
    );
    start_map.insert(
        "tcp_flow_stack_bytes".to_owned(),
        json!(tcp_flow_stack_bytes),
    );
    start_map.insert(
        "tcp_flow_stack_bytes_env".to_owned(),
        json!(RESIDENT_TCP_FLOW_STACK_BYTES_ENV),
    );
    start_map.insert("tcp_runtime".to_owned(), tcp_runtime_config.json());
    start_map.insert(
        "tcp_runtime_workers_env".to_owned(),
        json!(RESIDENT_TCP_RUNTIME_WORKERS_ENV),
    );
    start_map.insert(
        "tcp_connection_limit_env".to_owned(),
        json!(RESIDENT_TCP_CONNECTION_LIMIT_ENV),
    );
    start_map.insert("udp_session_limit".to_owned(), json!(udp_session_limit));
    start_map.insert(
        "udp_session_limit_env".to_owned(),
        json!(RESIDENT_UDP_SESSION_LIMIT_ENV),
    );
    start_map.insert(
        "udp_session_queue_depth".to_owned(),
        json!(udp_session_queue_depth),
    );
    start_map.insert(
        "udp_session_queue_depth_env".to_owned(),
        json!(RESIDENT_UDP_SESSION_QUEUE_DEPTH_ENV),
    );
    start_map.insert(
        "event_queue_depth".to_owned(),
        json!(resource_config.event_queue_depth.value()),
    );
    start_map.insert(
        "event_queue_depth_env".to_owned(),
        json!(RESIDENT_EVENT_QUEUE_DEPTH_ENV),
    );
    start_map.insert("event_file".to_owned(), Value::Null);
    start_map.insert("event_file_status".to_owned(), json!("disabled"));
    start_map.insert("event_log".to_owned(), json!("product-log-sink"));
    start_map.insert("reload_generation".to_owned(), json!(reload_generation));
    start_map.insert("runtime_owner".to_owned(), owner.task_registry_value());
    start_map.insert(
        "routing_tuple_map_id".to_owned(),
        json!(routing_tuple_map_id),
    );
    start_map.insert(
        "domain_routing_map_id".to_owned(),
        json!(domain_routing_map_id),
    );
    start_map.insert("dns_reload_restore".to_owned(), dns_reload_restore);
    start_map.insert(
        "dns_domain_routing".to_owned(),
        json!({
            "enabled": domain_routing_map_id.is_some(),
            "map_id": domain_routing_map_id,
            "source": "resident DNS accepted response cache and TCP domain++ sniffed-domain learning",
            "scope": "accepted DNS responses and TCP sniffed domains update domain_routing_map for kernel domain routing hits",
        }),
    );
    start_map.insert(
        "tcp_dial_mode".to_owned(),
        json!(tcp_router.dial_mode_name()),
    );
    start_map.insert(
        "tcp_sniffing_timeout".to_owned(),
        json!(format!("{:?}", tcp_router.sniffing_timeout())),
    );
    start_map.insert("proxy_count".to_owned(), json!(tcp_router.proxy_count()));
    start_map.insert(
        "health_check_worker_count".to_owned(),
        json!(if health_group_count > 0 {
            health_runtime_config.os_thread_count()
        } else {
            0
        }),
    );
    start_map.insert(
        "health_check_scheduler_count".to_owned(),
        json!(if health_group_count > 0 { 1 } else { 0 }),
    );
    start_map.insert(
        "health_check_group_count".to_owned(),
        json!(health_group_count),
    );
    start_map.insert("health_check_scheduler".to_owned(), health_scheduler_report);
    start_map.insert(
        "manual_probe_plan_count".to_owned(),
        json!(manual_probe_plan_count),
    );
    start_map.insert(
        "manual_probe_unavailable_count".to_owned(),
        json!(manual_probe_unavailable_count),
    );
    start_map.insert(
        "default_group".to_owned(),
        json!({
            "group": &proxy_group.group_name,
            "group_policy": proxy_group.group_policy_name(),
            "candidate_count": proxy_group.candidate_count(),
            "admitted_candidate_count": proxy_group.admitted_candidate_count(),
            "annotation_latency_offset_count": proxy_group.annotation_latency_offset_count(),
            "alive_state_wired": proxy_group.alive_state_wired(),
            "latency_state_wired": proxy_group.latency_state_wired(),
            "background_check_required": proxy_group.needs_background_checks(),
            "check_interval": format!("{:?}", proxy_group.check_interval()),
        }),
    );
    start_map.insert(
        "default_proxy".to_owned(),
        json!({
            "protocol": &proxy.protocol,
            "group": &proxy.group_name,
            "group_policy": &proxy.group_policy,
            "node_tag": &proxy.node_tag,
            "server_host": &proxy.server_host,
            "server_port": proxy.server_port,
            "server_name": &proxy.server_name,
            "transport": &proxy.net,
            "tls": proxy.tls,
            "flow": &proxy.flow,
            "alpn": &proxy.alpn,
            "allow_insecure": proxy.allow_insecure,
            "utls_fingerprint": default_proxy_utls,
            "mark": proxy.mark,
            "mptcp": proxy.mptcp,
            "executableGraph": proxy.executable_graph_value_for_reload_generation(reload_generation),
            "runtimeComponents": proxy.runtime_component_evidence_value_for_reload_generation(reload_generation),
        }),
    );
    start_map.insert(
        "scope".to_owned(),
        json!("resident worker consumes live tproxy TCP/UDP sockets and relays through admitted Rust proxy handlers; unsupported protocols fail explicitly instead of faking proxy success"),
    );
    let start = Value::Object(start_map);
    (
        start,
        Some(ResidentDataplaneRuntime {
            owner,
            groups: runtime_groups,
            manual_probe_index,
            dns_reload_handle,
            domain_routing_maintenance,
        }),
    )
}
