use super::plan::effective_so_mark_from_dae;
use super::*;
pub(crate) fn start_resident_dataplane_workers(
    handoff: &LiveLoadedTproxyListenSocketMap,
    config: &Config,
    artifact_dir: &Path,
    routing_tuple_map_id: Option<u32>,
    domain_routing_map_id: Option<u32>,
    geodata: &ResidentGeodataStore,
    latency_seed: &[Value],
    dns_reload_snapshot: Option<ResidentDnsReloadSnapshot>,
) -> (Value, Option<ResidentDataplaneRuntime>) {
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
    let so_mark_from_dae = effective_so_mark_from_dae(config.global.so_mark_from_dae);
    let default_outbound = plan.default_outbound;
    let tcp_dial_mode = plan.tcp_dial_mode;
    let sniffing_timeout = plan.sniffing_timeout;
    let dns_plan = plan.dns;
    let proxy_groups = plan.proxies;
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
    plan::apply_successful_latency_seed_snapshots(&proxy_groups, latency_seed);
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

    let reload_generation = RESIDENT_RELOAD_GENERATION.fetch_add(1, Ordering::Relaxed);
    let resource_config = ResidentRuntimeResourceConfig::from_config(config);
    apply_resident_udp_socket_buffer_tuning(&udp_socket);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let udp_sessions_active = Arc::new(AtomicUsize::new(0));
    let event_lock = Arc::new(Mutex::new(()));
    let mut owner = ResidentRuntimeOwner::new(
        event_file.clone(),
        Arc::clone(&event_lock),
        reload_generation,
        Arc::clone(&metrics),
        Arc::clone(&udp_sessions_active),
        resource_config.clone(),
    );
    let proxy = Arc::new(default_proxy);
    let proxy_group = Arc::clone(&default_group);
    let manual_probe_plans = plan::build_resident_manual_probe_plans(config);
    let manual_probe_plan_count = manual_probe_plans
        .values()
        .filter(|plan| plan.is_ok())
        .count();
    let manual_probe_unavailable_count = manual_probe_plans
        .len()
        .saturating_sub(manual_probe_plan_count);
    let runtime_groups = proxy_groups.values().cloned().collect::<Vec<_>>();
    let health_groups = runtime_groups
        .iter()
        .filter(|group| group.needs_background_checks())
        .cloned()
        .collect::<Vec<_>>();
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
    ));
    let dns = Arc::new(
        dns_plan
            .with_domain_routing(dns_domain_routing.clone())
            .with_upstream_routing(Some(dns_upstream_router)),
    );
    let dns_reload_restore = match dns_reload_snapshot.as_ref() {
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
    let udp_session_limit = resource_config.udp_session_limit.value();
    let udp_session_queue_depth = resource_config.udp_session_queue_depth.value();
    {
        let stop = owner.stop_handle();
        let tcp_router = Arc::clone(&tcp_router);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        owner.register_thread(
            "tcp-accept-loop",
            "tcp-accept",
            thread::spawn(move || {
                resident_tcp_accept_loop(
                    tcp_listener,
                    tcp_router,
                    stop,
                    event_file,
                    event_lock,
                    metrics,
                    tcp_flow_stack_bytes,
                )
            }),
        );
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
        let health_check_concurrency = resource_config.health_check_concurrency.value();
        let dns_fast_path_concurrency = resource_config.dns_fast_path_concurrency.value();
        owner.register_thread(
            "udp-session-manager",
            "udp-session-manager",
            thread::spawn(move || {
                resident_udp_loop(
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
                    udp_session_limit,
                    udp_session_queue_depth,
                    health_check_concurrency,
                    dns_fast_path_concurrency,
                )
            }),
        );
    }
    if let Some(dns_bind_listener) = dns_bind_listener {
        let stop = owner.stop_handle();
        let dns = Arc::clone(&dns);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let metrics = owner.metrics();
        owner.register_thread(
            "dns-bind-listener",
            "dns-bind-listener",
            thread::spawn(move || {
                resident_dns_bind_listener_loop(
                    dns_bind_listener,
                    dns,
                    stop,
                    event_file,
                    event_lock,
                    metrics,
                )
            }),
        );
    }
    for health_group in &health_groups {
        let stop = owner.stop_handle();
        let health_group = Arc::clone(health_group);
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let health_check_concurrency = resource_config.health_check_concurrency.value();
        owner.register_thread(
            "health-check-loop",
            "health-check",
            thread::spawn(move || {
                resident_group_health_check_loop(
                    health_group,
                    stop,
                    event_file,
                    event_lock,
                    health_check_concurrency,
                )
            }),
        );
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
        "tcp_flow_stack_bytes".to_owned(),
        json!(tcp_flow_stack_bytes),
    );
    start_map.insert(
        "tcp_flow_stack_bytes_env".to_owned(),
        json!(RESIDENT_TCP_FLOW_STACK_BYTES_ENV),
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
        json!(health_groups.len()),
    );
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
            manual_probe_plans,
            dns_reload_handle,
            domain_routing_maintenance,
        }),
    )
}
