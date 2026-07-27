use super::*;

pub(crate) struct ResidentDataplaneStartContext<'a> {
    pub(crate) handoff: &'a LiveLoadedTproxyListenSocketMap,
    pub(crate) reload_generation: u64,
    pub(crate) config: &'a Config,
    pub(crate) config_owner: Arc<Config>,
    pub(crate) artifact_dir: &'a Path,
    pub(crate) routing_tuple_map_id: Option<u32>,
    pub(crate) domain_routing_map_id: Option<u32>,
    pub(crate) prepared: ResidentPreparedDataplane,
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
        config_owner,
        artifact_dir,
        routing_tuple_map_id,
        domain_routing_map_id,
        prepared,
        latency_seed,
        dns_reload_snapshot,
    } = context;
    let event_file = artifact_dir.join("resident-production-dataplane-events.jsonl");
    if !prepared.plan.enabled {
        return (
            json!({
                "status": "pass",
                "enabled": false,
                "reason": prepared.plan.unsupported_reason,
                "event_file": Value::Null,
                "event_file_status": "disabled",
                "event_log": "product-log-sink",
            }),
            None,
        );
    }
    let resource_config = ResidentRuntimeResourceConfig::from_config(config);
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
    apply_resident_udp_socket_buffer_tuning(&udp_socket);
    let udp_sessions_active = Arc::new(AtomicUsize::new(0));
    let event_lock = Arc::new(Mutex::new(()));
    let mut owner = match ResidentRuntimeOwner::new(
        event_file.clone(),
        Arc::clone(&event_lock),
        reload_generation,
        Arc::clone(&metrics),
        Arc::clone(&udp_sessions_active),
        resource_config.clone(),
        udp_payload_admission,
    ) {
        Ok(owner) => owner,
        Err(error) => {
            return (
                json!({
                    "status": "fail",
                    "enabled": true,
                    "error": error,
                    "event_file": Value::Null,
                    "event_file_status": "disabled",
                    "event_log": "product-log-sink",
                }),
                None,
            );
        }
    };
    let built_generation =
        match build_resident_dataplane_generation(ResidentGenerationBuildContext {
            owner: &mut owner,
            config: config_owner,
            prepared,
            routing_tuple_map_id,
            domain_routing_map_id,
            latency_seed,
            dns_reload_snapshot,
        }) {
            Ok(generation) => generation,
            Err(error) => {
                let cleanup = owner.shutdown();
                return (
                    json!({
                        "status": "fail",
                        "enabled": true,
                        "error": error,
                        "cleanup": cleanup,
                        "event_file": Value::Null,
                        "event_file_status": "disabled",
                        "event_log": "product-log-sink",
                    }),
                    None,
                );
            }
        };
    let proxy = Arc::clone(&built_generation.default_proxy);
    let proxy_group = Arc::clone(&built_generation.default_group);
    let health_scheduler_report = built_generation.health_scheduler_report.clone();
    let health_group_count = built_generation.health_group_count;
    let health_worker_count = built_generation.health_worker_count;
    let manual_probe_plan_count = built_generation.manual_probe_plan_count;
    let manual_probe_unavailable_count = built_generation.manual_probe_unavailable_count;
    let dns_reload_restore = built_generation.dns_reload_restore.clone();
    let tcp_flow_stack_bytes = built_generation.tcp_flow_stack_bytes;
    let udp_runtime_config = built_generation.udp_runtime_config.clone();
    let tcp_runtime_config = built_generation.generation.tcp_runtime_config;
    let tcp_dial_mode_name = built_generation
        .generation
        .tcp_router
        .dial_mode_name()
        .to_owned();
    let tcp_sniffing_timeout = built_generation.generation.tcp_router.sniffing_timeout();
    let proxy_count = built_generation.generation.tcp_router.proxy_count();
    let udp_session_admission_limit = udp_runtime_config.session_admission_limit;
    let udp_session_soft_watermark = udp_runtime_config.session_soft_watermark;
    let udp_session_queue_depth = udp_runtime_config.session_queue_depth;
    let active_generation = ActiveGenerationSlot::new(built_generation.generation);
    let generation_drain = ResidentGenerationDrain::new(ResidentGenerationDrainPolicy::selected());
    {
        let stop = owner.stop_handle();
        let drain = generation_drain.clone();
        owner.spawn_async_task("generation-drain", "generation-drain", async move {
            drain.run(stop).await;
        });
    }
    {
        let stop = owner.stop_handle();
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        owner.spawn_async_task(
            "tcp-accept-loop",
            "tcp-accept",
            resident_tcp_accept_loop_async(
                tcp_listener,
                active_generation.clone(),
                stop,
                event_file,
                event_lock,
            ),
        );
    }
    {
        let stop = owner.stop_handle();
        let udp_generation = active_generation.clone();
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        let active_sessions = owner.udp_sessions_active();
        let cleanup_reporter = owner.cleanup_reporter("udp-session-manager");
        owner.spawn_async_task("udp-session-manager", "udp-session-manager", async move {
            let report = resident_udp_loop_async(
                udp_socket,
                udp_generation,
                stop,
                event_file,
                event_lock,
                active_sessions,
            )
            .await;
            cleanup_reporter.finish(report);
        });
    }
    if let Some(dns_bind_listener) = dns_bind_listener {
        let stop = owner.stop_handle();
        let dns_generation = active_generation.clone();
        let event_file = owner.event_file();
        let event_lock = owner.event_lock();
        owner.spawn_async_task("dns-bind-listener", "dns-bind-listener", async move {
            run_resident_dns_bind_listener_async(
                dns_bind_listener,
                dns_generation,
                stop,
                event_file,
                event_lock,
            )
            .await
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
    start_map.insert(
        "udp_session_admission".to_owned(),
        json!({
            "mode": if udp_session_admission_limit.is_some() { "fixed" } else { "automatic" },
            "fixed_limit": udp_session_admission_limit,
            "soft_watermark": udp_session_soft_watermark,
        }),
    );
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
    start_map.insert("tcp_dial_mode".to_owned(), json!(tcp_dial_mode_name));
    start_map.insert(
        "tcp_sniffing_timeout".to_owned(),
        json!(format!("{tcp_sniffing_timeout:?}")),
    );
    start_map.insert("proxy_count".to_owned(), json!(proxy_count));
    start_map.insert(
        "health_check_worker_count".to_owned(),
        json!(health_worker_count),
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
    start_map.insert("manual_probe_catalog".to_owned(), json!("lazy-on-request"));
    start_map.insert(
        "manual_probe_cache_key".to_owned(),
        json!("node-execution-identity"),
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
    let read_handle =
        ResidentDataplaneReadHandle::new(owner.read_handle(), generation_drain.clone());
    (
        start,
        Some(ResidentDataplaneRuntime {
            owner,
            read_handle,
            active_generation,
            generation_drain,
            workload_shutdown: None,
            routing_tuple_map_id,
            domain_routing_map_id,
        }),
    )
}
