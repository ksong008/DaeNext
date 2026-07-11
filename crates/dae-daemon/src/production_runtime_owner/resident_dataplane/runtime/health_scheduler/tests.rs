use super::*;

#[test]
fn resident_health_initial_jitter_is_stable_and_bounded() {
    let interval = Duration::from_secs(30);
    let first = resident_health_initial_jitter("proxy", 3, interval);
    let second = resident_health_initial_jitter("proxy", 3, interval);
    assert_eq!(first, second);
    assert!(first <= RESIDENT_HEALTH_INITIAL_JITTER_CEILING);
    assert!(first <= interval / 4);
}

#[test]
fn resident_health_initial_jitter_is_disabled_for_zero_interval() {
    assert_eq!(
        resident_health_initial_jitter("proxy", 3, Duration::ZERO),
        Duration::ZERO
    );
}

#[test]
fn health_resuscitation_admission_is_bounded_and_observable() {
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (handle, receiver) =
        resident_health_resuscitation_channel_with_depth(1, Arc::clone(&metrics));

    handle.trigger(1, NetworkType::DATA_UDP4);
    handle.trigger(1, NetworkType::DATA_UDP4);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["healthResuscitationQueued"], 1);
    assert_eq!(snapshot["healthResuscitationQueueFull"], 1);
    assert_eq!(snapshot["healthResuscitationDisconnected"], 0);

    drop(receiver);
    handle.trigger(1, NetworkType::DATA_UDP4);
    assert_eq!(metrics.snapshot()["healthResuscitationDisconnected"], 1);
}

#[test]
fn health_scheduler_reports_one_runtime_for_many_groups() {
    let runtime_config = ResidentHealthRuntimeConfig::from_parallelism(64, 128, 8);
    let report = resident_health_scheduler_value(128, 8, runtime_config);
    assert_eq!(report["runtimeInstances"], 1);
    assert_eq!(report["osThreadCount"], 5);
    assert_eq!(report["maximumOsThreadCount"], 9);
    assert_eq!(report["runtime"]["workerThreads"], 4);
    assert_eq!(report["runtime"]["maximumBlockingThreads"], 4);
    assert_eq!(report["scheduledGroupCount"], 128);
    assert_eq!(report["scheduledTasks"], 128);
    assert_eq!(report["perGroupCandidateConcurrency"], 8);
    assert_eq!(
        report["resuscitationQueueDepth"],
        RESIDENT_HEALTH_RESUSCITATION_QUEUE_DEPTH
    );
}

#[test]
fn health_scheduler_retains_shared_group_arcs_and_stops_without_a_round() {
    let config = parse_test_config(
        r#"
        global {
            lan_interface: daerust0
        }
        node {
            node_a: 'socks5://127.0.0.1:1080#node_a'
            node_b: 'socks5://127.0.0.1:1081#node_b'
        }
        group {
            alpha {
                filter: name(node_a)
                policy: min
            }
            beta {
                filter: name(node_b)
                policy: min
            }
        }
        routing {
            domain(suffix:beta.invalid) -> beta
            fallback: alpha
        }
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let shared = plan::share_resident_proxy_groups(plan.proxies);
    let groups = shared.values().cloned().collect::<Vec<_>>();
    assert_eq!(groups.len(), 2);
    for group in &groups {
        assert!(shared.values().any(|shared| Arc::ptr_eq(shared, group)));
    }

    let stop = ResidentStopSignal::shared();
    stop.store(true, Ordering::Relaxed);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (_handle, receiver) = resident_health_resuscitation_channel(Arc::clone(&metrics));
    resident_health_scheduler_loop(
        groups,
        shared,
        receiver,
        stop,
        std::env::temp_dir().join("daed-health-scheduler-test-events.jsonl"),
        Arc::new(Mutex::new(())),
        Arc::clone(&metrics),
        2,
        ResidentHealthRuntimeConfig::from_parallelism(1, 2, 2),
    );
    assert_eq!(metrics.snapshot()["healthRoundsStartedTotal"], 0);
    assert_eq!(metrics.snapshot()["healthRoundsActive"], 0);
}

#[tokio::test(flavor = "current_thread")]
async fn shared_health_schedule_runs_one_zero_interval_round_and_updates_selector_state() {
    let closed_port = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let config = parse_test_config(&format!(
        r#"
        global {{
            lan_interface: daerust0
            check_interval: 0s
            resident_tcp_probe_timeout_ms: 100
            tcp_check_url: 'http://127.0.0.1:{closed_port}/'
            udp_check_dns: '127.0.0.1:{closed_port}'
        }}
        node {{
            node_a: 'socks5://127.0.0.1:{closed_port}#node_a'
        }}
        group {{
            proxy {{
                filter: name(node_a)
                policy: min
            }}
        }}
        routing {{
            fallback: proxy
        }}
        "#
    ));
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let shared = plan::share_resident_proxy_groups(plan.proxies);
    let group = Arc::clone(shared.values().next().unwrap());
    let stop = ResidentStopSignal::shared();
    let (_stop_tx, stop_rx) = watch::channel(false);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());

    run_resident_health_group_schedule(
        Arc::clone(&group),
        stop,
        stop_rx,
        std::env::temp_dir().join("daed-health-scheduler-round-test-events.jsonl"),
        Arc::new(Mutex::new(())),
        Arc::clone(&metrics),
        1,
    )
    .await;

    assert!(
        group
            .latency_snapshots()
            .iter()
            .any(|snapshot| snapshot.checked_at_unix > 0)
    );
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["healthRoundsStartedTotal"], 1);
    assert_eq!(snapshot["healthRoundsCompletedTotal"], 1);
    assert_eq!(snapshot["healthRoundsCancelledTotal"], 0);
    assert_eq!(snapshot["healthRoundsActive"], 0);
}

#[tokio::test(flavor = "current_thread")]
async fn udp_resuscitation_runs_on_the_shared_health_runtime() {
    let closed_port = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let config = parse_test_config(&format!(
        r#"
        global {{
            lan_interface: daerust0
            resident_tcp_probe_timeout_ms: 100
            tcp_check_url: 'http://127.0.0.1:{closed_port}/'
            udp_check_dns: '127.0.0.1:{closed_port}'
        }}
        node {{
            node_a: 'socks5://127.0.0.1:{closed_port}#node_a'
        }}
        group {{
            proxy {{
                filter: name(node_a)
                policy: min
            }}
        }}
        routing {{
            fallback: proxy
        }}
        "#
    ));
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let shared = plan::share_resident_proxy_groups(plan.proxies);
    let outbound = *shared.keys().next().unwrap();
    let stop = ResidentStopSignal::shared();
    let (stop_tx, stop_rx) = watch::channel(false);
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let (handle, receiver) = resident_health_resuscitation_channel(Arc::clone(&metrics));
    let dispatcher = tokio::spawn(run_resident_health_resuscitation_dispatcher(
        shared,
        receiver,
        Arc::clone(&stop),
        stop_rx,
        Arc::clone(&metrics),
        1,
    ));

    handle.trigger(outbound, NetworkType::DATA_UDP4);
    tokio::time::timeout(Duration::from_secs(2), async {
        while metrics.snapshot()["healthRoundsCompletedTotal"] != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.store(true, Ordering::Relaxed);
    let _ = stop_tx.send(true);
    dispatcher.await.unwrap();

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot["healthResuscitationQueued"], 1);
    assert_eq!(snapshot["healthResuscitationQueueFull"], 0);
    assert_eq!(snapshot["healthRoundsStartedTotal"], 1);
    assert_eq!(snapshot["healthRoundsCompletedTotal"], 1);
    assert_eq!(snapshot["healthRoundsActive"], 0);
}

#[test]
fn production_health_path_has_no_per_group_thread_or_transient_round_runtime() {
    let workers = include_str!("../workers.rs");
    let checks = include_str!("../health_checks.rs");
    assert!(!workers.contains("health-check-loop"));
    assert!(!workers.contains("for health_group in"));
    assert!(workers.contains("health-check-scheduler"));
    assert!(!checks.contains("build_transient_probe_runtime(\"resident group health probe\")"));
}

fn parse_test_config(input: &str) -> Config {
    let sections = dae_config::parser::parse_config(input).unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}
