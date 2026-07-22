use super::*;

#[test]
fn fallback_view_uses_typed_runtime_traffic_counters() {
    let view = fallback_runtime_sample_view(
        Some(ResidentTrafficCounters {
            upload_total: 101,
            download_total: 202,
            active_tcp_connections: 3,
            active_udp_sessions: 4,
        }),
        60,
        10,
    );

    assert_eq!(view.sample_count, 0);
    assert_eq!(view.traffic.upload_total, 101);
    assert_eq!(view.traffic.download_total, 202);
    assert_eq!(view.traffic.upload_rate, 0);
    assert_eq!(view.traffic.download_rate, 0);
    assert_eq!(view.traffic.active_connections, 3);
    assert_eq!(view.traffic.udp_sessions, 4);
    assert_eq!(view.traffic.samples.len(), 1);
}

#[test]
fn reader_windows_do_not_mutate_shared_history() {
    let config = ProductRuntimeSamplerConfig::product_default();
    let mut state = ProductRuntimeSamplerState::default();
    for index in 0..20_u64 {
        state.record(
            RuntimeTrafficObservation {
                timestamp: 1_000 + index,
                upload_total: index * 10,
                download_total: index * 20,
                upload_rate: index,
                download_rate: index * 2,
                active_connections: index,
                udp_sessions: index / 2,
            },
            false,
            None,
            None,
            Value::Null,
            config,
        );
    }
    let stored = state.history_len();
    let narrow = state.view(3_600, 2);
    let broad = state.view(3_600, 20);

    assert_eq!(narrow.traffic.samples.len(), 2);
    assert_eq!(broad.traffic.samples.len(), 20);
    assert_eq!(state.history_len(), stored);
    assert_eq!(narrow.sample_count, broad.sample_count);
}

#[test]
fn downsampling_keeps_window_endpoints_without_truncating_storage() {
    let mut history = VecDeque::new();
    for index in 0..10_u64 {
        history.push_back(RuntimeTrafficRateSample {
            timestamp: 10_000 + index,
            upload_rate: index,
            download_rate: index * 2,
        });
    }
    let stats = runtime_traffic_stats_from_history(
        RuntimeTrafficObservation {
            timestamp: 10_009,
            ..RuntimeTrafficObservation::default()
        },
        &history,
        60,
        3,
    );

    assert_eq!(stats.samples.len(), 3);
    assert_eq!(stats.samples[0]["timestamp"], json!(iso8601_utc(10_000)));
    assert_eq!(stats.samples[2]["timestamp"], json!(iso8601_utc(10_009)));
    assert_eq!(history.len(), 10);
}

#[test]
fn counter_reset_clears_only_sampler_owned_history() {
    let config = ProductRuntimeSamplerConfig::for_test();
    let mut state = ProductRuntimeSamplerState::default();
    state.record(
        RuntimeTrafficObservation {
            timestamp: 100,
            upload_total: 100,
            download_total: 100,
            ..RuntimeTrafficObservation::default()
        },
        false,
        None,
        None,
        Value::Null,
        config,
    );
    state.record(
        RuntimeTrafficObservation {
            timestamp: 101,
            upload_total: 1,
            download_total: 1,
            ..RuntimeTrafficObservation::default()
        },
        true,
        None,
        None,
        Value::Null,
        config,
    );

    assert_eq!(state.history_len(), 1);
    assert_eq!(state.view(60, 10).traffic.upload_total, 1);
}

#[test]
fn sampler_history_obeys_internal_capacity_independent_of_readers() {
    let mut config = ProductRuntimeSamplerConfig::product_default();
    config.history_capacity = 5;
    let mut state = ProductRuntimeSamplerState::default();
    for timestamp in 1_000..1_010_u64 {
        state.record(
            RuntimeTrafficObservation {
                timestamp,
                upload_total: timestamp,
                download_total: timestamp,
                ..RuntimeTrafficObservation::default()
            },
            false,
            None,
            None,
            Value::Null,
            config,
        );
    }

    assert_eq!(state.history_len(), 5);
    assert_eq!(state.view(3_600, 1_000).traffic.samples.len(), 5);
}

#[cfg(target_os = "linux")]
#[test]
fn sampler_runs_on_fixed_cadence_and_api_reads_do_not_sample() {
    let baseline_threads = named_sampler_threads();
    let sampler = ProductRuntimeSampler::start_with_config(
        std::sync::Weak::<ProductRuntimeManager>::new(),
        ProductRuntimeSamplerConfig::for_test(),
    )
    .unwrap();
    wait_until(Duration::from_secs(1), || {
        named_sampler_threads() == baseline_threads + 1
    });

    let initial = sampler.view(60, 100).sample_count;
    for max_points in [1, 2, 10, 100] {
        let view = sampler.view(60, max_points);
        assert_eq!(view.sample_count, initial);
    }
    wait_until(Duration::from_secs(1), || {
        sampler.view(60, 100).sample_count >= initial.saturating_add(2)
    });
    let snapshot = sampler.snapshot();
    assert!(snapshot["historyLength"].as_u64().unwrap_or(0) > 0);
    assert_eq!(snapshot["processReadFailureTotal"], json!(0));

    drop(sampler);
    wait_until(Duration::from_secs(1), || {
        named_sampler_threads() == baseline_threads
    });
}

#[cfg(target_os = "linux")]
fn named_sampler_threads() -> usize {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_to_string(entry.path().join("comm")).ok())
        .filter(|name| name.trim() == "daed-metrics-rt")
        .count()
}

#[cfg(target_os = "linux")]
fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(predicate(), "condition did not become true before timeout");
}
