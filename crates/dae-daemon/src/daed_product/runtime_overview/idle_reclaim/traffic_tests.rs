use super::*;

#[test]
fn idle_reclaim_traffic_rate_uses_counter_delta_not_cumulative_total() {
    let previous_at = Instant::now();
    let previous = AllocatorIdleTrafficSample {
        upload_total_counter: 1_000_000,
        download_total_counter: 2_000_000,
        packet_total_counter: 100,
        request_total_counter: 200,
        queue_depth: 0,
        inflight_work: 0,
        udp_inflight_work: 0,
        active_tcp: 7,
        active_udp: 0,
        observed_at: previous_at,
    };
    let observation = AllocatorIdleObservation {
        active_tcp: 8,
        active_udp: 0,
        upload_total_counter: 1_010_000,
        download_total_counter: 2_030_000,
        packet_total_counter: 120,
        request_total_counter: 240,
        queue_depth: 0,
        inflight_work: 0,
        udp_inflight_work: 0,
    };

    let rate = idle_reclaim_traffic_rate_from_samples(
        previous,
        previous_at + Duration::from_secs(2),
        observation,
    );

    let rate = rate.unwrap();
    assert_eq!(rate.bytes_per_second, 20_000);
    assert_eq!(rate.packets_per_second, 10);
    assert_eq!(rate.requests_per_second, 20);
    assert!(rate.active_count_growing);
    assert_eq!(rate.window, Duration::from_secs(2));
}

#[test]
fn idle_reclaim_activity_detects_small_packet_qps_and_growing_queues() {
    let observed_at = Instant::now();
    let previous = AllocatorIdleTrafficSample {
        upload_total_counter: 1_000,
        download_total_counter: 2_000,
        packet_total_counter: 10,
        request_total_counter: 20,
        queue_depth: 0,
        inflight_work: 1,
        udp_inflight_work: 0,
        active_tcp: 4,
        active_udp: 2,
        observed_at,
    };
    let observation = AllocatorIdleObservation {
        active_tcp: 4,
        active_udp: 2,
        upload_total_counter: 1_100,
        download_total_counter: 2_100,
        packet_total_counter: 210,
        request_total_counter: 220,
        queue_depth: 3,
        inflight_work: 2,
        udp_inflight_work: 0,
    };

    let rate = idle_reclaim_traffic_rate_from_samples(
        previous,
        observed_at + Duration::from_secs(1),
        observation,
    )
    .unwrap();

    assert_eq!(rate.bytes_per_second, 200);
    assert_eq!(rate.packets_per_second, 200);
    assert_eq!(rate.requests_per_second, 200);
    assert!(rate.queue_growing);
    assert!(rate.inflight_growing);
    assert!(!rate.active_count_growing);
}

#[test]
fn idle_reclaim_traffic_rate_warms_up_after_counter_reset() {
    let previous_at = Instant::now();
    let previous = AllocatorIdleTrafficSample {
        upload_total_counter: 1_000_000,
        download_total_counter: 2_000_000,
        packet_total_counter: 1_000,
        request_total_counter: 2_000,
        queue_depth: 0,
        inflight_work: 0,
        udp_inflight_work: 0,
        active_tcp: 0,
        active_udp: 0,
        observed_at: previous_at,
    };
    let observation = AllocatorIdleObservation {
        active_tcp: 0,
        active_udp: 0,
        upload_total_counter: 100,
        download_total_counter: 200,
        packet_total_counter: 100,
        request_total_counter: 200,
        queue_depth: 0,
        inflight_work: 0,
        udp_inflight_work: 0,
    };

    assert_eq!(
        idle_reclaim_traffic_rate_from_samples(
            previous,
            previous_at + Duration::from_secs(1),
            observation
        ),
        None
    );
}

#[test]
fn idle_reclaim_counter_reset_clears_the_previous_low_traffic_window() {
    let previous_at = Instant::now();
    let mut state = default_idle_reclaim_state();
    state.last_sample = Some(AllocatorIdleTrafficSample {
        upload_total_counter: 1_000_000,
        download_total_counter: 2_000_000,
        packet_total_counter: 1_000,
        request_total_counter: 2_000,
        queue_depth: 0,
        inflight_work: 0,
        udp_inflight_work: 0,
        active_tcp: 0,
        active_udp: 0,
        observed_at: previous_at,
    });
    state.low_traffic_since = Some(previous_at - Duration::from_secs(300));

    let rate = idle_reclaim_traffic_rate_from_state(
        &mut state,
        previous_at + Duration::from_secs(60),
        AllocatorIdleObservation {
            active_tcp: 0,
            active_udp: 0,
            upload_total_counter: 100,
            download_total_counter: 200,
            packet_total_counter: 100,
            request_total_counter: 200,
            queue_depth: 0,
            inflight_work: 0,
            udp_inflight_work: 0,
        },
    );

    assert_eq!(rate, None);
    assert_eq!(state.low_traffic_since, None);
}

#[test]
fn idle_reclaim_traffic_rate_warms_up_after_clock_order_reset() {
    let previous_at = Instant::now();
    let previous = AllocatorIdleTrafficSample {
        upload_total_counter: 1_000_000,
        download_total_counter: 2_000_000,
        packet_total_counter: 1_000,
        request_total_counter: 2_000,
        queue_depth: 0,
        inflight_work: 0,
        udp_inflight_work: 0,
        active_tcp: 0,
        active_udp: 0,
        observed_at: previous_at + Duration::from_secs(10),
    };
    let observation = AllocatorIdleObservation {
        active_tcp: 0,
        active_udp: 0,
        upload_total_counter: 1_000_100,
        download_total_counter: 2_000_200,
        packet_total_counter: 1_001,
        request_total_counter: 2_001,
        queue_depth: 0,
        inflight_work: 0,
        udp_inflight_work: 0,
    };

    assert_eq!(
        idle_reclaim_traffic_rate_from_samples(previous, previous_at, observation),
        None
    );
}

#[test]
fn idle_reclaim_wait_remaining_is_saturating() {
    let now = Instant::now();
    let min_interval = Duration::from_secs(300);

    assert_eq!(
        idle_reclaim_wait_remaining_since(now, now - Duration::from_secs(120), min_interval,),
        Some(Duration::from_secs(180))
    );
    assert_eq!(
        idle_reclaim_wait_remaining_since(now, now - Duration::from_secs(300), min_interval,),
        None
    );
    assert_eq!(
        idle_reclaim_wait_remaining_since(now, now - Duration::from_secs(360), min_interval,),
        None
    );
    assert_eq!(
        idle_reclaim_wait_remaining_since(now, now + Duration::from_secs(30), min_interval,),
        Some(min_interval)
    );
}

#[test]
fn deferred_reclaim_waits_for_one_bounded_settle_window() {
    let started_at = Instant::now();
    let mut deadline = None;

    assert!(!deferred_reclaim_evaluation_due(
        &mut deadline,
        started_at,
        true,
    ));
    let first_deadline = deadline.unwrap();
    assert_eq!(
        first_deadline,
        started_at + ALLOCATOR_IDLE_RECLAIM_DEFERRED_SETTLE_INTERVAL
    );
    assert!(!deferred_reclaim_evaluation_due(
        &mut deadline,
        started_at + Duration::from_secs(2),
        true,
    ));
    assert_eq!(deadline, Some(first_deadline));
    assert!(deferred_reclaim_evaluation_due(
        &mut deadline,
        first_deadline,
        true,
    ));
    assert!(!deferred_reclaim_evaluation_due(
        &mut deadline,
        first_deadline,
        false,
    ));
    assert_eq!(deadline, None);
}

#[test]
fn publication_reclaim_requires_a_complete_worker_cache_flush() {
    assert!(allocator_publication_reclaim_satisfied(
        false,
        Some("partial")
    ));
    assert!(allocator_publication_reclaim_satisfied(true, Some("pass")));
    assert!(!allocator_publication_reclaim_satisfied(
        true,
        Some("partial")
    ));
    assert!(!allocator_publication_reclaim_satisfied(true, None));
}

#[test]
fn low_traffic_window_requires_configured_duration() {
    let started_at = Instant::now();
    let rate = AllocatorIdleTrafficRate {
        bytes_per_second: 16,
        packets_per_second: 0,
        requests_per_second: 0,
        queue_depth: 0,
        queue_growing: false,
        inflight_work: 0,
        udp_inflight_work: 0,
        inflight_growing: false,
        active_count_growing: false,
        window: Duration::from_secs(60),
        window_started_at: started_at,
    };
    let mut low_since = None;

    let warming = idle_reclaim_low_traffic_window_from_since(
        &mut low_since,
        started_at + Duration::from_secs(120),
        rate,
        Duration::from_secs(300),
    );
    let ready = idle_reclaim_low_traffic_window_from_since(
        &mut low_since,
        started_at + Duration::from_secs(300),
        rate,
        Duration::from_secs(300),
    );

    assert_eq!(warming.elapsed, Duration::from_secs(120));
    assert!(!warming.ready);
    assert_eq!(ready.elapsed, Duration::from_secs(300));
    assert!(ready.ready);
}

#[test]
fn low_traffic_window_resets_future_since_without_panicking() {
    let now = Instant::now();
    let rate = AllocatorIdleTrafficRate {
        bytes_per_second: 0,
        packets_per_second: 0,
        requests_per_second: 0,
        queue_depth: 0,
        queue_growing: false,
        inflight_work: 0,
        udp_inflight_work: 0,
        inflight_growing: false,
        active_count_growing: false,
        window: Duration::from_secs(60),
        window_started_at: now - Duration::from_secs(60),
    };
    let mut low_since = Some(now + Duration::from_secs(30));

    let warming = idle_reclaim_low_traffic_window_from_since(
        &mut low_since,
        now,
        rate,
        Duration::from_secs(300),
    );

    assert_eq!(low_since, Some(rate.window_started_at));
    assert_eq!(warming.elapsed, Duration::from_secs(60));
    assert!(!warming.ready);
}
