use super::*;
use crate::allocator::{
    allocator_request_control_plane_reclaim, allocator_reset_reclaim_requests_for_test,
};
use dae_product_control::runtime::RuntimeTrafficRead;

// The release gate runs daemon tests serially because allocator state is process-wide.
struct ReclaimFixture;

impl ReclaimFixture {
    fn new() -> Self {
        allocator_reset_reclaim_requests_for_test();
        *ALLOCATOR_IDLE_RECLAIM_STATE
            .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
            .lock()
            .unwrap() = default_idle_reclaim_state();
        warm_traffic();
        Self
    }
}

impl Drop for ReclaimFixture {
    fn drop(&mut self) {
        allocator_reset_reclaim_requests_for_test();
        *ALLOCATOR_IDLE_RECLAIM_STATE.get().unwrap().lock().unwrap() = default_idle_reclaim_state();
    }
}

fn policy(enabled: bool) -> AllocatorIdleReclaimPolicy {
    let mut policy = AllocatorIdleReclaimPolicy::from_config(None);
    policy.enabled = enabled;
    // Explicit lifecycle requests must still run when allocator slack is below
    // the configured threshold (including freed memory in linked C libraries).
    policy.pressure_threshold_bytes = u64::MAX;
    policy.sources.pressure_threshold_bytes = "config";
    policy
}

fn stopped() -> Option<AllocatorIdleObservation> {
    idle_reclaim_observation_from_read(RuntimeTrafficRead::runtime_stopped(1))
}

fn warm_traffic() {
    let _ = idle_reclaim_traffic_rate(
        Instant::now() - Duration::from_secs(120),
        stopped().unwrap(),
    );
}

#[test]
fn startup_reclaim_runs_before_traffic_samples_despite_background_work_and_cooldown() {
    for enabled in [true, false] {
        let _fixture = ReclaimFixture::new();
        {
            let mut state = ALLOCATOR_IDLE_RECLAIM_STATE.get().unwrap().lock().unwrap();
            state.last_sample = None;
            state.last_attempt = Some(Instant::now());
            state.low_yield_streak = 3;
            state.heavy_task_quiet_since = Some(Instant::now());
        }
        let _busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::GroupHealth);
        allocator_request_reclaim_for_publication(AllocatorReclaimReason::StartupControlBuilt, 42);
        let report = evaluate_allocator_idle_reclaim_with_observers(
            policy(enabled),
            true,
            || panic!("startup reclaim must not depend on traffic telemetry"),
            CgroupReclaimPressure::default,
        );
        assert_eq!(report["status"], "reclaimed", "{report}");
        assert_eq!(report["reason"], "startup_control_built");
        assert_eq!(report["scope"], "global");
        assert!(!allocator_pending_reclaim_requests());
    }
}

#[test]
fn reload_reclaim_still_waits_for_background_work() {
    let _fixture = ReclaimFixture::new();
    let _busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::GroupHealth);
    allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 42);
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["reason"], "reclaim_busy_lease_active");
    assert!(allocator_pending_reclaim_requests());
}

#[cfg(feature = "allocator-jemalloc")]
#[test]
fn startup_reclaim_retries_publication_after_a_partial_worker_flush() {
    let _fixture = ReclaimFixture::new();
    let (ready, wait_ready) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        let _worker = crate::allocator::allocator_register_reclaim_worker(
            crate::allocator::AllocatorWorkerKind::ControlAux,
        );
        ready.send(()).unwrap();
        let _ = wait_release.recv();
    });
    wait_ready.recv_timeout(Duration::from_secs(5)).unwrap();
    allocator_request_reclaim_for_publication(AllocatorReclaimReason::StartupControlBuilt, 42);
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        || None,
        CgroupReclaimPressure::default,
    );
    drop(release);
    worker.join().unwrap();
    assert_eq!(report["reclaim"]["status"], "partial", "{report}");
    assert_eq!(report["status"], "partial_retry_pending", "{report}");
    assert!(allocator_pending_reclaim_requests());
    let retry = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        || None,
        CgroupReclaimPressure::default,
    );
    assert_eq!(retry["status"], "reclaimed", "{retry}");
    assert!(!allocator_pending_reclaim_requests());
}

#[test]
fn disabled_idle_reclaim_preserves_unadmitted_requests_and_executes_explicit_work() {
    let _fixture = ReclaimFixture::new();
    allocator_request_reclaim(AllocatorReclaimReason::GeodataUpdate);
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(false),
        false,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["reason"], "disabled");
    assert!(allocator_pending_reclaim_requests());

    warm_traffic();
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(false),
        true,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["status"], "reclaimed", "{report}");
    assert_eq!(report["reason"], "geodata_update");
    assert!(!allocator_pending_reclaim_requests());
}

#[test]
fn stopped_runtime_reclaim_drains_stop_and_merged_control_plane_requests() {
    let _fixture = ReclaimFixture::new();
    allocator_request_reclaim(AllocatorReclaimReason::StopRuntime);
    allocator_request_control_plane_reclaim();
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["status"], "reclaimed", "{report}");
    assert_eq!(report["reclaim"]["scope"], "global");
    assert_eq!(report["deferred"]["requestCount"], 2);
    assert!(!allocator_pending_reclaim_requests());
}

#[test]
fn unavailable_runtime_reclaim_keeps_requests_for_a_later_observation() {
    let _fixture = ReclaimFixture::new();
    allocator_request_reclaim(AllocatorReclaimReason::StopRuntime);
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        || {
            idle_reclaim_observation_from_read(RuntimeTrafficRead {
                availability: RuntimeTrafficAvailability::TemporarilyUnavailable,
                ..RuntimeTrafficRead::runtime_stopped(1)
            })
        },
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["reason"], "runtime_metrics_unavailable");
    assert!(allocator_pending_reclaim_requests());
    warm_traffic();
    let retry = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(retry["status"], "reclaimed", "{retry}");
    assert!(!allocator_pending_reclaim_requests());
}

#[test]
fn emergency_reclaim_ignores_low_yield_backoff_without_memory_high_events() {
    let _fixture = ReclaimFixture::new();
    {
        let mut state = ALLOCATOR_IDLE_RECLAIM_STATE.get().unwrap().lock().unwrap();
        state.last_attempt = Some(Instant::now());
        state.low_yield_streak = 3;
    }
    allocator_request_reclaim(AllocatorReclaimReason::StopRuntime);
    let report =
        evaluate_allocator_idle_reclaim_with_observers(policy(true), true, stopped, || {
            cgroup_reclaim_pressure_from_snapshot(
                &json!({
                    "available": true,
                    "currentBytes": "950",
                    "maxBytes": "1000",
                    "highBytes": null,
                    "events": {"high": 0},
                }),
                true,
            )
        });
    assert_eq!(report["cgroupPressure"]["level"], "emergency");
    assert_eq!(report["cgroupPressure"]["highEventIncreased"], false);
    assert_eq!(report["status"], "reclaimed", "{report}");
    assert!(!allocator_pending_reclaim_requests());
}

#[test]
fn normal_reclaim_keeps_low_yield_backoff_and_the_pending_batch() {
    let _fixture = ReclaimFixture::new();
    {
        let mut state = ALLOCATOR_IDLE_RECLAIM_STATE.get().unwrap().lock().unwrap();
        state.last_attempt = Some(Instant::now());
        state.low_yield_streak = 3;
    }
    allocator_request_reclaim(AllocatorReclaimReason::StopRuntime);
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["reason"], "cooldown");
    assert_eq!(report["effectiveMinIntervalMillis"], "1200000");
    assert!(allocator_pending_reclaim_requests());
}

#[cfg(feature = "allocator-jemalloc")]
#[test]
fn scoped_reclaim_does_not_consume_a_global_request_arriving_during_evaluation() {
    let _fixture = ReclaimFixture::new();
    allocator_request_control_plane_reclaim();
    let report =
        evaluate_allocator_idle_reclaim_with_observers(policy(false), true, stopped, || {
            allocator_request_reclaim(AllocatorReclaimReason::StopRuntime);
            CgroupReclaimPressure::default()
        });
    assert_eq!(report["status"], "reclaimed", "{report}");
    assert_eq!(report["scope"], "control-plane");
    let remaining = allocator_take_reclaim_requests();
    assert!(remaining.is_only(AllocatorReclaimReason::StopRuntime));
    assert_eq!(remaining.scope(), AllocatorReclaimScope::Global);
}

#[test]
fn reclaim_batch_is_restored_when_an_observer_panics() {
    let _fixture = ReclaimFixture::new();
    allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 42);
    let result = std::panic::catch_unwind(|| {
        evaluate_allocator_idle_reclaim_with_observers(
            policy(true),
            true,
            || panic!("simulated telemetry failure"),
            CgroupReclaimPressure::default,
        )
    });
    assert!(result.is_err());
    let restored = allocator_take_reclaim_requests();
    assert_eq!(restored.publication_ids(), &[42]);
    assert!(restored.has_publication());
    allocator_restore_reclaim_requests(&restored);
}

#[cfg(all(
    not(feature = "allocator-jemalloc"),
    target_os = "linux",
    target_env = "gnu"
))]
#[test]
fn system_control_plane_reclaim_reaches_trim_without_jemalloc_statistics() {
    let _fixture = ReclaimFixture::new();
    assert!(allocator_stats_snapshot().is_none());
    allocator_request_control_plane_reclaim();
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["status"], "reclaimed", "{report}");
    assert_eq!(report["reclaim"]["detail"]["operation"], "malloc_trim");
    assert!(!allocator_pending_reclaim_requests());
}

#[cfg(not(feature = "allocator-jemalloc"))]
#[test]
fn system_reclaim_opt_out_finishes_requests_without_recording_a_purge() {
    const CHILD: &str = "DAENEXT_TEST_SYSTEM_RECLAIM_OPT_OUT";
    if std::env::var_os(CHILD).is_none() {
        // Set the opt-out before process start; do not mutate another test's
        // environment while runtime threads may be reading it.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daed_product::runtime_overview::idle_reclaim::coordinator_tests::system_reclaim_opt_out_finishes_requests_without_recording_a_purge",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env("ALLOCATOR_SYSTEM_TRIM", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let _fixture = ReclaimFixture::new();
    allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 42);
    let report = evaluate_allocator_idle_reclaim_with_observers(
        policy(true),
        true,
        stopped,
        CgroupReclaimPressure::default,
    );
    assert_eq!(report["status"], "skipped", "{report}");
    assert_eq!(
        report["reclaim"]["detail"]["operation"],
        "system_allocator_noop"
    );
    assert!(!allocator_pending_reclaim_requests());
    let retry =
        allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 42);
    assert_eq!(retry["status"], "requested");
}

#[test]
fn downstream_packets_and_stable_udp_backlog_defer_ordinary_reclaim() {
    for scenario in 0..3 {
        let _fixture = ReclaimFixture::new();
        let mut observation = stopped().unwrap();
        observation.active_udp = 1;
        match scenario {
            0 => observation.queue_depth = 1,
            1 => {
                observation.udp_inflight_work = 1;
                observation.inflight_work = 1;
            }
            _ => {}
        }
        let _ = idle_reclaim_traffic_rate(Instant::now() - Duration::from_secs(120), observation);
        if scenario == 2 {
            // High packet rate with zero payload bytes must still be hot.
            observation.packet_total_counter = 120 * 1024;
        }
        allocator_request_reclaim(AllocatorReclaimReason::RetiredGenerationReleased);
        let report = evaluate_allocator_idle_reclaim_with_observers(
            policy(true),
            true,
            || Some(observation),
            CgroupReclaimPressure::default,
        );
        assert_eq!(
            report["reason"], "traffic_active",
            "scenario {scenario}: {report}"
        );
        assert!(allocator_pending_reclaim_requests());
    }
}
