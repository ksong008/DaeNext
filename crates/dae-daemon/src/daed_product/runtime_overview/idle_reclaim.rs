use super::*;
use crate::allocator::{
    AllocatorReclaimRequestBatch, allocator_pending_publication_reclaim,
    allocator_pending_reclaim_is_only, allocator_pending_reclaim_requests,
    allocator_take_reclaim_requests,
};

#[path = "idle_reclaim/adaptive.rs"]
mod adaptive;
use self::adaptive::*;
#[path = "idle_reclaim/activity.rs"]
mod activity;
use self::activity::*;
#[path = "idle_reclaim/pressure.rs"]
mod pressure;
use self::pressure::*;

const ALLOCATOR_IDLE_RECLAIM_MONITOR_STACK_BYTES: usize = 256 * 1024;
const ALLOCATOR_IDLE_RECLAIM_MONITOR_WAKE_INTERVAL: Duration = Duration::from_secs(5);
const ALLOCATOR_IDLE_RECLAIM_DEFERRED_SETTLE_INTERVAL: Duration = Duration::from_secs(5);
const ALLOCATOR_IDLE_RECLAIM_DEFERRED_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const ALLOCATOR_IDLE_RECLAIM_HEAVY_TASK_QUIET: Duration = Duration::from_secs(10);
const ALLOCATOR_IDLE_RECLAIM_POST_BURST_QUIET: Duration = Duration::from_secs(30);
const ALLOCATOR_IDLE_RECLAIM_POST_BURST_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;
const ALLOCATOR_IDLE_RECLAIM_POST_BURST_THRESHOLD_PERCENT: u64 = 20;
const ALLOCATOR_IDLE_RECLAIM_POST_BURST_PRESSURE_BYTES: u64 = 4 * 1024 * 1024;
const ALLOCATOR_IDLE_RECLAIM_DYNAMIC_PRESSURE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const ALLOCATOR_IDLE_RECLAIM_ELEVATED_PRESSURE_MIN_BYTES: u64 = 2 * 1024 * 1024;
const ALLOCATOR_IDLE_RECLAIM_MAX_PACKET_QPS: u64 = 128;
const ALLOCATOR_IDLE_RECLAIM_MAX_REQUEST_QPS: u64 = 128;

#[derive(Clone, Copy, Debug)]
struct AllocatorIdleReclaimPolicy {
    enabled: bool,
    sample_interval: Duration,
    min_interval: Duration,
    low_traffic_duration: Duration,
    pressure_threshold_bytes: u64,
    max_traffic_rate_bytes_per_second: u64,
    pressure_capacity_bytes: Option<u64>,
    pressure_capacity_source: Option<&'static str>,
    sources: AllocatorIdleReclaimPolicySources,
}

#[derive(Clone, Copy, Debug)]
struct AllocatorIdleReclaimPolicySources {
    enabled: &'static str,
    sample_interval: &'static str,
    min_interval: &'static str,
    low_traffic_duration: &'static str,
    pressure_threshold_bytes: &'static str,
    max_traffic_rate_bytes_per_second: &'static str,
}

impl AllocatorIdleReclaimPolicy {
    fn from_config(config: Option<&Config>) -> Self {
        let global = config.map(|config| &config.global);
        let (enabled, enabled_source) = effective_bool(
            ALLOCATOR_IDLE_RECLAIM_ENABLED_ENV,
            global.and_then(|global| global.allocator_idle_reclaim_enabled),
            ALLOCATOR_IDLE_RECLAIM_ENABLED_DEFAULT,
        );
        let (sample_interval_seconds, sample_interval_source) = effective_u64(
            ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_ENV,
            global.and_then(|global| {
                global
                    .allocator_idle_reclaim_sample_interval
                    .map(|duration| config_duration_seconds_from_nanos(duration.as_nanos()))
            }),
            ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_DEFAULT,
            ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_MIN,
            ALLOCATOR_IDLE_RECLAIM_SAMPLE_INTERVAL_SECONDS_MAX,
        );
        let (min_interval_seconds, min_interval_source) = effective_u64(
            ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_ENV,
            global.and_then(|global| {
                global
                    .allocator_idle_reclaim_min_interval
                    .map(|duration| config_duration_seconds_from_nanos(duration.as_nanos()))
            }),
            ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_DEFAULT,
            ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_MIN,
            ALLOCATOR_IDLE_RECLAIM_MIN_INTERVAL_SECONDS_MAX,
        );
        let (low_traffic_seconds, low_traffic_source) = effective_u64(
            ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_ENV,
            global.and_then(|global| {
                global
                    .allocator_idle_reclaim_low_traffic_duration
                    .map(|duration| config_duration_seconds_from_nanos(duration.as_nanos()))
            }),
            ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_DEFAULT,
            ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_MIN,
            ALLOCATOR_IDLE_RECLAIM_LOW_TRAFFIC_SECONDS_MAX,
        );
        let (configured_pressure_threshold_bytes, configured_pressure_source) = effective_u64(
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_ENV,
            global.and_then(|global| global.allocator_idle_reclaim_pressure_threshold_bytes),
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT,
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN,
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MAX,
        );
        let pressure_capacity =
            crate::production_runtime_owner::effective_process_memory_capacity();
        let pressure_source = if configured_pressure_source == "default" {
            "application-live-working-set"
        } else {
            configured_pressure_source
        };
        let (max_traffic_rate_bytes_per_second, max_rate_source) = effective_u64(
            ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_ENV,
            global
                .and_then(|global| global.allocator_idle_reclaim_max_traffic_rate_bytes_per_second),
            ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_DEFAULT,
            0,
            ALLOCATOR_IDLE_RECLAIM_MAX_TRAFFIC_RATE_BYTES_PER_SECOND_MAX,
        );
        Self {
            enabled,
            sample_interval: Duration::from_secs(sample_interval_seconds),
            min_interval: Duration::from_secs(min_interval_seconds),
            low_traffic_duration: Duration::from_secs(low_traffic_seconds),
            pressure_threshold_bytes: configured_pressure_threshold_bytes,
            max_traffic_rate_bytes_per_second,
            pressure_capacity_bytes: pressure_capacity.map(|capacity| capacity.bytes()),
            pressure_capacity_source: pressure_capacity.map(|capacity| capacity.source()),
            sources: AllocatorIdleReclaimPolicySources {
                enabled: enabled_source,
                sample_interval: sample_interval_source,
                min_interval: min_interval_source,
                low_traffic_duration: low_traffic_source,
                pressure_threshold_bytes: pressure_source,
                max_traffic_rate_bytes_per_second: max_rate_source,
            },
        }
    }

    fn json(self) -> Value {
        json!({
            "enabled": self.enabled,
            "idleDetection": "traffic-rate-plus-busy-leases-and-allocator-state",
            "stateMachine": ["hot", "cooling", "cold", "pressure"],
            "sampleIntervalSeconds": self.sample_interval.as_secs(),
            "minIntervalSeconds": self.min_interval.as_secs(),
            "lowTrafficSeconds": self.low_traffic_duration.as_secs(),
            "pressureThresholdBytes": self.pressure_threshold_bytes.to_string(),
            "pressureCapacityBytes": self.pressure_capacity_bytes.map(|value| value.to_string()),
            "pressureCapacitySource": self.pressure_capacity_source,
            "pressureMetric": "maximum-of-arena-dirty-plus-muzzy-pages-and-worker-tcache",
            "retainedMetric": "diagnostic-virtual-address-space",
            "maxTrafficRateBytesPerSecond": self.max_traffic_rate_bytes_per_second.to_string(),
            "maxPacketQps": ALLOCATOR_IDLE_RECLAIM_MAX_PACKET_QPS,
            "maxRequestQps": ALLOCATOR_IDLE_RECLAIM_MAX_REQUEST_QPS,
            "sessionCountGate": false,
            "monitorFallbackWakeSeconds": ALLOCATOR_IDLE_RECLAIM_MONITOR_WAKE_INTERVAL.as_secs(),
            "heavyTaskQuietSeconds": ALLOCATOR_IDLE_RECLAIM_HEAVY_TASK_QUIET.as_secs(),
            "postBurstQuietSeconds": ALLOCATOR_IDLE_RECLAIM_POST_BURST_QUIET.as_secs(),
            "deferredSettleSeconds": ALLOCATOR_IDLE_RECLAIM_DEFERRED_SETTLE_INTERVAL.as_secs(),
            "sources": {
                "enabled": self.sources.enabled,
                "sampleIntervalSeconds": self.sources.sample_interval,
                "minIntervalSeconds": self.sources.min_interval,
                "lowTrafficSeconds": self.sources.low_traffic_duration,
                "pressureThresholdBytes": self.sources.pressure_threshold_bytes,
                "maxTrafficRateBytesPerSecond": self.sources.max_traffic_rate_bytes_per_second,
            },
        })
    }
}

#[derive(Clone, Debug)]
struct AllocatorIdleReclaimState {
    started: bool,
    last_attempt: Option<Instant>,
    last_sample: Option<AllocatorIdleTrafficSample>,
    low_traffic_since: Option<Instant>,
    low_yield_streak: u8,
    last_released_bytes: Option<u64>,
    last_reclaim_high_yield: bool,
    last_cgroup_high_events: Option<u64>,
    cgroup_high_event_latched: bool,
    previous_busy_count: u64,
    previous_busy_completion_count: u64,
    heavy_task_quiet_since: Option<Instant>,
    allocated_high_water: u64,
    post_burst_quiet_since: Option<Instant>,
    last_report: Value,
}

#[derive(Clone, Copy, Debug)]
struct AllocatorIdleTrafficSample {
    upload_total_counter: u64,
    download_total_counter: u64,
    packet_total_counter: u64,
    request_total_counter: u64,
    queue_depth: u64,
    inflight_work: u64,
    active_tcp: u64,
    active_udp: u64,
    observed_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct AllocatorIdleObservation {
    active_tcp: u64,
    active_udp: u64,
    upload_total_counter: u64,
    download_total_counter: u64,
    packet_total_counter: u64,
    request_total_counter: u64,
    queue_depth: u64,
    inflight_work: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocatorIdleTrafficRate {
    bytes_per_second: u64,
    packets_per_second: u64,
    requests_per_second: u64,
    queue_depth: u64,
    queue_growing: bool,
    inflight_work: u64,
    inflight_growing: bool,
    active_count_growing: bool,
    window: Duration,
    window_started_at: Instant,
}

impl AllocatorIdleTrafficRate {
    fn json(self) -> Value {
        json!({
            "bytesPerSecond": self.bytes_per_second.to_string(),
            "packetsPerSecond": self.packets_per_second,
            "requestsPerSecond": self.requests_per_second,
            "queueDepth": self.queue_depth,
            "queueGrowing": self.queue_growing,
            "inflightWork": self.inflight_work,
            "inflightGrowing": self.inflight_growing,
            "activeCountGrowing": self.active_count_growing,
            "windowMillis": self.window.as_millis().to_string(),
            "source": "resident_dataplane_typed_activity_delta",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocatorLowTrafficWindow {
    elapsed: Duration,
    ready: bool,
}

static ALLOCATOR_IDLE_RECLAIM_STATE: OnceLock<Mutex<AllocatorIdleReclaimState>> = OnceLock::new();
static ALLOCATOR_IDLE_RECLAIM_EVALUATION_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATOR_IDLE_RECLAIM_EXECUTED_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATOR_IDLE_RECLAIM_SKIPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATOR_IDLE_RECLAIM_MERGED_TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATOR_IDLE_RECLAIM_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);

struct AllocatorIdleReclaimStartedGuard;

impl Drop for AllocatorIdleReclaimStartedGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
            .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
            .lock()
        {
            state.started = false;
        }
    }
}

pub(crate) struct ProductAllocatorIdleReclaimMonitor {
    join: Option<thread::JoinHandle<()>>,
}

impl ProductAllocatorIdleReclaimMonitor {
    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| io::Error::other("allocator idle reclaim monitor panicked"))?;
        }
        Ok(())
    }
}

impl Drop for ProductAllocatorIdleReclaimMonitor {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn spawn_allocator_idle_reclaim_monitor(
    app: &Arc<AppState>,
) -> io::Result<Option<ProductAllocatorIdleReclaimMonitor>> {
    {
        let state_lock =
            ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
        let Ok(mut state) = state_lock.lock() else {
            return Ok(None);
        };
        if state.started {
            return Ok(None);
        }
        state.started = true;
    }

    let app = Arc::clone(app);
    let join = thread::Builder::new()
        .name("allocator-idle-reclaim".to_owned())
        .stack_size(ALLOCATOR_IDLE_RECLAIM_MONITOR_STACK_BYTES)
        .spawn(move || {
            let _started = AllocatorIdleReclaimStartedGuard;
            let mut next_periodic_evaluation = Instant::now();
            let mut next_deferred_evaluation = None;
            while !app.shutdown.is_requested() {
                let config = app.runtime.current_config();
                let policy = AllocatorIdleReclaimPolicy::from_config(config.as_deref());
                let now = Instant::now();
                let periodic_due = now >= next_periodic_evaluation;
                let deferred_due = deferred_reclaim_evaluation_due(
                    &mut next_deferred_evaluation,
                    now,
                    allocator_pending_reclaim_requests(),
                );
                if periodic_due || deferred_due {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        allocator_idle_reclaim_tick(&app, policy, deferred_due);
                    }))
                    .is_err()
                    {
                        record_idle_reclaim_tick_panic();
                    }
                    if periodic_due {
                        next_periodic_evaluation = now + policy.sample_interval;
                    }
                    if deferred_due {
                        next_deferred_evaluation = allocator_pending_reclaim_requests()
                            .then_some(now + ALLOCATOR_IDLE_RECLAIM_DEFERRED_RETRY_INTERVAL);
                    }
                }
                if app.shutdown.is_requested() {
                    break;
                }
                let wake_epoch = allocator_reclaim_request_wake_epoch();
                let now = Instant::now();
                let deferred_wait = next_deferred_evaluation
                    .map(|deadline| deadline.saturating_duration_since(now))
                    .unwrap_or(ALLOCATOR_IDLE_RECLAIM_MONITOR_WAKE_INTERVAL);
                allocator_wait_for_reclaim_request_since(
                    wake_epoch,
                    deferred_wait.min(ALLOCATOR_IDLE_RECLAIM_MONITOR_WAKE_INTERVAL),
                );
            }
        });
    let join = match join {
        Ok(join) => join,
        Err(err) => {
            if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
                .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
                .lock()
            {
                state.started = false;
            }
            return Err(err);
        }
    };
    Ok(Some(ProductAllocatorIdleReclaimMonitor {
        join: Some(join),
    }))
}

pub(crate) fn allocator_idle_reclaim_snapshot_json(app: &AppState) -> Value {
    let config = app.runtime.current_config();
    let policy = AllocatorIdleReclaimPolicy::from_config(config.as_deref());
    let last_report = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
        .ok()
        .map(|state| state.last_report.clone())
        .unwrap_or_else(|| json!({"status": "unavailable"}));
    json!({
        "policy": policy.json(),
        "evaluations": {
            "total": ALLOCATOR_IDLE_RECLAIM_EVALUATION_TOTAL.load(Ordering::Relaxed),
            "executed": ALLOCATOR_IDLE_RECLAIM_EXECUTED_TOTAL.load(Ordering::Relaxed),
            "skipped": ALLOCATOR_IDLE_RECLAIM_SKIPPED_TOTAL.load(Ordering::Relaxed),
            "merged": ALLOCATOR_IDLE_RECLAIM_MERGED_TOTAL.load(Ordering::Relaxed),
            "failed": ALLOCATOR_IDLE_RECLAIM_FAILED_TOTAL.load(Ordering::Relaxed),
        },
        "last": last_report,
    })
}

fn allocator_idle_reclaim_tick(
    app: &AppState,
    policy: AllocatorIdleReclaimPolicy,
    admit_deferred_requests: bool,
) {
    let report = evaluate_allocator_idle_reclaim(app, policy, admit_deferred_requests);
    record_idle_reclaim_evaluation(&report);
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.last_report = report;
    }
}

fn record_idle_reclaim_evaluation(report: &Value) {
    ALLOCATOR_IDLE_RECLAIM_EVALUATION_TOTAL.fetch_add(1, Ordering::Relaxed);
    match report.get("status").and_then(Value::as_str) {
        Some("reclaimed") => {
            ALLOCATOR_IDLE_RECLAIM_EXECUTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        Some("skipped") => {
            ALLOCATOR_IDLE_RECLAIM_SKIPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        Some("merged_pending" | "subsumed" | "partial_retry_pending") => {
            ALLOCATOR_IDLE_RECLAIM_MERGED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        Some("failed") | None => {
            ALLOCATOR_IDLE_RECLAIM_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        Some(_) => {}
    }
}

fn evaluate_allocator_idle_reclaim(
    app: &AppState,
    policy: AllocatorIdleReclaimPolicy,
    admit_deferred_requests: bool,
) -> Value {
    let deferred_waiting = allocator_pending_reclaim_requests();
    let deferred_pending = admit_deferred_requests && deferred_waiting;
    let publication_reclaim_pending = deferred_pending && allocator_pending_publication_reclaim();
    if !policy.enabled && !publication_reclaim_pending {
        reset_idle_reclaim_observation();
        clear_cgroup_reclaim_pressure_latch();
        let deferred = if admit_deferred_requests {
            let batch = allocator_take_reclaim_requests();
            if !batch.is_empty() {
                allocator_record_trailing_reclaim_evaluation();
            }
            batch
        } else {
            AllocatorReclaimRequestBatch::default()
        };
        return json!({"status": "skipped", "reason": "disabled", "deferred": deferred.json()});
    }

    let now = Instant::now();
    let retired_generation_release_only = deferred_pending
        && allocator_pending_reclaim_is_only(AllocatorReclaimReason::RetiredGenerationReleased);
    let cgroup_pressure = observe_cgroup_reclaim_pressure();
    let busy_count = allocator_reclaim_busy_count();
    let busy_completion_count = allocator_reclaim_busy_completion_count();
    let busy_quiet_required = if cgroup_pressure.level.is_urgent() {
        Duration::from_secs(5)
    } else {
        ALLOCATOR_IDLE_RECLAIM_HEAVY_TASK_QUIET
    };
    let busy_quiet =
        idle_reclaim_busy_quiet_window(now, busy_count, busy_completion_count, busy_quiet_required);
    if busy_count > 0 {
        reset_idle_reclaim_low_traffic_window();
        return json!({
            "status": "skipped",
            "state": "hot",
            "reason": "reclaim_busy_lease_active",
            "busyLeaseCount": busy_count,
            "cgroupPressure": cgroup_pressure.json(),
        });
    }
    if !busy_quiet.ready {
        return json!({
            "status": "skipped",
            "state": "cooling",
            "reason": "heavy_task_quiet_window",
            "busyLeaseCount": busy_count,
            "quietElapsedMillis": busy_quiet.elapsed.as_millis().to_string(),
            "quietRequiredMillis": busy_quiet_required.as_millis().to_string(),
            "cgroupPressure": cgroup_pressure.json(),
        });
    }
    if deferred_pending
        && allocator_pending_reclaim_scope() == Some(AllocatorReclaimScope::ControlPlane)
    {
        let deferred = allocator_take_reclaim_requests();
        allocator_record_trailing_reclaim_evaluation();
        let reclaim_reason = deferred
            .primary_reason()
            .unwrap_or(AllocatorReclaimReason::ControlPlaneIdle);
        let reclaim = allocator_reclaim_control_plane(reclaim_reason);
        let reclaim_status = reclaim.get("status").and_then(Value::as_str);
        let evaluation_status = match reclaim_status {
            Some("pass" | "partial") => "reclaimed",
            Some("subsumed") => "subsumed",
            _ => "failed",
        };
        if evaluation_status == "failed" {
            allocator_restore_reclaim_requests(&deferred);
        }
        return json!({
            "status": evaluation_status,
            "state": "cold",
            "reason": reclaim_reason.as_str(),
            "scope": AllocatorReclaimScope::ControlPlane.as_str(),
            "deferred": deferred.json(),
            "reclaim": reclaim,
            "cgroupPressure": cgroup_pressure.json(),
        });
    }
    let Some(observation) = idle_reclaim_observation(app) else {
        reset_idle_reclaim_observation();
        return json!({"status": "skipped", "reason": "runtime_metrics_unavailable"});
    };
    let Some(traffic_rate) = idle_reclaim_traffic_rate(now, observation) else {
        return json!({"status": "skipped", "reason": "traffic_sample_warming_up"});
    };
    let activity_hot = traffic_rate.bytes_per_second > policy.max_traffic_rate_bytes_per_second
        || traffic_rate.packets_per_second > ALLOCATOR_IDLE_RECLAIM_MAX_PACKET_QPS
        || traffic_rate.requests_per_second > ALLOCATOR_IDLE_RECLAIM_MAX_REQUEST_QPS
        || traffic_rate.queue_growing
        || traffic_rate.inflight_growing
        || traffic_rate.active_count_growing;
    if activity_hot && !cgroup_pressure.level.is_urgent() {
        reset_idle_reclaim_low_traffic_window();
        return json!({
            "status": "skipped",
            "state": "hot",
            "reason": "traffic_active",
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "packetRatePerSecond": traffic_rate.packets_per_second,
            "requestRatePerSecond": traffic_rate.requests_per_second,
            "queueDepth": traffic_rate.queue_depth,
            "queueGrowing": traffic_rate.queue_growing,
            "inflightWork": traffic_rate.inflight_work,
            "inflightGrowing": traffic_rate.inflight_growing,
            "activeCountGrowing": traffic_rate.active_count_growing,
            "trafficRateSource": "resident_dataplane_typed_activity_delta",
            "trafficRateWindowMillis": traffic_rate.window.as_millis().to_string(),
            "activity": traffic_rate.json(),
            "maxTrafficRateBytesPerSecond": policy.max_traffic_rate_bytes_per_second.to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
            "deferredReclaimPending": deferred_pending,
            "deferredReclaimWaiting": deferred_waiting,
            "cgroupPressure": cgroup_pressure.json(),
        });
    }
    let low_traffic =
        idle_reclaim_low_traffic_window(now, traffic_rate, policy.low_traffic_duration);
    // A pure retired-generation notification may be emitted by ordinary flow/session reaping
    // and therefore still observes the low-traffic window. If it is merged with a completed
    // reload (or any other explicit reclaim request), it must not suppress that request and
    // leave a publication-scoped purge pending indefinitely.
    let known_heavy_task_finished = deferred_pending && !retired_generation_release_only;
    if !known_heavy_task_finished && !cgroup_pressure.level.is_urgent() && !low_traffic.ready {
        return json!({
            "status": "skipped",
            "state": "cooling",
            "reason": "low_traffic_window_warming_up",
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "trafficRateWindowMillis": traffic_rate.window.as_millis().to_string(),
            "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
            "lowTrafficRequiredMillis": policy.low_traffic_duration.as_millis().to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
            "cgroupPressure": cgroup_pressure.json(),
            "activity": traffic_rate.json(),
        });
    }
    let adaptive_min_interval = idle_reclaim_effective_min_interval(
        policy.min_interval,
        policy.sources.min_interval == "default",
    );
    let effective_min_interval =
        if cgroup_pressure.level.is_emergency() && cgroup_pressure.high_event_increased {
            Duration::ZERO
        } else {
            adaptive_min_interval
        };
    if !publication_reclaim_pending
        && let Some(wait_remaining) = idle_reclaim_wait_remaining(now, effective_min_interval)
    {
        return json!({
            "status": "skipped",
            "reason": "cooldown",
            "waitRemainingMillis": wait_remaining.as_millis().to_string(),
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
            "deferredReclaimPending": deferred_pending,
            "deferredReclaimWaiting": deferred_waiting,
            "effectiveMinIntervalMillis": effective_min_interval.as_millis().to_string(),
            "cgroupPressure": cgroup_pressure.json(),
            "activity": traffic_rate.json(),
        });
    }

    let Some(stats) = allocator_stats_snapshot() else {
        return json!({"status": "skipped", "reason": "allocator_stats_unavailable"});
    };
    let page_pressure =
        allocator_reclaimable_page_bytes().unwrap_or_else(|| stats.idle_reclaim_pressure_bytes());
    let cache_pressure = stats.cache_reclaim_pressure_bytes();
    let pressure = page_pressure.max(cache_pressure);
    let (post_burst, post_burst_quiet) = idle_reclaim_post_burst_quiet_window(
        now,
        stats.allocated,
        ALLOCATOR_IDLE_RECLAIM_POST_BURST_QUIET,
    );
    if post_burst
        && !post_burst_quiet.ready
        && !cgroup_pressure.level.is_urgent()
        && !publication_reclaim_pending
    {
        return json!({
            "status": "skipped",
            "state": "cooling",
            "reason": "post_burst_quiet_window",
            "quietElapsedMillis": post_burst_quiet.elapsed.as_millis().to_string(),
            "quietRequiredMillis": ALLOCATOR_IDLE_RECLAIM_POST_BURST_QUIET.as_millis().to_string(),
            "allocatorApplicationLiveExcludingTcacheBytes": stats.application_live_excluding_tcache().to_string(),
            "allocatorRetainedBytes": stats.retained.to_string(),
            "cgroupPressure": cgroup_pressure.json(),
            "activity": traffic_rate.json(),
        });
    }
    let effective_pressure_threshold = idle_reclaim_pressure_threshold(
        policy.pressure_threshold_bytes,
        policy.sources.pressure_threshold_bytes,
        stats.application_live_excluding_tcache(),
        cgroup_pressure.level,
        post_burst,
    );
    if pressure < effective_pressure_threshold && !publication_reclaim_pending {
        let deferred = if deferred_pending {
            let batch = allocator_take_reclaim_requests();
            allocator_record_trailing_reclaim_evaluation();
            batch
        } else {
            AllocatorReclaimRequestBatch::default()
        };
        reset_idle_reclaim_allocated_high_water(stats.allocated);
        clear_cgroup_reclaim_pressure_latch();
        return json!({
            "status": "skipped",
            "state": if cgroup_pressure.level.is_elevated() { "pressure" } else { "cold" },
            "reason": "pressure_below_threshold",
            "pressureBytes": pressure.to_string(),
            "pressureMetric": "maximum-of-page-and-worker-cache-pressure",
            "pressureThresholdBytes": effective_pressure_threshold.to_string(),
            "allocatorReclaimablePageBytes": page_pressure.to_string(),
            "allocatorMergedTcacheBytes": cache_pressure.to_string(),
            "allocatorApplicationLiveExcludingTcacheBytes": stats.application_live_excluding_tcache().to_string(),
            "allocatorRetainedBytes": stats.retained.to_string(),
            "postBurst": post_burst,
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
            "deferred": deferred.json(),
            "effectiveMinIntervalMillis": effective_min_interval.as_millis().to_string(),
            "cgroupPressure": cgroup_pressure.json(),
            "activity": traffic_rate.json(),
        });
    }

    let deferred = if deferred_pending {
        let batch = allocator_take_reclaim_requests();
        allocator_record_trailing_reclaim_evaluation();
        batch
    } else {
        AllocatorReclaimRequestBatch::default()
    };
    let reclaim_reason = deferred
        .primary_reason()
        .unwrap_or(AllocatorReclaimReason::IdleMemoryPressure);
    let reclaim = allocator_reclaim(reclaim_reason);
    let reclaim_status = reclaim.get("status").and_then(Value::as_str);
    let merged_pending = reclaim_status == Some("merged_pending");
    let reclaim_executed = matches!(reclaim_status, Some("pass" | "partial"));
    let publication_reclaim_satisfied =
        allocator_publication_reclaim_satisfied(publication_reclaim_pending, reclaim_status);
    if !reclaim_executed || !publication_reclaim_satisfied {
        allocator_restore_reclaim_requests(&deferred);
    }
    if reclaim_executed {
        if publication_reclaim_satisfied {
            allocator_record_publication_reclaim(&deferred);
        }
        record_idle_reclaim_attempt(now);
        reset_idle_reclaim_allocated_high_water(stats.allocated);
        clear_cgroup_reclaim_pressure_latch();
    }
    let adaptive = record_idle_reclaim_outcome(&reclaim, effective_pressure_threshold);
    json!({
        "status": if merged_pending {
            "merged_pending"
        } else if reclaim_executed && !publication_reclaim_satisfied {
            "partial_retry_pending"
        } else if reclaim_executed {
            "reclaimed"
        } else {
            "failed"
        },
        "state": if cgroup_pressure.level.is_elevated() { "pressure" } else { "cold" },
        "reason": reclaim_reason.as_str(),
        "scope": deferred.scope().as_str(),
        "pressureBytes": pressure.to_string(),
        "pressureMetric": "maximum-of-page-and-worker-cache-pressure",
        "allocatorReclaimablePageBytes": page_pressure.to_string(),
        "allocatorMergedTcacheBytes": cache_pressure.to_string(),
        "allocatorApplicationLiveExcludingTcacheBytes": stats.application_live_excluding_tcache().to_string(),
        "allocatorRetainedBytes": stats.retained.to_string(),
        "postBurst": post_burst,
        "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
        "trafficRateSource": "resident_dataplane_total_counter_delta",
        "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
        "activeTcpConnections": observation.active_tcp,
        "activeUdpSessions": observation.active_udp,
        "deferred": deferred.json(),
        "effectiveMinIntervalMillis": effective_min_interval.as_millis().to_string(),
        "cgroupPressure": cgroup_pressure.json(),
        "activity": traffic_rate.json(),
        "adaptive": adaptive,
        "reclaim": reclaim,
    })
}

fn allocator_publication_reclaim_satisfied(
    publication_reclaim_pending: bool,
    reclaim_status: Option<&str>,
) -> bool {
    !publication_reclaim_pending || reclaim_status == Some("pass")
}

fn deferred_reclaim_evaluation_due(
    deadline: &mut Option<Instant>,
    now: Instant,
    pending: bool,
) -> bool {
    if !pending {
        *deadline = None;
        return false;
    }
    let deadline = deadline.get_or_insert(now + ALLOCATOR_IDLE_RECLAIM_DEFERRED_SETTLE_INTERVAL);
    now >= *deadline
}

fn idle_reclaim_observation(app: &AppState) -> Option<AllocatorIdleObservation> {
    let counters = app.runtime.resident_traffic_counters()?;
    Some(AllocatorIdleObservation {
        active_tcp: counters.active_tcp_connections,
        active_udp: counters.active_udp_sessions,
        upload_total_counter: counters.upload_total,
        download_total_counter: counters.download_total,
        packet_total_counter: counters.packet_total,
        request_total_counter: counters.request_total,
        queue_depth: counters.queue_depth,
        inflight_work: counters.inflight_work,
    })
}

fn idle_reclaim_wait_remaining(now: Instant, min_interval: Duration) -> Option<Duration> {
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    let state = state_lock.lock().ok()?;
    let last_attempt = state.last_attempt?;
    idle_reclaim_wait_remaining_since(now, last_attempt, min_interval)
}

fn idle_reclaim_wait_remaining_since(
    now: Instant,
    last_attempt: Instant,
    min_interval: Duration,
) -> Option<Duration> {
    let elapsed = now
        .checked_duration_since(last_attempt)
        .unwrap_or(Duration::ZERO);
    min_interval
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
}

fn record_idle_reclaim_attempt(now: Instant) {
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.last_attempt = Some(now);
    }
}

fn idle_reclaim_traffic_rate(
    now: Instant,
    observation: AllocatorIdleObservation,
) -> Option<AllocatorIdleTrafficRate> {
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    let mut state = state_lock.lock().ok()?;
    idle_reclaim_traffic_rate_from_state(&mut state, now, observation)
}

fn idle_reclaim_traffic_rate_from_state(
    state: &mut AllocatorIdleReclaimState,
    now: Instant,
    observation: AllocatorIdleObservation,
) -> Option<AllocatorIdleTrafficRate> {
    let previous = state.last_sample.replace(AllocatorIdleTrafficSample {
        upload_total_counter: observation.upload_total_counter,
        download_total_counter: observation.download_total_counter,
        packet_total_counter: observation.packet_total_counter,
        request_total_counter: observation.request_total_counter,
        queue_depth: observation.queue_depth,
        inflight_work: observation.inflight_work,
        active_tcp: observation.active_tcp,
        active_udp: observation.active_udp,
        observed_at: now,
    });
    let Some(previous) = previous else {
        state.low_traffic_since = None;
        return None;
    };
    let rate = idle_reclaim_traffic_rate_from_samples(previous, now, observation);
    if rate.is_none() {
        state.low_traffic_since = None;
    }
    rate
}

fn idle_reclaim_traffic_rate_from_samples(
    previous: AllocatorIdleTrafficSample,
    now: Instant,
    observation: AllocatorIdleObservation,
) -> Option<AllocatorIdleTrafficRate> {
    if observation.upload_total_counter < previous.upload_total_counter
        || observation.download_total_counter < previous.download_total_counter
        || observation.packet_total_counter < previous.packet_total_counter
        || observation.request_total_counter < previous.request_total_counter
    {
        return None;
    }
    let window = now.checked_duration_since(previous.observed_at)?;
    let elapsed = window.as_secs_f64();
    if elapsed <= 0.0 {
        return None;
    }
    let bytes = observation
        .upload_total_counter
        .saturating_sub(previous.upload_total_counter)
        .saturating_add(
            observation
                .download_total_counter
                .saturating_sub(previous.download_total_counter),
        );
    let packets = observation
        .packet_total_counter
        .saturating_sub(previous.packet_total_counter);
    let requests = observation
        .request_total_counter
        .saturating_sub(previous.request_total_counter);
    Some(AllocatorIdleTrafficRate {
        bytes_per_second: (bytes as f64 / elapsed) as u64,
        packets_per_second: (packets as f64 / elapsed) as u64,
        requests_per_second: (requests as f64 / elapsed) as u64,
        queue_depth: observation.queue_depth,
        queue_growing: observation.queue_depth > previous.queue_depth,
        inflight_work: observation.inflight_work,
        inflight_growing: observation.inflight_work > previous.inflight_work,
        active_count_growing: observation.active_tcp > previous.active_tcp
            || observation.active_udp > previous.active_udp,
        window,
        window_started_at: previous.observed_at,
    })
}

fn idle_reclaim_low_traffic_window(
    now: Instant,
    traffic_rate: AllocatorIdleTrafficRate,
    required: Duration,
) -> AllocatorLowTrafficWindow {
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    let mut state = match state_lock.lock() {
        Ok(state) => state,
        Err(_) => {
            return AllocatorLowTrafficWindow {
                elapsed: Duration::ZERO,
                ready: false,
            };
        }
    };
    idle_reclaim_low_traffic_window_from_since(
        &mut state.low_traffic_since,
        now,
        traffic_rate,
        required,
    )
}

fn idle_reclaim_low_traffic_window_from_since(
    low_traffic_since: &mut Option<Instant>,
    now: Instant,
    traffic_rate: AllocatorIdleTrafficRate,
    required: Duration,
) -> AllocatorLowTrafficWindow {
    let window_start = traffic_rate.window_started_at.min(now);
    let low_since = low_traffic_since.get_or_insert(window_start);
    if now.checked_duration_since(*low_since).is_none() {
        *low_since = window_start;
    }
    let elapsed = now
        .checked_duration_since(*low_since)
        .unwrap_or(Duration::ZERO);
    AllocatorLowTrafficWindow {
        elapsed,
        ready: elapsed >= required,
    }
}

fn record_idle_reclaim_tick_panic() {
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.low_traffic_since = None;
        state.last_report = json!({
            "status": "skipped",
            "reason": "monitor_tick_panicked",
            "lowTrafficWindowReset": true,
        });
    }
}

fn reset_idle_reclaim_low_traffic_window() {
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.low_traffic_since = None;
    }
}

fn reset_idle_reclaim_observation() {
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.last_sample = None;
        state.low_traffic_since = None;
    }
}

fn default_idle_reclaim_state() -> AllocatorIdleReclaimState {
    AllocatorIdleReclaimState {
        started: false,
        last_attempt: None,
        last_sample: None,
        low_traffic_since: None,
        low_yield_streak: 0,
        last_released_bytes: None,
        last_reclaim_high_yield: false,
        last_cgroup_high_events: None,
        cgroup_high_event_latched: false,
        previous_busy_count: 0,
        previous_busy_completion_count: allocator_reclaim_busy_completion_count(),
        heavy_task_quiet_since: None,
        allocated_high_water: 0,
        post_burst_quiet_since: None,
        last_report: json!({"status": "not_started"}),
    }
}

fn effective_bool(name: &str, configured: Option<bool>, default: bool) -> (bool, &'static str) {
    if let Some(value) = std::env::var(name)
        .ok()
        .and_then(|value| parse_env_bool(&value))
    {
        return (value, "env");
    }
    if let Some(value) = configured {
        return (value, "config");
    }
    (default, "default")
}

fn effective_u64(
    name: &str,
    configured: Option<u64>,
    default: u64,
    min: u64,
    max: u64,
) -> (u64, &'static str) {
    if let Some(value) = std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return (value.clamp(min, max), "env");
    }
    if let Some(value) = configured {
        return (value.clamp(min, max), "config");
    }
    (default.clamp(min, max), "default")
}

fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim() {
        "1" | "true" | "TRUE" | "on" | "ON" | "yes" | "YES" => Some(true),
        "0" | "false" | "FALSE" | "off" | "OFF" | "no" | "NO" => Some(false),
        _ => None,
    }
}

fn config_duration_seconds_from_nanos(nanos: i64) -> u64 {
    if nanos <= 0 {
        return 0;
    }
    ((nanos as u64).saturating_add(999_999_999)) / 1_000_000_000
}

#[cfg(test)]
mod tests {
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
}
