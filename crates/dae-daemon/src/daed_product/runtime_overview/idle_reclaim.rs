use super::*;
use crate::allocator::{
    AllocatorReclaimRequestBatch, allocator_pending_reclaim_reason,
    allocator_pending_reclaim_requests, allocator_take_reclaim_requests,
};

#[path = "idle_reclaim/adaptive.rs"]
mod adaptive;
use self::adaptive::*;
#[path = "idle_reclaim/capacity.rs"]
mod capacity;
use self::capacity::*;
#[path = "idle_reclaim/pressure.rs"]
mod pressure;
use self::pressure::*;

const ALLOCATOR_IDLE_RECLAIM_MONITOR_STACK_BYTES: usize = 256 * 1024;
const ALLOCATOR_IDLE_RECLAIM_MONITOR_WAKE_INTERVAL: Duration = Duration::from_secs(1);
const ALLOCATOR_IDLE_RECLAIM_DEFERRED_SETTLE_INTERVAL: Duration = Duration::from_secs(5);
const ALLOCATOR_IDLE_RECLAIM_DEFERRED_RETRY_INTERVAL: Duration = Duration::from_secs(5);

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
        let pressure = allocator_idle_reclaim_pressure_threshold(
            configured_pressure_threshold_bytes,
            configured_pressure_source,
            crate::production_runtime_owner::effective_process_memory_capacity(),
        );
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
            pressure_threshold_bytes: pressure.bytes,
            max_traffic_rate_bytes_per_second,
            pressure_capacity_bytes: pressure.capacity_bytes,
            pressure_capacity_source: pressure.capacity_source,
            sources: AllocatorIdleReclaimPolicySources {
                enabled: enabled_source,
                sample_interval: sample_interval_source,
                min_interval: min_interval_source,
                low_traffic_duration: low_traffic_source,
                pressure_threshold_bytes: pressure.source,
                max_traffic_rate_bytes_per_second: max_rate_source,
            },
        }
    }

    fn json(self) -> Value {
        json!({
            "enabled": self.enabled,
            "idleDetection": "traffic-rate-only",
            "sampleIntervalSeconds": self.sample_interval.as_secs(),
            "minIntervalSeconds": self.min_interval.as_secs(),
            "lowTrafficSeconds": self.low_traffic_duration.as_secs(),
            "pressureThresholdBytes": self.pressure_threshold_bytes.to_string(),
            "pressureCapacityBytes": self.pressure_capacity_bytes.map(|value| value.to_string()),
            "pressureCapacitySource": self.pressure_capacity_source,
            "pressureMetric": "allocator-resident-minus-active",
            "retainedMetric": "diagnostic-virtual-address-space",
            "maxTrafficRateBytesPerSecond": self.max_traffic_rate_bytes_per_second.to_string(),
            "sessionCountGate": false,
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
    last_cgroup_high_events: Option<u64>,
    cgroup_high_event_latched: bool,
    last_report: Value,
}

#[derive(Clone, Copy, Debug)]
struct AllocatorIdleTrafficSample {
    upload_total_counter: u64,
    download_total_counter: u64,
    observed_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct AllocatorIdleObservation {
    active_tcp: u64,
    active_udp: u64,
    upload_total_counter: u64,
    download_total_counter: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocatorIdleTrafficRate {
    bytes_per_second: u64,
    window: Duration,
    window_started_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocatorLowTrafficWindow {
    elapsed: Duration,
    ready: bool,
}

static ALLOCATOR_IDLE_RECLAIM_STATE: OnceLock<Mutex<AllocatorIdleReclaimState>> = OnceLock::new();

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
                if app
                    .shutdown
                    .wait_timeout(ALLOCATOR_IDLE_RECLAIM_MONITOR_WAKE_INTERVAL)
                {
                    break;
                }
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
        "last": last_report,
    })
}

fn allocator_idle_reclaim_tick(
    app: &AppState,
    policy: AllocatorIdleReclaimPolicy,
    admit_deferred_requests: bool,
) {
    let report = evaluate_allocator_idle_reclaim(app, policy, admit_deferred_requests);
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.last_report = report;
    }
}

fn evaluate_allocator_idle_reclaim(
    app: &AppState,
    policy: AllocatorIdleReclaimPolicy,
    admit_deferred_requests: bool,
) -> Value {
    if !policy.enabled {
        reset_idle_reclaim_observation();
        clear_cgroup_reclaim_pressure_latch();
        let deferred = if admit_deferred_requests {
            allocator_take_reclaim_requests()
        } else {
            AllocatorReclaimRequestBatch::default()
        };
        return json!({"status": "skipped", "reason": "disabled", "deferred": deferred.json()});
    }

    let now = Instant::now();
    let deferred_waiting = allocator_pending_reclaim_requests();
    let deferred_pending = admit_deferred_requests && deferred_waiting;
    let retired_generation_release_pending = deferred_pending
        && allocator_pending_reclaim_reason(AllocatorReclaimReason::RetiredGenerationReleased);
    let cgroup_pressure = observe_cgroup_reclaim_pressure();
    let Some(observation) = idle_reclaim_observation(app) else {
        reset_idle_reclaim_observation();
        return json!({"status": "skipped", "reason": "runtime_metrics_unavailable"});
    };
    let Some(traffic_rate) = idle_reclaim_traffic_rate(now, observation) else {
        return json!({"status": "skipped", "reason": "traffic_sample_warming_up"});
    };
    if traffic_rate.bytes_per_second > policy.max_traffic_rate_bytes_per_second
        && !cgroup_pressure.urgent
        && !retired_generation_release_pending
    {
        reset_idle_reclaim_low_traffic_window();
        return json!({
            "status": "skipped",
            "reason": "traffic_active",
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "trafficRateWindowMillis": traffic_rate.window.as_millis().to_string(),
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
    if !deferred_pending && !cgroup_pressure.urgent && !low_traffic.ready {
        return json!({
            "status": "skipped",
            "reason": "low_traffic_window_warming_up",
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "trafficRateWindowMillis": traffic_rate.window.as_millis().to_string(),
            "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
            "lowTrafficRequiredMillis": policy.low_traffic_duration.as_millis().to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
            "cgroupPressure": cgroup_pressure.json(),
        });
    }
    let adaptive_min_interval = idle_reclaim_effective_min_interval(policy.min_interval);
    let effective_min_interval = if retired_generation_release_pending {
        Duration::ZERO
    } else if cgroup_pressure.urgent {
        adaptive_min_interval.min(policy.sample_interval)
    } else {
        adaptive_min_interval
    };
    if let Some(wait_remaining) = idle_reclaim_wait_remaining(now, effective_min_interval) {
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
        });
    }

    let Some(stats) = allocator_stats_snapshot() else {
        return json!({"status": "skipped", "reason": "allocator_stats_unavailable"});
    };
    let pressure = stats.idle_reclaim_pressure_bytes();
    let effective_pressure_threshold = if cgroup_pressure.urgent {
        (policy.pressure_threshold_bytes / 4).max(ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN)
    } else {
        policy.pressure_threshold_bytes
    };
    if pressure < effective_pressure_threshold && !retired_generation_release_pending {
        let deferred = if deferred_pending {
            allocator_take_reclaim_requests()
        } else {
            AllocatorReclaimRequestBatch::default()
        };
        clear_cgroup_reclaim_pressure_latch();
        return json!({
            "status": "skipped",
            "reason": "pressure_below_threshold",
            "pressureBytes": pressure.to_string(),
            "pressureMetric": "allocator-resident-minus-active",
            "pressureThresholdBytes": effective_pressure_threshold.to_string(),
            "allocatorResidentMinusActiveBytes": stats.resident_minus_active().to_string(),
            "allocatorRetainedBytes": stats.retained.to_string(),
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
            "deferred": deferred.json(),
            "effectiveMinIntervalMillis": effective_min_interval.as_millis().to_string(),
            "cgroupPressure": cgroup_pressure.json(),
        });
    }

    let deferred = if deferred_pending {
        allocator_take_reclaim_requests()
    } else {
        AllocatorReclaimRequestBatch::default()
    };
    let reclaim_reason = deferred
        .primary_reason()
        .unwrap_or(AllocatorReclaimReason::IdleMemoryPressure);
    record_idle_reclaim_attempt(now);
    let reclaim = allocator_reclaim(reclaim_reason);
    let adaptive = record_idle_reclaim_outcome(&reclaim, policy.pressure_threshold_bytes);
    clear_cgroup_reclaim_pressure_latch();
    json!({
        "status": "reclaimed",
        "reason": reclaim_reason.as_str(),
        "pressureBytes": pressure.to_string(),
        "pressureMetric": "allocator-resident-minus-active",
        "allocatorResidentMinusActiveBytes": stats.resident_minus_active().to_string(),
        "allocatorRetainedBytes": stats.retained.to_string(),
        "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
        "trafficRateSource": "resident_dataplane_total_counter_delta",
        "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
        "activeTcpConnections": observation.active_tcp,
        "activeUdpSessions": observation.active_udp,
        "deferred": deferred.json(),
        "effectiveMinIntervalMillis": effective_min_interval.as_millis().to_string(),
        "cgroupPressure": cgroup_pressure.json(),
        "adaptive": adaptive,
        "reclaim": reclaim,
    })
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
    Some(AllocatorIdleTrafficRate {
        bytes_per_second: (bytes as f64 / elapsed) as u64,
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
        last_cgroup_high_events: None,
        cgroup_high_event_latched: false,
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
            observed_at: previous_at,
        };
        let observation = AllocatorIdleObservation {
            active_tcp: 8,
            active_udp: 0,
            upload_total_counter: 1_010_000,
            download_total_counter: 2_030_000,
        };

        let rate = idle_reclaim_traffic_rate_from_samples(
            previous,
            previous_at + Duration::from_secs(2),
            observation,
        );

        let rate = rate.unwrap();
        assert_eq!(rate.bytes_per_second, 20_000);
        assert_eq!(rate.window, Duration::from_secs(2));
    }

    #[test]
    fn idle_reclaim_traffic_rate_warms_up_after_counter_reset() {
        let previous_at = Instant::now();
        let previous = AllocatorIdleTrafficSample {
            upload_total_counter: 1_000_000,
            download_total_counter: 2_000_000,
            observed_at: previous_at,
        };
        let observation = AllocatorIdleObservation {
            active_tcp: 0,
            active_udp: 0,
            upload_total_counter: 100,
            download_total_counter: 200,
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
            observed_at: previous_at + Duration::from_secs(10),
        };
        let observation = AllocatorIdleObservation {
            active_tcp: 0,
            active_udp: 0,
            upload_total_counter: 1_000_100,
            download_total_counter: 2_000_200,
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
    fn low_traffic_window_requires_configured_duration() {
        let started_at = Instant::now();
        let rate = AllocatorIdleTrafficRate {
            bytes_per_second: 16,
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
