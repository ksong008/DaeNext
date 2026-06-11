use super::*;

const ALLOCATOR_IDLE_RECLAIM_MONITOR_STACK_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug)]
struct AllocatorIdleReclaimPolicy {
    enabled: bool,
    sample_interval: Duration,
    min_interval: Duration,
    low_traffic_duration: Duration,
    pressure_threshold_bytes: u64,
    max_traffic_rate_bytes_per_second: u64,
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
        let (pressure_threshold_bytes, pressure_source) = effective_u64(
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_ENV,
            global.and_then(|global| global.allocator_idle_reclaim_pressure_threshold_bytes),
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT,
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN,
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MAX,
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
            pressure_threshold_bytes,
            max_traffic_rate_bytes_per_second,
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
            "idleDetection": "traffic-rate-only",
            "sampleIntervalSeconds": self.sample_interval.as_secs(),
            "minIntervalSeconds": self.min_interval.as_secs(),
            "lowTrafficSeconds": self.low_traffic_duration.as_secs(),
            "pressureThresholdBytes": self.pressure_threshold_bytes.to_string(),
            "maxTrafficRateBytesPerSecond": self.max_traffic_rate_bytes_per_second.to_string(),
            "sessionCountGate": false,
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

pub(crate) fn spawn_allocator_idle_reclaim_monitor(app: &Arc<AppState>) {
    {
        let state_lock =
            ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
        let Ok(mut state) = state_lock.lock() else {
            return;
        };
        if state.started {
            return;
        }
        state.started = true;
    }

    let app = Arc::clone(app);
    let _ = thread::Builder::new()
        .name("allocator-idle-reclaim".to_owned())
        .stack_size(ALLOCATOR_IDLE_RECLAIM_MONITOR_STACK_BYTES)
        .spawn(move || {
            loop {
                let config = app.runtime.current_config();
                let policy = AllocatorIdleReclaimPolicy::from_config(config.as_ref());
                thread::sleep(policy.sample_interval);
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    allocator_idle_reclaim_tick(&app, policy);
                }))
                .is_err()
                {
                    record_idle_reclaim_tick_panic();
                }
            }
        });
}

pub(crate) fn allocator_idle_reclaim_snapshot_json(app: &AppState) -> Value {
    let config = app.runtime.current_config();
    let policy = AllocatorIdleReclaimPolicy::from_config(config.as_ref());
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

fn allocator_idle_reclaim_tick(app: &AppState, policy: AllocatorIdleReclaimPolicy) {
    let report = evaluate_allocator_idle_reclaim(app, policy);
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.last_report = report;
    }
}

fn evaluate_allocator_idle_reclaim(app: &AppState, policy: AllocatorIdleReclaimPolicy) -> Value {
    if !policy.enabled {
        return json!({"status": "skipped", "reason": "disabled"});
    }

    let now = Instant::now();
    let Some(observation) = idle_reclaim_observation(app) else {
        return json!({"status": "skipped", "reason": "runtime_metrics_unavailable"});
    };
    let Some(traffic_rate) = idle_reclaim_traffic_rate(now, observation) else {
        return json!({"status": "skipped", "reason": "traffic_sample_warming_up"});
    };
    if traffic_rate.bytes_per_second > policy.max_traffic_rate_bytes_per_second {
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
        });
    }
    let low_traffic =
        idle_reclaim_low_traffic_window(now, traffic_rate, policy.low_traffic_duration);
    if !low_traffic.ready {
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
        });
    }
    if let Some(wait_remaining) = idle_reclaim_wait_remaining(now, policy.min_interval) {
        return json!({
            "status": "skipped",
            "reason": "cooldown",
            "waitRemainingMillis": wait_remaining.as_millis().to_string(),
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
        });
    }

    let Some(stats) = allocator_stats_snapshot() else {
        return json!({"status": "skipped", "reason": "allocator_stats_unavailable"});
    };
    let pressure = stats.idle_reclaim_pressure_bytes();
    if pressure < policy.pressure_threshold_bytes {
        return json!({
            "status": "skipped",
            "reason": "pressure_below_threshold",
            "pressureBytes": pressure.to_string(),
            "pressureThresholdBytes": policy.pressure_threshold_bytes.to_string(),
            "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
            "trafficRateSource": "resident_dataplane_total_counter_delta",
            "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
            "activeTcpConnections": observation.active_tcp,
            "activeUdpSessions": observation.active_udp,
        });
    }

    record_idle_reclaim_attempt(now);
    let reclaim = allocator_reclaim(AllocatorReclaimReason::IdleMemoryPressure);
    json!({
        "status": "reclaimed",
        "reason": "idle_memory_pressure",
        "pressureBytes": pressure.to_string(),
        "trafficRateBytesPerSecond": traffic_rate.bytes_per_second.to_string(),
        "trafficRateSource": "resident_dataplane_total_counter_delta",
        "lowTrafficElapsedMillis": low_traffic.elapsed.as_millis().to_string(),
        "activeTcpConnections": observation.active_tcp,
        "activeUdpSessions": observation.active_udp,
        "reclaim": reclaim,
    })
}

fn idle_reclaim_observation(app: &AppState) -> Option<AllocatorIdleObservation> {
    let metrics = app.runtime.resident_dataplane_metrics_snapshot()?;
    Some(AllocatorIdleObservation {
        active_tcp: event_u64(&metrics, "activeTcpConnections"),
        active_udp: event_u64(&metrics, "activeUdpSessions"),
        upload_total_counter: event_u64(&metrics, "uploadTotal"),
        download_total_counter: event_u64(&metrics, "downloadTotal"),
    })
}

fn idle_reclaim_wait_remaining(now: Instant, min_interval: Duration) -> Option<Duration> {
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    let state = state_lock.lock().ok()?;
    let last_attempt = state.last_attempt?;
    let elapsed = now
        .checked_duration_since(last_attempt)
        .unwrap_or(Duration::ZERO);
    (elapsed < min_interval).then_some(min_interval - elapsed)
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
    let previous = state.last_sample.replace(AllocatorIdleTrafficSample {
        upload_total_counter: observation.upload_total_counter,
        download_total_counter: observation.download_total_counter,
        observed_at: now,
    })?;
    idle_reclaim_traffic_rate_from_samples(previous, now, observation)
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

fn default_idle_reclaim_state() -> AllocatorIdleReclaimState {
    AllocatorIdleReclaimState {
        started: false,
        last_attempt: None,
        last_sample: None,
        low_traffic_since: None,
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
