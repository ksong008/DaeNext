use super::*;

const ALLOCATOR_RECLAIM_MEANINGFUL_RELEASE_DIVISOR: u64 = 8;
const ALLOCATOR_RECLAIM_HIGH_YIELD_INTERVAL: Duration = Duration::from_secs(60);
const ALLOCATOR_RECLAIM_LOW_YIELD_FIRST_INTERVAL: Duration = Duration::from_secs(300);
const ALLOCATOR_RECLAIM_LOW_YIELD_SECOND_INTERVAL: Duration = Duration::from_secs(600);
const ALLOCATOR_RECLAIM_LOW_YIELD_MAX_INTERVAL: Duration = Duration::from_secs(1_200);

pub(super) fn idle_reclaim_pressure_threshold(
    configured_bytes: u64,
    configured_source: &'static str,
    application_live_excluding_tcache: u64,
    pressure_level: CgroupReclaimPressureLevel,
    post_burst: bool,
) -> u64 {
    let dynamic_base = (application_live_excluding_tcache / 8).clamp(
        ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN,
        ALLOCATOR_IDLE_RECLAIM_DYNAMIC_PRESSURE_MAX_BYTES,
    );
    let base = if matches!(configured_source, "env" | "config") {
        configured_bytes
    } else {
        dynamic_base
    };
    if pressure_level.is_urgent() {
        ALLOCATOR_IDLE_RECLAIM_ELEVATED_PRESSURE_MIN_BYTES
    } else if pressure_level.is_elevated() {
        (base / 2).max(ALLOCATOR_IDLE_RECLAIM_ELEVATED_PRESSURE_MIN_BYTES)
    } else if post_burst {
        ALLOCATOR_IDLE_RECLAIM_POST_BURST_PRESSURE_BYTES
    } else {
        base
    }
}

pub(super) fn idle_reclaim_effective_min_interval(
    base: Duration,
    allow_high_yield_shortening: bool,
) -> Duration {
    let (shift, last_high_yield) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
        .ok()
        .map(|state| {
            (
                u32::from(state.low_yield_streak),
                state.last_reclaim_high_yield,
            )
        })
        .unwrap_or((0, false));
    match shift {
        0 if allow_high_yield_shortening && last_high_yield => {
            base.min(ALLOCATOR_RECLAIM_HIGH_YIELD_INTERVAL)
        }
        0 => base,
        1 => base.max(ALLOCATOR_RECLAIM_LOW_YIELD_FIRST_INTERVAL),
        2 => base.max(ALLOCATOR_RECLAIM_LOW_YIELD_SECOND_INTERVAL),
        _ => base.max(ALLOCATOR_RECLAIM_LOW_YIELD_MAX_INTERVAL),
    }
}

pub(super) fn record_idle_reclaim_outcome(reclaim: &Value, pressure_threshold_bytes: u64) -> Value {
    let released_bytes = reclaim
        .pointer("/detail/physicalResidentReleasedBytes")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok());
    let executed = matches!(
        reclaim.get("status").and_then(Value::as_str),
        Some("pass" | "partial")
    );
    let meaningful_release_bytes = pressure_threshold_bytes
        .saturating_add(ALLOCATOR_RECLAIM_MEANINGFUL_RELEASE_DIVISOR - 1)
        / ALLOCATOR_RECLAIM_MEANINGFUL_RELEASE_DIVISOR;

    let mut low_yield_streak = 0_u8;
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        if executed {
            state.last_released_bytes = released_bytes;
            state.last_reclaim_high_yield =
                released_bytes.is_some_and(|released| released >= pressure_threshold_bytes);
            state.low_yield_streak = match released_bytes {
                Some(released) if released >= meaningful_release_bytes => 0,
                Some(_) | None => state.low_yield_streak.saturating_add(1),
            };
        }
        low_yield_streak = state.low_yield_streak;
    }

    json!({
        "executed": executed,
        "physicalResidentReleasedBytes": released_bytes.map(|value| value.to_string()),
        "meaningfulReleaseBytes": meaningful_release_bytes.to_string(),
        "lowYieldStreak": low_yield_streak,
        "backoffSeconds": idle_reclaim_effective_min_interval(Duration::ZERO, true).as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static ADAPTIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn pressure_threshold_tracks_live_working_set_and_cgroup_tier() {
        let mib = 1024 * 1024;
        assert_eq!(
            idle_reclaim_pressure_threshold(
                32 * mib,
                "application-live-working-set",
                64 * mib,
                CgroupReclaimPressureLevel::Normal,
                false,
            ),
            8 * mib
        );
        assert_eq!(
            idle_reclaim_pressure_threshold(
                32 * mib,
                "application-live-working-set",
                64 * mib,
                CgroupReclaimPressureLevel::Elevated,
                false,
            ),
            4 * mib
        );
        assert_eq!(
            idle_reclaim_pressure_threshold(
                48 * mib,
                "config",
                64 * mib,
                CgroupReclaimPressureLevel::Urgent,
                false,
            ),
            2 * mib
        );
    }

    #[test]
    fn reclaim_outcome_resets_backoff_after_meaningful_release() {
        let _guard = ADAPTIVE_TEST_LOCK.lock().unwrap();
        let state_lock =
            ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
        let mut state = state_lock.lock().unwrap();
        state.low_yield_streak = 3;
        drop(state);

        let report = record_idle_reclaim_outcome(
            &json!({
                "status": "pass",
                "detail": {"physicalResidentReleasedBytes": (8 * 1024 * 1024).to_string()},
            }),
            32 * 1024 * 1024,
        );

        assert_eq!(report["lowYieldStreak"], json!(0));
        assert_eq!(
            idle_reclaim_effective_min_interval(Duration::from_secs(300), true),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn high_yield_reclaim_uses_the_short_default_cooldown() {
        let _guard = ADAPTIVE_TEST_LOCK.lock().unwrap();
        let state_lock =
            ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
        state_lock.lock().unwrap().low_yield_streak = 0;

        let _ = record_idle_reclaim_outcome(
            &json!({
                "status": "pass",
                "detail": {"physicalResidentReleasedBytes": (32 * 1024 * 1024).to_string()},
            }),
            32 * 1024 * 1024,
        );

        assert_eq!(
            idle_reclaim_effective_min_interval(Duration::from_secs(120), true),
            Duration::from_secs(60)
        );
        assert_eq!(
            idle_reclaim_effective_min_interval(Duration::from_secs(300), false),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn reclaim_outcome_applies_bounded_backoff_after_low_yield() {
        let _guard = ADAPTIVE_TEST_LOCK.lock().unwrap();
        let state_lock =
            ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
        let mut state = state_lock.lock().unwrap();
        state.low_yield_streak = 0;
        drop(state);

        for _ in 0..8 {
            let _ = record_idle_reclaim_outcome(
                &json!({
                    "status": "pass",
                    "detail": {"physicalResidentReleasedBytes": "0"},
                }),
                32 * 1024 * 1024,
            );
        }

        assert_eq!(
            idle_reclaim_effective_min_interval(Duration::from_secs(60), true),
            Duration::from_secs(1_200)
        );
    }
}
