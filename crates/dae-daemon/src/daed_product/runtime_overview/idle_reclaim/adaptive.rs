use super::*;

const ALLOCATOR_RECLAIM_LOW_YIELD_BACKOFF_MAX_SHIFT: u32 = 4;
const ALLOCATOR_RECLAIM_MEANINGFUL_RELEASE_DIVISOR: u64 = 8;

pub(super) fn idle_reclaim_effective_min_interval(base: Duration) -> Duration {
    let shift = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
        .ok()
        .map(|state| {
            u32::from(state.low_yield_streak).min(ALLOCATOR_RECLAIM_LOW_YIELD_BACKOFF_MAX_SHIFT)
        })
        .unwrap_or(0);
    base.saturating_mul(1_u32 << shift)
}

pub(super) fn record_idle_reclaim_outcome(reclaim: &Value, pressure_threshold_bytes: u64) -> Value {
    let released_bytes = reclaim
        .pointer("/detail/physicalResidentReleasedBytes")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok());
    let executed = reclaim.get("status").and_then(Value::as_str) != Some("coalesced");
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
        "backoffMultiplier": 1_u64 << u32::from(low_yield_streak).min(ALLOCATOR_RECLAIM_LOW_YIELD_BACKOFF_MAX_SHIFT),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static ADAPTIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

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
            idle_reclaim_effective_min_interval(Duration::from_secs(300)),
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
            idle_reclaim_effective_min_interval(Duration::from_secs(60)),
            Duration::from_secs(960)
        );
    }
}
