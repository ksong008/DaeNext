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
