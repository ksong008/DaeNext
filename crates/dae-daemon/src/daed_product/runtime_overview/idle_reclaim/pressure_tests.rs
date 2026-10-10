use super::*;

static PRESSURE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn resident_pressure_uses_finite_cgroup_limit_and_recovers_without_a_purge() {
    let mut snapshot = json!({
        "available": true, "currentBytes": "850", "highBytes": "2000", "maxBytes": "1000",
    });
    assert!(resident_pressure_from_snapshot(&snapshot));
    snapshot["currentBytes"] = json!(849);
    assert!(!resident_pressure_from_snapshot(&snapshot));
    snapshot["highBytes"] = json!(800);
    assert!(resident_pressure_from_snapshot(&snapshot));
    snapshot["available"] = json!(false);
    assert!(!resident_pressure_from_snapshot(&snapshot));
    assert!(!resident_pressure_from_snapshot(
        &json!({"available": true, "currentBytes": 9999})
    ));
}

#[test]
fn cgroup_pressure_uses_finite_high_before_max() {
    let _guard = PRESSURE_TEST_LOCK.lock().unwrap();
    let pressure = cgroup_reclaim_pressure_from_snapshot(
        &json!({
            "available": true,
            "currentBytes": "900",
            "highBytes": "1000",
            "maxBytes": "2000",
            "events": {"high": 0},
        }),
        false,
    );
    assert!(pressure.urgent);
    assert_eq!(pressure.limiting_source, Some("memory.high"));
}

#[test]
fn cgroup_pressure_uses_lower_finite_max_when_high_is_larger() {
    let _guard = PRESSURE_TEST_LOCK.lock().unwrap();
    let pressure = cgroup_reclaim_pressure_from_snapshot(
        &json!({
            "available": true,
            "currentBytes": "900",
            "highBytes": "2000",
            "maxBytes": "1000",
            "events": {"high": 0},
        }),
        false,
    );
    assert!(pressure.urgent);
    assert_eq!(pressure.limiting_bytes, Some(1000));
    assert_eq!(pressure.limiting_source, Some("memory.max"));
}

#[test]
fn cgroup_pressure_detects_new_high_event_without_near_limit_usage() {
    let _guard = PRESSURE_TEST_LOCK.lock().unwrap();
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    state_lock.lock().unwrap().last_cgroup_high_events = Some(4);
    let pressure = cgroup_reclaim_pressure_from_snapshot(
        &json!({
            "available": true,
            "currentBytes": "100",
            "highBytes": "1000",
            "maxBytes": null,
            "events": {"high": 5},
        }),
        false,
    );
    assert!(pressure.urgent);
    assert!(pressure.high_event_increased);
}

#[test]
fn cgroup_high_event_stays_latched_until_allocator_decision() {
    let _guard = PRESSURE_TEST_LOCK.lock().unwrap();
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    {
        let mut state = state_lock.lock().unwrap();
        state.last_cgroup_high_events = Some(4);
        state.cgroup_high_event_latched = false;
    }

    let snapshot = json!({
        "available": true,
        "currentBytes": "100",
        "highBytes": "1000",
        "maxBytes": null,
        "events": {"high": 5},
    });
    let first = cgroup_reclaim_pressure_from_snapshot(&snapshot, true);
    assert!(first.high_event_increased);
    assert!(first.high_event_latched);

    let second = cgroup_reclaim_pressure_from_snapshot(&snapshot, true);
    assert!(!second.high_event_increased);
    assert!(second.high_event_latched);
    assert!(second.urgent);

    clear_cgroup_reclaim_pressure_latch();
    let cleared = cgroup_reclaim_pressure_from_snapshot(&snapshot, true);
    assert!(!cleared.high_event_increased);
    assert!(!cleared.high_event_latched);
    assert!(!cleared.urgent);
}
