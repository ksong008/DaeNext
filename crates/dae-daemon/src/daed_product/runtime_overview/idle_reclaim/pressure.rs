use super::*;

const CGROUP_RECLAIM_ELEVATED_USAGE_PERMILLE: u64 = 700;
const CGROUP_RECLAIM_URGENT_USAGE_PERMILLE: u64 = 850;
const CGROUP_RECLAIM_EMERGENCY_USAGE_PERMILLE: u64 = 900;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum CgroupReclaimPressureLevel {
    #[default]
    Normal,
    Elevated,
    Urgent,
    Emergency,
}

impl CgroupReclaimPressureLevel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Urgent => "urgent",
            Self::Emergency => "emergency",
        }
    }

    pub(super) const fn is_elevated(self) -> bool {
        !matches!(self, Self::Normal)
    }

    pub(super) const fn is_urgent(self) -> bool {
        matches!(self, Self::Urgent | Self::Emergency)
    }

    pub(super) const fn is_emergency(self) -> bool {
        matches!(self, Self::Emergency)
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct CgroupReclaimPressure {
    pub(super) urgent: bool,
    pub(super) level: CgroupReclaimPressureLevel,
    current_bytes: Option<u64>,
    limiting_bytes: Option<u64>,
    limiting_source: Option<&'static str>,
    high_events: Option<u64>,
    pub(super) high_event_increased: bool,
    high_event_latched: bool,
    anonymous_bytes: Option<u64>,
    non_allocator_bytes: Option<u64>,
}

impl CgroupReclaimPressure {
    pub(super) fn json(&self) -> Value {
        json!({
            "urgent": self.urgent,
            "level": self.level.as_str(),
            "currentBytes": self.current_bytes.map(|value| value.to_string()),
            "limitingBytes": self.limiting_bytes.map(|value| value.to_string()),
            "limitingSource": self.limiting_source,
            "elevatedUsagePermille": CGROUP_RECLAIM_ELEVATED_USAGE_PERMILLE,
            "urgentUsagePermille": CGROUP_RECLAIM_URGENT_USAGE_PERMILLE,
            "emergencyUsagePermille": CGROUP_RECLAIM_EMERGENCY_USAGE_PERMILLE,
            "highEvents": self.high_events,
            "highEventIncreased": self.high_event_increased,
            "highEventLatched": self.high_event_latched,
            "anonymousBytes": self.anonymous_bytes.map(|value| value.to_string()),
            "nonAllocatorBytes": self.non_allocator_bytes.map(|value| value.to_string()),
        })
    }
}

pub(super) fn observe_cgroup_reclaim_pressure() -> CgroupReclaimPressure {
    let snapshot = cgroup_memory_snapshot_json();
    cgroup_reclaim_pressure_from_snapshot(&snapshot, true)
}

fn cgroup_reclaim_pressure_from_snapshot(
    snapshot: &Value,
    update_observation: bool,
) -> CgroupReclaimPressure {
    if snapshot.get("available").and_then(Value::as_bool) != Some(true) {
        return CgroupReclaimPressure::default();
    }
    let current_bytes = json_u64(snapshot.get("currentBytes"));
    let high_bytes = json_u64(snapshot.get("highBytes"));
    let max_bytes = json_u64(snapshot.get("maxBytes"));
    let (limiting_bytes, limiting_source) = match (high_bytes, max_bytes) {
        (Some(high), Some(maximum)) if high <= maximum => (Some(high), Some("memory.high")),
        (Some(_), Some(maximum)) => (Some(maximum), Some("memory.max")),
        (Some(high), None) => (Some(high), Some("memory.high")),
        (None, Some(maximum)) => (Some(maximum), Some("memory.max")),
        (None, None) => (None, None),
    };
    let high_events = snapshot.pointer("/events/high").and_then(Value::as_u64);
    let mut previous_high_events = None;
    let mut high_event_latched = false;
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        previous_high_events = state.last_cgroup_high_events;
        let increased = high_events
            .zip(previous_high_events)
            .is_some_and(|(current, previous)| current > previous);
        if update_observation && high_events.is_some() {
            state.last_cgroup_high_events = high_events;
            state.cgroup_high_event_latched |= increased;
        }
        high_event_latched = state.cgroup_high_event_latched;
    }
    let high_event_increased = high_events
        .zip(previous_high_events)
        .is_some_and(|(current, previous)| current > previous);
    let usage_permille = current_bytes
        .zip(limiting_bytes)
        .and_then(|(current, limit)| (limit > 0).then_some(current.saturating_mul(1_000) / limit));
    let mut level = match usage_permille.unwrap_or_default() {
        usage if usage >= CGROUP_RECLAIM_EMERGENCY_USAGE_PERMILLE => {
            CgroupReclaimPressureLevel::Emergency
        }
        usage if usage >= CGROUP_RECLAIM_URGENT_USAGE_PERMILLE => {
            CgroupReclaimPressureLevel::Urgent
        }
        usage if usage >= CGROUP_RECLAIM_ELEVATED_USAGE_PERMILLE => {
            CgroupReclaimPressureLevel::Elevated
        }
        _ => CgroupReclaimPressureLevel::Normal,
    };
    if (high_event_increased || high_event_latched)
        && !matches!(level, CgroupReclaimPressureLevel::Emergency)
    {
        level = CgroupReclaimPressureLevel::Urgent;
    }
    let anonymous_bytes = json_u64(snapshot.pointer("/stat/anon"));
    let non_allocator_bytes = ["file", "slab", "sock", "kernel_stack", "pagetables"]
        .into_iter()
        .filter_map(|field| json_u64(snapshot.pointer(&format!("/stat/{field}"))))
        .fold(0_u64, u64::saturating_add);
    CgroupReclaimPressure {
        urgent: level.is_urgent(),
        level,
        current_bytes,
        limiting_bytes,
        limiting_source,
        high_events,
        high_event_increased,
        high_event_latched,
        anonymous_bytes,
        non_allocator_bytes: Some(non_allocator_bytes),
    }
}

pub(super) fn clear_cgroup_reclaim_pressure_latch() {
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.cgroup_high_event_latched = false;
    }
}

fn json_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static PRESSURE_TEST_LOCK: Mutex<()> = Mutex::new(());

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
}
