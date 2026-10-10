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

pub(crate) fn publish_resident_memory_pressure(snapshot: &Value) {
    dae_resident_dataplane::facade::set_resident_memory_pressure(resident_pressure_from_snapshot(
        snapshot,
    ));
}

fn resident_pressure_from_snapshot(snapshot: &Value) -> bool {
    if snapshot.get("available").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    let current = json_u64(snapshot.get("currentBytes"));
    let limit = [
        json_u64(snapshot.get("highBytes")),
        json_u64(snapshot.get("maxBytes")),
    ]
    .into_iter()
    .flatten()
    .min();
    current.zip(limit).is_some_and(|(current, limit)| {
        limit > 0 && current.saturating_mul(1000) / limit >= CGROUP_RECLAIM_URGENT_USAGE_PERMILLE
    })
}

pub(super) fn observe_cgroup_reclaim_pressure() -> CgroupReclaimPressure {
    let snapshot = cgroup_memory_snapshot_json();
    publish_resident_memory_pressure(&snapshot);
    cgroup_reclaim_pressure_from_snapshot(&snapshot, true)
}

pub(super) fn cgroup_reclaim_pressure_from_snapshot(
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
#[path = "pressure_tests.rs"]
mod tests;
