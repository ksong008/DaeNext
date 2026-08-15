use super::*;
use std::sync::OnceLock;

#[path = "auto/cgroup.rs"]
mod cgroup;
use self::cgroup::*;
#[path = "auto/host.rs"]
mod host;
use self::host::*;
#[cfg(test)]
#[path = "auto/tests.rs"]
mod tests;

pub(super) const RESIDENT_RUNTIME_PROFILE_AUTO: &str = "auto";
pub(super) const MEBIBYTE: u64 = 1024 * 1024;
pub(super) const GIBIBYTE: u64 = 1024 * MEBIBYTE;
pub(super) const AUTO_LOW_MEMORY_MAX_BYTES: u64 = 512 * MEBIBYTE;
pub(super) const AUTO_HIGH_PERFORMANCE_LOWER_BOUND_BYTES: u64 = 8 * GIBIBYTE;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AutomaticProfileDecision {
    profile: ResidentRuntimeProfile,
    source: &'static str,
    capacity_source: Option<&'static str>,
    effective_memory_bytes: Option<u64>,
    host_memory_bytes: Option<u64>,
    cgroup_limit_bytes: Option<u64>,
}

impl AutomaticProfileDecision {
    pub(super) fn into_selection(
        self,
        invalid_value: Option<String>,
    ) -> ResidentRuntimeProfileSelection {
        ResidentRuntimeProfileSelection {
            profile: self.profile,
            source: if invalid_value.is_some() {
                "invalid-env-auto"
            } else {
                self.source
            },
            capacity_source: self.capacity_source,
            effective_memory_bytes: self.effective_memory_bytes,
            host_memory_bytes: self.host_memory_bytes,
            cgroup_limit_bytes: self.cgroup_limit_bytes,
            invalid_value,
        }
    }
}

static AUTOMATIC_PROFILE_DECISION: OnceLock<AutomaticProfileDecision> = OnceLock::new();

pub(super) fn automatic_profile_decision() -> AutomaticProfileDecision {
    AUTOMATIC_PROFILE_DECISION
        .get_or_init(|| {
            let host_memory_bytes = read_host_memory_bytes().ok();
            let cgroup_limit = read_process_cgroup_memory_limit().ok().flatten();
            automatic_profile_decision_for_capacities(host_memory_bytes, cgroup_limit)
        })
        .clone()
}

pub(super) fn automatic_memory_capacity() -> Option<(u64, &'static str)> {
    let decision = automatic_profile_decision();
    decision
        .effective_memory_bytes
        .zip(decision.capacity_source)
}

pub(super) fn automatic_profile_decision_for_capacities(
    host_memory_bytes: Option<u64>,
    cgroup_limit: Option<(u64, &'static str)>,
) -> AutomaticProfileDecision {
    let cgroup_limit_bytes = cgroup_limit.map(|(bytes, _)| bytes);
    let (effective_memory_bytes, capacity_source) = match (host_memory_bytes, cgroup_limit) {
        (Some(host), Some((limit, source))) if limit < host => (Some(limit), Some(source)),
        (Some(host), _) => (Some(host), Some(HOST_MEMORY_CAPACITY_SOURCE)),
        (None, Some((limit, source))) => (Some(limit), Some(source)),
        (None, None) => (None, None),
    };
    let profile = effective_memory_bytes
        .map(profile_for_memory_capacity)
        .unwrap_or(ResidentRuntimeProfile::Balanced);
    AutomaticProfileDecision {
        profile,
        source: if effective_memory_bytes.is_some() {
            "auto"
        } else {
            "auto-fallback"
        },
        capacity_source,
        effective_memory_bytes,
        host_memory_bytes,
        cgroup_limit_bytes,
    }
}

fn profile_for_memory_capacity(memory_bytes: u64) -> ResidentRuntimeProfile {
    if memory_bytes <= AUTO_LOW_MEMORY_MAX_BYTES {
        ResidentRuntimeProfile::LowMemory
    } else if memory_bytes >= AUTO_HIGH_PERFORMANCE_LOWER_BOUND_BYTES {
        ResidentRuntimeProfile::HighPerformance
    } else {
        ResidentRuntimeProfile::Balanced
    }
}
