use super::*;
use crate::production_runtime_owner::EffectiveProcessMemoryCapacity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AllocatorIdleReclaimPressureThreshold {
    pub(super) bytes: u64,
    pub(super) source: &'static str,
    pub(super) capacity_bytes: Option<u64>,
    pub(super) capacity_source: Option<&'static str>,
}

pub(super) fn allocator_idle_reclaim_pressure_threshold(
    configured_bytes: u64,
    configured_source: &'static str,
    capacity: Option<EffectiveProcessMemoryCapacity>,
) -> AllocatorIdleReclaimPressureThreshold {
    if configured_source != "default" {
        return AllocatorIdleReclaimPressureThreshold {
            bytes: configured_bytes,
            source: configured_source,
            capacity_bytes: capacity.map(EffectiveProcessMemoryCapacity::bytes),
            capacity_source: capacity.map(EffectiveProcessMemoryCapacity::source),
        };
    }
    let Some(capacity) = capacity else {
        return AllocatorIdleReclaimPressureThreshold {
            bytes: configured_bytes,
            source: "default",
            capacity_bytes: None,
            capacity_source: None,
        };
    };
    let bytes = (capacity.bytes() / ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_CAPACITY_DIVISOR).clamp(
        ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_MIN,
        ALLOCATOR_IDLE_RECLAIM_AUTO_PRESSURE_MAX_BYTES,
    );
    AllocatorIdleReclaimPressureThreshold {
        bytes,
        source: "auto-capacity",
        capacity_bytes: Some(capacity.bytes()),
        capacity_source: Some(capacity.source()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn capacity(mib: u64) -> EffectiveProcessMemoryCapacity {
        EffectiveProcessMemoryCapacity::new(mib * MIB, "fixture-capacity")
    }

    #[test]
    fn automatic_pressure_threshold_is_capacity_derived_and_bounded() {
        let low = allocator_idle_reclaim_pressure_threshold(
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT,
            "default",
            Some(capacity(512)),
        );
        let balanced = allocator_idle_reclaim_pressure_threshold(
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT,
            "default",
            Some(capacity(4 * 1024)),
        );
        let high = allocator_idle_reclaim_pressure_threshold(
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT,
            "default",
            Some(capacity(16 * 1024)),
        );

        assert_eq!(low.bytes, 4 * MIB);
        assert_eq!(balanced.bytes, 16 * MIB);
        assert_eq!(high.bytes, 32 * MIB);
        assert_eq!(balanced.source, "auto-capacity");
        assert_eq!(balanced.capacity_source, Some("fixture-capacity"));
    }

    #[test]
    fn explicit_pressure_threshold_precedes_detected_capacity() {
        for source in ["env", "config"] {
            let selected =
                allocator_idle_reclaim_pressure_threshold(48 * MIB, source, Some(capacity(512)));
            assert_eq!(selected.bytes, 48 * MIB);
            assert_eq!(selected.source, source);
        }
    }

    #[test]
    fn missing_capacity_keeps_the_conservative_default() {
        let selected = allocator_idle_reclaim_pressure_threshold(
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT,
            "default",
            None,
        );
        assert_eq!(
            selected.bytes,
            ALLOCATOR_IDLE_RECLAIM_PRESSURE_BYTES_DEFAULT
        );
        assert_eq!(selected.source, "default");
        assert_eq!(selected.capacity_bytes, None);
    }
}
