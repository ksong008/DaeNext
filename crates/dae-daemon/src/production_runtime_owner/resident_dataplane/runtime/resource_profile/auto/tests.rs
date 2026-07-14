use super::*;
use std::path::PathBuf;

#[test]
fn automatic_profile_uses_stable_memory_boundaries() {
    assert_eq!(
        profile_for_memory_capacity(AUTO_LOW_MEMORY_MAX_BYTES),
        ResidentRuntimeProfile::LowMemory
    );
    assert_eq!(
        profile_for_memory_capacity(AUTO_LOW_MEMORY_MAX_BYTES + 1),
        ResidentRuntimeProfile::Balanced
    );
    assert_eq!(
        profile_for_memory_capacity(AUTO_HIGH_PERFORMANCE_LOWER_BOUND_BYTES - 1),
        ResidentRuntimeProfile::Balanced
    );
    assert_eq!(
        profile_for_memory_capacity(AUTO_HIGH_PERFORMANCE_LOWER_BOUND_BYTES),
        ResidentRuntimeProfile::HighPerformance
    );
}

#[test]
fn automatic_profile_uses_the_smallest_effective_capacity() {
    let limited = automatic_profile_decision_for_capacities(
        Some(16 * GIBIBYTE),
        Some((512 * MEBIBYTE, "cgroup-v2-memory.max")),
    );
    assert_eq!(limited.profile, ResidentRuntimeProfile::LowMemory);
    assert_eq!(limited.effective_memory_bytes, Some(512 * MEBIBYTE));
    assert_eq!(limited.capacity_source, Some("cgroup-v2-memory.max"));

    let host_limited = automatic_profile_decision_for_capacities(
        Some(512 * MEBIBYTE),
        Some((16 * GIBIBYTE, "cgroup-v2-memory.max")),
    );
    assert_eq!(host_limited.profile, ResidentRuntimeProfile::LowMemory);
    assert_eq!(
        host_limited.capacity_source,
        Some(HOST_MEMORY_CAPACITY_SOURCE)
    );

    let unavailable = automatic_profile_decision_for_capacities(None, None);
    assert_eq!(unavailable.profile, ResidentRuntimeProfile::Balanced);
    assert_eq!(unavailable.source, "auto-fallback");
}

#[test]
fn parses_host_memtotal_without_using_available_memory() {
    let meminfo = "MemTotal:         494436 kB\nMemAvailable:     400000 kB\n";
    assert_eq!(parse_memtotal_bytes(meminfo), Some(494436 * 1024));
    assert_eq!(parse_memtotal_bytes("MemAvailable: 10 kB\n"), None);
}

#[test]
fn resolves_v2_and_v1_memory_limit_paths() {
    let v2_cgroup = "0::/system.slice/daed.service\n";
    let v2_mount = "36 25 0:31 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n";
    assert_eq!(
        resolve_memory_limit_path(v2_cgroup, v2_mount),
        Some((
            PathBuf::from("/sys/fs/cgroup/system.slice/daed.service"),
            "cgroup-v2-memory.max",
            "memory.max",
        ))
    );

    let v1_cgroup = "5:cpu:/slice\n7:memory:/limited/daed\n";
    let v1_mount = "41 25 0:37 /limited /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n";
    assert_eq!(
        resolve_memory_limit_path(v1_cgroup, v1_mount),
        Some((
            PathBuf::from("/sys/fs/cgroup/memory/daed"),
            "cgroup-v1-memory.limit_in_bytes",
            "memory.limit_in_bytes",
        ))
    );
}

#[test]
fn parses_cgroup_limits_and_unlimited_values() {
    assert_eq!(parse_memory_limit("max", "memory.max").unwrap(), None);
    assert_eq!(
        parse_memory_limit("536870912", "memory.max").unwrap(),
        Some(536870912)
    );
    assert_eq!(
        parse_memory_limit(
            &CGROUP_V1_UNLIMITED_THRESHOLD.to_string(),
            "memory.limit_in_bytes"
        )
        .unwrap(),
        None
    );
}
