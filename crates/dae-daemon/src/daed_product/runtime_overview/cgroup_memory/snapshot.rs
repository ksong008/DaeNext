use super::*;

const CGROUP_MEMORY_CURRENT_FILE: &str = "memory.current";
const CGROUP_MEMORY_PEAK_FILE: &str = "memory.peak";
const CGROUP_MEMORY_MAX_FILE: &str = "memory.max";
const CGROUP_MEMORY_HIGH_FILE: &str = "memory.high";
const CGROUP_MEMORY_EVENTS_FILE: &str = "memory.events";
const CGROUP_MEMORY_PRESSURE_FILE: &str = "memory.pressure";
const CGROUP_MEMORY_STAT_FILE: &str = "memory.stat";
const CGROUP_MEMORY_STAT_FIELDS: &[&str] = &[
    "anon",
    "file",
    "kernel",
    "kernel_stack",
    "pagetables",
    "percpu",
    "sock",
    "shmem",
    "slab",
    "vmalloc",
    "file_mapped",
    "file_dirty",
    "file_writeback",
];

pub(super) fn read_cgroup_memory_snapshot(
    location: &CgroupMemoryLocation,
    generation: u64,
) -> io::Result<Value> {
    let current_bytes = read_cgroup_required_bytes(&location.path, CGROUP_MEMORY_CURRENT_FILE)?;
    let peak_bytes = read_cgroup_required_bytes(&location.path, CGROUP_MEMORY_PEAK_FILE).ok();
    let max_bytes = read_cgroup_optional_limit(&location.path, CGROUP_MEMORY_MAX_FILE)?;
    let high_bytes = read_cgroup_optional_limit(&location.path, CGROUP_MEMORY_HIGH_FILE)?;
    let events =
        read_cgroup_key_values(&location.path, CGROUP_MEMORY_EVENTS_FILE).unwrap_or_default();
    let pressure = read_bounded_cgroup_file(&location.path.join(CGROUP_MEMORY_PRESSURE_FILE))
        .unwrap_or_default();
    let stat = read_cgroup_memory_stat(&location.path).unwrap_or_default();
    let usage_ratio = max_bytes
        .filter(|max_bytes| *max_bytes > 0)
        .map(|max_bytes| (current_bytes as f64 / max_bytes as f64 * 10_000.0).round() / 10_000.0);

    Ok(json!({
        "available": true,
        "version": CGROUP_V2_VERSION,
        "locationGeneration": generation,
        "path": location.path.display().to_string(),
        "cgroupPath": location.cgroup_path,
        "mountPoint": location.mount_point,
        "currentBytes": current_bytes.to_string(),
        "peakBytes": peak_bytes.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "maxBytes": max_bytes.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "highBytes": high_bytes.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "usageRatio": usage_ratio.map(Value::from).unwrap_or(Value::Null),
        "events": cgroup_key_values_json(&events),
        "pressure": pressure,
        "stat": cgroup_key_values_json(&stat),
    }))
}

fn read_cgroup_memory_stat(path: &Path) -> io::Result<BTreeMap<String, u64>> {
    let content = read_bounded_cgroup_file(&path.join(CGROUP_MEMORY_STAT_FILE))?;
    let raw = parse_cgroup_key_values(&content);
    Ok(CGROUP_MEMORY_STAT_FIELDS
        .iter()
        .filter_map(|field| raw.get(*field).map(|value| ((*field).to_owned(), *value)))
        .collect())
}
