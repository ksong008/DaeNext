use super::*;

const CGROUP_MEMORY_SNAPSHOT_TTL: Duration = Duration::from_secs(1);
const CGROUP_FILE_READ_LIMIT: usize = 64 * 1024;
const PROC_SELF_CGROUP: &str = "/proc/self/cgroup";
const PROC_SELF_MOUNTINFO: &str = "/proc/self/mountinfo";
const CGROUP_V2_VERSION: &str = "v2";
const CGROUP_V2_MOUNT_TYPE: &str = "cgroup2";
const CGROUP_MEMORY_CURRENT_FILE: &str = "memory.current";
const CGROUP_MEMORY_MAX_FILE: &str = "memory.max";
const CGROUP_MEMORY_HIGH_FILE: &str = "memory.high";
const CGROUP_MEMORY_EVENTS_FILE: &str = "memory.events";
const CGROUP_MEMORY_PRESSURE_FILE: &str = "memory.pressure";
const CGROUP_MEMORY_STAT_FILE: &str = "memory.stat";
const CGROUP_UNLIMITED_VALUE: &str = "max";
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
    "file_mapped",
    "file_dirty",
    "file_writeback",
];

#[derive(Clone, Debug)]
struct CgroupMemoryLocation {
    path: PathBuf,
    cgroup_path: String,
    mount_point: String,
}

#[derive(Clone, Debug)]
struct CachedCgroupMemorySnapshot {
    observed_at: Instant,
    value: Value,
}

static CGROUP_MEMORY_LOCATION: OnceLock<Result<CgroupMemoryLocation, String>> = OnceLock::new();
static CGROUP_MEMORY_CACHE: OnceLock<Mutex<Option<CachedCgroupMemorySnapshot>>> = OnceLock::new();

pub(in crate::daed_product) fn cgroup_memory_snapshot_json() -> Value {
    if let Ok(mut guard) = CGROUP_MEMORY_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        let now = Instant::now();
        if let Some(cached) = guard.as_ref()
            && now.duration_since(cached.observed_at) < CGROUP_MEMORY_SNAPSHOT_TTL
        {
            return cached.value.clone();
        }
        let value = uncached_cgroup_memory_snapshot_json();
        *guard = Some(CachedCgroupMemorySnapshot {
            observed_at: now,
            value: value.clone(),
        });
        return value;
    }
    uncached_cgroup_memory_snapshot_json()
}

fn uncached_cgroup_memory_snapshot_json() -> Value {
    let location = CGROUP_MEMORY_LOCATION.get_or_init(resolve_cgroup_memory_location);
    let location = match location {
        Ok(location) => location,
        Err(reason) => {
            return json!({
                "available": false,
                "version": CGROUP_V2_VERSION,
                "reason": reason,
            });
        }
    };

    match read_cgroup_memory_snapshot(location) {
        Ok(snapshot) => snapshot,
        Err(err) => json!({
            "available": false,
            "version": CGROUP_V2_VERSION,
            "path": location.path.display().to_string(),
            "cgroupPath": location.cgroup_path,
            "mountPoint": location.mount_point,
            "reason": err.to_string(),
        }),
    }
}

fn read_cgroup_memory_snapshot(location: &CgroupMemoryLocation) -> io::Result<Value> {
    let current_bytes = read_cgroup_required_bytes(&location.path, CGROUP_MEMORY_CURRENT_FILE)?;
    let max_bytes = read_cgroup_optional_limit(&location.path, CGROUP_MEMORY_MAX_FILE)?;
    let high_bytes = read_cgroup_optional_limit(&location.path, CGROUP_MEMORY_HIGH_FILE)?;
    let events =
        read_cgroup_key_values(&location.path, CGROUP_MEMORY_EVENTS_FILE).unwrap_or_default();
    let pressure =
        read_optional_cgroup_file(&location.path, CGROUP_MEMORY_PRESSURE_FILE).unwrap_or_default();
    let stat = read_cgroup_memory_stat(&location.path).unwrap_or_default();
    let usage_ratio = max_bytes
        .filter(|max_bytes| *max_bytes > 0)
        .map(|max_bytes| (current_bytes as f64 / max_bytes as f64 * 10_000.0).round() / 10_000.0);

    Ok(json!({
        "available": true,
        "version": CGROUP_V2_VERSION,
        "path": location.path.display().to_string(),
        "cgroupPath": location.cgroup_path,
        "mountPoint": location.mount_point,
        "currentBytes": current_bytes.to_string(),
        "maxBytes": max_bytes.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "highBytes": high_bytes.map(|bytes| json!(bytes.to_string())).unwrap_or(Value::Null),
        "usageRatio": usage_ratio.map(Value::from).unwrap_or(Value::Null),
        "events": cgroup_key_values_json(&events),
        "pressure": pressure,
        "stat": cgroup_key_values_json(&stat),
    }))
}

fn resolve_cgroup_memory_location() -> Result<CgroupMemoryLocation, String> {
    resolve_cgroup_memory_location_from_files(PROC_SELF_CGROUP, PROC_SELF_MOUNTINFO)
}

fn resolve_cgroup_memory_location_from_files(
    cgroup_file: &str,
    mountinfo_file: &str,
) -> Result<CgroupMemoryLocation, String> {
    let cgroup = read_bounded_file(Path::new(cgroup_file), CGROUP_FILE_READ_LIMIT)
        .map_err(|err| format!("read {cgroup_file}: {err}"))?;
    let mountinfo = read_bounded_file(Path::new(mountinfo_file), CGROUP_FILE_READ_LIMIT)
        .map_err(|err| format!("read {mountinfo_file}: {err}"))?;
    resolve_cgroup_memory_location_from_strs(&cgroup, &mountinfo)
}

fn resolve_cgroup_memory_location_from_strs(
    cgroup: &str,
    mountinfo: &str,
) -> Result<CgroupMemoryLocation, String> {
    let cgroup_path = parse_cgroup_v2_path(cgroup)
        .ok_or_else(|| "process is not attached to a cgroup v2 hierarchy".to_owned())?;
    let mount_point = parse_cgroup_v2_mount_point(mountinfo)
        .ok_or_else(|| "cgroup v2 mount point not found".to_owned())?;
    let path = join_cgroup_path(&mount_point, &cgroup_path);
    Ok(CgroupMemoryLocation {
        path,
        cgroup_path,
        mount_point,
    })
}

fn parse_cgroup_v2_path(cgroup: &str) -> Option<String> {
    cgroup.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        match (fields.next(), fields.next(), fields.next()) {
            (Some("0"), Some(""), Some(path)) => Some(path.to_owned()),
            _ => None,
        }
    })
}

fn parse_cgroup_v2_mount_point(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let (pre_separator, post_separator) = line.split_once(" - ")?;
        let filesystem_type = post_separator.split_whitespace().next()?;
        if filesystem_type != CGROUP_V2_MOUNT_TYPE {
            return None;
        }
        let mount_point = pre_separator.split_whitespace().nth(4)?;
        Some(decode_mountinfo_path(mount_point))
    })
}

fn join_cgroup_path(mount_point: &str, cgroup_path: &str) -> PathBuf {
    let mut path = PathBuf::from(mount_point);
    for component in Path::new(cgroup_path).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {}
        }
    }
    path
}

fn decode_mountinfo_path(path: &str) -> String {
    let mut decoded = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let digits: String = chars.by_ref().take(3).collect();
        if digits.len() == 3
            && let Ok(value) = u8::from_str_radix(&digits, 8)
        {
            decoded.push(value as char);
            continue;
        }
        decoded.push('\\');
        decoded.push_str(&digits);
    }
    decoded
}

fn read_cgroup_required_bytes(path: &Path, file_name: &str) -> io::Result<u64> {
    let value = read_bounded_file(&path.join(file_name), CGROUP_FILE_READ_LIMIT)?;
    value
        .trim()
        .parse::<u64>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn read_cgroup_optional_limit(path: &Path, file_name: &str) -> io::Result<Option<u64>> {
    let value = read_bounded_file(&path.join(file_name), CGROUP_FILE_READ_LIMIT)?;
    parse_cgroup_optional_limit(value.trim())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid cgroup memory limit"))
}

fn parse_cgroup_optional_limit(value: &str) -> Option<Option<u64>> {
    if value == CGROUP_UNLIMITED_VALUE {
        Some(None)
    } else {
        value.parse::<u64>().ok().map(Some)
    }
}

fn read_optional_cgroup_file(path: &Path, file_name: &str) -> io::Result<String> {
    read_bounded_file(&path.join(file_name), CGROUP_FILE_READ_LIMIT)
}

fn read_cgroup_key_values(path: &Path, file_name: &str) -> io::Result<BTreeMap<String, u64>> {
    let content = read_bounded_file(&path.join(file_name), CGROUP_FILE_READ_LIMIT)?;
    Ok(parse_cgroup_key_values(&content))
}

fn read_cgroup_memory_stat(path: &Path) -> io::Result<BTreeMap<String, u64>> {
    let content = read_bounded_file(&path.join(CGROUP_MEMORY_STAT_FILE), CGROUP_FILE_READ_LIMIT)?;
    let raw = parse_cgroup_key_values(&content);
    Ok(CGROUP_MEMORY_STAT_FIELDS
        .iter()
        .filter_map(|field| raw.get(*field).map(|value| ((*field).to_owned(), *value)))
        .collect())
}

fn parse_cgroup_key_values(content: &str) -> BTreeMap<String, u64> {
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            let value = fields.next()?.parse::<u64>().ok()?;
            Some((key.to_owned(), value))
        })
        .collect()
}

fn cgroup_key_values_json(values: &BTreeMap<String, u64>) -> Value {
    let mut object = Map::new();
    for (key, value) in values {
        object.insert(key.clone(), json!(value));
    }
    Value::Object(object)
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut limited = file.take(max_bytes as u64 + 1);
    let mut content = String::new();
    limited.read_to_string(&mut content)?;
    if content.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cgroup file exceeds read limit",
        ));
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup_v2_location_from_proc_files() {
        let cgroup = "0::/system.slice/daed.service\n";
        let mountinfo = "\
36 25 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
        let location = resolve_cgroup_memory_location_from_strs(cgroup, mountinfo).unwrap();
        assert_eq!(location.cgroup_path, "/system.slice/daed.service");
        assert_eq!(location.mount_point, "/sys/fs/cgroup");
        assert_eq!(
            location.path,
            PathBuf::from("/sys/fs/cgroup/system.slice/daed.service")
        );
    }

    #[test]
    fn decodes_mountinfo_escaped_mount_point() {
        let cgroup = "0::/\n";
        let mountinfo = "\
36 25 0:31 / /sys/fs/cgroup\\040test rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
        let location = resolve_cgroup_memory_location_from_strs(cgroup, mountinfo).unwrap();
        assert_eq!(location.mount_point, "/sys/fs/cgroup test");
        assert_eq!(location.path, PathBuf::from("/sys/fs/cgroup test"));
    }

    #[test]
    fn parses_optional_memory_limits() {
        assert_eq!(parse_cgroup_optional_limit("max"), Some(None));
        assert_eq!(
            parse_cgroup_optional_limit("536870912"),
            Some(Some(536870912))
        );
        assert_eq!(parse_cgroup_optional_limit("invalid"), None);
    }

    #[test]
    fn parses_key_value_files_and_filters_memory_stat() {
        let values = parse_cgroup_key_values("anon 1024\nfile 2048\nbad nope\n");
        assert_eq!(values.get("anon"), Some(&1024));
        assert_eq!(values.get("file"), Some(&2048));
        assert!(!values.contains_key("bad"));
    }
}
