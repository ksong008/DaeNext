use super::*;

#[test]
fn parses_cgroup_v2_location_from_proc_files() {
    let cgroup = "0::/system.slice/daed.service\n";
    let mountinfo =
        "36 25 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
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
    let mountinfo = "36 25 0:31 / /sys/fs/cgroup\\040test rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
    let location = resolve_cgroup_memory_location_from_strs(cgroup, mountinfo).unwrap();
    assert_eq!(location.mount_point, "/sys/fs/cgroup test");
    assert_eq!(location.path, PathBuf::from("/sys/fs/cgroup test"));
}

#[test]
fn parses_optional_memory_limits_and_key_values() {
    assert_eq!(parse_cgroup_optional_limit("max"), Some(None));
    assert_eq!(
        parse_cgroup_optional_limit("536870912"),
        Some(Some(536870912))
    );
    assert_eq!(parse_cgroup_optional_limit("invalid"), None);
    let values = parse_cgroup_key_values("anon 1024\nfile 2048\nbad nope\n");
    assert_eq!(values.get("anon"), Some(&1024));
    assert_eq!(values.get("file"), Some(&2048));
    assert!(!values.contains_key("bad"));
}

#[test]
fn failed_location_is_retried_after_the_short_ttl() {
    let now = Instant::now();
    let location = test_location("/next");
    let mut cache = CgroupMemoryLocationCache::default();
    let mut calls = 0_u64;
    let first = cache.resolve(now, false, || {
        calls += 1;
        Err("not ready".to_owned())
    });
    assert!(first.result.is_err());
    let cached = cache.resolve(now + Duration::from_millis(500), false, || {
        calls += 1;
        Ok(location.clone())
    });
    assert!(cached.result.is_err());
    assert_eq!(calls, 1);

    let recovered = cache.resolve(now + CGROUP_MEMORY_LOCATION_FAILURE_TTL, false, || {
        calls += 1;
        Ok(location.clone())
    });
    assert_eq!(recovered.result, Ok(location));
    assert_eq!(recovered.generation, 2);
    assert_eq!(calls, 2);
}

#[test]
fn successful_location_refreshes_after_ttl_or_immediately_when_forced() {
    let now = Instant::now();
    let first_location = test_location("/first");
    let second_location = test_location("/second");
    let mut cache = CgroupMemoryLocationCache::default();
    let first = cache.resolve(now, false, || Ok(first_location.clone()));
    assert_eq!(first.generation, 1);
    let cached = cache.resolve(now + Duration::from_secs(1), false, || {
        Ok(second_location.clone())
    });
    assert_eq!(cached.result, Ok(first_location.clone()));
    let forced = cache.resolve(now + Duration::from_secs(1), true, || {
        Ok(second_location.clone())
    });
    assert_eq!(forced.result, Ok(second_location.clone()));
    assert_eq!(forced.generation, 2);

    let third_location = test_location("/third");
    let refreshed = cache.resolve(
        now + Duration::from_secs(1) + CGROUP_MEMORY_LOCATION_SUCCESS_TTL,
        false,
        || Ok(third_location.clone()),
    );
    assert_eq!(refreshed.result, Ok(third_location));
    assert_eq!(refreshed.generation, 3);
}

#[test]
fn snapshot_read_failure_forces_location_refresh_and_recovers() {
    let root = std::env::temp_dir().join(format!(
        "daed-cgroup-memory-migration-{}",
        fastrand::u64(..)
    ));
    let old = test_location_for_root(&root, "old");
    let new = test_location_for_root(&root, "new");
    write_memory_fixture(&new.path, 1234);
    let mut forced = false;
    let value = cgroup_memory_snapshot_from_resolver(|force| {
        forced |= force;
        CgroupMemoryLocationResolution {
            generation: if force { 2 } else { 1 },
            result: Ok(if force { new.clone() } else { old.clone() }),
        }
    });

    assert!(forced);
    assert_eq!(value["available"], json!(true));
    assert_eq!(value["locationGeneration"], json!(2));
    assert_eq!(value["path"], json!(new.path.display().to_string()));
    assert_eq!(value["currentBytes"], json!("1234"));
    assert_eq!(value["peakBytes"], json!("1334"));
    fs::remove_dir_all(root).unwrap();
}

fn test_location(cgroup_path: &str) -> CgroupMemoryLocation {
    CgroupMemoryLocation {
        path: PathBuf::from("/sys/fs/cgroup").join(cgroup_path.trim_start_matches('/')),
        cgroup_path: cgroup_path.to_owned(),
        mount_point: "/sys/fs/cgroup".to_owned(),
    }
}

fn test_location_for_root(root: &Path, name: &str) -> CgroupMemoryLocation {
    CgroupMemoryLocation {
        path: root.join(name),
        cgroup_path: format!("/{name}"),
        mount_point: root.display().to_string(),
    }
}

fn write_memory_fixture(path: &Path, current: u64) {
    fs::create_dir_all(path).unwrap();
    fs::write(path.join("memory.current"), current.to_string()).unwrap();
    fs::write(
        path.join("memory.peak"),
        current.saturating_add(100).to_string(),
    )
    .unwrap();
    fs::write(path.join("memory.max"), "4096\n").unwrap();
    fs::write(path.join("memory.high"), "max\n").unwrap();
    fs::write(path.join("memory.events"), "oom 0\n").unwrap();
    fs::write(path.join("memory.pressure"), "some avg10=0.00 total=0\n").unwrap();
    fs::write(path.join("memory.stat"), "anon 512\nfile 128\n").unwrap();
}
