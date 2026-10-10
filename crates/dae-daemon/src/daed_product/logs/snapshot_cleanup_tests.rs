use super::*;
#[test]
fn cleanup_keeps_live_pins_and_ignores_symlinks() {
    let dir = std::env::temp_dir().join(format!("daed-pin-cleanup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let dead = dir.join(".daed-log-snapshot-2147483647-1");
    let live = dir.join(format!(".daed-log-snapshot-{}-2", std::process::id()));
    let outside = dir.join("outside");
    let expired = dir.join(format!(".daed-log-snapshot-{}-4", std::process::id()));
    fs::create_dir(&expired).unwrap();
    fs::File::open(&expired)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
        .unwrap();
    fs::create_dir(&dead).unwrap();
    fs::create_dir(&live).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(dead.join("old-pin"), b"old").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join(".daed-log-snapshot-2147483647-3")).unwrap();
    assert_eq!(cleanup_abandoned_snapshots(&dir).unwrap(), 2);
    assert!(!expired.exists());
    assert!(!dead.exists());
    assert!(live.exists());
    assert!(outside.exists());
    fs::remove_dir_all(dir).unwrap();
}
