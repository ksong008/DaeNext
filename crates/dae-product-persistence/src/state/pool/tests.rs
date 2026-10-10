use super::*;

fn fixture() -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "daed-pool-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("state.db");
    ensure_state_schema(&path).unwrap();
    (dir, path)
}

#[test]
fn pooled_metadata_observes_external_wal_commits_and_rejects_newer_versions() {
    let (dir, path) = fixture();
    set_metadata(&path, "external", "before").unwrap();
    assert_eq!(
        get_metadata(&path, "external").unwrap().as_deref(),
        Some("before")
    );
    let external = open_state_connection(&path).unwrap();
    set_metadata_with_connection(&external, "external", "after").unwrap();
    assert_eq!(
        get_metadata(&path, "external").unwrap().as_deref(),
        Some("after")
    );
    external
        .pragma_update(None, "user_version", STATE_SCHEMA_VERSION + 1)
        .unwrap();
    let before = fs::read(&path).unwrap();
    let wal = fs::read(connection::state_sidecar_path(&path, "-wal")).unwrap();
    assert_eq!(
        get_metadata(&path, "external").unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        fs::read(connection::state_sidecar_path(&path, "-wal")).unwrap(),
        wal
    );
    drop(external);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pooled_metadata_reopens_replaced_inode_and_rejects_corruption() {
    let (dir, path) = fixture();
    set_metadata(&path, "value", "old").unwrap();
    let replacement = dir.join("replacement.db");
    let conn = open_initialized_state_connection(&replacement).unwrap();
    set_metadata_with_connection(&conn, "value", "new").unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(conn);
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(connection::state_sidecar_path(&path, suffix));
    }
    fs::rename(&replacement, &path).unwrap();
    assert_eq!(
        get_metadata(&path, "value").unwrap().as_deref(),
        Some("new")
    );
    let corrupt = dir.join("corrupt.db");
    fs::write(&corrupt, b"corrupted database").unwrap();
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(connection::state_sidecar_path(&path, suffix));
    }
    fs::rename(corrupt, &path).unwrap();
    assert!(get_metadata(&path, "value").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"corrupted database");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pooled_metadata_serializes_parallel_transactions_and_read_only_copy_includes_wal() {
    let (dir, path) = fixture();
    std::thread::scope(|scope| {
        for index in 0..8 {
            let path = &path;
            scope.spawn(move || set_metadata(path, &format!("key-{index}"), "committed").unwrap());
        }
    });
    let before = fs::read(connection::state_sidecar_path(&path, "-shm")).unwrap();
    let snapshot = open_state_connection_read_only(&path).unwrap();
    let count: i64 = snapshot
        .query_row(
            "SELECT COUNT(*) FROM daed_product_metadata WHERE key LIKE 'key-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 8);
    drop(snapshot);
    assert_eq!(
        fs::read(connection::state_sidecar_path(&path, "-shm")).unwrap(),
        before
    );
    fs::remove_dir_all(dir).unwrap();
}
