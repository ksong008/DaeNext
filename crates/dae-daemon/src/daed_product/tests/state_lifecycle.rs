use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::thread;

fn temp_root(scope: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "daed-state-{scope}-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ))
}

fn state_artifact_snapshot(state: &Path) -> BTreeMap<String, Option<(u64, String)>> {
    [
        state.to_path_buf(),
        PathBuf::from(format!("{}-wal", state.display())),
        PathBuf::from(format!("{}-shm", state.display())),
    ]
    .into_iter()
    .map(|path| {
        let value = path
            .metadata()
            .ok()
            .map(|metadata| (metadata.len(), sha256_file_hex(&path).unwrap()));
        (path_string(&path), value)
    })
    .collect()
}

#[test]
fn state_check_is_read_only_and_does_not_create_missing_state() {
    let root = temp_root("missing");
    let state = root.join("nested").join("daed.db");
    let error = state_check_report(&state).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(!root.exists());
}

#[test]
fn state_check_rejects_corrupt_state_without_mutating_it() {
    let root = temp_root("corrupt");
    fs::create_dir_all(&root).unwrap();
    let state = root.join("daed.db");
    fs::write(&state, b"not-a-sqlite-database").unwrap();
    let before = fs::read(&state).unwrap();
    let error = state_check_report(&state).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::Other
        ),
        "{error:?}"
    );
    assert_eq!(fs::read(&state).unwrap(), before);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn healthy_state_check_reports_quick_check_and_current_version() {
    let fixture = support::FreshProductState::new("healthy-state-check");
    let report = state_check_report(fixture.state()).unwrap();
    assert_eq!(report["status"], "pass");
    assert_eq!(report["read_only"], true);
    assert_eq!(report["mutation_executed"], false);
    assert_eq!(report["quick_check"], "ok");
    assert_eq!(report["schema_version"], STATE_SCHEMA_VERSION);
}

#[test]
fn newer_schema_is_rejected_before_permission_or_content_mutation() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let fixture = support::FreshProductState::new("newer-schema");
    let state = fixture.state();
    let conn = open_state_connection(state).unwrap();
    conn.pragma_update(None, "user_version", STATE_SCHEMA_VERSION + 1)
        .unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(conn);
    #[cfg(unix)]
    fs::set_permissions(state, fs::Permissions::from_mode(0o640)).unwrap();
    let before = state_artifact_snapshot(state);

    let error = ensure_state_schema(state).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(
        error
            .to_string()
            .contains("refusing to mutate or downgrade")
    );
    assert_eq!(state_artifact_snapshot(state), before);
    #[cfg(unix)]
    assert_eq!(
        state.metadata().unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn migration_failure_rolls_back_schema_data_and_version() {
    let root = temp_root("migration-rollback");
    fs::create_dir_all(&root).unwrap();
    let state = root.join("daed.db");
    let conn = Connection::open(&state).unwrap();
    conn.execute_batch(
        "CREATE TABLE migration_sentinel(value TEXT NOT NULL);\n\
         INSERT INTO migration_sentinel(value) VALUES('before');\n\
         PRAGMA user_version = 1;",
    )
    .unwrap();
    drop(conn);

    let error = ensure_state_schema_with_precommit_failure(&state).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected state migration failure")
    );
    let conn = Connection::open(&state).unwrap();
    assert_eq!(state_schema_version(&conn).unwrap(), 1);
    assert_eq!(
        conn.query_row("SELECT value FROM migration_sentinel", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "before"
    );
    assert!(
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .unwrap()
        .is_none()
    );
    drop(conn);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_schema_callers_serialize_one_atomic_migration() {
    let root = temp_root("concurrent-migration");
    fs::create_dir_all(&root).unwrap();
    let state = root.join("daed.db");
    let conn = Connection::open(&state).unwrap();
    conn.execute_batch(
        "CREATE TABLE migration_sentinel(value TEXT NOT NULL);\n\
         INSERT INTO migration_sentinel(value) VALUES('before');\n\
         PRAGMA user_version = 1;",
    )
    .unwrap();
    drop(conn);

    let caller_count = 8;
    let barrier = Arc::new(Barrier::new(caller_count));
    let callers = (0..caller_count)
        .map(|_| {
            let state = state.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                ensure_state_schema(&state)
            })
        })
        .collect::<Vec<_>>();
    let results = callers
        .into_iter()
        .map(|caller| caller.join().expect("schema caller panicked"))
        .collect::<Vec<_>>();
    assert!(
        results.iter().all(Result::is_ok),
        "concurrent migration failures: {results:?}"
    );

    let conn = open_state_connection_read_only(&state).unwrap();
    let snapshot = validate_state_connection_read_only(&conn).unwrap();
    assert!(snapshot.schema_current);
    assert_eq!(
        conn.query_row("SELECT value FROM migration_sentinel", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "before"
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM daed_schema_migrations WHERE id = 'production-daed-product-schema'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    drop(conn);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn older_state_check_reports_migration_required_without_migrating() {
    let root = temp_root("older-read-only");
    fs::create_dir_all(&root).unwrap();
    let state = root.join("daed.db");
    let conn = Connection::open(&state).unwrap();
    conn.execute_batch(
        "CREATE TABLE migration_sentinel(value TEXT NOT NULL);\n\
         INSERT INTO migration_sentinel(value) VALUES('older');\n\
         PRAGMA user_version = 1;",
    )
    .unwrap();
    drop(conn);
    let before = state_artifact_snapshot(&state);

    let report = state_check_report(&state).unwrap();
    assert_eq!(report["status"], "pass");
    assert_eq!(report["schema_current"], false);
    assert_eq!(report["migration_required"], true);
    assert_eq!(state_artifact_snapshot(&state), before);
    let conn = Connection::open(&state).unwrap();
    assert_eq!(state_schema_version(&conn).unwrap(), 1);
    drop(conn);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fresh_install_validation_does_not_manufacture_state() {
    let root = temp_root("fresh-install-validation");
    fs::create_dir_all(&root).unwrap();
    let state = root.join("daed.db");
    let report = validate_product_config_path(&root, false).unwrap();
    assert_eq!(report["statePresent"], false);
    assert_eq!(report["freshInstallStateOptional"], true);
    assert!(!state.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn runtime_validation_uses_explicit_state_and_does_not_mutate_it() {
    let config_root = temp_root("custom-state-config");
    fs::create_dir_all(&config_root).unwrap();
    let fixture = support::FreshProductState::new("custom-state-db");
    fixture.seed_selected_resources();
    let before = state_artifact_snapshot(fixture.state());

    let report =
        validate_product_config_dir_with_state(&config_root, true, Some(fixture.state())).unwrap();
    assert_eq!(report["state"], path_string(fixture.state()));
    assert_eq!(report["stateExplicit"], true);
    assert_eq!(report["stateQuickCheck"], "ok");
    assert_eq!(report["readOnly"], true);
    assert_eq!(report["mutationExecuted"], false);
    assert!(!config_root.join("daed.db").exists());
    assert_eq!(state_artifact_snapshot(fixture.state()), before);
    fs::remove_dir_all(config_root).unwrap();
}

#[test]
fn validate_parser_accepts_explicit_state_path() {
    let options = parse_validate_args(&[
        "--config=/etc/daed".to_owned(),
        "--state=/var/lib/daed/custom.db".to_owned(),
        "--runtime".to_owned(),
        "--json".to_owned(),
    ])
    .unwrap();
    assert_eq!(options.path, PathBuf::from("/etc/daed"));
    assert_eq!(
        options.state,
        Some(PathBuf::from("/var/lib/daed/custom.db"))
    );
    assert!(options.runtime);
    assert!(options.json_output);
}
