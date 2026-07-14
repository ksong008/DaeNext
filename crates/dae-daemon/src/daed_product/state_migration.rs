use super::*;

static STATE_SCHEMA_MIGRATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StateMigrationFault {
    None,
    BeforeCommit,
}

pub(super) fn ensure_state_schema(path: &Path) -> io::Result<()> {
    ensure_state_schema_with_fault(path, StateMigrationFault::None)
}

fn ensure_state_schema_with_fault(path: &Path, fault: StateMigrationFault) -> io::Result<()> {
    if path.exists() {
        let read_only = open_state_connection_read_only(path)?;
        quick_check_state_connection(&read_only)?;
        let version = state_schema_version(&read_only)?;
        reject_newer_state_schema(version)?;
        if version == STATE_SCHEMA_VERSION {
            validate_state_connection_read_only(&read_only)?;
            drop(read_only);
            if let Some(parent) = path.parent() {
                set_private_state_dir_permissions(parent)?;
            }
            set_private_db_permissions(path)?;
            let conn = open_state_connection_read_write_unchecked(path)?;
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(sqlite_io_error)?;
            return Ok(());
        }
    }

    let _guard = STATE_SCHEMA_MIGRATION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| io::Error::other("state schema migration lock poisoned"))?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut conn = open_state_connection_read_write_unchecked(path)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    quick_check_state_connection(&transaction)?;
    let version = state_schema_version(&transaction)?;
    reject_newer_state_schema(version)?;
    if version != STATE_SCHEMA_VERSION {
        apply_state_schema(&transaction)?;
    }
    if fault == StateMigrationFault::BeforeCommit {
        return Err(io::Error::other(
            "injected state migration failure before commit",
        ));
    }
    transaction.commit().map_err(sqlite_io_error)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(sqlite_io_error)?;
    if let Some(parent) = path.parent() {
        set_private_state_dir_permissions(parent)?;
    }
    set_private_db_permissions(path)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn ensure_state_schema_with_precommit_failure(path: &Path) -> io::Result<()> {
    ensure_state_schema_with_fault(path, StateMigrationFault::BeforeCommit)
}

pub(super) fn migrate_wing_db(from_wing_db: &Path, to: &Path, force: bool) -> io::Result<Value> {
    if !from_wing_db.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "wing.db source does not exist: {}",
                path_string(from_wing_db)
            ),
        ));
    }
    let wing_hash_before = sha256_file_hex(from_wing_db)?;
    let target_existed = to.exists();
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    let copied = if target_existed && !force {
        false
    } else {
        fs::copy(from_wing_db, to)?;
        set_private_db_permissions(to)?;
        true
    };
    ensure_state_schema(to)?;
    let mut conn = open_state_connection(to)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    transaction
        .execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
            params!["source_wing_db_path", path_string(from_wing_db)],
        )
        .map_err(sqlite_io_error)?;
    transaction
        .execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, datetime('now'))",
            params!["last_wing_db_import_at"],
        )
        .map_err(sqlite_io_error)?;
    transaction.commit().map_err(sqlite_io_error)?;
    let wing_hash_after = sha256_file_hex(from_wing_db)?;
    let wing_db_unchanged = wing_hash_before == wing_hash_after;
    if !wing_db_unchanged {
        return Err(io::Error::other("wing.db hash changed during import"));
    }
    Ok(json!({
        "status": "pass",
        "from_wing_db": path_string(from_wing_db),
        "to": path_string(to),
        "target_existed": target_existed,
        "copied": copied,
        "force": force,
        "wing_db_sha256_before": wing_hash_before,
        "wing_db_sha256_after": wing_hash_after,
        "wing_db_unchanged": wing_db_unchanged,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_destructive": false,
    }))
}
