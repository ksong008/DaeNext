use super::*;

pub(in crate::daed_product) fn stop_runtime_and_persist(
    state: &Path,
    runtime: &ProductRuntimeManager,
) -> Result<Value, String> {
    ensure_state_schema(state).map_err(|err| format!("prepare runtime stop state: {err}"))?;
    let prepared = runtime.prepare_stop()?;
    persist_system_stopped(state).map_err(|err| format!("persist runtime stop state: {err}"))?;
    Ok(prepared.commit_background())
}

#[cfg(test)]
pub(in crate::daed_product) fn mark_system_stopped(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    persist_system_stopped(state)
}

fn persist_system_stopped(state: &Path) -> io::Result<()> {
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let updated = tx
        .execute("UPDATE systems SET running = 0", [])
        .map_err(sqlite_io_error)?;
    if updated == 0 {
        tx.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
             VALUES(0, 0, 0, 0, 0, '')",
            [],
        )
        .map_err(sqlite_io_error)?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES('runtime_running', 'false')",
        [],
    )
    .map_err(sqlite_io_error)?;
    tx.execute(
        "DELETE FROM daed_product_metadata WHERE key = ?1",
        params![RUNTIME_PROCESS_TRANSITION_METADATA_KEY],
    )
    .map_err(sqlite_io_error)?;
    tx.execute(
        "DELETE FROM daed_product_metadata WHERE key = ?1",
        params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
    )
    .map_err(sqlite_io_error)?;
    tx.commit().map_err(sqlite_io_error)
}
