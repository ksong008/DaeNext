use super::*;

pub(in crate::daed_product::geodata) fn runtime_external_input_version_if_running(
    app: &AppState,
) -> io::Result<Option<i64>> {
    let running = app
        .runtime
        .inner
        .lock()
        .map(|inner| inner.runtime.is_some())
        .unwrap_or(false);
    if !running {
        return Ok(None);
    }
    ensure_state_schema(&app.state)?;
    let conn = open_state_connection(&app.state)?;
    current_runtime_external_input_version(&conn).map(Some)
}

pub(super) fn ensure_runtime_external_input_bumped(
    state: &Path,
    version_before: Option<i64>,
) -> io::Result<()> {
    let Some(version_before) = version_before else {
        return Ok(());
    };
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let current = current_runtime_external_input_version(&tx)?;
    if current < version_before {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime external input version moved backwards from {version_before} to {current}"
            ),
        ));
    }
    if current == version_before {
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    tx.commit().map_err(sqlite_io_error)
}
