use super::*;

#[derive(Clone, Copy, Debug)]
pub(in crate::daed_product::geodata) struct RuntimeInputVersions {
    pub(in crate::daed_product::geodata) external: i64,
    pub(in crate::daed_product::geodata) geodata: i64,
}

pub(in crate::daed_product::geodata) fn runtime_input_versions_if_running(
    context: &ProductGeodataUpdateContext,
) -> io::Result<Option<RuntimeInputVersions>> {
    let running = context
        .runtime
        .inner
        .lock()
        .map(|inner| inner.runtime.is_some())
        .unwrap_or(false);
    if !running {
        return Ok(None);
    }
    ensure_state_schema(&context.state)?;
    let conn = open_state_connection(&context.state)?;
    Ok(Some(RuntimeInputVersions {
        external: current_runtime_external_input_version(&conn)?,
        geodata: current_runtime_geodata_input_version(&conn)?,
    }))
}

pub(super) fn ensure_runtime_input_versions_bumped(
    state: &Path,
    versions_before: Option<RuntimeInputVersions>,
) -> io::Result<()> {
    let Some(versions_before) = versions_before else {
        return Ok(());
    };
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let current_external = current_runtime_external_input_version(&tx)?;
    if current_external < versions_before.external {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime external input version moved backwards from {} to {current_external}",
                versions_before.external
            ),
        ));
    }
    let current_geodata = current_runtime_geodata_input_version(&tx)?;
    if current_geodata < versions_before.geodata {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime geodata input version moved backwards from {} to {current_geodata}",
                versions_before.geodata
            ),
        ));
    }
    if current_external == versions_before.external {
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    if current_geodata == versions_before.geodata {
        bump_runtime_geodata_input_version_with_connection(&tx)?;
    }
    tx.commit().map_err(sqlite_io_error)
}
