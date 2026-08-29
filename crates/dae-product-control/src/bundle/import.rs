use super::*;

mod validate;
mod write;

use validate::prepare_bundle_import;
use write::{
    clear_bundle_resources, mark_imported_bundle_modified_if_running, write_bundle_resources,
    write_bundle_selected, write_user_storage,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBundleOutcome {
    pub imported: bool,
    pub runtime_reload_required: bool,
}

pub fn import_bundle(
    state: &Path,
    body: &Value,
    user: &UserRecord,
) -> io::Result<ImportBundleOutcome> {
    ensure_state_schema(state)?;
    let prepared = prepare_bundle_import(body, user)?;
    let mut conn = open_state_connection(state)?;
    ensure_import_user_exists(&conn, user.id())?;
    let running_state = running_runtime_state(&conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    clear_bundle_resources(&tx)?;
    write_bundle_resources(&tx, body)?;
    write_bundle_selected(&tx, body)?;
    if running_state.is_some() {
        mark_imported_bundle_modified_if_running(&tx)?;
    }
    write_user_storage(&tx, user.id(), &prepared.user_storage)?;
    tx.commit().map_err(sqlite_io_error)?;

    Ok(ImportBundleOutcome {
        imported: true,
        runtime_reload_required: running_state.is_some(),
    })
}

fn ensure_import_user_exists(conn: &Connection, user_id: i64) -> io::Result<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM users WHERE id = ?1",
            params![user_id],
            |_| Ok(()),
        )
        .optional()
        .map_err(sqlite_io_error)?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "bundle import user no longer exists",
        ))
    }
}
