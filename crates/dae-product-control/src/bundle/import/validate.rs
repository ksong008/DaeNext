use super::write::{write_bundle_resources, write_bundle_selected};
use super::*;

mod shape;
mod storage;

pub(super) struct PreparedBundleImport {
    pub(super) user_storage: String,
}

pub(super) fn prepare_bundle_import(
    body: &Value,
    user: &UserRecord,
) -> io::Result<PreparedBundleImport> {
    shape::validate_bundle_shape(body)?;
    validate_bundle_in_staging_database(body)?;
    Ok(PreparedBundleImport {
        user_storage: storage::prepare_user_storage(body, user)?,
    })
}

fn validate_bundle_in_staging_database(body: &Value) -> io::Result<()> {
    let staging = Connection::open_in_memory().map_err(sqlite_io_error)?;
    apply_state_schema(&staging)?;
    write_bundle_resources(&staging, body)?;
    write_bundle_selected(&staging, body)?;
    let plan = prepare_runtime_materialization_plan_with_connection(&staging)?;
    build_runtime_config_from_content(&plan.content)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(())
}
