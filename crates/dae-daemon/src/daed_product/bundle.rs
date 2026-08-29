use std::io;
use std::path::Path;

use dae_product_control::{
    ImportBundleOutcome, export_bundle as export_product_bundle,
    import_bundle as import_product_bundle,
};
use serde_json::Value;

use super::{UserRecord, append_log_for_config};

pub(super) fn export_bundle(state: &Path, user: &UserRecord) -> io::Result<Value> {
    export_product_bundle(state, user)
}

pub(super) fn import_bundle(
    state: &Path,
    config_dir: &Path,
    body: &Value,
    user: &UserRecord,
) -> io::Result<ImportBundleOutcome> {
    let outcome = import_product_bundle(state, body, user)?;
    let _ = append_log_for_config(
        config_dir,
        state,
        "info",
        "DAE bundle imported by Rust daed",
    );
    Ok(outcome)
}
