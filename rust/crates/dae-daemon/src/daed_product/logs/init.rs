use super::*;
pub(crate) static LOG_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
pub(crate) static LOG_LAST_ID_CACHE: OnceLock<Mutex<Option<ProductLogIdCache>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct ProductLogIdCache {
    pub(super) path: PathBuf,
    pub(super) id: u64,
}

pub(crate) fn initialize_log_store(config_dir: &Path, state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    ensure_log_dir(config_dir)?;
    let log_file = product_log_file(config_dir);
    if log_file.exists() {
        set_log_file_permissions(&log_file)?;
        let conn = open_state_connection(state)?;
        prune_log_file(config_dir, &conn)?;
        reset_log_id_cache_to_last(&log_file)?;
    }
    Ok(())
}

pub(crate) fn register_resident_event_product_log_sink(config_dir: &Path, state: &Path) {
    let config_dir = config_dir.to_path_buf();
    let state = state.to_path_buf();
    set_resident_event_log_sink(Some(Arc::new(move |event| {
        let _ = append_resident_event_product_log(&config_dir, &state, event);
    })));
}

#[cfg(test)]
pub(crate) fn clear_resident_event_product_log_sink() {
    set_resident_event_log_sink(None);
}
