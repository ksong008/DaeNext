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
    clear_log_file(config_dir)
}

pub(crate) fn register_resident_event_product_log_sink(config_dir: &Path, state: &Path) {
    let _ = refresh_resident_event_log_policy(state);
    let config_dir = config_dir.to_path_buf();
    let state = state.to_path_buf();
    set_resident_event_log_sink(Some(Arc::new(move |event| {
        let _ = append_resident_event_product_log(&config_dir, &state, event);
    })));
}

pub(crate) fn refresh_resident_event_log_policy(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let (max_entries, max_bytes) = log_settings_tuple(&conn)?;
    let runtime_level = current_runtime_log_level(state)?;
    set_resident_event_log_policy(Some(Arc::new(move |event| {
        let event_name = event.get("event").and_then(Value::as_str).unwrap_or("");
        let level = if event_name.is_empty() {
            "debug"
        } else {
            resident_event_product_log_level(event_name, event)
        };
        ResidentEventLogDecision {
            persist: log_level_enabled(level, &runtime_level),
            level: Some(level.to_owned()),
            max_entries: max_entries as usize,
            max_bytes: max_bytes as u64,
        }
    })));
    Ok(())
}

pub(crate) fn refresh_log_policy_and_reset_logs(
    config_dir: &Path,
    state: &Path,
    runtime: Option<&ProductRuntimeManager>,
) -> io::Result<()> {
    refresh_resident_event_log_policy(state)?;
    clear_log_file(config_dir)?;
    if let Some(runtime) = runtime {
        runtime.clear_resident_event_log()?;
    }
    Ok(())
}

pub(crate) fn refresh_log_policy_and_apply_log_limits(
    config_dir: &Path,
    state: &Path,
    runtime: Option<&ProductRuntimeManager>,
) -> io::Result<()> {
    refresh_resident_event_log_policy(state)?;
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    prune_log_file(config_dir, &conn)?;
    if let Some(runtime) = runtime {
        runtime.prune_resident_event_log()?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn clear_resident_event_product_log_sink() {
    set_resident_event_log_sink(None);
    set_resident_event_log_policy(None);
}
