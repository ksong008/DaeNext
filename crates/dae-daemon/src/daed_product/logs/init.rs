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
    clear_log_file_preserving_startup_reload_logs(config_dir)?;
    let conn = open_state_connection(state)?;
    prune_log_file(config_dir, &conn)
}

pub(crate) fn register_resident_event_product_log_sink(config_dir: &Path, state: &Path) {
    let _ = refresh_resident_event_log_policy(config_dir, state);
    let config_dir = config_dir.to_path_buf();
    let state = state.to_path_buf();
    set_resident_event_log_sink(Some(Arc::new(move |event| {
        let _ = append_resident_event_product_log(&config_dir, &state, event);
    })));
}

pub(crate) fn refresh_resident_event_log_policy(config_dir: &Path, state: &Path) -> io::Result<()> {
    let policy = ProductLogPolicy::load(state)?;
    if let Some(runtime) = product_log_runtime_for(config_dir) {
        runtime.replace_policy(policy.clone())?;
    }
    let ProductLogPolicy {
        runtime_level,
        max_entries,
        max_bytes,
    } = policy;
    let value_runtime_level = runtime_level.clone();
    let value_policy = Arc::new(move |event: &Value| {
        let event_name = event.get("event").and_then(Value::as_str).unwrap_or("");
        let level = if event_name.is_empty() {
            "debug"
        } else {
            resident_event_product_log_level(event_name, event)
        };
        ResidentEventLogDecision {
            persist: log_level_enabled(level, &value_runtime_level),
            level: Some(level.to_owned()),
            max_entries: max_entries as usize,
            max_bytes: max_bytes as u64,
        }
    });
    let prefilter_policy = Arc::new(move |metadata: ResidentEventMetadata| {
        let level = resident_event_product_log_level_from_metadata(metadata);
        ResidentEventLogDecision {
            persist: log_level_enabled(level, &runtime_level),
            level: Some(level.to_owned()),
            max_entries: max_entries as usize,
            max_bytes: max_bytes as u64,
        }
    });
    set_resident_event_log_policies(Some(value_policy), Some(prefilter_policy));
    Ok(())
}

pub(crate) fn refresh_log_policy_and_reset_logs(
    config_dir: &Path,
    state: &Path,
    runtime: Option<&ProductRuntimeManager>,
) -> io::Result<()> {
    refresh_resident_event_log_policy(config_dir, state)?;
    clear_log_file(config_dir)?;
    if let Some(runtime) = runtime {
        runtime.clear_resident_event_log()?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn refresh_log_policy_and_reset_runtime_cycle_logs(
    config_dir: &Path,
    state: &Path,
    runtime: Option<&ProductRuntimeManager>,
) -> io::Result<()> {
    refresh_resident_event_log_policy(config_dir, state)?;
    clear_log_file_preserving_startup_reload_logs(config_dir)?;
    apply_log_limits_without_runtime(config_dir, state)?;
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
    refresh_resident_event_log_policy(config_dir, state)?;
    apply_log_limits_without_runtime(config_dir, state)?;
    if let Some(runtime) = runtime {
        runtime.prune_resident_event_log()?;
    }
    Ok(())
}

fn apply_log_limits_without_runtime(config_dir: &Path, state: &Path) -> io::Result<()> {
    if product_log_runtime_for(config_dir).is_some() {
        return Ok(());
    }
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    prune_log_file(config_dir, &conn)
}

#[cfg(test)]
pub(crate) fn clear_resident_event_product_log_sink() {
    set_resident_event_log_sink(None);
    set_resident_event_log_policies(None, None);
}
