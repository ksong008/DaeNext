use super::*;

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

#[cfg(test)]
pub(crate) fn clear_resident_event_product_log_sink() {
    set_resident_event_log_sink(None);
    set_resident_event_log_policies(None, None);
}
