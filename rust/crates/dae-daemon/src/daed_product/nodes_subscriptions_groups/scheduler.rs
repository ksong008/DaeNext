use super::*;
pub(crate) fn start_subscription_scheduler(state: PathBuf, config_dir: PathBuf) {
    thread::spawn(move || {
        let _ = ensure_state_schema(&state);
        let _ = set_metadata(&state, "subscription_scheduler_started_at", &now_text());
        let _ = append_log_for_config(
            &config_dir,
            &state,
            "info",
            "subscription scheduler started by Rust daed",
        );
    });
}
