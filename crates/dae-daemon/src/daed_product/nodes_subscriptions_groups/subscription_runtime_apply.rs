use super::*;

#[derive(Debug, Default)]
pub(super) struct SubscriptionRuntimeApplyResult {
    pub(super) requested: bool,
    pub(super) applied: bool,
    pub(super) report: Option<Value>,
    pub(super) error: Option<String>,
}

impl SubscriptionRuntimeApplyResult {
    pub(super) fn insert_into(self, value: &mut Value) {
        let Value::Object(map) = value else {
            return;
        };
        map.insert("runtimeApplyRequested".to_owned(), json!(self.requested));
        map.insert("runtimeReloaded".to_owned(), json!(self.applied));
        map.insert(
            "runtimeReload".to_owned(),
            self.report.unwrap_or(Value::Null),
        );
        map.insert("runtimeReloadError".to_owned(), json!(self.error));
    }
}

pub(super) fn apply_runtime_after_subscription_change(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    runtime_input_changed: bool,
    source: &str,
) -> SubscriptionRuntimeApplyResult {
    if !runtime_input_changed || !runtime.is_running() {
        return SubscriptionRuntimeApplyResult::default();
    }
    match runtime_modified_for_running_runtime(state, runtime) {
        Ok(false) => return SubscriptionRuntimeApplyResult::default(),
        Err(error) => {
            return SubscriptionRuntimeApplyResult {
                requested: true,
                error: Some(error),
                ..SubscriptionRuntimeApplyResult::default()
            };
        }
        Ok(true) => {}
    }

    let reload_started_at = Instant::now();
    match restore_runtime_from_state(
        runtime,
        state,
        Some(config_dir),
        ProductRuntimeLifecycleLogMode::ReloadSubscriptionRefresh,
    ) {
        Ok(report) => {
            let applied = report["applied"].as_bool().unwrap_or(true);
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), source.to_owned());
            fields.insert("applied".to_owned(), applied.to_string());
            fields.insert(
                "elapsed".to_owned(),
                format!("{:?}", reload_started_at.elapsed()),
            );
            let _ = append_lifecycle_log_fields_for_config(
                config_dir,
                state,
                "info",
                "[Reload] Finished",
                fields,
            );
            SubscriptionRuntimeApplyResult {
                requested: true,
                applied,
                report: Some(report),
                error: None,
            }
        }
        Err(error) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), source.to_owned());
            fields.insert("error".to_owned(), error.clone());
            let _ = append_lifecycle_log_fields_for_config(
                config_dir,
                state,
                "error",
                "[Reload] Failed to reload",
                fields,
            );
            SubscriptionRuntimeApplyResult {
                requested: true,
                error: Some(format!(
                    "failed to reload runtime after subscription change: {error}"
                )),
                ..SubscriptionRuntimeApplyResult::default()
            }
        }
    }
}
