use super::*;

pub(in crate::daed_product) struct PreparedRuntimeReload {
    pub(in crate::daed_product) plan: RuntimeMaterializationPlan,
    pub(in crate::daed_product) config: Config,
}

pub(in crate::daed_product) struct AppliedRuntimeReload {
    pub(in crate::daed_product) runtime_report: Value,
    pub(in crate::daed_product) materialized_report: Value,
    pub(in crate::daed_product) allocator_reclaim: Value,
}

#[derive(Debug)]
pub(in crate::daed_product) enum RuntimeReloadPrepareError {
    LogPolicy(String),
    Materialize(String),
    BuildConfig(String),
    RuntimeLogLevel(String),
}

impl RuntimeReloadPrepareError {
    pub(in crate::daed_product) fn http_status(&self) -> u16 {
        match self {
            Self::Materialize(_) | Self::BuildConfig(_) => 400,
            Self::LogPolicy(_) | Self::RuntimeLogLevel(_) => 500,
        }
    }

    pub(in crate::daed_product) fn api_log_message(&self) -> &'static str {
        match self {
            Self::Materialize(_) => "[Reload] Failed to materialize runtime preview",
            Self::BuildConfig(_) => "[Reload] Failed to build runtime config",
            Self::LogPolicy(_) => "[Reload] Failed to prepare reload",
            Self::RuntimeLogLevel(_) => "[Reload] Failed to apply runtime log level",
        }
    }
}

impl std::fmt::Display for RuntimeReloadPrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LogPolicy(err)
            | Self::Materialize(err)
            | Self::BuildConfig(err)
            | Self::RuntimeLogLevel(err) => formatter.write_str(err),
        }
    }
}

pub(in crate::daed_product) fn prepare_runtime_reload_config(
    state: &Path,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let plan = prepare_runtime_materialization_plan(state)
        .map_err(|err| RuntimeReloadPrepareError::Materialize(err.to_string()))?;
    let config = build_runtime_config_from_content(&plan.content)
        .map_err(RuntimeReloadPrepareError::BuildConfig)?;
    Ok(PreparedRuntimeReload { plan, config })
}

pub(in crate::daed_product) fn prepare_runtime_reload_to_apply(
    log_config_dir: &Path,
    state: &Path,
    runtime: &ProductRuntimeManager,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    refresh_log_policy_and_reset_runtime_cycle_logs(log_config_dir, state, Some(runtime))
        .map_err(|err| RuntimeReloadPrepareError::LogPolicy(err.to_string()))?;
    let prepared = prepare_runtime_reload_config(state)?;
    set_runtime_log_level_from_config(state, &prepared.config)
        .map_err(|err| RuntimeReloadPrepareError::RuntimeLogLevel(err.to_string()))?;
    refresh_log_policy_and_reset_runtime_cycle_logs(log_config_dir, state, Some(runtime))
        .map_err(|err| RuntimeReloadPrepareError::LogPolicy(err.to_string()))?;
    Ok(prepared)
}

pub(in crate::daed_product) fn apply_prepared_runtime_reload(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    source: &str,
    prepared: PreparedRuntimeReload,
    latency_seed: &[Value],
    reclaim_reason: AllocatorReclaimReason,
) -> Result<AppliedRuntimeReload, String> {
    let mut checkpoints = NoopRuntimeApplyCheckpoints;
    let (runtime_report, materialized_report) = apply_runtime_generation(
        runtime,
        state,
        config_dir,
        source,
        prepared,
        latency_seed,
        &mut checkpoints,
    )?;
    let allocator_reclaim = allocator_reclaim(reclaim_reason);
    Ok(AppliedRuntimeReload {
        runtime_report,
        materialized_report,
        allocator_reclaim,
    })
}

pub(in crate::daed_product) fn runtime_modified_for_running_runtime(
    state: &Path,
    runtime: &ProductRuntimeManager,
) -> Result<bool, String> {
    if !runtime.is_running() {
        return Ok(false);
    }
    let conn = open_state_connection(state).map_err(|err| err.to_string())?;
    runtime_modified(&conn, true).map_err(|err| err.to_string())
}
