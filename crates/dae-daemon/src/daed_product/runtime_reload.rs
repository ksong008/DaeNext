use super::*;

pub(in crate::daed_product) struct PreparedRuntimeReload {
    pub(in crate::daed_product) plan: RuntimeMaterializationPlan,
    pub(in crate::daed_product) config: Config,
    pub(in crate::daed_product) process_transition: Option<Value>,
}

pub(in crate::daed_product) struct AppliedRuntimeReload {
    pub(in crate::daed_product) applied: bool,
    pub(in crate::daed_product) coalesced: bool,
    pub(in crate::daed_product) runtime_report: Value,
    pub(in crate::daed_product) materialized_report: Value,
    pub(in crate::daed_product) allocator_reclaim: Value,
    pub(in crate::daed_product) pending_process_transition: Option<Value>,
}

#[derive(Debug)]
pub(in crate::daed_product) enum RuntimeReloadPrepareError {
    Materialize(String),
    BuildConfig(String),
    Preflight(String),
}

impl RuntimeReloadPrepareError {
    pub(in crate::daed_product) fn http_status(&self) -> u16 {
        match self {
            Self::Materialize(_) | Self::BuildConfig(_) => 400,
            Self::Preflight(_) => 409,
        }
    }

    pub(in crate::daed_product) fn api_log_message(&self) -> &'static str {
        match self {
            Self::Materialize(_) => "[Reload] Failed to materialize runtime preview",
            Self::BuildConfig(_) => "[Reload] Failed to build runtime config",
            Self::Preflight(_) => "[Reload] Candidate preflight failed",
        }
    }
}

impl std::fmt::Display for RuntimeReloadPrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Materialize(err) | Self::BuildConfig(err) | Self::Preflight(err) => {
                formatter.write_str(err)
            }
        }
    }
}

#[derive(Debug)]
pub(in crate::daed_product) enum CoordinatedRuntimeReloadError {
    Prepare(RuntimeReloadPrepareError),
    Apply(String),
}

impl CoordinatedRuntimeReloadError {
    pub(in crate::daed_product) fn http_status(&self) -> u16 {
        match self {
            Self::Prepare(err) => err.http_status(),
            Self::Apply(err) if err.contains("superseded by stop") => 409,
            Self::Apply(_) => 500,
        }
    }

    pub(in crate::daed_product) fn api_log_message(&self) -> &'static str {
        match self {
            Self::Prepare(err) => err.api_log_message(),
            Self::Apply(_) => "[Reload] Failed to reload",
        }
    }
}

impl std::fmt::Display for CoordinatedRuntimeReloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prepare(err) => std::fmt::Display::fmt(err, formatter),
            Self::Apply(err) => formatter.write_str(err),
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
    Ok(PreparedRuntimeReload {
        plan,
        config,
        process_transition: None,
    })
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
    runtime.set_runtime_required_for_readiness(true);
    let allocator_reclaim = allocator_reclaim(reclaim_reason);
    let pending_process_transition = runtime.pending_process_transition();
    Ok(AppliedRuntimeReload {
        applied: true,
        coalesced: false,
        runtime_report,
        materialized_report,
        allocator_reclaim,
        pending_process_transition,
    })
}

pub(in crate::daed_product) fn coordinate_runtime_reload(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    intent: RuntimeApplyIntent,
    latency_seed: &[Value],
    reclaim_reason: AllocatorReclaimReason,
) -> Result<AppliedRuntimeReload, CoordinatedRuntimeReloadError> {
    let permit = runtime
        .begin_apply(intent)
        .map_err(CoordinatedRuntimeReloadError::Apply)?;
    permit.set_phase("reread-desired-state");
    let modified = runtime_modified_for_running_runtime(state, runtime)
        .map_err(CoordinatedRuntimeReloadError::Apply)?;
    let activation_identity_consistent = if runtime.is_running() {
        runtime_activation_identity_consistent(state, runtime)
            .map_err(|err| CoordinatedRuntimeReloadError::Apply(err.to_string()))?
    } else {
        true
    };
    if runtime.is_running()
        && !modified
        && activation_identity_consistent
        && (permit.waited() || permit.intent().requires_runtime_change())
    {
        let runtime_report = runtime.summary();
        permit.finish_coalesced();
        return Ok(AppliedRuntimeReload {
            applied: false,
            coalesced: true,
            runtime_report,
            materialized_report: json!({
                "applied": false,
                "coalesced": true,
                "reason": "active runtime already matches latest desired state",
            }),
            allocator_reclaim: Value::Null,
            pending_process_transition: runtime.pending_process_transition(),
        });
    }
    permit.set_phase("materializing");
    let mut prepared = match prepare_runtime_reload_config(state) {
        Ok(prepared) => prepared,
        Err(err) => {
            permit.finish("prepare-failed");
            return Err(CoordinatedRuntimeReloadError::Prepare(err));
        }
    };
    permit.set_phase("preflight");
    if let Err(err) = preflight_product_runtime_candidate(&prepared.config) {
        permit.finish("preflight-failed");
        return Err(CoordinatedRuntimeReloadError::Prepare(
            RuntimeReloadPrepareError::Preflight(err),
        ));
    }
    prepared.process_transition = runtime.process_transition_for_config(&prepared.config);
    permit.set_phase("applying");
    let result = apply_prepared_runtime_reload(
        runtime,
        state,
        config_dir,
        intent.source(),
        prepared,
        latency_seed,
        reclaim_reason,
    )
    .map_err(CoordinatedRuntimeReloadError::Apply);
    match result {
        Ok(applied) => {
            permit.finish("succeeded");
            Ok(applied)
        }
        Err(err) => {
            permit.finish("failed");
            Err(err)
        }
    }
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
