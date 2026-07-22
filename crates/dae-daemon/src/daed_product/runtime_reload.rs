use super::*;

pub(in crate::daed_product) struct PreparedRuntimeReload {
    pub(in crate::daed_product) plan: RuntimeMaterializationPlan,
    pub(in crate::daed_product) config: Arc<Config>,
    pub(in crate::daed_product) runtime_candidate: PreparedProductRuntime,
    pub(in crate::daed_product) process_transition: Option<Value>,
    pub(in crate::daed_product) preflight_evidence: Value,
    pub(in crate::daed_product) compile_elapsed_ns: u64,
    pub(in crate::daed_product) preflight_elapsed_ns: u64,
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct AppliedRuntimeReload {
    pub(in crate::daed_product) applied: bool,
    pub(in crate::daed_product) coalesced: bool,
    pub(in crate::daed_product) runtime_report: Value,
    pub(in crate::daed_product) materialized_report: Value,
    pub(in crate::daed_product) allocator_reclaim: Value,
    pub(in crate::daed_product) pending_process_transition: Option<Value>,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[cfg(test)]
pub(in crate::daed_product) fn prepare_runtime_reload_config(
    state: &Path,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let plan = prepare_runtime_materialization_plan(state)
        .map_err(|err| RuntimeReloadPrepareError::Materialize(err.to_string()))?;
    build_prepared_runtime_reload(plan)
}

pub(in crate::daed_product) fn prepare_runtime_reload_preview(
    state: &Path,
) -> Result<RuntimeMaterializationPlan, RuntimeReloadPrepareError> {
    let plan = prepare_runtime_materialization_plan(state)
        .map_err(|err| RuntimeReloadPrepareError::Materialize(err.to_string()))?;
    build_runtime_config_from_content(&plan.content)
        .map_err(RuntimeReloadPrepareError::BuildConfig)?;
    Ok(plan)
}

fn build_prepared_runtime_reload(
    plan: RuntimeMaterializationPlan,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let compile_started = Instant::now();
    let config = Arc::new(
        build_runtime_config_from_content(&plan.content)
            .map_err(RuntimeReloadPrepareError::BuildConfig)?,
    );
    let runtime_candidate = prepare_product_runtime_candidate(Arc::clone(&config))
        .map_err(RuntimeReloadPrepareError::Preflight)?;
    Ok(PreparedRuntimeReload {
        plan,
        config,
        runtime_candidate,
        process_transition: None,
        preflight_evidence: Value::Null,
        compile_elapsed_ns: elapsed_nanos(compile_started),
        preflight_elapsed_ns: 0,
    })
}

impl PreparedRuntimeReload {
    fn with_activation_metadata(
        mut self,
        preflight_evidence: Value,
        preflight_elapsed_ns: u64,
        process_transition: Option<Value>,
    ) -> Self {
        self.preflight_evidence = preflight_evidence;
        self.preflight_elapsed_ns = preflight_elapsed_ns;
        self.process_transition = process_transition;
        self
    }
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
    let request = runtime.begin_reconcile(intent);
    request.set_phase("reread-desired-state");
    let (plan, modified) =
        match prepare_runtime_materialization_plan_with_modified_state(state, runtime.is_running())
        {
            Ok(snapshot) => snapshot,
            Err(err) => {
                return Err(CoordinatedRuntimeReloadError::Prepare(
                    RuntimeReloadPrepareError::Materialize(err.to_string()),
                ));
            }
        };
    let admission = request
        .admit(&plan.active_fingerprint)
        .map_err(CoordinatedRuntimeReloadError::Apply)?;
    let RuntimeReconcileAdmission::Lead(mut lead) = admission else {
        let RuntimeReconcileAdmission::Follow(follower) = admission else {
            unreachable!("runtime reconcile admission has exactly two variants")
        };
        return follower.wait();
    };
    if let Err(error) = lead.checkpoint("desired-admitted") {
        return lead.finish(Err(error));
    }
    let activation_identity_consistent = if runtime.is_running() {
        match runtime_activation_identity_consistent(state, runtime) {
            Ok(consistent) => consistent,
            Err(error) => {
                return lead.finish(Err(CoordinatedRuntimeReloadError::Apply(error.to_string())));
            }
        }
    } else {
        true
    };
    if runtime.is_running() && !modified && activation_identity_consistent {
        let commit = lead.begin_commit();
        if commit.is_err() {
            let error = commit
                .err()
                .expect("runtime commit admission error was checked");
            return lead.finish(Err(error));
        }
        let permit = commit.expect("runtime commit admission success was checked");
        let runtime_report = runtime.summary();
        permit.finish_coalesced();
        return lead.finish(Ok(AppliedRuntimeReload {
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
        }));
    }
    if let Err(error) = lead.checkpoint("materializing") {
        return lead.finish(Err(error));
    }
    let prepared = match build_prepared_runtime_reload(plan) {
        Ok(prepared) => prepared,
        Err(err) => {
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(err)));
        }
    };
    if let Err(error) = lead.checkpoint("compiled") {
        return lead.finish(Err(error));
    }
    if let Err(error) = lead.checkpoint("preflight") {
        return lead.finish(Err(error));
    }
    let preflight_started = Instant::now();
    let preflight_evidence = match preflight_product_runtime_candidate(&prepared.config) {
        Ok(evidence) => evidence,
        Err(err) => {
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(
                RuntimeReloadPrepareError::Preflight(err),
            )));
        }
    };
    if let Err(error) = lead.checkpoint("preflight-complete") {
        return lead.finish(Err(error));
    }
    let preflight_elapsed_ns = elapsed_nanos(preflight_started);
    let process_transition = runtime.process_transition_for_config(&prepared.config);
    let prepared = prepared.with_activation_metadata(
        preflight_evidence,
        preflight_elapsed_ns,
        process_transition,
    );
    let commit = lead.begin_commit();
    if commit.is_err() {
        let error = commit
            .err()
            .expect("runtime commit admission error was checked");
        return lead.finish(Err(error));
    }
    let permit = commit.expect("runtime commit admission success was checked");
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
            lead.finish(Ok(applied))
        }
        Err(err) => {
            permit.finish("failed");
            lead.finish(Err(err))
        }
    }
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
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
