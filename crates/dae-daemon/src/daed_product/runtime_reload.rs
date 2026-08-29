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

pub(in crate::daed_product) use dae_product_control::runtime::{
    CoordinatedRuntimeReloadError, RuntimeReloadPrepareError,
};

#[cfg(test)]
pub(in crate::daed_product) fn prepare_runtime_reload_config(
    state: &Path,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let plan = prepare_runtime_materialization_plan(state)
        .map_err(|err| RuntimeReloadPrepareError::Materialize(err.to_string()))?;
    build_prepared_runtime_reload(plan, false)
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
    wait_for_network: bool,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let compile_started = Instant::now();
    let config = Arc::new(
        build_runtime_config_from_content(&plan.content)
            .map_err(RuntimeReloadPrepareError::BuildConfig)?,
    );
    if wait_for_network && !config.global.disable_waiting_network && !config.subscription.is_empty()
    {
        crate::service_contract::wait_for_network_before_subscriptions()
            .map_err(RuntimeReloadPrepareError::NetworkWait)?;
    }
    let runtime_candidate = prepare_product_runtime_candidate(Arc::clone(&config))
        .map_err(RuntimeReloadPrepareError::Preflight)?
        .with_transition_identity(RuntimeTransitionIdentity {
            routing_version: plan.routing_version,
            geodata_input_version: plan.geodata_input_version,
        });
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
) -> Result<AppliedRuntimeReload, String> {
    let mut checkpoints = NoopFaultCheckpoints;
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
    let pending_process_transition = runtime.pending_process_transition();
    Ok(AppliedRuntimeReload {
        applied: true,
        coalesced: false,
        runtime_report,
        materialized_report,
        allocator_reclaim: Value::Null,
        pending_process_transition,
    })
}

pub(in crate::daed_product) fn coordinate_runtime_reload_inner(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    intent: RuntimeApplyIntent,
    latency_seed: &[Value],
    reclaim_reason: AllocatorReclaimReason,
) -> Result<AppliedRuntimeReload, CoordinatedRuntimeReloadError> {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Publication);
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
        .admit(plan.active_fingerprint.as_str())
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
        return lead.finish_with_coalesced(
            Ok(AppliedRuntimeReload {
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
            }),
            true,
        );
    }
    if let Err(error) = lead.checkpoint("materializing") {
        return lead.finish(Err(error));
    }
    // Legacy rebuilds the control plane on both startup and reload, so a
    // reload that will pull subscriptions must honor the selected network
    // waiting policy as well.  Dry previews still use the non-waiting helper.
    let prepared = match build_prepared_runtime_reload(plan, true) {
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
    let previous_pprof_port = runtime.pprof_port();
    if let Err(error) = runtime.configure_pprof_port(prepared.config.global.pprof_port) {
        return lead.finish(Err(CoordinatedRuntimeReloadError::Apply(format!(
            "pprof listener preflight failed: {error}"
        ))));
    }
    let commit = lead.begin_commit();
    if commit.is_err() {
        let error = commit
            .err()
            .expect("runtime commit admission error was checked");
        let _ = runtime.configure_pprof_port(previous_pprof_port);
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
    )
    .map_err(CoordinatedRuntimeReloadError::Apply);
    match result {
        Ok(mut applied) => {
            if applied.applied {
                applied.allocator_reclaim = allocator_request_reclaim_for_publication(
                    reclaim_reason,
                    runtime.allocator_publication_id(),
                );
            }
            permit.finish("succeeded");
            lead.finish(Ok(applied))
        }
        Err(err) => {
            let pprof_restore = runtime
                .configure_pprof_port(previous_pprof_port)
                .map_err(|restore| format!("pprof listener rollback failed: {restore}"));
            permit.finish("failed");
            lead.finish(Err(match pprof_restore {
                Ok(()) => err,
                Err(restore) => CoordinatedRuntimeReloadError::Apply(format!("{err}; {restore}")),
            }))
        }
    }
}

pub(in crate::daed_product) fn coordinate_runtime_reload(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    intent: RuntimeApplyIntent,
    latency_seed: &[Value],
    reclaim_reason: AllocatorReclaimReason,
) -> Result<AppliedRuntimeReload, CoordinatedRuntimeReloadError> {
    coordinate_runtime_reload_inner(
        runtime,
        state,
        config_dir,
        intent,
        latency_seed,
        reclaim_reason,
    )
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}
