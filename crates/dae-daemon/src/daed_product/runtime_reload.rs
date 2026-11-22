use super::*;
use dae_product_control::geodata::{lock_geodata_snapshot, read_runtime_input_versions};

const RELOAD_CANCELLED: &str = "runtime reload request cancelled before commit";

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
    let config = build_runtime_config_from_content(&plan.content)
        .map_err(RuntimeReloadPrepareError::BuildConfig)?;
    build_prepared_runtime_reload(plan, Arc::new(config), false)
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

#[cfg(test)]
fn build_prepared_runtime_reload(
    plan: RuntimeMaterializationPlan,
    config: Arc<Config>,
    renew_trust: bool,
) -> Result<PreparedRuntimeReload, RuntimeReloadPrepareError> {
    let mut prepared = runtime_reload_candidate(plan, config, renew_trust);
    prepared.prepare_generation()?;
    Ok(prepared)
}

fn runtime_reload_candidate(
    plan: RuntimeMaterializationPlan,
    config: Arc<Config>,
    renew_trust: bool,
) -> PreparedRuntimeReload {
    let runtime_candidate = PreparedProductRuntime::from_config(Arc::clone(&config))
        .with_trust_renewal(renew_trust)
        .with_transition_identity(reload_transition_identity(&plan));
    PreparedRuntimeReload {
        plan,
        config,
        runtime_candidate,
        process_transition: None,
        preflight_evidence: Value::Null,
        compile_elapsed_ns: 0,
        preflight_elapsed_ns: 0,
    }
}

impl PreparedRuntimeReload {
    fn prepare_generation(&mut self) -> Result<(), RuntimeReloadPrepareError> {
        let started = Instant::now();
        self.runtime_candidate
            .prepare_generation()
            .map_err(RuntimeReloadPrepareError::Preflight)?;
        self.compile_elapsed_ns = elapsed_nanos(started);
        Ok(())
    }

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

pub(in crate::daed_product) fn coordinate_runtime_reload_until(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    intent: RuntimeApplyIntent,
    latency_seed: &[Value],
    reclaim_reason: AllocatorReclaimReason,
    cancelled: impl Fn() -> bool,
) -> Result<AppliedRuntimeReload, CoordinatedRuntimeReloadError> {
    if cancelled() {
        return Err(RELOAD_CANCELLED.to_owned().into());
    }
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Publication);
    let request = runtime.begin_reconcile(intent);
    request.set_phase("reread-desired-state");
    let (inputs, modified) = match lock_geodata_snapshot().and_then(|_snapshot| {
        prepare_runtime_inputs_with_modified_state(state, runtime.is_running())
    }) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return Err(CoordinatedRuntimeReloadError::Prepare(
                RuntimeReloadPrepareError::Materialize(err.to_string()),
            ));
        }
    };
    let admission = request
        .admit(inputs.active_fingerprint.as_str())
        .map_err(CoordinatedRuntimeReloadError::Apply)?;
    let RuntimeReconcileAdmission::Lead(mut lead) = admission else {
        let RuntimeReconcileAdmission::Follow(follower) = admission else {
            unreachable!("runtime reconcile admission has exactly two variants")
        };
        return follower.wait_until(cancelled);
    };
    if let Err(error) = lead.checkpoint("desired-admitted") {
        return lead.finish(Err(error));
    }
    let system_ca = dae_tls::refresh_system_ca_snapshot()
        .ok()
        .map(|snapshot| snapshot.identity().clone());
    let system_ca_changed = || {
        runtime.is_running()
            && *runtime
                .active_system_ca
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                != system_ca
    };
    if cancelled() {
        return lead.finish(Err(RELOAD_CANCELLED.to_owned().into()));
    }
    if runtime.is_running() && !modified && !system_ca_changed() {
        let geodata = match lock_geodata_snapshot().and_then(|snapshot| {
            ensure_reload_geodata_current(state, inputs.geodata_input_version)?;
            Ok(snapshot)
        }) {
            Ok(snapshot) => snapshot,
            Err(error) => return lead.finish(Err(error.to_string().into())),
        };
        let commit = lead.begin_commit_until(&cancelled);
        if commit.is_err() {
            let error = commit
                .err()
                .expect("runtime commit admission error was checked");
            return lead.finish(Err(error));
        }
        let permit = commit.expect("runtime commit admission success was checked");
        let still_active = open_state_connection(state).and_then(|conn| {
            Ok(runtime.is_running()
                && !inputs.differs_from_active(&conn)?
                && runtime_activation_identity_consistent_with_connection(&conn, runtime)?
                && runtime.has_transition_identity(RuntimeTransitionIdentity {
                    routing_version: inputs.routing_version(),
                    geodata_input_version: inputs.geodata_input_version,
                })
                && !system_ca_changed())
        });
        match still_active {
            Err(error) => {
                permit.finish("failed");
                return lead.finish(Err(error.to_string().into()));
            }
            Ok(true) if !cancelled() => {
                permit.finish_coalesced();
                drop(geodata);
                return lead.finish_with_coalesced(
                    Ok(AppliedRuntimeReload {
                        applied: false,
                        coalesced: true,
                        runtime_report: Value::Null,
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
            _ => permit.finish("retry-preparation"),
        }
        drop(geodata);
    }
    if let Err(error) = lead.checkpoint("materializing") {
        return lead.finish(Err(error));
    }
    let plan = match inputs.materialize() {
        Ok(plan) => plan,
        Err(error) => {
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(
                RuntimeReloadPrepareError::Materialize(error.to_string()),
            )));
        }
    };
    // Legacy rebuilds the control plane on both startup and reload, so a
    // reload that will pull subscriptions must honor the selected network
    // waiting policy as well.  Dry previews still use the non-waiting helper.
    let config = match build_runtime_config_from_content(&plan.content) {
        Ok(config) => Arc::new(config),
        Err(error) => {
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(
                RuntimeReloadPrepareError::BuildConfig(error),
            )));
        }
    };
    if !config.global.disable_waiting_network
        && !config.subscription.is_empty()
        && let Err(error) =
            crate::service_contract::wait_for_network_before_subscriptions_until(|| {
                cancelled() || lead.is_superseded()
            })
    {
        if let Err(error) = lead.checkpoint("network-wait") {
            return lead.finish(Err(error));
        }
        if cancelled() {
            return lead.finish(Err(RELOAD_CANCELLED.to_owned().into()));
        }
        return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(
            RuntimeReloadPrepareError::NetworkWait(error),
        )));
    }
    let _geodata = match lock_geodata_snapshot().and_then(|snapshot| {
        ensure_reload_geodata_current(state, plan.geodata_input_version)?;
        Ok(snapshot)
    }) {
        Ok(geodata) => geodata,
        Err(error) => return lead.finish(Err(error.to_string().into())),
    };
    if cancelled() {
        return lead.finish(Err(RELOAD_CANCELLED.to_owned().into()));
    }
    let mut prepared = runtime_reload_candidate(plan, config, system_ca_changed());
    let transition = match runtime.transition_for_reload(&prepared.runtime_candidate) {
        Ok(transition) => transition,
        Err(error) => return lead.finish(Err(error.into())),
    };
    let generation_prepared = transition_publishes_dataplane(transition);
    if generation_prepared {
        if let Err(error) = prepared.prepare_generation() {
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(error)));
        }
    }
    if let Err(error) = lead.checkpoint("compiled") {
        return lead.finish(Err(error));
    }
    if let Err(error) = lead.checkpoint("preflight") {
        return lead.finish(Err(error));
    }
    let preflight_started = Instant::now();
    let preflight_evidence = match {
        if transition == RuntimeTransitionClass::KernelRebind {
            preflight_product_runtime_candidate(&prepared.config)
        } else {
            Ok(json!({"status": "pass", "hostChecks": "existing-physical-runtime"}))
        }
    } {
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
    let mut prepared = prepared.with_activation_metadata(
        preflight_evidence,
        preflight_elapsed_ns,
        process_transition,
    );
    let commit = lead.begin_commit_until(&cancelled);
    if commit.is_err() {
        let error = commit
            .err()
            .expect("runtime commit admission error was checked");
        return lead.finish(Err(error));
    }
    let permit = commit.expect("runtime commit admission success was checked");
    if cancelled() {
        permit.finish("cancelled");
        return lead.finish(Err(RELOAD_CANCELLED.to_owned().into()));
    }
    prepared.runtime_candidate = prepared
        .runtime_candidate
        .with_trust_renewal(system_ca_changed());
    let commit_transition = match runtime.transition_for_reload(&prepared.runtime_candidate) {
        Ok(transition) => transition,
        Err(error) => {
            permit.finish("failed");
            return lead.finish(Err(error.into()));
        }
    };
    if transition_publishes_dataplane(commit_transition) && !generation_prepared {
        if let Err(error) = prepared.prepare_generation() {
            permit.finish("failed");
            return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(error)));
        }
    }
    if commit_transition == RuntimeTransitionClass::KernelRebind
        && transition != RuntimeTransitionClass::KernelRebind
    {
        let started = Instant::now();
        match preflight_product_runtime_candidate(&prepared.config) {
            Ok(evidence) => {
                prepared.preflight_evidence = evidence;
                prepared.preflight_elapsed_ns = elapsed_nanos(started);
            }
            Err(error) => {
                permit.finish("failed");
                return lead.finish(Err(CoordinatedRuntimeReloadError::Prepare(
                    RuntimeReloadPrepareError::Preflight(error),
                )));
            }
        }
    }
    prepared.process_transition = runtime.process_transition_for_config(&prepared.config);
    let previous_pprof_port = runtime.pprof_port();
    if cancelled() {
        permit.finish("cancelled");
        return lead.finish(Err(RELOAD_CANCELLED.to_owned().into()));
    }
    if let Err(error) = runtime.configure_pprof_port(prepared.config.global.pprof_port) {
        permit.finish("failed");
        return lead.finish(Err(
            format!("pprof listener preflight failed: {error}").into()
        ));
    }
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
            *runtime
                .active_system_ca
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = system_ca;
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
    let mut applied = coordinate_runtime_reload_until(
        runtime,
        state,
        config_dir,
        intent,
        latency_seed,
        reclaim_reason,
        || false,
    )?;
    if applied.coalesced && intent == RuntimeApplyIntent::StartupRestore {
        applied.runtime_report = runtime.summary();
    }
    Ok(applied)
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn reload_transition_identity(plan: &RuntimeMaterializationPlan) -> RuntimeTransitionIdentity {
    RuntimeTransitionIdentity {
        routing_version: plan.routing_version,
        geodata_input_version: plan.geodata_input_version,
    }
}

fn transition_publishes_dataplane(transition: RuntimeTransitionClass) -> bool {
    matches!(
        transition,
        RuntimeTransitionClass::GenerationSwap | RuntimeTransitionClass::KernelRebind
    )
}

fn ensure_reload_geodata_current(state: &Path, geodata_input_version: i64) -> io::Result<()> {
    if read_runtime_input_versions(state)?.geodata != geodata_input_version {
        return Err(io::Error::other(
            "runtime reload preparation was superseded by a Geo update",
        ));
    }
    Ok(())
}
