use super::*;

mod activate;
mod commit;
mod coordinator;
mod journal;
mod prepare;
mod reconcile;
mod rollback;

use self::activate::activate_runtime_generation;
use self::commit::commit_runtime_generation;
pub(in crate::daed_product) use self::coordinator::{
    RuntimeApplyCoordinator, RuntimeApplyIntent, RuntimeApplyPermit, RuntimeStopPermit,
};
pub(in crate::daed_product) use self::journal::recover_runtime_apply_transaction;
use self::prepare::prepare_runtime_generation;
use self::reconcile::{record_apply_failure, record_apply_success};
use self::rollback::rollback_runtime_generation;

pub(in crate::daed_product) const RUNTIME_GENERATION_METADATA_KEY: &str = "runtime_generation_id";
pub(in crate::daed_product) const RUNTIME_PROBE_GENERATION_METADATA_KEY: &str =
    "runtime_probe_generation";
const RUNTIME_RUNNING_METADATA_KEY: &str = "runtime_running";
const RUNTIME_TRANSITION_PHASE_METADATA_KEY: &str = "runtime_transition_phase";
const LAST_MATERIALIZED_AT_METADATA_KEY: &str = "last_materialized_at";
const LAST_GENERATED_CONFIG_PATH_METADATA_KEY: &str = "last_generated_config_path";
const RUNTIME_LOG_LEVEL_METADATA_KEY: &str = "runtime_log_level";
const RUNTIME_LAST_APPLY_ERROR_METADATA_KEY: &str = "runtime_last_apply_error";
pub(in crate::daed_product) const RUNTIME_PROCESS_TRANSITION_METADATA_KEY: &str =
    "runtime_pending_process_transition";
const RUNTIME_APPLY_SNAPSHOT_METADATA_KEYS: &[&str] = &[
    RUNTIME_GENERATION_METADATA_KEY,
    RUNTIME_PROBE_GENERATION_METADATA_KEY,
    RUNTIME_RUNNING_METADATA_KEY,
    RUNTIME_TRANSITION_PHASE_METADATA_KEY,
    LAST_MATERIALIZED_AT_METADATA_KEY,
    LAST_GENERATED_CONFIG_PATH_METADATA_KEY,
    RUNTIME_LOG_LEVEL_METADATA_KEY,
    RUNTIME_LAST_APPLY_ERROR_METADATA_KEY,
    RUNTIME_PROCESS_TRANSITION_METADATA_KEY,
    RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum RuntimeApplyCheckpoint {
    CreateDirectory,
    WriteCandidate,
    SyncCandidate,
    StartCandidate,
    CommitPostStart,
    RenameCandidate,
    CommitDatabase,
    PublishLogPolicy,
    Rollback,
}

pub(in crate::daed_product) fn apply_runtime_generation(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    source: &str,
    prepared: PreparedRuntimeReload,
    latency_seed: &[Value],
    checkpoints: &mut dyn FaultCheckpoints<RuntimeApplyCheckpoint>,
) -> Result<(Value, Value), String> {
    let runtime_log_level = runtime_log_level_for_config(&prepared.config);
    let process_transition = prepared.process_transition.clone();
    let preflight_evidence = prepared.preflight_evidence.clone();
    let reload_timings = json!({
        "snapshotNs": prepared.plan.timings.snapshot_ns,
        "dependencyResolutionNs": prepared.plan.timings.dependency_resolution_ns,
        "renderNs": prepared.plan.timings.render_ns,
        "compileNs": prepared.compile_elapsed_ns,
        "preflightNs": prepared.preflight_elapsed_ns,
    });
    let generation = runtime.begin_apply_generation();
    let mut candidate = match prepare_runtime_generation(
        state,
        config_dir,
        &prepared.plan,
        &generation,
        checkpoints,
    ) {
        Ok(candidate) => candidate,
        Err(err) => {
            record_apply_failure(runtime, &generation, "prepare", &err, "not-required", false);
            return Err(err);
        }
    };
    let snapshot = match runtime.snapshot_for_apply(&prepared.runtime_candidate) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            record_apply_failure(
                runtime,
                &generation,
                "snapshot",
                &err,
                "not-required",
                false,
            );
            return Err(err);
        }
    };
    let mut runtime_report = match activate_runtime_generation(
        runtime,
        prepared.runtime_candidate,
        prepared.plan.content.clone(),
        source,
        latency_seed,
        checkpoints,
    ) {
        Ok(report) => report,
        Err(err) => {
            record_apply_failure(
                runtime,
                &generation,
                "activate",
                &err,
                "runtime-manager-restored-or-unchanged",
                false,
            );
            return Err(err);
        }
    };
    if let Value::Object(report) = &mut runtime_report {
        report.insert("candidatePreflight".to_owned(), preflight_evidence);
        report.insert("reloadTimings".to_owned(), reload_timings);
    }
    candidate.set_probe_generation(runtime.current_probe_generation());
    runtime.set_apply_generation_phase(&generation, "commit");
    let commit_result = checkpoints
        .checkpoint(RuntimeApplyCheckpoint::CommitPostStart)
        .map_err(|err| format!("post-start runtime commit checkpoint: {err}"))
        .and_then(|()| {
            commit_runtime_generation(
                state,
                config_dir,
                &prepared.plan,
                &runtime_log_level,
                process_transition.as_ref(),
                &mut candidate,
                checkpoints,
            )
            .and_then(|report| {
                checkpoints
                    .checkpoint(RuntimeApplyCheckpoint::PublishLogPolicy)
                    .map_err(|err| format!("publish runtime log policy checkpoint: {err}"))?;
                if let Some(config_dir) = config_dir {
                    refresh_log_policy_and_apply_log_limits(config_dir, state, Some(runtime))
                        .map_err(|err| format!("publish runtime log policy: {err}"))?;
                }
                Ok(report)
            })
        });
    match commit_result {
        Ok(materialized_report) => {
            drop(snapshot);
            candidate.discard_rollback_state();
            runtime.publish_process_transition(process_transition);
            runtime.finalize_runtime_generation_publication();
            record_apply_success(runtime, &generation);
            Ok((runtime_report, materialized_report))
        }
        Err(commit_err) => {
            let rollback = rollback_runtime_generation(
                runtime,
                state,
                config_dir,
                &snapshot,
                &mut candidate,
                latency_seed,
                checkpoints,
            );
            match rollback {
                Ok(()) => {
                    record_apply_failure(
                        runtime,
                        &generation,
                        "rolled-back",
                        &commit_err,
                        "restored",
                        false,
                    );
                    Err(format!(
                        "{commit_err}; rollback restored previous runtime generation"
                    ))
                }
                Err(rollback_err) => {
                    let message = format!(
                        "{commit_err}; rollback failed and runtime reconciliation is required: {rollback_err}"
                    );
                    record_apply_failure(
                        runtime,
                        &generation,
                        "reconcile",
                        &message,
                        "failed",
                        true,
                    );
                    Err(message)
                }
            }
        }
    }
}
