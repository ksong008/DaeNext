use super::*;

mod activate;
mod commit;
mod prepare;
mod reconcile;
mod rollback;

use self::activate::activate_runtime_generation;
use self::commit::commit_runtime_generation;
use self::prepare::prepare_runtime_generation;
use self::reconcile::{record_apply_failure, record_apply_success};
use self::rollback::rollback_runtime_generation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::daed_product) enum RuntimeApplyCheckpoint {
    CreateDirectory,
    WriteCandidate,
    SyncCandidate,
    StartCandidate,
    CommitPostStart,
    RenameCandidate,
    CommitDatabase,
    Rollback,
}

pub(in crate::daed_product) trait RuntimeApplyCheckpoints {
    fn checkpoint(&mut self, point: RuntimeApplyCheckpoint) -> io::Result<()>;
}

pub(super) struct NoopRuntimeApplyCheckpoints;

impl RuntimeApplyCheckpoints for NoopRuntimeApplyCheckpoints {
    fn checkpoint(&mut self, _point: RuntimeApplyCheckpoint) -> io::Result<()> {
        Ok(())
    }
}

pub(in crate::daed_product) fn apply_runtime_generation(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    source: &str,
    prepared: PreparedRuntimeReload,
    latency_seed: &[Value],
    checkpoints: &mut dyn RuntimeApplyCheckpoints,
) -> Result<(Value, Value), String> {
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
    let snapshot = match runtime.snapshot_for_apply() {
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
    let runtime_report = match activate_runtime_generation(
        runtime,
        prepared.config,
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
    runtime.set_apply_generation_phase(&generation, "commit");
    let commit_result = checkpoints
        .checkpoint(RuntimeApplyCheckpoint::CommitPostStart)
        .map_err(|err| format!("post-start runtime commit checkpoint: {err}"))
        .and_then(|()| {
            commit_runtime_generation(
                state,
                config_dir,
                &prepared.plan,
                &mut candidate,
                checkpoints,
            )
        });
    match commit_result {
        Ok(materialized_report) => {
            record_apply_success(runtime, &generation);
            Ok((runtime_report, materialized_report))
        }
        Err(commit_err) => {
            let rollback = rollback_runtime_generation(
                runtime,
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
