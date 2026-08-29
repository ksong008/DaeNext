use super::PreparedRuntimeGeneration;
use super::*;

pub(super) fn commit_runtime_generation(
    state: &Path,
    config_dir: Option<&Path>,
    plan: &RuntimeMaterializationPlan,
    runtime_log_level: &str,
    process_transition: Option<&Value>,
    candidate: &mut PreparedRuntimeGeneration,
    checkpoints: &mut dyn FaultCheckpoints<RuntimeApplyCheckpoint>,
) -> Result<Value, String> {
    if candidate.candidate_path.is_some() && candidate.output_path.is_some() {
        super::journal::write_runtime_apply_journal(candidate)?;
    }
    if let (Some(_candidate_path), Some(output_path)) = (
        candidate.candidate_path.as_ref(),
        candidate.output_path.as_ref(),
    ) {
        checkpoints
            .checkpoint(RuntimeApplyCheckpoint::RenameCandidate)
            .map_err(|err| format!("rename runtime candidate checkpoint: {err}"))?;
        candidate
            .transaction
            .as_mut()
            .ok_or_else(|| "runtime apply transaction is missing before activation".to_owned())?
            .activate()
            .map_err(|err| {
                format!(
                    "activate runtime materialization {}: {err}",
                    path_string(output_path)
                )
            })?;
        candidate.candidate_path = None;
    }

    let commit_result = if let Some(mut transaction) = candidate.transaction.take() {
        let result = transaction.commit_database(|| {
            dae_product_runtime::commit_runtime_state(
                state,
                plan,
                runtime_log_level,
                process_transition,
                candidate,
                checkpoints,
            )
        });
        candidate.transaction = Some(transaction);
        result
    } else {
        dae_product_runtime::commit_runtime_state(
            state,
            plan,
            runtime_log_level,
            process_transition,
            candidate,
            checkpoints,
        )
    };
    commit_result?;
    super::journal::remove_runtime_apply_journal(candidate)?;
    candidate.mark_committed();
    Ok(plan.report(config_dir, false))
}
