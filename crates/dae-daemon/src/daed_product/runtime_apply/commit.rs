use super::prepare::{PreparedRuntimeGeneration, sync_directory};
use super::*;

pub(super) fn commit_runtime_generation(
    state: &Path,
    config_dir: Option<&Path>,
    plan: &RuntimeMaterializationPlan,
    candidate: &mut PreparedRuntimeGeneration,
    checkpoints: &mut dyn RuntimeApplyCheckpoints,
) -> Result<Value, String> {
    if let (Some(candidate_path), Some(output_path)) = (
        candidate.candidate_path.as_ref(),
        candidate.output_path.as_ref(),
    ) {
        checkpoints
            .checkpoint(RuntimeApplyCheckpoint::RenameCandidate)
            .map_err(|err| format!("rename runtime candidate checkpoint: {err}"))?;
        fs::rename(candidate_path, output_path).map_err(|err| {
            format!(
                "activate runtime materialization {}: {err}",
                path_string(output_path)
            )
        })?;
        if let Some(parent) = output_path.parent() {
            sync_directory(parent)?;
        }
        candidate.candidate_path = None;
    }

    commit_runtime_state(state, plan, candidate, checkpoints)?;
    candidate.mark_committed();
    Ok(plan.report(config_dir, false))
}

fn commit_runtime_state(
    state: &Path,
    plan: &RuntimeMaterializationPlan,
    candidate: &PreparedRuntimeGeneration,
    checkpoints: &mut dyn RuntimeApplyCheckpoints,
) -> Result<(), String> {
    let mut conn = open_state_connection(state)
        .map_err(|err| format!("open runtime state for commit: {err}"))?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("begin runtime state commit: {err}"))?;
    tx.execute("DELETE FROM systems", [])
        .map_err(|err| format!("clear previous runtime state: {err}"))?;
    tx.execute(
        "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids, running_config_id, running_dns_id, running_routing_id, running_external_input_version)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            1_i64,
            plan.config_version,
            plan.dns_version,
            plan.routing_version,
            plan.group_version_sum,
            plan.group_ids,
            plan.config_id,
            plan.dns_id,
            plan.routing_id,
            plan.external_input_version,
        ],
    )
    .map_err(|err| format!("insert committed runtime state: {err}"))?;
    set_metadata_in_transaction(&tx, "last_materialized_at", &plan.generated_at)?;
    set_metadata_in_transaction(&tx, "runtime_running", "true")?;
    set_metadata_in_transaction(&tx, "runtime_generation_id", &candidate.generation)?;
    set_metadata_in_transaction(&tx, "runtime_transition_phase", "committed")?;
    if let Some(output_path) = candidate.output_path.as_ref() {
        set_metadata_in_transaction(&tx, "last_generated_config_path", &path_string(output_path))?;
    }
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::CommitDatabase)
        .map_err(|err| format!("commit runtime database checkpoint: {err}"))?;
    tx.commit()
        .map_err(|err| format!("commit runtime state transaction: {err}"))
}

fn set_metadata_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    value: &str,
) -> Result<(), String> {
    tx.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params![key, value],
    )
    .map_err(|err| format!("set runtime metadata {key}: {err}"))?;
    Ok(())
}
