use super::*;
use super::{PreparedRuntimeGeneration, sync_directory};
use dae_product_persistence::create_synced_file;

pub(super) fn rollback_runtime_generation(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    snapshot: &ProductRuntimeApplySnapshot,
    candidate: &mut PreparedRuntimeGeneration,
    latency_seed: &[Value],
    checkpoints: &mut dyn FaultCheckpoints<RuntimeApplyCheckpoint>,
) -> Result<(), String> {
    if let Err(err) = checkpoints.checkpoint(RuntimeApplyCheckpoint::Rollback) {
        if let Some(transaction) = candidate.transaction.as_mut() {
            transaction.preserve_for_recovery();
        }
        return Err(format!("runtime rollback checkpoint: {err}"));
    }
    let mut errors = Vec::new();
    if let Err(err) = restore_previous_materialization(candidate) {
        errors.push(format!("restore materialization failed: {err}"));
    }
    let restored_probe_generation = match runtime.restore_after_failed_apply(snapshot, latency_seed)
    {
        Ok(()) => Some(runtime.current_probe_generation()),
        Err(err) => {
            errors.push(format!("restore runtime failed: {err}"));
            None
        }
    };
    if let Err(err) = dae_product_runtime::restore_runtime_database(
        state,
        &candidate.database_snapshot,
        restored_probe_generation,
    ) {
        errors.push(format!("restore runtime database failed: {err}"));
    }
    if let Err(err) = super::journal::remove_runtime_apply_journal(candidate) {
        errors.push(format!("remove runtime apply journal failed: {err}"));
    }
    if let Some(config_dir) = config_dir
        && let Err(err) = refresh_log_policy_and_apply_log_limits(config_dir, state, Some(runtime))
    {
        errors.push(format!("restore runtime log policy failed: {err}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn restore_previous_materialization(
    candidate: &mut PreparedRuntimeGeneration,
) -> Result<(), String> {
    if let Some(mut transaction) = candidate.transaction.take() {
        transaction
            .rollback()
            .map_err(|error| format!("rollback runtime materialization transaction: {error}"))?;
        candidate.candidate_path = None;
        candidate.journal_path = None;
        candidate.backup_path = None;
        return Ok(());
    }
    if let Some(candidate_path) = candidate.candidate_path.take() {
        match fs::remove_file(&candidate_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "remove staged runtime candidate {}: {err}",
                    path_string(&candidate_path)
                ));
            }
        }
    }
    let Some(output_path) = candidate.output_path.as_ref() else {
        return Ok(());
    };
    let parent = output_path
        .parent()
        .ok_or_else(|| "runtime materialization path has no parent".to_owned())?;
    if let Some(previous) = candidate.previous_content.as_ref() {
        let rollback_path =
            parent.join(format!(".generated.dae.{}.rollback", candidate.generation));
        create_synced_file(&rollback_path, previous).map_err(|err| {
            format!(
                "create rollback materialization {}: {err}",
                path_string(&rollback_path)
            )
        })?;
        fs::rename(&rollback_path, output_path).map_err(|err| {
            format!(
                "restore runtime materialization {}: {err}",
                path_string(output_path)
            )
        })?;
    } else {
        match fs::remove_file(output_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "remove failed runtime materialization {}: {err}",
                    path_string(output_path)
                ));
            }
        }
    }
    sync_directory(parent)
}
