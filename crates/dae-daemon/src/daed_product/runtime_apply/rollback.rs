use super::prepare::{PreparedRuntimeGeneration, RuntimeDatabaseSnapshot, sync_directory};
use super::*;
use std::fs::OpenOptions;

pub(super) fn rollback_runtime_generation(
    runtime: &ProductRuntimeManager,
    state: &Path,
    config_dir: Option<&Path>,
    snapshot: &ProductRuntimeApplySnapshot,
    candidate: &mut PreparedRuntimeGeneration,
    latency_seed: &[Value],
    checkpoints: &mut dyn RuntimeApplyCheckpoints,
) -> Result<(), String> {
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::Rollback)
        .map_err(|err| format!("runtime rollback checkpoint: {err}"))?;
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
    if let Err(err) = restore_runtime_database(
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

fn restore_runtime_database(
    state: &Path,
    snapshot: &RuntimeDatabaseSnapshot,
    restored_probe_generation: Option<Option<u64>>,
) -> Result<(), String> {
    let mut conn = open_state_connection(state)
        .map_err(|err| format!("open runtime state for rollback: {err}"))?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("begin runtime state rollback: {err}"))?;
    tx.execute("DELETE FROM systems", [])
        .map_err(|err| format!("clear failed runtime state: {err}"))?;
    if let Some(system) = snapshot.system.as_ref() {
        tx.execute(
            "INSERT INTO systems(
                running, running_config_version, running_dns_version,
                running_routing_version, running_group_version_sum, running_group_ids,
                running_config_id, running_dns_id, running_routing_id,
                running_external_input_version
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                system.running,
                system.config_version,
                system.dns_version,
                system.routing_version,
                system.group_version_sum,
                &system.group_ids,
                system.config_id,
                system.dns_id,
                system.routing_id,
                system.external_input_version,
            ],
        )
        .map_err(|err| format!("restore previous runtime state: {err}"))?;
    }
    for (key, value) in &snapshot.metadata {
        if key == RUNTIME_PROBE_GENERATION_METADATA_KEY
            && let Some(generation) = restored_probe_generation
        {
            super::super::runtime_manager::activation_identity::write_probe_generation(
                &tx, generation,
            )?;
            continue;
        }
        match value {
            Some(value) => {
                tx.execute(
                    "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
                    params![key, value],
                )
                .map_err(|err| format!("restore runtime metadata {key}: {err}"))?;
            }
            None => {
                tx.execute(
                    "DELETE FROM daed_product_metadata WHERE key = ?1",
                    params![key],
                )
                .map_err(|err| format!("remove failed runtime metadata {key}: {err}"))?;
            }
        }
    }
    tx.commit()
        .map_err(|err| format!("commit runtime state rollback: {err}"))
}

fn restore_previous_materialization(
    candidate: &mut PreparedRuntimeGeneration,
) -> Result<(), String> {
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
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&rollback_path)
            .map_err(|err| {
                format!(
                    "create rollback materialization {}: {err}",
                    path_string(&rollback_path)
                )
            })?;
        file.write_all(previous).map_err(|err| {
            format!(
                "write rollback materialization {}: {err}",
                path_string(&rollback_path)
            )
        })?;
        set_private_runtime_file_permissions(&rollback_path).map_err(|err| {
            format!(
                "set rollback materialization permissions {}: {err}",
                path_string(&rollback_path)
            )
        })?;
        file.sync_all().map_err(|err| {
            format!(
                "sync rollback materialization {}: {err}",
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
