use std::path::Path;

use dae_product_persistence::{FaultCheckpoints, open_state_connection};
use rusqlite::{TransactionBehavior, params};

use crate::{
    LAST_GENERATED_CONFIG_PATH_METADATA_KEY, LAST_MATERIALIZED_AT_METADATA_KEY,
    PreparedRuntimeGeneration, RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY,
    RUNTIME_GENERATION_METADATA_KEY, RUNTIME_LAST_APPLY_ERROR_METADATA_KEY,
    RUNTIME_LOG_LEVEL_METADATA_KEY, RUNTIME_PROBE_GENERATION_METADATA_KEY,
    RUNTIME_PROCESS_TRANSITION_METADATA_KEY, RUNTIME_RUNNING_METADATA_KEY,
    RUNTIME_TRANSITION_PHASE_METADATA_KEY, RuntimeApplyCheckpoint, RuntimeDatabaseSnapshot,
    RuntimeMaterializationPlan,
};
use dae_product_core::path_string;

pub fn commit_runtime_state(
    state: &Path,
    plan: &RuntimeMaterializationPlan,
    runtime_log_level: &str,
    process_transition: Option<&serde_json::Value>,
    candidate: &PreparedRuntimeGeneration,
    checkpoints: &mut dyn FaultCheckpoints<RuntimeApplyCheckpoint>,
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
    set_metadata_in_transaction(&tx, LAST_MATERIALIZED_AT_METADATA_KEY, &plan.generated_at)?;
    set_metadata_in_transaction(&tx, RUNTIME_RUNNING_METADATA_KEY, "true")?;
    set_metadata_in_transaction(&tx, RUNTIME_GENERATION_METADATA_KEY, &candidate.generation)?;
    match candidate.probe_generation() {
        Some(generation) => set_metadata_in_transaction(
            &tx,
            RUNTIME_PROBE_GENERATION_METADATA_KEY,
            &generation.to_string(),
        )?,
        None => {
            tx.execute(
                "DELETE FROM daed_product_metadata WHERE key = ?1",
                params![RUNTIME_PROBE_GENERATION_METADATA_KEY],
            )
            .map_err(|err| format!("clear runtime probe generation: {err}"))?;
        }
    }
    set_metadata_in_transaction(&tx, RUNTIME_TRANSITION_PHASE_METADATA_KEY, "committed")?;
    set_metadata_in_transaction(&tx, RUNTIME_LOG_LEVEL_METADATA_KEY, runtime_log_level)?;
    set_metadata_in_transaction(
        &tx,
        RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY,
        plan.active_fingerprint.as_str(),
    )?;
    tx.execute(
        "DELETE FROM daed_product_metadata WHERE key = ?1",
        params![RUNTIME_LAST_APPLY_ERROR_METADATA_KEY],
    )
    .map_err(|err| format!("clear previous runtime apply error: {err}"))?;
    match process_transition {
        Some(transition) => set_metadata_in_transaction(
            &tx,
            RUNTIME_PROCESS_TRANSITION_METADATA_KEY,
            &transition.to_string(),
        )?,
        None => {
            tx.execute(
                "DELETE FROM daed_product_metadata WHERE key = ?1",
                params![RUNTIME_PROCESS_TRANSITION_METADATA_KEY],
            )
            .map_err(|err| format!("clear runtime process transition: {err}"))?;
        }
    }
    if let Some(output_path) = candidate.output_path.as_ref() {
        set_metadata_in_transaction(
            &tx,
            LAST_GENERATED_CONFIG_PATH_METADATA_KEY,
            &path_string(output_path),
        )?;
    }
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::CommitDatabase)
        .map_err(|err| format!("commit runtime database checkpoint: {err}"))?;
    tx.commit()
        .map_err(|err| format!("commit runtime state transaction: {err}"))
}

pub fn restore_runtime_database(
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
            crate::write_probe_generation(&tx, generation)?;
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
