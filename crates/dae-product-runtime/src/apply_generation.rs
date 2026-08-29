use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use dae_product_persistence::{
    DurableTransaction, ensure_private_directory, ensure_state_schema, open_state_connection,
    reserve_private_file, sync_directory as sync_durable_directory,
};
use rusqlite::{OptionalExtension, params};

use crate::{
    RUNTIME_ACTIVE_FINGERPRINT_METADATA_KEY, RUNTIME_GENERATION_METADATA_KEY,
    RUNTIME_PROBE_GENERATION_METADATA_KEY, RUNTIME_PROCESS_TRANSITION_METADATA_KEY,
};
use dae_product_core::path_string;

pub const RUNTIME_RUNNING_METADATA_KEY: &str = "runtime_running";
pub const RUNTIME_TRANSITION_PHASE_METADATA_KEY: &str = "runtime_transition_phase";
pub const LAST_MATERIALIZED_AT_METADATA_KEY: &str = "last_materialized_at";
pub const LAST_GENERATED_CONFIG_PATH_METADATA_KEY: &str = "last_generated_config_path";
pub const RUNTIME_LOG_LEVEL_METADATA_KEY: &str = "runtime_log_level";
pub const RUNTIME_LAST_APPLY_ERROR_METADATA_KEY: &str = "runtime_last_apply_error";

pub const RUNTIME_APPLY_SNAPSHOT_METADATA_KEYS: &[&str] = &[
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
pub enum RuntimeApplyCheckpoint {
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

pub struct PreparedRuntimeGeneration {
    pub generation: String,
    pub candidate_path: Option<PathBuf>,
    pub output_path: Option<PathBuf>,
    pub previous_content: Option<Vec<u8>>,
    pub database_snapshot: RuntimeDatabaseSnapshot,
    pub journal_path: Option<PathBuf>,
    pub backup_path: Option<PathBuf>,
    pub transaction: Option<DurableTransaction>,
    probe_generation: Option<u64>,
    committed: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeDatabaseSnapshot {
    pub system: Option<RuntimeSystemSnapshot>,
    pub metadata: Vec<(String, Option<String>)>,
}

#[derive(Clone, Debug)]
pub struct RuntimeSystemSnapshot {
    pub running: i64,
    pub config_version: i64,
    pub dns_version: i64,
    pub routing_version: i64,
    pub group_version_sum: i64,
    pub group_ids: String,
    pub config_id: i64,
    pub dns_id: i64,
    pub routing_id: i64,
    pub external_input_version: i64,
}

impl PreparedRuntimeGeneration {
    pub fn set_probe_generation(&mut self, generation: Option<u64>) {
        self.probe_generation = generation;
    }

    pub fn probe_generation(&self) -> Option<u64> {
        self.probe_generation
    }

    pub fn mark_committed(&mut self) {
        self.committed = true;
        self.candidate_path = None;
    }

    pub fn discard_rollback_state(&mut self) {
        self.previous_content = None;
        self.database_snapshot = RuntimeDatabaseSnapshot::default();
    }
}

impl Drop for PreparedRuntimeGeneration {
    fn drop(&mut self) {
        if !self.committed
            && let Some(path) = self.candidate_path.as_ref()
        {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn prepare_runtime_generation(
    state: &Path,
    config_dir: Option<&Path>,
    plan: &crate::RuntimeMaterializationPlan,
    generation: &str,
    checkpoints: &mut dyn dae_product_persistence::FaultCheckpoints<RuntimeApplyCheckpoint>,
) -> Result<PreparedRuntimeGeneration, String> {
    ensure_state_schema(state).map_err(|error| format!("prepare runtime state: {error}"))?;
    let database_snapshot = snapshot_runtime_database(state)?;
    let Some(config_dir) = config_dir else {
        return Ok(PreparedRuntimeGeneration {
            generation: generation.to_owned(),
            candidate_path: None,
            output_path: None,
            previous_content: None,
            database_snapshot,
            journal_path: None,
            backup_path: None,
            transaction: None,
            probe_generation: None,
            committed: false,
        });
    };
    let runtime_dir = config_dir.join("runtime");
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::CreateDirectory)
        .map_err(|error| format!("prepare runtime directory checkpoint: {error}"))?;
    ensure_private_directory(&runtime_dir).map_err(|error| {
        format!(
            "create runtime directory {}: {error}",
            path_string(&runtime_dir)
        )
    })?;
    let output_path = runtime_dir.join("generated.dae");
    let previous_content = match fs::read(&output_path) {
        Ok(content) => Some(content),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "read previous runtime materialization {}: {error}",
                path_string(&output_path)
            ));
        }
    };
    let candidate_path = runtime_dir.join(format!(".generated.dae.{generation}.candidate"));
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::WriteCandidate)
        .map_err(|error| format!("write runtime candidate checkpoint: {error}"))?;
    let candidate = PreparedRuntimeGeneration {
        generation: generation.to_owned(),
        candidate_path: Some(candidate_path),
        output_path: Some(output_path),
        previous_content,
        database_snapshot,
        journal_path: None,
        backup_path: None,
        transaction: None,
        probe_generation: None,
        committed: false,
    };
    let candidate_path = candidate
        .candidate_path
        .as_ref()
        .ok_or_else(|| "prepared runtime candidate path is missing".to_owned())?;
    let mut file = reserve_private_file(candidate_path).map_err(|error| {
        format!(
            "create runtime candidate {}: {error}",
            path_string(candidate_path)
        )
    })?;
    file.write_all(plan.content.as_bytes()).map_err(|error| {
        format!(
            "write runtime candidate {}: {error}",
            path_string(candidate_path)
        )
    })?;
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::SyncCandidate)
        .map_err(|error| format!("sync runtime candidate checkpoint: {error}"))?;
    file.sync_all().map_err(|error| {
        format!(
            "sync runtime candidate {}: {error}",
            path_string(candidate_path)
        )
    })?;
    sync_directory(&runtime_dir)?;
    Ok(candidate)
}

fn snapshot_runtime_database(state: &Path) -> Result<RuntimeDatabaseSnapshot, String> {
    let conn = open_state_connection(state)
        .map_err(|error| format!("open runtime state for snapshot: {error}"))?;
    let system = conn
        .query_row(
            "SELECT running, running_config_version, running_dns_version,
                    running_routing_version, running_group_version_sum, running_group_ids,
                    running_config_id, running_dns_id, running_routing_id,
                    running_external_input_version
             FROM systems ORDER BY id LIMIT 1",
            [],
            |row| {
                Ok(RuntimeSystemSnapshot {
                    running: row.get(0)?,
                    config_version: row.get(1)?,
                    dns_version: row.get(2)?,
                    routing_version: row.get(3)?,
                    group_version_sum: row.get(4)?,
                    group_ids: row.get(5)?,
                    config_id: row.get(6)?,
                    dns_id: row.get(7)?,
                    routing_id: row.get(8)?,
                    external_input_version: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(|error| format!("snapshot running runtime state: {error}"))?;
    let mut metadata = Vec::with_capacity(RUNTIME_APPLY_SNAPSHOT_METADATA_KEYS.len());
    for key in RUNTIME_APPLY_SNAPSHOT_METADATA_KEYS {
        let value = conn
            .query_row(
                "SELECT value FROM daed_product_metadata WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| format!("snapshot runtime metadata {key}: {error}"))?;
        metadata.push(((*key).to_owned(), value));
    }
    Ok(RuntimeDatabaseSnapshot { system, metadata })
}

pub fn sync_directory(path: &Path) -> Result<(), String> {
    sync_durable_directory(path)
        .map_err(|error| format!("sync directory {}: {error}", path_string(path)))
}
