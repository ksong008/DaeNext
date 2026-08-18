use super::*;
use crate::daed_product::durable_commit::{
    ensure_private_directory, reserve_private_file, sync_directory as sync_durable_directory,
};

pub(super) struct PreparedRuntimeGeneration {
    pub(super) generation: String,
    pub(super) candidate_path: Option<PathBuf>,
    pub(super) output_path: Option<PathBuf>,
    pub(super) previous_content: Option<Vec<u8>>,
    pub(super) database_snapshot: RuntimeDatabaseSnapshot,
    pub(super) journal_path: Option<PathBuf>,
    pub(super) backup_path: Option<PathBuf>,
    probe_generation: Option<u64>,
    committed: bool,
}

#[derive(Clone, Debug, Default)]
pub(super) struct RuntimeDatabaseSnapshot {
    pub(super) system: Option<RuntimeSystemSnapshot>,
    pub(super) metadata: Vec<(String, Option<String>)>,
}

#[derive(Clone, Debug)]
pub(super) struct RuntimeSystemSnapshot {
    pub(super) running: i64,
    pub(super) config_version: i64,
    pub(super) dns_version: i64,
    pub(super) routing_version: i64,
    pub(super) group_version_sum: i64,
    pub(super) group_ids: String,
    pub(super) config_id: i64,
    pub(super) dns_id: i64,
    pub(super) routing_id: i64,
    pub(super) external_input_version: i64,
}

impl PreparedRuntimeGeneration {
    pub(super) fn set_probe_generation(&mut self, generation: Option<u64>) {
        self.probe_generation = generation;
    }

    pub(super) fn probe_generation(&self) -> Option<u64> {
        self.probe_generation
    }

    pub(super) fn mark_committed(&mut self) {
        self.committed = true;
        self.candidate_path = None;
    }

    pub(super) fn discard_rollback_state(&mut self) {
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

pub(super) fn prepare_runtime_generation(
    state: &Path,
    config_dir: Option<&Path>,
    plan: &RuntimeMaterializationPlan,
    generation: &str,
    checkpoints: &mut dyn FaultCheckpoints<RuntimeApplyCheckpoint>,
) -> Result<PreparedRuntimeGeneration, String> {
    ensure_state_schema(state).map_err(|err| format!("prepare runtime state: {err}"))?;
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
            probe_generation: None,
            committed: false,
        });
    };
    let runtime_dir = config_dir.join("runtime");
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::CreateDirectory)
        .map_err(|err| format!("prepare runtime directory checkpoint: {err}"))?;
    ensure_private_directory(&runtime_dir).map_err(|err| {
        format!(
            "create runtime directory {}: {err}",
            path_string(&runtime_dir)
        )
    })?;
    let output_path = runtime_dir.join("generated.dae");
    let previous_content = match fs::read(&output_path) {
        Ok(content) => Some(content),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(format!(
                "read previous runtime materialization {}: {err}",
                path_string(&output_path)
            ));
        }
    };
    let candidate_path = runtime_dir.join(format!(".generated.dae.{generation}.candidate"));
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::WriteCandidate)
        .map_err(|err| format!("write runtime candidate checkpoint: {err}"))?;
    let candidate = PreparedRuntimeGeneration {
        generation: generation.to_owned(),
        candidate_path: Some(candidate_path),
        output_path: Some(output_path),
        previous_content,
        database_snapshot,
        journal_path: None,
        backup_path: None,
        probe_generation: None,
        committed: false,
    };
    let candidate_path = candidate
        .candidate_path
        .as_ref()
        .expect("prepared runtime candidate path is present");
    let mut file = reserve_private_file(candidate_path).map_err(|err| {
        format!(
            "create runtime candidate {}: {err}",
            path_string(candidate_path)
        )
    })?;
    file.write_all(plan.content.as_bytes()).map_err(|err| {
        format!(
            "write runtime candidate {}: {err}",
            path_string(candidate_path)
        )
    })?;
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::SyncCandidate)
        .map_err(|err| format!("sync runtime candidate checkpoint: {err}"))?;
    file.sync_all().map_err(|err| {
        format!(
            "sync runtime candidate {}: {err}",
            path_string(candidate_path)
        )
    })?;
    sync_directory(&runtime_dir)?;
    Ok(candidate)
}

fn snapshot_runtime_database(state: &Path) -> Result<RuntimeDatabaseSnapshot, String> {
    let conn = open_state_connection(state)
        .map_err(|err| format!("open runtime state for snapshot: {err}"))?;
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
        .map_err(|err| format!("snapshot running runtime state: {err}"))?;
    let mut metadata = Vec::with_capacity(RUNTIME_APPLY_SNAPSHOT_METADATA_KEYS.len());
    for key in RUNTIME_APPLY_SNAPSHOT_METADATA_KEYS {
        let value = conn
            .query_row(
                "SELECT value FROM daed_product_metadata WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| format!("snapshot runtime metadata {key}: {err}"))?;
        metadata.push(((*key).to_owned(), value));
    }
    Ok(RuntimeDatabaseSnapshot { system, metadata })
}

pub(super) fn sync_directory(path: &Path) -> Result<(), String> {
    sync_durable_directory(path)
        .map_err(|err| format!("sync directory {}: {err}", path_string(path)))
}
