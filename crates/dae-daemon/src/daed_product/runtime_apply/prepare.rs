use super::*;
use std::fs::{File, OpenOptions};

pub(super) struct PreparedRuntimeGeneration {
    pub(super) generation: String,
    pub(super) candidate_path: Option<PathBuf>,
    pub(super) output_path: Option<PathBuf>,
    pub(super) previous_content: Option<Vec<u8>>,
    committed: bool,
}

impl PreparedRuntimeGeneration {
    pub(super) fn mark_committed(&mut self) {
        self.committed = true;
        self.candidate_path = None;
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
    checkpoints: &mut dyn RuntimeApplyCheckpoints,
) -> Result<PreparedRuntimeGeneration, String> {
    ensure_state_schema(state).map_err(|err| format!("prepare runtime state: {err}"))?;
    let Some(config_dir) = config_dir else {
        return Ok(PreparedRuntimeGeneration {
            generation: generation.to_owned(),
            candidate_path: None,
            output_path: None,
            previous_content: None,
            committed: false,
        });
    };
    let runtime_dir = config_dir.join("runtime");
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::CreateDirectory)
        .map_err(|err| format!("prepare runtime directory checkpoint: {err}"))?;
    fs::create_dir_all(&runtime_dir).map_err(|err| {
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
        committed: false,
    };
    let candidate_path = candidate
        .candidate_path
        .as_ref()
        .expect("prepared runtime candidate path is present");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(candidate_path)
        .map_err(|err| {
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
    set_private_runtime_file_permissions(candidate_path).map_err(|err| {
        format!(
            "set runtime candidate permissions {}: {err}",
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

pub(super) fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| format!("sync directory {}: {err}", path_string(path)))
}
