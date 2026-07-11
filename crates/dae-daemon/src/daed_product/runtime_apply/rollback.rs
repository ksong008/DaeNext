use super::prepare::{PreparedRuntimeGeneration, sync_directory};
use super::*;
use std::fs::OpenOptions;

pub(super) fn rollback_runtime_generation(
    runtime: &ProductRuntimeManager,
    snapshot: &ProductRuntimeApplySnapshot,
    candidate: &mut PreparedRuntimeGeneration,
    latency_seed: &[Value],
    checkpoints: &mut dyn RuntimeApplyCheckpoints,
) -> Result<(), String> {
    checkpoints
        .checkpoint(RuntimeApplyCheckpoint::Rollback)
        .map_err(|err| format!("runtime rollback checkpoint: {err}"))?;
    let file_result = restore_previous_materialization(candidate);
    let runtime_result = runtime.restore_after_failed_apply(snapshot, latency_seed);
    match (file_result, runtime_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(file_err), Ok(())) => Err(file_err),
        (Ok(()), Err(runtime_err)) => Err(runtime_err),
        (Err(file_err), Err(runtime_err)) => Err(format!(
            "restore materialization failed: {file_err}; restore runtime failed: {runtime_err}"
        )),
    }
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
