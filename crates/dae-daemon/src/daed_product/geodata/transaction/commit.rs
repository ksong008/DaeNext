use super::external_input::ensure_runtime_input_versions_bumped;
use super::files::{
    backup_live_file, remove_paths_best_effort, sync_directory, write_version_stage,
};
use super::journal::{GeodataJournalPhase, GeodataUpdateJournal, write_geodata_journal};
use super::recovery::{finalize_committed_geodata_journal, rollback_geodata_journal};
use super::*;

pub(in crate::daed_product::geodata) fn commit_geodata_generation(
    coordinator: &ProductGeodataUpdateCoordinator,
    state: &Path,
    dir: &Path,
    kind: GeodataKind,
    candidate: PreparedGeodataGeneration,
) -> io::Result<GeodataCommitResult> {
    let mut checkpoints = NoopFaultCheckpoints;
    commit_geodata_generation_with_checkpoints(
        coordinator,
        state,
        dir,
        kind,
        candidate,
        &mut checkpoints,
    )
}

pub(in crate::daed_product::geodata) fn commit_geodata_generation_with_checkpoints(
    coordinator: &ProductGeodataUpdateCoordinator,
    state: &Path,
    dir: &Path,
    kind: GeodataKind,
    candidate: PreparedGeodataGeneration,
    checkpoints: &mut dyn FaultCheckpoints<GeodataTransactionCheckpoint>,
) -> io::Result<GeodataCommitResult> {
    let PreparedGeodataGeneration {
        data_stage,
        version,
        summary,
        sha256,
        input_versions_before,
    } = candidate;
    if let Err(error) = checkpoints.checkpoint(GeodataTransactionCheckpoint::WriteVersionStage) {
        remove_paths_best_effort([data_stage]);
        return Err(error);
    }
    let version_stage = match write_version_stage(coordinator, dir, kind, &version) {
        Ok(path) => path,
        Err(error) => {
            remove_paths_best_effort([data_stage]);
            return Err(error);
        }
    };
    let status = match super::super::status::geodata_resource_status_from_staged_parts(
        &data_stage,
        kind,
        summary,
        sha256,
        &version,
    ) {
        Ok(status) => status,
        Err(error) => {
            remove_paths_best_effort([data_stage, version_stage]);
            return Err(error);
        }
    };
    if let Err(error) = checkpoints.checkpoint(GeodataTransactionCheckpoint::BackupLiveFiles) {
        remove_paths_best_effort([data_stage, version_stage]);
        return Err(error);
    }
    let data_live = dir.join(kind.file_name());
    let version_live = dir.join(kind.version_file_name());
    let data_backup = match backup_live_file(coordinator, dir, kind, &data_live, "data-backup") {
        Ok(path) => path,
        Err(error) => {
            remove_paths_best_effort([data_stage, version_stage]);
            return Err(error);
        }
    };
    let version_backup =
        match backup_live_file(coordinator, dir, kind, &version_live, "version-backup") {
            Ok(path) => path,
            Err(error) => {
                let mut paths = vec![data_stage, version_stage];
                paths.extend(data_backup);
                remove_paths_best_effort(paths);
                return Err(error);
            }
        };
    if let Err(error) = sync_directory(dir) {
        let mut paths = vec![data_stage, version_stage];
        paths.extend(data_backup);
        paths.extend(version_backup);
        remove_paths_best_effort(paths);
        return Err(error);
    }
    let mut journal = match GeodataUpdateJournal::new(
        kind,
        &data_stage,
        &version_stage,
        data_backup.as_deref(),
        version_backup.as_deref(),
        input_versions_before.map(|versions| versions.external),
        input_versions_before.map(|versions| versions.geodata),
    ) {
        Ok(journal) => journal,
        Err(error) => {
            let mut paths = vec![data_stage, version_stage];
            paths.extend(data_backup);
            paths.extend(version_backup);
            remove_paths_best_effort(paths);
            return Err(error);
        }
    };
    if let Err(error) = checkpoints.checkpoint(GeodataTransactionCheckpoint::WriteActivatingJournal)
    {
        remove_paths_best_effort(journal.artifact_paths(dir));
        return Err(error);
    }
    if let Err(error) = write_geodata_journal(dir, kind, &journal) {
        return Err(io::Error::new(
            error.kind(),
            format!("persist geodata activating journal: {error}"),
        ));
    }

    let activation = activate_files(dir, kind, &data_stage, &version_stage, checkpoints)
        .and_then(|()| {
            journal.phase = GeodataJournalPhase::FilesActivated;
            checkpoints.checkpoint(GeodataTransactionCheckpoint::WriteFilesActivatedJournal)?;
            write_geodata_journal(dir, kind, &journal)
        })
        .and_then(|()| {
            checkpoints.checkpoint(GeodataTransactionCheckpoint::BumpExternalInput)?;
            ensure_runtime_input_versions_bumped(state, input_versions_before)
        });
    if let Err(error) = activation {
        return rollback_after_failure(dir, kind, &mut journal, error);
    }

    if checkpoints
        .checkpoint(GeodataTransactionCheckpoint::CleanupCommitted)
        .is_ok()
    {
        let _ = finalize_committed_geodata_journal(dir, state, kind, &journal);
    }
    Ok(GeodataCommitResult {
        status,
        runtime_reload_required: input_versions_before.is_some(),
    })
}

fn activate_files(
    dir: &Path,
    kind: GeodataKind,
    data_stage: &Path,
    version_stage: &Path,
    checkpoints: &mut dyn FaultCheckpoints<GeodataTransactionCheckpoint>,
) -> io::Result<()> {
    checkpoints.checkpoint(GeodataTransactionCheckpoint::RenameData)?;
    fs::rename(data_stage, dir.join(kind.file_name()))?;
    checkpoints.checkpoint(GeodataTransactionCheckpoint::RenameVersion)?;
    fs::rename(version_stage, dir.join(kind.version_file_name()))?;
    checkpoints.checkpoint(GeodataTransactionCheckpoint::SyncActivatedDirectory)?;
    sync_directory(dir)
}

fn rollback_after_failure(
    dir: &Path,
    kind: GeodataKind,
    journal: &mut GeodataUpdateJournal,
    error: io::Error,
) -> io::Result<GeodataCommitResult> {
    journal.phase = GeodataJournalPhase::RollingBack;
    if let Err(journal_error) = write_geodata_journal(dir, kind, journal) {
        return Err(io::Error::new(
            error.kind(),
            format!(
                "geodata activation failed: {error}; persist rollback journal failed: {journal_error}; recovery is required"
            ),
        ));
    }
    match rollback_geodata_journal(dir, kind, journal) {
        Ok(()) => Err(io::Error::new(
            error.kind(),
            format!("geodata activation failed and previous generation was restored: {error}"),
        )),
        Err(rollback_error) => Err(io::Error::new(
            error.kind(),
            format!(
                "geodata activation failed: {error}; rollback failed: {rollback_error}; recovery is required"
            ),
        )),
    }
}
