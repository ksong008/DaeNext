use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use dae_product_persistence::{
    FaultCheckpoints, copy_regular_file_synced, remove_file_if_exists, sync_directory,
    write_reserved_file_synced,
};
use serde_json::Value;

use crate::{
    GeodataJournalPhase, GeodataKind, GeodataUpdateJournal, ProductGeodataUpdateCoordinator,
    RuntimeInputVersions, ensure_runtime_input_versions_bumped, finalize_committed_geodata_journal,
    geodata_resource_status_from_staged_parts, is_valid_geodata_release_version,
    rollback_geodata_journal, write_geodata_journal,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeodataTransactionCheckpoint {
    WriteVersionStage,
    BackupLiveFiles,
    WriteActivatingJournal,
    RenameData,
    RenameVersion,
    SyncActivatedDirectory,
    WriteFilesActivatedJournal,
    BumpExternalInput,
    CleanupCommitted,
}

#[derive(Debug)]
pub struct GeodataCommitResult {
    pub status: Value,
    pub runtime_reload_required: bool,
}

#[derive(Debug)]
pub struct PreparedGeodataGeneration {
    pub data_stage: PathBuf,
    pub version: String,
    pub summary: dae_geodata::GeoDataSummary,
    pub sha256: String,
    pub input_versions_before: Option<RuntimeInputVersions>,
}

pub fn commit_geodata_generation(
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

pub fn commit_geodata_generation_with_checkpoints(
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
    let status = match geodata_resource_status_from_staged_parts(
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

fn write_version_stage(
    coordinator: &ProductGeodataUpdateCoordinator,
    dir: &Path,
    kind: GeodataKind,
    version: &str,
) -> io::Result<PathBuf> {
    if !is_valid_geodata_release_version(version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid geodata release version: {version}"),
        ));
    }
    let path = coordinator.reserve_staging_path(dir, kind, "version")?;
    let result = write_reserved_file_synced(&path, format!("{version}\n").as_bytes());
    if let Err(error) = result {
        let _ = remove_file_if_exists(&path);
        return Err(error);
    }
    Ok(path)
}

fn backup_live_file(
    coordinator: &ProductGeodataUpdateCoordinator,
    dir: &Path,
    kind: GeodataKind,
    live_path: &Path,
    purpose: &str,
) -> io::Result<Option<PathBuf>> {
    match fs::metadata(live_path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let backup_path = coordinator.reserve_staging_path(dir, kind, purpose)?;
    if let Err(error) = copy_regular_file_synced(live_path, &backup_path) {
        let _ = remove_file_if_exists(&backup_path);
        return Err(error);
    }
    Ok(Some(backup_path))
}

fn remove_paths_best_effort(paths: impl IntoIterator<Item = PathBuf>) {
    for path in paths {
        let _ = remove_file_if_exists(&path);
    }
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

struct NoopFaultCheckpoints;

impl<Point: Copy> FaultCheckpoints<Point> for NoopFaultCheckpoints {
    fn checkpoint(&mut self, _point: Point) -> io::Result<()> {
        Ok(())
    }
}
