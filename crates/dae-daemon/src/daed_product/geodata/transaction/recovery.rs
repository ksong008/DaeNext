use super::external_input::{RuntimeInputVersions, ensure_runtime_input_versions_bumped};
use super::files::{
    cleanup_orphaned_internal_artifacts, copy_file_durable, remove_file_if_exists,
    remove_paths_best_effort, sync_directory,
};
use super::journal::{
    GeodataJournalPhase, GeodataUpdateJournal, read_geodata_journal,
    remove_geodata_journal_durable, remove_geodata_journal_next, write_geodata_journal,
};
use super::*;

pub(in crate::daed_product) fn recover_geodata_transactions(
    dir: &Path,
    state: &Path,
) -> io::Result<()> {
    for kind in [GeodataKind::Geosite, GeodataKind::Geoip] {
        recover_geodata_transaction(dir, state, kind)?;
    }
    Ok(())
}

pub(in crate::daed_product::geodata) fn recover_geodata_transaction(
    dir: &Path,
    state: &Path,
    kind: GeodataKind,
) -> io::Result<()> {
    let Some(mut journal) = read_geodata_journal(dir, kind)? else {
        remove_geodata_journal_next(dir, kind)?;
        return cleanup_orphaned_internal_artifacts(dir, kind);
    };
    match journal.phase {
        GeodataJournalPhase::Activating => {
            journal.phase = GeodataJournalPhase::RollingBack;
            write_geodata_journal(dir, kind, &journal)?;
            rollback_geodata_journal(dir, kind, &journal)
        }
        GeodataJournalPhase::RollingBack => rollback_geodata_journal(dir, kind, &journal),
        GeodataJournalPhase::FilesActivated => {
            finalize_committed_geodata_journal(dir, state, kind, &journal)
        }
    }
}

pub(super) fn rollback_geodata_journal(
    dir: &Path,
    kind: GeodataKind,
    journal: &GeodataUpdateJournal,
) -> io::Result<()> {
    journal.validate(kind)?;
    restore_live_file(
        dir,
        &dir.join(kind.file_name()),
        journal.data_backup.as_deref(),
        journal,
    )?;
    restore_live_file(
        dir,
        &dir.join(kind.version_file_name()),
        journal.version_backup.as_deref(),
        journal,
    )?;
    sync_directory(dir)?;
    remove_geodata_journal_durable(dir, kind)?;
    remove_paths_best_effort(journal.artifact_paths(dir));
    Ok(())
}

pub(super) fn finalize_committed_geodata_journal(
    dir: &Path,
    state: &Path,
    kind: GeodataKind,
    journal: &GeodataUpdateJournal,
) -> io::Result<()> {
    journal.validate(kind)?;
    let versions_before =
        journal
            .external_input_version_before
            .map(|external| RuntimeInputVersions {
                external,
                geodata: journal.geodata_input_version_before.unwrap_or(0),
            });
    ensure_runtime_input_versions_bumped(state, versions_before)?;
    remove_geodata_journal_durable(dir, kind)?;
    remove_paths_best_effort(journal.artifact_paths(dir));
    Ok(())
}

fn restore_live_file(
    dir: &Path,
    live_path: &Path,
    backup_name: Option<&str>,
    journal: &GeodataUpdateJournal,
) -> io::Result<()> {
    if let Some(backup_name) = backup_name {
        let backup_path = journal.artifact_path(dir, backup_name);
        copy_file_durable(&backup_path, live_path)
    } else {
        remove_file_if_exists(live_path)
    }
}
