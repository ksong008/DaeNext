use super::*;

mod commit;
mod external_input;
mod files;
mod journal;
mod recovery;

pub(super) use commit::commit_geodata_generation;
pub(super) use external_input::runtime_input_versions_if_running;
pub(super) use recovery::recover_geodata_transaction;
pub(in crate::daed_product) use recovery::recover_geodata_transactions;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GeodataTransactionCheckpoint {
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

pub(super) trait GeodataTransactionCheckpoints {
    fn checkpoint(&mut self, point: GeodataTransactionCheckpoint) -> io::Result<()>;
}

pub(super) struct NoopGeodataTransactionCheckpoints;

impl GeodataTransactionCheckpoints for NoopGeodataTransactionCheckpoints {
    fn checkpoint(&mut self, _point: GeodataTransactionCheckpoint) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct GeodataCommitResult {
    pub(super) status: Value,
    pub(super) runtime_reload_required: bool,
}

#[derive(Debug)]
pub(super) struct PreparedGeodataGeneration {
    pub(super) data_stage: PathBuf,
    pub(super) version: String,
    pub(super) summary: dae_geodata::GeoDataSummary,
    pub(super) sha256: String,
    pub(super) input_versions_before: Option<external_input::RuntimeInputVersions>,
}

#[cfg(test)]
pub(super) use commit::commit_geodata_generation_with_checkpoints;
#[cfg(test)]
pub(super) use external_input::RuntimeInputVersions;
#[cfg(test)]
pub(super) use journal::{GeodataJournalPhase, GeodataUpdateJournal, write_geodata_journal};
