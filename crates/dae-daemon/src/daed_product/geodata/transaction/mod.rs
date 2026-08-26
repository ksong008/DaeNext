use super::*;

mod commit;
mod external_input;
mod files;

pub(super) use commit::commit_geodata_generation;
pub(super) use dae_product_geodata::recover_geodata_transaction;
pub(in crate::daed_product) use dae_product_geodata::recover_geodata_transactions;
pub(super) use external_input::runtime_input_versions_if_running;

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
    pub(super) input_versions_before: Option<dae_product_geodata::RuntimeInputVersions>,
}

#[cfg(test)]
pub(super) use commit::commit_geodata_generation_with_checkpoints;
#[cfg(test)]
pub(super) use dae_product_geodata::RuntimeInputVersions;
#[cfg(test)]
pub(super) use dae_product_geodata::{
    GeodataJournalPhase, GeodataUpdateJournal, write_geodata_journal,
};
