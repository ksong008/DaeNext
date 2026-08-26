use std::io;
use std::path::{Path, PathBuf};

use dae_product_persistence::{
    ValidatedLeafName, bump_runtime_external_input_version_with_connection,
    bump_runtime_geodata_input_version_with_connection, cleanup_matching_artifacts,
    copy_regular_file_synced, current_runtime_external_input_version,
    current_runtime_geodata_input_version, ensure_state_schema, open_state_connection,
    read_json_journal, remove_file_if_exists, remove_leaf_if_exists_synced, sync_directory,
    write_json_journal,
};
use rusqlite::TransactionBehavior;
use serde::{Deserialize, Serialize};

use crate::GeodataKind;

const GEODATA_JOURNAL_FORMAT_VERSION: u32 = 1;
const GEODATA_JOURNAL_MAX_BYTES: u64 = 64 * 1024;
const GEODATA_INTERNAL_ARTIFACT_PURPOSES: [&str; 4] =
    ["download", "version", "data-backup", "version-backup"];

#[derive(Clone, Copy, Debug)]
pub struct RuntimeInputVersions {
    pub external: i64,
    pub geodata: i64,
}

pub fn read_runtime_input_versions(state: &Path) -> io::Result<RuntimeInputVersions> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    Ok(RuntimeInputVersions {
        external: current_runtime_external_input_version(&conn)?,
        geodata: current_runtime_geodata_input_version(&conn)?,
    })
}

pub fn ensure_runtime_input_versions_bumped(
    state: &Path,
    versions_before: Option<RuntimeInputVersions>,
) -> io::Result<()> {
    let Some(versions_before) = versions_before else {
        return Ok(());
    };
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(io::Error::other)?;
    let current_external = current_runtime_external_input_version(&tx)?;
    if current_external < versions_before.external {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime external input version moved backwards from {} to {current_external}",
                versions_before.external
            ),
        ));
    }
    let current_geodata = current_runtime_geodata_input_version(&tx)?;
    if current_geodata < versions_before.geodata {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime geodata input version moved backwards from {} to {current_geodata}",
                versions_before.geodata
            ),
        ));
    }
    if current_external == versions_before.external {
        bump_runtime_external_input_version_with_connection(&tx)?;
    }
    if current_geodata == versions_before.geodata {
        bump_runtime_geodata_input_version_with_connection(&tx)?;
    }
    tx.commit().map_err(io::Error::other)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeodataJournalPhase {
    Activating,
    FilesActivated,
    RollingBack,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeodataUpdateJournal {
    format_version: u32,
    kind: String,
    pub phase: GeodataJournalPhase,
    pub data_stage: String,
    pub version_stage: String,
    pub data_backup: Option<String>,
    pub version_backup: Option<String>,
    pub external_input_version_before: Option<i64>,
    #[serde(default)]
    pub geodata_input_version_before: Option<i64>,
}

impl GeodataUpdateJournal {
    pub fn new(
        kind: GeodataKind,
        data_stage: &Path,
        version_stage: &Path,
        data_backup: Option<&Path>,
        version_backup: Option<&Path>,
        external_input_version_before: Option<i64>,
        geodata_input_version_before: Option<i64>,
    ) -> io::Result<Self> {
        let journal = Self {
            format_version: GEODATA_JOURNAL_FORMAT_VERSION,
            kind: kind.response_key().to_owned(),
            phase: GeodataJournalPhase::Activating,
            data_stage: artifact_file_name(data_stage)?,
            version_stage: artifact_file_name(version_stage)?,
            data_backup: data_backup.map(artifact_file_name).transpose()?,
            version_backup: version_backup.map(artifact_file_name).transpose()?,
            external_input_version_before,
            geodata_input_version_before,
        };
        journal.validate(kind)?;
        Ok(journal)
    }

    pub fn validate(&self, expected_kind: GeodataKind) -> io::Result<()> {
        if self.format_version != GEODATA_JOURNAL_FORMAT_VERSION {
            return Err(invalid_journal("unsupported geodata journal format"));
        }
        if self.kind != expected_kind.response_key() {
            return Err(invalid_journal("geodata journal kind mismatch"));
        }
        validate_artifact_name(&self.data_stage, expected_kind, "download")?;
        validate_artifact_name(&self.version_stage, expected_kind, "version")?;
        if let Some(name) = self.data_backup.as_deref() {
            validate_artifact_name(name, expected_kind, "data-backup")?;
        }
        if let Some(name) = self.version_backup.as_deref() {
            validate_artifact_name(name, expected_kind, "version-backup")?;
        }
        if self
            .external_input_version_before
            .is_some_and(|value| value < 0)
            || self
                .geodata_input_version_before
                .is_some_and(|value| value < 0)
        {
            return Err(invalid_journal("geodata journal input version is negative"));
        }
        Ok(())
    }

    pub fn artifact_path(&self, dir: &Path, name: &str) -> PathBuf {
        dir.join(name)
    }

    pub fn artifact_paths(&self, dir: &Path) -> Vec<PathBuf> {
        let mut paths = vec![
            self.artifact_path(dir, &self.data_stage),
            self.artifact_path(dir, &self.version_stage),
        ];
        if let Some(name) = self.data_backup.as_deref() {
            paths.push(self.artifact_path(dir, name));
        }
        if let Some(name) = self.version_backup.as_deref() {
            paths.push(self.artifact_path(dir, name));
        }
        paths
    }
}

pub fn write_geodata_journal(
    dir: &Path,
    kind: GeodataKind,
    journal: &GeodataUpdateJournal,
) -> io::Result<()> {
    journal.validate(kind)?;
    write_json_journal(
        dir,
        &geodata_journal_leaf(kind)?,
        &geodata_journal_next_leaf(kind)?,
        GEODATA_JOURNAL_MAX_BYTES,
        journal,
    )
}

pub fn recover_geodata_transactions(dir: &Path, state: &Path) -> io::Result<()> {
    for kind in [GeodataKind::Geosite, GeodataKind::Geoip] {
        recover_geodata_transaction(dir, state, kind)?;
    }
    Ok(())
}

pub fn recover_geodata_transaction(dir: &Path, state: &Path, kind: GeodataKind) -> io::Result<()> {
    let Some(mut journal) = read_geodata_journal(dir, kind)? else {
        remove_file_if_exists(&geodata_journal_next_path(dir, kind))?;
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

pub fn rollback_geodata_journal(
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

pub fn finalize_committed_geodata_journal(
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

fn read_geodata_journal(dir: &Path, kind: GeodataKind) -> io::Result<Option<GeodataUpdateJournal>> {
    let journal: GeodataUpdateJournal =
        match read_json_journal(&geodata_journal_path(dir, kind), GEODATA_JOURNAL_MAX_BYTES) {
            Ok(journal) => journal,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
    journal.validate(kind)?;
    Ok(Some(journal))
}

fn restore_live_file(
    dir: &Path,
    live_path: &Path,
    backup_name: Option<&str>,
    journal: &GeodataUpdateJournal,
) -> io::Result<()> {
    if let Some(backup_name) = backup_name {
        copy_regular_file_synced(&journal.artifact_path(dir, backup_name), live_path)
    } else {
        remove_file_if_exists(live_path)
    }
}

fn remove_geodata_journal_durable(dir: &Path, kind: GeodataKind) -> io::Result<()> {
    remove_leaf_if_exists_synced(dir, &geodata_journal_leaf(kind)?)?;
    remove_file_if_exists(&geodata_journal_next_path(dir, kind))?;
    sync_directory(dir)
}

fn remove_paths_best_effort(paths: impl IntoIterator<Item = PathBuf>) {
    for path in paths {
        let _ = remove_file_if_exists(&path);
    }
}

fn cleanup_orphaned_internal_artifacts(dir: &Path, kind: GeodataKind) -> io::Result<()> {
    cleanup_matching_artifacts(dir, |name| {
        GEODATA_INTERNAL_ARTIFACT_PURPOSES
            .iter()
            .any(|purpose| name.starts_with(&format!(".{}.{}.tmp.", kind.file_name(), purpose)))
    })
}

fn artifact_file_name(path: &Path) -> io::Result<String> {
    ValidatedLeafName::from_path(path).map(|leaf| leaf.to_string())
}

fn validate_artifact_name(name: &str, kind: GeodataKind, purpose: &str) -> io::Result<()> {
    ValidatedLeafName::new(name)?;
    let expected_prefix = format!(".{}.{}.tmp.", kind.file_name(), purpose);
    if !name.starts_with(&expected_prefix) {
        return Err(invalid_journal(format!(
            "invalid geodata transaction artifact name: {name}"
        )));
    }
    Ok(())
}

fn geodata_journal_path(dir: &Path, kind: GeodataKind) -> PathBuf {
    dir.join(format!(".{}.update-journal.json", kind.file_name()))
}

fn geodata_journal_next_path(dir: &Path, kind: GeodataKind) -> PathBuf {
    dir.join(format!(".{}.update-journal.next", kind.file_name()))
}

fn geodata_journal_leaf(kind: GeodataKind) -> io::Result<ValidatedLeafName> {
    ValidatedLeafName::new(format!(".{}.update-journal.json", kind.file_name()))
}

fn geodata_journal_next_leaf(kind: GeodataKind) -> io::Result<ValidatedLeafName> {
    ValidatedLeafName::new(format!(".{}.update-journal.next", kind.file_name()))
}

fn invalid_journal(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
