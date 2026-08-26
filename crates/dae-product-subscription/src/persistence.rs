#[cfg(test)]
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use dae_product_persistence::{
    DurableArtifactSet, DurableTransaction, ValidatedLeafName, cleanup_matching_artifacts,
    copy_bounded_regular_file_synced, ensure_private_directory, read_json_journal,
    remove_file_if_exists, reserve_private_file, write_reserved_file_synced,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{PersistedSubscriptionContent, SUBSCRIPTION_MAX_BYTES};

const JOURNAL_FILE: &str = ".subscription-persist.apply-journal.json";
const JOURNAL_NEXT_FILE: &str = ".subscription-persist.apply-journal.next";
const JOURNAL_MAX_BYTES: u64 = 16 * 1024;
const ARTIFACT_ATTEMPTS: usize = 32;

#[derive(Debug, Deserialize, Serialize)]
struct SubscriptionPersistJournal {
    format: u32,
    generation: String,
    metadata_key: String,
    target: String,
    candidate: String,
    backup: Option<String>,
}

pub struct PreparedSubscriptionPersist {
    transaction: DurableTransaction,
    generation: String,
    metadata_key: String,
}

impl PreparedSubscriptionPersist {
    pub fn prepare(
        subscription_id: i64,
        content: PersistedSubscriptionContent<'_>,
    ) -> io::Result<Self> {
        let target = content.path().to_path_buf();
        let directory = target.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "persisted subscription path has no parent",
            )
        })?;
        ensure_private_directory(directory)?;
        let target_name = leaf_name(&target)?;
        let generation = format!(
            "{}-{}-{}",
            subscription_id,
            std::process::id(),
            fastrand::u64(..)
        );
        let candidate = reserve_artifact(directory, &target_name, &generation, "candidate")?;
        let write_result = content
            .copy_to(&candidate)
            .and_then(|()| File::open(&candidate)?.sync_all());
        if let Err(error) = write_result {
            let _ = remove_file_if_exists(&candidate);
            return Err(error);
        }
        let backup = if target.exists() {
            let backup = reserve_artifact(directory, &target_name, &generation, "backup")?;
            if let Err(error) = copy_file_synced(&target, &backup) {
                let _ = remove_file_if_exists(&candidate);
                let _ = remove_file_if_exists(&backup);
                return Err(error);
            }
            Some(backup)
        } else {
            None
        };
        let metadata_key = format!("subscription_persist_generation:{subscription_id}");
        let journal = SubscriptionPersistJournal {
            format: 1,
            generation: generation.clone(),
            metadata_key: metadata_key.clone(),
            target: target_name,
            candidate: leaf_name(&candidate)?,
            backup: backup.as_deref().map(leaf_name).transpose()?,
        };
        validate_journal(&journal)?;
        let artifacts = DurableArtifactSet::new(
            directory.to_path_buf(),
            ValidatedLeafName::new(journal.target.clone())?,
            ValidatedLeafName::new(journal.candidate.clone())?,
            journal
                .backup
                .as_ref()
                .map(|name| ValidatedLeafName::new(name.clone()))
                .transpose()?,
            ValidatedLeafName::new(JOURNAL_FILE)?,
            ValidatedLeafName::new(JOURNAL_NEXT_FILE)?,
        )?;
        let transaction = DurableTransaction::new(artifacts);
        transaction.write_intent(JOURNAL_MAX_BYTES, &journal)?;
        Ok(Self {
            transaction,
            generation,
            metadata_key,
        })
    }

    pub fn activate(&mut self) -> io::Result<()> {
        self.transaction.activate()
    }

    pub fn record_generation(&self, tx: &Connection) -> io::Result<()> {
        tx.execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
            params![self.metadata_key, self.generation],
        )
        .map_err(subscription_sqlite_io_error)?;
        Ok(())
    }

    pub fn commit_database<R, E>(&mut self, commit: impl FnOnce() -> Result<R, E>) -> Result<R, E> {
        self.transaction.commit_database(commit)
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.transaction.finish_in_place()
    }

    pub fn rollback(mut self) -> io::Result<()> {
        self.transaction.rollback()
    }
}

impl Drop for PreparedSubscriptionPersist {
    fn drop(&mut self) {
        if self.transaction.needs_rollback() {
            let _ = self.transaction.rollback();
        }
    }
}

pub fn recover_subscription_persist_transaction(state: &Path, config_dir: &Path) -> io::Result<()> {
    let directory = config_dir.join("persist.d");
    let journal_path = directory.join(JOURNAL_FILE);
    let journal: SubscriptionPersistJournal =
        match read_json_journal(&journal_path, JOURNAL_MAX_BYTES) {
            Ok(journal) => journal,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return cleanup_orphan_artifacts(&directory);
            }
            Err(error) => return Err(error),
        };
    validate_journal(&journal)?;
    let committed = dae_product_persistence::open_state_connection(state)?
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![journal.metadata_key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(subscription_sqlite_io_error)?
        .as_deref()
        == Some(journal.generation.as_str());
    let artifacts = DurableArtifactSet::new(
        directory,
        ValidatedLeafName::new(journal.target.clone())?,
        ValidatedLeafName::new(journal.candidate.clone())?,
        journal
            .backup
            .as_ref()
            .map(|name| ValidatedLeafName::new(name.clone()))
            .transpose()?,
        ValidatedLeafName::new(JOURNAL_FILE)?,
        ValidatedLeafName::new(JOURNAL_NEXT_FILE)?,
    )?;
    DurableTransaction::reconcile(artifacts, committed)
}

impl PersistedSubscriptionContent<'_> {
    fn path(&self) -> &Path {
        match self {
            Self::Bytes { path, .. } => path,
            Self::StagedFile { path, .. } => path,
        }
    }

    fn copy_to(&self, destination: &Path) -> io::Result<()> {
        match self {
            Self::Bytes { bytes, .. } => {
                if bytes.len() > SUBSCRIPTION_MAX_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "persisted subscription content exceeds size limit",
                    ));
                }
                write_reserved_file_synced(destination, bytes)
            }
            Self::StagedFile { staging, .. } => copy_bounded_regular_file_synced(
                staging,
                destination,
                SUBSCRIPTION_MAX_BYTES as u64,
            ),
        }
    }
}

fn reserve_artifact(
    directory: &Path,
    target: &str,
    generation: &str,
    kind: &str,
) -> io::Result<PathBuf> {
    for attempt in 0..ARTIFACT_ATTEMPTS {
        let path = directory.join(format!(".{target}.{generation}.{attempt}.{kind}"));
        match reserve_private_file(&path) {
            Ok(file) => {
                drop(file);
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot reserve persisted subscription transaction artifact",
    ))
}

fn copy_file_synced(source: &Path, destination: &Path) -> io::Result<()> {
    copy_bounded_regular_file_synced(source, destination, SUBSCRIPTION_MAX_BYTES as u64)
}

fn validate_journal(journal: &SubscriptionPersistJournal) -> io::Result<()> {
    if journal.format != 1
        || journal.generation.is_empty()
        || journal.generation.len() > 128
        || !journal
            .generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !journal
            .metadata_key
            .starts_with("subscription_persist_generation:")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid subscription persist journal header",
        ));
    }
    for name in [
        Some(journal.target.as_str()),
        Some(journal.candidate.as_str()),
        journal.backup.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        ValidatedLeafName::new(name)?;
    }
    if !journal.target.ends_with(".sub")
        || !journal
            .candidate
            .starts_with(&format!(".{}.", journal.target))
        || !journal
            .candidate
            .contains(&format!(".{}.", journal.generation))
        || !journal.candidate.ends_with(".candidate")
        || journal.backup.as_deref().is_some_and(|backup| {
            !backup.starts_with(&format!(".{}.", journal.target))
                || !backup.contains(&format!(".{}.", journal.generation))
                || !backup.ends_with(".backup")
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription persist journal path contract mismatch",
        ));
    }
    Ok(())
}

fn leaf_name(path: &Path) -> io::Result<String> {
    ValidatedLeafName::from_path(path).map(|leaf| leaf.to_string())
}

fn cleanup_orphan_artifacts(directory: &Path) -> io::Result<()> {
    cleanup_matching_artifacts(directory, |name| {
        if name == JOURNAL_NEXT_FILE
            || (name.starts_with('.')
                && (name.ends_with(".candidate") || name.ends_with(".backup")))
        {
            return true;
        }
        false
    })
}

fn subscription_sqlite_io_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FreshProductState {
        root: PathBuf,
        state: PathBuf,
    }

    impl FreshProductState {
        fn new(scope: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "dae-product-subscription-{scope}-{}",
                fastrand::u64(..)
            ));
            fs::create_dir_all(&root).unwrap();
            let state = root.join("state.db");
            let connection = rusqlite::Connection::open(&state).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE daed_product_metadata (
                        key TEXT PRIMARY KEY NOT NULL,
                        value TEXT NOT NULL
                    );",
                )
                .unwrap();
            Self { root, state }
        }

        fn root(&self) -> &Path {
            &self.root
        }

        fn state(&self) -> &Path {
            &self.state
        }

        fn connection(&self) -> rusqlite::Connection {
            rusqlite::Connection::open(&self.state).unwrap()
        }
    }

    impl Drop for FreshProductState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn interrupted_persist_fixture(
        scope: &str,
        database_committed: bool,
    ) -> (FreshProductState, PathBuf) {
        let fixture = FreshProductState::new(scope);
        let config_dir = fixture.root().join("config");
        let target = config_dir.join("persist.d/source.sub");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"old-content").unwrap();
        let content = PersistedSubscriptionContent::Bytes {
            path: &target,
            bytes: b"new-content",
        };
        let mut prepared = PreparedSubscriptionPersist::prepare(7, content).unwrap();
        prepared.activate().unwrap();
        if database_committed {
            let conn = fixture.connection();
            prepared.record_generation(&conn).unwrap();
        }
        std::mem::forget(prepared);
        (fixture, config_dir)
    }

    #[test]
    fn recovery_restores_old_content_without_database_generation() {
        let (fixture, config_dir) =
            interrupted_persist_fixture("subscription-persist-rollback", false);

        recover_subscription_persist_transaction(fixture.state(), &config_dir).unwrap();
        recover_subscription_persist_transaction(fixture.state(), &config_dir).unwrap();

        assert_eq!(
            fs::read(config_dir.join("persist.d/source.sub")).unwrap(),
            b"old-content"
        );
    }

    #[test]
    fn dropping_uncommitted_persist_restores_old_content() {
        let fixture = FreshProductState::new("subscription-persist-drop-rollback");
        let target = fixture.root().join("config/persist.d/source.sub");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"old-content").unwrap();
        let content = PersistedSubscriptionContent::Bytes {
            path: &target,
            bytes: b"new-content",
        };
        let mut prepared = PreparedSubscriptionPersist::prepare(7, content).unwrap();
        prepared.activate().unwrap();

        drop(prepared);

        assert_eq!(fs::read(&target).unwrap(), b"old-content");
        assert!(
            fs::read_dir(target.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.'))
        );
    }

    #[test]
    fn recovery_keeps_new_content_with_committed_database_generation() {
        let (fixture, config_dir) =
            interrupted_persist_fixture("subscription-persist-commit", true);

        recover_subscription_persist_transaction(fixture.state(), &config_dir).unwrap();
        recover_subscription_persist_transaction(fixture.state(), &config_dir).unwrap();

        assert_eq!(
            fs::read(config_dir.join("persist.d/source.sub")).unwrap(),
            b"new-content"
        );
        assert!(
            fs::read_dir(config_dir.join("persist.d"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.'))
        );
    }
}
