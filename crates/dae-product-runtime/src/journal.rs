use dae_product_persistence::{
    DurableArtifactSet, DurableTransaction, ValidatedLeafName, cleanup_matching_artifacts,
    create_synced_file, open_state_connection, read_json_journal,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

pub const RUNTIME_GENERATION_METADATA_KEY: &str = "runtime_generation_id";
pub const RUNTIME_PROCESS_TRANSITION_METADATA_KEY: &str = "runtime_pending_process_transition";
const RUNTIME_APPLY_JOURNAL: &str = ".generated.dae.apply-journal.json";
const RUNTIME_APPLY_JOURNAL_NEXT: &str = ".generated.dae.apply-journal.next";
const RUNTIME_APPLY_JOURNAL_MAX_BYTES: u64 = 16 * 1024;

#[derive(Debug, Deserialize, Serialize)]
struct RuntimeApplyJournal {
    format: u32,
    generation: String,
    output: String,
    candidate: String,
    backup: Option<String>,
}

pub struct RuntimeApplyTransactionParts {
    pub transaction: DurableTransaction,
    pub journal_path: PathBuf,
    pub backup_path: Option<PathBuf>,
}

pub fn prepare_runtime_apply_transaction(
    runtime_dir: &Path,
    generation: &str,
    output: &Path,
    candidate: &Path,
    previous_content: Option<&[u8]>,
) -> Result<RuntimeApplyTransactionParts, String> {
    let artifacts = runtime_artifact_set(runtime_dir, generation, previous_content.is_some())?;
    if artifacts.target_path() != output || artifacts.candidate_path() != candidate {
        return Err("runtime apply artifact paths do not match the generation".to_owned());
    }
    let backup_path = artifacts.backup_path();
    if let (Some(previous), Some(backup)) = (previous_content, backup_path.as_ref()) {
        create_synced_file(backup, previous).map_err(|error| {
            format!("create runtime apply backup {}: {error}", backup.display())
        })?;
    }
    let journal = RuntimeApplyJournal {
        format: 1,
        generation: generation.to_owned(),
        output: leaf_name(output)?,
        candidate: leaf_name(candidate)?,
        backup: backup_path.as_deref().map(leaf_name).transpose()?,
    };
    let transaction = DurableTransaction::new(artifacts);
    transaction
        .write_intent(RUNTIME_APPLY_JOURNAL_MAX_BYTES, &journal)
        .map_err(|error| {
            format!(
                "write runtime apply journal {}: {error}",
                transaction.artifacts().journal_path().display()
            )
        })?;
    Ok(RuntimeApplyTransactionParts {
        journal_path: transaction.artifacts().journal_path(),
        transaction,
        backup_path,
    })
}

pub fn recover_runtime_apply_transaction(state: &Path, config_dir: &Path) -> Result<(), String> {
    let runtime_dir = config_dir.join("runtime");
    let journal_path = runtime_dir.join(RUNTIME_APPLY_JOURNAL);
    let journal: RuntimeApplyJournal =
        match read_json_journal(&journal_path, RUNTIME_APPLY_JOURNAL_MAX_BYTES) {
            Ok(journal) => journal,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return cleanup_orphan_runtime_transaction_files(&runtime_dir);
            }
            Err(error) => {
                return Err(format!(
                    "inspect runtime apply journal {}: {error}",
                    journal_path.display()
                ));
            }
        };
    validate_journal(&journal)?;
    let artifacts = DurableArtifactSet::new(
        &runtime_dir,
        ValidatedLeafName::new(journal.output.clone()).map_err(|error| error.to_string())?,
        ValidatedLeafName::new(journal.candidate.clone()).map_err(|error| error.to_string())?,
        journal
            .backup
            .as_ref()
            .map(|leaf| ValidatedLeafName::new(leaf.clone()).map_err(|error| error.to_string()))
            .transpose()?,
        ValidatedLeafName::new(RUNTIME_APPLY_JOURNAL).map_err(|error| error.to_string())?,
        ValidatedLeafName::new(RUNTIME_APPLY_JOURNAL_NEXT).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let committed_generation = open_state_connection(state)
        .map_err(|error| format!("open runtime state for apply recovery: {error}"))?
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![RUNTIME_GENERATION_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| format!("read committed runtime generation: {error}"))?;
    DurableTransaction::recover(
        artifacts,
        committed_generation.as_deref() == Some(journal.generation.as_str()),
    )
    .map_err(|error| format!("recover runtime materialization transaction: {error}"))
}

fn validate_journal(journal: &RuntimeApplyJournal) -> Result<(), String> {
    if journal.format != 1 || journal.generation.is_empty() || journal.generation.len() > 128 {
        return Err("invalid runtime apply journal header".to_owned());
    }
    ValidatedLeafName::new(journal.output.clone()).map_err(|error| error.to_string())?;
    ValidatedLeafName::new(journal.candidate.clone()).map_err(|error| error.to_string())?;
    if journal.output != "generated.dae"
        || journal.candidate != format!(".generated.dae.{}.candidate", journal.generation)
    {
        return Err("runtime apply journal path does not match its generation".to_owned());
    }
    if let Some(backup) = journal.backup.as_deref() {
        ValidatedLeafName::new(backup.to_owned()).map_err(|error| error.to_string())?;
        if backup != format!(".generated.dae.{}.backup", journal.generation) {
            return Err("runtime apply journal backup does not match its generation".to_owned());
        }
    }
    Ok(())
}

fn leaf_name(path: &Path) -> Result<String, String> {
    ValidatedLeafName::from_path(path)
        .map(|leaf| leaf.to_string())
        .map_err(|error| error.to_string())
}

fn cleanup_orphan_runtime_transaction_files(runtime_dir: &Path) -> Result<(), String> {
    cleanup_matching_artifacts(runtime_dir, |name| {
        name == RUNTIME_APPLY_JOURNAL_NEXT
            || (name.starts_with(".generated.dae.")
                && (name.ends_with(".candidate")
                    || name.ends_with(".rollback")
                    || name.ends_with(".backup")))
    })
    .map_err(|error| {
        format!(
            "cleanup runtime transaction directory {}: {error}",
            runtime_dir.display()
        )
    })
}

fn runtime_artifact_set(
    runtime_dir: &Path,
    generation: &str,
    has_backup: bool,
) -> Result<DurableArtifactSet, String> {
    DurableArtifactSet::new(
        runtime_dir,
        ValidatedLeafName::new("generated.dae").map_err(|error| error.to_string())?,
        ValidatedLeafName::new(format!(".generated.dae.{generation}.candidate"))
            .map_err(|error| error.to_string())?,
        has_backup
            .then(|| ValidatedLeafName::new(format!(".generated.dae.{generation}.backup")))
            .transpose()
            .map_err(|error| error.to_string())?,
        ValidatedLeafName::new(RUNTIME_APPLY_JOURNAL).map_err(|error| error.to_string())?,
        ValidatedLeafName::new(RUNTIME_APPLY_JOURNAL_NEXT).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_product_persistence::{ensure_state_schema, set_metadata};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

    struct RuntimeJournalFixture {
        root: PathBuf,
        state: PathBuf,
        config_dir: PathBuf,
    }

    impl Drop for RuntimeJournalFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn interrupted_apply_fixture(scope: &str, committed: bool) -> RuntimeJournalFixture {
        let root = std::env::temp_dir().join(format!(
            "dae-product-runtime-journal-{scope}-{}-{}",
            std::process::id(),
            NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let state = root.join("daed.db");
        let config_dir = root.join("config");
        let runtime_dir = config_dir.join("runtime");
        fs::create_dir_all(&runtime_dir).unwrap();
        ensure_state_schema(&state).unwrap();
        let generation = "test-generation";
        let output = runtime_dir.join("generated.dae");
        let candidate = runtime_dir.join(format!(".generated.dae.{generation}.candidate"));
        fs::write(&output, b"old-generation").unwrap();
        fs::write(&candidate, b"new-generation").unwrap();
        let parts = prepare_runtime_apply_transaction(
            &runtime_dir,
            generation,
            &output,
            &candidate,
            Some(b"old-generation"),
        )
        .unwrap();
        let mut transaction = parts.transaction;
        transaction.activate().unwrap();
        std::mem::forget(transaction);
        set_metadata(
            &state,
            RUNTIME_GENERATION_METADATA_KEY,
            if committed {
                generation
            } else {
                "old-generation"
            },
        )
        .unwrap();
        RuntimeJournalFixture {
            root,
            state,
            config_dir,
        }
    }

    #[test]
    fn recovery_restores_previous_file_when_database_commit_is_missing() {
        let fixture = interrupted_apply_fixture("rollback", false);

        recover_runtime_apply_transaction(&fixture.state, &fixture.config_dir).unwrap();
        recover_runtime_apply_transaction(&fixture.state, &fixture.config_dir).unwrap();

        assert_eq!(
            fs::read(fixture.config_dir.join("runtime/generated.dae")).unwrap(),
            b"old-generation"
        );
    }

    #[test]
    fn recovery_keeps_new_file_when_database_commit_completed() {
        let fixture = interrupted_apply_fixture("commit", true);

        recover_runtime_apply_transaction(&fixture.state, &fixture.config_dir).unwrap();
        recover_runtime_apply_transaction(&fixture.state, &fixture.config_dir).unwrap();

        assert_eq!(
            fs::read(fixture.config_dir.join("runtime/generated.dae")).unwrap(),
            b"new-generation"
        );
        assert!(
            fs::read_dir(fixture.config_dir.join("runtime"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.'))
        );
    }
}
