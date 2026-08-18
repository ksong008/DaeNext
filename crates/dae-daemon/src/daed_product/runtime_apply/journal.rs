use super::prepare::PreparedRuntimeGeneration;
use super::*;
use crate::daed_product::durable_commit::{
    DurableArtifactSet, DurableTransaction, ValidatedLeafName, cleanup_matching_artifacts,
    create_synced_file, read_json_journal,
};
use serde::{Deserialize, Serialize};

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

pub(super) fn write_runtime_apply_journal(
    candidate: &mut PreparedRuntimeGeneration,
) -> Result<(), String> {
    let output = candidate
        .output_path
        .as_ref()
        .ok_or_else(|| "runtime apply journal has no output path".to_owned())?;
    let staged = candidate
        .candidate_path
        .as_ref()
        .ok_or_else(|| "runtime apply journal has no candidate path".to_owned())?;
    let runtime_dir = output
        .parent()
        .ok_or_else(|| "runtime materialization path has no parent".to_owned())?;
    let artifacts = runtime_artifact_set(
        runtime_dir,
        &candidate.generation,
        candidate.previous_content.is_some(),
    )?;
    if artifacts.target_path() != *output || artifacts.candidate_path() != *staged {
        return Err("runtime apply artifact paths do not match the generation".to_owned());
    }
    let backup = artifacts.backup_path();
    if let (Some(previous), Some(backup)) = (candidate.previous_content.as_ref(), backup.as_ref()) {
        create_synced_file(backup, previous).map_err(|error| {
            format!(
                "create runtime apply backup {}: {error}",
                path_string(backup)
            )
        })?;
    }
    let journal = RuntimeApplyJournal {
        format: 1,
        generation: candidate.generation.clone(),
        output: leaf_name(output)?,
        candidate: leaf_name(staged)?,
        backup: backup.as_deref().map(leaf_name).transpose()?,
    };
    let transaction = DurableTransaction::new(artifacts);
    transaction
        .write_intent(RUNTIME_APPLY_JOURNAL_MAX_BYTES, &journal)
        .map_err(|error| {
            format!(
                "write runtime apply journal {}: {error}",
                path_string(&transaction.artifacts().journal_path())
            )
        })?;
    candidate.journal_path = Some(transaction.artifacts().journal_path());
    candidate.backup_path = backup;
    candidate.transaction = Some(transaction);
    Ok(())
}

pub(super) fn remove_runtime_apply_journal(
    candidate: &mut PreparedRuntimeGeneration,
) -> Result<(), String> {
    if let Some(transaction) = candidate.transaction.take() {
        transaction
            .finish()
            .map_err(|error| format!("finish runtime apply transaction: {error}"))?;
    }
    candidate.journal_path = None;
    candidate.backup_path = None;
    Ok(())
}

pub(in crate::daed_product) fn recover_runtime_apply_transaction(
    state: &Path,
    config_dir: &Path,
) -> Result<(), String> {
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
                    path_string(&journal_path)
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
        if name == RUNTIME_APPLY_JOURNAL_NEXT
            || (name.starts_with(".generated.dae.")
                && (name.ends_with(".candidate")
                    || name.ends_with(".rollback")
                    || name.ends_with(".backup")))
        {
            return true;
        }
        false
    })
    .map_err(|error| {
        format!(
            "cleanup runtime transaction directory {}: {error}",
            path_string(runtime_dir)
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
    use crate::daed_product::tests::support::FreshProductState;

    fn interrupted_apply_fixture(scope: &str, committed: bool) -> (FreshProductState, PathBuf) {
        let fixture = FreshProductState::new(scope);
        let config_dir = fixture.root().join("config");
        let runtime_dir = config_dir.join("runtime");
        fs::create_dir_all(&runtime_dir).unwrap();
        let generation = "test-generation";
        let output = runtime_dir.join("generated.dae");
        let candidate = runtime_dir.join(format!(".generated.dae.{generation}.candidate"));
        let backup = runtime_dir.join(format!(".generated.dae.{generation}.backup"));
        fs::write(&output, b"old-generation").unwrap();
        fs::write(&candidate, b"new-generation").unwrap();
        fs::write(&backup, b"old-generation").unwrap();
        fs::rename(&candidate, &output).unwrap();
        let journal = RuntimeApplyJournal {
            format: 1,
            generation: generation.to_owned(),
            output: "generated.dae".to_owned(),
            candidate: format!(".generated.dae.{generation}.candidate"),
            backup: Some(format!(".generated.dae.{generation}.backup")),
        };
        fs::write(
            runtime_dir.join(RUNTIME_APPLY_JOURNAL),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        set_metadata(
            fixture.state(),
            RUNTIME_GENERATION_METADATA_KEY,
            if committed {
                generation
            } else {
                "old-generation"
            },
        )
        .unwrap();
        (fixture, config_dir)
    }

    #[test]
    fn recovery_restores_previous_file_when_database_commit_is_missing() {
        let (fixture, config_dir) = interrupted_apply_fixture("runtime-journal-rollback", false);

        recover_runtime_apply_transaction(fixture.state(), &config_dir).unwrap();
        recover_runtime_apply_transaction(fixture.state(), &config_dir).unwrap();

        assert_eq!(
            fs::read(config_dir.join("runtime/generated.dae")).unwrap(),
            b"old-generation"
        );
        assert!(
            !config_dir
                .join("runtime")
                .join(RUNTIME_APPLY_JOURNAL)
                .exists()
        );
    }

    #[test]
    fn recovery_keeps_new_file_when_database_commit_completed() {
        let (fixture, config_dir) = interrupted_apply_fixture("runtime-journal-commit", true);

        recover_runtime_apply_transaction(fixture.state(), &config_dir).unwrap();
        recover_runtime_apply_transaction(fixture.state(), &config_dir).unwrap();

        assert_eq!(
            fs::read(config_dir.join("runtime/generated.dae")).unwrap(),
            b"new-generation"
        );
        assert!(
            fs::read_dir(config_dir.join("runtime"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.'))
        );
    }
}
