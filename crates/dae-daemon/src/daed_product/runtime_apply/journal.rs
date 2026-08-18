use super::prepare::{PreparedRuntimeGeneration, sync_directory};
use super::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;

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
    let backup = candidate
        .previous_content
        .as_ref()
        .map(|_| runtime_dir.join(format!(".generated.dae.{}.backup", candidate.generation)));
    if let (Some(previous), Some(backup)) = (candidate.previous_content.as_ref(), backup.as_ref()) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(backup)
            .map_err(|error| {
                format!(
                    "create runtime apply backup {}: {error}",
                    path_string(backup)
                )
            })?;
        set_private_runtime_file_permissions(backup).map_err(|error| {
            format!(
                "set runtime apply backup permissions {}: {error}",
                path_string(backup)
            )
        })?;
        file.write_all(previous).map_err(|error| {
            format!(
                "write runtime apply backup {}: {error}",
                path_string(backup)
            )
        })?;
        file.sync_all().map_err(|error| {
            format!("sync runtime apply backup {}: {error}", path_string(backup))
        })?;
    }
    let journal = RuntimeApplyJournal {
        format: 1,
        generation: candidate.generation.clone(),
        output: leaf_name(output)?,
        candidate: leaf_name(staged)?,
        backup: backup.as_deref().map(leaf_name).transpose()?,
    };
    let bytes = serde_json::to_vec(&journal)
        .map_err(|error| format!("serialize runtime apply journal: {error}"))?;
    let next = runtime_dir.join(RUNTIME_APPLY_JOURNAL_NEXT);
    let path = runtime_dir.join(RUNTIME_APPLY_JOURNAL);
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&next)
            .map_err(|error| {
                format!(
                    "create runtime apply journal {}: {error}",
                    path_string(&next)
                )
            })?;
        set_private_runtime_file_permissions(&next).map_err(|error| {
            format!(
                "set runtime apply journal permissions {}: {error}",
                path_string(&next)
            )
        })?;
        file.write_all(&bytes).map_err(|error| {
            format!(
                "write runtime apply journal {}: {error}",
                path_string(&next)
            )
        })?;
        file.sync_all().map_err(|error| {
            format!("sync runtime apply journal {}: {error}", path_string(&next))
        })?;
        fs::rename(&next, &path).map_err(|error| {
            format!(
                "activate runtime apply journal {}: {error}",
                path_string(&path)
            )
        })?;
        sync_directory(runtime_dir)
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&next);
        if let Some(backup) = backup.as_ref() {
            let _ = fs::remove_file(backup);
        }
        return Err(error);
    }
    candidate.journal_path = Some(path);
    candidate.backup_path = backup;
    Ok(())
}

pub(super) fn remove_runtime_apply_journal(
    candidate: &mut PreparedRuntimeGeneration,
) -> Result<(), String> {
    let mut errors = Vec::new();
    let parent = candidate.output_path.as_deref().and_then(Path::parent);
    if let Some(path) = candidate.journal_path.take() {
        if let Err(error) = remove_file_if_exists(&path) {
            errors.push(format!("remove {}: {error}", path_string(&path)));
        } else if let Some(parent) = parent
            && let Err(error) = sync_directory(parent)
        {
            errors.push(error);
        }
    }
    if errors.is_empty()
        && let Some(path) = candidate.backup_path.take()
        && let Err(error) = remove_file_if_exists(&path)
    {
        errors.push(format!("remove {}: {error}", path_string(&path)));
    }
    if errors.is_empty()
        && let Some(parent) = parent
        && let Err(error) = sync_directory(parent)
    {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(in crate::daed_product) fn recover_runtime_apply_transaction(
    state: &Path,
    config_dir: &Path,
) -> Result<(), String> {
    let runtime_dir = config_dir.join("runtime");
    let journal_path = runtime_dir.join(RUNTIME_APPLY_JOURNAL);
    let metadata = match fs::metadata(&journal_path) {
        Ok(metadata) => metadata,
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
    if !metadata.is_file() || metadata.len() > RUNTIME_APPLY_JOURNAL_MAX_BYTES {
        return Err("runtime apply journal is not a bounded regular file".to_owned());
    }
    let journal: RuntimeApplyJournal = serde_json::from_slice(
        &fs::read(&journal_path).map_err(|error| format!("read runtime apply journal: {error}"))?,
    )
    .map_err(|error| format!("parse runtime apply journal: {error}"))?;
    validate_journal(&journal)?;
    let output = runtime_dir.join(&journal.output);
    let staged = runtime_dir.join(&journal.candidate);
    let backup = journal.backup.as_ref().map(|leaf| runtime_dir.join(leaf));
    let committed_generation = open_state_connection(state)
        .map_err(|error| format!("open runtime state for apply recovery: {error}"))?
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![RUNTIME_GENERATION_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| format!("read committed runtime generation: {error}"))?;
    if committed_generation.as_deref() != Some(journal.generation.as_str()) {
        match backup.as_ref() {
            Some(backup) => fs::rename(backup, &output)
                .map_err(|error| format!("restore interrupted runtime materialization: {error}"))?,
            None => remove_file_if_exists(&output)
                .map_err(|error| format!("remove interrupted runtime materialization: {error}"))?,
        }
    } else if !output.is_file() {
        return Err("committed runtime generation is missing generated.dae".to_owned());
    }
    remove_file_if_exists(&staged)
        .map_err(|error| format!("remove interrupted runtime candidate: {error}"))?;
    remove_file_if_exists(&journal_path)
        .map_err(|error| format!("remove runtime apply recovery journal: {error}"))?;
    sync_directory(&runtime_dir)?;
    if let Some(backup) = backup.as_ref() {
        remove_file_if_exists(backup)
            .map_err(|error| format!("remove runtime apply recovery backup: {error}"))?;
    }
    remove_file_if_exists(&runtime_dir.join(RUNTIME_APPLY_JOURNAL_NEXT))
        .map_err(|error| format!("remove runtime apply recovery next journal: {error}"))?;
    sync_directory(&runtime_dir)
}

fn validate_journal(journal: &RuntimeApplyJournal) -> Result<(), String> {
    if journal.format != 1 || journal.generation.is_empty() || journal.generation.len() > 128 {
        return Err("invalid runtime apply journal header".to_owned());
    }
    leaf_path(&journal.output)?;
    leaf_path(&journal.candidate)?;
    if journal.output != "generated.dae"
        || journal.candidate != format!(".generated.dae.{}.candidate", journal.generation)
    {
        return Err("runtime apply journal path does not match its generation".to_owned());
    }
    if let Some(backup) = journal.backup.as_deref() {
        leaf_path(backup)?;
        if backup != format!(".generated.dae.{}.backup", journal.generation) {
            return Err("runtime apply journal backup does not match its generation".to_owned());
        }
    }
    Ok(())
}

fn leaf_name(path: &Path) -> Result<String, String> {
    path.file_name()
        .and_then(|leaf| leaf.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "runtime transaction path has no UTF-8 leaf: {}",
                path_string(path)
            )
        })
}

fn leaf_path(leaf: &str) -> Result<(), String> {
    let path = Path::new(leaf);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err("runtime apply journal contains a non-leaf path".to_owned());
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn cleanup_orphan_runtime_transaction_files(runtime_dir: &Path) -> Result<(), String> {
    let entries = match fs::read_dir(runtime_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "inspect runtime transaction directory {}: {error}",
                path_string(runtime_dir)
            ));
        }
    };
    let mut removed = false;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read runtime transaction entry: {error}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == RUNTIME_APPLY_JOURNAL_NEXT
            || (name.starts_with(".generated.dae.")
                && (name.ends_with(".candidate")
                    || name.ends_with(".rollback")
                    || name.ends_with(".backup")))
        {
            remove_file_if_exists(&entry.path()).map_err(|error| {
                format!(
                    "remove orphan runtime transaction file {}: {error}",
                    path_string(&entry.path())
                )
            })?;
            removed = true;
        }
    }
    if removed {
        sync_directory(runtime_dir)?;
    }
    Ok(())
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
