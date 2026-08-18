use super::transaction::PersistedSubscriptionContent;
use super::*;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};

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

pub(super) struct PreparedSubscriptionPersist {
    directory: PathBuf,
    target: PathBuf,
    candidate: Option<PathBuf>,
    backup: Option<PathBuf>,
    journal: Option<PathBuf>,
    generation: String,
    metadata_key: String,
    activated: bool,
    database_committed: bool,
}

impl PreparedSubscriptionPersist {
    pub(super) fn prepare(
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
        fs::create_dir_all(directory)?;
        set_private_permissions(directory, 0o700)?;
        let target_name = leaf_name(&target)?;
        let generation = format!(
            "{}-{}-{}",
            subscription_id,
            std::process::id(),
            fastrand::u64(..)
        );
        let candidate = reserve_artifact(directory, &target_name, &generation, "candidate")?;
        let write_result = content.copy_to(&candidate).and_then(|()| {
            set_private_permissions(&candidate, 0o600)?;
            File::open(&candidate)?.sync_all()
        });
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
        let journal_path = directory.join(JOURNAL_FILE);
        let journal = SubscriptionPersistJournal {
            format: 1,
            generation: generation.clone(),
            metadata_key: metadata_key.clone(),
            target: target_name,
            candidate: leaf_name(&candidate)?,
            backup: backup.as_deref().map(leaf_name).transpose()?,
        };
        if let Err(error) = write_journal(directory, &journal) {
            let _ = remove_file_if_exists(&candidate);
            if let Some(backup) = backup.as_ref() {
                let _ = remove_file_if_exists(backup);
            }
            return Err(error);
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            target,
            candidate: Some(candidate),
            backup,
            journal: Some(journal_path),
            generation,
            metadata_key,
            activated: false,
            database_committed: false,
        })
    }

    pub(super) fn activate(&mut self) -> io::Result<()> {
        let candidate = self
            .candidate
            .as_ref()
            .ok_or_else(|| io::Error::other("persisted subscription candidate is unavailable"))?;
        fs::rename(candidate, &self.target)?;
        self.candidate = None;
        self.activated = true;
        sync_directory(&self.directory)?;
        Ok(())
    }

    pub(super) fn record_generation(&self, tx: &Connection) -> io::Result<()> {
        tx.execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
            params![self.metadata_key, self.generation],
        )
        .map_err(sqlite_io_error)?;
        Ok(())
    }

    pub(super) fn finish(mut self) -> io::Result<()> {
        self.database_committed = true;
        self.remove_intent_then_backup()
    }

    pub(super) fn rollback(mut self) -> io::Result<()> {
        let mut errors = Vec::new();
        if self.activated {
            match self.backup.as_ref() {
                Some(backup) => {
                    if let Err(error) = fs::rename(backup, &self.target) {
                        errors.push(format!("restore persisted subscription backup: {error}"));
                    } else {
                        self.backup = None;
                    }
                }
                None => {
                    if let Err(error) = remove_file_if_exists(&self.target) {
                        errors.push(format!("remove new persisted subscription: {error}"));
                    }
                }
            }
            if let Err(error) = sync_directory(&self.directory) {
                errors.push(error.to_string());
            }
        }
        if let Some(candidate) = self.candidate.take()
            && let Err(error) = remove_file_if_exists(&candidate)
        {
            errors.push(format!("remove persisted subscription candidate: {error}"));
        }
        if errors.is_empty() {
            self.remove_intent_then_backup()?;
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    fn remove_intent_then_backup(&mut self) -> io::Result<()> {
        if let Some(journal) = self.journal.take() {
            remove_file_if_exists(&journal)?;
            sync_directory(&self.directory)?;
        }
        if let Some(backup) = self.backup.take() {
            remove_file_if_exists(&backup)?;
        }
        if let Some(candidate) = self.candidate.take() {
            remove_file_if_exists(&candidate)?;
        }
        sync_directory(&self.directory)
    }
}

impl Drop for PreparedSubscriptionPersist {
    fn drop(&mut self) {
        if self.journal.is_some() && !self.database_committed && self.activated {
            match self.backup.as_ref() {
                Some(backup) => {
                    if fs::rename(backup, &self.target).is_ok() {
                        self.backup = None;
                    }
                }
                None => {
                    let _ = remove_file_if_exists(&self.target);
                }
            }
            let _ = sync_directory(&self.directory);
        }
        if let Some(candidate) = self.candidate.take() {
            let _ = remove_file_if_exists(&candidate);
        }
        if self.journal.is_some()
            && !self.database_committed
            && let Some(journal) = self.journal.take()
        {
            let _ = remove_file_if_exists(&journal);
            let _ = sync_directory(&self.directory);
        }
        if self.journal.is_none()
            && let Some(backup) = self.backup.take()
        {
            let _ = remove_file_if_exists(&backup);
        }
    }
}

pub(in crate::daed_product) fn recover_subscription_persist_transaction(
    state: &Path,
    config_dir: &Path,
) -> io::Result<()> {
    let directory = config_dir.join("persist.d");
    let journal_path = directory.join(JOURNAL_FILE);
    let metadata = match fs::symlink_metadata(&journal_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return cleanup_orphan_artifacts(&directory);
        }
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.len() > JOURNAL_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription persist journal is not a bounded regular file",
        ));
    }
    let journal: SubscriptionPersistJournal = serde_json::from_slice(&fs::read(&journal_path)?)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse subscription persist journal: {error}"),
            )
        })?;
    validate_journal(&journal)?;
    let target = directory.join(&journal.target);
    let candidate = directory.join(&journal.candidate);
    let backup = journal.backup.as_ref().map(|name| directory.join(name));
    let committed = open_state_connection(state)?
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![journal.metadata_key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
        .as_deref()
        == Some(journal.generation.as_str());
    if committed {
        if !target.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "committed persisted subscription file is missing",
            ));
        }
    } else {
        match backup.as_ref() {
            Some(backup) => fs::rename(backup, &target)?,
            None => remove_file_if_exists(&target)?,
        }
        sync_directory(&directory)?;
    }
    remove_file_if_exists(&candidate)?;
    remove_file_if_exists(&journal_path)?;
    sync_directory(&directory)?;
    if let Some(backup) = backup.as_ref() {
        remove_file_if_exists(backup)?;
    }
    remove_file_if_exists(&directory.join(JOURNAL_NEXT_FILE))?;
    sync_directory(&directory)
}

impl PersistedSubscriptionContent<'_> {
    fn path(&self) -> &Path {
        match self {
            #[cfg(test)]
            Self::Bytes { path, .. } => path,
            #[cfg(not(test))]
            Self::StagedFile { path, .. } => path,
        }
    }

    fn copy_to(&self, destination: &Path) -> io::Result<()> {
        match self {
            #[cfg(test)]
            Self::Bytes { bytes, .. } => {
                if bytes.len() > subscription_http_body_limit() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "persisted subscription content exceeds size limit",
                    ));
                }
                let mut output = OpenOptions::new().write(true).open(destination)?;
                output.write_all(bytes)?;
                output.sync_all()
            }
            #[cfg(not(test))]
            Self::StagedFile { staging, .. } => {
                let source = File::open(staging)?;
                let metadata = source.metadata()?;
                if !metadata.is_file() || metadata.len() > subscription_http_body_limit() as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "persisted subscription staging file is invalid or too large",
                    ));
                }
                let mut output = OpenOptions::new().write(true).open(destination)?;
                io::copy(&mut io::BufReader::new(source), &mut output)?;
                output.sync_all()
            }
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
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => {
                set_private_permissions(&path, 0o600)?;
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
    let mut source = File::open(source)?;
    let metadata = source.metadata()?;
    if !metadata.is_file() || metadata.len() > subscription_http_body_limit() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "existing persisted subscription file is invalid or too large",
        ));
    }
    let mut destination = OpenOptions::new().write(true).open(destination)?;
    io::copy(&mut source, &mut destination)?;
    destination.sync_all()
}

fn write_journal(directory: &Path, journal: &SubscriptionPersistJournal) -> io::Result<()> {
    validate_journal(journal)?;
    let bytes = serde_json::to_vec(journal).map_err(io::Error::other)?;
    if bytes.len() as u64 > JOURNAL_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription persist journal exceeds size limit",
        ));
    }
    let next = directory.join(JOURNAL_NEXT_FILE);
    let path = directory.join(JOURNAL_FILE);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&next)?;
    set_private_permissions(&next, 0o600)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&next, &path)?;
    sync_directory(directory)
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
        validate_leaf(name)?;
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

fn validate_leaf(name: &str) -> io::Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "subscription persist journal contains a non-leaf path",
        ));
    }
    Ok(())
}

fn leaf_name(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 subscription path"))
}

fn cleanup_orphan_artifacts(directory: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut removed = false;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == JOURNAL_NEXT_FILE
            || (name.starts_with('.')
                && (name.ends_with(".candidate") || name.ends_with(".backup")))
        {
            remove_file_if_exists(&entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_directory(directory)?;
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

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daed_product::tests::support::FreshProductState;

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
