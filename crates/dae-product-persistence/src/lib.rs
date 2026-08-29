use serde::Serialize;
use serde::de::DeserializeOwned;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ProductUserRecord {
    id: i64,
    username: String,
    password_hash: String,
    jwt_secret: String,
    json_storage: String,
    avatar: Option<String>,
    name: Option<String>,
}

impl ProductUserRecord {
    pub fn new(
        id: i64,
        username: String,
        password_hash: String,
        jwt_secret: String,
        json_storage: String,
        avatar: Option<String>,
        name: Option<String>,
    ) -> Self {
        Self {
            id,
            username,
            password_hash,
            jwt_secret,
            json_storage,
            avatar,
            name,
        }
    }

    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }

    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn json_storage(&self) -> &str {
        &self.json_storage
    }

    pub fn json_storage_mut(&mut self) -> &mut String {
        &mut self.json_storage
    }

    pub fn avatar(&self) -> Option<&str> {
        self.avatar.as_deref()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn set_username(&mut self, username: String) {
        self.username = username;
    }

    pub fn set_password_hash(&mut self, password_hash: String) {
        self.password_hash = password_hash;
    }

    pub fn set_jwt_secret(&mut self, jwt_secret: String) {
        self.jwt_secret = jwt_secret;
    }

    pub fn set_avatar(&mut self, avatar: Option<String>) {
        self.avatar = avatar;
    }

    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }
}

mod desired_state;
pub use desired_state::*;

mod json_storage;
pub use json_storage::*;

mod state;
pub use state::*;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ValidatedLeafName(String);

impl ValidatedLeafName {
    pub fn new(name: impl Into<String>) -> io::Result<Self> {
        let name = name.into();
        let mut components = Path::new(&name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable artifact name must be one relative path component",
            ));
        }
        Ok(Self(name))
    }

    pub fn from_path(path: &Path) -> io::Result<Self> {
        let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable artifact path has no UTF-8 leaf name",
            )
        })?;
        Self::new(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn path_in(&self, directory: &Path) -> PathBuf {
        directory.join(&self.0)
    }
}

impl fmt::Display for ValidatedLeafName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct DurableArtifactSet {
    directory: PathBuf,
    target: ValidatedLeafName,
    candidate: ValidatedLeafName,
    backup: Option<ValidatedLeafName>,
    journal: ValidatedLeafName,
    journal_next: ValidatedLeafName,
}

impl DurableArtifactSet {
    pub fn new(
        directory: impl Into<PathBuf>,
        target: ValidatedLeafName,
        candidate: ValidatedLeafName,
        backup: Option<ValidatedLeafName>,
        journal: ValidatedLeafName,
        journal_next: ValidatedLeafName,
    ) -> io::Result<Self> {
        let set = Self {
            directory: directory.into(),
            target,
            candidate,
            backup,
            journal,
            journal_next,
        };
        let mut names = vec![
            set.target.as_str(),
            set.candidate.as_str(),
            set.journal.as_str(),
            set.journal_next.as_str(),
        ];
        if let Some(backup) = set.backup.as_ref() {
            names.push(backup.as_str());
        }
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable artifact paths must be distinct",
            ));
        }
        Ok(set)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn target_path(&self) -> PathBuf {
        self.target.path_in(&self.directory)
    }

    pub fn candidate_path(&self) -> PathBuf {
        self.candidate.path_in(&self.directory)
    }

    pub fn backup_path(&self) -> Option<PathBuf> {
        self.backup
            .as_ref()
            .map(|backup| backup.path_in(&self.directory))
    }

    pub fn journal_path(&self) -> PathBuf {
        self.journal.path_in(&self.directory)
    }

    pub fn journal_next_path(&self) -> PathBuf {
        self.journal_next.path_in(&self.directory)
    }
}

#[derive(Debug)]
pub struct DurableTransaction {
    artifacts: DurableArtifactSet,
    activated: bool,
    database_committed: bool,
    finished: bool,
    rollback_failed: bool,
}

impl DurableTransaction {
    pub fn new(artifacts: DurableArtifactSet) -> Self {
        Self {
            artifacts,
            activated: false,
            database_committed: false,
            finished: false,
            rollback_failed: false,
        }
    }

    pub fn artifacts(&self) -> &DurableArtifactSet {
        &self.artifacts
    }

    pub fn write_intent<T: Serialize>(&self, max_bytes: u64, value: &T) -> io::Result<()> {
        write_json_journal(
            self.artifacts.directory(),
            &self.artifacts.journal,
            &self.artifacts.journal_next,
            max_bytes,
            value,
        )
    }

    pub fn activate(&mut self) -> io::Result<()> {
        fs::rename(
            self.artifacts.candidate.path_in(self.artifacts.directory()),
            self.artifacts.target.path_in(self.artifacts.directory()),
        )?;
        self.activated = true;
        sync_directory(self.artifacts.directory())?;
        Ok(())
    }

    pub fn commit_database<R, E>(&mut self, commit: impl FnOnce() -> Result<R, E>) -> Result<R, E> {
        let result = commit()?;
        self.database_committed = true;
        Ok(result)
    }

    pub fn needs_rollback(&self) -> bool {
        !self.finished && !self.database_committed
    }

    pub fn preserve_for_recovery(&mut self) {
        self.rollback_failed = true;
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.database_committed = true;
        self.finish_in_place()
    }

    pub fn finish_in_place(&mut self) -> io::Result<()> {
        self.database_committed = true;
        let result = cleanup_transaction_artifacts(&self.artifacts, true);
        self.finished = result.is_ok();
        result
    }

    pub fn rollback(&mut self) -> io::Result<()> {
        let mut errors = Vec::new();
        let mut restored = true;
        if self.activated {
            if let Err(error) = restore_transaction_target(&self.artifacts) {
                errors.push(error.to_string());
                restored = false;
            } else {
                self.activated = false;
            }
        }
        if let Err(error) = cleanup_transaction_artifacts(&self.artifacts, restored) {
            errors.push(error.to_string());
        }
        self.finished = errors.is_empty();
        self.rollback_failed = !errors.is_empty();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    pub fn reconcile(artifacts: DurableArtifactSet, database_committed: bool) -> io::Result<()> {
        if database_committed {
            if !artifacts.target_path().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "committed durable target is missing",
                ));
            }
        } else {
            restore_transaction_target(&artifacts)?;
        }
        cleanup_transaction_artifacts(&artifacts, true)
    }

    pub fn recover(artifacts: DurableArtifactSet, database_committed: bool) -> io::Result<()> {
        Self::reconcile(artifacts, database_committed)
    }
}

impl Drop for DurableTransaction {
    fn drop(&mut self) {
        if self.finished || self.database_committed || self.rollback_failed {
            return;
        }
        if self.activated {
            let restored = restore_transaction_target(&self.artifacts).is_ok();
            let _ = cleanup_transaction_artifacts(&self.artifacts, restored);
        } else {
            let _ = cleanup_transaction_artifacts(&self.artifacts, true);
        }
    }
}

fn restore_transaction_target(artifacts: &DurableArtifactSet) -> io::Result<()> {
    match artifacts.backup_path() {
        Some(backup) => fs::rename(backup, artifacts.target_path())?,
        None => remove_file_if_exists(&artifacts.target_path())?,
    }
    sync_directory(artifacts.directory())
}

fn cleanup_transaction_artifacts(
    artifacts: &DurableArtifactSet,
    remove_backup: bool,
) -> io::Result<()> {
    let mut errors = Vec::new();
    for path in [
        artifacts.journal_path(),
        artifacts.journal_next_path(),
        artifacts.candidate_path(),
    ] {
        if let Err(error) = remove_file_if_exists(&path) {
            errors.push(error.to_string());
        }
    }
    if remove_backup
        && let Some(backup) = artifacts.backup_path()
        && let Err(error) = remove_file_if_exists(&backup)
    {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        sync_directory(artifacts.directory())
    } else {
        Err(io::Error::other(errors.join("; ")))
    }
}

pub trait FaultCheckpoints<Point: Copy> {
    fn checkpoint(&mut self, point: Point) -> io::Result<()>;
}

pub struct NoopFaultCheckpoints;

impl<Point: Copy> FaultCheckpoints<Point> for NoopFaultCheckpoints {
    fn checkpoint(&mut self, _point: Point) -> io::Result<()> {
        Ok(())
    }
}

pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_private_permissions(path, 0o700)
}

pub fn reserve_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

pub fn create_synced_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = reserve_private_file(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

pub fn write_reserved_file_synced(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = open_existing_for_write(path, true)?;
    file.write_all(contents)?;
    file.sync_all()
}

pub fn copy_regular_file_synced(source: &Path, destination: &Path) -> io::Result<()> {
    let mut source = open_regular_file(source)?;
    let mut destination = open_existing_for_write(destination, true)?;
    io::copy(&mut source, &mut destination)?;
    destination.sync_all()
}

pub fn copy_bounded_regular_file_synced(
    source: &Path,
    destination: &Path,
    max_bytes: u64,
) -> io::Result<()> {
    let mut source = open_regular_file(source)?;
    if source.metadata()?.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable artifact exceeds size limit",
        ));
    }
    let mut destination = open_existing_for_write(destination, true)?;
    let copied = io::copy(
        &mut Read::by_ref(&mut source).take(max_bytes.saturating_add(1)),
        &mut destination,
    )?;
    if copied > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable artifact exceeds size limit",
        ));
    }
    destination.sync_all()
}

pub fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let file = open_regular_file(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable artifact exceeds size limit",
        ));
    }
    let mut bytes =
        Vec::with_capacity(metadata.len().min(max_bytes).min(usize::MAX as u64) as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable artifact exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub fn read_json_journal<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> io::Result<T> {
    let bytes = read_bounded_regular_file(path, max_bytes)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse durable journal: {error}"),
        )
    })
}

pub fn write_json_journal<T: Serialize>(
    directory: &Path,
    journal: &ValidatedLeafName,
    journal_next: &ValidatedLeafName,
    max_bytes: u64,
    value: &T,
) -> io::Result<()> {
    if journal == journal_next {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable journal and next journal paths must differ",
        ));
    }
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable journal exceeds size limit",
        ));
    }
    let next_path = journal_next.path_in(directory);
    let journal_path = journal.path_in(directory);
    let result = (|| {
        create_synced_file(&next_path, &bytes)?;
        fs::rename(&next_path, &journal_path)?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = remove_file_if_exists(&next_path);
    }
    result
}

pub fn remove_leaf_if_exists_synced(directory: &Path, leaf: &ValidatedLeafName) -> io::Result<()> {
    remove_file_if_exists(&leaf.path_in(directory))?;
    sync_directory(directory)
}

pub fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn cleanup_matching_artifacts(
    directory: &Path,
    mut matches: impl FnMut(&str) -> bool,
) -> io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut removed = false;
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !matches(&name) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("durable artifact is unexpectedly a directory: {name}"),
            ));
        }
        remove_file_if_exists(&entry.path())?;
        removed = true;
    }
    if removed {
        sync_directory(directory)?;
    }
    Ok(())
}

pub fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn open_regular_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable artifact is not a regular file",
        ));
    }
    Ok(file)
}

fn open_existing_for_write(path: &Path, truncate: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable artifact is not a regular file",
        ));
    }
    Ok(file)
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

    fn temp_dir(scope: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "daenext-durable-commit-{scope}-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn leaf_name_rejects_paths_and_parent_components() {
        for invalid in ["", ".", "..", "a/b", "/tmp/a"] {
            assert!(ValidatedLeafName::new(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            ValidatedLeafName::new("artifact.next").unwrap().as_str(),
            "artifact.next"
        );
    }

    #[test]
    fn bounded_read_rejects_oversized_and_non_regular_inputs() {
        let directory = temp_dir("bounded-read");
        let file = directory.join("file");
        fs::write(&file, b"12345").unwrap();
        assert_eq!(read_bounded_regular_file(&file, 5).unwrap(), b"12345");
        assert_eq!(
            read_bounded_regular_file(&file, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_bounded_regular_file(&directory, 5).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = temp_dir("symlink");
        let file = directory.join("file");
        let link = directory.join("link");
        fs::write(&file, b"value").unwrap();
        symlink(&file, &link).unwrap();
        assert!(read_bounded_regular_file(&link, 32).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn journal_replace_and_cleanup_are_idempotent() {
        let directory = temp_dir("journal");
        let journal = ValidatedLeafName::new("journal.json").unwrap();
        let next = ValidatedLeafName::new("journal.next").unwrap();
        write_json_journal(&directory, &journal, &next, 1024, &vec!["first"]).unwrap();
        write_json_journal(&directory, &journal, &next, 1024, &vec!["second"]).unwrap();
        let value: Vec<String> = read_json_journal(&journal.path_in(&directory), 1024).unwrap();
        assert_eq!(value, ["second"]);
        remove_leaf_if_exists_synced(&directory, &journal).unwrap();
        remove_leaf_if_exists_synced(&directory, &journal).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    fn transaction_artifacts(directory: &Path) -> DurableArtifactSet {
        DurableArtifactSet::new(
            directory,
            ValidatedLeafName::new("target").unwrap(),
            ValidatedLeafName::new("candidate").unwrap(),
            Some(ValidatedLeafName::new("backup").unwrap()),
            ValidatedLeafName::new("journal").unwrap(),
            ValidatedLeafName::new("journal.next").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn dropping_activated_transaction_restores_backup() {
        let directory = temp_dir("drop-rollback");
        fs::write(directory.join("target"), b"old").unwrap();
        fs::rename(directory.join("target"), directory.join("backup")).unwrap();
        fs::write(directory.join("candidate"), b"new").unwrap();
        {
            let mut transaction = DurableTransaction::new(transaction_artifacts(&directory));
            transaction.activate().unwrap();
            assert_eq!(fs::read(directory.join("target")).unwrap(), b"new");
        }
        assert_eq!(fs::read(directory.join("target")).unwrap(), b"old");
        assert!(!directory.join("backup").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_rollback_preserves_backup_for_recovery() {
        let directory = temp_dir("rollback-backup");
        fs::write(directory.join("backup"), b"old").unwrap();
        fs::write(directory.join("candidate"), b"new").unwrap();
        let mut transaction = DurableTransaction::new(transaction_artifacts(&directory));
        transaction.activate().unwrap();
        fs::remove_file(directory.join("target")).unwrap();
        fs::create_dir(directory.join("target")).unwrap();
        assert!(transaction.rollback().is_err());
        assert_eq!(fs::read(directory.join("backup")).unwrap(), b"old");
        fs::remove_dir_all(directory).unwrap();
    }
}
