use serde::Serialize;
use serde::de::DeserializeOwned;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

mod startup_recovery;

pub(in crate::daed_product) use startup_recovery::recover_product_durable_state;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(in crate::daed_product) struct ValidatedLeafName(String);

impl ValidatedLeafName {
    pub(in crate::daed_product) fn new(name: impl Into<String>) -> io::Result<Self> {
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

    pub(in crate::daed_product) fn from_path(path: &Path) -> io::Result<Self> {
        let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable artifact path has no UTF-8 leaf name",
            )
        })?;
        Self::new(name)
    }

    pub(in crate::daed_product) fn as_str(&self) -> &str {
        &self.0
    }

    pub(in crate::daed_product) fn path_in(&self, directory: &Path) -> PathBuf {
        directory.join(&self.0)
    }
}

impl fmt::Display for ValidatedLeafName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug)]
pub(in crate::daed_product) struct DurableArtifactSet {
    directory: PathBuf,
    target: ValidatedLeafName,
    candidate: ValidatedLeafName,
    backup: Option<ValidatedLeafName>,
    journal: ValidatedLeafName,
    journal_next: ValidatedLeafName,
}

impl DurableArtifactSet {
    pub(in crate::daed_product) fn new(
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

    pub(in crate::daed_product) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(in crate::daed_product) fn target_path(&self) -> PathBuf {
        self.target.path_in(&self.directory)
    }

    pub(in crate::daed_product) fn candidate_path(&self) -> PathBuf {
        self.candidate.path_in(&self.directory)
    }

    pub(in crate::daed_product) fn backup_path(&self) -> Option<PathBuf> {
        self.backup
            .as_ref()
            .map(|backup| backup.path_in(&self.directory))
    }

    pub(in crate::daed_product) fn journal_path(&self) -> PathBuf {
        self.journal.path_in(&self.directory)
    }

    pub(in crate::daed_product) fn journal_next_path(&self) -> PathBuf {
        self.journal_next.path_in(&self.directory)
    }
}

pub(in crate::daed_product) trait FaultCheckpoints<Point: Copy> {
    fn checkpoint(&mut self, point: Point) -> io::Result<()>;
}

pub(in crate::daed_product) struct NoopFaultCheckpoints;

impl<Point: Copy> FaultCheckpoints<Point> for NoopFaultCheckpoints {
    fn checkpoint(&mut self, _point: Point) -> io::Result<()> {
        Ok(())
    }
}

pub(in crate::daed_product) fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_private_permissions(path, 0o700)
}

pub(in crate::daed_product) fn reserve_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

pub(in crate::daed_product) fn create_synced_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = reserve_private_file(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

pub(in crate::daed_product) fn write_reserved_file_synced(
    path: &Path,
    contents: &[u8],
) -> io::Result<()> {
    let mut file = open_existing_for_write(path, true)?;
    file.write_all(contents)?;
    file.sync_all()
}

pub(in crate::daed_product) fn copy_regular_file_synced(
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    let mut source = open_regular_file(source)?;
    let mut destination = open_existing_for_write(destination, true)?;
    io::copy(&mut source, &mut destination)?;
    destination.sync_all()
}

pub(in crate::daed_product) fn copy_bounded_regular_file_synced(
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

pub(in crate::daed_product) fn read_bounded_regular_file(
    path: &Path,
    max_bytes: u64,
) -> io::Result<Vec<u8>> {
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

pub(in crate::daed_product) fn read_json_journal<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> io::Result<T> {
    let bytes = read_bounded_regular_file(path, max_bytes)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse durable journal: {error}"),
        )
    })
}

pub(in crate::daed_product) fn write_json_journal<T: Serialize>(
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

pub(in crate::daed_product) fn atomic_replace_synced(
    directory: &Path,
    source: &ValidatedLeafName,
    destination: &ValidatedLeafName,
) -> io::Result<()> {
    fs::rename(source.path_in(directory), destination.path_in(directory))?;
    sync_directory(directory)
}

pub(in crate::daed_product) fn remove_leaf_if_exists_synced(
    directory: &Path,
    leaf: &ValidatedLeafName,
) -> io::Result<()> {
    remove_file_if_exists(&leaf.path_in(directory))?;
    sync_directory(directory)
}

pub(in crate::daed_product) fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(in crate::daed_product) fn cleanup_matching_artifacts(
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

pub(in crate::daed_product) fn sync_directory(path: &Path) -> io::Result<()> {
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
}
