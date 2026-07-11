use super::*;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProductLogWriterFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    created: Option<SystemTime>,
}

impl ProductLogWriterFileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(not(unix))]
            created: metadata.created().ok(),
        }
    }
}

pub(super) enum ProductLogAppendOutcome {
    Filtered,
    Appended { pruned: bool },
}

pub(super) struct ProductLogWriter {
    config_dir: PathBuf,
    path: PathBuf,
    policy: ProductLogPolicy,
    file: Option<fs::File>,
    identity: Option<ProductLogWriterFileIdentity>,
    size_bytes: u64,
    entry_count: usize,
    last_id: u64,
}

impl ProductLogWriter {
    pub(super) fn open(config_dir: PathBuf, policy: ProductLogPolicy) -> io::Result<Self> {
        let path = product_log_file(&config_dir);
        let mut writer = Self {
            config_dir,
            path,
            policy,
            file: None,
            identity: None,
            size_bytes: 0,
            entry_count: 0,
            last_id: 0,
        };
        let _guard = product_log_file_lock()?;
        writer.reopen_locked()?;
        Ok(writer)
    }

    pub(super) fn append(
        &mut self,
        request: ProductLogAppendRequest,
    ) -> io::Result<ProductLogAppendOutcome> {
        if request.respect_runtime_log_level
            && !log_level_enabled(&request.level, &self.policy.runtime_level)
        {
            return Ok(ProductLogAppendOutcome::Filtered);
        }
        let _guard = product_log_file_lock()?;
        self.ensure_current_file_locked()?;
        let id = self.last_id.saturating_add(1);
        let line = encode_log_entry_line(id, &request.level, &request.message, request.fields)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("product log file is unavailable"))?;
        file.write_all(&line)?;
        self.last_id = id;
        self.size_bytes = self.size_bytes.saturating_add(line.len() as u64);
        self.entry_count = self.entry_count.saturating_add(1);
        set_log_id_cache(&self.path, id)?;
        let pruned = self.prune_if_over_limit_locked()?;
        Ok(ProductLogAppendOutcome::Appended { pruned })
    }

    pub(super) fn clear(&mut self) -> io::Result<()> {
        self.file.take();
        clear_log_file_direct(&self.config_dir)?;
        let _guard = product_log_file_lock()?;
        self.reopen_locked()
    }

    pub(super) fn clear_preserving_lifecycle(&mut self) -> io::Result<bool> {
        self.file.take();
        clear_log_file_preserving_startup_reload_logs_direct(&self.config_dir)?;
        let _guard = product_log_file_lock()?;
        self.reopen_locked()?;
        self.prune_if_over_limit_locked()
    }

    pub(super) fn replace_policy(&mut self, policy: ProductLogPolicy) -> io::Result<bool> {
        self.policy = policy;
        let _guard = product_log_file_lock()?;
        self.ensure_current_file_locked()?;
        self.prune_if_over_limit_locked()
    }

    pub(super) fn apply_limits(&mut self, max_entries: i64, max_bytes: i64) -> io::Result<bool> {
        self.policy.max_entries = normalize_log_max_entries(max_entries);
        self.policy.max_bytes = normalize_log_max_bytes(max_bytes);
        let _guard = product_log_file_lock()?;
        self.ensure_current_file_locked()?;
        self.prune_if_over_limit_locked()
    }

    fn ensure_current_file_locked(&mut self) -> io::Result<()> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return self.reopen_locked();
            }
            Err(error) => return Err(error),
        };
        let current_identity = ProductLogWriterFileIdentity::from_metadata(&metadata);
        if self.file.is_none()
            || self.identity != Some(current_identity)
            || self.size_bytes != metadata.len()
        {
            return self.reopen_locked();
        }
        repair_log_file_mode_if_needed(&self.path, &metadata)
    }

    fn reopen_locked(&mut self) -> io::Result<()> {
        self.file.take();
        ensure_log_dir_mode_if_needed(&self.config_dir)?;
        #[cfg(test)]
        observe_log_append_open(&self.path);
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        let metadata = file.metadata()?;
        repair_log_file_mode_if_needed(&self.path, &metadata)?;
        let metadata = file.metadata()?;
        let entry_count = count_entries_from_file(&file)?;
        let last_id = read_last_log_id(&self.path)?;
        self.identity = Some(ProductLogWriterFileIdentity::from_metadata(&metadata));
        self.size_bytes = metadata.len();
        self.entry_count = entry_count;
        self.last_id = last_id;
        set_log_id_cache(&self.path, last_id)?;
        self.file = Some(file);
        Ok(())
    }

    fn prune_if_over_limit_locked(&mut self) -> io::Result<bool> {
        let max_entries = normalize_log_max_entries(self.policy.max_entries) as usize;
        let max_bytes = normalize_log_max_bytes(self.policy.max_bytes) as u64;
        if self.entry_count <= max_entries && self.size_bytes <= max_bytes {
            return Ok(false);
        }
        self.file.take();
        prune_log_file_with_settings(&self.path, max_entries as i64, max_bytes as i64)?;
        self.reopen_locked()?;
        Ok(true)
    }
}

fn product_log_file_lock() -> io::Result<std::sync::MutexGuard<'static, ()>> {
    LOG_FILE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))
}

fn count_entries_from_file(file: &fs::File) -> io::Result<usize> {
    let mut reader = io::BufReader::new(file.try_clone()?);
    reader.seek(SeekFrom::Start(0))?;
    let mut count = 0_usize;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        if !line.trim().is_empty() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn ensure_log_dir_mode_if_needed(config_dir: &Path) -> io::Result<()> {
    let path = product_log_dir(config_dir);
    fs::create_dir_all(&path)?;
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&path)?;
        if metadata.permissions().mode() & 0o777 != 0o750 {
            #[cfg(test)]
            observe_log_dir_permission_write(&path);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o750))?;
        }
    }
    Ok(())
}

fn repair_log_file_mode_if_needed(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return set_log_file_permissions(path);
    }
    Ok(())
}
