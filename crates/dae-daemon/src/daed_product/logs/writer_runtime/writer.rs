use super::*;
use std::collections::VecDeque;

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

const PRODUCT_LOG_SEGMENT_MAX_BYTES: u64 = 128 * 1024;
const PRODUCT_LOG_SEGMENT_MAX_ENTRIES: usize = 512;
const PRODUCT_LOG_VISIBILITY_BUDGET_BYTES: u64 = 2 * PRODUCT_LOG_VISIBILITY_JOURNAL_MAX_BYTES;

#[cfg(test)]
thread_local! {
    pub(super) static LOG_APPEND_PARTIAL_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static LOG_VISIBILITY_PARTIAL_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn write_product_log_line(file: &mut fs::File, line: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if LOG_APPEND_PARTIAL_FAILURE.with(|fail| fail.replace(false)) {
        file.write_all(&line[..line.len() / 2])?;
        return Err(io::Error::from_raw_os_error(libc::ENOSPC));
    }
    file.write_all(line)
}

fn write_log_visibility_record(file: &mut fs::File, record: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if LOG_VISIBILITY_PARTIAL_FAILURE.with(|fail| fail.replace(false)) {
        file.write_all(&record[..record.len() / 2])?;
        return Err(io::Error::from_raw_os_error(libc::ENOSPC));
    }
    file.write_all(record)
}

struct ProductLogWriterSegment {
    // Filename bounds stay fixed after trimming or compacting a sealed segment.
    // Keeping only these IDs avoids retaining the log directory for every file.
    sealed_ids: Option<(u64, u64)>,
    size_bytes: u64,
    visible_bytes: u64,
    visible_entries: usize,
    head_offset: u64,
    first_id: u64,
    last_id: u64,
}

impl ProductLogWriterSegment {
    fn path<'a>(&self, active_path: &'a Path) -> std::borrow::Cow<'a, Path> {
        match self.sealed_ids {
            Some((first, last)) => std::borrow::Cow::Owned(
                active_path.with_file_name(format!("segment-{first:020}-{last:020}.jsonl")),
            ),
            None => std::borrow::Cow::Borrowed(active_path),
        }
    }

    fn scan(path: &Path, sealed_ids: Option<(u64, u64)>) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        let size_bytes = file.metadata()?.len();
        let mut reader = io::BufReader::new(file);
        let mut visible_entries = 0_usize;
        let mut first_id = None;
        let mut last_id = 0;
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line)? != 0 {
            if let Ok(text) = std::str::from_utf8(&line)
                && let Some(entry) = parse_log_entry_line(text)
            {
                visible_entries = visible_entries.saturating_add(1);
                first_id.get_or_insert(entry.id);
                last_id = entry.id;
            }
            line.clear();
        }
        Ok(Self {
            sealed_ids,
            size_bytes,
            visible_bytes: size_bytes,
            visible_entries,
            head_offset: 0,
            first_id: first_id.unwrap_or(0),
            last_id,
        })
    }
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
    first_visible_id: u64,
    visible_bytes: u64,
    persisted_visible_first_id: u64,
    visibility_journal_bytes: u64,
    segments: VecDeque<ProductLogWriterSegment>,
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
            first_visible_id: 1,
            visible_bytes: 0,
            persisted_visible_first_id: 0,
            visibility_journal_bytes: 0,
            segments: VecDeque::new(),
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
        if self.size_bytes >= PRODUCT_LOG_SEGMENT_MAX_BYTES
            || self
                .segments
                .back()
                .is_some_and(|segment| segment.visible_entries >= PRODUCT_LOG_SEGMENT_MAX_ENTRIES)
        {
            self.rotate_active_locked()?;
        }
        let id = self.last_id.saturating_add(1);
        let line = encode_log_entry_line(id, &request.level, &request.message, request.fields)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("product log file is unavailable"))?;
        if let Err(error) = write_product_log_line(file, &line) {
            // A short write belongs to this writer, not an external replacement.
            // Remove the partial record if possible and reopen without discarding
            // sealed history. Reopen also tolerates an incomplete tail when the
            // filesystem refuses the truncation.
            let _ = file.set_len(self.size_bytes);
            self.file.take();
            return Err(error);
        }
        let was_empty = self.entry_count == 0;
        self.last_id = id;
        self.size_bytes = self.size_bytes.saturating_add(line.len() as u64);
        self.entry_count = self.entry_count.saturating_add(1);
        self.visible_bytes = self.visible_bytes.saturating_add(line.len() as u64);
        if let Some(active) = self.segments.back_mut() {
            if active.visible_entries == 0 {
                active.first_id = id;
                if was_empty {
                    self.first_visible_id = id;
                }
            }
            active.visible_entries = active.visible_entries.saturating_add(1);
            active.size_bytes = self.size_bytes;
            active.visible_bytes = active.visible_bytes.saturating_add(line.len() as u64);
            active.last_id = id;
        }
        set_log_id_cache(&self.path, id)?;
        let pruned = self.prune_if_over_limit_locked()?;
        set_log_visible_first_id(&self.path, self.first_visible_id)?;
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
                if self.file.is_some() {
                    remove_product_log_segments(&self.config_dir)?;
                    remove_product_log_visibility_file(&self.config_dir)?;
                }
                return self.reopen_locked();
            }
            Err(error) => return Err(error),
        };
        let current_identity = ProductLogWriterFileIdentity::from_metadata(&metadata);
        if self.file.is_none()
            || self.identity != Some(current_identity)
            || self.size_bytes != metadata.len()
        {
            if self.file.is_some() {
                remove_product_log_segments(&self.config_dir)?;
                remove_product_log_visibility_file(&self.config_dir)?;
            }
            return self.reopen_locked();
        }
        repair_log_file_mode_if_needed(&self.path, &metadata)
    }

    fn reopen_locked(&mut self) -> io::Result<()> {
        self.file.take();
        ensure_log_dir_mode_if_needed(&self.config_dir)?;
        recover_product_log_clear(&self.config_dir)?;
        remove_product_log_temporary_files(&self.config_dir)?;
        #[cfg(test)]
        observe_log_append_open(&self.path);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        let mut last_byte = [0_u8; 1];
        if file.metadata()?.len() > 0 {
            file.seek(SeekFrom::End(-1))?;
            file.read_exact(&mut last_byte)?;
            if last_byte[0] != b'\n' {
                file.write_all(b"\n")?;
            }
        }
        let metadata = file.metadata()?;
        repair_log_file_mode_if_needed(&self.path, &metadata)?;
        let metadata = file.metadata()?;
        let mut segments = VecDeque::new();
        for segment in product_log_segments(&self.config_dir)? {
            segments.push_back(ProductLogWriterSegment::scan(
                &segment.path,
                Some((segment.first_id, segment.last_id)),
            )?);
        }
        segments.push_back(ProductLogWriterSegment::scan(&self.path, None)?);
        let entry_count = segments.iter().map(|segment| segment.visible_entries).sum();
        let visible_bytes = segments.iter().map(|segment| segment.visible_bytes).sum();
        let last_id = segments
            .iter()
            .map(|segment| segment.last_id)
            .max()
            .unwrap_or(0);
        let first_visible_id = segments
            .iter()
            .find(|segment| segment.first_id != 0)
            .map(|segment| segment.first_id)
            .unwrap_or_else(|| last_id.saturating_add(1));
        self.identity = Some(ProductLogWriterFileIdentity::from_metadata(&metadata));
        self.size_bytes = metadata.len();
        self.entry_count = entry_count;
        self.last_id = last_id;
        self.first_visible_id = first_visible_id;
        self.visible_bytes = visible_bytes;
        self.segments = segments;
        let (mut persisted_first_id, mut journal_bytes) = read_log_visibility(&self.config_dir)?;
        if last_id.saturating_add(1) < persisted_first_id {
            remove_product_log_visibility_file(&self.config_dir)?;
            persisted_first_id = 0;
            journal_bytes = 0;
        }
        self.persisted_visible_first_id = persisted_first_id;
        self.visibility_journal_bytes = journal_bytes;
        self.file = Some(file);
        while self.entry_count > 0 && self.first_visible_id < persisted_first_id {
            self.trim_oldest_entry_locked()?;
        }
        set_log_id_cache(&self.path, last_id)?;
        self.prune_if_over_limit_locked()?;
        Ok(())
    }

    fn prune_if_over_limit_locked(&mut self) -> io::Result<bool> {
        let max_entries = normalize_log_max_entries(self.policy.max_entries) as usize;
        let max_bytes = normalize_log_max_bytes(self.policy.max_bytes) as u64;
        let visible_byte_limit = max_bytes
            .saturating_sub(PRODUCT_LOG_SEGMENT_MAX_BYTES + PRODUCT_LOG_VISIBILITY_BUDGET_BYTES);
        let mut pruned = false;
        while self.entry_count > max_entries || self.visible_bytes > visible_byte_limit {
            self.trim_oldest_entry_locked()?;
            pruned = true;
        }
        while self.physical_bytes() > max_bytes {
            if self
                .segments
                .front()
                .is_some_and(|segment| segment.head_offset > 0)
            {
                self.compact_head_locked()?;
            } else if self.entry_count > 0 {
                self.trim_oldest_entry_locked()?;
                pruned = true;
            } else {
                break;
            }
        }
        self.persist_visibility_locked()?;
        set_log_visible_first_id(&self.path, self.first_visible_id)?;
        Ok(pruned)
    }

    fn persist_visibility_locked(&mut self) -> io::Result<()> {
        self.persist_visibility_record_locked().inspect_err(|_| {
            // A partial journal write or failed compaction must be recovered
            // before any later append can acknowledge another visible boundary.
            // Reopening repairs a torn tail and keeps the sealed log history.
            self.file.take();
        })
    }

    fn persist_visibility_record_locked(&mut self) -> io::Result<()> {
        if self.first_visible_id == self.persisted_visible_first_id {
            return Ok(());
        }
        let path = product_log_visibility_file(&self.config_dir);
        let mut record = [0_u8; PRODUCT_LOG_VISIBILITY_RECORD_BYTES as usize];
        record[..8].copy_from_slice(&self.first_visible_id.to_le_bytes());
        record[8..].copy_from_slice(&(!self.first_visible_id).to_le_bytes());
        // Compact before appending at the limit. Repeated compaction failures
        // must not grow a valid journal past the recovery reader's size bound.
        if self.visibility_journal_bytes >= PRODUCT_LOG_VISIBILITY_JOURNAL_MAX_BYTES {
            let tmp = path.with_extension("bin.tmp");
            let mut compact = fs::File::create(&tmp)?;
            compact.write_all(&record)?;
            compact.sync_all()?;
            set_log_file_permissions(&tmp)?;
            fs::rename(tmp, path)?;
            self.visibility_journal_bytes = PRODUCT_LOG_VISIBILITY_RECORD_BYTES;
        } else {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            write_log_visibility_record(&mut file, &record)?;
            set_log_file_permissions(&path)?;
            self.visibility_journal_bytes += PRODUCT_LOG_VISIBILITY_RECORD_BYTES;
        }
        self.persisted_visible_first_id = self.first_visible_id;
        Ok(())
    }

    fn physical_bytes(&self) -> u64 {
        self.segments
            .iter()
            .map(|segment| segment.size_bytes)
            .sum::<u64>()
            + self.visibility_journal_bytes
    }

    fn trim_oldest_entry_locked(&mut self) -> io::Result<()> {
        loop {
            let Some(front) = self.segments.front_mut() else {
                return Ok(());
            };
            if front.visible_entries == 0 {
                if front.sealed_ids.is_some() {
                    self.visible_bytes = self.visible_bytes.saturating_sub(front.visible_bytes);
                    fs::remove_file(front.path(&self.path))?;
                    self.segments.pop_front();
                    continue;
                }
                self.visible_bytes = self.visible_bytes.saturating_sub(front.visible_bytes);
                self.file.take();
                fs::write(&self.path, [])?;
                let file = fs::OpenOptions::new()
                    .read(true)
                    .append(true)
                    .open(&self.path)?;
                self.identity = Some(ProductLogWriterFileIdentity::from_metadata(
                    &file.metadata()?,
                ));
                self.size_bytes = 0;
                front.size_bytes = 0;
                front.visible_bytes = 0;
                front.head_offset = 0;
                self.file = Some(file);
                self.first_visible_id = self.last_id.saturating_add(1);
                return Ok(());
            }
            let path = front.path(&self.path);
            let mut reader = io::BufReader::new(fs::File::open(&path)?);
            reader.seek(SeekFrom::Start(front.head_offset))?;
            let mut line = Vec::new();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "log segment ended before its visible entries",
                ));
            }
            front.head_offset += read as u64;
            front.visible_bytes = front.visible_bytes.saturating_sub(read as u64);
            self.visible_bytes = self.visible_bytes.saturating_sub(read as u64);
            if let Ok(text) = std::str::from_utf8(&line)
                && let Some(entry) = parse_log_entry_line(text)
            {
                front.visible_entries -= 1;
                self.entry_count -= 1;
                self.first_visible_id = entry.id.saturating_add(1);
            }
            if front.visible_entries == 0 && front.sealed_ids.is_some() {
                fs::remove_file(path)?;
                self.segments.pop_front();
            }
            return Ok(());
        }
    }

    fn compact_head_locked(&mut self) -> io::Result<()> {
        let Some(front) = self.segments.front_mut() else {
            return Ok(());
        };
        let path = front.path(&self.path);
        let mut input = fs::File::open(&path)?;
        input.seek(SeekFrom::Start(front.head_offset))?;
        let tmp_path = path.with_extension("jsonl.compact.tmp");
        let mut output = fs::File::create(&tmp_path)?;
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        set_log_file_permissions(&tmp_path)?;
        if front.sealed_ids.is_none() {
            self.file.take();
        }
        fs::rename(&tmp_path, &path)?;
        front.size_bytes = front.visible_bytes;
        front.head_offset = 0;
        if front.sealed_ids.is_none() {
            let file = fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(&self.path)?;
            let metadata = file.metadata()?;
            self.identity = Some(ProductLogWriterFileIdentity::from_metadata(&metadata));
            self.size_bytes = metadata.len();
            self.file = Some(file);
        }
        Ok(())
    }

    fn rotate_active_locked(&mut self) -> io::Result<()> {
        let Some(active) = self.segments.back() else {
            return Ok(());
        };
        if active.visible_entries == 0 {
            self.file.take();
            fs::write(&self.path, [])?;
            return self.reopen_locked();
        }
        let archived = product_log_segment_path(&self.config_dir, active.first_id, active.last_id);
        if archived.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "product log segment already exists",
            ));
        }
        self.file.take();
        fs::rename(&self.path, &archived)?;
        if let Some(active) = self.segments.back_mut() {
            active.sealed_ids = Some((active.first_id, active.last_id));
        }
        let file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        set_log_file_permissions(&self.path)?;
        self.identity = Some(ProductLogWriterFileIdentity::from_metadata(
            &file.metadata()?,
        ));
        self.size_bytes = 0;
        self.segments.push_back(ProductLogWriterSegment {
            sealed_ids: None,
            size_bytes: 0,
            visible_bytes: 0,
            visible_entries: 0,
            head_offset: 0,
            first_id: 0,
            last_id: 0,
        });
        self.file = Some(file);
        Ok(())
    }
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
