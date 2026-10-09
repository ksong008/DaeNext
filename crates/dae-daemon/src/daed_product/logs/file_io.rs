use super::*;
use std::borrow::Cow;

#[cfg(test)]
thread_local! {
    pub(super) static LOG_CLEAR_INTERRUPT_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn interrupt_log_clear_after_rename() -> io::Result<()> {
    if LOG_CLEAR_INTERRUPT_AFTER_RENAME.replace(false) {
        return Err(io::Error::other("injected interrupted log clear"));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct ProductLogEntry {
    pub(super) id: u64,
    pub(super) ts: String,
    pub(super) level: String,
    pub(super) message: String,
    pub(super) fields: BTreeMap<String, String>,
}

pub(crate) fn product_log_file(config_dir: &Path) -> PathBuf {
    product_log_dir(config_dir).join(PRODUCT_LOG_FILE)
}

pub(crate) fn product_log_file_lock() -> io::Result<std::sync::MutexGuard<'static, ()>> {
    LOG_FILE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))
}

pub(crate) fn product_log_dir(config_dir: &Path) -> PathBuf {
    match std::env::var_os(PRODUCT_LOG_DIR_ENV).filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                config_dir.join(path)
            }
        }
        None => config_dir.join(PRODUCT_LOG_DIR),
    }
}

const PRODUCT_LOG_SEGMENT_PREFIX: &str = "segment-";
const PRODUCT_LOG_SEGMENT_SUFFIX: &str = ".jsonl";
const PRODUCT_LOG_VISIBILITY_FILE: &str = "visible-first-id.bin";
pub(super) const PRODUCT_LOG_VISIBILITY_RECORD_BYTES: u64 = 16;
pub(super) const PRODUCT_LOG_VISIBILITY_JOURNAL_MAX_BYTES: u64 = 4 * 1024;

pub(crate) fn product_log_visibility_file(config_dir: &Path) -> PathBuf {
    product_log_dir(config_dir).join(PRODUCT_LOG_VISIBILITY_FILE)
}

pub(super) fn read_log_visibility(config_dir: &Path) -> io::Result<(u64, u64)> {
    let path = product_log_visibility_file(config_dir);
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => return Err(error),
    };
    if data.len() as u64
        > PRODUCT_LOG_VISIBILITY_JOURNAL_MAX_BYTES + PRODUCT_LOG_VISIBILITY_RECORD_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "product log visibility journal is oversized",
        ));
    }
    let mut last_id = 0;
    let mut valid_bytes = 0;
    for record in data.chunks_exact(PRODUCT_LOG_VISIBILITY_RECORD_BYTES as usize) {
        let id = u64::from_le_bytes(record[..8].try_into().expect("visibility record length"));
        let complement =
            u64::from_le_bytes(record[8..].try_into().expect("visibility record length"));
        if complement != !id || id < last_id {
            break;
        }
        last_id = id;
        valid_bytes += PRODUCT_LOG_VISIBILITY_RECORD_BYTES;
    }
    if valid_bytes != data.len() as u64 {
        fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(valid_bytes)?;
    }
    Ok((last_id, valid_bytes))
}

pub(crate) fn remove_product_log_visibility_file(config_dir: &Path) -> io::Result<()> {
    for path in [
        product_log_visibility_file(config_dir),
        product_log_dir(config_dir).join("visible-first-id.bin.tmp"),
    ] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) struct ProductLogSegmentFile {
    pub(crate) path: PathBuf,
    pub(crate) first_id: u64,
    pub(crate) last_id: u64,
}

pub(crate) fn product_log_segment_path(config_dir: &Path, first_id: u64, last_id: u64) -> PathBuf {
    product_log_dir(config_dir).join(format!(
        "{PRODUCT_LOG_SEGMENT_PREFIX}{first_id:020}-{last_id:020}{PRODUCT_LOG_SEGMENT_SUFFIX}"
    ))
}

pub(crate) fn product_log_segments(config_dir: &Path) -> io::Result<Vec<ProductLogSegmentFile>> {
    let dir = product_log_dir(config_dir);
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut segments = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(bounds) = name
            .strip_prefix(PRODUCT_LOG_SEGMENT_PREFIX)
            .and_then(|name| name.strip_suffix(PRODUCT_LOG_SEGMENT_SUFFIX))
        else {
            continue;
        };
        let Some((first, last)) = bounds.split_once('-') else {
            continue;
        };
        let (Ok(first_id), Ok(last_id)) = (first.parse::<u64>(), last.parse::<u64>()) else {
            continue;
        };
        if first_id > last_id || !entry.file_type()?.is_file() {
            continue;
        }
        segments.push(ProductLogSegmentFile {
            path: entry.path(),
            first_id,
            last_id,
        });
    }
    segments.sort_unstable_by_key(|segment| (segment.first_id, segment.last_id));
    Ok(segments)
}

pub(crate) fn product_log_files(config_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<_> = product_log_segments(config_dir)?
        .into_iter()
        .map(|segment| segment.path)
        .collect();
    files.push(product_log_file(config_dir));
    Ok(files)
}

#[cfg(test)]
thread_local! {
    pub(crate) static LOG_READER_AFTER_ENUMERATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn observe_log_reader_enumeration() {
    if let Some(callback) = LOG_READER_AFTER_ENUMERATION.with(|slot| slot.borrow_mut().take()) {
        callback();
    }
}

pub(crate) fn remove_product_log_segments(config_dir: &Path) -> io::Result<()> {
    for segment in product_log_segments(config_dir)? {
        match fs::remove_file(segment.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn remove_product_log_temporary_files(config_dir: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(product_log_dir(config_dir)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.ends_with(".jsonl.compact.tmp")
            || name == "current.jsonl.clear.tmp"
            || name == "current.jsonl.install.tmp"
            || name == "visible-first-id.bin.tmp")
        {
            continue;
        }
        if entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

// A durable ready file owns the new snapshot until replacement and reclamation
// are complete. Installation uses a hard link so retrying does not copy it.
fn commit_product_log_clear(config_dir: &Path, temporary: &Path) -> io::Result<()> {
    fs::File::open(temporary)?.sync_all()?;
    let ready = product_log_file(config_dir).with_extension("jsonl.clear.ready");
    fs::rename(temporary, &ready)?;
    fs::File::open(product_log_dir(config_dir))?.sync_all()?;
    recover_product_log_clear(config_dir)
}

pub(crate) fn recover_product_log_clear(config_dir: &Path) -> io::Result<()> {
    let path = product_log_file(config_dir);
    let ready = path.with_extension("jsonl.clear.ready");
    match fs::metadata(&ready) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let install = path.with_extension("jsonl.install.tmp");
    match fs::remove_file(&install) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::hard_link(&ready, &install)?;
    fs::rename(&install, &path)?;
    #[cfg(test)]
    interrupt_log_clear_after_rename()?;
    remove_product_log_segments(config_dir)?;
    remove_product_log_visibility_file(config_dir)?;
    let directory = fs::File::open(product_log_dir(config_dir))?;
    directory.sync_all()?;
    fs::remove_file(ready)?;
    directory.sync_all()?;
    set_log_visible_first_id(&path, 0)?;
    reset_log_id_cache_to_last(&path)
}

pub(crate) fn clear_log_file(config_dir: &Path) -> io::Result<()> {
    if let Some(runtime) = product_log_runtime_for(config_dir) {
        return runtime.clear();
    }
    clear_log_file_direct(config_dir)
}

pub(crate) fn clear_log_file_direct(config_dir: &Path) -> io::Result<()> {
    let log_file = product_log_file(config_dir);
    ensure_log_dir(config_dir)?;
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    recover_product_log_clear(config_dir)?;
    let temporary = log_file.with_extension("jsonl.clear.tmp");
    fs::write(&temporary, [])?;
    set_log_file_permissions(&temporary)?;
    commit_product_log_clear(config_dir, &temporary)
}

pub(crate) fn clear_log_file_preserving_startup_reload_logs(config_dir: &Path) -> io::Result<()> {
    if let Some(runtime) = product_log_runtime_for(config_dir) {
        return runtime.clear_preserving_lifecycle();
    }
    clear_log_file_preserving_startup_reload_logs_direct(config_dir)
}

pub(crate) fn clear_log_file_preserving_startup_reload_logs_direct(
    config_dir: &Path,
) -> io::Result<()> {
    let log_file = product_log_file(config_dir);
    ensure_log_dir(config_dir)?;
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    recover_product_log_clear(config_dir)?;
    let first_visible_id = read_log_visibility(config_dir)?.0;
    let tmp_path = log_file.with_extension("jsonl.clear.tmp");
    {
        let output = fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(output);
        for path in product_log_files(config_dir)? {
            match fs::File::open(path) {
                Ok(input) => {
                    let mut reader = io::BufReader::new(input);
                    let mut line = Vec::new();
                    loop {
                        line.clear();
                        let read = reader.read_until(b'\n', &mut line)?;
                        if read == 0 {
                            break;
                        }
                        if std::str::from_utf8(&line)
                            .ok()
                            .and_then(parse_log_entry_line)
                            .is_some_and(|entry| {
                                entry.id >= first_visible_id
                                    && startup_reload_lifecycle_log_entry(&entry)
                            })
                        {
                            writer.write_all(&line)?;
                            if !line.ends_with(b"\n") {
                                writer.write_all(b"\n")?;
                            }
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        writer.flush()?;
    }
    set_log_file_permissions(&tmp_path)?;
    commit_product_log_clear(config_dir, &tmp_path)
}

pub(crate) fn set_log_file_permissions(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    observe_log_file_permission_write(path);
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

pub(crate) fn ensure_log_dir(config_dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let log_dir = product_log_dir(config_dir);
    #[cfg(test)]
    observe_log_dir_permission_write(&log_dir);
    fs::create_dir_all(&log_dir)?;
    fs::set_permissions(log_dir, fs::Permissions::from_mode(0o750))
}

pub(crate) fn encode_log_entry_line(
    id: u64,
    level: &str,
    message: &str,
    fields: BTreeMap<String, String>,
) -> io::Result<Vec<u8>> {
    let mut message = trim_log_string(message, MAX_LOG_LINE_BYTES);
    let mut fields = trim_log_fields(fields, MAX_LOG_FIELD_VALUE_LEN);
    let mut line = encode_log_entry_json_line(id, level, &message, &fields)?;
    if line.len() > MAX_LOG_LINE_BYTES {
        message = trim_log_string(&message, MAX_LOG_LINE_BYTES / 2);
        fields = trim_log_fields(fields, 256);
        line = encode_log_entry_json_line(id, level, &message, &fields)?;
    }
    if line.len() > MAX_LOG_LINE_BYTES {
        message = trim_log_string(&message, 1024);
        fields.clear();
        line = encode_log_entry_json_line(id, level, &message, &fields)?;
    }
    Ok(line)
}

pub(crate) fn encode_log_entry_json_line(
    id: u64,
    level: &str,
    message: &str,
    fields: &BTreeMap<String, String>,
) -> io::Result<Vec<u8>> {
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(id));
    object.insert("ts".to_owned(), json!(product_log_timestamp_text()));
    object.insert("level".to_owned(), json!(level));
    object.insert("message".to_owned(), json!(message));
    if !fields.is_empty() {
        object.insert("fields".to_owned(), json!(fields));
    }
    let mut data = serde_json::to_vec(&Value::Object(object))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    data.push(b'\n');
    Ok(data)
}

fn product_log_timestamp_text() -> String {
    local_product_log_timestamp_text(unix_now()).unwrap_or_else(now_text)
}

#[cfg(target_family = "unix")]
fn local_product_log_timestamp_text(timestamp: u64) -> Option<String> {
    let timestamp = timestamp.try_into().ok()?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    let local = unsafe { libc::localtime_r(&timestamp, tm.as_mut_ptr()) };
    if local.is_null() {
        return None;
    }
    let tm = unsafe { tm.assume_init() };
    #[cfg(target_pointer_width = "64")]
    let offset_seconds = tm.tm_gmtoff;
    #[cfg(target_pointer_width = "32")]
    let offset_seconds = i64::from(tm.tm_gmtoff);
    Some(format_product_log_timestamp_with_offset(
        i64::from(tm.tm_year) + 1900,
        i64::from(tm.tm_mon) + 1,
        i64::from(tm.tm_mday),
        i64::from(tm.tm_hour),
        i64::from(tm.tm_min),
        i64::from(tm.tm_sec),
        offset_seconds,
    ))
}

#[cfg(not(target_family = "unix"))]
fn local_product_log_timestamp_text(_timestamp: u64) -> Option<String> {
    None
}

pub(crate) fn format_product_log_timestamp_with_offset(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    offset_seconds: i64,
) -> String {
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let offset_minutes = (offset_seconds / 60).abs();
    let offset_hour = offset_minutes / 60;
    let offset_minute = offset_minutes % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{sign}{offset_hour:02}:{offset_minute:02}"
    )
}

pub(crate) fn trim_log_fields(
    fields: BTreeMap<String, String>,
    max_value_len: usize,
) -> BTreeMap<String, String> {
    fields
        .into_iter()
        .map(|(key, value)| (key, trim_log_string(&value, max_value_len)))
        .collect()
}

pub(crate) fn trim_log_string(value: &str, max_len: usize) -> String {
    if max_len == 0 || value.len() <= max_len {
        return value.to_owned();
    }
    let mut boundary = 0;
    for (idx, _) in value.char_indices() {
        if idx > max_len {
            break;
        }
        boundary = idx;
    }
    if boundary == 0 {
        return "...".to_owned();
    }
    format!("{}...", &value[..boundary])
}

pub(crate) fn parse_log_entry_line(line: &str) -> Option<ProductLogEntry> {
    let raw = serde_json::from_str::<ProductLogEntryRaw<'_>>(line).ok()?;
    let id = raw.id.into_u64()?;
    let level = normalize_log_level_name(raw.level)?;
    let fields = raw
        .fields
        .into_iter()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    Some(ProductLogEntry {
        id,
        ts: raw.ts.to_owned(),
        level,
        message: raw.message.to_owned(),
        fields,
    })
}

#[derive(serde::Deserialize)]
struct ProductLogEntryRaw<'a> {
    id: ProductLogIdRaw,
    #[serde(borrow)]
    ts: &'a str,
    #[serde(borrow)]
    level: &'a str,
    #[serde(borrow)]
    message: &'a str,
    #[serde(default, borrow)]
    fields: BTreeMap<Cow<'a, str>, ProductLogFieldRaw<'a>>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ProductLogIdRaw {
    Unsigned(u64),
    Signed(i64),
}

impl ProductLogIdRaw {
    fn into_u64(self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(value),
            Self::Signed(value) => u64::try_from(value).ok(),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ProductLogFieldRaw<'a> {
    String(#[serde(borrow)] &'a str),
    Other(Value),
}

impl ProductLogFieldRaw<'_> {
    fn into_owned(self) -> String {
        match self {
            Self::String(value) => value.to_owned(),
            Self::Other(value) => value.to_string(),
        }
    }
}

pub(crate) fn startup_reload_lifecycle_log_kind(message: &str) -> Option<&'static str> {
    if message.starts_with("[Startup]") {
        return Some("startup");
    }
    if message.starts_with("[Reload]") {
        return Some("reload");
    }
    if matches!(
        message,
        "The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure."
            | "Rust/Aya BPF loader loaded"
            | "Loaded eBPF programs and maps"
    ) || (message.starts_with("Bind ") && message.contains(" via Rust/Aya "))
        || message.starts_with("Routing match set len:")
    {
        return Some("startup");
    }
    None
}

fn startup_reload_lifecycle_log_entry(entry: &ProductLogEntry) -> bool {
    matches!(
        entry.fields.get("lifecycle").map(String::as_str),
        Some("startup" | "reload")
    ) || startup_reload_lifecycle_log_kind(&entry.message).is_some()
}

pub(crate) fn log_entry_value(entry: ProductLogEntry) -> Value {
    let mut object = Map::new();
    object.insert("id".to_owned(), json!(entry.id));
    object.insert("ts".to_owned(), json!(entry.ts));
    object.insert("level".to_owned(), json!(entry.level));
    object.insert("message".to_owned(), json!(entry.message));
    object.insert("fields".to_owned(), json!(entry.fields));
    Value::Object(object)
}

pub(crate) fn log_entry_matches_filter(
    entry: &ProductLogEntry,
    level: Option<&str>,
    query: Option<&str>,
) -> bool {
    if level.is_some_and(|level| level != entry.level) {
        return false;
    }
    let Some(query) = query else {
        return true;
    };
    if entry.message.to_ascii_lowercase().contains(query) {
        return true;
    }
    entry.fields.iter().any(|(key, value)| {
        key.to_ascii_lowercase().contains(query) || value.to_ascii_lowercase().contains(query)
    })
}

pub(crate) fn read_last_log_id(path: &Path) -> io::Result<u64> {
    let data = match read_tail_bytes(path, LOG_TAIL_ID_SCAN_BYTES) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err),
    };
    for line in data.split(|byte| *byte == b'\n').rev() {
        if line.is_empty() {
            continue;
        }
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        if let Some(entry) = parse_log_entry_line(line) {
            return Ok(entry.id);
        }
    }
    let Some(dir) = path.parent() else {
        return Ok(0);
    };
    let mut last_id = 0;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(bounds) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PRODUCT_LOG_SEGMENT_PREFIX))
            .and_then(|name| name.strip_suffix(PRODUCT_LOG_SEGMENT_SUFFIX))
        else {
            continue;
        };
        if let Some((_, last)) = bounds.split_once('-')
            && let Ok(id) = last.parse::<u64>()
        {
            last_id = last_id.max(id);
        }
    }
    Ok(last_id)
}

pub(crate) fn cached_last_log_id(path: &Path) -> io::Result<u64> {
    let lock = LOG_LAST_ID_CACHE.get_or_init(|| Mutex::new(None));
    {
        let cache = lock
            .lock()
            .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
        if let Some(cached) = cache.as_ref()
            && cached.path == path
        {
            return Ok(cached.id);
        }
    }
    reset_log_id_cache_to_last(path)?;
    let cache = lock
        .lock()
        .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
    Ok(cache.as_ref().map(|cached| cached.id).unwrap_or(0))
}

pub(crate) fn set_log_id_cache(path: &Path, id: u64) -> io::Result<()> {
    let lock = LOG_LAST_ID_CACHE.get_or_init(|| Mutex::new(None));
    let mut cache = lock
        .lock()
        .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
    *cache = Some(ProductLogIdCache {
        path: path.to_path_buf(),
        id,
    });
    Ok(())
}

pub(crate) fn set_log_visible_first_id(path: &Path, id: u64) -> io::Result<()> {
    let mut cache = LOG_VISIBLE_FIRST_ID_CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| io::Error::other("product log visibility cache lock poisoned"))?;
    cache.insert(path.to_path_buf(), id);
    Ok(())
}

pub(crate) fn cached_log_visible_first_id(path: &Path) -> io::Result<Option<u64>> {
    let cache = LOG_VISIBLE_FIRST_ID_CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| io::Error::other("product log visibility cache lock poisoned"))?;
    Ok(cache.get(path).copied())
}

pub(crate) fn reset_log_id_cache_to_last(path: &Path) -> io::Result<()> {
    set_log_id_cache(path, read_last_log_id(path)?)
}

pub(crate) fn count_log_file_entries(config_dir: &Path) -> io::Result<i64> {
    let _guard = product_log_file_lock()?;
    let first_visible_id = cached_log_visible_first_id(&product_log_file(config_dir))?.unwrap_or(0);
    let mut count = 0_i64;
    for path in product_log_files(config_dir)? {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let mut reader = io::BufReader::new(file);
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line)? != 0 {
            if std::str::from_utf8(&line)
                .ok()
                .and_then(parse_log_entry_line)
                .is_some_and(|entry| entry.id >= first_visible_id)
            {
                count = count.saturating_add(1);
            }
            line.clear();
        }
    }
    Ok(count)
}

pub(crate) fn read_tail_bytes(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(Vec::new());
    }
    let offset = size.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(offset))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    if offset > 0
        && let Some(newline) = data.iter().position(|byte| *byte == b'\n')
    {
        data = data.split_off(newline + 1);
    }
    Ok(data)
}

pub(crate) fn prune_log_file(config_dir: &Path, conn: &Connection) -> io::Result<()> {
    let (max_entries, max_bytes) = log_settings_tuple(conn)?;
    if let Some(runtime) = product_log_runtime_for(config_dir) {
        return runtime.apply_limits(max_entries, max_bytes);
    }
    apply_product_log_limits_without_runtime(config_dir, max_entries, max_bytes)
}

#[cfg(test)]
pub(crate) fn prune_log_file_with_settings(
    path: &Path,
    max_entries: i64,
    max_bytes: i64,
) -> io::Result<()> {
    let max_entries = normalize_log_max_entries(max_entries) as usize;
    let max_bytes = normalize_log_max_bytes(max_bytes) as u64;
    let data = match read_tail_bytes(path, max_bytes) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if data.is_empty() {
        return Ok(());
    }
    #[cfg(test)]
    observe_log_prune_rewrite(path);
    let tmp_path = path.with_extension("jsonl.tmp");
    write_pruned_log_tail(&tmp_path, &data, max_entries)?;
    set_log_file_permissions(&tmp_path)?;
    fs::rename(tmp_path, path)
}

#[cfg(test)]
fn write_pruned_log_tail(path: &Path, data: &[u8], max_entries: usize) -> io::Result<()> {
    let mut ranges = Vec::new();
    let mut start = 0_usize;
    while start < data.len() {
        let end = data[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| start + offset)
            .unwrap_or(data.len());
        if end > start {
            ranges.push((start, end));
        }
        start = end.saturating_add(1);
    }
    let keep_from = ranges.len().saturating_sub(max_entries);
    let file = fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    for (start, end) in ranges.into_iter().skip(keep_from) {
        writer.write_all(&data[start..end])?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}
