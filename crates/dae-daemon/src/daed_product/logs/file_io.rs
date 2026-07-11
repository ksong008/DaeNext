use super::*;
use std::borrow::Cow;

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

pub(crate) fn clear_log_file(config_dir: &Path) -> io::Result<()> {
    let log_file = product_log_file(config_dir);
    ensure_log_dir(config_dir)?;
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    fs::write(&log_file, [])?;
    set_log_id_cache(&log_file, 0)?;
    set_log_file_permissions(&log_file)
}

pub(crate) fn clear_log_file_preserving_startup_reload_logs(config_dir: &Path) -> io::Result<()> {
    let log_file = product_log_file(config_dir);
    ensure_log_dir(config_dir)?;
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    let tmp_path = log_file.with_extension("jsonl.clear.tmp");
    {
        let output = fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(output);
        match fs::File::open(&log_file) {
            Ok(input) => {
                let mut reader = io::BufReader::new(input);
                let mut line = String::new();
                loop {
                    line.clear();
                    let read = reader.read_line(&mut line)?;
                    if read == 0 {
                        break;
                    }
                    if startup_reload_lifecycle_log_line(&line) {
                        writer.write_all(line.as_bytes())?;
                        if !line.ends_with('\n') {
                            writer.write_all(b"\n")?;
                        }
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        writer.flush()?;
    }
    set_log_file_permissions(&tmp_path)?;
    fs::rename(tmp_path, &log_file)?;
    reset_log_id_cache_to_last(&log_file)
}

pub(crate) fn append_log_line(path: &Path, line: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(line)?;
    set_log_file_permissions(path)
}

pub(crate) fn set_log_file_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

pub(crate) fn ensure_log_dir(config_dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let log_dir = product_log_dir(config_dir);
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
    let timestamp = libc::time_t::try_from(timestamp).ok()?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    let local = unsafe { libc::localtime_r(&timestamp, tm.as_mut_ptr()) };
    if local.is_null() {
        return None;
    }
    let tm = unsafe { tm.assume_init() };
    Some(format_product_log_timestamp_with_offset(
        i64::from(tm.tm_year) + 1900,
        i64::from(tm.tm_mon) + 1,
        i64::from(tm.tm_mday),
        i64::from(tm.tm_hour),
        i64::from(tm.tm_min),
        i64::from(tm.tm_sec),
        tm.tm_gmtoff as i64,
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

fn startup_reload_lifecycle_log_line(line: &str) -> bool {
    parse_log_entry_line(line).is_some_and(|entry| startup_reload_lifecycle_log_entry(&entry))
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
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
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
    Ok(0)
}

pub(crate) fn next_log_id(path: &Path) -> io::Result<u64> {
    let lock = LOG_LAST_ID_CACHE.get_or_init(|| Mutex::new(None));
    let mut cache = lock
        .lock()
        .map_err(|_| io::Error::other("product log id cache lock poisoned"))?;
    if let Some(cached) = cache.as_mut()
        && cached.path == path
    {
        cached.id = cached.id.saturating_add(1);
        return Ok(cached.id);
    }
    let id = read_last_log_id(path)?.saturating_add(1);
    *cache = Some(ProductLogIdCache {
        path: path.to_path_buf(),
        id,
    });
    Ok(id)
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

pub(crate) fn reset_log_id_cache_to_last(path: &Path) -> io::Result<()> {
    set_log_id_cache(path, read_last_log_id(path)?)
}

pub(crate) fn count_log_file_entries(config_dir: &Path) -> io::Result<i64> {
    let log_file = product_log_file(config_dir);
    let file = match fs::File::open(&log_file) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut count = 0_i64;
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        if parse_log_entry_line(&line).is_some() {
            count = count.saturating_add(1);
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
    let log_file = product_log_file(config_dir);
    let lock = LOG_FILE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("product log file lock poisoned"))?;
    prune_log_file_with_settings(&log_file, max_entries, max_bytes)?;
    reset_log_id_cache_to_last(&log_file)
}

pub(crate) fn prune_log_file_if_needed(
    path: &Path,
    max_entries: i64,
    max_bytes: i64,
    last_id: u64,
) -> io::Result<()> {
    let max_bytes = normalize_log_max_bytes(max_bytes) as u64;
    let size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if size <= max_bytes && !last_id.is_multiple_of(LOG_PRUNE_INTERVAL) {
        return Ok(());
    }
    prune_log_file_with_settings(path, max_entries, max_bytes as i64)
}

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
    let tmp_path = path.with_extension("jsonl.tmp");
    write_pruned_log_tail(&tmp_path, &data, max_entries)?;
    set_log_file_permissions(&tmp_path)?;
    fs::rename(tmp_path, path)
}

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
