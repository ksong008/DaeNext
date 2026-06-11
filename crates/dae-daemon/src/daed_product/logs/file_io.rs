use super::*;
#[derive(Debug)]
pub(crate) struct ProductLogEntry {
    pub(super) id: u64,
    pub(super) ts: String,
    pub(super) level: String,
    pub(super) message: String,
    pub(super) fields: BTreeMap<String, String>,
}

pub(crate) fn product_log_file(config_dir: &Path) -> PathBuf {
    config_dir.join(PRODUCT_LOG_DIR).join(PRODUCT_LOG_FILE)
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
    let data = match fs::read_to_string(&log_file) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err),
    };
    let mut retained = data
        .lines()
        .filter(|line| startup_reload_lifecycle_log_line(line))
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .join("\n");
    if !retained.is_empty() {
        retained.push('\n');
    }
    fs::write(&log_file, retained)?;
    set_log_file_permissions(&log_file)?;
    reset_log_id_cache_to_last(&log_file)
}

pub(crate) fn append_log_line(path: &Path, line: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
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
    let log_dir = config_dir.join(PRODUCT_LOG_DIR);
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
    object.insert("ts".to_owned(), json!(now_text()));
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
    let value = serde_json::from_str::<Value>(line).ok()?;
    let id = value.get("id").and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
    })?;
    let ts = value.get("ts")?.as_str()?.to_owned();
    let level = normalize_log_level_name(value.get("level")?.as_str()?)?;
    let message = value.get("message")?.as_str()?.to_owned();
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .map(|fields| {
            fields
                .iter()
                .map(|(key, value)| {
                    (
                        key.to_owned(),
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string()),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    Some(ProductLogEntry {
        id,
        ts,
        level,
        message,
        fields,
    })
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
    for line in data.lines().rev() {
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

pub(crate) fn scan_log_entries_after_id(
    config_dir: &Path,
    after_id: u64,
) -> io::Result<(Vec<ProductLogEntry>, u64)> {
    let log_file = product_log_file(config_dir);
    let file = match fs::File::open(&log_file) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), after_id)),
        Err(err) => return Err(err),
    };
    let mut max_seen_id = after_id;
    let mut entries = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        let Some(entry) = parse_log_entry_line(&line) else {
            continue;
        };
        if entry.id > max_seen_id {
            max_seen_id = entry.id;
        }
        if entry.id > after_id {
            entries.push(entry);
        }
    }
    Ok((entries, max_seen_id))
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

pub(crate) fn read_tail_bytes(path: &Path, max_bytes: u64) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(String::new());
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
    Ok(String::from_utf8_lossy(&data).into_owned())
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
    if size <= max_bytes && last_id % LOG_PRUNE_INTERVAL != 0 {
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
    let mut lines = data
        .trim_end_matches('\n')
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if lines.len() > max_entries {
        lines = lines.split_off(lines.len() - max_entries);
    }
    let mut pruned = lines.join("\n");
    if !pruned.is_empty() {
        pruned.push('\n');
    }
    let tmp_path = path.with_extension("jsonl.tmp");
    fs::write(&tmp_path, pruned)?;
    set_log_file_permissions(&tmp_path)?;
    fs::rename(tmp_path, path)
}
