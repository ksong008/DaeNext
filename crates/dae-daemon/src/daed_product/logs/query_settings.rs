use super::*;
pub(crate) fn list_logs_value(
    config_dir: &Path,
    state: &Path,
    level: Option<&str>,
    query: Option<&str>,
    limit: usize,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let limit = if limit == 0 {
        DEFAULT_LOG_QUERY_LIMIT
    } else {
        limit.min(MAX_LOG_QUERY_LIMIT)
    };
    let level = normalize_log_level_filter(level)?;
    let query = query
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    with_product_log_snapshot(config_dir, |snapshot| {
        let mut items = VecDeque::new();
        let mut line = Vec::new();
        for file in snapshot.files {
            let mut reader = io::BufReader::new(file);
            while read_product_log_line(&mut reader, &mut line)? {
                let Ok(text) = std::str::from_utf8(&line) else {
                    continue;
                };
                let Some(entry) = parse_log_entry_line(text) else {
                    continue;
                };
                if entry.id < snapshot.first_visible_id
                    || !log_entry_matches_filter(&entry, level.as_deref(), query.as_deref())
                {
                    continue;
                }
                if items.len() == limit {
                    items.pop_front();
                }
                items.push_back(log_entry_value(entry));
            }
        }
        Ok(json!({"items": items.into_iter().collect::<Vec<_>>()}))
    })
}

pub(crate) fn log_settings_value(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let (max_entries, max_bytes) = log_settings_tuple(&conn)?;
    Ok(json!({
        "maxEntries": max_entries,
        "maxBytes": max_bytes,
        "minMaxEntries": MIN_LOG_MAX_ENTRIES,
        "maxMaxEntries": MAX_LOG_MAX_ENTRIES,
        "minMaxBytes": MIN_LOG_MAX_BYTES,
        "maxMaxBytes": MAX_LOG_MAX_BYTES,
    }))
}

pub(crate) fn log_settings_tuple(conn: &Connection) -> io::Result<(i64, i64)> {
    conn.query_row(
        "SELECT max_entries, max_bytes FROM log_settings WHERE id = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )
    .optional()
    .map_err(sqlite_io_error)
    .map(|value| {
        let (max_entries, max_bytes) =
            value.unwrap_or((DEFAULT_LOG_MAX_ENTRIES, DEFAULT_LOG_MAX_BYTES));
        (
            normalize_log_max_entries(max_entries),
            normalize_log_max_bytes(max_bytes),
        )
    })
}
