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
        'files: for file in snapshot.files.rev() {
            let sealed = file.sealed_version();
            let mut input = Some(file.open()?);
            if let Some(entries) =
                super::parsed_cache::sealed_entries(&snapshot.store, &mut input, sealed)?
            {
                for entry in entries.iter() {
                    if entry.id >= snapshot.first_visible_id
                        && log_entry_matches_filter(entry, level.as_deref(), query.as_deref())
                    {
                        items.push_front(log_entry_value(entry.clone()));
                        if items.len() == limit {
                            break 'files;
                        }
                    }
                }
                continue;
            }
            let mut reader = super::reverse_reader::ReverseFileLineReader::new(
                input.take().expect("opened snapshot file"),
                MAX_LOG_LINE_BYTES * 2,
            );
            while reader.read_line(&mut line)? {
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
                items.push_front(log_entry_value(entry));
                if items.len() == limit {
                    break;
                }
            }
            if let Some(version) = sealed
                && ProductLogContentVersion::from_metadata(&reader.metadata()?) != version
            {
                return Err(super::store::snapshot_changed());
            }
            if items.len() == limit {
                break;
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
