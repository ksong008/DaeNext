use super::*;
pub(crate) fn current_runtime_log_level(state: &Path) -> io::Result<String> {
    #[cfg(test)]
    observe_runtime_level_read(state);
    let level = get_metadata(state, "runtime_log_level")?
        .and_then(|level| normalize_runtime_log_level(&level))
        .unwrap_or_else(|| DEFAULT_RUNTIME_LOG_LEVEL.to_owned());
    Ok(level)
}

pub(crate) fn runtime_log_level_for_config(config: &Config) -> String {
    normalize_runtime_log_level(&config.global.log_level)
        .unwrap_or_else(|| DEFAULT_RUNTIME_LOG_LEVEL.to_owned())
}

#[cfg(test)]
pub(crate) fn set_runtime_log_level_from_config(state: &Path, config: &Config) -> io::Result<()> {
    let level = runtime_log_level_for_config(config);
    set_metadata(state, "runtime_log_level", &level)
}

pub(crate) fn log_level_enabled(entry_level: &str, runtime_level: &str) -> bool {
    let Some(entry_rank) = log_level_rank(entry_level) else {
        return false;
    };
    let runtime_rank = log_level_rank(runtime_level).unwrap_or(4);
    entry_rank <= runtime_rank
}

pub(crate) fn log_level_rank(level: &str) -> Option<u8> {
    match level {
        "panic" => Some(0),
        "fatal" => Some(1),
        "error" => Some(2),
        "warn" => Some(3),
        "info" => Some(4),
        "debug" => Some(5),
        "trace" => Some(6),
        _ => None,
    }
}

pub(crate) fn normalize_log_max_entries(value: i64) -> i64 {
    if value == 0 {
        DEFAULT_LOG_MAX_ENTRIES
    } else {
        value.clamp(MIN_LOG_MAX_ENTRIES, MAX_LOG_MAX_ENTRIES)
    }
}

pub(crate) fn normalize_log_max_bytes(value: i64) -> i64 {
    if value == 0 {
        DEFAULT_LOG_MAX_BYTES
    } else {
        value.clamp(MIN_LOG_MAX_BYTES, MAX_LOG_MAX_BYTES)
    }
}

pub(crate) fn normalize_log_level_filter(level: Option<&str>) -> io::Result<Option<String>> {
    let Some(level) = level else {
        return Ok(None);
    };
    let level = level.trim();
    if level.is_empty() || level.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    normalize_log_level_name(level).map(Some).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a valid logrus Level: {level:?}"),
        )
    })
}

pub(crate) fn normalize_log_level_name(level: &str) -> Option<String> {
    let level = level.trim().to_ascii_lowercase();
    match level.as_str() {
        "panic" | "fatal" | "error" | "warn" | "info" | "debug" | "trace" => Some(level),
        "warning" => Some("warn".to_owned()),
        _ => None,
    }
}

pub(crate) fn sse_response_events(events: &[(&str, Value)], retry_ms: Option<u64>) -> HttpResponse {
    let mut body = String::new();
    if let Some(retry_ms) = retry_ms {
        body.push_str(&format!("retry: {retry_ms}\n\n"));
    }
    for (event, payload) in events {
        body.push_str(&format!("event: {event}\ndata: {payload}\n\n"));
    }
    let mut response = HttpResponse::text(200, "text/event-stream; charset=utf-8", body);
    response
        .extra_headers
        .push(("Cache-Control".to_owned(), "no-cache".to_owned()));
    response
        .extra_headers
        .push(("X-Accel-Buffering".to_owned(), "no".to_owned()));
    response
}
