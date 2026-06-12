use super::*;

pub(in crate::daed_product) fn api_runtime_events(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let full = runtime_overview_report(app, request);
    thread::sleep(Duration::from_millis(200));
    let delta = runtime_overview_delta_report(app, request);
    sse_response_events(
        &[
            ("runtime.overview", full),
            ("runtime.overview.delta", delta),
        ],
        Some(LOG_STREAM_RETRY_MS),
    )
}

pub(in crate::daed_product) fn stream_runtime_events(
    stream: &mut TcpStream,
    app: &AppState,
    request: &HttpRequest,
) -> io::Result<()> {
    write_sse_stream_headers(stream, request)?;
    write!(stream, "retry: {LOG_STREAM_RETRY_MS}\n\n")?;
    let first = runtime_overview_report(app, request);
    let mut last_reload_count = first
        .pointer("/runtime/reloadCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    write_sse_stream_event(stream, "runtime.overview", &first)?;
    let mut last_heartbeat = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(1));
        let delta = runtime_overview_delta_report(app, request);
        let reload_count = delta["reloadCount"].as_u64().unwrap_or(last_reload_count);
        if reload_count != last_reload_count {
            let full = runtime_overview_report(app, request);
            last_reload_count = full
                .pointer("/runtime/reloadCount")
                .and_then(Value::as_u64)
                .unwrap_or(reload_count);
            write_sse_stream_event(stream, "runtime.overview", &full)?;
        } else {
            write_sse_stream_event(stream, "runtime.overview.delta", &delta)?;
        }
        if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
            stream.write_all(b": keep-alive\n\n")?;
            stream.flush()?;
            last_heartbeat = Instant::now();
        }
    }
}

pub(in crate::daed_product) fn api_log_events(
    _app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    match log_level_filter_from_request(request) {
        Ok(_) => sse_response_events(&[], Some(LOG_STREAM_RETRY_MS)),
        Err(err) => HttpResponse::json(400, json!({"error": err})),
    }
}

pub(in crate::daed_product) fn stream_log_events(
    stream: &mut TcpStream,
    app: &AppState,
    request: &HttpRequest,
) -> io::Result<()> {
    let level = match log_level_filter_from_request(request) {
        Ok(level) => level,
        Err(err) => {
            let response = HttpResponse::json(400, json!({"error": err}));
            return write_http_response_for_request(stream, request, &response, false);
        }
    };
    let query = request
        .query
        .get("q")
        .and_then(|values| values.first())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    write_sse_stream_headers(stream, request)?;
    write!(stream, "retry: {LOG_STREAM_RETRY_MS}\n\n")?;
    stream.flush()?;

    let log_file = product_log_file(&app.config_dir);
    let mut last_seen_id = cached_last_log_id(&log_file).unwrap_or(0);
    let mut scan_offset = log_file_size(&app.config_dir).unwrap_or(0);
    let mut last_heartbeat = Instant::now();
    loop {
        let current_last_id = cached_last_log_id(&log_file).unwrap_or(0);
        if current_last_id < last_seen_id {
            last_seen_id = 0;
            scan_offset = 0;
        }
        if current_last_id == last_seen_id {
            if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
                stream.write_all(b": heartbeat\n\n")?;
                stream.flush()?;
                last_heartbeat = Instant::now();
            }
            thread::sleep(LOG_STREAM_POLL_INTERVAL);
            continue;
        }
        let scan_result =
            scan_log_entries_from_offset(&app.config_dir, scan_offset, last_seen_id, |entry| {
                if log_entry_matches_filter(&entry, level.as_deref(), query.as_deref()) {
                    write_sse_stream_event(stream, "log.entry", &log_entry_value(entry))?;
                }
                Ok(())
            });
        if let Ok(scan) = scan_result {
            scan_offset = scan.offset;
            if scan.max_seen_id > last_seen_id {
                last_seen_id = scan.max_seen_id;
            }
        }
        if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
            stream.write_all(b": heartbeat\n\n")?;
            stream.flush()?;
            last_heartbeat = Instant::now();
        }
        thread::sleep(LOG_STREAM_POLL_INTERVAL);
    }
}
