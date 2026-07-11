use super::*;

const LOG_SSE_SCAN_BATCH_SIZE: usize = 256;
const LOG_SSE_SCAN_BATCHES_PER_TICK: usize = 4;

pub(super) async fn stream_runtime_events_async(
    stream: &mut tokio::net::TcpStream,
    app: &AppState,
    request: &HttpRequest,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    write_sse_headers(stream, request).await?;
    write_sse_retry(stream).await?;
    let first = runtime_overview_report(app, request);
    let mut last_reload_count = first
        .pointer("/runtime/reloadCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    write_sse_event(stream, "runtime.overview", &first).await?;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => {}
        }
        let delta = runtime_overview_delta_report(app, request);
        let reload_count = delta["reloadCount"].as_u64().unwrap_or(last_reload_count);
        if reload_count != last_reload_count {
            let full = runtime_overview_report(app, request);
            last_reload_count = full
                .pointer("/runtime/reloadCount")
                .and_then(Value::as_u64)
                .unwrap_or(reload_count);
            write_sse_event(stream, "runtime.overview", &full).await?;
        } else {
            write_sse_event(stream, "runtime.overview.delta", &delta).await?;
        }
    }
}

pub(super) async fn stream_log_events_async(
    stream: &mut tokio::net::TcpStream,
    app: &AppState,
    request: &HttpRequest,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let level = log_level_filter_from_request(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let after_id = log_event_after_id_from_request(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let query = request
        .query
        .get("q")
        .and_then(|values| values.first())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    write_sse_headers(stream, request).await?;
    write_sse_retry(stream).await?;

    let log_file = product_log_file(&app.config_dir);
    let replay_from_cursor = after_id.is_some();
    let mut last_seen_id = after_id.unwrap_or_else(|| cached_last_log_id(&log_file).unwrap_or(0));
    let mut cursor = if replay_from_cursor {
        ProductLogScanCursor::start()
    } else {
        ProductLogScanCursor::at_end(&app.config_dir)?
    };
    let mut last_heartbeat = Instant::now();
    let mut interval = tokio::time::interval(LOG_STREAM_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut log_updates = product_log_update_receiver(&app.config_dir);
    loop {
        if let Some(updates) = log_updates.as_mut() {
            enum LogStreamWake {
                Stop,
                Update(Result<(), tokio::sync::watch::error::RecvError>),
                Poll,
            }
            let wake = tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        LogStreamWake::Stop
                    } else {
                        LogStreamWake::Poll
                    }
                }
                changed = updates.changed() => LogStreamWake::Update(changed),
                _ = interval.tick() => LogStreamWake::Poll,
            };
            match wake {
                LogStreamWake::Stop => return Ok(()),
                LogStreamWake::Update(Err(_)) => log_updates = None,
                LogStreamWake::Update(Ok(())) | LogStreamWake::Poll => {}
            }
        } else {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return Ok(());
                    }
                }
                _ = interval.tick() => {}
            }
        }
        let current_last_id = cached_last_log_id(&log_file)?;
        if current_last_id < last_seen_id {
            last_seen_id = 0;
            cursor = ProductLogScanCursor::start();
        }
        if current_last_id != last_seen_id {
            for _ in 0..LOG_SSE_SCAN_BATCHES_PER_TICK {
                let batch = read_log_entry_batch_from_cursor(
                    &app.config_dir,
                    cursor,
                    last_seen_id,
                    LOG_SSE_SCAN_BATCH_SIZE,
                )?;
                cursor = batch.state.cursor;
                if batch.state.max_seen_id > last_seen_id {
                    last_seen_id = batch.state.max_seen_id;
                }
                for entry in batch.entries {
                    if log_entry_matches_filter(&entry, level.as_deref(), query.as_deref()) {
                        write_sse_event(stream, "log.entry", &log_entry_value(entry)).await?;
                    }
                }
                if batch.reached_eof || last_seen_id >= current_last_id {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
            write_sse_heartbeat(stream).await?;
            last_heartbeat = Instant::now();
        }
    }
}
