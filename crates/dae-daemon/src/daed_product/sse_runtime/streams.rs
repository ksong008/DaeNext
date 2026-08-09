use super::*;

const LOG_SSE_SCAN_BATCH_SIZE: usize = 256;
const LOG_SSE_SCAN_BATCHES_PER_TICK: usize = 4;

pub(super) async fn stream_runtime_events_async(
    stream: &mut tokio::net::TcpStream,
    app: &AppState,
    request: &HttpRequest,
    mut stop: tokio::sync::watch::Receiver<bool>,
    mut overview: tokio::sync::broadcast::Receiver<Arc<ProductRuntimeOverviewTick>>,
    overview_full_cache: Arc<ProductRuntimeOverviewFullCache>,
) -> io::Result<()> {
    write_sse_headers(stream, request).await?;
    write_sse_retry(stream).await?;
    let mut last_runtime_identity = app.runtime.runtime_event_identity();
    let first = overview_full_cache.serialized(app, request)?;
    let mut last_reload_count = app.runtime.runtime_overview_delta_state().reload_count;
    write_sse_serialized_runtime_overview(stream, &first).await?;
    let mut group_selection_events = RuntimeGroupSelectionEventTracker::default();
    if let Some(event) = group_selection_events.observe_app(app) {
        write_sse_event(stream, RUNTIME_GROUP_SELECTION_EVENT, &event).await?;
    }
    let mut last_sequence = 0_u64;
    let mut sequence_synced = false;
    loop {
        let tick = tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
                continue;
            }
            peer = wait_sse_peer_closed(stream) => return peer,
            tick = overview.recv() => tick,
        };
        let tick = match tick {
            Ok(tick) => tick,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                let full = overview_full_cache.serialized(app, request)?;
                write_sse_serialized_runtime_overview(stream, &full).await?;
                sequence_synced = false;
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        };
        let runtime_identity = app.runtime.runtime_event_identity();
        let sequence_gap = sequence_synced && tick.sequence != last_sequence.saturating_add(1);
        if sequence_gap
            || tick.reload_count != last_reload_count
            || runtime_identity != last_runtime_identity
        {
            let full = overview_full_cache.serialized(app, request)?;
            last_reload_count = tick.reload_count;
            last_runtime_identity = runtime_identity;
            write_sse_serialized_runtime_overview(stream, &full).await?;
        } else {
            write_sse_serialized_runtime_delta(stream, &tick.payload).await?;
        }
        last_sequence = tick.sequence;
        sequence_synced = true;
        if let Some(event) = group_selection_events.observe_app(app) {
            write_sse_event(stream, RUNTIME_GROUP_SELECTION_EVENT, &event).await?;
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
                Peer(io::Result<()>),
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
                peer = wait_sse_peer_closed(stream) => LogStreamWake::Peer(peer),
                changed = updates.changed() => LogStreamWake::Update(changed),
                _ = interval.tick() => LogStreamWake::Poll,
            };
            match wake {
                LogStreamWake::Stop => return Ok(()),
                LogStreamWake::Peer(result) => return result,
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
                peer = wait_sse_peer_closed(stream) => return peer,
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
