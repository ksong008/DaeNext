use super::*;

pub(super) fn drain_latency_probe_helper_lines<F>(
    line_rx: &Receiver<Result<String, String>>,
    reload_generation: u64,
    snapshots: &mut Vec<Value>,
    streamed_bytes: &mut usize,
    on_snapshot: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Value),
{
    loop {
        match line_rx.try_recv() {
            Ok(line) => consume_latency_probe_helper_line(
                line,
                reload_generation,
                snapshots,
                streamed_bytes,
                on_snapshot,
            )?,
            Err(mpsc::TryRecvError::Empty) => return Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
        }
    }
}

pub(super) fn drain_latency_probe_helper_until_closed<F>(
    line_rx: &Receiver<Result<String, String>>,
    reload_generation: u64,
    snapshots: &mut Vec<Value>,
    streamed_bytes: &mut usize,
    on_snapshot: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Value),
{
    let started = Instant::now();
    loop {
        match line_rx.recv_timeout(Duration::from_millis(20)) {
            Ok(line) => consume_latency_probe_helper_line(
                line,
                reload_generation,
                snapshots,
                streamed_bytes,
                on_snapshot,
            )?,
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout)
                if started.elapsed() >= LATENCY_PROBE_HELPER_READER_JOIN_GRACE =>
            {
                return Err("latency probe helper stdout reader did not finish".to_owned());
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

fn consume_latency_probe_helper_line<F>(
    line: Result<String, String>,
    reload_generation: u64,
    snapshots: &mut Vec<Value>,
    streamed_bytes: &mut usize,
    on_snapshot: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Value),
{
    let line = line?;
    *streamed_bytes = streamed_bytes
        .checked_add(line.len())
        .ok_or_else(|| "latency probe helper stream size overflow".to_owned())?;
    if *streamed_bytes > LATENCY_PROBE_HELPER_MAX_IO_BYTES {
        return Err(format!(
            "latency probe helper stream exceeds {} bytes",
            LATENCY_PROBE_HELPER_MAX_IO_BYTES
        ));
    }
    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }
    let snapshot: Value = serde_json::from_str(line)
        .map_err(|err| format!("parse latency probe helper stream line: {err}"))?;
    if snapshot.get("reloadGeneration").and_then(Value::as_u64) != Some(reload_generation) {
        return Err("latency probe helper stream reloadGeneration mismatch".to_owned());
    }
    snapshots.push(snapshot);
    if let Some(snapshot) = snapshots.last() {
        on_snapshot(snapshot);
    }
    Ok(())
}
