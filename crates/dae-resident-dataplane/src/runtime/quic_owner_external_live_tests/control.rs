use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::time;

const RESTART_READY_FILE: &str = "restart-ready";
const RESTART_COMPLETE_FILE: &str = "restart-complete";
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) async fn coordinate_remote_restart(
    directory: &Path,
    protocol: &str,
    timeout: Duration,
) -> Result<(), String> {
    let ready = directory.join(RESTART_READY_FILE);
    let complete = directory.join(RESTART_COMPLETE_FILE);
    if ready.exists() || complete.exists() {
        return Err("external restart control directory contains stale markers".to_owned());
    }
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ready)
        .map_err(|err| format!("create external restart-ready marker: {err}"))?;
    writeln!(marker, "{protocol}")
        .map_err(|err| format!("write external restart-ready marker: {err}"))?;
    marker
        .sync_all()
        .map_err(|err| format!("sync external restart-ready marker: {err}"))?;

    let deadline = Instant::now() + timeout;
    while !complete.is_file() {
        if Instant::now() >= deadline {
            return Err("external server restart did not complete before timeout".to_owned());
        }
        time::sleep(CONTROL_POLL_INTERVAL).await;
    }
    Ok(())
}
