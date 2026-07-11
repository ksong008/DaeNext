use super::super::*;
use super::*;

mod failure;
mod process;
mod protocol;
mod stream;

pub(crate) use failure::latency_probe_failure_snapshots_for_unseen_links;
use process::{
    LatencyProbeHelperProcess, spawn_bounded_stderr_reader, spawn_bounded_stdout_reader,
};
use protocol::{LatencyProbeHelperConfig, LatencyProbeHelperRequest};
pub(crate) use protocol::{
    latency_probe_helper_response_from_request, latency_probe_helper_response_lines_from_request,
};
use stream::{drain_latency_probe_helper_lines, drain_latency_probe_helper_until_closed};

pub(crate) const LATENCY_PROBE_HELPER_MAX_IO_BYTES: usize = 16 * 1024 * 1024;
const LATENCY_PROBE_HELPER_MAX_LINE_BYTES: usize = 1024 * 1024;
const LATENCY_PROBE_HELPER_MAX_STDERR_BYTES: usize = 64 * 1024;
const LATENCY_PROBE_HELPER_MAX_CHANNEL_CAPACITY: usize = 1024;
const LATENCY_PROBE_HELPER_CONCURRENCY_BATCHES_PER_PROCESS: usize = 4;
const LATENCY_PROBE_HELPER_TIMEOUT: Duration = Duration::from_secs(20);
const LATENCY_PROBE_HELPER_TIMEOUT_GRACE: Duration = Duration::from_secs(20);
const LATENCY_PROBE_HELPER_READER_JOIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(crate) struct LatencyProbeHelperStreamError {
    pub(crate) snapshots: Vec<Value>,
    pub(crate) message: String,
}

#[derive(Debug)]
pub(crate) enum LatencyProbeHelperStreamOutcome {
    Completed,
    Cancelled,
}

pub(crate) fn run_latency_probe_helper_streaming<F, C>(
    config_content: &str,
    reload_generation: u64,
    concurrency: usize,
    tcp_probe_timeout: Duration,
    links: &[String],
    mut should_cancel: C,
    mut on_snapshot: F,
) -> Result<LatencyProbeHelperStreamOutcome, LatencyProbeHelperStreamError>
where
    F: FnMut(&Value),
    C: FnMut() -> bool,
{
    if should_cancel() {
        return Ok(LatencyProbeHelperStreamOutcome::Cancelled);
    }
    let current_exe = std::env::current_exe().map_err(|err| LatencyProbeHelperStreamError {
        snapshots: Vec::new(),
        message: format!("resolve latency probe helper executable: {err}"),
    })?;
    let request = LatencyProbeHelperRequest {
        schema_version: 1,
        scope: "manual-latency-probe".to_owned(),
        reload_generation,
        requested_links: links.to_vec(),
        config: LatencyProbeHelperConfig {
            source: "current-runtime-config".to_owned(),
            content: config_content.to_owned(),
        },
        concurrency: concurrency.max(1),
    };
    let request_json =
        serde_json::to_vec(&request).map_err(|err| LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: format!("encode latency probe helper request: {err}"),
        })?;
    if request_json.len() > LATENCY_PROBE_HELPER_MAX_IO_BYTES {
        return Err(LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: format!(
                "latency probe helper request exceeds {} bytes",
                LATENCY_PROBE_HELPER_MAX_IO_BYTES
            ),
        });
    }

    let child = Command::new(current_exe)
        .args(["latency-probe-helper", "--stdin-json-lines"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: format!("spawn latency probe helper: {err}"),
        })?;
    let mut process = LatencyProbeHelperProcess::new(child);
    {
        let Some(mut stdin) = process.child_mut().stdin.take() else {
            return Err(LatencyProbeHelperStreamError {
                snapshots: Vec::new(),
                message: "open latency probe helper stdin: unavailable".to_owned(),
            });
        };
        if let Err(err) = stdin.write_all(&request_json) {
            return Err(LatencyProbeHelperStreamError {
                snapshots: Vec::new(),
                message: format!("write latency probe helper request: {err}"),
            });
        }
    }

    let Some(stdout) = process.child_mut().stdout.take() else {
        return Err(LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: "open latency probe helper stdout: unavailable".to_owned(),
        });
    };
    let Some(stderr) = process.child_mut().stderr.take() else {
        return Err(LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: "open latency probe helper stderr: unavailable".to_owned(),
        });
    };

    let channel_capacity = concurrency
        .max(1)
        .saturating_mul(2)
        .min(LATENCY_PROBE_HELPER_MAX_CHANNEL_CAPACITY);
    let (line_tx, line_rx) = mpsc::sync_channel::<Result<String, String>>(channel_capacity);
    process.set_readers(
        spawn_bounded_stdout_reader(stdout, line_tx, LATENCY_PROBE_HELPER_MAX_LINE_BYTES),
        spawn_bounded_stderr_reader(stderr, LATENCY_PROBE_HELPER_MAX_STDERR_BYTES),
    );

    let mut snapshots = Vec::new();
    let mut streamed_bytes = 0usize;
    let timeout = latency_probe_helper_timeout(concurrency, links.len(), tcp_probe_timeout);
    let started = Instant::now();
    let mut cancelled = false;
    let status = loop {
        drain_latency_probe_helper_lines(
            &line_rx,
            reload_generation,
            &mut snapshots,
            &mut streamed_bytes,
            &mut on_snapshot,
        )
        .map_err(|message| LatencyProbeHelperStreamError {
            snapshots: snapshots.clone(),
            message,
        })?;
        if should_cancel() {
            cancelled = true;
            break process.terminate_and_wait();
        }
        match process
            .child_mut()
            .try_wait()
            .map_err(|err| LatencyProbeHelperStreamError {
                snapshots: snapshots.clone(),
                message: format!("wait latency probe helper: {err}"),
            })? {
            Some(exit_status) => {
                process.mark_reaped();
                break Some(exit_status);
            }
            None if started.elapsed() >= timeout => {
                break process.terminate_and_wait();
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    };

    drain_latency_probe_helper_until_closed(
        &line_rx,
        reload_generation,
        &mut snapshots,
        &mut streamed_bytes,
        &mut on_snapshot,
    )
    .map_err(|message| LatencyProbeHelperStreamError {
        snapshots: snapshots.clone(),
        message,
    })?;
    let stderr = process.join_readers();

    if cancelled {
        return Ok(LatencyProbeHelperStreamOutcome::Cancelled);
    }

    let Some(status) = status else {
        return Err(LatencyProbeHelperStreamError {
            snapshots,
            message: "latency probe helper exited without status".to_owned(),
        });
    };
    if started.elapsed() >= timeout && !status.success() {
        return Err(LatencyProbeHelperStreamError {
            snapshots,
            message: format!(
                "latency probe helper timed out after {:?}: {}",
                timeout,
                stderr.trim()
            ),
        });
    }
    if !status.success() {
        return Err(LatencyProbeHelperStreamError {
            snapshots,
            message: format!(
                "latency probe helper exited with status {}: {}",
                status,
                stderr.trim()
            ),
        });
    }
    Ok(LatencyProbeHelperStreamOutcome::Completed)
}

pub(crate) fn latency_probe_helper_parent_chunk_size(
    concurrency: usize,
    unique_link_count: usize,
) -> usize {
    let unique_link_count = unique_link_count.max(1);
    concurrency
        .max(1)
        .saturating_mul(LATENCY_PROBE_HELPER_CONCURRENCY_BATCHES_PER_PROCESS)
        .min(unique_link_count)
}

pub(crate) fn latency_probe_helper_timeout(
    concurrency: usize,
    link_count: usize,
    tcp_probe_timeout: Duration,
) -> Duration {
    let concurrency = concurrency.max(1);
    let link_count = link_count.max(1);
    let batches = link_count.div_ceil(concurrency).max(1);
    let task_budget = tcp_probe_timeout.saturating_mul(batches.try_into().unwrap_or(u32::MAX));
    LATENCY_PROBE_HELPER_TIMEOUT.max(task_budget.saturating_add(LATENCY_PROBE_HELPER_TIMEOUT_GRACE))
}
