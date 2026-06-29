use serde::{Deserialize, Serialize};

use super::super::*;
use super::*;

pub(crate) const LATENCY_PROBE_HELPER_MAX_IO_BYTES: usize = 64 * 1024 * 1024;
const LATENCY_PROBE_HELPER_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const LATENCY_PROBE_HELPER_PARENT_MAX_INTERNAL_BATCHES: usize = 2;
pub(crate) const LATENCY_PROBE_HELPER_PARENT_CONSERVATIVE_LINK_CAP: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LatencyProbeHelperConfig {
    pub(crate) source: String,
    pub(crate) content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LatencyProbeHelperRequest {
    #[serde(rename = "schemaVersion")]
    pub(crate) schema_version: u64,
    pub(crate) scope: String,
    #[serde(rename = "reloadGeneration")]
    pub(crate) reload_generation: u64,
    #[serde(rename = "requestedLinks")]
    pub(crate) requested_links: Vec<String>,
    pub(crate) config: LatencyProbeHelperConfig,
    pub(crate) concurrency: usize,
}

#[derive(Debug)]
pub(crate) struct LatencyProbeHelperStreamError {
    pub(crate) snapshots: Vec<Value>,
    pub(crate) message: String,
}

pub(crate) fn run_latency_probe_helper_streaming<F>(
    config_content: &str,
    reload_generation: u64,
    concurrency: usize,
    links: &[String],
    mut on_snapshot: F,
) -> Result<Vec<Value>, LatencyProbeHelperStreamError>
where
    F: FnMut(&Value),
{
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

    let mut child = Command::new(current_exe)
        .args(["latency-probe-helper", "--stdin-json-lines"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: format!("spawn latency probe helper: {err}"),
        })?;
    {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            return Err(LatencyProbeHelperStreamError {
                snapshots: Vec::new(),
                message: "open latency probe helper stdin: unavailable".to_owned(),
            });
        };
        if let Err(err) = stdin.write_all(&request_json) {
            let _ = child.kill();
            return Err(LatencyProbeHelperStreamError {
                snapshots: Vec::new(),
                message: format!("write latency probe helper request: {err}"),
            });
        }
    }

    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err(LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: "open latency probe helper stdout: unavailable".to_owned(),
        });
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        return Err(LatencyProbeHelperStreamError {
            snapshots: Vec::new(),
            message: "open latency probe helper stderr: unavailable".to_owned(),
        });
    };

    let (line_tx, line_rx) = mpsc::channel::<Result<String, String>>();
    let stdout_reader = thread::spawn(move || {
        let reader = io::BufReader::new(stdout);
        for line in reader.lines() {
            if line_tx
                .send(line.map_err(|err| format!("read latency probe helper stdout: {err}")))
                .is_err()
            {
                break;
            }
        }
    });
    let (stderr_tx, stderr_rx) = mpsc::channel::<String>();
    let stderr_reader = thread::spawn(move || {
        let mut reader = io::BufReader::new(stderr);
        let mut stderr = String::new();
        let _ = reader.read_to_string(&mut stderr);
        let _ = stderr_tx.send(stderr);
    });

    let mut snapshots = Vec::new();
    let started = Instant::now();
    let status = loop {
        drain_latency_probe_helper_lines(
            &line_rx,
            reload_generation,
            &mut snapshots,
            &mut on_snapshot,
        )
        .map_err(|message| LatencyProbeHelperStreamError {
            snapshots: snapshots.clone(),
            message,
        })?;
        match child
            .try_wait()
            .map_err(|err| LatencyProbeHelperStreamError {
                snapshots: snapshots.clone(),
                message: format!("wait latency probe helper: {err}"),
            })? {
            Some(exit_status) => break Some(exit_status),
            None if started.elapsed() >= LATENCY_PROBE_HELPER_TIMEOUT => {
                let _ = child.kill();
                break child.wait().ok();
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    };

    let _ = stdout_reader.join();
    let _ = stderr_reader.join();
    drain_latency_probe_helper_lines(
        &line_rx,
        reload_generation,
        &mut snapshots,
        &mut on_snapshot,
    )
    .map_err(|message| LatencyProbeHelperStreamError {
        snapshots: snapshots.clone(),
        message,
    })?;

    let stderr = stderr_rx.try_recv().unwrap_or_default();
    let Some(status) = status else {
        return Err(LatencyProbeHelperStreamError {
            snapshots,
            message: "latency probe helper exited without status".to_owned(),
        });
    };
    if started.elapsed() >= LATENCY_PROBE_HELPER_TIMEOUT && !status.success() {
        return Err(LatencyProbeHelperStreamError {
            snapshots,
            message: format!(
                "latency probe helper timed out after {:?}: {}",
                LATENCY_PROBE_HELPER_TIMEOUT,
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
    Ok(snapshots)
}

fn drain_latency_probe_helper_lines<F>(
    line_rx: &Receiver<Result<String, String>>,
    reload_generation: u64,
    snapshots: &mut Vec<Value>,
    on_snapshot: &mut F,
) -> Result<(), String>
where
    F: FnMut(&Value),
{
    loop {
        match line_rx.try_recv() {
            Ok(Ok(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let snapshot: Value = serde_json::from_str(line)
                    .map_err(|err| format!("parse latency probe helper stream line: {err}"))?;
                if snapshot.get("reloadGeneration").and_then(Value::as_u64)
                    != Some(reload_generation)
                {
                    return Err("latency probe helper stream reloadGeneration mismatch".to_owned());
                }
                snapshots.push(snapshot);
                if let Some(snapshot) = snapshots.last() {
                    on_snapshot(snapshot);
                }
            }
            Ok(Err(err)) => return Err(err),
            Err(mpsc::TryRecvError::Empty) => return Ok(()),
            Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
        }
    }
}

pub(crate) fn latency_probe_helper_parent_chunk_size(
    concurrency: usize,
    unique_link_count: usize,
) -> usize {
    let concurrency = concurrency.max(1);
    let unique_link_count = unique_link_count.max(1);
    let max_links_per_helper = concurrency.max(
        concurrency
            .saturating_mul(LATENCY_PROBE_HELPER_PARENT_MAX_INTERNAL_BATCHES)
            .min(LATENCY_PROBE_HELPER_PARENT_CONSERVATIVE_LINK_CAP),
    );
    unique_link_count.min(max_links_per_helper.max(1))
}

pub(crate) fn latency_probe_helper_response_from_request(input: &[u8]) -> Result<Value, String> {
    let request = latency_probe_helper_request_from_input(input)?;
    let config = build_runtime_config_from_content(&request.config.content)?;
    let snapshots = crate::production_runtime_owner::run_resident_manual_latency_probe_helper(
        &config,
        &request.requested_links,
        request.reload_generation,
        request.concurrency.max(1),
    );
    Ok(json!({
        "schemaVersion": 1,
        "scope": "manual-latency-probe",
        "reloadGeneration": request.reload_generation,
        "snapshots": snapshots,
        "errors": [],
    }))
}

pub(crate) fn latency_probe_helper_response_lines_from_request<W: Write>(
    input: &[u8],
    mut writer: W,
) -> Result<(), String> {
    let request = latency_probe_helper_request_from_input(input)?;
    let config = build_runtime_config_from_content(&request.config.content)?;
    crate::production_runtime_owner::run_resident_manual_latency_probe_helper_streaming(
        &config,
        &request.requested_links,
        request.reload_generation,
        request.concurrency.max(1),
        |snapshot| {
            serde_json::to_writer(&mut writer, &snapshot)
                .map_err(|err| format!("write latency probe helper stream snapshot: {err}"))?;
            writer
                .write_all(b"\n")
                .map_err(|err| format!("write latency probe helper stream newline: {err}"))?;
            writer
                .flush()
                .map_err(|err| format!("flush latency probe helper stream: {err}"))?;
            Ok(())
        },
    )
}

fn latency_probe_helper_request_from_input(
    input: &[u8],
) -> Result<LatencyProbeHelperRequest, String> {
    if input.len() > LATENCY_PROBE_HELPER_MAX_IO_BYTES {
        return Err(format!(
            "latency probe helper stdin exceeds {} bytes",
            LATENCY_PROBE_HELPER_MAX_IO_BYTES
        ));
    }
    let request: LatencyProbeHelperRequest = serde_json::from_slice(input)
        .map_err(|err| format!("parse latency probe helper request: {err}"))?;
    if request.schema_version != 1 {
        return Err("unsupported latency probe helper request schemaVersion".to_owned());
    }
    if request.scope != "manual-latency-probe" {
        return Err("unsupported latency probe helper request scope".to_owned());
    }
    if request.config.source != "current-runtime-config" {
        return Err("unsupported latency probe helper config source".to_owned());
    }
    Ok(request)
}

pub(crate) fn latency_probe_failure_snapshots(
    links: &[String],
    reload_generation: u64,
    reason: &str,
    detail: &str,
) -> Vec<Value> {
    let checked_at = unix_now() as i64;
    links
        .iter()
        .filter(|link| !link.is_empty())
        .map(|link| {
            let display_name = node_name_from_link(link);
            let link_hash = runtime_link_hash(link);
            let redacted_source = runtime_redacted_link_source(link);
            json!({
                "name": display_name.as_str(),
                "displayName": display_name.as_str(),
                "graphId": graph_id_from_runtime_link_hash(&link_hash),
                "reloadGeneration": reload_generation,
                "linkHash": link_hash.as_str(),
                "linkIdentity": runtime_link_identity_value(&display_name, &link_hash, &redacted_source),
                "admission": {
                    "status": "fail-closed",
                    "unsupportedReason": detail,
                },
                "latencyMs": Value::Null,
                "alive": false,
                "checkedAtUnix": checked_at,
                "message": format!("{reason}: {detail}"),
                "scope": "proxy-tcp-check",
            })
        })
        .collect()
}

pub(crate) fn latency_probe_failure_snapshots_for_unseen_links(
    links: &[String],
    reload_generation: u64,
    reason: &str,
    detail: &str,
    seen_snapshots: &[Value],
) -> Vec<Value> {
    let seen_link_hashes = seen_snapshots
        .iter()
        .filter_map(runtime_latency_snapshot_link_hash)
        .collect::<HashSet<_>>();
    let unseen_links = links
        .iter()
        .filter(|link| !seen_link_hashes.contains(runtime_link_hash(link).as_str()))
        .cloned()
        .collect::<Vec<_>>();
    latency_probe_failure_snapshots(&unseen_links, reload_generation, reason, detail)
}

fn graph_id_from_runtime_link_hash(link_hash: &str) -> String {
    let graph_hash = link_hash.trim_start_matches("sha256:");
    format!("resident-graph:{}", &graph_hash[..16.min(graph_hash.len())])
}
