use super::super::*;
use super::*;
#[cfg(test)]
use dae_product_control::subscription::parse_node_link;
#[cfg(test)]
use dae_product_control::subscription::{
    NODE_LATENCY_DB_WRITE_BATCH_SIZE, write_node_latency_results,
};

pub(crate) fn enqueue_node_latency_job(
    state: &Path,
    config_dir: &Path,
    control_runtime: Arc<ProductControlRuntime>,
    runtime: Arc<ProductRuntimeManager>,
    jobs: Arc<LatencyJobManager>,
    ids: &[i64],
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let nodes = latency_probe_nodes_for_ids(&conn, ids)?;
    drop(conn);
    let (job, admission) = jobs.start_or_current(nodes.len())?;
    let value = json!({
        "items": [],
        "admission": admission.as_str(),
        "job": job.to_value(),
    });
    if admission.should_spawn() {
        let job_id = job.id();
        let cancellation = job.cancellation();
        let context = LatencyJobRuntimeContext {
            state: state.to_path_buf(),
            config_dir: config_dir.to_path_buf(),
            control_runtime,
            runtime,
            jobs: Arc::clone(&jobs),
        };
        let spawn_result = thread::Builder::new()
            .name(format!("daed-latency-job-{job_id}"))
            .spawn(move || {
                run_node_latency_job(job_id, cancellation, context, nodes);
            });
        if let Err(err) = spawn_result {
            jobs.mark_failed(job_id, format!("spawn manual latency probe job: {err}"));
            return Err(io::Error::other(format!(
                "spawn manual latency probe job: {err}"
            )));
        }
    }
    Ok(value)
}

struct LatencyJobRuntimeContext {
    state: PathBuf,
    config_dir: PathBuf,
    control_runtime: Arc<ProductControlRuntime>,
    runtime: Arc<ProductRuntimeManager>,
    jobs: Arc<LatencyJobManager>,
}

fn run_node_latency_job(
    job_id: u64,
    cancellation: LatencyJobCancellation,
    context: LatencyJobRuntimeContext,
    nodes: Vec<LatencyProbeNode>,
) {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::ManualLatency);
    debug_assert_eq!(cancellation.job_id(), job_id);
    let state = context.state.clone();
    let log_state = state.clone();
    let config_dir = context.config_dir.clone();
    let jobs = Arc::clone(&context.jobs);
    dae_product_control::subscription::run_latency_job(
        job_id,
        cancellation,
        jobs,
        state,
        nodes,
        move |cancellation, nodes| {
            run_node_latency_job_inner(job_id, cancellation, &context, nodes)
        },
        move || {
            let _ = append_log_for_config(
                &config_dir,
                &log_state,
                "info",
                "node latency probe updated by Rust daed",
            );
        },
    );
    allocator_request_reclaim(AllocatorReclaimReason::ManualLatencyProbe);
}

fn run_node_latency_job_inner(
    job_id: u64,
    cancellation: &LatencyJobCancellation,
    context: &LatencyJobRuntimeContext,
    nodes: &[LatencyProbeNode],
) -> io::Result<LatencyJobRunOutcome> {
    let LatencyJobRuntimeContext {
        state,
        control_runtime,
        runtime,
        jobs,
        ..
    } = context;
    let mut conn = open_state_connection(state)?;
    let mut completed = 0usize;
    let mut succeeded = 0usize;
    jobs.flush_pending_latency_results(job_id, state);

    if cancellation.is_requested() {
        return Ok(LatencyJobRunOutcome {
            completed,
            succeeded,
            cancelled: true,
        });
    }

    if let Some(handle) = runtime.node_latency_probe_handle() {
        let generation = handle.probe_generation();
        let chunk_size = handle
            .probe_batch_size(latency_probe_unique_link_count(nodes))
            .max(1);
        for link_chunk in latency_probe_link_chunks(nodes, chunk_size) {
            if cancellation.is_requested() {
                break;
            }
            let chunk_nodes = latency_probe_nodes_for_links(nodes, &link_chunk);
            let chunk_nodes = current_latency_probe_nodes(&conn, &chunk_nodes)?;
            if chunk_nodes.is_empty() {
                continue;
            }
            let link_chunk = latency_probe_unique_links(&chunk_nodes);
            let node_index = RuntimeNodeLatencyIndex::new(&chunk_nodes);
            let mut seen_links = LatencyProbeSeenLinks::default();
            let probe_cancelled = handle.probe_node_latencies_streaming_without_group_update(
                control_runtime,
                &link_chunk,
                || cancellation.is_requested(),
                |runtime_snapshots| {
                    if cancellation.is_requested() {
                        return;
                    }
                    if let Some(generation) = generation
                        && runtime.current_probe_generation() != Some(generation)
                    {
                        return;
                    }
                    seen_links.record_snapshots(runtime_snapshots);
                    let results = node_index.results_for_snapshots(runtime_snapshots).0;
                    if results.is_empty() {
                        return;
                    }
                    let (result_count, alive) = apply_and_persist_runtime_latency_results(
                        jobs,
                        job_id,
                        cancellation,
                        state,
                        runtime_snapshots,
                        &results,
                        |snapshots| handle.apply_latency_probe_snapshots_to_groups(snapshots),
                    );
                    completed = completed.saturating_add(result_count);
                    succeeded = succeeded.saturating_add(alive);
                    jobs.mark_progress(
                        job_id,
                        completed,
                        succeeded,
                        completed.saturating_sub(succeeded),
                    );
                },
            );
            if probe_cancelled || cancellation.is_requested() {
                break;
            }
            if let Some(generation) = generation
                && runtime.current_probe_generation() != Some(generation)
            {
                if cancellation.is_requested() {
                    break;
                }
                let failures = latency_probe_failure_snapshots_for_unseen_links(
                    &link_chunk,
                    generation,
                    "manual latency probe result discarded",
                    "resident runtime generation changed while latency probe was running",
                    &seen_links,
                );
                if failures.is_empty() {
                    continue;
                }
                let results = node_latency_results_for_runtime_snapshots(
                    &chunk_nodes,
                    &node_index,
                    &failures,
                );
                if !results.is_empty() && !cancellation.is_requested() {
                    let alive = results.iter().filter(|result| result.alive).count();
                    completed = completed.saturating_add(results.len());
                    succeeded = succeeded.saturating_add(alive);
                    jobs.queue_and_flush_latency_results(job_id, state, &results);
                    jobs.mark_progress(
                        job_id,
                        completed,
                        succeeded,
                        completed.saturating_sub(succeeded),
                    );
                }
            }
        }
    } else if !nodes.is_empty() && !cancellation.is_requested() {
        let lifecycle_epoch = runtime.latency_probe_lifecycle_epoch();
        let config_snapshot = ManualProbeConfigSnapshot::capture(state)?;
        let outcome = StandaloneManualProbeJob {
            job_id,
            cancellation,
            state,
            runtime,
            jobs,
            conn: &mut conn,
            lifecycle_epoch,
            config_snapshot: &config_snapshot,
        }
        .run(nodes)?;
        completed = outcome.completed;
        succeeded = outcome.succeeded;
    }

    jobs.flush_pending_latency_results(job_id, state);
    let cancelled = cancellation.is_requested();
    Ok(LatencyJobRunOutcome {
        completed,
        succeeded,
        cancelled,
    })
}

fn apply_and_persist_runtime_latency_results(
    jobs: &LatencyJobManager,
    job_id: u64,
    cancellation: &LatencyJobCancellation,
    state: &Path,
    runtime_snapshots: &[Value],
    results: &[NodeLatencyWrite],
    apply_selector: impl FnOnce(&[Value]),
) -> (usize, usize) {
    if results.is_empty() || cancellation.is_requested() {
        return (0, 0);
    }
    apply_selector(runtime_snapshots);
    let alive = results.iter().filter(|result| result.alive).count();
    jobs.queue_and_flush_latency_results(job_id, state, results);
    (results.len(), alive)
}

#[cfg(test)]
pub(crate) fn node_latency_results_for_runtime_snapshots_only(
    nodes: &[LatencyProbeNode],
    runtime_snapshots: &[Value],
) -> Vec<NodeLatencyWrite> {
    runtime_node_latency_results_for_nodes(nodes, runtime_snapshots).0
}

pub(crate) fn current_node_latency_job_value(jobs: &LatencyJobManager) -> Value {
    json!({"job": jobs.current_value()})
}

pub(crate) fn add_node_latency_job_value(value: &mut Value, jobs: &LatencyJobManager) {
    value["job"] = jobs.current_value();
}

#[cfg(test)]
#[path = "jobs_tests.rs"]
mod tests;
