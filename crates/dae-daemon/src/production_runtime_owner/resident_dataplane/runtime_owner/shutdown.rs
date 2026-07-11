use super::*;

pub(super) const RESIDENT_RUNTIME_TASK_JOIN_GRACE: Duration = Duration::from_secs(2);
const RESIDENT_RUNTIME_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Debug, Default)]
struct ResidentRuntimeShutdownTasks {
    joined: usize,
    panicked: usize,
    timed_out: usize,
    results: Vec<Value>,
    pending: Vec<ResidentRuntimeTask>,
}

pub(super) fn shutdown_resident_runtime_owner(
    owner: &mut ResidentRuntimeOwner,
    grace: Duration,
) -> Value {
    let started = Instant::now();
    let deadline = started.checked_add(grace).unwrap_or(started);
    owner.stop.store(true, Ordering::Relaxed);
    let task_count_started = owner.tasks.len();
    let mut task_shutdown =
        wait_for_runtime_tasks(std::mem::take(&mut owner.tasks), started, deadline, grace);
    owner.tasks.append(&mut task_shutdown.pending);

    let metrics = owner.metrics.snapshot();
    let active_tcp = metrics["activeTcpConnections"].as_u64().unwrap_or(0);
    let active_udp = metrics["activeUdpSessions"].as_u64().unwrap_or(0);
    let legacy_udp_active = owner.udp_sessions_active.load(Ordering::Relaxed);
    let event_writer = owner.event_writer.shutdown_until(deadline);
    let shutdown_elapsed_ns = elapsed_nanos(started);
    let shutdown_passed = task_shutdown.panicked == 0
        && task_shutdown.timed_out == 0
        && event_writer["status"].as_str() == Some("pass");

    json!({
        "name": "stop-resident-dataplane-runtime",
        "status": if shutdown_passed { "pass" } else { "fail" },
        "owner": "resident-runtime-owner",
        "reload_generation": owner.reload_generation,
        "reloadGeneration": owner.reload_generation,
        "task_count_started": task_count_started,
        "task_count_joined": task_shutdown.joined,
        "task_count_timed_out": task_shutdown.timed_out,
        "task_count_aborted": 0,
        "task_count_detached": task_shutdown.timed_out,
        "task_count_panicked": task_shutdown.panicked,
        "task_count_join_exceeded_grace": 0,
        "join_grace_ms": duration_millis(grace),
        "joined_worker_threads": task_shutdown.joined,
        "panicked_worker_threads": task_shutdown.panicked,
        "active_tcp_connections_at_shutdown": active_tcp,
        "active_udp_sessions_at_shutdown": active_udp,
        "udp_sessions_active_at_shutdown": legacy_udp_active,
        "runtime_handle_owner": "resident-runtime-owner",
        "manual_probe_runtime_available": true,
        "manual_probe_runtime_persistent": false,
        "manual_probe_runtime_stopped": true,
        "event_writer": event_writer,
        "shutdown_elapsed_ns": shutdown_elapsed_ns,
        "shutdown_elapsed_ms": shutdown_elapsed_ns / 1_000_000,
        "shutdown_deadline_ms": duration_millis(grace),
        "event_file": Value::Null,
        "event_file_status": "disabled",
        "event_log": "product-log-sink",
        "tasks": task_shutdown.results,
    })
}

fn wait_for_runtime_tasks(
    mut pending: Vec<ResidentRuntimeTask>,
    started: Instant,
    deadline: Instant,
    grace: Duration,
) -> ResidentRuntimeShutdownTasks {
    let mut shutdown = ResidentRuntimeShutdownTasks {
        results: Vec::with_capacity(pending.len()),
        ..ResidentRuntimeShutdownTasks::default()
    };

    loop {
        let mut index = 0;
        while index < pending.len() {
            let finished = pending[index]
                .handle
                .as_ref()
                .is_none_or(JoinHandle::is_finished);
            if !finished {
                index += 1;
                continue;
            }

            let mut task = pending.swap_remove(index);
            let completion = task
                .completion
                .as_ref()
                .and_then(|receiver| receiver.try_recv().ok());
            let join_started = Instant::now();
            let join_result = task.handle.take().map(JoinHandle::join).unwrap_or(Ok(()));
            let join_elapsed_ns = elapsed_nanos(join_started);
            let panicked =
                completion == Some(ResidentRuntimeTaskExit::Panicked) || join_result.is_err();
            if panicked {
                shutdown.panicked += 1;
            } else {
                shutdown.joined += 1;
            }
            let completion_wait_elapsed_ns = elapsed_nanos(started);
            shutdown.results.push(json!({
                "name": task.name,
                "kind": task.kind,
                "status": if panicked { "panicked" } else { "joined" },
                "join_elapsed_ns": join_elapsed_ns,
                "join_elapsed_ms": join_elapsed_ns / 1_000_000,
                "completion_wait_elapsed_ns": completion_wait_elapsed_ns,
                "completion_wait_elapsed_ms": completion_wait_elapsed_ns / 1_000_000,
                "join_grace_ms": duration_millis(grace),
                "join_exceeded_grace": false,
            }));
        }

        if pending.is_empty() || Instant::now() >= deadline {
            break;
        }
        thread::park_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(RESIDENT_RUNTIME_COMPLETION_POLL_INTERVAL),
        );
    }

    for task in pending.drain(..) {
        shutdown.timed_out += 1;
        let completion_wait_elapsed_ns = elapsed_nanos(started);
        shutdown.results.push(json!({
            "name": task.name,
            "kind": task.kind,
            "status": "timed_out",
            "join_elapsed_ns": Value::Null,
            "join_elapsed_ms": Value::Null,
            "completion_wait_elapsed_ns": completion_wait_elapsed_ns,
            "completion_wait_elapsed_ms": completion_wait_elapsed_ns / 1_000_000,
            "join_grace_ms": duration_millis(grace),
            "join_exceeded_grace": false,
            "aborted": false,
            "detached": true,
        }));
        shutdown.pending.push(task);
    }
    shutdown
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests;
