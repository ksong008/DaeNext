use serde_json::{Value, json};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{ResidentAsyncRuntimeTask, ResidentRuntimeTask, ResidentRuntimeTaskExit};

const RESIDENT_RUNTIME_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Debug, Default)]
pub struct ResidentRuntimeThreadShutdown {
    pub joined: usize,
    pub panicked: usize,
    pub timed_out: usize,
    pub results: Vec<Value>,
    pub pending: Vec<ResidentRuntimeTask>,
}

pub fn take_resident_async_runtime_tasks(
    tasks: &mut Vec<ResidentAsyncRuntimeTask>,
    role: crate::ResidentRuntimeTaskRole,
) -> Vec<ResidentAsyncRuntimeTask> {
    let mut selected = Vec::new();
    let mut remaining = Vec::new();
    for task in std::mem::take(tasks) {
        if task.role == role {
            selected.push(task);
        } else {
            remaining.push(task);
        }
    }
    *tasks = remaining;
    selected
}

pub fn wait_for_resident_runtime_tasks(
    mut pending: Vec<ResidentRuntimeTask>,
    started: Instant,
    deadline: Instant,
    grace: Duration,
) -> ResidentRuntimeThreadShutdown {
    let mut shutdown = ResidentRuntimeThreadShutdown {
        results: Vec::with_capacity(pending.len()),
        ..ResidentRuntimeThreadShutdown::default()
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
                "role": "workload",
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
            "role": "workload",
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

pub fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
