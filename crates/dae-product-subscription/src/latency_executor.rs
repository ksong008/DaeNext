use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::{LatencyJobCancellation, LatencyJobManager, LatencyProbeNode};

#[derive(Clone, Copy, Debug)]
pub struct LatencyJobRunOutcome {
    pub completed: usize,
    pub succeeded: usize,
    pub cancelled: bool,
}

impl LatencyJobRunOutcome {
    pub fn failed(self) -> usize {
        self.completed.saturating_sub(self.succeeded)
    }
}

pub fn run_latency_job<F, L>(
    job_id: u64,
    cancellation: LatencyJobCancellation,
    jobs: Arc<LatencyJobManager>,
    state: impl AsRef<Path>,
    nodes: Vec<LatencyProbeNode>,
    execute: F,
    on_success: L,
) where
    F: FnOnce(&LatencyJobCancellation, &[LatencyProbeNode]) -> io::Result<LatencyJobRunOutcome>,
    L: FnOnce(),
{
    debug_assert_eq!(cancellation.job_id(), job_id);
    jobs.mark_running(job_id);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute(&cancellation, &nodes)
    }));
    if matches!(result, Ok(Ok(_))) {
        jobs.flush_pending_latency_results(job_id, state.as_ref());
    }
    match result {
        Ok(Ok(outcome)) if outcome.cancelled || cancellation.is_requested() => {
            jobs.mark_cancelled(
                job_id,
                outcome.completed,
                outcome.succeeded,
                outcome.failed(),
            );
        }
        Ok(Ok(outcome)) => {
            jobs.mark_finished(
                job_id,
                outcome.completed,
                outcome.succeeded,
                outcome.failed(),
            );
            on_success();
        }
        Ok(Err(error)) => jobs.mark_failed(job_id, error.to_string()),
        Err(payload) => jobs.mark_failed(
            job_id,
            format!(
                "manual latency probe panicked: {}",
                panic_payload_message(payload.as_ref()),
            ),
        ),
    }
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic payload".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_payload_message_preserves_string_payloads() {
        let literal = "latency panic literal";
        let owned = "latency panic string".to_owned();

        assert_eq!(panic_payload_message(&literal), literal);
        assert_eq!(panic_payload_message(&owned), owned);
    }
}
