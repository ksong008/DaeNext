use std::fmt;
use std::sync::atomic::AtomicBool;

use super::super::*;
use super::persistence::LatencyPersistenceQueue;
use super::*;

#[derive(Debug, Default)]
pub(crate) struct LatencyJobManager {
    next_id: AtomicU64,
    current: Mutex<Option<LatencyJobRecord>>,
    pub(super) persistence: LatencyPersistenceQueue,
}

#[derive(Clone, Debug)]
pub(crate) struct LatencyJobCancellation {
    job_id: u64,
    requested: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub(crate) struct LatencyJobRecord {
    id: u64,
    status: &'static str,
    total: usize,
    completed: usize,
    succeeded: usize,
    failed: usize,
    queued_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    message: Option<String>,
    persist_pending: usize,
    cancellation: LatencyJobCancellation,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LatencyJobCancelError {
    NoCurrentJob,
    JobIdMismatch { expected: u64, current: u64 },
    ManagerUnavailable,
}

impl fmt::Display for LatencyJobCancelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCurrentJob => formatter.write_str("no manual latency probe job exists"),
            Self::JobIdMismatch { expected, current } => write!(
                formatter,
                "manual latency probe job {expected} does not match current job {current}"
            ),
            Self::ManagerUnavailable => formatter.write_str("latency job manager lock poisoned"),
        }
    }
}

impl std::error::Error for LatencyJobCancelError {}

impl LatencyJobCancellation {
    pub(crate) fn new(job_id: u64) -> Self {
        Self {
            job_id,
            requested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn job_id(&self) -> u64 {
        self.job_id
    }

    pub(crate) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    fn request(&self) {
        self.requested.store(true, Ordering::Release);
    }
}

impl LatencyJobManager {
    pub(crate) fn start_or_current(&self, total: usize) -> io::Result<(LatencyJobRecord, bool)> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("latency job manager lock poisoned"))?;
        if let Some(job) = current.as_ref()
            && job.blocks_new_job()
        {
            return Ok((job.clone(), false));
        }
        let id = self
            .next_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let job = LatencyJobRecord {
            id,
            status: "queued",
            total,
            completed: 0,
            succeeded: 0,
            failed: 0,
            queued_at: now_text(),
            started_at: None,
            finished_at: None,
            message: None,
            persist_pending: self.persistence.pending_count(),
            cancellation: LatencyJobCancellation::new(id),
        };
        *current = Some(job.clone());
        Ok((job, true))
    }

    pub(crate) fn current_value(&self) -> Value {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.clone())
            .map(|job| job.to_value())
            .unwrap_or(Value::Null)
    }

    pub(super) fn request_cancel(
        &self,
        expected_job_id: u64,
    ) -> Result<LatencyJobRecord, LatencyJobCancelError> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| LatencyJobCancelError::ManagerUnavailable)?;
        let Some(job) = current.as_mut() else {
            return Err(LatencyJobCancelError::NoCurrentJob);
        };
        if job.id != expected_job_id {
            return Err(LatencyJobCancelError::JobIdMismatch {
                expected: expected_job_id,
                current: job.id,
            });
        }
        if job.blocks_new_job() {
            job.cancellation.request();
            job.status = "cancelling";
            job.message = Some("manual latency probe cancellation requested".to_owned());
        }
        Ok(job.clone())
    }

    pub(super) fn mark_running(&self, id: u64) {
        self.update_job(id, |job| {
            if job.status != "queued" || job.cancellation.is_requested() {
                return;
            }
            job.status = "running";
            job.started_at = Some(now_text());
            job.message = Some("manual latency probe running".to_owned());
        });
    }

    pub(super) fn mark_finished(&self, id: u64, completed: usize, succeeded: usize, failed: usize) {
        let persist_pending = self.persistence.pending_count();
        self.update_job(id, |job| {
            job.status = "finished";
            job.completed = completed;
            job.succeeded = succeeded;
            job.failed = failed;
            job.finished_at = Some(now_text());
            job.persist_pending = persist_pending;
            job.message = Some(if persist_pending == 0 {
                "manual latency probe finished".to_owned()
            } else {
                format!(
                    "manual latency probe finished; {persist_pending} result(s) pending persistence"
                )
            });
        });
    }

    pub(super) fn mark_cancelled(
        &self,
        id: u64,
        completed: usize,
        succeeded: usize,
        failed: usize,
    ) {
        let persist_pending = self.persistence.pending_count();
        self.update_job(id, |job| {
            job.status = "cancelled";
            job.completed = completed.min(job.total);
            job.succeeded = succeeded.min(job.completed);
            job.failed = failed.min(job.completed.saturating_sub(job.succeeded));
            job.finished_at = Some(now_text());
            job.persist_pending = persist_pending;
            job.message = Some("manual latency probe cancelled".to_owned());
        });
    }

    pub(super) fn mark_progress(&self, id: u64, completed: usize, succeeded: usize, failed: usize) {
        self.update_job(id, |job| {
            if !job.accepts_progress() {
                return;
            }
            job.status = "running";
            job.completed = completed.min(job.total);
            job.succeeded = succeeded.min(job.completed);
            job.failed = failed.min(job.completed.saturating_sub(job.succeeded));
            job.message = Some(format!(
                "manual latency probe running ({}/{})",
                job.completed, job.total
            ));
        });
    }

    pub(super) fn mark_failed(&self, id: u64, message: String) {
        let persist_pending = self.persistence.pending_count();
        self.update_job(id, |job| {
            job.status = "failed";
            job.finished_at = Some(now_text());
            job.message = Some(message);
            job.persist_pending = persist_pending;
        });
    }

    pub(super) fn queue_and_flush_latency_results(
        &self,
        id: u64,
        state: &Path,
        results: &[NodeLatencyWrite],
    ) {
        let pending = match self.persistence.queue(results) {
            Ok(_) => self.persistence.flush(state).pending,
            Err(_) => self.persistence.pending_count(),
        };
        self.update_job(id, |job| job.persist_pending = pending);
    }

    pub(super) fn flush_pending_latency_results(&self, id: u64, state: &Path) {
        let report = self.persistence.flush(state);
        self.update_job(id, |job| {
            job.persist_pending = report.pending;
            if let Some(error) = report.error {
                job.message = Some(format!("manual latency probe persistence pending: {error}"));
            }
        });
    }

    fn update_job(&self, id: u64, update: impl FnOnce(&mut LatencyJobRecord)) {
        let Ok(mut current) = self.current.lock() else {
            return;
        };
        let Some(job) = current.as_mut().filter(|job| job.id == id) else {
            return;
        };
        update(job);
    }
}

impl LatencyJobRecord {
    fn blocks_new_job(&self) -> bool {
        matches!(self.status, "queued" | "running" | "cancelling")
    }

    fn accepts_progress(&self) -> bool {
        matches!(self.status, "queued" | "running") && !self.cancellation.is_requested()
    }

    pub(super) fn id(&self) -> u64 {
        self.id
    }

    pub(super) fn cancellation(&self) -> LatencyJobCancellation {
        self.cancellation.clone()
    }

    pub(crate) fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "status": self.status,
            "total": self.total,
            "completed": self.completed,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "queuedAt": self.queued_at,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "message": self.message,
            "persistPending": self.persist_pending,
        })
    }
}

pub(crate) fn cancel_node_latency_job_value(
    jobs: &LatencyJobManager,
    expected_job_id: u64,
) -> Result<Value, LatencyJobCancelError> {
    let job = jobs.request_cancel(expected_job_id)?;
    Ok(json!({"job": job.to_value()}))
}
