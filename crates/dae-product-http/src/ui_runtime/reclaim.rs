use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{ProductUiReclaimHooks, ProductUiRuntime};
use crate::ProductHttpMetrics;

const PRODUCT_UI_RECLAIM_ACK_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(super) struct ProductUiReclaim {
    hooks: Arc<dyn ProductUiReclaimHooks>,
    desired_epoch: AtomicU64,
    completed_epoch: AtomicU64,
    finishing_epoch: AtomicU64,
    active_workers: AtomicU64,
    expected_workers: AtomicU64,
    acknowledged_workers: AtomicU64,
    flush_failures: AtomicU64,
    requested_total: AtomicU64,
    completed_total: AtomicU64,
    partial_total: AtomicU64,
    partial_epoch: AtomicU64,
    owner_retry: AtomicBool,
    state: Mutex<ProductUiReclaimState>,
}

#[derive(Debug, Default)]
struct ProductUiReclaimState {
    requested_at: Option<Instant>,
    last_result: Option<Value>,
}

impl ProductUiReclaim {
    pub(super) fn new(hooks: Arc<dyn ProductUiReclaimHooks>) -> Self {
        Self {
            hooks,
            desired_epoch: AtomicU64::new(0),
            completed_epoch: AtomicU64::new(0),
            finishing_epoch: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            expected_workers: AtomicU64::new(0),
            acknowledged_workers: AtomicU64::new(0),
            flush_failures: AtomicU64::new(0),
            requested_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            partial_total: AtomicU64::new(0),
            partial_epoch: AtomicU64::new(0),
            owner_retry: AtomicBool::new(false),
            state: Mutex::new(ProductUiReclaimState::default()),
        }
    }

    pub(super) fn request(&self) -> bool {
        let desired = self.desired_epoch.load(Ordering::Acquire);
        if desired != self.completed_epoch.load(Ordering::Acquire) {
            return false;
        }
        let epoch = desired.saturating_add(1);
        self.acknowledged_workers.store(0, Ordering::Relaxed);
        self.flush_failures.store(0, Ordering::Relaxed);
        self.expected_workers.store(
            self.active_workers.load(Ordering::Acquire),
            Ordering::Relaxed,
        );
        self.partial_epoch.store(0, Ordering::Relaxed);
        self.owner_retry.store(false, Ordering::Relaxed);
        if let Ok(mut state) = self.state.lock() {
            state.requested_at = Some(Instant::now());
        }
        self.requested_total.fetch_add(1, Ordering::Relaxed);
        self.desired_epoch.store(epoch, Ordering::Release);
        true
    }

    pub(super) fn register(self: &Arc<Self>) -> ProductUiReclaimWorker {
        let last_epoch = self.desired_epoch.load(Ordering::Acquire);
        let binding = self.hooks.bind_control_plane_thread();
        self.active_workers.fetch_add(1, Ordering::AcqRel);
        ProductUiReclaimWorker {
            reclaim: Arc::clone(self),
            last_epoch,
            binding,
        }
    }

    fn acknowledge(
        &self,
        runtime: &ProductUiRuntime,
        metrics: &ProductHttpMetrics,
        epoch: u64,
        flush_failed: bool,
    ) {
        if flush_failed {
            self.flush_failures.fetch_add(1, Ordering::Relaxed);
        }
        self.acknowledged_workers.fetch_add(1, Ordering::AcqRel);
        self.finish_if_ready(runtime, metrics, epoch);
    }

    pub(super) fn observe(&self, runtime: &ProductUiRuntime, metrics: &ProductHttpMetrics) {
        let epoch = self.desired_epoch.load(Ordering::Acquire);
        if epoch == self.completed_epoch.load(Ordering::Acquire) {
            return;
        }
        self.finish_if_ready(runtime, metrics, epoch);
        if epoch == self.completed_epoch.load(Ordering::Acquire)
            || self.partial_epoch.load(Ordering::Acquire) == epoch
        {
            return;
        }
        let timed_out = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.requested_at)
            .is_some_and(|requested_at| requested_at.elapsed() >= PRODUCT_UI_RECLAIM_ACK_TIMEOUT);
        if timed_out
            && self
                .partial_epoch
                .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.partial_total.fetch_add(1, Ordering::Relaxed);
            self.record_last(json!({
                "epoch": epoch,
                "status": "partial",
                "reason": "worker_ack_timeout",
                "expectedWorkers": self.expected_workers.load(Ordering::Relaxed),
                "acknowledgedWorkers": self.acknowledged_workers.load(Ordering::Relaxed),
                "flushFailures": self.flush_failures.load(Ordering::Relaxed),
            }));
        }
    }

    fn finish_if_ready(
        &self,
        runtime: &ProductUiRuntime,
        metrics: &ProductHttpMetrics,
        epoch: u64,
    ) {
        let expected = self.expected_workers.load(Ordering::Acquire);
        let acknowledged = self.acknowledged_workers.load(Ordering::Acquire);
        if acknowledged < expected {
            return;
        }
        if self
            .finishing_epoch
            .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let flush_failures = self.flush_failures.load(Ordering::Relaxed);
        let owner_drained = runtime.owner_drained(metrics);
        let (status, detail) = if owner_drained && flush_failures == 0 {
            let request = self.hooks.request_control_plane_reclaim();
            let status = if request.get("status").and_then(Value::as_str) == Some("requested") {
                "requested"
            } else {
                "fail"
            };
            (status, request)
        } else if !owner_drained {
            self.owner_retry.store(true, Ordering::Release);
            (
                "cancelled",
                json!({
                    "operation": "control_plane_arena_purge",
                    "reason": "owner_became_active",
                }),
            )
        } else {
            (
                "partial",
                json!({
                    "operation": "control_plane_arena_purge",
                    "reason": "worker_tcache_flush_failed",
                    "flushFailures": flush_failures,
                }),
            )
        };
        self.record_last(json!({
            "epoch": epoch,
            "status": status,
            "expectedWorkers": expected,
            "acknowledgedWorkers": acknowledged,
            "flushFailures": flush_failures,
            "ownerDrained": owner_drained,
            "detail": detail,
        }));
        self.completed_total.fetch_add(1, Ordering::Relaxed);
        self.completed_epoch.store(epoch, Ordering::Release);
        self.finishing_epoch.store(0, Ordering::Release);
    }

    fn record_last(&self, result: Value) {
        if let Ok(mut state) = self.state.lock() {
            state.last_result = Some(result);
        }
    }

    pub(super) fn take_owner_retry(&self) -> bool {
        self.owner_retry.swap(false, Ordering::AcqRel)
    }

    pub(super) fn snapshot(&self) -> Value {
        let last_result = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.last_result.clone());
        json!({
            "epoch": self.desired_epoch.load(Ordering::Relaxed),
            "completedEpoch": self.completed_epoch.load(Ordering::Relaxed),
            "requestedTotal": self.requested_total.load(Ordering::Relaxed),
            "completedTotal": self.completed_total.load(Ordering::Relaxed),
            "partialTotal": self.partial_total.load(Ordering::Relaxed),
            "activeWorkers": self.active_workers.load(Ordering::Relaxed),
            "expectedWorkers": self.expected_workers.load(Ordering::Relaxed),
            "acknowledgedWorkers": self.acknowledged_workers.load(Ordering::Relaxed),
            "last": last_result,
        })
    }
}

pub struct ProductUiReclaimWorker {
    reclaim: Arc<ProductUiReclaim>,
    last_epoch: u64,
    binding: Result<Option<u32>, String>,
}

impl ProductUiReclaimWorker {
    pub fn poll(&mut self, runtime: &ProductUiRuntime, metrics: &ProductHttpMetrics) {
        let epoch = self.reclaim.desired_epoch.load(Ordering::Acquire);
        if epoch > self.last_epoch {
            let flush_failed =
                self.binding.is_err() || self.reclaim.hooks.flush_current_thread_cache().is_err();
            self.last_epoch = epoch;
            self.reclaim
                .acknowledge(runtime, metrics, epoch, flush_failed);
        }
        self.reclaim.observe(runtime, metrics);
    }
}

impl Drop for ProductUiReclaimWorker {
    fn drop(&mut self) {
        let desired = self.reclaim.desired_epoch.load(Ordering::Acquire);
        if desired > self.last_epoch {
            let _ = self.reclaim.expected_workers.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |expected| Some(expected.saturating_sub(1)),
            );
        }
        self.reclaim.active_workers.fetch_sub(1, Ordering::AcqRel);
    }
}
