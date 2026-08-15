use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use super::ResidentEventLifecycleClass;

#[derive(Debug)]
pub(super) struct ResidentEventWriterMetrics {
    queue_capacity: u64,
    queue_depth: AtomicU64,
    persisted_count: AtomicU64,
    filtered_count: AtomicU64,
    dropped_count: AtomicU64,
    dropped_startup_count: AtomicU64,
    dropped_reload_count: AtomicU64,
    dropped_error_count: AtomicU64,
    dropped_packet_count: AtomicU64,
    dropped_flow_count: AtomicU64,
    dropped_health_count: AtomicU64,
    dropped_debug_count: AtomicU64,
    prune_count: AtomicU64,
    last_write_error: Mutex<Option<String>>,
}

impl ResidentEventWriterMetrics {
    pub(super) fn new(queue_capacity: u64) -> Self {
        Self {
            queue_capacity,
            queue_depth: AtomicU64::new(0),
            persisted_count: AtomicU64::new(0),
            filtered_count: AtomicU64::new(0),
            dropped_count: AtomicU64::new(0),
            dropped_startup_count: AtomicU64::new(0),
            dropped_reload_count: AtomicU64::new(0),
            dropped_error_count: AtomicU64::new(0),
            dropped_packet_count: AtomicU64::new(0),
            dropped_flow_count: AtomicU64::new(0),
            dropped_health_count: AtomicU64::new(0),
            dropped_debug_count: AtomicU64::new(0),
            prune_count: AtomicU64::new(0),
            last_write_error: Mutex::new(None),
        }
    }

    pub(super) fn command_enqueued(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn command_dequeued(&self) {
        let _ = self
            .queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    pub(super) fn command_rejected(&self) {
        self.command_dequeued();
    }

    pub(super) fn persisted(&self) {
        self.persisted_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn filtered(&self) {
        self.filtered_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn pruned(&self) {
        self.prune_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dropped(&self, class: ResidentEventLifecycleClass) {
        self.dropped_count.fetch_add(1, Ordering::Relaxed);
        match class {
            ResidentEventLifecycleClass::Startup => {
                self.dropped_startup_count.fetch_add(1, Ordering::Relaxed);
            }
            ResidentEventLifecycleClass::Reload => {
                self.dropped_reload_count.fetch_add(1, Ordering::Relaxed);
            }
            ResidentEventLifecycleClass::Error => {
                self.dropped_error_count.fetch_add(1, Ordering::Relaxed);
            }
            ResidentEventLifecycleClass::Packet => {
                self.dropped_packet_count.fetch_add(1, Ordering::Relaxed);
            }
            ResidentEventLifecycleClass::Flow => {
                self.dropped_flow_count.fetch_add(1, Ordering::Relaxed);
            }
            ResidentEventLifecycleClass::Health => {
                self.dropped_health_count.fetch_add(1, Ordering::Relaxed);
            }
            ResidentEventLifecycleClass::Debug => {
                self.dropped_debug_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn record_error(&self, message: impl Into<String>) {
        if let Ok(mut guard) = self.last_write_error.lock() {
            *guard = Some(message.into());
        }
    }

    pub(super) fn snapshot(&self) -> Value {
        let last_write_error = self
            .last_write_error
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        json!({
            "schemaVersion": 1,
            "owner": "resident-event-writer",
            "queueCapacity": self.queue_capacity,
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
            "persistedCount": self.persisted_count.load(Ordering::Relaxed),
            "filteredCount": self.filtered_count.load(Ordering::Relaxed),
            "droppedCount": self.dropped_count.load(Ordering::Relaxed),
            "droppedByClass": {
                "startup": self.dropped_startup_count.load(Ordering::Relaxed),
                "reload": self.dropped_reload_count.load(Ordering::Relaxed),
                "error": self.dropped_error_count.load(Ordering::Relaxed),
                "packet": self.dropped_packet_count.load(Ordering::Relaxed),
                "flow": self.dropped_flow_count.load(Ordering::Relaxed),
                "health": self.dropped_health_count.load(Ordering::Relaxed),
                "debug": self.dropped_debug_count.load(Ordering::Relaxed),
            },
            "pruneCount": self.prune_count.load(Ordering::Relaxed),
            "lastWriteError": last_write_error,
        })
    }
}
