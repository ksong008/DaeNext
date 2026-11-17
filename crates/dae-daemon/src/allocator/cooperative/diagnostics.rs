use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum CacheOperation {
    Flush,
    ParkReadEnabled,
    ParkDisable,
    UnparkRestore,
}

impl CacheOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Flush => "flush",
            Self::ParkReadEnabled => "parkReadEnabled",
            Self::ParkDisable => "parkDisable",
            Self::UnparkRestore => "unparkRestore",
        }
    }
}

#[derive(Default)]
pub(super) struct CacheDiagnostics {
    flush_errors: AtomicU64,
    park_read_errors: AtomicU64,
    park_disable_errors: AtomicU64,
    unpark_restore_errors: AtomicU64,
    flush_recoveries: AtomicU64,
    last_error: Mutex<Option<Value>>,
}

impl CacheDiagnostics {
    pub(super) fn record_error(
        &self,
        operation: CacheOperation,
        kind: AllocatorWorkerKind,
        epoch: u64,
        error: String,
    ) {
        let count = match operation {
            CacheOperation::Flush => &self.flush_errors,
            CacheOperation::ParkReadEnabled => &self.park_read_errors,
            CacheOperation::ParkDisable => &self.park_disable_errors,
            CacheOperation::UnparkRestore => &self.unpark_restore_errors,
        };
        count.fetch_add(1, Ordering::Relaxed);
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(json!({
            "operation": operation.as_str(),
            "class": kind.as_str(),
            "epoch": epoch,
            "error": error,
        }));
    }

    pub(super) fn record_flush_recovery(&self) {
        self.flush_recoveries.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn json(&self) -> Value {
        json!({
            // These are process lifetime attempt counters. A successful later
            // operation never erases them; flushFailures remains the number of
            // workers with an unresolved failure in the requested epoch.
            "errorsByOperation": {
                "flush": self.flush_errors.load(Ordering::Relaxed),
                "parkReadEnabled": self.park_read_errors.load(Ordering::Relaxed),
                "parkDisable": self.park_disable_errors.load(Ordering::Relaxed),
                "unparkRestore": self.unpark_restore_errors.load(Ordering::Relaxed),
            },
            "flushRecoveriesTotal": self.flush_recoveries.load(Ordering::Relaxed),
            "lastError": self.last_error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        })
    }
}
