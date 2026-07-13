use super::*;
use std::sync::MutexGuard;

const BACKGROUND_STOP_CLEANUP_MODE: &str = "background-stop";

pub(in crate::daed_product) struct PreparedProductRuntimeStop<'a> {
    manager: &'a ProductRuntimeManager,
    coordinator: RuntimeStopPermit<'a>,
    _lifecycle: MutexGuard<'a, ()>,
    inner: MutexGuard<'a, ProductRuntimeState>,
    started: Instant,
}

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn prepare_stop(
        &self,
    ) -> Result<PreparedProductRuntimeStop<'_>, String> {
        let started = Instant::now();
        let coordinator = self.coordinator.begin_stop()?;
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "product runtime lifecycle lock poisoned".to_owned())?;
        let inner = self
            .inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        Ok(PreparedProductRuntimeStop {
            manager: self,
            coordinator,
            _lifecycle: lifecycle,
            inner,
            started,
        })
    }

    #[cfg(test)]
    pub(in crate::daed_product) fn stop(&self) -> Result<Value, String> {
        self.prepare_stop()
            .map(PreparedProductRuntimeStop::commit_background)
    }

    pub(in crate::daed_product) fn stop_and_wait_for_cleanup(
        &self,
        cleanup_mode: &str,
    ) -> Result<Value, String> {
        self.prepare_stop()?.commit_and_wait(cleanup_mode)
    }
}

impl<'a> PreparedProductRuntimeStop<'a> {
    pub(in crate::daed_product) fn commit_background(self) -> Value {
        let (manager_inner, stopped_runtime, was_running, cleanup_epoch, started, coordinator) =
            self.take_runtime(BACKGROUND_STOP_CLEANUP_MODE);
        if was_running {
            spawn_background_cleanup(manager_inner, cleanup_epoch, stopped_runtime);
        } else {
            drop(stopped_runtime);
        }
        let report = stop_report(
            started,
            was_running,
            cleanup_epoch,
            BACKGROUND_STOP_CLEANUP_MODE,
            None,
        );
        coordinator.finish("stopped");
        report
    }

    fn commit_and_wait(self, cleanup_mode: &str) -> Result<Value, String> {
        let (manager_inner, stopped_runtime, was_running, cleanup_epoch, started, coordinator) =
            self.take_runtime(cleanup_mode);
        let cleanup_report = if was_running {
            let cleanup_report = cleanup_runtime_instance_with_reclaim(
                stopped_runtime,
                AllocatorReclaimReason::StopRuntime,
            );
            let mut inner = manager_inner
                .lock()
                .map_err(|_| "product runtime manager lock poisoned after cleanup".to_owned())?;
            if inner.cleanup.epoch == cleanup_epoch {
                inner.cleanup.finish(cleanup_report.clone());
            }
            cleanup_report
        } else {
            drop(stopped_runtime);
            None
        };
        let report = stop_report(
            started,
            was_running,
            cleanup_epoch,
            cleanup_mode,
            cleanup_report,
        );
        coordinator.finish("stopped");
        Ok(report)
    }

    fn take_runtime(
        mut self,
        cleanup_mode: &str,
    ) -> (
        Arc<Mutex<ProductRuntimeState>>,
        Option<ProductRuntimeInstance>,
        bool,
        u64,
        Instant,
        RuntimeStopPermit<'a>,
    ) {
        self.inner.lifecycle_epoch = self.inner.lifecycle_epoch.wrapping_add(1);
        let was_running = self.inner.runtime.is_some();
        let stopped_runtime = self.inner.runtime.take();
        if was_running {
            let cleanup_epoch = self.inner.lifecycle_epoch;
            self.inner.cleanup.begin(cleanup_epoch, cleanup_mode);
        }
        self.inner.config = None;
        self.inner.config_content = None;
        self.inner.traffic_carry = RuntimeTrafficCarry::default();
        self.inner.runtime_started_at = None;
        self.inner.stop_count += 1;
        self.inner.last_transition_at = Some(now_text());
        self.inner.last_report = None;
        self.inner.last_error = None;
        self.inner.active_generation = None;
        self.inner.pending_process_transition = None;
        let cleanup_epoch = self.inner.lifecycle_epoch;
        let manager_inner = Arc::clone(&self.manager.inner);
        let started = self.started;
        let coordinator = self.coordinator;
        drop(self.inner);
        (
            manager_inner,
            stopped_runtime,
            was_running,
            cleanup_epoch,
            started,
            coordinator,
        )
    }
}

fn stop_report(
    started: Instant,
    was_running: bool,
    cleanup_epoch: u64,
    cleanup_mode: &str,
    cleanup_report: Option<Value>,
) -> Value {
    let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    json!({
        "stopped": true,
        "wasRunning": was_running,
        "runtimeControl": "resident-production-runtime-manager",
        "fakeRuntime": product_runtime_fake_start_enabled(),
        "allocatorReclaim": Value::Null,
        "stopElapsedNs": elapsed_ns,
        "stopElapsedMs": elapsed_ns / 1_000_000,
        "cleanupStarted": was_running,
        "cleanupEpoch": if was_running { json!(cleanup_epoch) } else { Value::Null },
        "cleanupMode": if was_running { json!(cleanup_mode) } else { Value::Null },
        "cleanupReport": cleanup_report,
    })
}
