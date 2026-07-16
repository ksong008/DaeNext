use std::future::{Future, pending};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use tokio::sync::Notify;
use tokio::time;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxyUdpBridgeTestSnapshot
{
    pub(in crate::production_runtime_owner::resident_dataplane) socket_live: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) task_live: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) execution_future_live: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) execution_future_cancelled: usize,
}

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxyUdpBridgeTestObservation
{
    stall_execution: AtomicBool,
    socket_live: AtomicUsize,
    task_live: AtomicUsize,
    execution_future_live: AtomicUsize,
    execution_future_cancelled: AtomicUsize,
    execution_started: Notify,
}

impl ResidentProxyUdpBridgeTestObservation {
    pub(in crate::production_runtime_owner::resident_dataplane) fn stalled_execution() -> Arc<Self>
    {
        Arc::new(Self {
            stall_execution: AtomicBool::new(true),
            socket_live: AtomicUsize::new(0),
            task_live: AtomicUsize::new(0),
            execution_future_live: AtomicUsize::new(0),
            execution_future_cancelled: AtomicUsize::new(0),
            execution_started: Notify::new(),
        })
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn snapshot(
        &self,
    ) -> ResidentProxyUdpBridgeTestSnapshot {
        ResidentProxyUdpBridgeTestSnapshot {
            socket_live: self.socket_live.load(Ordering::Acquire),
            task_live: self.task_live.load(Ordering::Acquire),
            execution_future_live: self.execution_future_live.load(Ordering::Acquire),
            execution_future_cancelled: self.execution_future_cancelled.load(Ordering::Acquire),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn wait_execution_started(
        &self,
        deadline: time::Instant,
    ) -> bool {
        loop {
            if self.execution_future_live.load(Ordering::Acquire) != 0 {
                return true;
            }
            if time::timeout_at(deadline, self.execution_started.notified())
                .await
                .is_err()
            {
                return false;
            }
        }
    }

    pub(super) fn socket_guard(self: &Arc<Self>) -> BridgeSocketGuard {
        self.socket_live.fetch_add(1, Ordering::AcqRel);
        BridgeSocketGuard(Arc::clone(self))
    }

    pub(super) fn task_guard(self: &Arc<Self>) -> BridgeTaskGuard {
        self.task_live.fetch_add(1, Ordering::AcqRel);
        BridgeTaskGuard(Arc::clone(self))
    }
}

pub(super) struct BridgeSocketGuard(Arc<ResidentProxyUdpBridgeTestObservation>);

impl Drop for BridgeSocketGuard {
    fn drop(&mut self) {
        let previous = self.0.socket_live.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            previous > 0,
            "proxy UDP bridge test socket counter underflow"
        );
    }
}

pub(super) struct BridgeTaskGuard(Arc<ResidentProxyUdpBridgeTestObservation>);

impl Drop for BridgeTaskGuard {
    fn drop(&mut self) {
        let previous = self.0.task_live.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "proxy UDP bridge test task counter underflow");
    }
}

struct BridgeExecutionGuard {
    observation: Arc<ResidentProxyUdpBridgeTestObservation>,
    completed: bool,
}

impl BridgeExecutionGuard {
    fn new(observation: Arc<ResidentProxyUdpBridgeTestObservation>) -> Self {
        observation
            .execution_future_live
            .fetch_add(1, Ordering::AcqRel);
        observation.execution_started.notify_waiters();
        Self {
            observation,
            completed: false,
        }
    }
}

impl Drop for BridgeExecutionGuard {
    fn drop(&mut self) {
        let previous = self
            .observation
            .execution_future_live
            .fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            previous > 0,
            "proxy UDP bridge test execution counter underflow"
        );
        if !self.completed {
            self.observation
                .execution_future_cancelled
                .fetch_add(1, Ordering::AcqRel);
        }
    }
}

pub(super) async fn observe_execution<F>(
    observation: Option<&Arc<ResidentProxyUdpBridgeTestObservation>>,
    future: F,
) -> F::Output
where
    F: Future,
{
    let Some(observation) = observation else {
        return future.await;
    };
    let mut guard = BridgeExecutionGuard::new(Arc::clone(observation));
    if observation.stall_execution.load(Ordering::Acquire) {
        pending::<()>().await;
    }
    let output = future.await;
    guard.completed = true;
    output
}
