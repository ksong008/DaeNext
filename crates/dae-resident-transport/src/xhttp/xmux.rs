use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, AtomicI32, Ordering},
};
#[cfg(any(test, feature = "test-support"))]
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(test)]
use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;

mod h2_manager;
use self::h2_manager::XhttpH2GenerationManagers;
pub(super) use self::h2_manager::select_xhttp_h2_xmux_client;

mod h3_manager;
use self::h3_manager::XhttpH3GenerationManagers;
pub(super) use self::h3_manager::select_xhttp_h3_xmux_client;

mod capacity;
use self::capacity::{XhttpXmuxConnectionCapacity, can_release_retiring_owner};

mod lifecycle;
use self::lifecycle::{XhttpXmuxManagerHandle, XhttpXmuxManagerLifecycle, XhttpXmuxOpeningLease};

mod state_signal;
use self::state_signal::{XhttpXmuxStateSignal, XhttpXmuxStateWait};

mod key;
pub(super) use self::key::XhttpXmuxKey;

static XHTTP_XMUX_GENERATION_OWNERS: OnceLock<Mutex<HashMap<u64, Weak<XhttpXmuxGenerationOwner>>>> =
    OnceLock::new();

struct XhttpXmuxGenerationOwner {
    runtime_generation: u64,
    closing: AtomicBool,
    runtime: tokio::runtime::Handle,
    runtime_worker_threads: usize,
    uses_shared_data_plane_executor: bool,
    shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    h2: XhttpH2GenerationManagers,
    h3: XhttpH3GenerationManagers,
}

#[derive(Clone)]
pub struct XhttpXmuxGenerationOwnerHandle {
    owner: Arc<XhttpXmuxGenerationOwner>,
}

impl XhttpXmuxGenerationOwnerHandle {
    pub fn metrics_snapshot(&self) -> Value {
        let executor = if self.owner.uses_shared_data_plane_executor {
            "process-owned-shared-multi-thread"
        } else if self.owner.runtime_worker_threads == 1 {
            "current-thread"
        } else {
            "multi-thread"
        };
        json!({
            "schemaVersion": 1,
            "owner": "generation-owned-xhttp-xmux",
            "reloadGeneration": self.owner.runtime_generation,
            "closing": self.owner.closing.load(Ordering::Acquire),
            "persistentRuntime": if self.owner.uses_shared_data_plane_executor {
                "process-owned-shared-multi-thread".to_owned()
            } else {
                format!("dedicated-{executor}")
            },
            "executor": executor,
            "sharedDataPlaneExecutor": self.owner.uses_shared_data_plane_executor,
            "runtimeWorkerThreads": self.owner.runtime_worker_threads,
            "h2": self.owner.h2.metrics_snapshot(),
            "h3": self.owner.h3.metrics_snapshot(),
        })
    }
}

#[cfg(test)]
pub fn start_xhttp_xmux_generation_owner(
    runtime_generation: u64,
    thread_stack_bytes: usize,
    runtime_worker_threads: usize,
) -> Result<(XhttpXmuxGenerationOwnerHandle, JoinHandle<()>), String> {
    let runtime_worker_threads = runtime_worker_threads.max(1);
    let runtime = if runtime_worker_threads == 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(runtime_worker_threads)
            .thread_name("resident-xhttp-xmux-runtime")
            .thread_stack_size(thread_stack_bytes)
            .enable_all()
            .build()
    }
    .map_err(|err| format!("build resident xHTTP xmux owner runtime: {err}"))?;
    let runtime_handle = runtime.handle().clone();
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let owner = Arc::new(XhttpXmuxGenerationOwner {
        runtime_generation,
        closing: AtomicBool::new(false),
        runtime: runtime_handle,
        runtime_worker_threads,
        uses_shared_data_plane_executor: false,
        shutdown: Mutex::new(Some(shutdown)),
        h2: XhttpH2GenerationManagers::new(),
        h3: XhttpH3GenerationManagers::new(),
    });
    let mut owners = XHTTP_XMUX_GENERATION_OWNERS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "resident xHTTP xmux generation owner registry lock poisoned".to_owned())?;
    owners.retain(|_, owner| owner.strong_count() > 0);
    if owners
        .get(&runtime_generation)
        .and_then(Weak::upgrade)
        .is_some_and(|owner| !owner.closing.load(Ordering::Acquire))
    {
        return Err(format!(
            "resident xHTTP xmux generation owner {runtime_generation} is already active"
        ));
    }
    owners.insert(runtime_generation, Arc::downgrade(&owner));
    drop(owners);

    let thread = match std::thread::Builder::new()
        .name("resident-xhttp-xmux-owner".to_owned())
        .stack_size(thread_stack_bytes)
        .spawn(move || {
            runtime.block_on(async {
                let _ = shutdown_rx.await;
            });
            runtime.shutdown_timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);
        }) {
        Ok(thread) => thread,
        Err(err) => {
            unregister_xhttp_xmux_generation_owner(&owner);
            return Err(format!(
                "spawn resident xHTTP xmux owner runtime thread: {err}"
            ));
        }
    };
    Ok((XhttpXmuxGenerationOwnerHandle { owner }, thread))
}

pub fn start_xhttp_xmux_generation_owner_on(
    runtime: &tokio::runtime::Handle,
    runtime_generation: u64,
    runtime_worker_threads: usize,
) -> Result<(XhttpXmuxGenerationOwnerHandle, tokio::task::JoinHandle<()>), String> {
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let owner = Arc::new(XhttpXmuxGenerationOwner {
        runtime_generation,
        closing: AtomicBool::new(false),
        runtime: runtime.clone(),
        runtime_worker_threads: runtime_worker_threads.max(1),
        uses_shared_data_plane_executor: true,
        shutdown: Mutex::new(Some(shutdown)),
        h2: XhttpH2GenerationManagers::new(),
        h3: XhttpH3GenerationManagers::new(),
    });
    let mut owners = XHTTP_XMUX_GENERATION_OWNERS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "resident xHTTP xmux generation owner registry lock poisoned".to_owned())?;
    owners.retain(|_, owner| owner.strong_count() > 0);
    if owners
        .get(&runtime_generation)
        .and_then(Weak::upgrade)
        .is_some_and(|owner| !owner.closing.load(Ordering::Acquire))
    {
        return Err(format!(
            "resident xHTTP xmux generation owner {runtime_generation} is already active"
        ));
    }
    owners.insert(runtime_generation, Arc::downgrade(&owner));
    drop(owners);
    let task = runtime.spawn(async move {
        let _ = shutdown_rx.await;
    });
    Ok((XhttpXmuxGenerationOwnerHandle { owner }, task))
}

fn xhttp_xmux_generation_owner(
    runtime_generation: u64,
) -> Result<Arc<XhttpXmuxGenerationOwner>, String> {
    let owner = XHTTP_XMUX_GENERATION_OWNERS
        .get()
        .and_then(|owners| owners.lock().ok())
        .and_then(|owners| owners.get(&runtime_generation).and_then(Weak::upgrade))
        .ok_or_else(|| {
            format!("resident xHTTP xmux generation owner {runtime_generation} is unavailable")
        })?;
    if owner.closing.load(Ordering::Acquire) {
        return Err(format!(
            "resident xHTTP xmux generation owner {runtime_generation} is closing"
        ));
    }
    Ok(owner)
}

fn unregister_xhttp_xmux_generation_owner(owner: &Arc<XhttpXmuxGenerationOwner>) {
    if let Some(owners) = XHTTP_XMUX_GENERATION_OWNERS.get()
        && let Ok(mut owners) = owners.lock()
        && owners
            .get(&owner.runtime_generation)
            .and_then(Weak::upgrade)
            .is_some_and(|registered| Arc::ptr_eq(&registered, owner))
    {
        owners.remove(&owner.runtime_generation);
    }
}

struct XhttpXmuxOwnerTask<T> {
    task: tokio::task::JoinHandle<T>,
}

impl<T> XhttpXmuxOwnerTask<T> {
    fn spawn(
        owner: &XhttpXmuxGenerationOwner,
        future: impl Future<Output = T> + Send + 'static,
    ) -> Self
    where
        T: Send + 'static,
    {
        Self {
            task: owner.runtime.spawn(future),
        }
    }
}

impl<T> Future for XhttpXmuxOwnerTask<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.task).poll(cx)
    }
}

impl<T> Drop for XhttpXmuxOwnerTask<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn execute_xhttp_xmux_owner_task<T>(
    owner: &XhttpXmuxGenerationOwner,
    future: impl Future<Output = T> + Send + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    XhttpXmuxOwnerTask::spawn(owner, future)
        .await
        .map_err(|err| format!("resident xHTTP xmux owner task failed: {err}"))
}

#[cfg(test)]
mod test_support;

pub struct XhttpXmuxUsage {
    pub open_usage: AtomicI32,
    pub left_requests: AtomicI32,
    accepting_requests: AtomicBool,
    pub unreusable_at: Option<Instant>,
    state_signal: XhttpXmuxStateSignal,
    release_reaper: OnceLock<XhttpXmuxReleaseReaper>,
}

type XhttpXmuxReleaseReaper = Arc<dyn Fn() + Send + Sync + 'static>;

pub struct XhttpXmuxClientLease {
    pub usage: Arc<XhttpXmuxUsage>,
}

#[derive(Clone)]
pub struct XhttpXmuxRequestHandle {
    pub usage: Arc<XhttpXmuxUsage>,
}

pub struct XhttpXmuxH2SelectedClient {
    pub sender: h2::client::SendRequest<Bytes>,
    pub lease: XhttpXmuxClientLease,
}

pub struct XhttpXmuxH3SelectedClient {
    pub client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub lease: XhttpXmuxClientLease,
}

impl XhttpXmuxClientLease {
    pub fn open(usage: Arc<XhttpXmuxUsage>) -> Self {
        usage.open_usage.fetch_add(1, Ordering::AcqRel);
        Self { usage }
    }

    pub fn request_handle(&self) -> XhttpXmuxRequestHandle {
        XhttpXmuxRequestHandle {
            usage: Arc::clone(&self.usage),
        }
    }

    pub fn independent_lease(&self) -> Self {
        Self::open(Arc::clone(&self.usage))
    }

    pub fn install_release_reaper(&self, reaper: XhttpXmuxReleaseReaper) {
        let _ = self.usage.release_reaper.set(reaper);
    }

    pub fn note_request(&self) -> i32 {
        let left = self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1;
        self.usage.state_signal.notify();
        if left <= 0 {
            self.usage.retire_physical();
        }
        left
    }

    pub fn retire_physical(&self) {
        self.usage.retire_physical();
    }
}

impl XhttpXmuxRequestHandle {
    pub fn use_for_packet_up_post(&self) -> bool {
        let left = self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1;
        self.usage.state_signal.notify();
        let reusable = self.usage.accepting_requests.load(Ordering::Acquire)
            && left > 0
            && self
                .usage
                .unreusable_at
                .is_none_or(|deadline| Instant::now() <= deadline);
        if !reusable {
            self.usage.retire_physical();
        }
        reusable
    }

    pub fn retire_physical(&self) {
        self.usage.retire_physical();
    }
}

impl XhttpXmuxUsage {
    fn retire_physical(&self) {
        if self.accepting_requests.swap(false, Ordering::AcqRel) {
            self.state_signal.notify();
        }
        self.reap_if_released();
    }

    fn reap_if_released(&self) {
        if self.open_usage.load(Ordering::Acquire) <= 0
            && let Some(reaper) = self.release_reaper.get()
        {
            reaper();
        }
    }

    fn reap_after_last_lease_if_retiring(&self) {
        let expired = self
            .unreusable_at
            .is_some_and(|deadline| Instant::now() > deadline);
        if !self.accepting_requests.load(Ordering::Acquire) || expired {
            self.reap_if_released();
        }
    }
}

#[cfg(test)]
pub fn xhttp_xmux_test_lease(left_requests: i32) -> (XhttpXmuxClientLease, Arc<XhttpXmuxUsage>) {
    let usage = Arc::new(XhttpXmuxUsage {
        open_usage: AtomicI32::new(0),
        left_requests: AtomicI32::new(left_requests),
        accepting_requests: AtomicBool::new(true),
        unreusable_at: None,
        state_signal: XhttpXmuxStateSignal::new(),
        release_reaper: OnceLock::new(),
    });
    (XhttpXmuxClientLease::open(Arc::clone(&usage)), usage)
}

impl Drop for XhttpXmuxClientLease {
    fn drop(&mut self) {
        let previous = self.usage.open_usage.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "xHTTP xmux lease accounting underflow");
        self.usage.state_signal.notify();
        if previous == 1 {
            self.usage.reap_after_last_lease_if_retiring();
        }
    }
}

pub fn note_xhttp_xmux_request(xmux_lease: Option<&XhttpXmuxClientLease>) {
    if let Some(lease) = xmux_lease {
        let _ = lease.note_request();
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn shutdown_xhttp_xmux_generation_owner(
    owner: &XhttpXmuxGenerationOwnerHandle,
    thread: JoinHandle<()>,
    grace: Duration,
) -> XhttpXmuxClearReport {
    let mut report = stop_xhttp_xmux_generation_owner(owner, grace);
    report.owner_thread_joined = thread.join().is_ok();
    report
}

pub fn stop_xhttp_xmux_generation_owner(
    owner: &XhttpXmuxGenerationOwnerHandle,
    grace: Duration,
) -> XhttpXmuxClearReport {
    let already_closing = owner.owner.closing.swap(true, Ordering::AcqRel);
    unregister_xhttp_xmux_generation_owner(&owner.owner);

    let report = if already_closing {
        XhttpXmuxClearReport::default()
    } else {
        let deadline = tokio::time::Instant::now() + grace;
        let (report_tx, report_rx) = std::sync::mpsc::sync_channel(1);
        let task_owner = Arc::clone(&owner.owner);
        let cleanup = owner.owner.runtime.spawn(async move {
            let report = XhttpXmuxClearReport {
                h2: h2_manager::clear_xhttp_h2_xmux_managers(&task_owner.h2, deadline).await,
                h3: h3_manager::clear_xhttp_h3_xmux_managers(&task_owner.h3, deadline).await,
                ..XhttpXmuxClearReport::default()
            };
            let _ = report_tx.send(report);
        });
        match report_rx.recv_timeout(grace) {
            Ok(report) => report,
            Err(_) => {
                cleanup.abort();
                XhttpXmuxClearReport {
                    cleanup_timed_out: true,
                    ..XhttpXmuxClearReport::default()
                }
            }
        }
    };

    if let Ok(mut shutdown) = owner.owner.shutdown.lock()
        && let Some(shutdown) = shutdown.take()
    {
        let _ = shutdown.send(());
    }
    report
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XhttpXmuxClearReport {
    pub h2: XhttpXmuxManagerClearReport,
    pub h3: XhttpXmuxManagerClearReport,
    pub cleanup_timed_out: bool,
    pub owner_thread_joined: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XhttpXmuxManagerClearReport {
    pub managers: usize,
    pub clients: usize,
    pub locked_managers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn xmux_usage(left_requests: i32, unreusable_at: Option<Instant>) -> Arc<XhttpXmuxUsage> {
        Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            accepting_requests: AtomicBool::new(true),
            unreusable_at,
            state_signal: XhttpXmuxStateSignal::new(),
            release_reaper: OnceLock::new(),
        })
    }

    #[test]
    fn xhttp_xmux_packet_up_uses_official_left_request_switch_boundary() {
        let handle = XhttpXmuxRequestHandle {
            usage: xmux_usage(2, None),
        };

        assert!(handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 1);
        assert!(!handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 0);
    }

    #[test]
    fn xhttp_xmux_packet_up_switches_when_client_is_past_reusable_deadline() {
        let handle = XhttpXmuxRequestHandle {
            usage: xmux_usage(10, Some(Instant::now() - Duration::from_secs(1))),
        };

        assert!(!handle.use_for_packet_up_post());
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 9);
    }

    #[test]
    fn xhttp_xmux_request_handle_does_not_extend_open_usage_lease() {
        let usage = xmux_usage(4, None);
        assert_eq!(usage.open_usage.load(Ordering::Acquire), 0);

        let handle = {
            let lease = XhttpXmuxClientLease::open(Arc::clone(&usage));
            assert_eq!(usage.open_usage.load(Ordering::Acquire), 1);
            let handle = lease.request_handle();
            assert!(handle.use_for_packet_up_post());
            handle
        };

        assert_eq!(usage.open_usage.load(Ordering::Acquire), 0);
        assert_eq!(handle.usage.left_requests.load(Ordering::Acquire), 3);
    }

    #[test]
    fn xhttp_xmux_independent_leases_balance_open_usage() {
        let usage = xmux_usage(4, None);
        let first = XhttpXmuxClientLease::open(Arc::clone(&usage));
        let second = first.independent_lease();

        assert_eq!(usage.open_usage.load(Ordering::Acquire), 2);
        assert!(!can_release_retiring_owner(
            usage.open_usage.load(Ordering::Acquire)
        ));
        drop(first);
        assert_eq!(usage.open_usage.load(Ordering::Acquire), 1);
        assert!(!can_release_retiring_owner(
            usage.open_usage.load(Ordering::Acquire)
        ));
        drop(second);
        assert_eq!(usage.open_usage.load(Ordering::Acquire), 0);
        assert!(can_release_retiring_owner(
            usage.open_usage.load(Ordering::Acquire)
        ));
    }

    #[test]
    fn xhttp_xmux_retired_physical_is_not_reused_for_packet_up() {
        let usage = xmux_usage(4, None);
        let lease = XhttpXmuxClientLease::open(Arc::clone(&usage));
        let request = lease.request_handle();

        lease.retire_physical();

        assert!(!usage.accepting_requests.load(Ordering::Acquire));
        assert!(!request.use_for_packet_up_post());
        assert_eq!(usage.left_requests.load(Ordering::Acquire), 3);
    }

    #[test]
    fn xhttp_xmux_retired_physical_reaps_after_its_last_lease() {
        let usage = xmux_usage(1, None);
        let lease = XhttpXmuxClientLease::open(Arc::clone(&usage));
        let request = lease.request_handle();
        let reaped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reaped_by_callback = Arc::clone(&reaped);
        lease.install_release_reaper(Arc::new(move || {
            reaped_by_callback.fetch_add(1, Ordering::AcqRel);
        }));

        assert!(!request.use_for_packet_up_post());
        assert_eq!(reaped.load(Ordering::Acquire), 0);
        drop(lease);
        assert_eq!(reaped.load(Ordering::Acquire), 1);
    }

    #[test]
    fn xhttp_xmux_runtime_follows_the_normalized_worker_count() {
        let current_generation = fastrand::u64(..);
        let (current, current_thread) =
            start_xhttp_xmux_generation_owner(current_generation, 1024 * 1024, 1).unwrap();
        let current_metrics = current.metrics_snapshot();
        assert_eq!(current_metrics["executor"], "current-thread");
        assert_eq!(current_metrics["runtimeWorkerThreads"], 1);
        assert_eq!(
            current_metrics["persistentRuntime"],
            "dedicated-current-thread"
        );
        assert!(
            shutdown_xhttp_xmux_generation_owner(&current, current_thread, Duration::from_secs(1),)
                .owner_thread_joined
        );

        let multi_generation = current_generation.wrapping_add(1);
        let (multi, multi_thread) =
            start_xhttp_xmux_generation_owner(multi_generation, 1024 * 1024, 2).unwrap();
        let multi_metrics = multi.metrics_snapshot();
        assert_eq!(multi_metrics["executor"], "multi-thread");
        assert_eq!(multi_metrics["runtimeWorkerThreads"], 2);
        assert_eq!(multi_metrics["persistentRuntime"], "dedicated-multi-thread");
        assert!(
            shutdown_xhttp_xmux_generation_owner(&multi, multi_thread, Duration::from_secs(1),)
                .owner_thread_joined
        );
    }
}
