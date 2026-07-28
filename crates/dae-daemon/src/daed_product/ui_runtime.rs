use super::*;

mod registry;
use self::registry::*;
mod activity;
use self::activity::*;
mod reclaim;
use self::reclaim::ProductUiReclaim;
pub(in crate::daed_product) use self::reclaim::ProductUiReclaimWorker;

pub(super) const PRODUCT_UI_PAGE_HEADER: &str = "x-daed-page-id";
const PRODUCT_UI_SESSION_LIMIT: usize = 64;
const PRODUCT_UI_SESSION_PER_USER_LIMIT: usize = 8;
const PRODUCT_UI_SESSION_LEASE: Duration = Duration::from_secs(10);
const PRODUCT_UI_PAGE_ID_MAX_BYTES: usize = 64;

#[derive(Debug)]
pub(super) struct ProductUiRuntime {
    state: Mutex<ProductUiRegistryState>,
    session_limit: AtomicU64,
    per_user_limit: AtomicU64,
    lease: Duration,
    sessions_active: AtomicU64,
    sessions_peak: AtomicU64,
    requests_active: AtomicU64,
    headerless_requests_active: AtomicU64,
    bytes_in_flight: AtomicU64,
    drain_epoch: AtomicU64,
    reclaim_drain_epoch: AtomicU64,
    headerless_drain_epoch: AtomicU64,
    reclaim_headerless_drain_epoch: AtomicU64,
    headerless_reclaim_activity: Mutex<ProductUiHeaderlessReclaimActivity>,
    reclaim: Arc<ProductUiReclaim>,
}

impl Default for ProductUiRuntime {
    fn default() -> Self {
        Self::new(
            PRODUCT_UI_SESSION_LIMIT,
            PRODUCT_UI_SESSION_PER_USER_LIMIT,
            PRODUCT_UI_SESSION_LEASE,
        )
    }
}

impl ProductUiRuntime {
    fn new(session_limit: usize, per_user_limit: usize, lease: Duration) -> Self {
        Self {
            state: Mutex::new(ProductUiRegistryState::default()),
            session_limit: AtomicU64::new(session_limit as u64),
            per_user_limit: AtomicU64::new(per_user_limit as u64),
            lease,
            sessions_active: AtomicU64::new(0),
            sessions_peak: AtomicU64::new(0),
            requests_active: AtomicU64::new(0),
            headerless_requests_active: AtomicU64::new(0),
            bytes_in_flight: AtomicU64::new(0),
            drain_epoch: AtomicU64::new(0),
            reclaim_drain_epoch: AtomicU64::new(0),
            headerless_drain_epoch: AtomicU64::new(0),
            reclaim_headerless_drain_epoch: AtomicU64::new(0),
            headerless_reclaim_activity: Mutex::new(ProductUiHeaderlessReclaimActivity::default()),
            reclaim: Arc::new(ProductUiReclaim::default()),
        }
    }

    pub(super) fn configure(&self, session_limit: usize, per_user_limit: usize) {
        self.session_limit
            .store(session_limit as u64, Ordering::Relaxed);
        self.per_user_limit
            .store(per_user_limit as u64, Ordering::Relaxed);
    }

    pub(super) fn touch(&self, user_id: i64, request: &HttpRequest) -> io::Result<()> {
        let page_id = page_id_from_request(request)?;
        self.touch_page(user_id, page_id, Instant::now())
    }

    pub(super) fn close_hint(&self, user_id: i64, request: &HttpRequest) -> io::Result<bool> {
        let page_id = page_id_from_request(request)?;
        self.close_page(user_id, page_id, Instant::now())
    }

    pub(super) fn open_stream(
        self: &Arc<Self>,
        user_id: i64,
        request: &HttpRequest,
    ) -> io::Result<Option<ProductUiStreamLease>> {
        let Some(page_id) = optional_page_id_from_request(request)? else {
            return Ok(None);
        };
        self.touch_page(user_id, page_id, Instant::now())?;
        let key = ProductUiSessionKey::new(user_id, page_id);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("UI session state is unavailable"))?;
        let session = state
            .sessions
            .get_mut(&key)
            .ok_or_else(|| io::Error::other("UI session disappeared during stream admission"))?;
        session.active_streams = session.active_streams.saturating_add(1);
        Ok(Some(ProductUiStreamLease {
            runtime: Arc::clone(self),
            key: Some(key),
        }))
    }

    pub(super) fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    pub(super) fn register_reclaim_worker(&self) -> ProductUiReclaimWorker {
        self.reclaim.register()
    }

    pub(super) fn maintain(
        &self,
        metrics: &ProductHttpMetrics,
        worker: &mut ProductUiReclaimWorker,
    ) {
        self.sweep();
        self.request_reclaim_if_drained(metrics);
        self.request_reclaim_if_headerless_idle(metrics);
        worker.poll(self, metrics);
        if self.reclaim.take_owner_retry() {
            let drain_epoch = self.drain_epoch.load(Ordering::Acquire);
            self.reclaim_drain_epoch
                .store(drain_epoch.saturating_sub(1), Ordering::Release);
        }
    }

    fn request_reclaim_if_drained(&self, metrics: &ProductHttpMetrics) {
        let drain_epoch = self.drain_epoch.load(Ordering::Acquire);
        if drain_epoch == 0
            || self.reclaim_drain_epoch.load(Ordering::Acquire) >= drain_epoch
            || !self.owner_drained(metrics)
        {
            return;
        }
        let recorded_epoch = self.reclaim_drain_epoch.load(Ordering::Acquire);
        if recorded_epoch < drain_epoch
            && self
                .reclaim_drain_epoch
                .compare_exchange(
                    recorded_epoch,
                    drain_epoch,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            if self.owner_drained(metrics) {
                let _ = self.reclaim.request();
            } else {
                let _ = self.reclaim_drain_epoch.compare_exchange(
                    drain_epoch,
                    recorded_epoch,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
    }

    fn owner_drained(&self, metrics: &ProductHttpMetrics) -> bool {
        self.sessions_active.load(Ordering::Acquire) == 0
            && self.requests_active.load(Ordering::Acquire) == 0
            && metrics.active_connections.load(Ordering::Acquire) == 0
            && metrics.active_sse_connections.load(Ordering::Acquire) == 0
            && metrics.queue_depth.load(Ordering::Acquire) == 0
            && metrics.sse_queue_depth.load(Ordering::Acquire) == 0
    }

    pub(super) fn snapshot(&self) -> Value {
        json!({
            "sessionLimit": self.session_limit.load(Ordering::Relaxed),
            "perUserLimit": self.per_user_limit.load(Ordering::Relaxed),
            "leaseSeconds": self.lease.as_secs(),
            "sessionsActive": self.sessions_active.load(Ordering::Relaxed),
            "sessionsPeak": self.sessions_peak.load(Ordering::Relaxed),
            "requestsActive": self.requests_active.load(Ordering::Relaxed),
            "headerlessRequestsActive": self.headerless_requests_active.load(Ordering::Relaxed),
            "bytesInFlight": self.bytes_in_flight.load(Ordering::Relaxed).to_string(),
            "drainEpoch": self.drain_epoch.load(Ordering::Relaxed),
            "headerlessDrainEpoch": self.headerless_drain_epoch.load(Ordering::Relaxed),
            "reclaimHeaderlessDrainEpoch": self.reclaim_headerless_drain_epoch.load(Ordering::Relaxed),
            "reclaim": self.reclaim.snapshot(),
        })
    }
}

fn optional_page_id_from_request(request: &HttpRequest) -> io::Result<Option<&str>> {
    let Some(page_id) = request.headers.get(PRODUCT_UI_PAGE_HEADER) else {
        return Ok(None);
    };
    let page_id = page_id.trim();
    if page_id.len() < 16
        || page_id.len() > PRODUCT_UI_PAGE_ID_MAX_BYTES
        || !page_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid WebUI page identity",
        ));
    }
    Ok(Some(page_id))
}

fn page_id_from_request(request: &HttpRequest) -> io::Result<&str> {
    optional_page_id_from_request(request)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "WebUI page identity header is required",
        )
    })
}

pub(super) struct ProductUiStreamLease {
    runtime: Arc<ProductUiRuntime>,
    key: Option<ProductUiSessionKey>,
}

impl Drop for ProductUiStreamLease {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.runtime.close_stream(&key, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(page_id: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".to_owned(),
            path: "/api/ui/session".to_owned(),
            query: HashMap::new(),
            headers: HashMap::from([(PRODUCT_UI_PAGE_HEADER.to_owned(), page_id.to_owned())]),
            body: Vec::new(),
        }
    }

    fn headerless_request() -> HttpRequest {
        HttpRequest {
            method: "GET".to_owned(),
            path: "/api/runtime/overview".to_owned(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn sessions_are_bounded_globally_and_per_user() {
        let runtime = ProductUiRuntime::new(2, 1, Duration::from_secs(10));
        runtime.touch(1, &request("aaaaaaaaaaaaaaaa")).unwrap();
        assert_eq!(
            runtime
                .touch(1, &request("bbbbbbbbbbbbbbbb"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        runtime.touch(2, &request("cccccccccccccccc")).unwrap();
        assert_eq!(
            runtime
                .touch(3, &request("dddddddddddddddd"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn close_hint_waits_for_the_stream_owner() {
        let runtime = Arc::new(ProductUiRuntime::new(4, 2, Duration::from_secs(10)));
        let request = request("aaaaaaaaaaaaaaaa");
        runtime.touch(1, &request).unwrap();
        let stream = runtime.open_stream(1, &request).unwrap().unwrap();
        assert!(runtime.close_hint(1, &request).unwrap());
        assert_eq!(runtime.snapshot()["sessionsActive"], json!(1));
        drop(stream);
        assert_eq!(runtime.snapshot()["sessionsActive"], json!(0));
        assert_eq!(runtime.snapshot()["drainEpoch"], json!(1));
    }

    #[test]
    fn expired_session_is_removed_without_a_close_hint() {
        let runtime = ProductUiRuntime::new(4, 2, Duration::from_secs(1));
        let now = Instant::now();
        runtime.touch_page(1, "aaaaaaaaaaaaaaaa", now).unwrap();
        runtime.sweep_at(now + Duration::from_secs(2));
        assert_eq!(runtime.snapshot()["sessionsActive"], json!(0));
    }

    #[test]
    fn drained_workers_acknowledge_before_scoped_reclaim_completes() {
        let runtime = Arc::new(ProductUiRuntime::new(4, 2, Duration::from_secs(10)));
        let metrics = ProductHttpMetrics::default();
        let mut first = runtime.register_reclaim_worker();
        let mut second = runtime.register_reclaim_worker();
        let request = request("aaaaaaaaaaaaaaaa");
        runtime.touch(1, &request).unwrap();
        runtime.close_hint(1, &request).unwrap();

        runtime.maintain(&metrics, &mut first);
        assert_eq!(runtime.snapshot()["reclaim"]["completedTotal"], json!(0));
        runtime.maintain(&metrics, &mut second);

        let reclaim = &runtime.snapshot()["reclaim"];
        assert_eq!(reclaim["completedTotal"], json!(1));
        assert_eq!(reclaim["expectedWorkers"], json!(2));
        assert_eq!(reclaim["acknowledgedWorkers"], json!(2));
        assert_eq!(
            reclaim.pointer("/last/detail/arenaPurgeScope"),
            Some(&json!("control-plane-only"))
        );
    }

    #[test]
    fn headerless_control_requests_trigger_one_coalesced_idle_reclaim() {
        let runtime = Arc::new(ProductUiRuntime::new(4, 2, Duration::from_secs(10)));
        let metrics = ProductHttpMetrics::default();
        let mut first = runtime.register_reclaim_worker();
        let mut second = runtime.register_reclaim_worker();
        let lease = runtime.request_lease(&headerless_request()).unwrap();
        assert_eq!(runtime.snapshot()["headerlessRequestsActive"], json!(1));
        drop(lease);
        assert_eq!(runtime.snapshot()["headerlessDrainEpoch"], json!(1));
        runtime
            .headerless_reclaim_activity
            .lock()
            .unwrap()
            .idle_since = Some(Instant::now() - PRODUCT_UI_HEADERLESS_RECLAIM_QUIET);

        runtime.maintain(&metrics, &mut first);
        runtime.maintain(&metrics, &mut second);

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot["reclaimHeaderlessDrainEpoch"], json!(1));
        assert_eq!(snapshot["reclaim"]["completedTotal"], json!(1));
    }
}
