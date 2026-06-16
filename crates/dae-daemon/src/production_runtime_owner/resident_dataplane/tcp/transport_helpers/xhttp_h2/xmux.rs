use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicI32, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct XhttpXmuxKey {
    origin: String,
    server_host: String,
    server_port: u16,
    server_name: String,
    alpn: Vec<String>,
    stream_host: String,
    stream_path: String,
    mode: ResidentXhttpMode,
    allow_insecure: bool,
    tls_fragment: Option<(usize, usize, u64, u64)>,
    xmux: ResidentXhttpXmuxPlan,
    mark: u32,
    mptcp: bool,
}

pub(super) struct XhttpXmuxUsage {
    pub(super) open_usage: AtomicI32,
    pub(super) left_requests: AtomicI32,
    pub(super) unreusable_at: Option<Instant>,
}

#[derive(Clone)]
pub(crate) struct XhttpXmuxClientLease {
    pub(super) usage: Arc<XhttpXmuxUsage>,
}

#[derive(Clone)]
pub(crate) struct XhttpXmuxRequestHandle {
    pub(super) usage: Arc<XhttpXmuxUsage>,
}

struct XhttpXmuxH2ClientEntry {
    pub(super) sender: h2::client::SendRequest<Bytes>,
    connection_task: tokio::task::JoinHandle<()>,
    pub(super) usage: Arc<XhttpXmuxUsage>,
    left_usage: i32,
}

struct XhttpXmuxH2Manager {
    config: ResidentXhttpXmuxPlan,
    concurrency: i32,
    connections: i32,
    clients: Vec<XhttpXmuxH2ClientEntry>,
}

pub(super) struct XhttpXmuxH2SelectedClient {
    pub(super) sender: h2::client::SendRequest<Bytes>,
    pub(super) lease: XhttpXmuxClientLease,
}

struct XhttpXmuxH3ClientEntry {
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: XhttpH3Connection,
    pub(super) usage: Arc<XhttpXmuxUsage>,
    left_usage: i32,
}

struct XhttpXmuxH3Manager {
    config: ResidentXhttpXmuxPlan,
    concurrency: i32,
    connections: i32,
    clients: Vec<XhttpXmuxH3ClientEntry>,
}

pub(super) struct XhttpXmuxH3SelectedClient {
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(super) lease: XhttpXmuxClientLease,
}

static XHTTP_XMUX_H2_MANAGERS: OnceLock<
    Mutex<HashMap<XhttpXmuxKey, Arc<tokio::sync::Mutex<XhttpXmuxH2Manager>>>>,
> = OnceLock::new();
static XHTTP_XMUX_H3_MANAGERS: OnceLock<
    Mutex<HashMap<XhttpXmuxKey, Arc<tokio::sync::Mutex<XhttpXmuxH3Manager>>>>,
> = OnceLock::new();

impl XhttpXmuxKey {
    pub(super) fn primary(
        proxy: &ResidentProxyPlan,
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        let fingerprint = proxy
            .utls_fingerprint
            .as_ref()
            .map(|fingerprint| fingerprint.canonical.as_str())
            .unwrap_or_default();
        Self::new(
            format!(
                "primary:{}:{}:{}:{}",
                proxy.graph_link_hash,
                proxy.tls,
                fingerprint,
                proxy.reality.is_some()
            ),
            endpoint,
            xmux,
            mark,
            mptcp,
        )
    }

    pub(super) fn endpoint(
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self::new("endpoint".to_owned(), endpoint, xmux, mark, mptcp)
    }

    fn new(
        origin: String,
        endpoint: &ResidentXhttpEndpointPlan,
        xmux: &ResidentXhttpXmuxPlan,
        mark: u32,
        mptcp: bool,
    ) -> Self {
        Self {
            origin,
            server_host: endpoint.server_host.clone(),
            server_port: endpoint.server_port,
            server_name: endpoint.server_name.clone(),
            alpn: endpoint.alpn.clone(),
            stream_host: endpoint.stream_host.clone(),
            stream_path: endpoint.stream_path.clone(),
            mode: endpoint.mode,
            allow_insecure: endpoint.allow_insecure,
            tls_fragment: endpoint.tls_fragment.as_ref().map(|fragment| {
                (
                    fragment.min_length,
                    fragment.max_length,
                    fragment.min_interval_ms,
                    fragment.max_interval_ms,
                )
            }),
            xmux: xmux.clone().official_normalized(),
            mark,
            mptcp,
        }
    }
}

impl XhttpXmuxClientLease {
    pub(super) fn open(usage: Arc<XhttpXmuxUsage>) -> Self {
        usage.open_usage.fetch_add(1, Ordering::AcqRel);
        Self { usage }
    }

    pub(super) fn request_handle(&self) -> XhttpXmuxRequestHandle {
        XhttpXmuxRequestHandle {
            usage: Arc::clone(&self.usage),
        }
    }

    pub(super) fn note_request(&self) -> i32 {
        self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1
    }
}

impl XhttpXmuxRequestHandle {
    pub(super) fn use_for_packet_up_post(&self) -> bool {
        let left = self.usage.left_requests.fetch_sub(1, Ordering::AcqRel) - 1;
        left > 0
            && !self
                .usage
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline)
    }
}

impl Drop for XhttpXmuxClientLease {
    fn drop(&mut self) {
        self.usage.open_usage.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) fn note_xhttp_xmux_request(xmux_lease: Option<&XhttpXmuxClientLease>) {
    if let Some(lease) = xmux_lease {
        let _ = lease.note_request();
    }
}

impl XhttpXmuxH2Manager {
    fn new(config: ResidentXhttpXmuxPlan) -> Self {
        let config = config.official_normalized();
        Self {
            concurrency: ResidentXhttpXmuxPlan::sample_range(config.max_concurrency),
            connections: ResidentXhttpXmuxPlan::sample_range(config.max_connections),
            config,
            clients: Vec::new(),
        }
    }

    async fn select<F, Fut>(&mut self, new_sender: F) -> Result<XhttpXmuxH2SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH2EndpointSender, String>>,
    {
        self.prune();

        if self.reusable_len() == 0 {
            return self.new_client(new_sender).await;
        }

        if self.connections > 0 && self.reusable_len() < self.connections as usize {
            return self.new_client(new_sender).await;
        }

        let candidates = self
            .clients
            .iter()
            .enumerate()
            .filter_map(|(index, client)| {
                if self.client_reusable(client)
                    && (self.concurrency <= 0
                        || client.usage.open_usage.load(Ordering::Acquire) < self.concurrency)
                {
                    Some(index)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return self.new_client(new_sender).await;
        }

        let index = candidates[fastrand::usize(..candidates.len())];
        let client = &mut self.clients[index];
        if client.left_usage > 0 {
            client.left_usage -= 1;
        }
        Ok(XhttpXmuxH2SelectedClient {
            sender: client.sender.clone(),
            lease: XhttpXmuxClientLease::open(Arc::clone(&client.usage)),
        })
    }

    async fn new_client<F, Fut>(
        &mut self,
        new_sender: F,
    ) -> Result<XhttpXmuxH2SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH2EndpointSender, String>>,
    {
        let sender = new_sender().await?;
        let mut left_usage = -1;
        let sampled_left_usage = ResidentXhttpXmuxPlan::sample_range(self.config.c_max_reuse_times);
        if sampled_left_usage > 0 {
            left_usage = sampled_left_usage - 1;
        }
        let mut left_requests = i32::MAX;
        let sampled_left_requests =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_request_times);
        if sampled_left_requests > 0 {
            left_requests = sampled_left_requests;
        }
        let sampled_reusable_secs =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_reusable_secs);
        let unreusable_at = if sampled_reusable_secs > 0 {
            Some(Instant::now() + Duration::from_secs(sampled_reusable_secs as u64))
        } else {
            None
        };
        let usage = Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
        });
        self.clients.push(XhttpXmuxH2ClientEntry {
            sender: sender.sender.clone(),
            connection_task: sender
                .connection_task
                .expect("new xmux H2 clients must own their connection task"),
            usage: Arc::clone(&usage),
            left_usage,
        });
        Ok(XhttpXmuxH2SelectedClient {
            sender: sender.sender,
            lease: XhttpXmuxClientLease::open(usage),
        })
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.clients.len() {
            let should_retire = {
                let client = &self.clients[index];
                client.connection_task.is_finished()
                    || client.left_usage == 0
                    || client.usage.left_requests.load(Ordering::Acquire) <= 0
                    || client
                        .usage
                        .unreusable_at
                        .is_some_and(|deadline| now > deadline)
            };
            if should_retire {
                let client = self.clients.swap_remove(index);
                if client.usage.open_usage.load(Ordering::Acquire) <= 0 {
                    client.connection_task.abort();
                }
            } else {
                index += 1;
            }
        }
    }

    fn reusable_len(&self) -> usize {
        self.clients
            .iter()
            .filter(|client| self.client_reusable(client))
            .count()
    }

    fn client_reusable(&self, client: &XhttpXmuxH2ClientEntry) -> bool {
        !client.connection_task.is_finished()
            && client.left_usage != 0
            && client.usage.left_requests.load(Ordering::Acquire) > 0
            && !client
                .usage
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline)
    }
}

impl XhttpXmuxH3Manager {
    fn new(config: ResidentXhttpXmuxPlan) -> Self {
        let config = config.official_normalized();
        Self {
            concurrency: ResidentXhttpXmuxPlan::sample_range(config.max_concurrency),
            connections: ResidentXhttpXmuxPlan::sample_range(config.max_connections),
            config,
            clients: Vec::new(),
        }
    }

    async fn select<F, Fut>(&mut self, new_client: F) -> Result<XhttpXmuxH3SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH3EndpointClient, String>>,
    {
        self.prune();

        if self.reusable_len() == 0 {
            return self.new_client(new_client).await;
        }

        if self.connections > 0 && self.reusable_len() < self.connections as usize {
            return self.new_client(new_client).await;
        }

        let candidates = self
            .clients
            .iter()
            .enumerate()
            .filter_map(|(index, client)| {
                if self.client_reusable(client)
                    && (self.concurrency <= 0
                        || client.usage.open_usage.load(Ordering::Acquire) < self.concurrency)
                {
                    Some(index)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return self.new_client(new_client).await;
        }

        let index = candidates[fastrand::usize(..candidates.len())];
        let client = &mut self.clients[index];
        if client.left_usage > 0 {
            client.left_usage -= 1;
        }
        Ok(XhttpXmuxH3SelectedClient {
            client: client.client.clone(),
            lease: XhttpXmuxClientLease::open(Arc::clone(&client.usage)),
        })
    }

    async fn new_client<F, Fut>(
        &mut self,
        new_client: F,
    ) -> Result<XhttpXmuxH3SelectedClient, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<XhttpH3EndpointClient, String>>,
    {
        let client = new_client().await?;
        let mut left_usage = -1;
        let sampled_left_usage = ResidentXhttpXmuxPlan::sample_range(self.config.c_max_reuse_times);
        if sampled_left_usage > 0 {
            left_usage = sampled_left_usage - 1;
        }
        let mut left_requests = i32::MAX;
        let sampled_left_requests =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_request_times);
        if sampled_left_requests > 0 {
            left_requests = sampled_left_requests;
        }
        let sampled_reusable_secs =
            ResidentXhttpXmuxPlan::sample_range(self.config.h_max_reusable_secs);
        let unreusable_at = if sampled_reusable_secs > 0 {
            Some(Instant::now() + Duration::from_secs(sampled_reusable_secs as u64))
        } else {
            None
        };
        let usage = Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
        });
        self.clients.push(XhttpXmuxH3ClientEntry {
            client: client.client.clone(),
            connection: client
                .connection
                .expect("new xmux H3 clients must own their connection"),
            usage: Arc::clone(&usage),
            left_usage,
        });
        Ok(XhttpXmuxH3SelectedClient {
            client: client.client,
            lease: XhttpXmuxClientLease::open(usage),
        })
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.clients.len() {
            let should_retire = {
                let client = &self.clients[index];
                client.connection.is_finished()
                    || client.left_usage == 0
                    || client.usage.left_requests.load(Ordering::Acquire) <= 0
                    || client
                        .usage
                        .unreusable_at
                        .is_some_and(|deadline| now > deadline)
            };
            if should_retire {
                let client = self.clients.swap_remove(index);
                if client.usage.open_usage.load(Ordering::Acquire) <= 0 {
                    client
                        .connection
                        .abort_with_reason(b"resident xhttp h3 xmux retire");
                }
            } else {
                index += 1;
            }
        }
    }

    fn reusable_len(&self) -> usize {
        self.clients
            .iter()
            .filter(|client| self.client_reusable(client))
            .count()
    }

    fn client_reusable(&self, client: &XhttpXmuxH3ClientEntry) -> bool {
        !client.connection.is_finished()
            && client.left_usage != 0
            && client.usage.left_requests.load(Ordering::Acquire) > 0
            && !client
                .usage
                .unreusable_at
                .is_some_and(|deadline| Instant::now() > deadline)
    }
}

pub(super) async fn select_xhttp_h2_xmux_client<F, Fut>(
    key: XhttpXmuxKey,
    xmux: ResidentXhttpXmuxPlan,
    new_sender: F,
) -> Result<XhttpXmuxH2SelectedClient, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<XhttpH2EndpointSender, String>>,
{
    let manager =
        {
            let mut managers = XHTTP_XMUX_H2_MANAGERS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .map_err(|_| "resident xHTTP H2 xmux manager lock poisoned".to_owned())?;
            Arc::clone(managers.entry(key).or_insert_with(|| {
                Arc::new(tokio::sync::Mutex::new(XhttpXmuxH2Manager::new(xmux)))
            }))
        };
    let mut manager = manager.lock().await;
    manager.select(new_sender).await
}

pub(super) async fn select_xhttp_h3_xmux_client<F, Fut>(
    key: XhttpXmuxKey,
    xmux: ResidentXhttpXmuxPlan,
    new_client: F,
) -> Result<XhttpXmuxH3SelectedClient, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<XhttpH3EndpointClient, String>>,
{
    let manager =
        {
            let mut managers = XHTTP_XMUX_H3_MANAGERS
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .map_err(|_| "resident xHTTP H3 xmux manager lock poisoned".to_owned())?;
            Arc::clone(managers.entry(key).or_insert_with(|| {
                Arc::new(tokio::sync::Mutex::new(XhttpXmuxH3Manager::new(xmux)))
            }))
        };
    let mut manager = manager.lock().await;
    manager.select(new_client).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xmux_usage(left_requests: i32, unreusable_at: Option<Instant>) -> Arc<XhttpXmuxUsage> {
        Arc::new(XhttpXmuxUsage {
            open_usage: AtomicI32::new(0),
            left_requests: AtomicI32::new(left_requests),
            unreusable_at,
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
}
