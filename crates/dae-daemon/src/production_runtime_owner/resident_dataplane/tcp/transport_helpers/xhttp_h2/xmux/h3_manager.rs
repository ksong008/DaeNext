use super::super::*;
use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

static XHTTP_XMUX_H3_MANAGERS: OnceLock<
    Mutex<HashMap<XhttpXmuxKey, Arc<tokio::sync::Mutex<XhttpXmuxH3Manager>>>>,
> = OnceLock::new();

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
            && client
                .usage
                .unreusable_at
                .is_none_or(|deadline| Instant::now() <= deadline)
    }
}

pub(in super::super) async fn select_xhttp_h3_xmux_client<F, Fut>(
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
