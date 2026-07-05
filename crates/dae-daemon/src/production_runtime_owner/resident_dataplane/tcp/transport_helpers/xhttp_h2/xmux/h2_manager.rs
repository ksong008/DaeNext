use super::super::*;
use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

static XHTTP_XMUX_H2_MANAGERS: OnceLock<
    Mutex<HashMap<XhttpXmuxKey, Arc<tokio::sync::Mutex<XhttpXmuxH2Manager>>>>,
> = OnceLock::new();

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
    opening: usize,
    clients: Vec<XhttpXmuxH2ClientEntry>,
}

enum XhttpXmuxH2SelectAction {
    Selected(XhttpXmuxH2SelectedClient),
    OpenNew,
    WaitForOpening,
}

impl XhttpXmuxH2Manager {
    fn new(config: ResidentXhttpXmuxPlan) -> Self {
        let config = config.official_normalized();
        Self {
            concurrency: ResidentXhttpXmuxPlan::sample_range(config.max_concurrency),
            connections: ResidentXhttpXmuxPlan::sample_range(config.max_connections),
            opening: 0,
            config,
            clients: Vec::new(),
        }
    }

    fn select_or_reserve_new(&mut self) -> XhttpXmuxH2SelectAction {
        self.prune();

        let reusable_len = self.reusable_len();
        if reusable_len == 0 {
            return self.reserve_new_or_wait(reusable_len);
        }

        if self.connections > 0
            && reusable_len.saturating_add(self.opening) < self.connections as usize
        {
            self.opening = self.opening.saturating_add(1);
            return XhttpXmuxH2SelectAction::OpenNew;
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
            return self.reserve_new_or_wait(reusable_len);
        }

        let index = candidates[fastrand::usize(..candidates.len())];
        let client = &mut self.clients[index];
        if client.left_usage > 0 {
            client.left_usage -= 1;
        }
        XhttpXmuxH2SelectAction::Selected(XhttpXmuxH2SelectedClient {
            sender: client.sender.clone(),
            lease: XhttpXmuxClientLease::open(Arc::clone(&client.usage)),
        })
    }

    fn reserve_new_or_wait(&mut self, reusable_len: usize) -> XhttpXmuxH2SelectAction {
        if self.connections > 0
            && reusable_len.saturating_add(self.opening) >= self.connections as usize
        {
            return XhttpXmuxH2SelectAction::WaitForOpening;
        }
        if self.opening == 0 || self.connections > 0 {
            self.opening = self.opening.saturating_add(1);
            XhttpXmuxH2SelectAction::OpenNew
        } else {
            XhttpXmuxH2SelectAction::WaitForOpening
        }
    }

    fn complete_new_client(
        &mut self,
        sender: XhttpH2EndpointSender,
    ) -> Result<XhttpXmuxH2SelectedClient, String> {
        self.finish_opening();
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

    fn finish_opening(&mut self) {
        self.opening = self.opening.saturating_sub(1);
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
            && client
                .usage
                .unreusable_at
                .is_none_or(|deadline| Instant::now() <= deadline)
    }

    fn force_close(&mut self) -> usize {
        self.opening = 0;
        let mut closed = 0_usize;
        for client in self.clients.drain(..) {
            client.connection_task.abort();
            closed = closed.saturating_add(1);
        }
        closed
    }
}

pub(super) fn clear_xhttp_h2_xmux_managers() -> XhttpXmuxManagerClearReport {
    let Some(managers) = XHTTP_XMUX_H2_MANAGERS.get() else {
        return XhttpXmuxManagerClearReport::default();
    };
    let Ok(mut managers) = managers.lock() else {
        return XhttpXmuxManagerClearReport {
            locked_managers: 1,
            ..XhttpXmuxManagerClearReport::default()
        };
    };
    let drained = std::mem::take(&mut *managers);
    drop(managers);

    let mut report = XhttpXmuxManagerClearReport {
        managers: drained.len(),
        ..XhttpXmuxManagerClearReport::default()
    };
    for manager in drained.into_values() {
        match manager.try_lock() {
            Ok(mut manager) => {
                report.clients = report.clients.saturating_add(manager.force_close());
            }
            Err(_) => {
                report.locked_managers = report.locked_managers.saturating_add(1);
            }
        }
    }
    report
}

pub(in super::super) async fn select_xhttp_h2_xmux_client<F, Fut>(
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
    let mut new_sender = Some(new_sender);
    loop {
        let action = {
            let mut manager = manager.lock().await;
            manager.select_or_reserve_new()
        };
        match action {
            XhttpXmuxH2SelectAction::Selected(selected) => return Ok(selected),
            XhttpXmuxH2SelectAction::OpenNew => {
                let Some(new_sender) = new_sender.take() else {
                    return Err("resident xHTTP H2 xmux new sender was already consumed".to_owned());
                };
                let sender = new_sender().await;
                let mut manager = manager.lock().await;
                return match sender {
                    Ok(sender) => manager.complete_new_client(sender),
                    Err(err) => {
                        manager.finish_opening();
                        Err(err)
                    }
                };
            }
            XhttpXmuxH2SelectAction::WaitForOpening => {
                tokio::time::sleep(RESIDENT_IDLE_SLEEP).await;
            }
        }
    }
}
