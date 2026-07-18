use super::super::*;
use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(super) struct XhttpH3GenerationManagers {
    managers: Mutex<HashMap<XhttpXmuxKey, XhttpXmuxManagerHandle<XhttpXmuxH3Manager>>>,
}

impl XhttpH3GenerationManagers {
    pub(super) fn new() -> Self {
        Self {
            managers: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn metrics_snapshot(&self) -> Value {
        let Ok(managers) = self.managers.lock() else {
            return json!({
                "managers": Value::Null,
                "clients": Value::Null,
                "opening": Value::Null,
                "leases": Value::Null,
                "lockedManagers": 1,
            });
        };
        let mut clients = 0_usize;
        let mut opening = 0_usize;
        let mut leases = 0_usize;
        let mut locked_managers = 0_usize;
        for manager in managers.values() {
            opening = opening.saturating_add(manager.lifecycle.opening());
            match manager.manager.try_lock() {
                Ok(state) => {
                    clients = clients.saturating_add(state.clients.len());
                    leases = state.clients.iter().fold(leases, |leases, client| {
                        leases.saturating_add(
                            client
                                .usage
                                .open_usage
                                .load(std::sync::atomic::Ordering::Acquire)
                                .max(0) as usize,
                        )
                    });
                }
                Err(_) => locked_managers = locked_managers.saturating_add(1),
            }
        }
        json!({
            "managers": managers.len(),
            "clients": clients,
            "opening": opening,
            "leases": leases,
            "lockedManagers": locked_managers,
        })
    }
}

struct XhttpXmuxH3ClientEntry {
    pub(super) client: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: XhttpH3Connection,
    pub(super) usage: Arc<XhttpXmuxUsage>,
    left_usage: i32,
}

struct PendingXhttpH3Client(Option<XhttpH3EndpointClient>);

struct XhttpXmuxH3Manager {
    config: ResidentXhttpXmuxPlan,
    concurrency: i32,
    connection_capacity: XhttpXmuxConnectionCapacity,
    clients: Vec<XhttpXmuxH3ClientEntry>,
    lifecycle: Arc<XhttpXmuxManagerLifecycle>,
}

enum XhttpXmuxH3SelectAction {
    Selected(XhttpXmuxH3SelectedClient),
    OpenNew(XhttpXmuxOpeningLease),
    WaitForState(XhttpXmuxStateWait),
    Closed,
}

impl XhttpXmuxH3Manager {
    fn new(config: ResidentXhttpXmuxPlan, lifecycle: Arc<XhttpXmuxManagerLifecycle>) -> Self {
        let config = config.official_normalized();
        Self {
            concurrency: ResidentXhttpXmuxPlan::sample_range(config.max_concurrency),
            connection_capacity: XhttpXmuxConnectionCapacity::from_plan(&config),
            config,
            clients: Vec::new(),
            lifecycle,
        }
    }

    fn select_or_reserve_new(&mut self) -> XhttpXmuxH3SelectAction {
        if self.lifecycle.is_closing() {
            return XhttpXmuxH3SelectAction::Closed;
        }
        self.prune();

        let live_len = self.clients.len();
        let reusable_len = self.reusable_len();
        if reusable_len == 0 {
            return self.reserve_new_or_wait(live_len);
        }

        if self
            .connection_capacity
            .should_fill_preferred(live_len, self.lifecycle.opening())
        {
            return self.reserve_opening();
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
            return self.reserve_new_or_wait(live_len);
        }

        let index = candidates[fastrand::usize(..candidates.len())];
        let client = &mut self.clients[index];
        if client.left_usage > 0 {
            client.left_usage -= 1;
        }
        let selected = XhttpXmuxH3SelectedClient {
            client: client.client.clone(),
            lease: XhttpXmuxClientLease::open(Arc::clone(&client.usage)),
        };
        self.lifecycle.notify();
        XhttpXmuxH3SelectAction::Selected(selected)
    }

    fn reserve_new_or_wait(&mut self, live_len: usize) -> XhttpXmuxH3SelectAction {
        let opening = self.lifecycle.opening();
        if !self
            .connection_capacity
            .can_start_opening(live_len, opening)
        {
            return XhttpXmuxH3SelectAction::WaitForState(self.state_waiter());
        }
        self.reserve_opening()
    }

    fn reserve_opening(&self) -> XhttpXmuxH3SelectAction {
        self.lifecycle
            .reserve_opening()
            .map(XhttpXmuxH3SelectAction::OpenNew)
            .unwrap_or(XhttpXmuxH3SelectAction::Closed)
    }

    fn complete_new_client(
        &mut self,
        mut client: XhttpH3EndpointClient,
        opening: &XhttpXmuxOpeningLease,
    ) -> Result<XhttpXmuxH3SelectedClient, String> {
        if !opening.is_current() || self.lifecycle.is_closing() {
            abort_new_h3_client(&mut client);
            return Err(format!(
                "resident xHTTP H3 xmux manager generation {} closed during open",
                self.lifecycle.generation()
            ));
        }
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
            state_signal: self.lifecycle.signal(),
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
        let mut changed = false;
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
            if should_retire
                && can_release_retiring_owner(
                    self.clients[index].usage.open_usage.load(Ordering::Acquire),
                )
            {
                let client = self.clients.swap_remove(index);
                changed = true;
                client
                    .connection
                    .abort_with_reason(b"resident xhttp h3 xmux retire");
            } else {
                index += 1;
            }
        }
        if changed {
            self.lifecycle.notify();
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

    fn state_waiter(&self) -> XhttpXmuxStateWait {
        let deadline = self
            .clients
            .iter()
            .filter_map(|client| client.usage.unreusable_at)
            .min();
        self.lifecycle.waiter(deadline)
    }

    fn take_connections(&mut self) -> Vec<XhttpH3Connection> {
        self.lifecycle.close();
        let connections = self
            .clients
            .drain(..)
            .map(|client| client.connection)
            .collect();
        self.lifecycle.notify();
        connections
    }

    fn force_close(&mut self) -> usize {
        let connections = self.take_connections();
        let closed = connections.len();
        for connection in connections {
            connection.abort_with_reason(b"resident xhttp h3 xmux runtime cleanup");
        }
        closed
    }
}

impl Drop for XhttpXmuxH3Manager {
    fn drop(&mut self) {
        let _ = self.force_close();
    }
}

fn abort_new_h3_client(client: &mut XhttpH3EndpointClient) {
    if let Some(connection) = client.connection.take() {
        connection.abort_with_reason(b"resident xhttp h3 xmux generation closed");
    }
}

impl PendingXhttpH3Client {
    fn new(client: XhttpH3EndpointClient) -> Self {
        Self(Some(client))
    }

    fn take(&mut self) -> XhttpH3EndpointClient {
        self.0
            .take()
            .expect("pending xHTTP H3 client must be present")
    }
}

impl Drop for PendingXhttpH3Client {
    fn drop(&mut self) {
        if let Some(client) = &mut self.0 {
            abort_new_h3_client(client);
        }
    }
}

pub(super) async fn clear_xhttp_h3_xmux_managers(
    generation: &XhttpH3GenerationManagers,
    deadline: tokio::time::Instant,
) -> XhttpXmuxManagerClearReport {
    let drained = match generation.managers.lock() {
        Ok(mut managers) => managers
            .drain()
            .map(|(_, manager)| manager)
            .collect::<Vec<_>>(),
        Err(_) => {
            return XhttpXmuxManagerClearReport {
                locked_managers: 1,
                ..XhttpXmuxManagerClearReport::default()
            };
        }
    };

    let mut report = XhttpXmuxManagerClearReport {
        managers: drained.len(),
        ..XhttpXmuxManagerClearReport::default()
    };
    for manager in &drained {
        manager.lifecycle.close();
    }
    for manager in drained {
        let (clients, deferred) = close_xhttp_h3_manager(&manager, deadline).await;
        report.clients = report.clients.saturating_add(clients);
        report.locked_managers = report.locked_managers.saturating_add(usize::from(deferred));
    }
    report
}

async fn close_xhttp_h3_manager(
    manager: &XhttpXmuxManagerHandle<XhttpXmuxH3Manager>,
    deadline: tokio::time::Instant,
) -> (usize, bool) {
    manager.lifecycle.close();
    let Ok(mut state) = tokio::time::timeout_at(deadline, manager.manager.lock()).await else {
        return (0, true);
    };
    let connections = state.take_connections();
    let clients = connections.len();
    drop(state);
    for connection in connections {
        let _ = tokio::time::timeout_at(
            deadline,
            connection.close(b"resident xhttp h3 xmux runtime cleanup"),
        )
        .await;
    }
    (clients, false)
}

pub(in super::super) async fn select_xhttp_h3_xmux_client<F, Fut>(
    key: XhttpXmuxKey,
    xmux: ResidentXhttpXmuxPlan,
    new_client: F,
) -> Result<XhttpXmuxH3SelectedClient, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<XhttpH3EndpointClient, String>> + Send + 'static,
{
    let generation = xhttp_xmux_generation_owner(key.runtime_generation())?;
    let manager = {
        let mut managers = generation
            .h3
            .managers
            .lock()
            .map_err(|_| "resident xHTTP H3 xmux manager lock poisoned".to_owned())?;
        managers
            .entry(key)
            .or_insert_with(|| {
                XhttpXmuxManagerHandle::new(|lifecycle| XhttpXmuxH3Manager::new(xmux, lifecycle))
            })
            .clone()
    };
    let mut new_client = Some(new_client);
    loop {
        if manager.lifecycle.is_closing() {
            return Err(format!(
                "resident xHTTP H3 xmux manager generation {} is closing",
                manager.lifecycle.generation()
            ));
        }
        let action = {
            let mut manager = manager.manager.lock().await;
            manager.select_or_reserve_new()
        };
        match action {
            XhttpXmuxH3SelectAction::Selected(selected) => {
                if manager.lifecycle.is_closing() {
                    return Err(format!(
                        "resident xHTTP H3 xmux manager generation {} closed during selection",
                        manager.lifecycle.generation()
                    ));
                }
                return Ok(selected);
            }
            XhttpXmuxH3SelectAction::OpenNew(opening) => {
                let Some(new_client) = new_client.take() else {
                    return Err("resident xHTTP H3 xmux new client was already consumed".to_owned());
                };
                let open = new_client();
                let mut client = execute_xhttp_xmux_owner_task(&generation, async move {
                    open.await.map(PendingXhttpH3Client::new)
                })
                .await??;
                let mut state = manager.manager.lock().await;
                return state.complete_new_client(client.take(), &opening);
            }
            XhttpXmuxH3SelectAction::WaitForState(waiter) => waiter.wait().await,
            XhttpXmuxH3SelectAction::Closed => {
                return Err(format!(
                    "resident xHTTP H3 xmux manager generation {} is closed",
                    manager.lifecycle.generation()
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
