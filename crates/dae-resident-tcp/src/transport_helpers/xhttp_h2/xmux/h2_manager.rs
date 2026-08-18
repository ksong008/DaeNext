use super::super::*;
use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

pub struct XhttpH2GenerationManagers {
    managers: Mutex<HashMap<XhttpXmuxKey, XhttpXmuxManagerHandle<XhttpXmuxH2Manager>>>,
}

impl XhttpH2GenerationManagers {
    pub fn new() -> Self {
        Self {
            managers: Mutex::new(HashMap::new()),
        }
    }

    pub fn metrics_snapshot(&self) -> Value {
        let Ok(managers) = self.managers.lock() else {
            return json!({
                "managers": Value::Null,
                "clients": Value::Null,
                "reusableClients": Value::Null,
                "retiringClients": Value::Null,
                "opening": Value::Null,
                "leases": Value::Null,
                "lockedManagers": 1,
            });
        };
        let mut clients = 0_usize;
        let mut reusable_clients = 0_usize;
        let mut retiring_clients = 0_usize;
        let mut opening = 0_usize;
        let mut leases = 0_usize;
        let mut locked_managers = 0_usize;
        for manager in managers.values() {
            opening = opening.saturating_add(manager.lifecycle.opening());
            match manager.manager.try_lock() {
                Ok(state) => {
                    clients = clients.saturating_add(state.clients.len());
                    for client in &state.clients {
                        if state.client_reusable(client) {
                            reusable_clients = reusable_clients.saturating_add(1);
                        } else {
                            retiring_clients = retiring_clients.saturating_add(1);
                        }
                    }
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
            "reusableClients": reusable_clients,
            "retiringClients": retiring_clients,
            "opening": opening,
            "leases": leases,
            "lockedManagers": locked_managers,
        })
    }
}

struct XhttpXmuxH2ClientEntry {
    pub sender: h2::client::SendRequest<Bytes>,
    connection_task: tokio::task::JoinHandle<()>,
    pub usage: Arc<XhttpXmuxUsage>,
    left_usage: i32,
}

struct PendingXhttpH2Sender(Option<XhttpH2EndpointSender>);

struct XhttpXmuxH2Manager {
    config: ResidentXhttpXmuxPlan,
    concurrency: i32,
    connection_capacity: XhttpXmuxConnectionCapacity,
    clients: Vec<XhttpXmuxH2ClientEntry>,
    lifecycle: Arc<XhttpXmuxManagerLifecycle>,
}

enum XhttpXmuxH2SelectAction {
    Selected(XhttpXmuxH2SelectedClient),
    OpenNew(XhttpXmuxOpeningLease),
    WaitForState(XhttpXmuxStateWait),
    Closed,
}

impl XhttpXmuxH2Manager {
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

    fn select_or_reserve_new(&mut self) -> XhttpXmuxH2SelectAction {
        if self.lifecycle.is_closing() {
            return XhttpXmuxH2SelectAction::Closed;
        }
        self.prune();

        let reusable_len = self.reusable_len();
        if reusable_len == 0 {
            return self.reserve_new_or_wait(reusable_len);
        }

        if self
            .connection_capacity
            .should_fill_preferred(reusable_len, self.lifecycle.opening())
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
            return self.reserve_new_or_wait(reusable_len);
        }

        let index = candidates[fastrand::usize(..candidates.len())];
        let client = &mut self.clients[index];
        if client.left_usage > 0 {
            client.left_usage -= 1;
            if client.left_usage == 0 {
                client.usage.retire_physical();
            }
        }
        let selected = XhttpXmuxH2SelectedClient {
            sender: client.sender.clone(),
            lease: XhttpXmuxClientLease::open(Arc::clone(&client.usage)),
        };
        self.lifecycle.notify();
        XhttpXmuxH2SelectAction::Selected(selected)
    }

    fn reserve_new_or_wait(&mut self, live_len: usize) -> XhttpXmuxH2SelectAction {
        let opening = self.lifecycle.opening();
        if !self
            .connection_capacity
            .can_start_opening(live_len, opening)
        {
            return XhttpXmuxH2SelectAction::WaitForState(self.state_waiter());
        }
        self.reserve_opening()
    }

    fn reserve_opening(&self) -> XhttpXmuxH2SelectAction {
        self.lifecycle
            .reserve_opening()
            .map(XhttpXmuxH2SelectAction::OpenNew)
            .unwrap_or(XhttpXmuxH2SelectAction::Closed)
    }

    fn complete_new_client(
        &mut self,
        mut sender: XhttpH2EndpointSender,
        opening: &XhttpXmuxOpeningLease,
    ) -> Result<XhttpXmuxH2SelectedClient, String> {
        if !opening.is_current() || self.lifecycle.is_closing() {
            abort_new_h2_sender(&mut sender);
            return Err(format!(
                "resident xHTTP H2 xmux manager generation {} closed during open",
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
            accepting_requests: AtomicBool::new(true),
            unreusable_at,
            state_signal: self.lifecycle.signal(),
            release_reaper: OnceLock::new(),
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
        let mut changed = false;
        while index < self.clients.len() {
            let should_retire = {
                let client = &self.clients[index];
                client.connection_task.is_finished()
                    || !client.usage.accepting_requests.load(Ordering::Acquire)
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
                client.connection_task.abort();
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

    fn client_reusable(&self, client: &XhttpXmuxH2ClientEntry) -> bool {
        !client.connection_task.is_finished()
            && client.usage.accepting_requests.load(Ordering::Acquire)
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

    fn take_connection_tasks(&mut self) -> Vec<tokio::task::JoinHandle<()>> {
        self.lifecycle.close();
        let tasks = self
            .clients
            .drain(..)
            .map(|client| client.connection_task)
            .collect();
        self.lifecycle.notify();
        tasks
    }

    fn force_close(&mut self) -> usize {
        let tasks = self.take_connection_tasks();
        let closed = tasks.len();
        for task in tasks {
            task.abort();
        }
        closed
    }
}

fn install_h2_release_reaper(
    generation: &XhttpXmuxGenerationOwner,
    manager: &XhttpXmuxManagerHandle<XhttpXmuxH2Manager>,
    lease: &XhttpXmuxClientLease,
) {
    let runtime = generation.runtime.clone();
    let lifecycle = Arc::downgrade(&manager.lifecycle);
    let manager = Arc::downgrade(&manager.manager);
    lease.install_release_reaper(Arc::new(move || {
        let manager = Weak::clone(&manager);
        let lifecycle = Weak::clone(&lifecycle);
        if lifecycle
            .upgrade()
            .is_none_or(|lifecycle| lifecycle.is_closing())
        {
            return;
        }
        runtime.spawn(async move {
            let Some(manager) = manager.upgrade() else {
                return;
            };
            manager.lock().await.prune();
        });
    }));
}

impl Drop for XhttpXmuxH2Manager {
    fn drop(&mut self) {
        let _ = self.force_close();
    }
}

fn abort_new_h2_sender(sender: &mut XhttpH2EndpointSender) {
    if let Some(connection_task) = sender.connection_task.take() {
        connection_task.abort();
    }
}

impl PendingXhttpH2Sender {
    fn new(sender: XhttpH2EndpointSender) -> Self {
        Self(Some(sender))
    }

    fn take(&mut self) -> XhttpH2EndpointSender {
        self.0
            .take()
            .expect("pending xHTTP H2 sender must be present")
    }
}

impl Drop for PendingXhttpH2Sender {
    fn drop(&mut self) {
        if let Some(sender) = &mut self.0 {
            abort_new_h2_sender(sender);
        }
    }
}

pub async fn clear_xhttp_h2_xmux_managers(
    generation: &XhttpH2GenerationManagers,
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
        let (clients, deferred) = close_xhttp_h2_manager(&manager, deadline).await;
        report.clients = report.clients.saturating_add(clients);
        report.locked_managers = report.locked_managers.saturating_add(usize::from(deferred));
    }
    report
}

async fn close_xhttp_h2_manager(
    manager: &XhttpXmuxManagerHandle<XhttpXmuxH2Manager>,
    deadline: tokio::time::Instant,
) -> (usize, bool) {
    manager.lifecycle.close();
    let Ok(mut state) = tokio::time::timeout_at(deadline, manager.manager.lock()).await else {
        return (0, true);
    };
    let tasks = state.take_connection_tasks();
    let clients = tasks.len();
    drop(state);
    for mut task in tasks {
        task.abort();
        let _ = tokio::time::timeout_at(deadline, &mut task).await;
    }
    (clients, false)
}

pub(in super::super) async fn select_xhttp_h2_xmux_client<F, Fut>(
    key: XhttpXmuxKey,
    xmux: ResidentXhttpXmuxPlan,
    new_sender: F,
) -> Result<XhttpXmuxH2SelectedClient, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<XhttpH2EndpointSender, String>> + Send + 'static,
{
    let generation = xhttp_xmux_generation_owner(key.runtime_generation())?;
    let manager = {
        let mut managers = generation
            .h2
            .managers
            .lock()
            .map_err(|_| "resident xHTTP H2 xmux manager lock poisoned".to_owned())?;
        managers
            .entry(key)
            .or_insert_with(|| {
                XhttpXmuxManagerHandle::new(|lifecycle| XhttpXmuxH2Manager::new(xmux, lifecycle))
            })
            .clone()
    };
    let mut new_sender = Some(new_sender);
    loop {
        if manager.lifecycle.is_closing() {
            return Err(format!(
                "resident xHTTP H2 xmux manager generation {} is closing",
                manager.lifecycle.generation()
            ));
        }
        let action = {
            let mut manager = manager.manager.lock().await;
            manager.select_or_reserve_new()
        };
        match action {
            XhttpXmuxH2SelectAction::Selected(selected) => {
                if manager.lifecycle.is_closing() {
                    return Err(format!(
                        "resident xHTTP H2 xmux manager generation {} closed during selection",
                        manager.lifecycle.generation()
                    ));
                }
                return Ok(selected);
            }
            XhttpXmuxH2SelectAction::OpenNew(opening) => {
                let Some(new_sender) = new_sender.take() else {
                    return Err("resident xHTTP H2 xmux new sender was already consumed".to_owned());
                };
                let open = new_sender();
                let mut sender = execute_xhttp_xmux_owner_task(&generation, async move {
                    open.await.map(PendingXhttpH2Sender::new)
                })
                .await??;
                let mut state = manager.manager.lock().await;
                let selected = state.complete_new_client(sender.take(), &opening)?;
                drop(state);
                install_h2_release_reaper(&generation, &manager, &selected.lease);
                return Ok(selected);
            }
            XhttpXmuxH2SelectAction::WaitForState(waiter) => waiter.wait().await,
            XhttpXmuxH2SelectAction::Closed => {
                return Err(format!(
                    "resident xHTTP H2 xmux manager generation {} is closed",
                    manager.lifecycle.generation()
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
