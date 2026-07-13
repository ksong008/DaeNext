use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

use super::client::open_connect_udp_h2_client;
use super::*;

pub(super) struct ConnectUdpH2Pool {
    max_connections: usize,
    sessions_per_connection: usize,
    state: Mutex<ConnectUdpH2PoolState>,
    state_changed: Arc<Notify>,
}

#[derive(Default)]
struct ConnectUdpH2PoolState {
    closing: bool,
    opening: usize,
    clients: Vec<ConnectUdpH2ClientEntry>,
}

struct ConnectUdpH2ClientEntry {
    sender: ::h2::client::SendRequest<Bytes>,
    driver_task: tokio::task::JoinHandle<()>,
    usage: Arc<ConnectUdpH2ConnectionUsage>,
}

pub(super) struct ConnectUdpH2ConnectionUsage {
    active_sessions: AtomicUsize,
}

pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2)
struct ConnectUdpH2ConnectionLease
{
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h2) sender:
        ::h2::client::SendRequest<Bytes>,
    usage: Arc<ConnectUdpH2ConnectionUsage>,
    state_changed: Arc<Notify>,
}

enum ConnectUdpH2AcquireAction {
    Selected(ConnectUdpH2ConnectionLease),
    Open,
    Wait,
}

impl Drop for ConnectUdpH2ConnectionLease {
    fn drop(&mut self) {
        self.usage.active_sessions.fetch_sub(1, Ordering::AcqRel);
        self.state_changed.notify_one();
    }
}

impl ConnectUdpH2Pool {
    pub(super) fn new(runtime: ResidentConnectUdpRuntimePlan) -> Self {
        Self {
            max_connections: runtime.h2_pool_connections.max(1),
            sessions_per_connection: runtime.sessions_per_connection.max(1),
            state: Mutex::new(ConnectUdpH2PoolState::default()),
            state_changed: Arc::new(Notify::new()),
        }
    }

    pub(super) async fn acquire(
        self: &Arc<Self>,
        proxy: &ResidentProxyPlan,
    ) -> Result<ConnectUdpH2ConnectionLease, String> {
        loop {
            let wait = self.state_changed.notified();
            let action = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "CONNECT-UDP H2 pool state lock poisoned".to_owned())?;
                if state.closing {
                    return Err("CONNECT-UDP H2 pool is closing".to_owned());
                }
                state
                    .clients
                    .retain(|client| !client.driver_task.is_finished());
                if let Some(client) = state
                    .clients
                    .iter()
                    .min_by_key(|client| client.usage.active_sessions.load(Ordering::Acquire))
                {
                    let active = client.usage.active_sessions.load(Ordering::Acquire);
                    let peer_limit = client.sender.current_max_send_streams();
                    let limit = self.sessions_per_connection.min(peer_limit);
                    if active < limit {
                        client.usage.active_sessions.fetch_add(1, Ordering::AcqRel);
                        ConnectUdpH2AcquireAction::Selected(ConnectUdpH2ConnectionLease {
                            sender: client.sender.clone(),
                            usage: Arc::clone(&client.usage),
                            state_changed: Arc::clone(&self.state_changed),
                        })
                    } else if state.clients.len().saturating_add(state.opening)
                        < self.max_connections
                    {
                        state.opening = state.opening.saturating_add(1);
                        ConnectUdpH2AcquireAction::Open
                    } else {
                        ConnectUdpH2AcquireAction::Wait
                    }
                } else if state.clients.len().saturating_add(state.opening) < self.max_connections {
                    state.opening = state.opening.saturating_add(1);
                    ConnectUdpH2AcquireAction::Open
                } else {
                    ConnectUdpH2AcquireAction::Wait
                }
            };

            match action {
                ConnectUdpH2AcquireAction::Selected(lease) => return Ok(lease),
                ConnectUdpH2AcquireAction::Open => {
                    let opened =
                        open_connect_udp_h2_client(proxy, Arc::clone(&self.state_changed)).await;
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| "CONNECT-UDP H2 pool state lock poisoned".to_owned())?;
                    state.opening = state.opening.saturating_sub(1);
                    let result = match opened {
                        Ok(opened) if !state.closing => {
                            let usage = Arc::new(ConnectUdpH2ConnectionUsage {
                                active_sessions: AtomicUsize::new(1),
                            });
                            let lease = ConnectUdpH2ConnectionLease {
                                sender: opened.sender.clone(),
                                usage: Arc::clone(&usage),
                                state_changed: Arc::clone(&self.state_changed),
                            };
                            state.clients.push(ConnectUdpH2ClientEntry {
                                sender: opened.sender,
                                driver_task: opened.driver_task,
                                usage,
                            });
                            Ok(lease)
                        }
                        Ok(opened) => {
                            opened.driver_task.abort();
                            Err("CONNECT-UDP H2 pool closed while opening a connection".to_owned())
                        }
                        Err(err) => Err(err),
                    };
                    drop(state);
                    self.state_changed.notify_waiters();
                    return result;
                }
                ConnectUdpH2AcquireAction::Wait => {
                    time::timeout(RESIDENT_CONNECT_TIMEOUT, wait)
                        .await
                        .map_err(|_| "CONNECT-UDP H2 pool capacity wait timeout".to_owned())?;
                }
            }
        }
    }

    pub(super) fn close(&self) -> Result<usize, ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        state.closing = true;
        let connections = state.clients.len();
        for client in state.clients.drain(..) {
            client.driver_task.abort();
        }
        self.state_changed.notify_waiters();
        Ok(connections)
    }
}

impl Drop for ConnectUdpH2Pool {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
