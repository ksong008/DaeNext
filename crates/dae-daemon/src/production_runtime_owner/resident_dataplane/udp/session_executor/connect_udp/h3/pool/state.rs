use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

use super::*;
use crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::actor::{
    ConnectUdpH3ActorCommand, start_connect_udp_h3_actor,
};

pub(super) struct ConnectUdpH3Pool {
    max_connections: usize,
    sessions_per_connection: usize,
    state: Mutex<ConnectUdpH3PoolState>,
    state_changed: Arc<Notify>,
}

#[derive(Default)]
struct ConnectUdpH3PoolState {
    closing: bool,
    opening: usize,
    actors: Vec<ConnectUdpH3ActorEntry>,
}

struct ConnectUdpH3ActorEntry {
    sender: tokio::sync::mpsc::Sender<ConnectUdpH3ActorCommand>,
    task: tokio::task::JoinHandle<()>,
    usage: Arc<ConnectUdpH3ActorUsage>,
}

struct ConnectUdpH3ActorUsage {
    active_sessions: AtomicUsize,
}

pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3)
struct ConnectUdpH3ActorLease
{
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3) sender:
        tokio::sync::mpsc::Sender<ConnectUdpH3ActorCommand>,
    usage: Arc<ConnectUdpH3ActorUsage>,
    state_changed: Arc<Notify>,
}

enum ConnectUdpH3AcquireAction {
    Selected(ConnectUdpH3ActorLease),
    Open,
    Wait,
}

impl Drop for ConnectUdpH3ActorLease {
    fn drop(&mut self) {
        self.usage.active_sessions.fetch_sub(1, Ordering::AcqRel);
        self.state_changed.notify_one();
    }
}

impl ConnectUdpH3Pool {
    pub(super) fn new(runtime: ResidentConnectUdpRuntimePlan) -> Self {
        Self {
            max_connections: runtime.h3_pool_connections.max(1),
            sessions_per_connection: runtime.sessions_per_connection.max(1),
            state: Mutex::new(ConnectUdpH3PoolState::default()),
            state_changed: Arc::new(Notify::new()),
        }
    }

    pub(super) async fn acquire(
        self: &Arc<Self>,
        proxy: &ResidentProxyPlan,
        runtime: ResidentConnectUdpRuntimePlan,
    ) -> Result<ConnectUdpH3ActorLease, String> {
        loop {
            let wait = self.state_changed.notified();
            let action = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "CONNECT-UDP H3 pool state lock poisoned".to_owned())?;
                if state.closing {
                    return Err("CONNECT-UDP H3 pool is closing".to_owned());
                }
                state.actors.retain(|actor| !actor.task.is_finished());
                if let Some(actor) = state
                    .actors
                    .iter()
                    .min_by_key(|actor| actor.usage.active_sessions.load(Ordering::Acquire))
                {
                    let active = actor.usage.active_sessions.load(Ordering::Acquire);
                    if active < self.sessions_per_connection {
                        actor.usage.active_sessions.fetch_add(1, Ordering::AcqRel);
                        ConnectUdpH3AcquireAction::Selected(ConnectUdpH3ActorLease {
                            sender: actor.sender.clone(),
                            usage: Arc::clone(&actor.usage),
                            state_changed: Arc::clone(&self.state_changed),
                        })
                    } else if state.actors.len().saturating_add(state.opening)
                        < self.max_connections
                    {
                        state.opening = state.opening.saturating_add(1);
                        ConnectUdpH3AcquireAction::Open
                    } else {
                        ConnectUdpH3AcquireAction::Wait
                    }
                } else if state.actors.len().saturating_add(state.opening) < self.max_connections {
                    state.opening = state.opening.saturating_add(1);
                    ConnectUdpH3AcquireAction::Open
                } else {
                    ConnectUdpH3AcquireAction::Wait
                }
            };

            match action {
                ConnectUdpH3AcquireAction::Selected(lease) => return Ok(lease),
                ConnectUdpH3AcquireAction::Open => {
                    let opened =
                        start_connect_udp_h3_actor(proxy, runtime, Arc::clone(&self.state_changed))
                            .await;
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| "CONNECT-UDP H3 pool state lock poisoned".to_owned())?;
                    state.opening = state.opening.saturating_sub(1);
                    let result = match opened {
                        Ok(opened) if !state.closing => {
                            let usage = Arc::new(ConnectUdpH3ActorUsage {
                                active_sessions: AtomicUsize::new(1),
                            });
                            let lease = ConnectUdpH3ActorLease {
                                sender: opened.sender.clone(),
                                usage: Arc::clone(&usage),
                                state_changed: Arc::clone(&self.state_changed),
                            };
                            state.actors.push(ConnectUdpH3ActorEntry {
                                sender: opened.sender,
                                task: opened.task,
                                usage,
                            });
                            Ok(lease)
                        }
                        Ok(opened) => {
                            let _ = opened.sender.try_send(ConnectUdpH3ActorCommand::Shutdown);
                            opened.task.abort();
                            Err("CONNECT-UDP H3 pool closed while opening an actor".to_owned())
                        }
                        Err(err) => Err(err),
                    };
                    drop(state);
                    self.state_changed.notify_waiters();
                    return result;
                }
                ConnectUdpH3AcquireAction::Wait => {
                    time::timeout(RESIDENT_CONNECT_TIMEOUT, wait)
                        .await
                        .map_err(|_| "CONNECT-UDP H3 pool capacity wait timeout".to_owned())?;
                }
            }
        }
    }

    pub(super) fn close(&self) -> Result<usize, ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        state.closing = true;
        let connections = state.actors.len();
        for actor in state.actors.drain(..) {
            let _ = actor.sender.try_send(ConnectUdpH3ActorCommand::Shutdown);
            actor.task.abort();
        }
        self.state_changed.notify_waiters();
        Ok(connections)
    }
}

impl Drop for ConnectUdpH3Pool {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
