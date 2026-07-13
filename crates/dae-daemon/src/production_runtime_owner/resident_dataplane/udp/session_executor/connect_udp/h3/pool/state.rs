use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

use super::*;
use crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::actor::{
    ConnectUdpH3ActorAdmission, ConnectUdpH3ActorCommand, start_connect_udp_h3_actor,
};

mod snapshot;

pub(super) use self::snapshot::ConnectUdpH3PoolSnapshot;

pub(super) struct ConnectUdpH3Pool {
    max_connections: usize,
    sessions_per_connection: usize,
    state: Mutex<ConnectUdpH3PoolState>,
    state_changed: Arc<Notify>,
    events: Arc<ConnectUdpPoolEvents>,
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
    admission: Arc<ConnectUdpH3ActorAdmission>,
    max_datagram_size: usize,
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
    admission: Arc<ConnectUdpH3ActorAdmission>,
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

impl ConnectUdpH3ActorLease {
    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3) fn retire(
        &self,
        reason: ConnectUdpConnectionRetirementReason,
    ) {
        self.admission.retire(reason);
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3) fn record_queue_full(
        &self,
    ) {
        self.admission.record_queue_full();
    }
}

impl ConnectUdpH3Pool {
    pub(super) fn new(runtime: ResidentConnectUdpRuntimePlan) -> Self {
        Self {
            max_connections: runtime.h3_pool_connections.max(1),
            sessions_per_connection: runtime.sessions_per_connection.max(1),
            state: Mutex::new(ConnectUdpH3PoolState::default()),
            state_changed: Arc::new(Notify::new()),
            events: Arc::new(ConnectUdpPoolEvents::default()),
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
                state.actors.retain(|actor| {
                    let retired_idle = !actor.admission.is_accepting()
                        && actor.usage.active_sessions.load(Ordering::Acquire) == 0;
                    if retired_idle {
                        let _ = actor.sender.try_send(ConnectUdpH3ActorCommand::Shutdown);
                        actor.task.abort();
                    }
                    !actor.task.is_finished() && !retired_idle
                });
                let accepting_actors = state
                    .actors
                    .iter()
                    .filter(|actor| actor.admission.is_accepting())
                    .count();
                if let Some(actor) = state
                    .actors
                    .iter()
                    .filter(|actor| actor.admission.is_accepting())
                    .min_by_key(|actor| actor.usage.active_sessions.load(Ordering::Acquire))
                {
                    let active = actor.usage.active_sessions.load(Ordering::Acquire);
                    if active < self.sessions_per_connection {
                        actor.usage.active_sessions.fetch_add(1, Ordering::AcqRel);
                        ConnectUdpH3AcquireAction::Selected(ConnectUdpH3ActorLease {
                            sender: actor.sender.clone(),
                            usage: Arc::clone(&actor.usage),
                            state_changed: Arc::clone(&self.state_changed),
                            admission: Arc::clone(&actor.admission),
                        })
                    } else if accepting_actors.saturating_add(state.opening) < self.max_connections
                    {
                        state.opening = state.opening.saturating_add(1);
                        ConnectUdpH3AcquireAction::Open
                    } else {
                        ConnectUdpH3AcquireAction::Wait
                    }
                } else if accepting_actors.saturating_add(state.opening) < self.max_connections {
                    state.opening = state.opening.saturating_add(1);
                    ConnectUdpH3AcquireAction::Open
                } else {
                    ConnectUdpH3AcquireAction::Wait
                }
            };

            match action {
                ConnectUdpH3AcquireAction::Selected(lease) => return Ok(lease),
                ConnectUdpH3AcquireAction::Open => {
                    let admission = Arc::new(ConnectUdpH3ActorAdmission::new(
                        Arc::clone(&self.events),
                        Arc::clone(&self.state_changed),
                    ));
                    let opened =
                        start_connect_udp_h3_actor(proxy, runtime, Arc::clone(&admission)).await;
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
                                admission: Arc::clone(&admission),
                            };
                            state.actors.push(ConnectUdpH3ActorEntry {
                                sender: opened.sender,
                                task: opened.task,
                                usage,
                                admission,
                                max_datagram_size: opened.max_datagram_size,
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
