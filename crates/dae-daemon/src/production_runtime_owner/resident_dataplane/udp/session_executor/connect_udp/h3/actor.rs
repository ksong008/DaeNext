use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::sync::{Notify, mpsc, oneshot};

use super::*;

mod connection;
mod monitor;
mod open;
mod runtime;

pub(super) async fn start_connect_udp_h3_actor(
    proxy: &ResidentProxyPlan,
    runtime: ResidentConnectUdpRuntimePlan,
    admission: Arc<ConnectUdpH3ActorAdmission>,
) -> Result<ConnectUdpH3ActorClient, String> {
    connection::start_connect_udp_h3_actor(proxy, runtime, admission).await
}

pub(super) struct ConnectUdpH3ActorAdmission {
    accepting: AtomicBool,
    events: Arc<ConnectUdpPoolEvents>,
    state_changed: Arc<Notify>,
}

impl ConnectUdpH3ActorAdmission {
    pub(super) fn new(events: Arc<ConnectUdpPoolEvents>, state_changed: Arc<Notify>) -> Self {
        Self {
            accepting: AtomicBool::new(true),
            events,
            state_changed,
        }
    }

    pub(super) fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    pub(super) fn retire(&self, reason: ConnectUdpConnectionRetirementReason) {
        if self.accepting.swap(false, Ordering::AcqRel) {
            self.events.record_retirement(reason);
            self.state_changed.notify_waiters();
        }
    }

    pub(super) fn record_reset(&self) {
        self.events.record_reset();
    }

    pub(super) fn record_queue_full(&self) {
        self.events.record_queue_full();
    }

    pub(super) fn record_mtu_rejection(&self) {
        self.events.record_mtu_rejection();
    }
}

pub(super) struct ConnectUdpH3OpenFailure {
    message: String,
    retirement_reason: Option<ConnectUdpConnectionRetirementReason>,
}

impl ConnectUdpH3OpenFailure {
    pub(super) fn retryable_connection(
        message: impl Into<String>,
        reason: ConnectUdpConnectionRetirementReason,
    ) -> Self {
        Self {
            message: message.into(),
            retirement_reason: Some(reason),
        }
    }

    pub(super) fn terminal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retirement_reason: None,
        }
    }

    pub(super) fn is_retryable_connection(&self) -> bool {
        self.retirement_reason.is_some()
    }

    pub(super) fn retirement_reason(&self) -> Option<ConnectUdpConnectionRetirementReason> {
        self.retirement_reason
    }

    pub(super) fn into_message(self) -> String {
        self.message
    }
}

pub(super) struct ConnectUdpH3ActorClient {
    pub(super) sender: mpsc::Sender<ConnectUdpH3ActorCommand>,
    pub(super) task: tokio::task::JoinHandle<()>,
    pub(super) max_datagram_size: usize,
}

pub(super) struct ConnectUdpH3OpenedSession {
    pub(super) quarter_stream_id: MasqueQuarterStreamId,
    pub(super) responses: mpsc::Receiver<Result<Bytes, String>>,
}

pub(super) enum ConnectUdpH3ActorCommand {
    OpenSession {
        target: SocketAddr,
        response: oneshot::Sender<Result<ConnectUdpH3OpenedSession, ConnectUdpH3OpenFailure>>,
    },
    SendDatagram {
        quarter_stream_id: MasqueQuarterStreamId,
        payload: Bytes,
        response: oneshot::Sender<Result<(), String>>,
    },
    CloseSession {
        quarter_stream_id: MasqueQuarterStreamId,
    },
    Shutdown,
}
