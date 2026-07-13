use std::sync::Arc;

use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::sync::{mpsc, oneshot};

use super::*;

mod connection;
mod monitor;
mod open;
mod runtime;

pub(super) async fn start_connect_udp_h3_actor(
    proxy: &ResidentProxyPlan,
    runtime: ResidentConnectUdpRuntimePlan,
    state_changed: Arc<tokio::sync::Notify>,
) -> Result<ConnectUdpH3ActorClient, String> {
    connection::start_connect_udp_h3_actor(proxy, runtime, state_changed).await
}

pub(super) struct ConnectUdpH3ActorClient {
    pub(super) sender: mpsc::Sender<ConnectUdpH3ActorCommand>,
    pub(super) task: tokio::task::JoinHandle<()>,
}

pub(super) struct ConnectUdpH3OpenedSession {
    pub(super) quarter_stream_id: MasqueQuarterStreamId,
    pub(super) responses: mpsc::Receiver<Result<Bytes, String>>,
}

pub(super) enum ConnectUdpH3ActorCommand {
    OpenSession {
        target: SocketAddr,
        response: oneshot::Sender<Result<ConnectUdpH3OpenedSession, String>>,
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
