use super::super::actor::{
    ConnectUdpH3ActorCommand, ConnectUdpH3OpenFailure, ConnectUdpH3OpenedSession,
};
use super::super::pool::{ConnectUdpH3ActorLease, acquire_connect_udp_h3_actor};
use super::super::*;

pub(super) struct OpenedConnectUdpH3Binding {
    pub(super) quarter_stream_id: MasqueQuarterStreamId,
    pub(super) responses: tokio::sync::mpsc::Receiver<Result<Bytes, String>>,
    pub(super) actor: ConnectUdpH3ActorLease,
}

pub(super) async fn open_connect_udp_h3_binding(
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
    runtime: ResidentConnectUdpRuntimePlan,
) -> Result<OpenedConnectUdpH3Binding, String> {
    let max_attempts = runtime.h3_session_open_attempts();
    let mut last_connection_error = None;

    for _ in 0..max_attempts {
        let actor = acquire_connect_udp_h3_actor(proxy).await?;
        match open_on_actor(&actor, target).await {
            Ok(opened) => {
                return Ok(OpenedConnectUdpH3Binding {
                    quarter_stream_id: opened.quarter_stream_id,
                    responses: opened.responses,
                    actor,
                });
            }
            Err(failure) if failure.is_retryable_connection() => {
                actor.retire(
                    failure
                        .retirement_reason()
                        .unwrap_or(ConnectUdpConnectionRetirementReason::Other),
                );
                last_connection_error = Some(failure.into_message());
            }
            Err(failure) => return Err(failure.into_message()),
        }
    }

    Err(last_connection_error
        .unwrap_or_else(|| "CONNECT-UDP H3 exhausted the bounded actor-open attempts".to_owned()))
}

async fn open_on_actor(
    actor: &ConnectUdpH3ActorLease,
    target: SocketAddr,
) -> Result<ConnectUdpH3OpenedSession, ConnectUdpH3OpenFailure> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    time::timeout(
        RESIDENT_CONNECT_TIMEOUT,
        actor.sender.send(ConnectUdpH3ActorCommand::OpenSession {
            target,
            response: response_tx,
        }),
    )
    .await
    .map_err(|_| {
        actor.record_queue_full();
        ConnectUdpH3OpenFailure::terminal("CONNECT-UDP H3 actor open queue timeout")
    })?
    .map_err(|_| {
        ConnectUdpH3OpenFailure::retryable_connection(
            "CONNECT-UDP H3 actor is closed",
            ConnectUdpConnectionRetirementReason::Other,
        )
    })?;
    time::timeout(RESIDENT_CONNECT_TIMEOUT, response_rx)
        .await
        .map_err(|_| {
            ConnectUdpH3OpenFailure::retryable_connection(
                "CONNECT-UDP H3 session open timeout",
                ConnectUdpConnectionRetirementReason::Other,
            )
        })?
        .map_err(|_| {
            ConnectUdpH3OpenFailure::retryable_connection(
                "CONNECT-UDP H3 actor dropped session open result",
                ConnectUdpConnectionRetirementReason::Other,
            )
        })?
}
