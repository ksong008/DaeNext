use super::pool::{ConnectUdpH2ConnectionLease, acquire_connect_udp_h2_connection};
use super::request::{connect_udp_h2_request, validate_connect_udp_h2_response};
use super::*;

pub(super) struct ConnectUdpH2Tunnel {
    pub(super) target: SocketAddr,
    pub(super) send: ::h2::SendStream<Bytes>,
    pub(super) receive: ::h2::RecvStream,
    pub(super) connection_lease: ConnectUdpH2ConnectionLease,
}

enum ConnectUdpH2OpenFailure {
    RetryableConnection {
        message: String,
        reason: ConnectUdpConnectionRetirementReason,
    },
    Terminal(String),
}

impl ConnectUdpH2OpenFailure {
    fn into_message(self) -> String {
        match self {
            Self::RetryableConnection { message, .. } | Self::Terminal(message) => message,
        }
    }
}

pub(super) async fn open_connect_udp_h2_tunnel(
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
    runtime: ResidentConnectUdpRuntimePlan,
) -> Result<ConnectUdpH2Tunnel, String> {
    let max_attempts = runtime.h2_session_open_attempts();
    let mut last_connection_error = None;

    for _ in 0..max_attempts {
        let lease = acquire_connect_udp_h2_connection(proxy).await?;
        match open_on_connection(proxy, target, &lease).await {
            Ok((send, receive)) => {
                return Ok(ConnectUdpH2Tunnel {
                    target,
                    send,
                    receive,
                    connection_lease: lease,
                });
            }
            Err(ConnectUdpH2OpenFailure::RetryableConnection { message, reason }) => {
                lease.retire(reason);
                last_connection_error = Some(message);
            }
            Err(failure) => return Err(failure.into_message()),
        }
    }

    Err(last_connection_error.unwrap_or_else(|| {
        "CONNECT-UDP H2 exhausted the bounded connection-open attempts".to_owned()
    }))
}

async fn open_on_connection(
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
    lease: &ConnectUdpH2ConnectionLease,
) -> Result<(::h2::SendStream<Bytes>, ::h2::RecvStream), ConnectUdpH2OpenFailure> {
    let mut sender = time::timeout(RESIDENT_CONNECT_TIMEOUT, lease.sender.clone().ready())
        .await
        .map_err(|_| ConnectUdpH2OpenFailure::RetryableConnection {
            message: "CONNECT-UDP H2 stream capacity timeout".to_owned(),
            reason: ConnectUdpConnectionRetirementReason::Other,
        })?
        .map_err(|err| ConnectUdpH2OpenFailure::RetryableConnection {
            message: format!("CONNECT-UDP H2 stream capacity: {err}"),
            reason: h2_retirement_reason(&err),
        })?;
    if !sender.is_extended_connect_protocol_enabled() {
        return Err(ConnectUdpH2OpenFailure::Terminal(
            "CONNECT-UDP H2 peer disabled extended CONNECT before stream creation".to_owned(),
        ));
    }

    let request =
        connect_udp_h2_request(proxy, target).map_err(ConnectUdpH2OpenFailure::Terminal)?;
    let (response, send) = sender.send_request(request, false).map_err(|err| {
        ConnectUdpH2OpenFailure::RetryableConnection {
            message: format!("send CONNECT-UDP H2 request headers: {err}"),
            reason: h2_retirement_reason(&err),
        }
    })?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| ConnectUdpH2OpenFailure::RetryableConnection {
            message: "CONNECT-UDP H2 response headers timeout".to_owned(),
            reason: ConnectUdpConnectionRetirementReason::Other,
        })?
        .map_err(|err| ConnectUdpH2OpenFailure::RetryableConnection {
            message: format!("read CONNECT-UDP H2 response headers: {err}"),
            reason: h2_retirement_reason(&err),
        })?;
    validate_connect_udp_h2_response(&response).map_err(ConnectUdpH2OpenFailure::Terminal)?;
    Ok((send, response.into_body()))
}

fn h2_retirement_reason(error: &::h2::Error) -> ConnectUdpConnectionRetirementReason {
    if error.is_go_away() {
        ConnectUdpConnectionRetirementReason::GoAway
    } else if error.is_reset() {
        ConnectUdpConnectionRetirementReason::Reset
    } else {
        ConnectUdpConnectionRetirementReason::Other
    }
}
