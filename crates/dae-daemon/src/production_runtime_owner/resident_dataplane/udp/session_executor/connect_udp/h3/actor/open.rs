use super::*;
use crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3::request::{
    connect_udp_h3_request, validate_connect_udp_h3_response,
};

pub(super) type ConnectUdpH3SendStream =
    ::h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(super) type ConnectUdpH3RecvStream = ::h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

pub(super) struct ConnectUdpH3OpenedStream {
    pub(super) quarter_stream_id: MasqueQuarterStreamId,
    pub(super) send: ConnectUdpH3SendStream,
    pub(super) receive: ConnectUdpH3RecvStream,
    pub(super) response_sender: mpsc::Sender<Result<Bytes, String>>,
    pub(super) response_receiver: mpsc::Receiver<Result<Bytes, String>>,
}

pub(super) struct ConnectUdpH3OpenResult {
    pub(super) response:
        oneshot::Sender<Result<ConnectUdpH3OpenedSession, ConnectUdpH3OpenFailure>>,
    pub(super) result: Result<ConnectUdpH3OpenedStream, ConnectUdpH3OpenFailure>,
}

pub(super) async fn open_connect_udp_h3_session(
    mut client: ::h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    proxy: Arc<ResidentProxyPlan>,
    target: SocketAddr,
    response_queue_depth: usize,
    response: oneshot::Sender<Result<ConnectUdpH3OpenedSession, ConnectUdpH3OpenFailure>>,
) -> ConnectUdpH3OpenResult {
    let result = async {
        let request =
            connect_udp_h3_request(&proxy, target).map_err(ConnectUdpH3OpenFailure::terminal)?;
        let mut stream = time::timeout(RESIDENT_CONNECT_TIMEOUT, client.send_request(request))
            .await
            .map_err(|_| {
                ConnectUdpH3OpenFailure::retryable_connection(
                    "CONNECT-UDP H3 request stream timeout",
                    ConnectUdpConnectionRetirementReason::Other,
                )
            })?
            .map_err(|err| {
                ConnectUdpH3OpenFailure::retryable_connection(
                    format!("send CONNECT-UDP H3 request: {err:?}"),
                    h3_retirement_reason(&err),
                )
            })?;
        let quarter_stream_id = MasqueQuarterStreamId::from_quarter_stream_id(stream.id().index())
            .map_err(|err| {
                ConnectUdpH3OpenFailure::terminal(format!(
                    "derive CONNECT-UDP H3 Quarter Stream ID: {err}"
                ))
            })?;
        let received = time::timeout(RESIDENT_CONNECT_TIMEOUT, stream.recv_response())
            .await
            .map_err(|_| {
                ConnectUdpH3OpenFailure::retryable_connection(
                    "CONNECT-UDP H3 response headers timeout",
                    ConnectUdpConnectionRetirementReason::Other,
                )
            })?
            .map_err(|err| {
                ConnectUdpH3OpenFailure::retryable_connection(
                    format!("read CONNECT-UDP H3 response headers: {err:?}"),
                    h3_retirement_reason(&err),
                )
            })?;
        validate_connect_udp_h3_response(&received).map_err(ConnectUdpH3OpenFailure::terminal)?;
        let (send, receive) = stream.split();
        let (response_sender, response_receiver) = mpsc::channel(response_queue_depth.max(1));
        Ok(ConnectUdpH3OpenedStream {
            quarter_stream_id,
            send,
            receive,
            response_sender,
            response_receiver,
        })
    }
    .await;
    ConnectUdpH3OpenResult { response, result }
}

fn h3_retirement_reason(error: &::h3::error::StreamError) -> ConnectUdpConnectionRetirementReason {
    match error {
        ::h3::error::StreamError::RemoteClosing => ConnectUdpConnectionRetirementReason::GoAway,
        ::h3::error::StreamError::RemoteTerminate { .. } => {
            ConnectUdpConnectionRetirementReason::Reset
        }
        _ => ConnectUdpConnectionRetirementReason::Other,
    }
}
