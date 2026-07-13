use super::open::ConnectUdpH3RecvStream;
use super::*;

pub(super) struct ConnectUdpH3MonitorResult {
    pub(super) quarter_stream_id: MasqueQuarterStreamId,
    pub(super) error: Option<String>,
    pub(super) reset: bool,
}

pub(super) async fn monitor_connect_udp_h3_stream(
    quarter_stream_id: MasqueQuarterStreamId,
    mut receive: ConnectUdpH3RecvStream,
    mut cancelled: oneshot::Receiver<()>,
) -> ConnectUdpH3MonitorResult {
    let (error, reset) = tokio::select! {
        _ = &mut cancelled => (None, false),
        data = receive.recv_data() => {
            match data {
                Ok(Some(_)) => (Some(
                    "CONNECT-UDP H3 response stream carried unexpected DATA frames".to_owned(),
                ), false),
                Ok(None) => (Some("CONNECT-UDP H3 request stream closed".to_owned()), false),
                Err(err) => {
                    let reset = matches!(
                        err,
                        ::h3::error::StreamError::RemoteTerminate { .. }
                    );
                    (Some(format!("read CONNECT-UDP H3 request stream: {err:?}")), reset)
                }
            }
        }
    };
    ConnectUdpH3MonitorResult {
        quarter_stream_id,
        error,
        reset,
    }
}
