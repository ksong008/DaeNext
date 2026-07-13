use super::open::ConnectUdpH3RecvStream;
use super::*;

pub(super) struct ConnectUdpH3MonitorResult {
    pub(super) quarter_stream_id: MasqueQuarterStreamId,
    pub(super) error: Option<String>,
}

pub(super) async fn monitor_connect_udp_h3_stream(
    quarter_stream_id: MasqueQuarterStreamId,
    mut receive: ConnectUdpH3RecvStream,
    mut cancelled: oneshot::Receiver<()>,
) -> ConnectUdpH3MonitorResult {
    let error = tokio::select! {
        _ = &mut cancelled => None,
        data = receive.recv_data() => {
            match data {
                Ok(Some(_)) => Some(
                    "CONNECT-UDP H3 response stream carried unexpected DATA frames".to_owned(),
                ),
                Ok(None) => Some("CONNECT-UDP H3 request stream closed".to_owned()),
                Err(err) => Some(format!("read CONNECT-UDP H3 request stream: {err:?}")),
            }
        }
    };
    ConnectUdpH3MonitorResult {
        quarter_stream_id,
        error,
    }
}
