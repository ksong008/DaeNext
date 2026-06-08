use super::*;
#[derive(Debug)]
pub(super) struct StreamPacketCongestionServerReport {
    pub(super) selected_alpn: String,
    pub(super) accept_bi_stream_count: usize,
    pub(super) request_read_count: usize,
    pub(super) request_match_count: usize,
    pub(super) response_write_count: usize,
    pub(super) server_stream_finish_count: usize,
    pub(super) server_stream_acked_count: usize,
    pub(super) stats: quinn::ConnectionStats,
}

pub(super) async fn run_stream_packet_congestion_server(
    endpoint: quinn::Endpoint,
    expected_target: String,
    expected_payload: Vec<u8>,
    response_frame: JuicityStreamPacketFrame,
    iterations: usize,
) -> Result<StreamPacketCongestionServerReport, OutboundError> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| bad_stream_packet_congestion("server accept returned none"))?
        .await
        .map_err(|err| {
            bad_stream_packet_congestion(format!("server accept stream congestion: {err}"))
        })?;
    let selected_alpn = selected_alpn(&connection);
    let mut accept_bi_stream_count = 0_usize;
    let mut request_read_count = 0_usize;
    let mut request_match_count = 0_usize;
    let mut response_write_count = 0_usize;
    let mut server_stream_finish_count = 0_usize;
    let mut server_stream_acked_count = 0_usize;
    for _ in 0..iterations {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(|err| {
            bad_stream_packet_congestion(format!("accept stream congestion bi stream: {err}"))
        })?;
        accept_bi_stream_count += 1;
        let request = recv.read_to_end(8192).await.map_err(|err| {
            bad_stream_packet_congestion(format!("read stream congestion request: {err}"))
        })?;
        request_read_count += 1;
        let parsed = parse_stream_conn_request(&request)?;
        if parsed.network_byte == TrojanNetwork::Udp.byte()
            && parsed.initial_target == expected_target
            && parsed.frame.target == expected_target
            && parsed.frame.payload == expected_payload
        {
            request_match_count += 1;
        }
        send.write_all(&response_frame.encoded)
            .await
            .map_err(|err| {
                bad_stream_packet_congestion(format!("write stream congestion response: {err}"))
            })?;
        response_write_count += 1;
        send.finish().map_err(|err| {
            bad_stream_packet_congestion(format!("finish stream congestion response: {err}"))
        })?;
        server_stream_finish_count += 1;
        if send
            .stopped()
            .await
            .map_err(|err| {
                bad_stream_packet_congestion(format!("wait server congestion ack: {err}"))
            })?
            .is_none()
        {
            server_stream_acked_count += 1;
        }
    }
    let stats = connection.stats();
    endpoint.wait_idle().await;
    Ok(StreamPacketCongestionServerReport {
        selected_alpn,
        accept_bi_stream_count,
        request_read_count,
        request_match_count,
        response_write_count,
        server_stream_finish_count,
        server_stream_acked_count,
        stats,
    })
}
