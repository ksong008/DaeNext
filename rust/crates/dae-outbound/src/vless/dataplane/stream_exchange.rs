use super::*;
pub fn tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    payload: &[u8],
) -> Result<VlessTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "tcp", target, false, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let mut echoed_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut echoed_payload)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    Ok(VlessTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Tcp.byte(),
        payload_len: payload.len(),
        echoed_payload,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn udp_over_tcp_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    target: &str,
    payload: &[u8],
) -> Result<VlessUdpOverTcpExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let request = packet::first_write_bytes(key, "", "udp", target, false, payload)?;
    stream
        .write_all(&request)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let (response_header_len, echoed_payload) = read_udp_response_payload(stream)?;
    if echoed_payload.len() != payload.len() {
        return Err(OutboundError::BadVless(format!(
            "unexpected VLESS UDP response payload length: got {}, want {}",
            echoed_payload.len(),
            payload.len()
        )));
    }

    Ok(VlessUdpOverTcpExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Udp.byte(),
        payload_len: payload.len(),
        packet_len: 2 + payload.len(),
        echoed_payload,
        response_header_len,
        true_dataplane: true,
        default_go_path: true,
    })
}

pub fn mux_exchange_over_stream<S>(
    stream: &mut S,
    proxy: &str,
    key: &[u8; 16],
    mux_id: [u8; 2],
    target: &str,
    network: &str,
    payload: &[u8],
) -> Result<VlessMuxExchangeReport, OutboundError>
where
    S: Read + Write,
{
    let header = packet::request_header(key, "", "tcp", "0.0.0.0:0", true, &[])?;
    let metadata = VMessMetadata::parse(network, target)?;
    let options = MuxFrameOptions::new(mux_id, metadata.hostname(), metadata.port(), network);
    stream
        .write_all(&header)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    stream
        .write_all(&mux_new_frame(&options)?)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    stream
        .write_all(&mux_data_frame(mux_id, payload)?)
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;

    let echoed = mux::read_mux_frame(stream)?;
    stream
        .write_all(&mux_end_frame(mux_id))
        .map_err(|err| OutboundError::BadVless(err.to_string()))?;
    if echoed.payload != payload {
        return Err(OutboundError::BadVless(
            "VLESS mux payload response mismatch".to_owned(),
        ));
    }

    Ok(VlessMuxExchangeReport {
        proxy: proxy.to_owned(),
        target: target.to_owned(),
        key_hex: hex_encode(key),
        command: VMessNetwork::Mux.byte(),
        mux_id_hex: hex_encode(&mux_id),
        payload_len: payload.len(),
        echoed_payload: echoed.payload,
        new_frame_validated: true,
        data_frame_validated: true,
        end_frame_sent: true,
        true_dataplane: true,
        default_go_path: true,
    })
}
