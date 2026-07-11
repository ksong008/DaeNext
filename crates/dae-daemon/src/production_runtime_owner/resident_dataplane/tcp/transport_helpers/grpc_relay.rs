use super::*;
pub(crate) async fn relay_tcp_over_grpc_h2(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: SharedResidentStopSignal,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_buf = GrpcHunkReadBuffer::default();
    let mut vless_response_stripper =
        strip_vless_response_header.then(VlessResponseStripper::default);
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(read) => {
                        send_grpc_hunk(send_stream, &inbound_buf[..read], false).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                    }
                    Err(err) => return Err(format!("read inbound TCP for gRPC relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release gRPC HTTP/2 response capacity: {err}"))?;
                        response_buf.extend_from_slice(&bytes);
                        while let Some(payload) = response_buf.pop_payload()? {
                            let payload = if let Some(stripper) = vless_response_stripper.as_mut() {
                                stripper.consume(&payload)?
                            } else {
                                payload
                            };
                            if !payload.is_empty() {
                                inbound
                                    .write_all(&payload)
                                    .await
                                    .map_err(|err| format!("write gRPC response to inbound: {err}"))?;
                                stats.direct_to_client += payload.len();
                                metrics.add_download(payload.len());
                            }
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Some(Err(err)) => return Err(format!("read gRPC HTTP/2 response data: {err}")),
                    None => {
                        response_closed = true;
                        if !response_buf.is_empty() {
                            return Err("gRPC response stream ended with partial hunk".to_owned());
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                }
            }
            _ = &mut idle_deadline => break,
        }
        if inbound_closed && response_closed {
            break;
        }
    }
    Ok(stats)
}
