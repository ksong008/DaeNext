use super::*;
pub(crate) async fn relay_tcp_over_grpc_h2(
    inbound: &mut TokioTcpStream,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_buf = GrpcHunkReadBuffer::default();
    let mut vless_response_stripper =
        strip_vless_response_header.then(VlessResponseStripper::default);

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_grpc_hunk(send_stream, &inbound_buf[..read], false).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
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
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read gRPC HTTP/2 response data: {err}")),
                    None => {
                        response_closed = true;
                        if !response_buf.is_empty() {
                            return Err("gRPC response stream ended with partial hunk".to_owned());
                        }
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if (inbound_closed && response_closed) || last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    break;
                }
            }
        }
    }
    Ok(stats)
}
