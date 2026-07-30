use super::*;
pub(crate) async fn relay_tcp_over_vmess_grpc_h2(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    send_stream: &mut h2::SendStream<Bytes>,
    response: &mut GrpcH2Response,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let (mut encrypted_writer, encrypted_reader) = tokio::io::duplex(64 * 1024);
    let (decrypted_tx, mut decrypted_rx) = tokio::sync::mpsc::channel(16);
    let request = session.request.clone();
    let decoder = tokio::spawn(async move {
        decode_vmess_grpc_response_stream_async(encrypted_reader, request, decrypted_tx).await
    });
    let mut upload_codec = session.upload;
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut decoder_disconnected = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_buf = GrpcHunkReadBuffer::default();
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    let mut relay_cancelled = false;

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => {
                relay_cancelled = true;
                break;
            }
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(read) => {
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess gRPC upload chunk: {err}"))?;
                        send_grpc_hunk(send_stream, &encrypted, false).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read inbound TCP for VMess gRPC relay: {err}")),
                }
            }
            data = response.next_data(), if !response_closed => {
                match data {
                    Ok(Some(bytes)) => {
                        response_buf.extend_from_slice(&bytes);
                        while let Some(payload) = response_buf.pop_payload()? {
                            if !payload.is_empty() {
                                encrypted_writer
                                    .write_all(&payload)
                                    .await
                                .map_err(|err| format!("write VMess gRPC encrypted response to decoder: {err}"))?;
                            }
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(err),
                    Ok(None) => {
                        response_closed = true;
                        let _ = encrypted_writer.shutdown().await;
                        if !response_buf.is_empty() {
                            return Err("VMess gRPC response stream ended with partial hunk".to_owned());
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                }
            }
            decoded = decrypted_rx.recv(), if !decoder_disconnected => {
                match decoded {
                    Some(Ok(plain)) => {
                        write_vmess_decrypted_chunk(inbound, &mut stats, metrics, plain).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Some(Err(err)) => {
                        let _ = encrypted_writer.shutdown().await;
                        decoder.abort();
                        return Err(err);
                    }
                    None => decoder_disconnected = true,
                }
            }
            _ = &mut idle_deadline => {
                relay_cancelled = true;
                break;
            }
        }

        if inbound_closed && response_closed && decoder_disconnected {
            break;
        }
    }
    let _ = encrypted_writer.shutdown().await;
    if relay_cancelled {
        decoder.abort();
        let _ = decoder.await;
        return Ok(stats);
    }
    let decoder_result = decoder
        .await
        .map_err(|err| format!("join VMess gRPC response decoder failed: {err}"))?;
    decoder_result?;
    Ok(stats)
}

pub(crate) async fn write_vmess_decrypted_chunk(
    inbound: &mut (impl AsyncWrite + Unpin),
    stats: &mut DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    plain: Vec<u8>,
) -> Result<(), String> {
    if !plain.is_empty() {
        inbound
            .write_all(&plain)
            .await
            .map_err(|err| format!("write VMess gRPC response to inbound: {err}"))?;
        stats.direct_to_client += plain.len();
        metrics.add_download(plain.len());
    }
    Ok(())
}

pub(crate) async fn decode_vmess_grpc_response_stream_async<R>(
    mut reader: R,
    request: dae_outbound::vmess::VMessAeadTcpRequest,
    decrypted_tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, String>>,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    let mut response = match aead_tcp_response_reader_from_async_stream(&mut reader, &request).await
    {
        Ok(response) => response,
        Err(err) => {
            let message = err.to_string();
            if is_vmess_grpc_graceful_decode_close(&message) {
                return Ok(());
            }
            let _ = decrypted_tx
                .send(Err(format!(
                    "read VMess gRPC AEAD response header: {message}"
                )))
                .await;
            return Ok(());
        }
    };
    loop {
        match response.read_chunk_from_async_stream(&mut reader).await {
            Ok(plain) => {
                if decrypted_tx.send(Ok(plain)).await.is_err() {
                    return Ok(());
                }
            }
            Err(err) => {
                let message = err.to_string();
                if is_vmess_grpc_graceful_decode_close(&message) {
                    return Ok(());
                }
                let _ = decrypted_tx
                    .send(Err(format!("read VMess gRPC response chunk: {message}")))
                    .await;
                return Ok(());
            }
        }
    }
}

pub(crate) fn is_vmess_grpc_graceful_decode_close(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
}
