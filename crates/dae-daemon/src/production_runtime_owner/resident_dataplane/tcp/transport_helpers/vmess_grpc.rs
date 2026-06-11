use super::*;
pub(crate) async fn relay_tcp_over_vmess_grpc_h2(
    inbound: &mut TokioTcpStream,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: Arc<AtomicBool>,
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
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_buf = Vec::new();
    let mut decode_error = None;

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
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess gRPC upload chunk: {err}"))?;
                        send_grpc_hunk(send_stream, &encrypted, false).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data(send_stream, Bytes::new(), true).await?;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for VMess gRPC relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release VMess gRPC HTTP/2 response capacity: {err}"))?;
                        response_buf.extend_from_slice(&bytes);
                        while let Some(payload) = pop_grpc_hunk_payload(&mut response_buf)? {
                            if !payload.is_empty() {
                                encrypted_writer
                                    .write_all(&payload)
                                    .await
                                    .map_err(|err| format!("write VMess gRPC encrypted response to decoder: {err}"))?;
                            }
                        }
                        let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                            &mut decrypted_rx,
                            &mut decode_error,
                        );
                        decoder_disconnected = disconnected;
                        write_vmess_grpc_decrypted(
                            inbound,
                            &mut stats,
                            metrics,
                            plain_chunks,
                        )
                        .await?;
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read VMess gRPC HTTP/2 response data: {err}")),
                    None => {
                        response_closed = true;
                        let _ = encrypted_writer.shutdown().await;
                        if !response_buf.is_empty() {
                            return Err("VMess gRPC response stream ended with partial hunk".to_owned());
                        }
                        let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                            &mut decrypted_rx,
                            &mut decode_error,
                        );
                        decoder_disconnected = disconnected;
                        write_vmess_grpc_decrypted(
                            inbound,
                            &mut stats,
                            metrics,
                            plain_chunks,
                        )
                        .await?;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                    &mut decrypted_rx,
                    &mut decode_error,
                );
                decoder_disconnected = disconnected;
                write_vmess_grpc_decrypted(
                    inbound,
                    &mut stats,
                    metrics,
                    plain_chunks,
                )
                .await?;
                if inbound_closed && response_closed && decoder_disconnected {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    break;
                }
            }
        }

        if let Some(err) = decode_error.take() {
            let _ = encrypted_writer.shutdown().await;
            decoder.abort();
            return Err(err);
        }
        if inbound_closed && response_closed && decoder_disconnected {
            break;
        }
    }
    let _ = encrypted_writer.shutdown().await;
    let decoder_result = decoder
        .await
        .map_err(|err| format!("join VMess gRPC response decoder failed: {err}"))?;
    if let Err(err) = decoder_result {
        return Err(err);
    }
    Ok(stats)
}

pub(crate) fn collect_vmess_grpc_decrypted(
    decrypted_rx: &mut tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    decode_error: &mut Option<String>,
) -> (Vec<Vec<u8>>, bool) {
    let mut chunks = Vec::new();
    loop {
        match decrypted_rx.try_recv() {
            Ok(Ok(plain)) => {
                chunks.push(plain);
            }
            Ok(Err(err)) => {
                *decode_error = Some(err);
                return (chunks, false);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return (chunks, false),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return (chunks, true),
        }
    }
}

pub(crate) async fn write_vmess_grpc_decrypted(
    inbound: &mut TokioTcpStream,
    stats: &mut DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    chunks: Vec<Vec<u8>>,
) -> Result<(), String> {
    for plain in chunks {
        if !plain.is_empty() {
            inbound
                .write_all(&plain)
                .await
                .map_err(|err| format!("write VMess gRPC response to inbound: {err}"))?;
            stats.direct_to_client += plain.len();
            metrics.add_download(plain.len());
        }
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
