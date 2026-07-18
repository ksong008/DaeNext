use super::*;
use bytes::BytesMut;

const H2_UPLOAD_READ_CHUNK: usize = 16 * 1024;

pub(crate) async fn open_h2_body_stream(
    proxy: &ResidentProxyPlan,
    first_payload: &[u8],
    context: &str,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream, H2CarrierLease), String> {
    let initial_chunks = if first_payload.is_empty() {
        Vec::new()
    } else {
        vec![Bytes::copy_from_slice(first_payload)]
    };
    open_h2_body_stream_with_initial_chunks(proxy, initial_chunks, context).await
}

pub(crate) async fn open_h2_body_stream_with_initial_chunks(
    proxy: &ResidentProxyPlan,
    initial_chunks: Vec<Bytes>,
    context: &str,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream, H2CarrierLease), String> {
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = acquire_h2_carrier(Arc::new(proxy.clone()), deadline).await?;
    let uri = format!(
        "https://{}{}",
        h2_body_authority(proxy),
        h2_body_request_path(&proxy.stream_path)
    );
    let request = h2_body_request(uri, context)?;
    let (response, mut send_stream) = lease
        .open_request(request, false, deadline, context)
        .await?;
    for chunk in initial_chunks {
        if !chunk.is_empty() {
            send_h2_data_with_context(&mut send_stream, chunk, false, context).await?;
        }
    }
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| format!("{context} HTTP/2 response headers timeout"))?
        .map_err(|err| format!("read {context} HTTP/2 response headers: {err}"))?;
    if response.status() != http::StatusCode::OK {
        return Err(format!(
            "{context} HTTP/2 response status {}",
            response.status()
        ));
    }
    Ok((send_stream, response.into_body(), lease))
}

pub(crate) async fn open_h2_body_stream_with_deferred_response(
    proxy: &ResidentProxyPlan,
    initial_chunks: Vec<Bytes>,
    context: &'static str,
) -> Result<
    (
        h2::SendStream<Bytes>,
        tokio::task::JoinHandle<Result<h2::RecvStream, String>>,
        H2CarrierLease,
    ),
    String,
> {
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = acquire_h2_carrier(Arc::new(proxy.clone()), deadline).await?;
    let uri = format!(
        "https://{}{}",
        h2_body_authority(proxy),
        h2_body_request_path(&proxy.stream_path)
    );
    let request = h2_body_request(uri, context)?;
    let (response, mut send_stream) = lease
        .open_request(request, false, deadline, context)
        .await?;
    for chunk in initial_chunks {
        if !chunk.is_empty() {
            send_h2_data_with_context(&mut send_stream, chunk, false, context).await?;
        }
    }
    // V2Ray HTTP/2 transports expose a writable connection before the server
    // response is available; keep uploading client bytes while headers arrive.
    let response_task = tokio::spawn(async move {
        let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
            .await
            .map_err(|_| format!("{context} HTTP/2 response headers timeout"))?
            .map_err(|err| format!("read {context} HTTP/2 response headers: {err}"))?;
        if response.status() != http::StatusCode::OK {
            return Err(format!(
                "{context} HTTP/2 response status {}",
                response.status()
            ));
        }
        Ok(response.into_body())
    });
    Ok((send_stream, response_task, lease))
}

// Deferred H2 relay keeps stream halves, state, metrics, and protocol toggles explicit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_deferred_h2_body(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    send_stream: &mut h2::SendStream<Bytes>,
    mut response_task: tokio::task::JoinHandle<Result<h2::RecvStream, String>>,
    stop: SharedResidentStopSignal,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
    context: &str,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut inbound_buf = BytesMut::with_capacity(H2_UPLOAD_READ_CHUNK);
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            response = &mut response_task => {
                let mut recv_stream = response
                    .map_err(|err| format!("join {context} HTTP/2 response task: {err}"))??;
                return relay_tcp_over_ready_h2_body(
                    inbound,
                    send_stream,
                    &mut recv_stream,
                    stop,
                    stats,
                    metrics,
                    strip_vless_response_header,
                    context,
                    inbound_closed,
                )
                .await;
            }
            read = read_h2_upload_chunk(inbound, &mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(None) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(Some(chunk)) => {
                        let read = chunk.len();
                        send_h2_data_with_context(send_stream, chunk, false, context).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read inbound TCP for {context} relay: {err}")),
                }
            }
            _ = &mut idle_deadline, if inbound_closed => break,
        }
    }
    response_task.abort();
    let _ = response_task.await;
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn relay_tcp_over_ready_h2_body(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: SharedResidentStopSignal,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
    context: &str,
    mut inbound_closed: bool,
) -> Result<DirectTcpRelayStats, String> {
    let mut response_closed = false;
    let mut inbound_buf = BytesMut::with_capacity(H2_UPLOAD_READ_CHUNK);
    let mut vless_response_stripper =
        strip_vless_response_header.then(VlessResponseStripper::default);
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            read = read_h2_upload_chunk(inbound, &mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(None) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(Some(chunk)) => {
                        let read = chunk.len();
                        send_h2_data_with_context(send_stream, chunk, false, context).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read inbound TCP for {context} relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release {context} HTTP/2 response capacity: {err}"))?;
                        let payload = if let Some(stripper) = vless_response_stripper.as_mut() {
                            stripper.consume(&bytes)?
                        } else {
                            bytes.to_vec()
                        };
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write {context} response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Some(Err(err)) => return Err(format!("read {context} HTTP/2 response data: {err}")),
                    None => {
                        response_closed = true;
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

async fn read_h2_upload_chunk(
    inbound: &mut (impl AsyncRead + Unpin),
    buffer: &mut BytesMut,
) -> std::io::Result<Option<Bytes>> {
    buffer.reserve(H2_UPLOAD_READ_CHUNK);
    let read = inbound.read_buf(buffer).await?;
    if read == 0 {
        return Ok(None);
    }
    Ok(Some(buffer.split_to(read).freeze()))
}

pub(crate) async fn relay_tcp_over_vmess_h2_body(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let (mut encrypted_writer, encrypted_reader) = tokio::io::duplex(64 * 1024);
    let (decrypted_tx, mut decrypted_rx) = tokio::sync::mpsc::channel(16);
    let request = session.request.clone();
    let decoder = tokio::spawn(async move {
        decode_vmess_h2_response_stream_async(encrypted_reader, request, decrypted_tx).await
    });
    let mut upload_codec = session.upload;
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut decoder_disconnected = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
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
                        send_h2_data_with_context(send_stream, Bytes::new(), true, "VMess H2").await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(read) => {
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode VMess H2 upload chunk: {err}"))?;
                        send_h2_data_with_context(
                            send_stream,
                            Bytes::from(encrypted),
                            false,
                            "VMess H2",
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, "VMess H2").await?;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read inbound TCP for VMess H2 relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release VMess H2 response capacity: {err}"))?;
                        if !bytes.is_empty() {
                            encrypted_writer
                                .write_all(&bytes)
                                .await
                                .map_err(|err| format!("write VMess H2 encrypted response to decoder: {err}"))?;
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Some(Err(err)) => return Err(format!("read VMess H2 response data: {err}")),
                    None => {
                        response_closed = true;
                        let _ = encrypted_writer.shutdown().await;
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
        .map_err(|err| format!("join VMess H2 response decoder failed: {err}"))?;
    decoder_result?;
    Ok(stats)
}

async fn decode_vmess_h2_response_stream_async<R>(
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
                    "read VMess H2 AEAD response header: {message}"
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
                    .send(Err(format!("read VMess H2 response chunk: {message}")))
                    .await;
                return Ok(());
            }
        }
    }
}

fn h2_body_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

fn h2_body_request_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn h2_body_request(uri: String, context: &str) -> Result<http::Request<()>, String> {
    http::Request::builder()
        .method(http::Method::PUT)
        .version(http::Version::HTTP_2)
        .uri(uri)
        .header(http::header::ACCEPT_ENCODING, "identity")
        .header(http::header::USER_AGENT, "dae-rust-native-resident")
        .body(())
        .map_err(|err| format!("build {context} HTTP/2 request: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_h2_body_request_uses_http2_pseudo_header_encoding() {
        let request = h2_body_request(
            "https://transport.invalid/tunnel".to_owned(),
            "legacy carrier test",
        )
        .unwrap();

        assert_eq!(request.version(), http::Version::HTTP_2);
        assert_eq!(request.method(), http::Method::PUT);
        assert_eq!(request.uri().authority().unwrap(), "transport.invalid");
    }
}
