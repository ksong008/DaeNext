use super::*;

pub(crate) async fn open_h2_body_stream(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    first_payload: &[u8],
    context: &str,
) -> Result<
    (
        h2::SendStream<Bytes>,
        h2::RecvStream,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let initial_chunks = if first_payload.is_empty() {
        Vec::new()
    } else {
        vec![Bytes::copy_from_slice(first_payload)]
    };
    open_h2_body_stream_with_initial_chunks(client, proxy, initial_chunks, context).await
}

pub(crate) async fn open_h2_body_stream_with_initial_chunks(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    initial_chunks: Vec<Bytes>,
    context: &str,
) -> Result<
    (
        h2::SendStream<Bytes>,
        h2::RecvStream,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| format!("{context} HTTP/2 handshake timeout"))?
            .map_err(|err| format!("{context} HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let uri = format!(
        "https://{}{}",
        h2_body_authority(proxy),
        h2_body_request_path(&proxy.stream_path)
    );
    let request = h2_body_request(uri, context)?;
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send {context} HTTP/2 request headers: {err}"))?;
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
        connection_task.abort();
        return Err(format!(
            "{context} HTTP/2 response status {}",
            response.status()
        ));
    }
    Ok((send_stream, response.into_body(), connection_task))
}

pub(crate) async fn open_h2_body_stream_with_deferred_response(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    initial_chunks: Vec<Bytes>,
    context: &'static str,
) -> Result<
    (
        h2::SendStream<Bytes>,
        tokio::task::JoinHandle<Result<h2::RecvStream, String>>,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| format!("{context} HTTP/2 handshake timeout"))?
            .map_err(|err| format!("{context} HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let uri = format!(
        "https://{}{}",
        h2_body_authority(proxy),
        h2_body_request_path(&proxy.stream_path)
    );
    let request = h2_body_request(uri, context)?;
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send {context} HTTP/2 request headers: {err}"))?;
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
    Ok((send_stream, response_task, connection_task))
}

// Deferred H2 relay keeps stream halves, state, metrics, and protocol toggles explicit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_tcp_over_deferred_h2_body(
    inbound: &mut TokioTcpStream,
    send_stream: &mut h2::SendStream<Bytes>,
    mut response_task: tokio::task::JoinHandle<Result<h2::RecvStream, String>>,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
    context: &str,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
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
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_h2_data_with_context(
                            send_stream,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                            false,
                            context,
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for {context} relay: {err}")),
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if inbound_closed && last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    break;
                }
            }
        }
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn relay_tcp_over_ready_h2_body(
    inbound: &mut TokioTcpStream,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
    context: &str,
    mut inbound_closed: bool,
) -> Result<DirectTcpRelayStats, String> {
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut vless_response_stripper =
        strip_vless_response_header.then(VlessResponseStripper::default);

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_h2_data_with_context(
                            send_stream,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                            false,
                            context,
                        )
                        .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                        last_activity = Instant::now();
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
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read {context} HTTP/2 response data: {err}")),
                    None => {
                        response_closed = true;
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

pub(crate) async fn relay_tcp_over_vmess_h2_body(
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
        decode_vmess_h2_response_stream_async(encrypted_reader, request, decrypted_tx).await
    });
    let mut upload_codec = session.upload;
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut decoder_disconnected = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut decode_error = None;

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, "VMess H2").await?;
                        last_activity = Instant::now();
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
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        send_h2_data_with_context(send_stream, Bytes::new(), true, "VMess H2").await?;
                        last_activity = Instant::now();
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
                        let (plain_chunks, disconnected) =
                            collect_vmess_grpc_decrypted(&mut decrypted_rx, &mut decode_error);
                        decoder_disconnected = disconnected;
                        write_vmess_grpc_decrypted(inbound, &mut stats, metrics, plain_chunks).await?;
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read VMess H2 response data: {err}")),
                    None => {
                        response_closed = true;
                        let _ = encrypted_writer.shutdown().await;
                        let (plain_chunks, disconnected) =
                            collect_vmess_grpc_decrypted(&mut decrypted_rx, &mut decode_error);
                        decoder_disconnected = disconnected;
                        write_vmess_grpc_decrypted(inbound, &mut stats, metrics, plain_chunks).await?;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                let (plain_chunks, disconnected) =
                    collect_vmess_grpc_decrypted(&mut decrypted_rx, &mut decode_error);
                decoder_disconnected = disconnected;
                write_vmess_grpc_decrypted(inbound, &mut stats, metrics, plain_chunks).await?;
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
        .uri(uri)
        .header(http::header::ACCEPT_ENCODING, "identity")
        .header(http::header::USER_AGENT, "dae-rust-native-resident")
        .body(())
        .map_err(|err| format!("build {context} HTTP/2 request: {err}"))
}
