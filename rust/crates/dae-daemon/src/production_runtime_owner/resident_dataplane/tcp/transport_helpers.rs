fn grpc_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

fn grpc_request_path(service_name: &str) -> String {
    let service_name = if service_name.is_empty() {
        "GunService"
    } else {
        service_name.trim_start_matches('/')
    };
    format!("/{service_name}/Tun")
}

async fn open_xhttp_h2_packet_up_session(
    client: AsyncResidentTlsClient,
    proxy: &ResidentProxyPlan,
    session_id: &str,
) -> Result<
    (
        h2::client::SendRequest<Bytes>,
        h2::RecvStream,
        tokio::task::JoinHandle<()>,
    ),
    String,
> {
    let (mut sender, connection) =
        time::timeout(RESIDENT_CONNECT_TIMEOUT, h2::client::handshake(client))
            .await
            .map_err(|_| "xHTTP HTTP/2 handshake timeout".to_owned())?
            .map_err(|err| format!("xHTTP HTTP/2 client handshake: {err}"))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = xhttp_h2_request(
        http::Method::GET,
        proxy,
        &xhttp_session_path_suffix(session_id, None),
        false,
    )?;
    let (response, _send_stream) = sender
        .send_request(request, true)
        .map_err(|err| format!("send xHTTP HTTP/2 download request headers: {err}"))?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "xHTTP HTTP/2 download response headers timeout".to_owned())?
        .map_err(|err| format!("read xHTTP HTTP/2 download response headers: {err}"))?;
    if !response.status().is_success() {
        connection_task.abort();
        return Err(format!(
            "xHTTP HTTP/2 download response status {}",
            response.status()
        ));
    }
    Ok((sender, response.into_body(), connection_task))
}

async fn send_xhttp_h2_packet_up_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    proxy: &ResidentProxyPlan,
    session_id: &str,
    seq: u64,
    payload: Bytes,
) -> Result<(), String> {
    let request = xhttp_h2_request(
        http::Method::POST,
        proxy,
        &xhttp_session_path_suffix(session_id, Some(seq)),
        true,
    )?;
    let (response, mut send_stream) = sender
        .send_request(request, false)
        .map_err(|err| format!("send xHTTP HTTP/2 packet-up request headers: {err}"))?;
    send_h2_data_with_context(&mut send_stream, payload, true, "xHTTP HTTP/2 packet-up").await?;
    let response = time::timeout(RESIDENT_CONNECT_TIMEOUT, response)
        .await
        .map_err(|_| "xHTTP HTTP/2 packet-up response headers timeout".to_owned())?
        .map_err(|err| format!("read xHTTP HTTP/2 packet-up response headers: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "xHTTP HTTP/2 packet-up response status {}",
            response.status()
        ));
    }
    drain_xhttp_h2_response_body(response.into_body()).await
}

fn xhttp_h2_request(
    method: http::Method,
    proxy: &ResidentProxyPlan,
    path_suffix: &str,
    has_body: bool,
) -> Result<http::Request<()>, String> {
    let uri = xhttp_uri(proxy, path_suffix);
    let referer = xhttp_padding_referer(&xhttp_uri(proxy, ""));
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::USER_AGENT, "Mozilla/5.0")
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("pragma", "no-cache")
        .header(http::header::REFERER, referer);
    if has_body {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }
    builder
        .body(())
        .map_err(|err| format!("build xHTTP HTTP/2 request: {err}"))
}

fn xhttp_uri(proxy: &ResidentProxyPlan, path_suffix: &str) -> String {
    let normalized = ir::normalize_xhttp_path_and_query(&proxy.stream_path);
    let mut path = normalized.path;
    path.push_str(path_suffix);
    let mut uri = format!("https://{}{}", xhttp_authority(proxy), path);
    if !normalized.query.is_empty() {
        uri.push('?');
        uri.push_str(&normalized.query);
    }
    uri
}

fn xhttp_padding_referer(base_uri: &str) -> String {
    const DEFAULT_PADDING_LEN: usize = 128;
    let base_without_query = base_uri.split_once('?').map_or(base_uri, |(base, _)| base);
    format!(
        "{base_without_query}?x_padding={}",
        "X".repeat(DEFAULT_PADDING_LEN)
    )
}

fn xhttp_authority(proxy: &ResidentProxyPlan) -> String {
    if proxy.stream_host.is_empty() {
        proxy.server_name.clone()
    } else {
        proxy.stream_host.clone()
    }
}

fn xhttp_session_path_suffix(session_id: &str, seq: Option<u64>) -> String {
    match seq {
        Some(seq) => format!("{session_id}/{seq}"),
        None => session_id.to_owned(),
    }
}

fn new_xhttp_session_id() -> String {
    let high = fastrand::u64(..);
    let low = fastrand::u64(..);
    let value = ((high as u128) << 64) | low as u128;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (value >> 96) as u32,
        ((value >> 80) & 0xffff) as u16,
        ((value >> 64) & 0xffff) as u16,
        ((value >> 48) & 0xffff) as u16,
        value & 0xffff_ffff_ffff
    )
}

async fn drain_xhttp_h2_response_body(mut body: h2::RecvStream) -> Result<(), String> {
    loop {
        let data = time::timeout(RESIDENT_CONNECT_TIMEOUT, body.data())
            .await
            .map_err(|_| "xHTTP HTTP/2 packet-up response body timeout".to_owned())?;
        let Some(data) = data else {
            return Ok(());
        };
        let bytes =
            data.map_err(|err| format!("read xHTTP HTTP/2 packet-up response body: {err}"))?;
        body.flow_control()
            .release_capacity(bytes.len())
            .map_err(|err| format!("release xHTTP HTTP/2 packet-up response capacity: {err}"))?;
    }
}

async fn send_grpc_hunk(
    send_stream: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_stream: bool,
) -> Result<(), String> {
    let hunk = grpc_hunk_frame(payload).map_err(|err| format!("build gRPC hunk: {err}"))?;
    send_h2_data(send_stream, Bytes::from(hunk), end_stream).await
}

async fn send_h2_data(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
) -> Result<(), String> {
    send_h2_data_with_context(send_stream, data, end_stream, "gRPC HTTP/2").await
}

async fn send_h2_data_with_context(
    send_stream: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_stream: bool,
    context: &str,
) -> Result<(), String> {
    let required = data.len();
    if required > 0 {
        send_stream.reserve_capacity(required);
        while send_stream.capacity() < required {
            let Some(capacity) = poll_fn(|cx| send_stream.poll_capacity(cx)).await else {
                return Err(format!(
                    "{context} send stream closed before capacity became available"
                ));
            };
            capacity.map_err(|err| format!("reserve {context} send capacity: {err}"))?;
        }
    }
    send_stream
        .send_data(data, end_stream)
        .map_err(|err| format!("send {context} data: {err}"))
}

async fn relay_tcp_over_grpc_h2(
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
    let mut response_buf = Vec::new();
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
                        while let Some(payload) = pop_grpc_hunk_payload(&mut response_buf)? {
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

#[allow(clippy::too_many_arguments)]
async fn relay_tcp_over_xhttp_h2_packet_up(
    inbound: &mut TokioTcpStream,
    sender: &mut h2::client::SendRequest<Bytes>,
    recv_stream: &mut h2::RecvStream,
    proxy: &ResidentProxyPlan,
    session_id: &str,
    mut seq: u64,
    stop: Arc<AtomicBool>,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut inbound_closed = false;
    let mut response_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_stripper = VlessResponseStripper::default();

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        send_xhttp_h2_packet_up_request(
                            sender,
                            proxy,
                            session_id,
                            seq,
                            Bytes::copy_from_slice(&inbound_buf[..read]),
                        )
                        .await?;
                        seq = seq.saturating_add(1);
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for xHTTP relay: {err}")),
                }
            }
            data = recv_stream.data(), if !response_closed => {
                match data {
                    Some(Ok(bytes)) => {
                        recv_stream
                            .flow_control()
                            .release_capacity(bytes.len())
                            .map_err(|err| format!("release xHTTP HTTP/2 download capacity: {err}"))?;
                        let payload = response_stripper.consume(&bytes)?;
                        if !payload.is_empty() {
                            inbound
                                .write_all(&payload)
                                .await
                                .map_err(|err| format!("write xHTTP response to inbound: {err}"))?;
                            stats.direct_to_client += payload.len();
                            metrics.add_download(payload.len());
                        }
                        last_activity = Instant::now();
                    }
                    Some(Err(err)) => return Err(format!("read xHTTP HTTP/2 download data: {err}")),
                    None => {
                        response_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                if response_closed || (inbound_closed && response_closed) {
                    break;
                }
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident xHTTP HTTP/2 relay idle timeout".to_owned());
                }
            }
        }
    }
    Ok(stats)
}

async fn relay_tcp_over_vmess_grpc_h2(
    inbound: &mut TokioTcpStream,
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: Arc<AtomicBool>,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let encrypted_queue = Arc::new(VmessGrpcEncryptedQueue::default());
    let (decrypted_tx, decrypted_rx) = mpsc::channel();
    let request = session.request.clone();
    let decoder_queue = VmessGrpcEncryptedReader::new(Arc::clone(&encrypted_queue));
    let decoder = thread::spawn(move || {
        decode_vmess_grpc_response_stream(decoder_queue, request, decrypted_tx)
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
                                encrypted_queue.push(&payload);
                            }
                        }
                        let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                            &decrypted_rx,
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
                        encrypted_queue.close();
                        if !response_buf.is_empty() {
                            return Err("VMess gRPC response stream ended with partial hunk".to_owned());
                        }
                        let (plain_chunks, disconnected) = collect_vmess_grpc_decrypted(
                            &decrypted_rx,
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
                    &decrypted_rx,
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
            encrypted_queue.close();
            let _ = decoder.join();
            return Err(err);
        }
        if inbound_closed && response_closed && decoder_disconnected {
            break;
        }
    }
    encrypted_queue.close();
    let decoder_result = decoder
        .join()
        .map_err(|_| "join VMess gRPC response decoder failed".to_owned())?;
    if let Err(err) = decoder_result {
        return Err(err);
    }
    Ok(stats)
}

fn collect_vmess_grpc_decrypted(
    decrypted_rx: &mpsc::Receiver<Result<Vec<u8>, String>>,
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
            Err(mpsc::TryRecvError::Empty) => return (chunks, false),
            Err(mpsc::TryRecvError::Disconnected) => return (chunks, true),
        }
    }
}

async fn write_vmess_grpc_decrypted(
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

fn decode_vmess_grpc_response_stream(
    mut reader: VmessGrpcEncryptedReader,
    request: dae_outbound::vmess::VMessAeadTcpRequest,
    decrypted_tx: mpsc::Sender<Result<Vec<u8>, String>>,
) -> Result<(), String> {
    let mut response = match aead_tcp_response_reader_from_stream(&mut reader, &request) {
        Ok(response) => response,
        Err(err) => {
            let message = err.to_string();
            if is_vmess_grpc_graceful_decode_close(&message) {
                return Ok(());
            }
            let _ = decrypted_tx.send(Err(format!(
                "read VMess gRPC AEAD response header: {message}"
            )));
            return Ok(());
        }
    };
    loop {
        match response.read_chunk_from_stream(&mut reader) {
            Ok(plain) => {
                if decrypted_tx.send(Ok(plain)).is_err() {
                    return Ok(());
                }
            }
            Err(err) => {
                let message = err.to_string();
                if is_vmess_grpc_graceful_decode_close(&message) {
                    return Ok(());
                }
                let _ =
                    decrypted_tx.send(Err(format!("read VMess gRPC response chunk: {message}")));
                return Ok(());
            }
        }
    }
}

fn is_vmess_grpc_graceful_decode_close(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
}

#[derive(Default)]
struct VmessGrpcEncryptedQueue {
    inner: Mutex<VmessGrpcEncryptedQueueInner>,
    ready: Condvar,
}

#[derive(Default)]
struct VmessGrpcEncryptedQueueInner {
    bytes: VecDeque<u8>,
    closed: bool,
}

impl VmessGrpcEncryptedQueue {
    fn push(&self, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().expect("VMess gRPC queue poisoned");
        inner.bytes.extend(payload);
        self.ready.notify_all();
    }

    fn close(&self) {
        let mut inner = self.inner.lock().expect("VMess gRPC queue poisoned");
        inner.closed = true;
        self.ready.notify_all();
    }
}

struct VmessGrpcEncryptedReader {
    queue: Arc<VmessGrpcEncryptedQueue>,
}

impl VmessGrpcEncryptedReader {
    fn new(queue: Arc<VmessGrpcEncryptedQueue>) -> Self {
        Self { queue }
    }
}

impl Read for VmessGrpcEncryptedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self
            .queue
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("VMess gRPC encrypted queue lock poisoned"))?;
        while inner.bytes.is_empty() && !inner.closed {
            inner =
                self.queue.ready.wait(inner).map_err(|_| {
                    std::io::Error::other("VMess gRPC encrypted queue wait poisoned")
                })?;
        }
        if inner.bytes.is_empty() && inner.closed {
            return Ok(0);
        }
        let read = buf.len().min(inner.bytes.len());
        for slot in &mut buf[..read] {
            *slot = inner.bytes.pop_front().expect("queue length checked");
        }
        Ok(read)
    }
}

fn pop_grpc_hunk_payload(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err("compressed gRPC hunk is not admitted by resident relay".to_owned());
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    let payload = grpc_hunk_payload(&buffer[5..5 + len])
        .map_err(|err| format!("decode gRPC Hunk protobuf payload: {err}"))?;
    buffer.drain(..5 + len);
    Ok(Some(payload))
}

async fn relay_tcp_over_resident_tls_plain_async(
    inbound: &mut TokioTcpStream,
    client: &mut AsyncResidentTlsClient,
    stop: Arc<AtomicBool>,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut last_activity = Instant::now();
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        client
                            .write_plain_all(&inbound_buf[..read], "write client payload to proxy TLS")
                            .await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        client.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read inbound TCP for proxy TLS relay: {err}")),
                }
            }
            read = client.read_plain(&mut proxy_buf), if !proxy_closed => {
                match read {
                    Ok(0) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Ok(read) => {
                        if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                            if is_graceful_stream_close_error(&err) {
                                break;
                            }
                            return Err(format!("write proxy TLS payload to client: {err}"));
                        }
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        last_activity = Instant::now();
                    }
                    Err(err) if is_graceful_tls_plain_close_error(&err) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        last_activity = Instant::now();
                    }
                    Err(err) => return Err(format!("read proxy TLS plaintext: {err}")),
                }
            }
            _ = time::sleep(Duration::from_millis(100)) => {
                if last_activity.elapsed() > RESIDENT_TCP_IDLE_TIMEOUT {
                    return Err("resident proxy TLS relay idle timeout".to_owned());
                }
            }
        }

        if proxy_closed || (inbound_closed && proxy_closed) {
            break;
        }
    }
    Ok(stats)
}
