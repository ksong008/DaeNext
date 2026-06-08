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

pub(crate) fn collect_vmess_grpc_decrypted(
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

pub(crate) fn decode_vmess_grpc_response_stream(
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

pub(crate) fn is_vmess_grpc_graceful_decode_close(message: &str) -> bool {
    message.contains("early eof")
        || message.contains("failed to fill whole buffer")
        || message.contains("Connection reset")
        || message.contains("connection reset")
        || message.contains("timed out")
}

#[derive(Default)]
pub(crate) struct VmessGrpcEncryptedQueue {
    pub(super) inner: Mutex<VmessGrpcEncryptedQueueInner>,
    pub(super) ready: Condvar,
}

#[derive(Default)]
pub(crate) struct VmessGrpcEncryptedQueueInner {
    pub(super) bytes: VecDeque<u8>,
    pub(super) closed: bool,
}

impl VmessGrpcEncryptedQueue {
    pub(super) fn push(&self, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().expect("VMess gRPC queue poisoned");
        inner.bytes.extend(payload);
        self.ready.notify_all();
    }

    pub(super) fn close(&self) {
        let mut inner = self.inner.lock().expect("VMess gRPC queue poisoned");
        inner.closed = true;
        self.ready.notify_all();
    }
}

pub(crate) struct VmessGrpcEncryptedReader {
    pub(super) queue: Arc<VmessGrpcEncryptedQueue>,
}

impl VmessGrpcEncryptedReader {
    pub(super) fn new(queue: Arc<VmessGrpcEncryptedQueue>) -> Self {
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
