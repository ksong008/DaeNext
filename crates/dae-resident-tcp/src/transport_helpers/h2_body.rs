use super::*;
use bytes::BytesMut;

const H2_UPLOAD_READ_CHUNK: usize = 16 * 1024;

pub async fn open_h2_body_stream(
    binding: &ResidentProxyBinding,
    first_payload: &[u8],
    context: &str,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream, H2CarrierLease), String> {
    let initial_chunks = if first_payload.is_empty() {
        Vec::new()
    } else {
        vec![Bytes::copy_from_slice(first_payload)]
    };
    open_h2_body_stream_with_initial_chunks(binding, initial_chunks, context).await
}

pub async fn open_h2_body_stream_with_initial_chunks(
    binding: &ResidentProxyBinding,
    initial_chunks: Vec<Bytes>,
    context: &str,
) -> Result<(h2::SendStream<Bytes>, h2::RecvStream, H2CarrierLease), String> {
    let proxy = binding.plan();
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = acquire_h2_carrier(binding.clone(), deadline).await?;
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

pub async fn open_h2_body_stream_with_deferred_response(
    binding: &ResidentProxyBinding,
    initial_chunks: Vec<Bytes>,
    context: &'static str,
) -> Result<
    (
        h2::SendStream<Bytes>,
        H2CarrierResponseFuture,
        H2CarrierLease,
    ),
    String,
> {
    let proxy = binding.plan();
    let deadline =
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = acquire_h2_carrier(binding.clone(), deadline).await?;
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
    Ok((send_stream, response, lease))
}

// Deferred H2 relay keeps stream halves, state, metrics, and protocol toggles explicit.
#[allow(clippy::too_many_arguments)]
pub async fn relay_tcp_over_deferred_h2_body(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    send_stream: &mut h2::SendStream<Bytes>,
    response: H2CarrierResponseFuture,
    stop: SharedResidentStopSignal,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
    strip_vless_response_header: bool,
    context: &'static str,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    if stats.direct_to_client != 0 {
        progress.record_download(stats.direct_to_client);
    }
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut buffer = BytesMut::with_capacity(H2_UPLOAD_READ_CHUNK);
        loop {
            match read_h2_upload_chunk(&mut inbound_read, &mut buffer).await {
                Ok(None) => {
                    send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                    return Ok(());
                }
                Ok(Some(chunk)) => {
                    let read = chunk.len();
                    send_h2_data_with_context(send_stream, chunk, false, context).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
                Err(err) if is_graceful_stream_close_error(&err) => {
                    send_h2_data_with_context(send_stream, Bytes::new(), true, context).await?;
                    return Ok(());
                }
                Err(err) => return Err(format!("read inbound TCP for {context} relay: {err}")),
            }
        }
    };
    let download_progress = progress.clone();
    let download = async move {
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
        let mut recv_stream = response.into_body();
        let mut inbound_write = inbound_write;
        let mut vless_response_stripper =
            strip_vless_response_header.then(VlessResponseStripper::default);
        loop {
            let Some(data) = recv_stream.data().await else {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            };
            let bytes =
                data.map_err(|err| format!("read {context} HTTP/2 response data: {err}"))?;
            recv_stream
                .flow_control()
                .release_capacity(bytes.len())
                .map_err(|err| format!("release {context} HTTP/2 response capacity: {err}"))?;
            let payload = if let Some(stripper) = vless_response_stripper.as_mut() {
                stripper.consume(&bytes)?
            } else {
                std::borrow::Cow::Borrowed(bytes.as_ref())
            };
            if !payload.is_empty() {
                inbound_write
                    .write_all(&payload)
                    .await
                    .map_err(|err| format!("write {context} response to inbound: {err}"))?;
                download_progress.record_download(payload.len());
                metrics.add_download(payload.len());
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident HTTP/2 body relay idle timeout",
        None,
    )
    .await
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

pub async fn relay_tcp_over_vmess_h2_body(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    send_stream: &mut h2::SendStream<Bytes>,
    recv_stream: &mut h2::RecvStream,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    if stats.direct_to_client != 0 {
        progress.record_download(stats.direct_to_client);
    }
    let mut upload_codec = session.upload;
    let mut response = VmessAeadResponseBuffer::new(session.request);
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        loop {
            let mut buffer = upload_codec.new_owned_chunk_buffer(0);
            let read = match (&mut inbound_read)
                .take(VMESS_AEAD_TCP_MAX_PAYLOAD_SIZE as u64)
                .read_buf(&mut buffer)
                .await
            {
                Ok(0) => {
                    send_h2_data_with_context(send_stream, Bytes::new(), true, "VMess H2").await?;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    send_h2_data_with_context(send_stream, Bytes::new(), true, "VMess H2").await?;
                    return Ok(());
                }
                Err(err) => return Err(format!("read inbound TCP for VMess H2 relay: {err}")),
            };
            let wire_len = upload_codec
                .seal_owned_chunk_in_place(&mut buffer, 0, read)
                .map_err(|err| format!("encode VMess H2 upload chunk: {err}"))?;
            buffer.truncate(wire_len);
            send_h2_data_with_context(send_stream, Bytes::from(buffer), false, "VMess H2").await?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        loop {
            let Some(data) = recv_stream.data().await else {
                if !response.response_header_received() {
                    return Err("VMess H2 closed before the response header".to_owned());
                }
                let _ = inbound_write.shutdown().await;
                return Ok(());
            };
            let bytes = data.map_err(|err| format!("read VMess H2 response data: {err}"))?;
            recv_stream
                .flow_control()
                .release_capacity(bytes.len())
                .map_err(|err| format!("release VMess H2 response capacity: {err}"))?;
            response.extend_from_slice(&bytes)?;
            while let Some(plain) = response.next_chunk()? {
                if plain.is_empty() {
                    continue;
                }
                inbound_write
                    .write_all(plain)
                    .await
                    .map_err(|err| format!("write VMess H2 response to inbound: {err}"))?;
                download_progress.record_download(plain.len());
                metrics.add_download(plain.len());
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident VMess H2 relay idle timeout",
        None,
    )
    .await
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
