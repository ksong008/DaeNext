use super::*;
use bytes::BytesMut;

const H2_UPLOAD_READ_CHUNK: usize = 16 * 1024;

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
