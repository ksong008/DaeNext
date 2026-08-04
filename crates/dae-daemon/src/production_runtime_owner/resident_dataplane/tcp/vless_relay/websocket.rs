use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
pub(crate) async fn relay_tcp_over_vless_websocket_tls_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncVlessTlsClient,
    stop: SharedResidentStopSignal,
    initial_payload_len: usize,
    metrics: &ResidentDataplaneMetrics,
) -> Result<RelayStats, RelayError> {
    let (progress, activity) = resident_duplex_progress();
    if initial_payload_len != 0 {
        progress.record_upload(initial_payload_len);
    }
    let response_header_stripped = Arc::new(AtomicBool::new(false));
    let (control_tx, mut control_rx) = websocket_control_channel();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (client_read, client_write) = tokio::io::split(&mut *client);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut client_write = client_write;
        let mut buffer = [0_u8; RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE];
        loop {
            tokio::select! {
                biased;
                control = control_rx.recv() => {
                    let Some(control) = control else {
                        return Ok(());
                    };
                    write_websocket_control_response(
                        &mut client_write,
                        control,
                        "VLESS websocket",
                    ).await?;
                }
                read = inbound_read.read(&mut buffer) => {
                    let read = match read {
                        Ok(0) => {
                            return Ok(());
                        }
                        Ok(read) => read,
                        Err(err) if is_graceful_stream_close_error(&err) => {
                            return Ok(());
                        }
                        Err(err) => return Err(format!("read inbound TCP: {err}")),
                    };
                    write_websocket_binary_frame_in_place_to_async_stream(
                        &mut client_write,
                        &mut buffer[..read],
                        "write client payload websocket frame",
                    ).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
            }
        }
    };
    let download_progress = progress.clone();
    let download_header_state = Arc::clone(&response_header_stripped);
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut client_read = client_read;
        let mut stripper = VlessResponseStripper::default();
        let mut decoder = WebSocketBinaryFrameDecoder::default();
        let mut buffer = [0_u8; RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE];
        loop {
            let read = match client_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) => {
                    let snapshot = download_progress.snapshot();
                    let current = RelayStats {
                        client_to_proxy: snapshot.client_to_direct,
                        proxy_to_client: snapshot.direct_to_client,
                        response_header_stripped: download_header_state.load(Ordering::Acquire),
                        ..RelayStats::default()
                    };
                    if is_graceful_vless_response_tls_plain_close_error(&err, &current) {
                        let _ = inbound_write.shutdown().await;
                        return Ok(());
                    }
                    return Err(format!("read websocket TLS plaintext: {err}"));
                }
            };
            decoder.extend(&buffer[..read])?;
            while let Some(frame) = decoder.next_message()? {
                let payload = stripper.consume(frame)?;
                download_header_state.store(stripper.done, Ordering::Release);
                if !payload.is_empty() {
                    inbound_write
                        .write_all(&payload)
                        .await
                        .map_err(|err| format!("write VLESS websocket payload to client: {err}"))?;
                    download_progress.record_download(payload.len());
                    metrics.add_download(payload.len());
                }
            }
            queue_websocket_control_responses(&mut decoder, &control_tx, "VLESS websocket").await?;
            if decoder.is_closed() {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            }
        }
    };
    let result = run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident websocket relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await;
    let snapshot = progress.snapshot();
    let stats = RelayStats {
        client_to_proxy: snapshot.client_to_direct,
        proxy_to_client: snapshot.direct_to_client,
        response_header_stripped: response_header_stripped.load(Ordering::Acquire),
        ..RelayStats::default()
    };
    result
        .map(|_| stats.clone())
        .map_err(|error| RelayError::new(error, &stats))
}

pub(crate) async fn relay_tcp_over_trojan_websocket_tls_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    client: &mut AsyncResidentTlsClient,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    let (control_tx, mut control_rx) = websocket_control_channel();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (client_read, client_write) = tokio::io::split(&mut *client);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut client_write = client_write;
        let mut buffer = [0_u8; RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE];
        loop {
            tokio::select! {
                biased;
                control = control_rx.recv() => {
                    let Some(control) = control else {
                        return Ok(());
                    };
                    write_websocket_control_response(
                        &mut client_write,
                        control,
                        "Trojan websocket",
                    ).await?;
                }
                read = inbound_read.read(&mut buffer) => {
                    let read = match read {
                        Ok(0) => {
                            return Ok(());
                        }
                        Ok(read) => read,
                        Err(err) if is_graceful_stream_close_error(&err) => {
                            return Ok(());
                        }
                        Err(err) => return Err(format!("read inbound TCP for Trojan websocket relay: {err}")),
                    };
                    write_websocket_binary_frame_in_place_to_async_stream(
                        &mut client_write,
                        &mut buffer[..read],
                        "write client payload websocket frame",
                    ).await?;
                    upload_progress.record_upload(read);
                    metrics.add_upload(read);
                }
            }
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut client_read = client_read;
        let mut decoder = WebSocketBinaryFrameDecoder::default();
        let mut buffer = [0_u8; RESIDENT_WEBSOCKET_RELAY_BUFFER_SIZE];
        loop {
            let read = client_read
                .read(&mut buffer)
                .await
                .map_err(|err| format!("read Trojan websocket TLS plaintext: {err}"))?;
            if read == 0 {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            }
            decoder
                .extend(&buffer[..read])
                .map_err(|err| format!("decode Trojan websocket frame: {err}"))?;
            while let Some(payload) = decoder
                .next_message()
                .map_err(|err| format!("decode Trojan websocket frame: {err}"))?
            {
                if payload.is_empty() {
                    continue;
                }
                if let Err(err) = inbound_write.write_all(payload).await {
                    if is_graceful_stream_close_error(&err) {
                        return Ok(());
                    }
                    return Err(format!("write Trojan websocket payload to client: {err}"));
                }
                download_progress.record_download(payload.len());
                metrics.add_download(payload.len());
            }
            queue_websocket_control_responses(&mut decoder, &control_tx, "Trojan websocket")
                .await?;
            if decoder.is_closed() {
                let _ = inbound_write.shutdown().await;
                return Ok(());
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident Trojan websocket relay idle timeout",
        Some(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT),
    )
    .await
}
