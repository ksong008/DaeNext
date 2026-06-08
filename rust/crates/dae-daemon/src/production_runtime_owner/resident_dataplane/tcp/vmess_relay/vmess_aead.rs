use super::*;
pub(crate) fn relay_tcp_over_vmess_aead(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone VMess proxy stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for VMess upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VMess upload read timeout: {err}"))?;
    let relay_done = Arc::new(AtomicBool::new(false));
    let upload_done = Arc::clone(&relay_done);
    let mut upload_codec = session.upload;
    let upload = thread::spawn(move || {
        let mut stats = 0_usize;
        let mut buf = [0_u8; 16 * 1024];
        loop {
            if upload_done.load(Ordering::Relaxed) {
                break;
            }
            let read = match upload_inbound.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => return Err(format!("read inbound TCP for VMess upload: {err}")),
            };
            let encrypted = upload_codec
                .seal_chunk(&buf[..read])
                .map_err(|err| format!("encode VMess upload chunk: {err}"))?;
            if let Err(err) = upload_proxy.write_all(&encrypted) {
                if is_graceful_stream_close_error(&err) {
                    break;
                }
                return Err(format!("write VMess upload chunk: {err}"));
            }
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let mut response = match aead_tcp_response_reader_from_stream(proxy, &session.request) {
        Ok(response) => response,
        Err(err) => {
            relay_done.store(true, Ordering::Relaxed);
            let _ = inbound.shutdown(Shutdown::Read);
            let _ = proxy.shutdown(Shutdown::Write);
            let _ = upload.join();
            return Err(format!("read VMess AEAD response header: {err}"));
        }
    };
    let _response_header_len = response.response_header_len;

    let mut download_error = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match response.read_chunk_from_stream(proxy) {
            Ok(plain) => {
                if plain.is_empty() {
                    continue;
                }
                inbound
                    .write_all(&plain)
                    .map_err(|err| format!("write VMess response to inbound: {err}"))?;
                stats.direct_to_client += plain.len();
                metrics.add_download(plain.len());
            }
            Err(err) => {
                let message = err.to_string();
                if message.contains("early eof")
                    || message.contains("failed to fill whole buffer")
                    || message.contains("Connection reset")
                    || message.contains("connection reset")
                    || message.contains("timed out")
                {
                    break;
                }
                download_error = Some(format!("read VMess response chunk: {message}"));
                break;
            }
        }
    }
    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy.shutdown(Shutdown::Write);
    let upload_bytes = upload
        .join()
        .map_err(|_| "join VMess upload relay thread failed".to_owned())??;
    if let Some(err) = download_error {
        return Err(err);
    }
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}

pub(crate) fn relay_tcp_over_vmess_websocket_aead(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone VMess WebSocket proxy stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for VMess WebSocket upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set VMess WebSocket upload read timeout: {err}"))?;
    let relay_done = Arc::new(AtomicBool::new(false));
    let upload_done = Arc::clone(&relay_done);
    let mut upload_codec = session.upload;
    let upload = thread::spawn(move || {
        let mut stats = 0_usize;
        let mut buf = [0_u8; 16 * 1024];
        loop {
            if upload_done.load(Ordering::Relaxed) {
                break;
            }
            let read = match upload_inbound.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) if is_graceful_stream_close_error(&err) => break,
                Err(err) => {
                    return Err(format!(
                        "read inbound TCP for VMess WebSocket upload: {err}"
                    ));
                }
            };
            let encrypted = upload_codec
                .seal_chunk(&buf[..read])
                .map_err(|err| format!("encode VMess WebSocket upload chunk: {err}"))?;
            write_websocket_binary_frame_to_stream(
                &mut upload_proxy,
                &encrypted,
                "write VMess websocket upload frame",
            )?;
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let download_result = {
        let mut ws_reader = WebSocketPayloadReader::new(proxy);
        let mut response =
            aead_tcp_response_reader_from_stream(&mut ws_reader, &session.request)
                .map_err(|err| format!("read VMess WebSocket AEAD response header: {err}"))?;
        let _response_header_len = response.response_header_len;

        let mut download_error = None;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match response.read_chunk_from_stream(&mut ws_reader) {
                Ok(plain) => {
                    if plain.is_empty() {
                        continue;
                    }
                    inbound.write_all(&plain).map_err(|err| {
                        format!("write VMess WebSocket response to inbound: {err}")
                    })?;
                    stats.direct_to_client += plain.len();
                    metrics.add_download(plain.len());
                }
                Err(err) => {
                    let message = err.to_string();
                    if message.contains("early eof")
                        || message.contains("failed to fill whole buffer")
                        || message.contains("Connection reset")
                        || message.contains("connection reset")
                        || message.contains("timed out")
                    {
                        break;
                    }
                    download_error =
                        Some(format!("read VMess WebSocket response chunk: {message}"));
                    break;
                }
            }
        }
        if let Some(err) = download_error {
            Err(err)
        } else {
            Ok(())
        }
    };

    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy.shutdown(Shutdown::Write);
    let upload_bytes = upload
        .join()
        .map_err(|_| "join VMess WebSocket upload relay thread failed".to_owned())??;
    download_result?;
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}
