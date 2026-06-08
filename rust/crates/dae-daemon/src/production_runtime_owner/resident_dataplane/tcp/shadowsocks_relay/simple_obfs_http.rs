use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) fn relay_tcp_over_shadowsocks_simple_obfs_http(
    inbound: &mut TcpStream,
    proxy: &mut TcpStream,
    stop: &AtomicBool,
    target: &str,
    cipher: &str,
    password: &str,
    salt_len: usize,
    initial_payload: &[u8],
    metrics: &ResidentDataplaneMetrics,
    host: &str,
    path: &str,
) -> Result<DirectTcpRelayStats, String> {
    let target_metadata = ShadowsocksMetadata::parse(target)
        .map_err(|err| format!("parse Shadowsocks simple-obfs target: {err}"))?;
    let mut first_plain = target_metadata
        .encode()
        .map_err(|err| format!("encode Shadowsocks simple-obfs target metadata: {err}"))?;
    first_plain.extend_from_slice(initial_payload);
    let mut client_salt = vec![0_u8; salt_len];
    fastrand::fill(&mut client_salt);
    let mut encoder = AeadStreamCodec::new(cipher, password, &client_salt)
        .map_err(|err| format!("create Shadowsocks simple-obfs upload encoder: {err}"))?;
    let mut encrypted_initial = client_salt.clone();
    encrypted_initial.extend(
        encoder
            .encrypt_chunk(&first_plain)
            .map_err(|err| format!("encode Shadowsocks simple-obfs initial frame: {err}"))?,
    );
    let options = Sip003SimpleObfsHttpOptions::new(host, path);
    let obfs_request = simple_obfs_http_request_with_body(&options, &encrypted_initial);
    proxy
        .write_all(&obfs_request)
        .map_err(|err| format!("write Shadowsocks simple-obfs request: {err}"))?;
    let (response_head, response_leftover) = read_http_head_and_leftover_from_stream(proxy)
        .map_err(|err| format!("read Shadowsocks simple-obfs response head: {err}"))?;
    validate_simple_obfs_http_response_status(&response_head)
        .map_err(|err| format!("validate Shadowsocks simple-obfs response status: {err}"))?;

    let mut stats = DirectTcpRelayStats::default();
    if !initial_payload.is_empty() {
        stats.client_to_direct += initial_payload.len();
        metrics.add_upload(initial_payload.len());
    }

    let mut upload_proxy = proxy
        .try_clone()
        .map_err(|err| format!("clone Shadowsocks simple-obfs stream for upload: {err}"))?;
    let mut upload_inbound = inbound
        .try_clone()
        .map_err(|err| format!("clone inbound stream for Shadowsocks simple-obfs upload: {err}"))?;
    upload_inbound
        .set_read_timeout(Some(RESIDENT_CONNECT_TIMEOUT))
        .map_err(|err| format!("set Shadowsocks simple-obfs upload read timeout: {err}"))?;
    let relay_done = Arc::new(AtomicBool::new(false));
    let upload_done = Arc::clone(&relay_done);
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
                        "read inbound TCP for Shadowsocks simple-obfs upload: {err}"
                    ));
                }
            };
            let encrypted = encoder
                .encrypt_chunk(&buf[..read])
                .map_err(|err| format!("encrypt Shadowsocks simple-obfs upload chunk: {err}"))?;
            if let Err(err) = upload_proxy.write_all(&encrypted) {
                if is_graceful_stream_close_error(&err) {
                    break;
                }
                return Err(format!("write Shadowsocks simple-obfs upload chunk: {err}"));
            }
            stats += read;
        }
        let _ = upload_proxy.shutdown(Shutdown::Write);
        Ok::<usize, String>(stats)
    });

    let mut proxy_reader = PrefixTcpReader::new(response_leftover, proxy);
    let mut server_salt = vec![0_u8; salt_len];
    if let Err(err) = proxy_reader.read_exact(&mut server_salt) {
        relay_done.store(true, Ordering::Relaxed);
        let _ = inbound.shutdown(Shutdown::Read);
        let _ = proxy_reader.shutdown_write();
        let _ = upload.join();
        return Err(format!("read Shadowsocks simple-obfs server salt: {err}"));
    }
    let mut decoder = match AeadStreamCodec::new(cipher, password, &server_salt) {
        Ok(decoder) => decoder,
        Err(err) => {
            relay_done.store(true, Ordering::Relaxed);
            let _ = inbound.shutdown(Shutdown::Read);
            let _ = proxy_reader.shutdown_write();
            let _ = upload.join();
            return Err(format!(
                "create Shadowsocks simple-obfs response decoder: {err}"
            ));
        }
    };

    let mut download_error = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match read_encrypted_chunk_from_stream(&mut proxy_reader, &mut decoder) {
            Ok(plain) => {
                if plain.is_empty() {
                    continue;
                }
                inbound
                    .write_all(&plain)
                    .map_err(|err| format!("write Shadowsocks simple-obfs response: {err}"))?;
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
                download_error = Some(format!("read Shadowsocks simple-obfs response: {message}"));
                break;
            }
        }
    }
    relay_done.store(true, Ordering::Relaxed);
    let _ = inbound.shutdown(Shutdown::Read);
    let _ = proxy_reader.shutdown_write();
    let upload_bytes = upload
        .join()
        .map_err(|_| "join Shadowsocks simple-obfs upload relay thread failed".to_owned())??;
    if let Some(err) = download_error {
        return Err(err);
    }
    if upload_bytes > 0 {
        stats.client_to_direct += upload_bytes;
        metrics.add_upload(upload_bytes);
    }
    Ok(stats)
}
