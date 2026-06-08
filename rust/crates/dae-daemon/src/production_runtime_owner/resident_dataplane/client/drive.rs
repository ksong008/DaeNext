use super::*;
pub(crate) fn drive_tls_io_record_aware(
    client: &mut VlessTlsClient,
) -> Result<TlsDriveOutcome, String> {
    match &mut client.engine {
        VlessTlsEngine::Rustls {
            tcp,
            conn,
            tls_records,
        }
        | VlessTlsEngine::RealityRustls {
            tcp,
            conn,
            tls_records,
        } => {
            let mut progressed = false;
            while conn.wants_write() {
                match conn.write_tls(tcp) {
                    Ok(0) => break,
                    Ok(_) => progressed = true,
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(err) => return Err(format!("write VLESS TLS record: {err}")),
                }
            }
            if conn.wants_read() {
                match tls_records.read_one(conn, tcp)? {
                    TlsDriveOutcome::Progressed(read_progressed) => progressed |= read_progressed,
                    error @ TlsDriveOutcome::DecryptErrorRawRecord { .. } => return Ok(error),
                }
            }
            Ok(TlsDriveOutcome::Progressed(progressed))
        }
        VlessTlsEngine::Boring {
            tls,
            pending_plaintext,
        } => Ok(TlsDriveOutcome::Progressed(
            flush_boring_writes_nonblocking(tls, pending_plaintext)?,
        )),
    }
}

pub(crate) fn flush_tls_writes(
    client: &mut VlessTlsClient,
    stop: &AtomicBool,
) -> Result<(), String> {
    match &mut client.engine {
        VlessTlsEngine::Rustls { tcp, conn, .. }
        | VlessTlsEngine::RealityRustls { tcp, conn, .. } => flush_rustls_writes(tcp, conn, stop),
        VlessTlsEngine::Boring {
            tls,
            pending_plaintext,
        } => {
            let started = Instant::now();
            while !pending_plaintext.is_empty() && !stop.load(Ordering::Relaxed) {
                match tls.write(pending_plaintext) {
                    Ok(0) => {
                        return Err("flush VLESS BoringSSL writes: wrote zero bytes".to_owned());
                    }
                    Ok(written) => {
                        pending_plaintext.drain(..written);
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
                            return Err("flush VLESS BoringSSL writes timeout".to_owned());
                        }
                        thread::sleep(RESIDENT_IDLE_SLEEP);
                    }
                    Err(err) => return Err(format!("flush VLESS BoringSSL writes: {err}")),
                }
            }
            tls.flush()
                .map_err(|err| format!("flush VLESS BoringSSL stream: {err}"))
        }
    }
}

pub(crate) fn flush_rustls_writes(
    tcp: &mut ResidentTcpStream,
    conn: &mut ClientConnection,
    stop: &AtomicBool,
) -> Result<(), String> {
    let started = Instant::now();
    while conn.wants_write() && !stop.load(Ordering::Relaxed) {
        match conn.write_tls(tcp) {
            Ok(0) => return Err("flush VLESS TLS writes: wrote zero bytes".to_owned()),
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
                    return Err("flush VLESS TLS writes timeout".to_owned());
                }
                thread::sleep(RESIDENT_IDLE_SLEEP);
            }
            Err(err) => return Err(format!("flush VLESS TLS writes: {err}")),
        }
    }
    Ok(())
}

pub(crate) fn flush_boring_writes_nonblocking(
    tls: &mut SslStream<TcpStream>,
    pending_plaintext: &mut Vec<u8>,
) -> Result<bool, String> {
    let mut progressed = false;
    while !pending_plaintext.is_empty() {
        match tls.write(pending_plaintext) {
            Ok(0) => {
                return Err("flush VLESS BoringSSL writes: wrote zero bytes".to_owned());
            }
            Ok(written) => {
                pending_plaintext.drain(..written);
                progressed = true;
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                break;
            }
            Err(err) => return Err(format!("flush VLESS BoringSSL writes: {err}")),
        }
    }
    Ok(progressed)
}

pub(crate) fn drive_tls_io_blocking(client: &mut VlessTlsClient) -> Result<(), String> {
    match &mut client.engine {
        VlessTlsEngine::Rustls { tcp, conn, .. }
        | VlessTlsEngine::RealityRustls { tcp, conn, .. } => {
            let started = Instant::now();
            loop {
                match conn.complete_io(tcp) {
                    Ok(_) if !conn.is_handshaking() && !conn.wants_write() => return Ok(()),
                    Ok(_) => {}
                    Err(err)
                        if matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) && started.elapsed() <= RESIDENT_CONNECT_TIMEOUT => {}
                    Err(err) => return Err(format!("drive VLESS TLS handshake: {err}")),
                }
                if started.elapsed() > RESIDENT_CONNECT_TIMEOUT {
                    return Err("VLESS TLS handshake timeout".to_owned());
                }
            }
        }
        VlessTlsEngine::Boring { .. } => Ok(()),
    }
}

pub(crate) fn tls_underlay_name(client: &VlessTlsClient) -> &'static str {
    match &client.engine {
        VlessTlsEngine::Rustls { .. } => "rustls",
        VlessTlsEngine::RealityRustls { .. } => "reality",
        VlessTlsEngine::Boring { .. } => "boringssl",
    }
}

pub(crate) fn async_tls_underlay_name(client: &AsyncVlessTlsClient) -> &'static str {
    match &client.engine {
        AsyncVlessTlsEngine::Rustls { .. } => "rustls",
        AsyncVlessTlsEngine::RealityRustls { .. } => "reality",
        AsyncVlessTlsEngine::Boring { .. } => "boringssl",
    }
}

pub(crate) fn async_resident_tls_underlay_name(client: &AsyncResidentTlsClient) -> &'static str {
    async_tls_underlay_name(client)
}
