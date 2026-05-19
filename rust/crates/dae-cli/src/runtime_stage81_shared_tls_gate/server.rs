use super::*;

#[derive(Debug, Default)]
pub(super) struct SharedTlsServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_shared_tls_server(
    opts: &Stage81Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<SharedTlsServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage81 bind loopback shared TLS server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage81 shared TLS server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage81 shared TLS listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage81 shared TLS nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let expected_payload_len = opts.payload.len();
    let expected_alpn = opts.alpn_protocol.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        let mut summary = SharedTlsServerSummary::default();
        let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
        while summary.accepted < iterations {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(timeout))
                        .map_err(|err| format!("stage81 server set read timeout failed: {err}"))?;
                    stream
                        .set_write_timeout(Some(timeout))
                        .map_err(|err| format!("stage81 server set write timeout failed: {err}"))?;
                    let observation = shared_transport::tls_server_echo(
                        stream,
                        server_config.clone(),
                        expected_payload_len,
                    )
                    .map_err(|err| format!("stage81 shared TLS server exchange failed: {err}"))?;
                    if observation.selected_alpn == expected_alpn {
                        summary.alpn_validated_count += 1;
                    }
                    if observation.tls_handshake_validated {
                        summary.tls_handshake_count += 1;
                    }
                    if observation.payload_roundtrip_validated {
                        summary.payload_roundtrip_count += 1;
                    }
                    summary.selected_alpns.push(observation.selected_alpn);
                    summary
                        .payload_ascii
                        .push(String::from_utf8_lossy(&observation.echoed_payload).to_string());
                    summary
                        .response_ascii
                        .push(String::from_utf8_lossy(&observation.echoed_payload).to_string());
                    summary.accepted += 1;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    return Err(format!(
                        "stage81 shared TLS server timed out after accepting {} of {} connections",
                        summary.accepted, iterations
                    ));
                }
                Err(err) => return Err(format!("stage81 shared TLS accept failed: {err}")),
            }
        }
        Ok(summary)
    });
    Ok((server_addr, listener_report, handle))
}
