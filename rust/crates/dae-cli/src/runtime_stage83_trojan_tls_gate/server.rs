use super::*;

#[derive(Debug, Default)]
pub(super) struct TrojanTlsServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) password_hash_match_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_trojan_tls_server(
    opts: &Stage83Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<TrojanTlsServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage83 bind loopback trojan tls server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage83 trojan tls server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage83 trojan tls listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage83 trojan tls nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let expected_alpn = opts.alpn_protocol.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_trojan_tls(
            listener,
            iterations,
            &password,
            &target,
            &payload,
            &expected_alpn,
            timeout,
            server_config,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_trojan_tls(
    listener: TcpListener,
    iterations: usize,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    expected_alpn: &str,
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<TrojanTlsServerSummary, String> {
    let mut summary = TrojanTlsServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage83 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage83 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage83 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                handle_trojan_tls(
                    &mut tls,
                    password,
                    expected_target,
                    expected_payload,
                    &mut summary,
                )?;
                let selected_alpn = tls
                    .conn
                    .alpn_protocol()
                    .map(|value| String::from_utf8_lossy(value).to_string())
                    .unwrap_or_default();
                if selected_alpn == expected_alpn {
                    summary.alpn_validated_count += 1;
                }
                summary.selected_alpns.push(selected_alpn);
                summary.tls_handshake_count += 1;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage83 trojan tls server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage83 trojan tls accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_trojan_tls<S>(
    stream: &mut S,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    summary: &mut TrojanTlsServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let request = trojan::read_tcp_request_from_stream(stream, expected_payload.len())
        .map_err(|err| format!("stage83 read trojan tls request failed: {err}"))?;
    let expected_hash = trojan::packet::password_sha224_hex(password);
    if request.password_sha224_hex != expected_hash {
        return Err("stage83 trojan tls password SHA224 mismatch".to_owned());
    }
    if request.command != trojan::TrojanNetwork::Tcp.byte() {
        return Err(format!(
            "stage83 trojan tls command mismatch: got {}, want {}",
            request.command,
            trojan::TrojanNetwork::Tcp.byte()
        ));
    }
    if request.target != expected_target {
        return Err(format!(
            "stage83 trojan tls target mismatch: got {}, want {}",
            request.target, expected_target
        ));
    }
    if request.payload != expected_payload {
        return Err("stage83 trojan tls payload mismatch".to_owned());
    }
    stream
        .write_all(&request.payload)
        .map_err(|err| format!("stage83 write trojan tls echo failed: {err}"))?;
    summary.password_hash_match_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(request.target);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    Ok(())
}
