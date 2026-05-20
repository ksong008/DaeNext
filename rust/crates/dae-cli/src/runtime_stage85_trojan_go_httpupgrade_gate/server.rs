use super::*;

#[derive(Debug, Default)]
pub(super) struct TrojanGoHttpUpgradeServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) httpupgrade_count: usize,
    pub(super) password_hash_match_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) targets: Vec<String>,
    pub(super) httpupgrade_hosts: Vec<String>,
    pub(super) httpupgrade_paths: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_trojan_go_httpupgrade_server(
    opts: &Stage85Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<TrojanGoHttpUpgradeServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp).map_err(|err| {
        format!("stage85 bind loopback trojan-go HTTPUpgrade server failed: {err}")
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage85 trojan-go HTTPUpgrade server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage85 trojan-go HTTPUpgrade listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage85 trojan-go HTTPUpgrade nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let expected_alpn = opts.alpn_protocol.clone();
    let httpupgrade_host = opts.httpupgrade_host.clone();
    let httpupgrade_path = opts.httpupgrade_path.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_trojan_go_httpupgrade(
            listener,
            iterations,
            &password,
            &target,
            &httpupgrade_host,
            &httpupgrade_path,
            &payload,
            &expected_alpn,
            timeout,
            server_config,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_trojan_go_httpupgrade(
    listener: TcpListener,
    iterations: usize,
    password: &str,
    expected_target: &str,
    expected_httpupgrade_host: &str,
    expected_httpupgrade_path: &str,
    expected_payload: &[u8],
    expected_alpn: &str,
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<TrojanGoHttpUpgradeServerSummary, String> {
    let mut summary = TrojanGoHttpUpgradeServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage85 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage85 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage85 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                handle_trojan_go_httpupgrade(
                    &mut tls,
                    password,
                    expected_target,
                    expected_httpupgrade_host,
                    expected_httpupgrade_path,
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
                    "stage85 trojan-go HTTPUpgrade server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => {
                return Err(format!(
                    "stage85 trojan-go HTTPUpgrade accept failed: {err}"
                ));
            }
        }
    }
    Ok(summary)
}

fn handle_trojan_go_httpupgrade<S>(
    stream: &mut S,
    password: &str,
    expected_target: &str,
    expected_httpupgrade_host: &str,
    expected_httpupgrade_path: &str,
    expected_payload: &[u8],
    summary: &mut TrojanGoHttpUpgradeServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage85 read HTTPUpgrade request failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage85 HTTPUpgrade request is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {expected_httpupgrade_path} HTTP/1.1\r\n")) {
        return Err("stage85 HTTPUpgrade path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {expected_httpupgrade_host}\r\n")) {
        return Err("stage85 HTTPUpgrade Host header mismatch".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage85 HTTPUpgrade Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .map_err(|err| format!("stage85 write HTTPUpgrade response failed: {err}"))?;
    let request = trojan::read_tcp_request_from_stream(stream, expected_payload.len())
        .map_err(|err| format!("stage85 read trojan-go HTTPUpgrade request failed: {err}"))?;
    let expected_hash = trojan::packet::password_sha224_hex(password);
    if request.password_sha224_hex != expected_hash {
        return Err("stage85 trojan-go HTTPUpgrade password SHA224 mismatch".to_owned());
    }
    if request.command != trojan::TrojanNetwork::Tcp.byte() {
        return Err(format!(
            "stage85 trojan-go HTTPUpgrade command mismatch: got {}, want {}",
            request.command,
            trojan::TrojanNetwork::Tcp.byte()
        ));
    }
    if request.target != expected_target {
        return Err(format!(
            "stage85 trojan-go HTTPUpgrade target mismatch: got {}, want {}",
            request.target, expected_target
        ));
    }
    if request.payload != expected_payload {
        return Err("stage85 trojan-go HTTPUpgrade payload mismatch".to_owned());
    }
    stream
        .write_all(&request.payload)
        .map_err(|err| format!("stage85 write trojan-go HTTPUpgrade echo failed: {err}"))?;

    summary.httpupgrade_count += 1;
    summary.password_hash_match_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(request.target);
    summary
        .httpupgrade_hosts
        .push(expected_httpupgrade_host.to_owned());
    summary
        .httpupgrade_paths
        .push(expected_httpupgrade_path.to_owned());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    Ok(())
}
