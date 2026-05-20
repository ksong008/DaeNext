use super::*;

#[derive(Debug, Default)]
pub(super) struct TrojanGoCombinationServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) websocket_upgrade_count: usize,
    pub(super) websocket_binary_request_count: usize,
    pub(super) inner_shadowsocks_decrypt_count: usize,
    pub(super) no_request_metadata_count: usize,
    pub(super) password_hash_match_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) response_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) targets: Vec<String>,
    pub(super) ws_hosts: Vec<String>,
    pub(super) ws_paths: Vec<String>,
    pub(super) response_metadata_targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
    pub(super) websocket_request_frame_lens: Vec<usize>,
}

pub(super) fn spawn_trojan_go_combination_server(
    opts: &Stage103Options,
    material: &shared_transport::TlsLoopbackMaterial,
    salt_len: usize,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<TrojanGoCombinationServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp).map_err(|err| {
        format!("stage103 bind loopback trojan-go combination server failed: {err}")
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage103 trojan-go combination server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage103 trojan-go combination listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage103 trojan-go combination nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let shadowsocks_password = opts.shadowsocks_password.clone();
    let trojan_password = opts.trojan_password.clone();
    let target = opts.target.clone();
    let response_metadata_target = opts.response_metadata_target.clone();
    let payload = opts.payload.clone();
    let expected_alpn = opts.alpn_protocol.clone();
    let ws_host = opts.ws_host.clone();
    let ws_path = opts.ws_path.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_trojan_go_combination(
            listener,
            iterations,
            &cipher,
            &shadowsocks_password,
            &trojan_password,
            &target,
            &response_metadata_target,
            &ws_host,
            &ws_path,
            &payload,
            &expected_alpn,
            salt_len,
            timeout,
            server_config,
        )
    });
    Ok((server_addr, listener_report, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_trojan_go_combination(
    listener: TcpListener,
    iterations: usize,
    cipher: &str,
    shadowsocks_password: &str,
    trojan_password: &str,
    expected_target: &str,
    response_metadata_target: &str,
    expected_ws_host: &str,
    expected_ws_path: &str,
    expected_payload: &[u8],
    expected_alpn: &str,
    salt_len: usize,
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<TrojanGoCombinationServerSummary, String> {
    let mut summary = TrojanGoCombinationServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage103 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage103 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage103 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                let server_salt = salt_for(summary.accepted, salt_len, 0x91);
                handle_trojan_go_combination(
                    &mut tls,
                    cipher,
                    shadowsocks_password,
                    trojan_password,
                    expected_target,
                    response_metadata_target,
                    expected_ws_host,
                    expected_ws_path,
                    expected_payload,
                    &server_salt,
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
                    "stage103 trojan-go combination server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => {
                return Err(format!(
                    "stage103 trojan-go combination accept failed: {err}"
                ));
            }
        }
    }
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn handle_trojan_go_combination<S>(
    stream: &mut S,
    cipher: &str,
    shadowsocks_password: &str,
    trojan_password: &str,
    expected_target: &str,
    response_metadata_target: &str,
    expected_ws_host: &str,
    expected_ws_path: &str,
    expected_payload: &[u8],
    server_salt: &[u8],
    summary: &mut TrojanGoCombinationServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage103 read WebSocket upgrade failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage103 WebSocket upgrade is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {expected_ws_path} HTTP/1.1\r\n")) {
        return Err("stage103 WebSocket upgrade path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {expected_ws_host}\r\n")) {
        return Err("stage103 WebSocket Host header mismatch".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage103 WebSocket Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                shared_transport::WS_ACCEPT_SAMPLE
            )
            .as_bytes(),
        )
        .map_err(|err| format!("stage103 write WebSocket upgrade response failed: {err}"))?;

    let websocket_payload = shared_transport::read_websocket_binary_frame(stream)
        .map_err(|err| format!("stage103 read WebSocket binary request failed: {err}"))?;
    let websocket_request_frame_len = websocket_payload.len();
    let mut cursor = std::io::Cursor::new(websocket_payload);
    let request = trojan::read_inner_shadowsocks_trojan_request_from_stream(
        &mut cursor,
        cipher,
        shadowsocks_password,
        expected_payload.len(),
    )
    .map_err(|err| format!("stage103 read inner Shadowsocks trojanc request failed: {err}"))?;
    if cursor.position() as usize != cursor.get_ref().len() {
        return Err(format!(
            "stage103 inner Shadowsocks request has trailing bytes: {}",
            cursor.get_ref().len() - cursor.position() as usize
        ));
    }
    let expected_hash = trojan::packet::password_sha224_hex(trojan_password);
    if request.request.password_sha224_hex != expected_hash {
        return Err("stage103 trojan-go combination password SHA224 mismatch".to_owned());
    }
    if request.request.command != trojan::TrojanNetwork::Tcp.byte() {
        return Err(format!(
            "stage103 trojan-go combination command mismatch: got {}, want {}",
            request.request.command,
            trojan::TrojanNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage103 trojan-go combination target mismatch: got {}, want {}",
            request.request.target, expected_target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage103 trojan-go combination payload mismatch".to_owned());
    }
    let response = trojan::trojan_go_wss_inner_shadowsocks_response_frame(
        cipher,
        shadowsocks_password,
        server_salt,
        response_metadata_target,
        &request.request.payload,
    )
    .map_err(|err| format!("stage103 encode WSS inner Shadowsocks response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage103 write WSS inner Shadowsocks response failed: {err}"))?;

    summary.websocket_upgrade_count += 1;
    summary.websocket_binary_request_count += 1;
    summary.inner_shadowsocks_decrypt_count += 1;
    if !request.inner_shadowsocks_request_metadata_present {
        summary.no_request_metadata_count += 1;
    }
    summary.password_hash_match_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.response_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(request.request.target);
    summary.ws_hosts.push(expected_ws_host.to_owned());
    summary.ws_paths.push(expected_ws_path.to_owned());
    summary
        .response_metadata_targets
        .push(response_metadata_target.to_owned());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .websocket_request_frame_lens
        .push(websocket_request_frame_len);
    Ok(())
}
