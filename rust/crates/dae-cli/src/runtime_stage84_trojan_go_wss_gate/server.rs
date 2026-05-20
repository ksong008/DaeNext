use super::*;

#[derive(Debug, Default)]
pub(super) struct TrojanGoWssServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) websocket_upgrade_count: usize,
    pub(super) websocket_binary_request_count: usize,
    pub(super) password_hash_match_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) targets: Vec<String>,
    pub(super) ws_hosts: Vec<String>,
    pub(super) ws_paths: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
    pub(super) websocket_request_frame_lens: Vec<usize>,
}

pub(super) fn spawn_trojan_go_wss_server(
    opts: &Stage84Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<TrojanGoWssServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage84 bind loopback trojan-go WSS server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage84 trojan-go WSS server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage84 trojan-go WSS listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage84 trojan-go WSS nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let expected_alpn = opts.alpn_protocol.clone();
    let ws_host = opts.ws_host.clone();
    let ws_path = opts.ws_path.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_trojan_go_wss(
            listener,
            iterations,
            &password,
            &target,
            &ws_host,
            &ws_path,
            &payload,
            &expected_alpn,
            timeout,
            server_config,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_trojan_go_wss(
    listener: TcpListener,
    iterations: usize,
    password: &str,
    expected_target: &str,
    expected_ws_host: &str,
    expected_ws_path: &str,
    expected_payload: &[u8],
    expected_alpn: &str,
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<TrojanGoWssServerSummary, String> {
    let mut summary = TrojanGoWssServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage84 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage84 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage84 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                handle_trojan_go_wss(
                    &mut tls,
                    password,
                    expected_target,
                    expected_ws_host,
                    expected_ws_path,
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
                    "stage84 trojan-go WSS server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage84 trojan-go WSS accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_trojan_go_wss<S>(
    stream: &mut S,
    password: &str,
    expected_target: &str,
    expected_ws_host: &str,
    expected_ws_path: &str,
    expected_payload: &[u8],
    summary: &mut TrojanGoWssServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage84 read WebSocket upgrade failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage84 WebSocket upgrade is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {expected_ws_path} HTTP/1.1\r\n")) {
        return Err("stage84 WebSocket upgrade path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {expected_ws_host}\r\n")) {
        return Err("stage84 WebSocket Host header mismatch".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage84 WebSocket Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                shared_transport::WS_ACCEPT_SAMPLE
            )
            .as_bytes(),
        )
        .map_err(|err| format!("stage84 write WebSocket upgrade response failed: {err}"))?;
    let request = trojan::read_tcp_request_from_websocket_stream(stream, expected_payload.len())
        .map_err(|err| format!("stage84 read trojan-go WSS request failed: {err}"))?;
    let expected_hash = trojan::packet::password_sha224_hex(password);
    if request.request.password_sha224_hex != expected_hash {
        return Err("stage84 trojan-go WSS password SHA224 mismatch".to_owned());
    }
    if request.request.command != trojan::TrojanNetwork::Tcp.byte() {
        return Err(format!(
            "stage84 trojan-go WSS command mismatch: got {}, want {}",
            request.request.command,
            trojan::TrojanNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage84 trojan-go WSS target mismatch: got {}, want {}",
            request.request.target, expected_target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage84 trojan-go WSS payload mismatch".to_owned());
    }
    let response = shared_transport::websocket_server_binary_frame(&request.request.payload)
        .map_err(|err| format!("stage84 encode WebSocket response frame failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage84 write trojan-go WSS echo failed: {err}"))?;

    summary.websocket_upgrade_count += 1;
    summary.websocket_binary_request_count += 1;
    summary.password_hash_match_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(request.request.target);
    summary.ws_hosts.push(expected_ws_host.to_owned());
    summary.ws_paths.push(expected_ws_path.to_owned());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .websocket_request_frame_lens
        .push(request.websocket_request_frame_len);
    Ok(())
}
