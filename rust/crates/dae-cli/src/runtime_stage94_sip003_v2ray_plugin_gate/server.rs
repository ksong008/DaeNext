use std::sync::Arc;

use rustls::{ServerConfig, ServerConnection};

use super::*;

#[derive(Debug, Default)]
pub(super) struct Sip003V2rayPluginServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) websocket_handshake_count: usize,
    pub(super) websocket_host_match_count: usize,
    pub(super) mux_new_frame_count: usize,
    pub(super) mux_data_frame_count: usize,
    pub(super) inner_decrypt_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) response_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) ws_hosts: Vec<String>,
    pub(super) ws_paths: Vec<String>,
    pub(super) mux_ids: Vec<String>,
    pub(super) mux_metadata_lengths: Vec<usize>,
    pub(super) websocket_payload_lengths: Vec<usize>,
    pub(super) targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
}

pub(super) fn spawn_sip003_v2ray_plugin_server(
    opts: &Stage94Options,
    plugin_options: &shadowsocks::Sip003V2rayPluginOptions,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<Sip003V2rayPluginServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage94 bind loopback SIP003 v2ray-plugin failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage94 SIP003 v2ray-plugin server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage94 SIP003 v2ray-plugin listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage94 SIP003 v2ray-plugin server nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let ws_host = plugin_options.ws_host.clone();
    let ws_path = plugin_options.ws_path.clone();
    let mux_id = plugin_options.mux.id;
    let server_config = Arc::clone(&material.server_config);
    let salt_len = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage94 AEAD cipher invalid: {err}"))?
        .salt_len;
    let handle = thread::spawn(move || {
        accept_sip003_v2ray_plugin(
            listener,
            iterations,
            server_config,
            &cipher,
            &password,
            &target,
            &payload,
            &ws_host,
            &ws_path,
            mux_id,
            salt_len,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_sip003_v2ray_plugin(
    listener: TcpListener,
    iterations: usize,
    server_config: Arc<ServerConfig>,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    expected_ws_host: &str,
    expected_ws_path: &str,
    mux_id: [u8; 2],
    salt_len: usize,
    timeout: Duration,
) -> Result<Sip003V2rayPluginServerSummary, String> {
    let mut summary = Sip003V2rayPluginServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage94 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage94 server set write timeout failed: {err}"))?;
                let server_salt = salt_for(summary.accepted, salt_len, 0x81);
                handle_sip003_v2ray_plugin(
                    stream,
                    Arc::clone(&server_config),
                    cipher,
                    password,
                    expected_target,
                    expected_payload,
                    expected_ws_host,
                    expected_ws_path,
                    mux_id,
                    &server_salt,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage94 SIP003 v2ray-plugin server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => {
                return Err(format!("stage94 SIP003 v2ray-plugin accept failed: {err}"));
            }
        }
    }
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn handle_sip003_v2ray_plugin(
    stream: TcpStream,
    server_config: Arc<ServerConfig>,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    expected_ws_host: &str,
    expected_ws_path: &str,
    mux_id: [u8; 2],
    server_salt: &[u8],
    summary: &mut Sip003V2rayPluginServerSummary,
) -> Result<(), String> {
    let conn = ServerConnection::new(server_config)
        .map_err(|err| format!("stage94 TLS server accept failed: {err}"))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let request_head = shared_transport::read_http_head(&mut tls)
        .map_err(|err| format!("stage94 read WebSocket handshake failed: {err}"))?;
    let request_text = std::str::from_utf8(&request_head)
        .map_err(|err| format!("stage94 WebSocket request is not UTF-8: {err}"))?;
    let request_line = request_text
        .split("\r\n")
        .next()
        .ok_or_else(|| "stage94 empty WebSocket request".to_owned())?;
    let expected_request_line = format!("GET {expected_ws_path} HTTP/1.1");
    if request_line != expected_request_line {
        return Err(format!(
            "stage94 WebSocket request line mismatch: got {request_line}, want {expected_request_line}"
        ));
    }
    let host = header_value(request_text, "Host")
        .ok_or_else(|| "stage94 WebSocket Host header missing".to_owned())?;
    if host != expected_ws_host {
        return Err(format!(
            "stage94 WebSocket Host mismatch: got {host}, want {expected_ws_host}"
        ));
    }
    tls.write_all(
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            shared_transport::WS_ACCEPT_SAMPLE
        )
        .as_bytes(),
    )
    .map_err(|err| format!("stage94 write WebSocket handshake response failed: {err}"))?;
    tls.flush()
        .map_err(|err| format!("stage94 flush WebSocket handshake response failed: {err}"))?;

    let request =
        shadowsocks::read_v2ray_plugin_muxed_shadowsocks_request(&mut tls, cipher, password)
            .map_err(|err| format!("stage94 read muxed Shadowsocks request failed: {err}"))?;
    validate_go_mux_default(&request, mux_id)?;
    if request.target != expected_target {
        return Err(format!(
            "stage94 inner Shadowsocks target mismatch: got {}, want {}",
            request.target, expected_target
        ));
    }
    if request.payload != expected_payload {
        return Err("stage94 inner Shadowsocks payload mismatch".to_owned());
    }
    let response = shadowsocks::encode_v2ray_plugin_muxed_shadowsocks_response(
        cipher,
        password,
        server_salt,
        request.mux_data.id,
        &request.payload,
    )
    .map_err(|err| format!("stage94 encode muxed Shadowsocks response failed: {err}"))?;
    tls.write_all(&response)
        .map_err(|err| format!("stage94 write muxed Shadowsocks response failed: {err}"))?;
    tls.flush()
        .map_err(|err| format!("stage94 flush muxed Shadowsocks response failed: {err}"))?;

    summary.tls_handshake_count += 1;
    summary.websocket_handshake_count += 1;
    summary.websocket_host_match_count += 1;
    summary.mux_new_frame_count += 1;
    summary.mux_data_frame_count += 1;
    summary.inner_decrypt_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.response_count += 1;
    summary
        .selected_alpns
        .push(selected_alpn(tls.conn.alpn_protocol()));
    summary.ws_hosts.push(host.to_owned());
    summary.ws_paths.push(expected_ws_path.to_owned());
    summary.mux_ids.push(hex_encode(&request.mux_new.id));
    summary
        .mux_metadata_lengths
        .push(request.mux_new.metadata.len());
    summary
        .websocket_payload_lengths
        .push(request.websocket_payload_len);
    summary.targets.push(request.target);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    Ok(())
}

fn validate_go_mux_default(
    request: &shadowsocks::Sip003V2rayPluginRequest,
    expected_id: [u8; 2],
) -> Result<(), String> {
    if request.mux_new.id != expected_id || request.mux_data.id != expected_id {
        return Err("stage94 mux id mismatch".to_owned());
    }
    let metadata = &request.mux_new.metadata;
    if metadata.len() != 12 {
        return Err(format!(
            "stage94 mux metadata length mismatch: got {}, want 12",
            metadata.len()
        ));
    }
    if metadata[4] != 0x01 || &metadata[5..7] != [0, 0] || metadata[7] != 0x01 {
        return Err("stage94 mux tcp/port/address-type metadata mismatch".to_owned());
    }
    if &metadata[8..12] != [127, 0, 0, 1] {
        return Err("stage94 mux host metadata mismatch".to_owned());
    }
    Ok(())
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}:");
    headers.split("\r\n").find_map(|line| {
        line.strip_prefix(&prefix)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn selected_alpn(protocol: Option<&[u8]>) -> String {
    protocol
        .map(|value| String::from_utf8_lossy(value).to_string())
        .unwrap_or_default()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
