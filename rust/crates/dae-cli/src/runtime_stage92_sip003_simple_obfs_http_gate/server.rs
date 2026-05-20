use super::*;

#[derive(Debug, Default)]
pub(super) struct Sip003SimpleObfsHttpServerSummary {
    pub(super) accepted: usize,
    pub(super) http_request_count: usize,
    pub(super) host_match_count: usize,
    pub(super) path_match_count: usize,
    pub(super) content_length_match_count: usize,
    pub(super) inner_decrypt_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) response_count: usize,
    pub(super) request_lines: Vec<String>,
    pub(super) hosts: Vec<String>,
    pub(super) paths: Vec<String>,
    pub(super) content_lengths: Vec<usize>,
    pub(super) targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
}

pub(super) fn spawn_sip003_simple_obfs_http_server(
    opts: &Stage92Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<Sip003SimpleObfsHttpServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage92 bind loopback SIP003 simple-obfs HTTP failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage92 SIP003 server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage92 SIP003 listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage92 SIP003 server nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let plugin_host = opts.plugin_host.clone();
    let plugin_path = opts.plugin_path.clone();
    let timeout = opts.timeout;
    let salt_len = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage92 AEAD cipher invalid: {err}"))?
        .salt_len;
    let handle = thread::spawn(move || {
        accept_sip003_simple_obfs_http(
            listener,
            iterations,
            &cipher,
            &password,
            &target,
            &payload,
            &plugin_host,
            &plugin_path,
            salt_len,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_sip003_simple_obfs_http(
    listener: TcpListener,
    iterations: usize,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    plugin_host: &str,
    plugin_path: &str,
    salt_len: usize,
    timeout: Duration,
) -> Result<Sip003SimpleObfsHttpServerSummary, String> {
    let mut summary = Sip003SimpleObfsHttpServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage92 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage92 server set write timeout failed: {err}"))?;
                let server_salt = salt_for(summary.accepted, salt_len, 0x61);
                handle_sip003_simple_obfs_http(
                    &mut stream,
                    cipher,
                    password,
                    expected_target,
                    expected_payload,
                    plugin_host,
                    plugin_path,
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
                    "stage92 SIP003 simple-obfs HTTP server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => {
                return Err(format!(
                    "stage92 SIP003 simple-obfs HTTP accept failed: {err}"
                ));
            }
        }
    }
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn handle_sip003_simple_obfs_http(
    stream: &mut TcpStream,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    plugin_host: &str,
    plugin_path: &str,
    server_salt: &[u8],
    summary: &mut Sip003SimpleObfsHttpServerSummary,
) -> Result<(), String> {
    let options = shadowsocks::Sip003SimpleObfsHttpOptions::new(plugin_host, plugin_path);
    let request = shadowsocks::read_simple_obfs_http_request(stream)
        .map_err(|err| format!("stage92 read simple-obfs HTTP request failed: {err}"))?;
    let expected_request_line = format!("GET {} HTTP/1.1", options.path);
    if request.request_line != expected_request_line {
        return Err(format!(
            "stage92 simple-obfs request line mismatch: got {}, want {expected_request_line}",
            request.request_line
        ));
    }
    if request.host != options.host {
        return Err(format!(
            "stage92 simple-obfs host mismatch: got {}, want {}",
            request.host, options.host
        ));
    }
    if request.path != options.path {
        return Err(format!(
            "stage92 simple-obfs path mismatch: got {}, want {}",
            request.path, options.path
        ));
    }
    if request.content_length != request.inner_payload.len() {
        return Err(format!(
            "stage92 simple-obfs content length mismatch: got {}, body {}",
            request.content_length,
            request.inner_payload.len()
        ));
    }
    let (target, payload) =
        shadowsocks::decode_simple_obfs_http_shadowsocks_request(&request, cipher, password)
            .map_err(|err| format!("stage92 decode inner Shadowsocks request failed: {err}"))?;
    if target != expected_target {
        return Err(format!(
            "stage92 inner Shadowsocks target mismatch: got {target}, want {expected_target}"
        ));
    }
    if payload != expected_payload {
        return Err("stage92 inner Shadowsocks payload mismatch".to_owned());
    }
    let response = shadowsocks::encode_simple_obfs_http_shadowsocks_response(
        cipher,
        password,
        server_salt,
        &payload,
    )
    .map_err(|err| format!("stage92 encode simple-obfs Shadowsocks response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage92 write simple-obfs Shadowsocks response failed: {err}"))?;

    summary.http_request_count += 1;
    summary.host_match_count += 1;
    summary.path_match_count += 1;
    summary.content_length_match_count += 1;
    summary.inner_decrypt_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.response_count += 1;
    summary.request_lines.push(request.request_line);
    summary.hosts.push(request.host);
    summary.paths.push(request.path);
    summary.content_lengths.push(request.content_length);
    summary.targets.push(target);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&payload).to_string());
    Ok(())
}
