use super::*;

#[derive(Debug, Default)]
pub(super) struct Sip003SimpleObfsTlsServerSummary {
    pub(super) accepted: usize,
    pub(super) client_hello_count: usize,
    pub(super) sni_match_count: usize,
    pub(super) session_ticket_match_count: usize,
    pub(super) inner_decrypt_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) response_count: usize,
    pub(super) server_names: Vec<String>,
    pub(super) session_ticket_lengths: Vec<usize>,
    pub(super) client_hello_lengths: Vec<usize>,
    pub(super) targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
}

pub(super) fn spawn_sip003_simple_obfs_tls_server(
    opts: &Stage93Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<Sip003SimpleObfsTlsServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage93 bind loopback SIP003 simple-obfs TLS failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage93 SIP003 TLS server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage93 SIP003 TLS listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage93 SIP003 TLS server nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let server_name = opts.server_name.clone();
    let timeout = opts.timeout;
    let salt_len = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage93 AEAD cipher invalid: {err}"))?
        .salt_len;
    let handle = thread::spawn(move || {
        accept_sip003_simple_obfs_tls(
            listener,
            iterations,
            &cipher,
            &password,
            &target,
            &payload,
            &server_name,
            salt_len,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_sip003_simple_obfs_tls(
    listener: TcpListener,
    iterations: usize,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    server_name: &str,
    salt_len: usize,
    timeout: Duration,
) -> Result<Sip003SimpleObfsTlsServerSummary, String> {
    let mut summary = Sip003SimpleObfsTlsServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage93 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage93 server set write timeout failed: {err}"))?;
                let server_salt = salt_for(summary.accepted, salt_len, 0x71);
                handle_sip003_simple_obfs_tls(
                    &mut stream,
                    cipher,
                    password,
                    expected_target,
                    expected_payload,
                    server_name,
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
                    "stage93 SIP003 simple-obfs TLS server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => {
                return Err(format!(
                    "stage93 SIP003 simple-obfs TLS accept failed: {err}"
                ));
            }
        }
    }
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn handle_sip003_simple_obfs_tls(
    stream: &mut TcpStream,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    server_name: &str,
    server_salt: &[u8],
    summary: &mut Sip003SimpleObfsTlsServerSummary,
) -> Result<(), String> {
    let options = shadowsocks::Sip003SimpleObfsTlsOptions::new(server_name);
    let request = shadowsocks::read_simple_obfs_tls_client_hello(stream)
        .map_err(|err| format!("stage93 read simple-obfs TLS client hello failed: {err}"))?;
    if request.server_name != options.server_name {
        return Err(format!(
            "stage93 simple-obfs TLS SNI mismatch: got {}, want {}",
            request.server_name, options.server_name
        ));
    }
    if request.session_ticket_len != request.inner_payload.len() {
        return Err(format!(
            "stage93 simple-obfs TLS ticket length mismatch: got {}, body {}",
            request.session_ticket_len,
            request.inner_payload.len()
        ));
    }
    let (target, payload) =
        shadowsocks::decode_simple_obfs_tls_shadowsocks_request(&request, cipher, password)
            .map_err(|err| format!("stage93 decode inner Shadowsocks request failed: {err}"))?;
    if target != expected_target {
        return Err(format!(
            "stage93 inner Shadowsocks target mismatch: got {target}, want {expected_target}"
        ));
    }
    if payload != expected_payload {
        return Err("stage93 inner Shadowsocks payload mismatch".to_owned());
    }
    let response = shadowsocks::encode_simple_obfs_tls_shadowsocks_response(
        cipher,
        password,
        server_salt,
        &payload,
    )
    .map_err(|err| format!("stage93 encode simple-obfs TLS response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage93 write simple-obfs TLS response failed: {err}"))?;

    summary.client_hello_count += 1;
    summary.sni_match_count += 1;
    summary.session_ticket_match_count += 1;
    summary.inner_decrypt_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.response_count += 1;
    summary.server_names.push(request.server_name);
    summary
        .session_ticket_lengths
        .push(request.session_ticket_len);
    summary.client_hello_lengths.push(request.client_hello_len);
    summary.targets.push(target);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&payload).to_string());
    Ok(())
}
