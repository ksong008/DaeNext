use super::*;

#[derive(Debug, Default)]
pub(super) struct TrojanGoInnerShadowsocksServerSummary {
    pub(super) accepted: usize,
    pub(super) decrypt_count: usize,
    pub(super) no_request_metadata_count: usize,
    pub(super) password_hash_match_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) response_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) targets: Vec<String>,
    pub(super) response_metadata_targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_trojan_go_inner_shadowsocks_server(
    opts: &Stage87Options,
    salt_len: usize,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<TrojanGoInnerShadowsocksServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp).map_err(|err| {
        format!("stage87 bind loopback trojan-go inner Shadowsocks server failed: {err}")
    })?;
    let local_addr = listener.local_addr().map_err(|err| {
        format!("stage87 trojan-go inner Shadowsocks server local_addr failed: {err}")
    })?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage87 trojan-go inner Shadowsocks listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage87 trojan-go inner Shadowsocks nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let shadowsocks_password = opts.shadowsocks_password.clone();
    let trojan_password = opts.trojan_password.clone();
    let target = opts.target.clone();
    let response_metadata_target = opts.response_metadata_target.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_trojan_go_inner_shadowsocks(
            listener,
            iterations,
            &cipher,
            &shadowsocks_password,
            &trojan_password,
            &target,
            &response_metadata_target,
            &payload,
            salt_len,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_trojan_go_inner_shadowsocks(
    listener: TcpListener,
    iterations: usize,
    cipher: &str,
    shadowsocks_password: &str,
    trojan_password: &str,
    expected_target: &str,
    response_metadata_target: &str,
    expected_payload: &[u8],
    salt_len: usize,
    timeout: Duration,
) -> Result<TrojanGoInnerShadowsocksServerSummary, String> {
    let mut summary = TrojanGoInnerShadowsocksServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage87 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage87 server set write timeout failed: {err}"))?;
                let server_salt = salt_for(summary.accepted, salt_len, 0x91);
                handle_trojan_go_inner_shadowsocks(
                    &mut stream,
                    cipher,
                    shadowsocks_password,
                    trojan_password,
                    expected_target,
                    response_metadata_target,
                    expected_payload,
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
                    "stage87 trojan-go inner Shadowsocks server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => {
                return Err(format!(
                    "stage87 trojan-go inner Shadowsocks accept failed: {err}"
                ));
            }
        }
    }
    Ok(summary)
}

fn handle_trojan_go_inner_shadowsocks(
    stream: &mut TcpStream,
    cipher: &str,
    shadowsocks_password: &str,
    trojan_password: &str,
    expected_target: &str,
    response_metadata_target: &str,
    expected_payload: &[u8],
    server_salt: &[u8],
    summary: &mut TrojanGoInnerShadowsocksServerSummary,
) -> Result<(), String> {
    let request = trojan::read_inner_shadowsocks_trojan_request_from_stream(
        stream,
        cipher,
        shadowsocks_password,
        expected_payload.len(),
    )
    .map_err(|err| format!("stage87 read inner Shadowsocks request failed: {err}"))?;
    let expected_hash = trojan::packet::password_sha224_hex(trojan_password);
    if request.request.password_sha224_hex != expected_hash {
        return Err("stage87 trojan-go inner Shadowsocks password SHA224 mismatch".to_owned());
    }
    if request.request.command != trojan::TrojanNetwork::Tcp.byte() {
        return Err(format!(
            "stage87 trojan-go inner Shadowsocks command mismatch: got {}, want {}",
            request.request.command,
            trojan::TrojanNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage87 trojan-go inner Shadowsocks target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage87 trojan-go inner Shadowsocks payload mismatch".to_owned());
    }
    let response = trojan::encode_inner_shadowsocks_response(
        cipher,
        shadowsocks_password,
        server_salt,
        response_metadata_target,
        &request.request.payload,
    )
    .map_err(|err| format!("stage87 encode inner Shadowsocks response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage87 write inner Shadowsocks response failed: {err}"))?;

    summary.decrypt_count += 1;
    if !request.inner_shadowsocks_request_metadata_present {
        summary.no_request_metadata_count += 1;
    }
    summary.password_hash_match_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.response_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(request.request.target);
    summary
        .response_metadata_targets
        .push(response_metadata_target.to_owned());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    Ok(())
}
