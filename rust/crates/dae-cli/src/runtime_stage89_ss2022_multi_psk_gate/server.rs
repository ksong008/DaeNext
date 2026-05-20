use super::*;

#[derive(Debug, Default)]
pub(super) struct Ss2022MultiPskServerSummary {
    pub(super) accepted: usize,
    pub(super) decrypt_count: usize,
    pub(super) multi_psk_count: usize,
    pub(super) upsk_last_count: usize,
    pub(super) identity_header_count: usize,
    pub(super) identity_header_bytes_len: usize,
    pub(super) identity_header_validated_count: usize,
    pub(super) request_header_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) request_salt_echo_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
}

pub(super) fn spawn_ss2022_multi_psk_server(
    opts: &Stage89Options,
    salt_len: usize,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<Ss2022MultiPskServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage89 bind loopback SS2022 multi-PSK server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage89 SS2022 multi-PSK server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage89 SS2022 multi-PSK listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage89 SS2022 multi-PSK nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_ss2022_multi_psk(
            listener, iterations, &cipher, &password, &target, &payload, salt_len, timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_ss2022_multi_psk(
    listener: TcpListener,
    iterations: usize,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    salt_len: usize,
    timeout: Duration,
) -> Result<Ss2022MultiPskServerSummary, String> {
    let mut summary = Ss2022MultiPskServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage89 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage89 server set write timeout failed: {err}"))?;
                let request_salt = salt_for(summary.accepted, salt_len, 0x51);
                let server_salt = salt_for(summary.accepted, salt_len, 0xa1);
                handle_ss2022_multi_psk(
                    &mut stream,
                    cipher,
                    password,
                    expected_target,
                    expected_payload,
                    &request_salt,
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
                    "stage89 SS2022 multi-PSK server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage89 SS2022 multi-PSK accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_ss2022_multi_psk(
    stream: &mut TcpStream,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    request_salt: &[u8],
    server_salt: &[u8],
    summary: &mut Ss2022MultiPskServerSummary,
) -> Result<(), String> {
    let request = shadowsocks::read_ss2022_tcp_multi_psk_client_request_from_stream(
        stream,
        cipher,
        password,
        expected_payload.len(),
    )
    .map_err(|err| format!("stage89 read SS2022 multi-PSK request failed: {err}"))?;
    if request.target != expected_target {
        return Err(format!(
            "stage89 SS2022 multi-PSK target mismatch: got {}, want {expected_target}",
            request.target
        ));
    }
    if request.payload != expected_payload {
        return Err("stage89 SS2022 multi-PSK payload mismatch".to_owned());
    }
    if request.request_salt_len != request_salt.len() {
        return Err(format!(
            "stage89 SS2022 multi-PSK request salt len mismatch: got {}, want {}",
            request.request_salt_len,
            request_salt.len()
        ));
    }
    let response = shadowsocks::encode_ss2022_tcp_multi_psk_server_response(
        cipher,
        password,
        server_salt,
        request_salt,
        &request.payload,
        1_765_000_089,
    )
    .map_err(|err| format!("stage89 encode SS2022 multi-PSK response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage89 write SS2022 multi-PSK response failed: {err}"))?;

    summary.decrypt_count += 1;
    if request.psk_count >= 2 {
        summary.multi_psk_count += 1;
    }
    if request.upsk_index == request.psk_count.saturating_sub(1) {
        summary.upsk_last_count += 1;
    }
    summary.identity_header_count += request.identity_header_count;
    summary.identity_header_bytes_len += request.identity_header_bytes_len;
    if request.identity_header_validated {
        summary.identity_header_validated_count += 1;
    }
    if request.request_header_type == shadowsocks::ss2022::HEADER_TYPE_CLIENT_STREAM {
        summary.request_header_count += 1;
    }
    summary.target_metadata_count += 1;
    summary.request_salt_echo_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(request.target);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    Ok(())
}
