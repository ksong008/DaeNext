use super::*;

#[derive(Debug, Default)]
pub(super) struct ShadowsocksRServerSummary {
    pub(super) accepted: usize,
    pub(super) obfs_layer_count: usize,
    pub(super) stream_cipher_count: usize,
    pub(super) protocol_wrapper_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) response_count: usize,
    pub(super) targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) obfs_request_payload_lengths: Vec<usize>,
    pub(super) stream_iv_lengths: Vec<usize>,
    pub(super) stream_key_lengths: Vec<usize>,
}

pub(super) fn spawn_shadowsocksr_server(
    opts: &Stage95Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<ShadowsocksRServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage95 bind loopback ShadowsocksR failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage95 ShadowsocksR server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage95 ShadowsocksR listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage95 ShadowsocksR server nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let password = opts.password.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let obfs_host = opts.obfs_host.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_shadowsocksr(
            listener,
            iterations,
            &cipher,
            &password,
            &target,
            &payload,
            &obfs_host,
            server_addr.port(),
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_shadowsocksr(
    listener: TcpListener,
    iterations: usize,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    obfs_host: &str,
    obfs_port: u16,
    timeout: Duration,
) -> Result<ShadowsocksRServerSummary, String> {
    let mut summary = ShadowsocksRServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage95 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage95 server set write timeout failed: {err}"))?;
                let options = shadowsocks::ShadowsocksRThreeLayerOptions::http_simple_origin(
                    obfs_host,
                    obfs_port,
                    iv_for(summary.accepted, 0x45),
                    iv_for(summary.accepted, 0x95),
                );
                handle_shadowsocksr(
                    &mut stream,
                    cipher,
                    password,
                    expected_target,
                    expected_payload,
                    &options,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage95 ShadowsocksR server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage95 ShadowsocksR accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_shadowsocksr(
    stream: &mut TcpStream,
    cipher: &str,
    password: &str,
    expected_target: &str,
    expected_payload: &[u8],
    options: &shadowsocks::ShadowsocksRThreeLayerOptions,
    summary: &mut ShadowsocksRServerSummary,
) -> Result<(), String> {
    let request =
        shadowsocks::read_shadowsocksr_http_simple_request(stream, cipher, password, options)
            .map_err(|err| format!("stage95 read ShadowsocksR request failed: {err}"))?;
    if request.target != expected_target {
        return Err(format!(
            "stage95 ShadowsocksR target mismatch: got {}, want {}",
            request.target, expected_target
        ));
    }
    if request.payload != expected_payload {
        return Err("stage95 ShadowsocksR payload mismatch".to_owned());
    }
    let response = shadowsocks::encode_shadowsocksr_http_simple_response(
        cipher,
        password,
        &options.server_iv,
        &request.payload,
    )
    .map_err(|err| format!("stage95 encode ShadowsocksR response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage95 write ShadowsocksR response failed: {err}"))?;
    stream
        .flush()
        .map_err(|err| format!("stage95 flush ShadowsocksR response failed: {err}"))?;

    summary.obfs_layer_count += 1;
    summary.stream_cipher_count += 1;
    summary.protocol_wrapper_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.response_count += 1;
    summary.targets.push(request.target);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    summary
        .obfs_request_payload_lengths
        .push(request.obfs_request_payload_len);
    summary.stream_iv_lengths.push(request.stream_iv_len);
    summary.stream_key_lengths.push(request.stream_key_len);
    Ok(())
}
