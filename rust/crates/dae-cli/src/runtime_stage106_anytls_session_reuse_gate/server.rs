use super::*;

#[derive(Debug, Default)]
pub(super) struct AnyTlsSessionReuseServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) auth_key_match_count: usize,
    pub(super) logical_stream_count: usize,
    pub(super) settings_frame_count: usize,
    pub(super) syn_frame_count: usize,
    pub(super) psh_target_frame_count: usize,
    pub(super) psh_payload_frame_count: usize,
    pub(super) synack_response_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) fin_frame_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) stream_sids: Vec<u32>,
    pub(super) targets: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
    pub(super) settings_frame_lens: Vec<usize>,
    pub(super) psh_target_frame_lens: Vec<usize>,
    pub(super) psh_payload_frame_lens: Vec<usize>,
    pub(super) fin_frame_lens: Vec<usize>,
}

pub(super) fn spawn_anytls_session_reuse_server(
    opts: &Stage106Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<AnyTlsSessionReuseServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage106 bind loopback anytls server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage106 anytls server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage106 anytls listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage106 anytls nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let auth = opts.auth.clone();
    let first_target = opts.first_target.clone();
    let second_target = opts.second_target.clone();
    let first_payload = opts.first_payload.clone();
    let second_payload = opts.second_payload.clone();
    let expected_alpn = opts.alpn_protocol.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_anytls_session_reuse(
            listener,
            iterations,
            &auth,
            &first_target,
            &second_target,
            &first_payload,
            &second_payload,
            &expected_alpn,
            timeout,
            server_config,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_anytls_session_reuse(
    listener: TcpListener,
    iterations: usize,
    auth: &str,
    expected_first_target: &str,
    expected_second_target: &str,
    expected_first_payload: &[u8],
    expected_second_payload: &[u8],
    expected_alpn: &str,
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<AnyTlsSessionReuseServerSummary, String> {
    let mut summary = AnyTlsSessionReuseServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage106 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage106 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage106 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                handle_anytls_session_reuse(
                    &mut tls,
                    auth,
                    expected_first_target,
                    expected_second_target,
                    expected_first_payload,
                    expected_second_payload,
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
                    "stage106 anytls server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage106 anytls accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_anytls_session_reuse<S>(
    stream: &mut S,
    auth: &str,
    expected_first_target: &str,
    expected_second_target: &str,
    expected_first_payload: &[u8],
    expected_second_payload: &[u8],
    summary: &mut AnyTlsSessionReuseServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let expected_auth = anytls::link::handshake_auth_bytes(auth);
    let mut auth_handshake = vec![0_u8; expected_auth.len()];
    stream
        .read_exact(&mut auth_handshake)
        .map_err(|err| format!("stage106 read anytls auth handshake failed: {err}"))?;
    if auth_handshake != expected_auth {
        return Err("stage106 anytls auth key mismatch".to_owned());
    }
    summary.auth_key_match_count += 1;

    handle_logical_stream(
        stream,
        1,
        expected_first_target,
        expected_first_payload,
        summary,
    )?;
    handle_logical_stream(
        stream,
        2,
        expected_second_target,
        expected_second_payload,
        summary,
    )?;
    Ok(())
}

fn handle_logical_stream<S>(
    stream: &mut S,
    expected_sid: u32,
    expected_target: &str,
    expected_payload: &[u8],
    summary: &mut AnyTlsSessionReuseServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let settings = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage106 read anytls settings frame failed: {err}"))?;
    if settings.cmd != anytls::contract::CMD_SETTINGS
        || settings.sid != expected_sid
        || settings.data != anytls::link::settings_bytes()
    {
        return Err("stage106 anytls settings frame mismatch".to_owned());
    }
    let syn = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage106 read anytls SYN frame failed: {err}"))?;
    if syn.cmd != anytls::contract::CMD_SYN || syn.sid != expected_sid || !syn.data.is_empty() {
        return Err("stage106 anytls SYN frame mismatch".to_owned());
    }
    let psh_target = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage106 read anytls target PSH frame failed: {err}"))?;
    if psh_target.cmd != anytls::contract::CMD_PSH || psh_target.sid != expected_sid {
        return Err("stage106 anytls target PSH frame mismatch".to_owned());
    }
    let (target, consumed) = Socks5Address::decode(&psh_target.data)
        .map_err(|err| format!("stage106 anytls target address decode failed: {err}"))?;
    if consumed != psh_target.data.len() {
        return Err("stage106 anytls target address trailing bytes".to_owned());
    }
    if target.authority() != expected_target {
        return Err(format!(
            "stage106 anytls target mismatch: got {}, want {}",
            target.authority(),
            expected_target
        ));
    }
    anytls::write_frame_to_stream(stream, anytls::contract::CMD_SYNACK, expected_sid, &[])
        .map_err(|err| format!("stage106 write anytls SYNACK failed: {err}"))?;

    let psh_payload = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage106 read anytls payload PSH frame failed: {err}"))?;
    if psh_payload.cmd != anytls::contract::CMD_PSH
        || psh_payload.sid != expected_sid
        || psh_payload.data != expected_payload
    {
        return Err("stage106 anytls payload PSH frame mismatch".to_owned());
    }
    anytls::write_frame_to_stream(
        stream,
        anytls::contract::CMD_PSH,
        expected_sid,
        &psh_payload.data,
    )
    .map_err(|err| format!("stage106 write anytls payload echo failed: {err}"))?;

    let fin = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage106 read anytls FIN frame failed: {err}"))?;
    if fin.cmd != anytls::contract::CMD_FIN || fin.sid != expected_sid || !fin.data.is_empty() {
        return Err("stage106 anytls FIN frame mismatch".to_owned());
    }

    summary.logical_stream_count += 1;
    summary.settings_frame_count += 1;
    summary.syn_frame_count += 1;
    summary.psh_target_frame_count += 1;
    summary.psh_payload_frame_count += 1;
    summary.synack_response_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.fin_frame_count += 1;
    summary.stream_sids.push(expected_sid);
    summary.targets.push(target.authority());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&psh_payload.data).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&psh_payload.data).to_string());
    summary
        .settings_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + settings.data.len());
    summary
        .psh_target_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + psh_target.data.len());
    summary
        .psh_payload_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + psh_payload.data.len());
    summary
        .fin_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + fin.data.len());
    Ok(())
}
