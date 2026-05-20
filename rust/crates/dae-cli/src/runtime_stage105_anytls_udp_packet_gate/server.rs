use super::*;

#[derive(Debug, Default)]
pub(super) struct AnyTlsUdpPacketServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) alpn_validated_count: usize,
    pub(super) auth_key_match_count: usize,
    pub(super) settings_frame_count: usize,
    pub(super) syn_frame_count: usize,
    pub(super) psh_magic_target_frame_count: usize,
    pub(super) first_packet_frame_count: usize,
    pub(super) next_packet_frame_count: usize,
    pub(super) synack_response_count: usize,
    pub(super) first_packet_response_count: usize,
    pub(super) next_packet_response_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) stream_targets: Vec<String>,
    pub(super) original_udp_targets: Vec<String>,
    pub(super) first_payload_ascii: Vec<String>,
    pub(super) next_payload_ascii: Vec<String>,
    pub(super) response_first_ascii: Vec<String>,
    pub(super) response_next_ascii: Vec<String>,
    pub(super) settings_frame_lens: Vec<usize>,
    pub(super) psh_magic_target_frame_lens: Vec<usize>,
    pub(super) first_packet_frame_lens: Vec<usize>,
    pub(super) next_packet_frame_lens: Vec<usize>,
}

pub(super) fn spawn_anytls_udp_packet_server(
    opts: &Stage105Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<AnyTlsUdpPacketServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage105 bind loopback anytls server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage105 anytls server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage105 anytls listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage105 anytls nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let auth = opts.auth.clone();
    let original_udp_target = opts.original_udp_target.clone();
    let first_payload = opts.first_payload.clone();
    let next_payload = opts.next_payload.clone();
    let expected_alpn = opts.alpn_protocol.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_anytls_udp_packet_session(
            listener,
            iterations,
            &auth,
            &original_udp_target,
            &first_payload,
            &next_payload,
            &expected_alpn,
            timeout,
            server_config,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_anytls_udp_packet_session(
    listener: TcpListener,
    iterations: usize,
    auth: &str,
    expected_original_udp_target: &str,
    expected_first_payload: &[u8],
    expected_next_payload: &[u8],
    expected_alpn: &str,
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<AnyTlsUdpPacketServerSummary, String> {
    let mut summary = AnyTlsUdpPacketServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage105 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage105 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage105 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                handle_anytls_udp_packet_session(
                    &mut tls,
                    auth,
                    expected_original_udp_target,
                    expected_first_payload,
                    expected_next_payload,
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
                    "stage105 anytls server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage105 anytls accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_anytls_udp_packet_session<S>(
    stream: &mut S,
    auth: &str,
    expected_original_udp_target: &str,
    expected_first_payload: &[u8],
    expected_next_payload: &[u8],
    summary: &mut AnyTlsUdpPacketServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let expected_session_target = anytls::link::udp_stream_target(expected_original_udp_target)
        .map_err(|err| format!("stage105 build expected UDP stream target failed: {err}"))?;
    let expected_auth = anytls::link::handshake_auth_bytes(auth);
    let mut auth_handshake = vec![0_u8; expected_auth.len()];
    stream
        .read_exact(&mut auth_handshake)
        .map_err(|err| format!("stage105 read anytls auth handshake failed: {err}"))?;
    if auth_handshake != expected_auth {
        return Err("stage105 anytls auth key mismatch".to_owned());
    }

    let settings = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage105 read anytls settings frame failed: {err}"))?;
    if settings.cmd != anytls::contract::CMD_SETTINGS
        || settings.sid != 1
        || settings.data != anytls::link::settings_bytes()
    {
        return Err("stage105 anytls settings frame mismatch".to_owned());
    }
    let syn = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage105 read anytls SYN frame failed: {err}"))?;
    if syn.cmd != anytls::contract::CMD_SYN || syn.sid != 1 || !syn.data.is_empty() {
        return Err("stage105 anytls SYN frame mismatch".to_owned());
    }
    let psh_target = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage105 read anytls target PSH frame failed: {err}"))?;
    if psh_target.cmd != anytls::contract::CMD_PSH || psh_target.sid != 1 {
        return Err("stage105 anytls target PSH frame mismatch".to_owned());
    }
    let (stream_target, consumed) = Socks5Address::decode(&psh_target.data)
        .map_err(|err| format!("stage105 anytls stream target decode failed: {err}"))?;
    if consumed != psh_target.data.len() {
        return Err("stage105 anytls stream target trailing bytes".to_owned());
    }
    if stream_target.authority() != expected_session_target {
        return Err(format!(
            "stage105 anytls stream target mismatch: got {}, want {}",
            stream_target.authority(),
            expected_session_target
        ));
    }
    anytls::write_frame_to_stream(stream, anytls::contract::CMD_SYNACK, 1, &[])
        .map_err(|err| format!("stage105 write anytls SYNACK failed: {err}"))?;

    let first_packet = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage105 read anytls first packet PSH frame failed: {err}"))?;
    if first_packet.cmd != anytls::contract::CMD_PSH || first_packet.sid != 1 {
        return Err("stage105 anytls first packet PSH frame mismatch".to_owned());
    }
    let first_write = anytls::decode_packet_first_write(&first_packet.data)
        .map_err(|err| format!("stage105 decode first UDP packet failed: {err}"))?;
    if first_write.target.as_deref() != Some(expected_original_udp_target)
        || first_write.payload != expected_first_payload
    {
        return Err("stage105 first UDP packet mismatch".to_owned());
    }

    let next_packet = anytls::read_frame_from_stream(stream)
        .map_err(|err| format!("stage105 read anytls next packet PSH frame failed: {err}"))?;
    if next_packet.cmd != anytls::contract::CMD_PSH || next_packet.sid != 1 {
        return Err("stage105 anytls next packet PSH frame mismatch".to_owned());
    }
    let next_write = anytls::decode_packet_next_write(&next_packet.data)
        .map_err(|err| format!("stage105 decode next UDP packet failed: {err}"))?;
    if next_write.target.is_some() || next_write.payload != expected_next_payload {
        return Err("stage105 next UDP packet mismatch".to_owned());
    }

    let first_response = anytls::link::packet_next_write(&first_write.payload);
    let next_response = anytls::link::packet_next_write(&next_write.payload);
    anytls::write_frame_to_stream(stream, anytls::contract::CMD_PSH, 1, &first_response)
        .map_err(|err| format!("stage105 write first UDP packet response failed: {err}"))?;
    anytls::write_frame_to_stream(stream, anytls::contract::CMD_PSH, 1, &next_response)
        .map_err(|err| format!("stage105 write next UDP packet response failed: {err}"))?;

    summary.auth_key_match_count += 1;
    summary.settings_frame_count += 1;
    summary.syn_frame_count += 1;
    summary.psh_magic_target_frame_count += 1;
    summary.first_packet_frame_count += 1;
    summary.next_packet_frame_count += 1;
    summary.synack_response_count += 1;
    summary.first_packet_response_count += 1;
    summary.next_packet_response_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.stream_targets.push(stream_target.authority());
    summary
        .original_udp_targets
        .push(expected_original_udp_target.to_owned());
    summary
        .first_payload_ascii
        .push(String::from_utf8_lossy(&first_write.payload).to_string());
    summary
        .next_payload_ascii
        .push(String::from_utf8_lossy(&next_write.payload).to_string());
    summary
        .response_first_ascii
        .push(String::from_utf8_lossy(&first_write.payload).to_string());
    summary
        .response_next_ascii
        .push(String::from_utf8_lossy(&next_write.payload).to_string());
    summary
        .settings_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + settings.data.len());
    summary
        .psh_magic_target_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + psh_target.data.len());
    summary
        .first_packet_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + first_packet.data.len());
    summary
        .next_packet_frame_lens
        .push(anytls::contract::HEADER_OVERHEAD_SIZE + next_packet.data.len());
    Ok(())
}
