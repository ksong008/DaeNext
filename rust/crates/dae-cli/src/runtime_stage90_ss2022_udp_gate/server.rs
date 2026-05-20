use super::*;

#[derive(Debug, Default)]
pub(super) struct Ss2022UdpServerSummary {
    pub accepted: usize,
    pub decrypt_count: usize,
    pub aes_separate_header_count: usize,
    pub chacha_merged_header_count: usize,
    pub multi_psk_count: usize,
    pub upsk_last_count: usize,
    pub identity_header_count: usize,
    pub identity_header_bytes_len: usize,
    pub identity_header_validated_count: usize,
    pub request_header_count: usize,
    pub target_metadata_count: usize,
    pub replay_window_accept_count: usize,
    pub payload_roundtrip_count: usize,
    pub packet_ids: Vec<u64>,
    pub targets: Vec<String>,
    pub payload_ascii: Vec<String>,
}

pub(super) fn spawn_ss2022_udp_server(
    opts: &Stage90Options,
    branch: Stage90Branch,
) -> Result<
    (
        SocketAddrV4,
        thread::JoinHandle<Result<Ss2022UdpServerSummary, String>>,
    ),
    String,
> {
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .map_err(|err| format!("stage90 bind UDP server failed: {err}"))?;
    let local_addr = socket
        .local_addr()
        .map_err(|err| format!("stage90 UDP server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => return Err(format!("stage90 UDP server is not IPv4: {addr}")),
    };
    socket
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage90 UDP server read timeout failed: {err}"))?;
    socket
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage90 UDP server write timeout failed: {err}"))?;
    let iterations = opts.benchmark_iters;
    let cipher = branch.cipher(opts).to_owned();
    let password = branch.password(opts).to_owned();
    let target = opts.target.clone();
    let response_target = opts.response_target.clone();
    let payload = opts.payload.clone();
    let server_session_id = branch.server_session_id();
    let nonce_base = branch.response_nonce_base();
    let handle = thread::spawn(move || {
        accept_ss2022_udp(
            socket,
            iterations,
            branch,
            &cipher,
            &password,
            &target,
            &response_target,
            &payload,
            server_session_id,
            nonce_base,
        )
    });
    Ok((server_addr, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_ss2022_udp(
    socket: UdpSocket,
    iterations: usize,
    branch: Stage90Branch,
    cipher: &str,
    password: &str,
    expected_target: &str,
    response_target: &str,
    expected_payload: &[u8],
    server_session_id: [u8; 8],
    nonce_base: u8,
) -> Result<Ss2022UdpServerSummary, String> {
    let mut summary = Ss2022UdpServerSummary::default();
    let mut replay = shadowsocks::Ss2022UdpReplayTracker::default();
    while summary.accepted < iterations {
        let mut buf = vec![0_u8; 4096];
        let (read, peer) = socket
            .recv_from(&mut buf)
            .map_err(|err| format!("stage90 UDP receive failed: {err}"))?;
        buf.truncate(read);
        let now = shadowsocks::ss2022_udp_unix_timestamp_now();
        let decoded = shadowsocks::decode_ss2022_udp_client_packet(cipher, password, &buf, now)
            .map_err(|err| format!("stage90 UDP decode failed: {err}"))?;
        replay
            .check(decoded.session_id, decoded.packet_id)
            .map_err(|err| format!("stage90 UDP replay check failed: {err}"))?;
        if decoded.target != expected_target {
            return Err(format!(
                "stage90 UDP target mismatch: got {}, want {}",
                decoded.target, expected_target
            ));
        }
        if decoded.payload != expected_payload {
            return Err("stage90 UDP payload mismatch".to_owned());
        }
        let conf = shadowsocks::ss2022::cipher_conf(cipher)
            .ok_or_else(|| format!("stage90 unsupported cipher: {cipher}"))?;
        let packet_nonce = if conf.packet_cipher {
            Some(nonce_for(
                summary.accepted,
                conf.packet_nonce_len,
                nonce_base,
            ))
        } else {
            None
        };
        let response = shadowsocks::encode_ss2022_udp_server_packet(
            cipher,
            password,
            server_session_id,
            summary.accepted as u64,
            decoded.session_id,
            response_target,
            &decoded.payload,
            now,
            packet_nonce.as_deref(),
        )
        .map_err(|err| format!("stage90 UDP response encode failed: {err}"))?;
        socket
            .send_to(&response.wire, peer)
            .map_err(|err| format!("stage90 UDP send response failed: {err}"))?;

        summary.accepted += 1;
        summary.decrypt_count += 1;
        match branch {
            Stage90Branch::AesSeparateHeader => summary.aes_separate_header_count += 1,
            Stage90Branch::ChachaMergedHeader => summary.chacha_merged_header_count += 1,
        }
        if decoded.identity_header_count > 0 {
            summary.multi_psk_count += 1;
            summary.upsk_last_count += 1;
        }
        summary.identity_header_count += decoded.identity_header_count;
        summary.identity_header_bytes_len += decoded.identity_header_bytes_len;
        if decoded.identity_header_validated {
            summary.identity_header_validated_count += 1;
        }
        if decoded.packet_type == shadowsocks::ss2022::HEADER_TYPE_CLIENT_PACKET {
            summary.request_header_count += 1;
        }
        if decoded.target_metadata_len > 0 {
            summary.target_metadata_count += 1;
        }
        summary.replay_window_accept_count += 1;
        summary.payload_roundtrip_count += 1;
        summary.packet_ids.push(decoded.packet_id);
        summary.targets.push(decoded.target);
        summary
            .payload_ascii
            .push(String::from_utf8_lossy(&decoded.payload).to_string());
    }
    Ok(summary)
}
