use super::*;

#[derive(Debug, Default)]
pub(super) struct TrojanGoGrpcHttp2ServerSummary {
    pub(super) accepted: usize,
    pub(super) tls_handshake_count: usize,
    pub(super) tls_alpn_validated_count: usize,
    pub(super) http2_client_preface_count: usize,
    pub(super) http2_settings_count: usize,
    pub(super) http2_headers_count: usize,
    pub(super) http2_data_count: usize,
    pub(super) grpc_hunk_tunnel_count: usize,
    pub(super) no_outer_duplicate_tls_count: usize,
    pub(super) password_hash_match_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) selected_alpns: Vec<String>,
    pub(super) targets: Vec<String>,
    pub(super) grpc_service_names: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
    pub(super) response_settings_ack_count: usize,
    pub(super) response_headers_count: usize,
    pub(super) response_data_count: usize,
}

pub(super) fn spawn_trojan_go_grpc_http2_tls_server(
    opts: &Stage97Options,
    material: &shared_transport::TlsLoopbackMaterial,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<TrojanGoGrpcHttp2ServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp).map_err(|err| {
        format!("stage97 bind loopback trojan-go gRPC HTTP/2 server failed: {err}")
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage97 trojan-go gRPC HTTP/2 server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage97 trojan-go gRPC HTTP/2 listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage97 trojan-go gRPC HTTP/2 nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let password = opts.password.clone();
    let target = opts.target.clone();
    let grpc_service_name = opts.grpc_service_name.clone();
    let grpc_authority = server_addr.to_string();
    let expected_alpn = DEFAULT_GRPC_TLS_ALPN.to_owned();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let server_config = material.server_config.clone();
    let handle = thread::spawn(move || {
        accept_trojan_go_grpc_http2_tls(
            listener,
            iterations,
            &password,
            &target,
            &grpc_service_name,
            &grpc_authority,
            &expected_alpn,
            &payload,
            timeout,
            server_config,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_trojan_go_grpc_http2_tls(
    listener: TcpListener,
    iterations: usize,
    password: &str,
    expected_target: &str,
    expected_service_name: &str,
    grpc_authority: &str,
    expected_alpn: &str,
    expected_payload: &[u8],
    timeout: Duration,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> Result<TrojanGoGrpcHttp2ServerSummary, String> {
    let mut summary = TrojanGoGrpcHttp2ServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage97 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage97 server set write timeout failed: {err}"))?;
                let conn = rustls::ServerConnection::new(server_config.clone())
                    .map_err(|err| format!("stage97 server tls accept failed: {err}"))?;
                let mut tls = rustls::StreamOwned::new(conn, stream);
                handle_trojan_go_grpc_http2_tls(
                    &mut tls,
                    password,
                    expected_target,
                    expected_service_name,
                    grpc_authority,
                    expected_payload,
                    &mut summary,
                )?;
                let selected_alpn = tls
                    .conn
                    .alpn_protocol()
                    .map(|value| String::from_utf8_lossy(value).to_string())
                    .unwrap_or_default();
                if selected_alpn == expected_alpn {
                    summary.tls_alpn_validated_count += 1;
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
                    "stage97 trojan-go gRPC HTTP/2 server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => {
                return Err(format!(
                    "stage97 trojan-go gRPC HTTP/2 accept failed: {err}"
                ));
            }
        }
    }
    Ok(summary)
}

fn handle_trojan_go_grpc_http2_tls<S>(
    stream: &mut S,
    password: &str,
    expected_target: &str,
    expected_service_name: &str,
    grpc_authority: &str,
    expected_payload: &[u8],
    summary: &mut TrojanGoGrpcHttp2ServerSummary,
) -> Result<(), String>
where
    S: Read + Write,
{
    let http2_options = shared_transport::GrpcHttp2LifecycleOptions {
        authority: grpc_authority.to_owned(),
        service_name: expected_service_name.to_owned(),
    };
    let request = trojan::read_tcp_request_from_grpc_http2_stream(
        stream,
        &http2_options,
        expected_payload.len(),
    )
    .map_err(|err| format!("stage97 read trojan-go gRPC HTTP/2 request failed: {err}"))?;
    let expected_hash = trojan::packet::password_sha224_hex(password);
    if request.request.password_sha224_hex != expected_hash {
        return Err("stage97 trojan-go gRPC HTTP/2 password SHA224 mismatch".to_owned());
    }
    if request.request.command != trojan::TrojanNetwork::Tcp.byte() {
        return Err(format!(
            "stage97 trojan-go gRPC HTTP/2 command mismatch: got {}, want {}",
            request.request.command,
            trojan::TrojanNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage97 trojan-go gRPC HTTP/2 target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage97 trojan-go gRPC HTTP/2 payload mismatch".to_owned());
    }
    let response_frames = trojan::write_grpc_http2_hunk_response(stream, &request.request.payload)
        .map_err(|err| format!("stage97 write trojan-go gRPC HTTP/2 echo failed: {err}"))?;

    summary.http2_client_preface_count +=
        usize::from(request.http2_frames.http2_client_preface_validated);
    summary.http2_settings_count += usize::from(request.http2_frames.settings_frame_validated);
    summary.http2_headers_count += usize::from(request.http2_frames.headers_frame_validated);
    summary.http2_data_count += usize::from(request.http2_frames.data_frame_validated);
    summary.grpc_hunk_tunnel_count += 1;
    summary.no_outer_duplicate_tls_count += 1;
    summary.password_hash_match_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.response_settings_ack_count +=
        usize::from(response_frames.response_settings_ack_validated);
    summary.response_headers_count += usize::from(response_frames.response_headers_validated);
    summary.response_data_count += usize::from(response_frames.response_data_validated);
    summary.targets.push(request.request.target);
    summary
        .grpc_service_names
        .push(request.http2_frames.service_name);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    Ok(())
}
