use super::*;

#[derive(Debug, Default)]
pub(super) struct TrojanGoGrpcServerSummary {
    pub(super) accepted: usize,
    pub(super) grpc_stream_preface_count: usize,
    pub(super) grpc_hunk_tunnel_count: usize,
    pub(super) no_outer_tls_count: usize,
    pub(super) password_hash_match_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) targets: Vec<String>,
    pub(super) grpc_service_names: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_trojan_go_grpc_server(
    opts: &Stage86Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<TrojanGoGrpcServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage86 bind loopback trojan-go gRPC server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage86 trojan-go gRPC server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage86 trojan-go gRPC listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage86 trojan-go gRPC nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let password = opts.password.clone();
    let target = opts.target.clone();
    let grpc_service_name = opts.grpc_service_name.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_trojan_go_grpc(
            listener,
            iterations,
            &password,
            &target,
            &grpc_service_name,
            &payload,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_trojan_go_grpc(
    listener: TcpListener,
    iterations: usize,
    password: &str,
    expected_target: &str,
    expected_service_name: &str,
    expected_payload: &[u8],
    timeout: Duration,
) -> Result<TrojanGoGrpcServerSummary, String> {
    let mut summary = TrojanGoGrpcServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage86 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage86 server set write timeout failed: {err}"))?;
                handle_trojan_go_grpc(
                    &mut stream,
                    password,
                    expected_target,
                    expected_service_name,
                    expected_payload,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage86 trojan-go gRPC server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage86 trojan-go gRPC accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_trojan_go_grpc(
    stream: &mut TcpStream,
    password: &str,
    expected_target: &str,
    expected_service_name: &str,
    expected_payload: &[u8],
    summary: &mut TrojanGoGrpcServerSummary,
) -> Result<(), String> {
    let expected_preface = shared_transport::grpc_stream_preface(expected_service_name);
    let mut preface = vec![0_u8; expected_preface.len()];
    stream
        .read_exact(&mut preface)
        .map_err(|err| format!("stage86 read gRPC preface failed: {err}"))?;
    if preface != expected_preface {
        return Err("stage86 gRPC preface mismatch; possible outer TLS wrapper".to_owned());
    }
    let request = trojan::read_tcp_request_from_grpc_hunk_stream(stream, expected_payload.len())
        .map_err(|err| format!("stage86 read trojan-go gRPC hunk request failed: {err}"))?;
    let expected_hash = trojan::packet::password_sha224_hex(password);
    if request.request.password_sha224_hex != expected_hash {
        return Err("stage86 trojan-go gRPC password SHA224 mismatch".to_owned());
    }
    if request.request.command != trojan::TrojanNetwork::Tcp.byte() {
        return Err(format!(
            "stage86 trojan-go gRPC command mismatch: got {}, want {}",
            request.request.command,
            trojan::TrojanNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage86 trojan-go gRPC target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage86 trojan-go gRPC payload mismatch".to_owned());
    }
    let response = shared_transport::grpc_hunk_frame(&request.request.payload)
        .map_err(|err| format!("stage86 encode gRPC hunk response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage86 write trojan-go gRPC echo failed: {err}"))?;

    summary.grpc_stream_preface_count += 1;
    summary.grpc_hunk_tunnel_count += 1;
    summary.no_outer_tls_count += 1;
    summary.password_hash_match_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(request.request.target);
    summary
        .grpc_service_names
        .push(expected_service_name.to_owned());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    Ok(())
}
