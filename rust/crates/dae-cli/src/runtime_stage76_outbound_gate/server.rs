use super::*;

#[derive(Debug, Default)]
pub(super) struct VlessGrpcHunkServerSummary {
    pub(super) accepted: usize,
    pub(super) grpc_stream_preface_count: usize,
    pub(super) grpc_hunk_tunnel_count: usize,
    pub(super) request_header_count: usize,
    pub(super) response_header_count: usize,
    pub(super) empty_addons_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) targets: Vec<String>,
    pub(super) grpc_service_names: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_vless_grpc_hunk_server(
    opts: &Stage76Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VlessGrpcHunkServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage76 bind loopback VLESS gRPC hunk server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage76 VLESS gRPC hunk server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage76 VLESS gRPC hunk listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage76 VLESS gRPC hunk nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let uuid = opts.uuid.clone();
    let target = opts.target.clone();
    let grpc_service_name = opts.grpc_service_name.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_vless_grpc_hunk(
            listener,
            iterations,
            &uuid,
            &target,
            &grpc_service_name,
            &payload,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vless_grpc_hunk(
    listener: TcpListener,
    iterations: usize,
    uuid: &str,
    expected_target: &str,
    expected_service_name: &str,
    expected_payload: &[u8],
    timeout: Duration,
) -> Result<VlessGrpcHunkServerSummary, String> {
    let mut summary = VlessGrpcHunkServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage76 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage76 server set write timeout failed: {err}"))?;
                handle_vless_grpc_hunk(
                    &mut stream,
                    uuid,
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
                    "stage76 VLESS gRPC hunk server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage76 VLESS gRPC hunk accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vless_grpc_hunk(
    stream: &mut TcpStream,
    uuid: &str,
    expected_target: &str,
    expected_service_name: &str,
    expected_payload: &[u8],
    summary: &mut VlessGrpcHunkServerSummary,
) -> Result<(), String> {
    let expected_preface = shared_transport::grpc_stream_preface(expected_service_name);
    let mut preface = vec![0_u8; expected_preface.len()];
    stream
        .read_exact(&mut preface)
        .map_err(|err| format!("stage76 read gRPC hunk preface failed: {err}"))?;
    if preface != expected_preface {
        return Err("stage76 gRPC hunk stream preface mismatch".to_owned());
    }
    let expected_key =
        vless::password_to_key(uuid).map_err(|err| format!("stage76 VLESS key failed: {err}"))?;
    let request = vless::read_tcp_request_from_grpc_hunk_stream(stream, expected_payload.len())
        .map_err(|err| format!("stage76 read VLESS gRPC hunk request failed: {err}"))?;
    if request.request.key != expected_key {
        return Err("stage76 VLESS key mismatch".to_owned());
    }
    if request.request.addons_len != 0 {
        return Err(format!(
            "stage76 VLESS addons length mismatch: got {}, want 0",
            request.request.addons_len
        ));
    }
    if request.request.command != dae_outbound::VMessNetwork::Tcp.byte() {
        return Err(format!(
            "stage76 VLESS command mismatch: got {}, want {}",
            request.request.command,
            dae_outbound::VMessNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage76 VLESS target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage76 VLESS gRPC hunk payload mismatch".to_owned());
    }
    let response = vless::response_payload_bytes(&request.request.payload);
    let response = shared_transport::grpc_hunk_frame(&response)
        .map_err(|err| format!("stage76 encode VLESS gRPC hunk frame failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage76 write VLESS gRPC hunk echo failed: {err}"))?;

    summary.grpc_stream_preface_count += 1;
    summary.grpc_hunk_tunnel_count += 1;
    summary.request_header_count += 1;
    summary.response_header_count += 1;
    summary.empty_addons_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
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
