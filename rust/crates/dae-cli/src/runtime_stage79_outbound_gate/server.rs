use super::*;

#[derive(Debug, Default)]
pub(super) struct VlessXHttpPacketServerSummary {
    pub(super) accepted: usize,
    pub(super) xhttp_packet_up_count: usize,
    pub(super) request_header_count: usize,
    pub(super) response_header_count: usize,
    pub(super) empty_addons_count: usize,
    pub(super) tcp_command_count: usize,
    pub(super) target_metadata_count: usize,
    pub(super) payload_roundtrip_count: usize,
    pub(super) targets: Vec<String>,
    pub(super) xhttp_request_paths: Vec<String>,
    pub(super) xhttp_hosts: Vec<String>,
    pub(super) payload_ascii: Vec<String>,
    pub(super) response_ascii: Vec<String>,
}

pub(super) fn spawn_vless_xhttp_packet_server(
    opts: &Stage79Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VlessXHttpPacketServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage79 bind loopback VLESS xHTTP packet server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage79 VLESS xHTTP packet server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage79 VLESS xHTTP packet listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage79 VLESS xHTTP packet nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let uuid = opts.uuid.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let xhttp_options = opts
        .xhttp_options()
        .map_err(|err| format!("stage79 xhttp options invalid: {err}"))?;
    let handle = thread::spawn(move || {
        accept_vless_xhttp_packet(
            listener,
            iterations,
            &uuid,
            &target,
            &payload,
            &xhttp_options,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vless_xhttp_packet(
    listener: TcpListener,
    iterations: usize,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    xhttp_options: &shared_transport::XHttpLifecycleOptions,
    timeout: Duration,
) -> Result<VlessXHttpPacketServerSummary, String> {
    let mut summary = VlessXHttpPacketServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage79 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage79 server set write timeout failed: {err}"))?;
                handle_vless_xhttp_packet(
                    &mut stream,
                    uuid,
                    expected_target,
                    expected_payload,
                    xhttp_options,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage79 VLESS xHTTP packet server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage79 VLESS xHTTP packet accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vless_xhttp_packet(
    stream: &mut TcpStream,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    xhttp_options: &shared_transport::XHttpLifecycleOptions,
    summary: &mut VlessXHttpPacketServerSummary,
) -> Result<(), String> {
    let expected_key =
        vless::password_to_key(uuid).map_err(|err| format!("stage79 VLESS key failed: {err}"))?;
    let request = vless::read_tcp_request_from_xhttp_packet_stream(
        stream,
        expected_payload.len(),
        xhttp_options,
    )
    .map_err(|err| format!("stage79 read VLESS xHTTP packet request failed: {err}"))?;
    if request.request.key != expected_key {
        return Err("stage79 VLESS key mismatch".to_owned());
    }
    if request.request.addons_len != 0 {
        return Err(format!(
            "stage79 VLESS addons length mismatch: got {}, want 0",
            request.request.addons_len
        ));
    }
    if request.request.command != dae_outbound::VMessNetwork::Tcp.byte() {
        return Err(format!(
            "stage79 VLESS command mismatch: got {}, want {}",
            request.request.command,
            dae_outbound::VMessNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage79 VLESS target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage79 VLESS xHTTP packet payload mismatch".to_owned());
    }
    let response = vless::response_payload_bytes(&request.request.payload);
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                response.len()
            )
            .as_bytes(),
        )
        .map_err(|err| format!("stage79 write xHTTP response head failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage79 write xHTTP response body failed: {err}"))?;

    summary.xhttp_packet_up_count += 1;
    summary.request_header_count += 1;
    summary.response_header_count += 1;
    summary.empty_addons_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
    summary.xhttp_request_paths.push(request.xhttp_request_path);
    summary.xhttp_hosts.push(xhttp_options.host.clone());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    Ok(())
}
