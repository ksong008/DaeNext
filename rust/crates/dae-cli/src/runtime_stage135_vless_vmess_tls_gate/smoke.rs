use super::*;

#[derive(Debug)]
pub(super) struct Stage135Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    vless_wss: vless::VlessWssTlsExchangeReport,
    vmess_wss: vmess::VMessAeadWssTlsExchangeReport,
    vless_httpupgrade: vless::VlessHttpsHttpUpgradeTlsExchangeReport,
    vmess_httpupgrade: vmess::VMessAeadHttpsHttpUpgradeTlsExchangeReport,
    certificate_der_len: usize,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
}

pub(super) fn run_stage135_smoke(opts: &Stage135Options) -> Result<Stage135Outcome, String> {
    let tls_options = opts
        .tls_options()
        .map_err(|err| format!("stage135 tls options invalid: {err}"))?;
    let material = shared_transport::tls_loopback_material(&tls_options)
        .map_err(|err| format!("stage135 build tls material failed: {err}"))?;
    let certificate_der_len = material.certificate_der_len;
    let key = vless::password_to_key(&opts.uuid)
        .map_err(|err| format!("stage135 vless uuid is invalid: {err}"))?;
    let start = Instant::now();
    let mut last_listener = None;
    let mut last_dial = None;
    let mut last_vless_wss = None;
    let mut last_vmess_wss = None;
    let mut last_vless_httpupgrade = None;
    let mut last_vmess_httpupgrade = None;
    for _ in 0..opts.benchmark_iters {
        let (_, _, report) = run_vless_wss_once(opts, &material, &tls_options, key)?;
        last_vless_wss = Some(report);
        let (_, _, report) = run_vmess_wss_once(opts, &material, &tls_options)?;
        last_vmess_wss = Some(report);
        let (_, _, report) = run_vless_httpupgrade_once(opts, &material, &tls_options, key)?;
        last_vless_httpupgrade = Some(report);
        let (listener, dial, report) = run_vmess_httpupgrade_once(opts, &material, &tls_options)?;
        last_listener = Some(listener);
        last_dial = Some(dial);
        last_vmess_httpupgrade = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let exchange_count = opts.benchmark_iters * 4;
    Ok(Stage135Outcome {
        listener_report: last_listener
            .ok_or_else(|| "stage135 missing listener report".to_owned())?,
        last_dial_report: last_dial.ok_or_else(|| "stage135 missing dial report".to_owned())?,
        vless_wss: last_vless_wss.ok_or_else(|| "stage135 missing VLESS WSS report".to_owned())?,
        vmess_wss: last_vmess_wss.ok_or_else(|| "stage135 missing VMess WSS report".to_owned())?,
        vless_httpupgrade: last_vless_httpupgrade
            .ok_or_else(|| "stage135 missing VLESS HTTPUpgrade report".to_owned())?,
        vmess_httpupgrade: last_vmess_httpupgrade
            .ok_or_else(|| "stage135 missing VMess HTTPUpgrade report".to_owned())?,
        certificate_der_len,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / exchange_count as f64,
        exchange_count,
    })
}

fn run_vless_wss_once(
    opts: &Stage135Options,
    material: &shared_transport::TlsLoopbackMaterial,
    tls_options: &shared_transport::TlsUnderlayOptions,
    key: [u8; 16],
) -> Result<
    (
        TcpLoopbackListenerReport,
        TcpDirectDialReport,
        vless::VlessWssTlsExchangeReport,
    ),
    String,
> {
    let server_config = material.server_config.clone();
    let payload = opts.payload.clone();
    let target = opts.vless_wss_target.clone();
    let host = opts.wss_host.clone();
    let path = opts.wss_path.clone();
    run_stage135_exchange(opts, move |stream| {
        let conn = rustls::ServerConnection::new(server_config)
            .map_err(|err| format!("stage135 VLESS WSS server tls accept failed: {err}"))?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_ws_upgrade(&mut tls, &host, &path)?;
        let request = vless::read_tcp_request_from_websocket_stream(&mut tls, payload.len())
            .map_err(|err| format!("stage135 VLESS WSS request read failed: {err}"))?;
        if request.request.key != key || request.request.target != target {
            return Err("stage135 VLESS WSS request metadata mismatch".to_owned());
        }
        let response = vless::response_payload_bytes(&request.request.payload);
        let response = shared_transport::websocket_server_binary_frame(&response)
            .map_err(|err| format!("stage135 VLESS WSS response frame failed: {err}"))?;
        tls.write_all(&response)
            .map_err(|err| format!("stage135 VLESS WSS response write failed: {err}"))?;
        Ok(())
    })
    .and_then(|(server_addr, listener, dial)| {
        let report = vless::tcp_exchange_over_wss_tls_stream(
            dial.stream,
            material,
            tls_options,
            &server_addr.to_string(),
            &key,
            &opts.vless_wss_target,
            &opts.wss_host,
            &opts.wss_path,
            &opts.payload,
        )
        .map_err(|err| format!("stage135 VLESS WSS exchange failed: {err}"))?;
        join_stage135_server(dial.handle)?;
        Ok((listener, dial.report, report))
    })
}

fn run_vmess_wss_once(
    opts: &Stage135Options,
    material: &shared_transport::TlsLoopbackMaterial,
    tls_options: &shared_transport::TlsUnderlayOptions,
) -> Result<
    (
        TcpLoopbackListenerReport,
        TcpDirectDialReport,
        vmess::VMessAeadWssTlsExchangeReport,
    ),
    String,
> {
    let server_config = material.server_config.clone();
    let payload = opts.payload.clone();
    let target = opts.vmess_wss_target.clone();
    let host = opts.wss_host.clone();
    let path = opts.wss_path.clone();
    let uuid = opts.uuid.clone();
    run_stage135_exchange(opts, move |stream| {
        let conn = rustls::ServerConnection::new(server_config)
            .map_err(|err| format!("stage135 VMess WSS server tls accept failed: {err}"))?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_ws_upgrade(&mut tls, &host, &path)?;
        let request = vmess::read_aead_tcp_request_from_websocket_stream(&mut tls, &uuid)
            .map_err(|err| format!("stage135 VMess WSS request read failed: {err}"))?;
        if request.request.target != target || request.request.payload != payload {
            return Err("stage135 VMess WSS request metadata mismatch".to_owned());
        }
        let response = vmess::aead_tcp_response_packet(&request.request, &request.request.payload)
            .map_err(|err| format!("stage135 VMess WSS response packet failed: {err}"))?;
        let response = shared_transport::websocket_server_binary_frame(&response)
            .map_err(|err| format!("stage135 VMess WSS response frame failed: {err}"))?;
        tls.write_all(&response)
            .map_err(|err| format!("stage135 VMess WSS response write failed: {err}"))?;
        Ok(())
    })
    .and_then(|(server_addr, listener, dial)| {
        let report = vmess::aead_tcp_exchange_over_wss_tls_stream(
            dial.stream,
            material,
            tls_options,
            &server_addr.to_string(),
            &opts.uuid,
            &opts.vmess_wss_target,
            &opts.wss_host,
            &opts.wss_path,
            &opts.payload,
        )
        .map_err(|err| format!("stage135 VMess WSS exchange failed: {err}"))?;
        join_stage135_server(dial.handle)?;
        Ok((listener, dial.report, report))
    })
}

fn run_vless_httpupgrade_once(
    opts: &Stage135Options,
    material: &shared_transport::TlsLoopbackMaterial,
    tls_options: &shared_transport::TlsUnderlayOptions,
    key: [u8; 16],
) -> Result<
    (
        TcpLoopbackListenerReport,
        TcpDirectDialReport,
        vless::VlessHttpsHttpUpgradeTlsExchangeReport,
    ),
    String,
> {
    let server_config = material.server_config.clone();
    let payload = opts.payload.clone();
    let target = opts.vless_httpupgrade_target.clone();
    let host = opts.httpupgrade_host.clone();
    let path = opts.httpupgrade_path.clone();
    run_stage135_exchange(opts, move |stream| {
        let conn = rustls::ServerConnection::new(server_config)
            .map_err(|err| format!("stage135 VLESS HTTPUpgrade server tls accept failed: {err}"))?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_httpupgrade(&mut tls, &host, &path)?;
        let request = vless::read_tcp_request_from_stream(&mut tls, payload.len())
            .map_err(|err| format!("stage135 VLESS HTTPUpgrade request read failed: {err}"))?;
        if request.key != key || request.target != target {
            return Err("stage135 VLESS HTTPUpgrade request metadata mismatch".to_owned());
        }
        let response = vless::response_payload_bytes(&request.payload);
        tls.write_all(&response)
            .map_err(|err| format!("stage135 VLESS HTTPUpgrade response write failed: {err}"))?;
        Ok(())
    })
    .and_then(|(server_addr, listener, dial)| {
        let report = vless::tcp_exchange_over_https_httpupgrade_tls_stream(
            dial.stream,
            material,
            tls_options,
            &server_addr.to_string(),
            &key,
            &opts.vless_httpupgrade_target,
            &opts.httpupgrade_host,
            &opts.httpupgrade_path,
            &opts.payload,
        )
        .map_err(|err| format!("stage135 VLESS HTTPUpgrade exchange failed: {err}"))?;
        join_stage135_server(dial.handle)?;
        Ok((listener, dial.report, report))
    })
}

fn run_vmess_httpupgrade_once(
    opts: &Stage135Options,
    material: &shared_transport::TlsLoopbackMaterial,
    tls_options: &shared_transport::TlsUnderlayOptions,
) -> Result<
    (
        TcpLoopbackListenerReport,
        TcpDirectDialReport,
        vmess::VMessAeadHttpsHttpUpgradeTlsExchangeReport,
    ),
    String,
> {
    let server_config = material.server_config.clone();
    let payload = opts.payload.clone();
    let target = opts.vmess_httpupgrade_target.clone();
    let host = opts.httpupgrade_host.clone();
    let path = opts.httpupgrade_path.clone();
    let uuid = opts.uuid.clone();
    run_stage135_exchange(opts, move |stream| {
        let conn = rustls::ServerConnection::new(server_config)
            .map_err(|err| format!("stage135 VMess HTTPUpgrade server tls accept failed: {err}"))?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        validate_httpupgrade(&mut tls, &host, &path)?;
        let request = vmess::read_aead_tcp_request_from_stream(&mut tls, &uuid)
            .map_err(|err| format!("stage135 VMess HTTPUpgrade request read failed: {err}"))?;
        if request.target != target || request.payload != payload {
            return Err("stage135 VMess HTTPUpgrade request metadata mismatch".to_owned());
        }
        let response = vmess::aead_tcp_response_packet(&request, &request.payload)
            .map_err(|err| format!("stage135 VMess HTTPUpgrade response packet failed: {err}"))?;
        tls.write_all(&response)
            .map_err(|err| format!("stage135 VMess HTTPUpgrade response write failed: {err}"))?;
        Ok(())
    })
    .and_then(|(server_addr, listener, dial)| {
        let report = vmess::aead_tcp_exchange_over_https_httpupgrade_tls_stream(
            dial.stream,
            material,
            tls_options,
            &server_addr.to_string(),
            &opts.uuid,
            &opts.vmess_httpupgrade_target,
            &opts.httpupgrade_host,
            &opts.httpupgrade_path,
            &opts.payload,
        )
        .map_err(|err| format!("stage135 VMess HTTPUpgrade exchange failed: {err}"))?;
        join_stage135_server(dial.handle)?;
        Ok((listener, dial.report, report))
    })
}

struct Stage135Dial {
    stream: std::net::TcpStream,
    report: TcpDirectDialReport,
    handle: thread::JoinHandle<Result<(), String>>,
}

fn run_stage135_exchange<F>(
    opts: &Stage135Options,
    handler: F,
) -> Result<(SocketAddrV4, TcpLoopbackListenerReport, Stage135Dial), String>
where
    F: FnOnce(std::net::TcpStream) -> Result<(), String> + Send + 'static,
{
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage135 bind loopback listener failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage135 listener local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage135 listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage135 listener nonblocking failed: {err}"))?;
    let timeout = opts.timeout;
    let handle = thread::spawn(move || accept_one(listener, timeout, handler));
    let connected = magic_tcp_connect(
        server_addr,
        &TcpDirectDialOptions {
            mark: opts.so_mark,
            mptcp: opts.mptcp,
            timeout: opts.timeout,
        },
    )
    .map_err(|err| format!("stage135 magic_tcp_connect failed: {err}"))?;
    Ok((
        server_addr,
        listener_report,
        Stage135Dial {
            stream: connected.stream,
            report: connected.report,
            handle,
        },
    ))
}

fn accept_one<F>(listener: TcpListener, timeout: Duration, handler: F) -> Result<(), String>
where
    F: FnOnce(std::net::TcpStream) -> Result<(), String>,
{
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage135 server read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage135 server write timeout failed: {err}"))?;
                return handler(stream);
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err("stage135 server accept timeout".to_owned());
            }
            Err(err) => return Err(format!("stage135 accept failed: {err}")),
        }
    }
}

fn validate_ws_upgrade<S>(stream: &mut S, host: &str, path: &str) -> Result<(), String>
where
    S: Read + Write,
{
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage135 read WSS upgrade failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage135 WSS request is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {path} HTTP/1.1\r\n")) {
        return Err("stage135 WSS path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {host}\r\n")) {
        return Err("stage135 WSS Host header mismatch".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage135 WSS Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                shared_transport::WS_ACCEPT_SAMPLE
            )
            .as_bytes(),
        )
        .map_err(|err| format!("stage135 write WSS upgrade response failed: {err}"))
}

fn validate_httpupgrade<S>(stream: &mut S, host: &str, path: &str) -> Result<(), String>
where
    S: Read + Write,
{
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage135 read HTTPUpgrade failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage135 HTTPUpgrade request is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {path} HTTP/1.1\r\n")) {
        return Err("stage135 HTTPUpgrade path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {host}\r\n")) {
        return Err("stage135 HTTPUpgrade Host header mismatch".to_owned());
    }
    if !request_head.contains("Connection: upgrade\r\n") {
        return Err("stage135 HTTPUpgrade Connection header mismatch".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage135 HTTPUpgrade Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .map_err(|err| format!("stage135 write HTTPUpgrade response failed: {err}"))
}

fn join_stage135_server(handle: thread::JoinHandle<Result<(), String>>) -> Result<(), String> {
    handle
        .join()
        .map_err(|_| "stage135 server thread panicked".to_owned())?
}

pub(super) fn apply_stage135_outcome(report: &mut Value, outcome: Stage135Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let vless_wss_passed = tls_wss_vless_passed(&outcome.vless_wss);
    let vmess_wss_passed = tls_wss_vmess_passed(&outcome.vmess_wss);
    let vless_httpupgrade_passed = tls_httpupgrade_vless_passed(&outcome.vless_httpupgrade);
    let vmess_httpupgrade_passed = tls_httpupgrade_vmess_passed(&outcome.vmess_httpupgrade);
    let passed = vless_wss_passed
        && vmess_wss_passed
        && vless_httpupgrade_passed
        && vmess_httpupgrade_passed
        && so_mark_observed
        && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vless_wss_tls_lifecycle_admitted"] = json!(vless_wss_passed);
    report["vmess_wss_tls_lifecycle_admitted"] = json!(vmess_wss_passed);
    report["vless_https_httpupgrade_tls_lifecycle_admitted"] = json!(vless_httpupgrade_passed);
    report["vmess_https_httpupgrade_tls_lifecycle_admitted"] = json!(vmess_httpupgrade_passed);
    report["vless_vmess_tls_wss_httpupgrade_smoke_passed"] = json!(passed);
    report["stage135_tls_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["stage135_tls_contract"]["certificate_der_len"] = json!(outcome.certificate_der_len);
    report["stage135_tls_contract"]["selected_alpn"] = json!(outcome.vless_wss.selected_alpn);
    report["stage135_tls_contract"]["tls_handshake_validated"] = json!(passed);
    report["stage135_tls_contract"]["wss_validated"] = json!(vless_wss_passed && vmess_wss_passed);
    report["stage135_tls_contract"]["https_httpupgrade_validated"] =
        json!(vless_httpupgrade_passed && vmess_httpupgrade_passed);
    report["underlay_socket"]["listener"] = json!({
        "requested_mptcp": outcome.listener_report.requested_mptcp,
        "mptcp_socket_created": outcome.listener_report.mptcp_socket_created,
        "fallback_used": outcome.listener_report.fallback_used,
        "socket_protocol": outcome.listener_report.socket_protocol,
        "local_addr": outcome.listener_report.local_addr
    });
    report["underlay_socket"]["last_dial_report"] = json!({
        "requested_mark": outcome.last_dial_report.requested_mark,
        "requested_mptcp": outcome.last_dial_report.requested_mptcp,
        "mptcp_socket_attempted": outcome.last_dial_report.mptcp_socket_attempted,
        "mptcp_socket_created": outcome.last_dial_report.mptcp_socket_created,
        "mptcp_connect_fallback_used": outcome.last_dial_report.mptcp_connect_fallback_used,
        "socket_protocol": outcome.last_dial_report.socket_protocol,
        "so_mark": outcome.last_dial_report.so_mark,
        "so_mark_applied": outcome.last_dial_report.so_mark_applied,
        "mptcp_info_available": outcome.last_dial_report.mptcp_info_available,
        "mptcp_fallen_back": outcome.last_dial_report.mptcp_fallen_back,
        "mptcp_protocol_observed": outcome.last_dial_report.mptcp_protocol_observed,
        "peer_addr": outcome.last_dial_report.peer_addr,
        "local_addr": outcome.last_dial_report.local_addr
    });
    report["underlay_socket"]["so_mark_observed"] = json!(so_mark_observed);
    report["underlay_socket"]["mptcp_status_recorded"] = json!(mptcp_status_recorded);
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["iterations_per_transport"] = json!(outcome.exchange_count / 4);
    report["benchmark"]["total_exchange_count"] = json!(outcome.exchange_count);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vless_vmess_tls_transport_exchange"] =
        json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.vless_wss.payload_len);
    report["benchmark"]["vless_wss_request_frame_len"] =
        json!(outcome.vless_wss.websocket_request_frame_len);
    report["benchmark"]["vmess_wss_request_frame_len"] =
        json!(outcome.vmess_wss.websocket_request_frame_len);
    report["benchmark"]["vless_httpupgrade_request_len"] =
        json!(outcome.vless_httpupgrade.httpupgrade_request_len);
    report["benchmark"]["vmess_httpupgrade_request_len"] =
        json!(outcome.vmess_httpupgrade.httpupgrade_request_len);
    report["protocol_matrix"]["vless_wss_tls_lifecycle_admitted"] = json!(vless_wss_passed);
    report["protocol_matrix"]["vmess_wss_tls_lifecycle_admitted"] = json!(vmess_wss_passed);
    report["protocol_matrix"]["vless_https_httpupgrade_tls_lifecycle_admitted"] =
        json!(vless_httpupgrade_passed);
    report["protocol_matrix"]["vmess_https_httpupgrade_tls_lifecycle_admitted"] =
        json!(vmess_httpupgrade_passed);
}

fn tls_wss_vless_passed(report: &vless::VlessWssTlsExchangeReport) -> bool {
    report.true_dataplane
        && report.rustls_tls_lifecycle
        && report.alpn_validated
        && report.websocket_handshake_validated
        && report.websocket_binary_frame_validated
}

fn tls_wss_vmess_passed(report: &vmess::VMessAeadWssTlsExchangeReport) -> bool {
    report.true_dataplane
        && report.rustls_tls_lifecycle
        && report.alpn_validated
        && report.websocket_handshake_validated
        && report.websocket_binary_frame_validated
}

fn tls_httpupgrade_vless_passed(report: &vless::VlessHttpsHttpUpgradeTlsExchangeReport) -> bool {
    report.true_dataplane
        && report.rustls_tls_lifecycle
        && report.alpn_validated
        && report.httpupgrade_handshake_validated
}

fn tls_httpupgrade_vmess_passed(
    report: &vmess::VMessAeadHttpsHttpUpgradeTlsExchangeReport,
) -> bool {
    report.true_dataplane
        && report.rustls_tls_lifecycle
        && report.alpn_validated
        && report.httpupgrade_handshake_validated
}
