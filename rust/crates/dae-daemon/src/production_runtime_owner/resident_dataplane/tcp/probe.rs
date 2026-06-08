pub(super) fn probe_resident_proxy_tcp(
    proxy: &ResidentProxyPlan,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|err| format!("bind resident TCP probe loopback listener: {err}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| format!("read resident TCP probe listener address: {err}"))?;
    let mut client = TcpStream::connect(listen_addr)
        .map_err(|err| format!("connect resident TCP probe loopback client: {err}"))?;
    client
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("set resident TCP probe read timeout: {err}"))?;
    client
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("set resident TCP probe write timeout: {err}"))?;
    let (accepted, peer) = listener
        .accept()
        .map_err(|err| format!("accept resident TCP probe loopback stream: {err}"))?;
    accepted
        .set_nonblocking(true)
        .map_err(|err| format!("set resident TCP probe inbound nonblocking: {err}"))?;

    let selection = TcpProxySelection {
        route: TcpRouteSelection {
            initial_outbound: 0,
            final_outbound: 0,
            final_mark: proxy.mark,
            userspace_route_executed: false,
            userspace_route_must: false,
            dial_target: target.to_owned(),
            dial_ip: false,
            log_metadata: TcpRoutingLogMetadata {
                pid: 0,
                dscp: 0,
                pname: String::new(),
                mac: String::new(),
            },
        },
        proxy: proxy.clone(),
    };
    let sniff = TcpSniffReport {
        payload: if scheme == "https" {
            Vec::new()
        } else {
            resident_tcp_probe_http_request(method, path, host)
        },
        domain: host.to_owned(),
        error: None,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let handler_stop = Arc::clone(&stop);
    let handler_metrics = Arc::clone(&metrics);
    let original_dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let handle = thread::Builder::new()
        .name("dae-resident-tcp-probe".to_owned())
        .spawn(move || {
            let runtime = runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|err| format!("build resident TCP probe runtime: {err}"))?;
            runtime.block_on(async move {
                let mut inbound = TokioTcpStream::from_std(accepted)
                    .map_err(|err| format!("adopt resident TCP probe inbound stream: {err}"))?;
                if matches!(
                    selection.proxy.handler,
                    ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
                ) {
                    handle_proxy_tcp_connection_async(
                        &mut inbound,
                        peer,
                        original_dst,
                        selection,
                        handler_stop,
                        &sniff,
                        &handler_metrics,
                    )
                    .await
                } else if matches!(
                    selection.proxy.handler,
                    ResidentProxyProtocolPlan::TrojanTcpTls { .. }
                        | ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
                        | ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
                ) {
                    handle_frame_tls_tcp_connection_async(
                        &mut inbound,
                        peer,
                        original_dst,
                        selection,
                        handler_stop,
                        &sniff,
                        &handler_metrics,
                    )
                    .await
                } else if matches!(
                    selection.proxy.handler,
                    ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
                        | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
                        | ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
                ) {
                    handle_quic_tcp_connection_async(
                        &mut inbound,
                        peer,
                        original_dst,
                        selection,
                        handler_stop,
                        &sniff,
                        &handler_metrics,
                    )
                    .await
                } else {
                    handle_resident_proxy_tcp_connection_async(
                        inbound,
                        peer,
                        original_dst,
                        selection,
                        handler_stop,
                        sniff,
                        handler_metrics,
                    )
                    .await
                }
            })
        })
        .map_err(|err| format!("spawn resident TCP probe handler: {err}"))?;

    let response_result = match scheme {
        "http" => read_resident_tcp_probe_response(&mut client, path),
        "https" => read_resident_tcp_probe_https_response(&mut client, host, path, method),
        other => Err(format!("resident TCP probe unsupported scheme: {other}")),
    };
    stop.store(true, Ordering::Relaxed);
    let _ = client.shutdown(Shutdown::Both);
    let handler_result = handle
        .join()
        .map_err(|_| "join resident TCP probe handler: panicked".to_owned())?;
    match response_result {
        Ok(()) => Ok(()),
        Err(response_err) => match handler_result {
            Ok(event) => Err(format!(
                "{response_err}; handler_event={}",
                sanitize_probe_event(event)
            )),
            Err(handler_err) => Err(format!("{response_err}; handler_error={handler_err}")),
        },
    }
}

fn resident_tcp_probe_http_request(method: &str, path: &str, host: &str) -> Vec<u8> {
    let method = if method.is_empty() { "HEAD" } else { method };
    let path = if path.is_empty() { "/" } else { path };
    format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dae-rust-resident-check\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn read_resident_tcp_probe_https_response(
    stream: &mut TcpStream,
    host: &str,
    path: &str,
    method: &str,
) -> Result<(), String> {
    let config = resident_tcp_probe_tls_config();
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|err| format!("resident TCP probe invalid HTTPS server name {host}: {err}"))?;
    let conn = ClientConnection::new(config, server_name)
        .map_err(|err| format!("resident TCP probe create HTTPS client: {err}"))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let request = resident_tcp_probe_http_request(method, path, host);
    tls.write_all(&request)
        .map_err(|err| format!("write resident HTTPS probe request: {err}"))?;
    tls.flush()
        .map_err(|err| format!("flush resident HTTPS probe request: {err}"))?;
    read_resident_tcp_probe_response(&mut tls, path)
}

fn resident_tcp_probe_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

fn read_resident_tcp_probe_response(stream: &mut impl Read, path: &str) -> Result<(), String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    while response.len() < 8192 {
        let read = stream
            .read(&mut buf)
            .map_err(|err| format!("read resident TCP probe response: {err}"))?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(2).any(|window| window == b"\r\n") && response.len() >= 12 {
            break;
        }
    }
    if response.is_empty() {
        return Err("resident TCP probe got empty response".to_owned());
    }
    let text = String::from_utf8_lossy(&response);
    let mut fields = text.split_whitespace();
    let version = fields.next().unwrap_or("");
    let status = fields
        .next()
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| format!("resident TCP probe bad HTTP response: {text:?}"))?;
    if !version.starts_with("HTTP/") {
        return Err(format!("resident TCP probe non-HTTP response: {text:?}"));
    }
    if resident_tcp_probe_status_ok(path, status) {
        Ok(())
    } else {
        Err(format!("resident TCP probe bad HTTP status: {status}"))
    }
}

fn resident_tcp_probe_status_ok(path: &str, status: u16) -> bool {
    let page = path.rsplit('/').next().unwrap_or("");
    if let Some(expected) = page.strip_prefix("generate_")
        && let Ok(expected) = expected.parse::<u16>()
    {
        return status == expected;
    }
    (200..500).contains(&status)
}

fn sanitize_probe_event(event: Value) -> String {
    event
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
}
