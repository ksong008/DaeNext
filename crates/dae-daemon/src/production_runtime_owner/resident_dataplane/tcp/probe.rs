use super::*;

pub(crate) const RESIDENT_TCP_PROBE_FAILED_HANDLER_JOIN_GRACE: Duration =
    Duration::from_millis(100);
pub(crate) async fn probe_resident_proxy_tcp_async(
    proxy: &ResidentProxyPlan,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    let listener = bind_resident_tcp_probe_loopback_listener(timeout).await?;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| format!("read resident TCP probe listener address: {err}"))?;
    let client = time::timeout(timeout, TokioTcpStream::connect(listen_addr))
        .await
        .map_err(|_| "connect resident TCP probe loopback client: timeout".to_owned())?
        .map_err(|err| format!("connect resident TCP probe loopback client: {err}"))?;
    let (accepted, peer) = time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| "accept resident TCP probe loopback stream: timeout".to_owned())?
        .map_err(|err| format!("accept resident TCP probe loopback stream: {err}"))?;

    let selection = TcpProxySelection {
        mark: proxy.mark,
        mptcp: proxy.mptcp,
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
        proxy: Arc::new(proxy.clone()),
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
    let original_dst = listen_addr;
    let mut handle = tokio::spawn(async move {
        let mut inbound = accepted;
        if matches!(
            &selection.proxy.handler,
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
                | ResidentProxyProtocolPlan::VlessMuxTcpTls { .. }
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
            &selection.proxy.handler,
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
            &selection.proxy.handler,
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
    });

    let response_result = match scheme {
        "http" => {
            let mut client = client;
            let result = read_resident_tcp_probe_response_async(&mut client, path, timeout).await;
            let _ = client.shutdown().await;
            result
        }
        "https" => {
            read_resident_tcp_probe_https_response_async(client, host, path, method, timeout).await
        }
        other => Err(format!("resident TCP probe unsupported scheme: {other}")),
    };
    stop.store(true, Ordering::Relaxed);
    let handler_result =
        join_resident_tcp_probe_handler_async(&mut handle, timeout, response_result.is_err()).await;
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

pub(crate) async fn join_resident_tcp_probe_handler_async(
    handle: &mut tokio::task::JoinHandle<Result<Value, String>>,
    timeout: Duration,
    response_failed: bool,
) -> Result<Value, String> {
    let join_timeout = if response_failed {
        std::cmp::min(timeout, RESIDENT_TCP_PROBE_FAILED_HANDLER_JOIN_GRACE)
    } else {
        timeout
    };
    match time::timeout(join_timeout, &mut *handle).await {
        Ok(joined) => joined.map_err(|err| format!("join resident TCP probe handler: {err}"))?,
        Err(_) => {
            handle.abort();
            if response_failed {
                Err("join resident TCP probe handler: timeout after probe failure".to_owned())
            } else {
                Err("join resident TCP probe handler: timeout".to_owned())
            }
        }
    }
}

async fn bind_resident_tcp_probe_loopback_listener(
    timeout: Duration,
) -> Result<TokioTcpListener, String> {
    let ipv6_addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
    match time::timeout(timeout, TokioTcpListener::bind(ipv6_addr)).await {
        Ok(Ok(listener)) => return Ok(listener),
        Ok(Err(ipv6_err)) => {
            let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            return time::timeout(timeout, TokioTcpListener::bind(ipv4_addr))
                .await
                .map_err(|_| "bind resident TCP probe IPv4 loopback listener: timeout".to_owned())?
                .map_err(|ipv4_err| {
                    format!(
                        "bind resident TCP probe loopback listener: ipv6={ipv6_err}; ipv4={ipv4_err}"
                    )
                });
        }
        Err(_) => {}
    }
    let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    time::timeout(timeout, TokioTcpListener::bind(ipv4_addr))
        .await
        .map_err(|_| "bind resident TCP probe loopback listener: timeout".to_owned())?
        .map_err(|err| format!("bind resident TCP probe IPv4 loopback listener: {err}"))
}

pub(crate) fn resident_tcp_probe_http_request(method: &str, path: &str, host: &str) -> Vec<u8> {
    let method = if method.is_empty() { "HEAD" } else { method };
    let path = if path.is_empty() { "/" } else { path };
    format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dae-rust-resident-check\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

pub(crate) async fn read_resident_tcp_probe_https_response_async(
    stream: TokioTcpStream,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    let config = resident_tcp_probe_tls_config();
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|err| format!("resident TCP probe invalid HTTPS server name {host}: {err}"))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let mut tls = time::timeout(timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| "resident TCP probe HTTPS handshake timeout".to_owned())?
        .map_err(|err| format!("resident TCP probe create HTTPS client: {err}"))?;
    let request = resident_tcp_probe_http_request(method, path, host);
    time::timeout(timeout, tls.write_all(&request))
        .await
        .map_err(|_| "write resident HTTPS probe request: timeout".to_owned())?
        .map_err(|err| format!("write resident HTTPS probe request: {err}"))?;
    time::timeout(timeout, tls.flush())
        .await
        .map_err(|_| "flush resident HTTPS probe request: timeout".to_owned())?
        .map_err(|err| format!("flush resident HTTPS probe request: {err}"))?;
    read_resident_tcp_probe_response_async(&mut tls, path, timeout).await
}

pub(crate) fn resident_tcp_probe_tls_config() -> Arc<ClientConfig> {
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

pub(crate) async fn read_resident_tcp_probe_response_async(
    stream: &mut (impl AsyncRead + Unpin),
    path: &str,
    timeout: Duration,
) -> Result<(), String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 256];
    while response.len() < 8192 {
        let read = time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| "read resident TCP probe response: timeout".to_owned())?
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

pub(crate) fn resident_tcp_probe_status_ok(path: &str, status: u16) -> bool {
    let page = path.rsplit('/').next().unwrap_or("");
    if let Some(expected) = page.strip_prefix("generate_")
        && let Ok(expected) = expected.parse::<u16>()
    {
        return status == expected;
    }
    (200..500).contains(&status)
}

pub(crate) fn sanitize_probe_event(event: Value) -> String {
    event
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
}
