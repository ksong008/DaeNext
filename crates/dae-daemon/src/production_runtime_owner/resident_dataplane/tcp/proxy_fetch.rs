use super::*;

pub(crate) async fn fetch_resident_proxy_http_response_async(
    proxy: Arc<ResidentProxyPlan>,
    tls: bool,
    target: &str,
    host: &str,
    request: &[u8],
    response_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let sniff_payload = if tls { Vec::new() } else { request.to_vec() };
    exchange_resident_proxy_tcp_stream_async(
        proxy,
        target,
        false,
        sniff_payload,
        host.to_owned(),
        timeout,
        |client| async move {
            if tls {
                fetch_resident_proxy_https_response_async(
                    client,
                    host,
                    request,
                    response_limit,
                    timeout,
                )
                .await
            } else {
                fetch_resident_proxy_plain_http_response_async(
                    client,
                    request,
                    response_limit,
                    timeout,
                )
                .await
            }
        },
    )
    .await
}

pub(crate) async fn exchange_resident_proxy_tcp_stream_async<F, Fut>(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    timeout: Duration,
    exchange: F,
) -> Result<Vec<u8>, String>
where
    F: FnOnce(TokioTcpStream) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    let listener = bind_resident_proxy_fetch_loopback_listener(timeout).await?;
    let listen_addr = listener
        .local_addr()
        .map_err(|err| format!("read resident proxy TCP listener address: {err}"))?;
    let client = time::timeout(timeout, TokioTcpStream::connect(listen_addr))
        .await
        .map_err(|_| "connect resident proxy TCP loopback client: timeout".to_owned())?
        .map_err(|err| format!("connect resident proxy TCP loopback client: {err}"))?;
    let (accepted, peer) = time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| "accept resident proxy TCP loopback stream: timeout".to_owned())?
        .map_err(|err| format!("accept resident proxy TCP loopback stream: {err}"))?;

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
            dial_ip,
            log_metadata: TcpRoutingLogMetadata {
                pid: 0,
                dscp: 0,
                pname: String::new(),
                mac: String::new(),
            },
        },
        proxy,
    };
    let sniff = TcpSniffReport {
        payload: sniff_payload,
        domain: sniff_domain,
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

    let response_result = exchange(client).await;
    stop.store(true, Ordering::Relaxed);
    let handler_result =
        join_resident_tcp_probe_handler_async(&mut handle, timeout, response_result.is_err()).await;
    match response_result {
        Ok(response) => Ok(response),
        Err(response_err) => match handler_result {
            Ok(event) => Err(format!(
                "{response_err}; handler_event={}",
                sanitize_probe_event(event)
            )),
            Err(handler_err) => Err(format!("{response_err}; handler_error={handler_err}")),
        },
    }
}

pub(crate) async fn exchange_resident_proxy_dns_tcp_async(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
    payload: &[u8],
    response_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    exchange_resident_proxy_tcp_stream_async(
        proxy,
        target,
        true,
        Vec::new(),
        String::new(),
        timeout,
        |client| async move {
            exchange_resident_proxy_dns_tcp_loopback_async(client, payload, response_limit, timeout)
                .await
        },
    )
    .await
}

async fn bind_resident_proxy_fetch_loopback_listener(
    timeout: Duration,
) -> Result<TokioTcpListener, String> {
    let ipv6_addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
    match time::timeout(timeout, TokioTcpListener::bind(ipv6_addr)).await {
        Ok(Ok(listener)) => return Ok(listener),
        Ok(Err(ipv6_err)) => {
            let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            return time::timeout(timeout, TokioTcpListener::bind(ipv4_addr))
                .await
                .map_err(|_| {
                    "bind resident proxy fetch IPv4 loopback listener: timeout".to_owned()
                })?
                .map_err(|ipv4_err| {
                    format!(
                        "bind resident proxy fetch loopback listener: ipv6={ipv6_err}; ipv4={ipv4_err}"
                    )
                });
        }
        Err(_) => {}
    }
    let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    time::timeout(timeout, TokioTcpListener::bind(ipv4_addr))
        .await
        .map_err(|_| "bind resident proxy fetch loopback listener: timeout".to_owned())?
        .map_err(|err| format!("bind resident proxy fetch IPv4 loopback listener: {err}"))
}

async fn fetch_resident_proxy_plain_http_response_async(
    mut stream: TokioTcpStream,
    request: &[u8],
    response_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    time::timeout(timeout, stream.write_all(request))
        .await
        .map_err(|_| "write resident proxy fetch request: timeout".to_owned())?
        .map_err(|err| format!("write resident proxy fetch request: {err}"))?;
    time::timeout(timeout, stream.flush())
        .await
        .map_err(|_| "flush resident proxy fetch request: timeout".to_owned())?
        .map_err(|err| format!("flush resident proxy fetch request: {err}"))?;
    let response =
        read_resident_proxy_fetch_response_async(&mut stream, response_limit, timeout).await;
    let _ = stream.shutdown().await;
    response
}

async fn fetch_resident_proxy_https_response_async(
    stream: TokioTcpStream,
    host: &str,
    request: &[u8],
    response_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|err| format!("resident proxy fetch invalid HTTPS server name {host}: {err}"))?;
    let connector = tokio_rustls::TlsConnector::from(resident_tcp_probe_tls_config());
    let mut tls = time::timeout(timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| "resident proxy fetch HTTPS handshake timeout".to_owned())?
        .map_err(|err| format!("resident proxy fetch create HTTPS client: {err}"))?;
    time::timeout(timeout, tls.write_all(request))
        .await
        .map_err(|_| "write resident proxy fetch HTTPS request: timeout".to_owned())?
        .map_err(|err| format!("write resident proxy fetch HTTPS request: {err}"))?;
    time::timeout(timeout, tls.flush())
        .await
        .map_err(|_| "flush resident proxy fetch HTTPS request: timeout".to_owned())?
        .map_err(|err| format!("flush resident proxy fetch HTTPS request: {err}"))?;
    let response =
        read_resident_proxy_fetch_response_async(&mut tls, response_limit, timeout).await;
    let _ = tls.shutdown().await;
    response
}

async fn exchange_resident_proxy_dns_tcp_loopback_async(
    mut stream: TokioTcpStream,
    payload: &[u8],
    response_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS request exceeds TCP frame limit: {}", payload.len()))?;
    time::timeout(timeout, stream.write_all(&len.to_be_bytes()))
        .await
        .map_err(|_| "write resident proxy DNS TCP frame length: timeout".to_owned())?
        .map_err(|err| format!("write resident proxy DNS TCP frame length: {err}"))?;
    time::timeout(timeout, stream.write_all(payload))
        .await
        .map_err(|_| "write resident proxy DNS TCP frame payload: timeout".to_owned())?
        .map_err(|err| format!("write resident proxy DNS TCP frame payload: {err}"))?;
    time::timeout(timeout, stream.flush())
        .await
        .map_err(|_| "flush resident proxy DNS TCP request: timeout".to_owned())?
        .map_err(|err| format!("flush resident proxy DNS TCP request: {err}"))?;

    let mut len = [0_u8; 2];
    time::timeout(timeout, stream.read_exact(&mut len))
        .await
        .map_err(|_| "read resident proxy DNS TCP response length: timeout".to_owned())?
        .map_err(|err| format!("read resident proxy DNS TCP response length: {err}"))?;
    let len = u16::from_be_bytes(len) as usize;
    if len > response_limit {
        return Err(format!(
            "resident proxy DNS TCP response length {len} exceeds {response_limit}"
        ));
    }
    let mut response = vec![0_u8; len];
    time::timeout(timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| "read resident proxy DNS TCP response payload: timeout".to_owned())?
        .map_err(|err| format!("read resident proxy DNS TCP response payload: {err}"))?;
    let _ = stream.shutdown().await;
    Ok(response)
}

async fn read_resident_proxy_fetch_response_async(
    stream: &mut (impl AsyncRead + Unpin),
    response_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| "read resident proxy fetch response: timeout".to_owned())?
            .map_err(|err| format!("read resident proxy fetch response: {err}"))?;
        if read == 0 {
            break;
        }
        let next_len = response
            .len()
            .checked_add(read)
            .ok_or_else(|| "resident proxy fetch response size overflow".to_owned())?;
        if next_len > response_limit {
            return Err(format!(
                "resident proxy fetch response exceeds {response_limit} bytes"
            ));
        }
        response.extend_from_slice(&buf[..read]);
    }
    if response.is_empty() {
        return Err("resident proxy fetch got empty response".to_owned());
    }
    Ok(response)
}
