use super::*;

pub(crate) const RESIDENT_TCP_PROBE_FAILED_HANDLER_JOIN_GRACE: Duration =
    Duration::from_millis(100);
pub(crate) async fn probe_resident_proxy_tcp_async(
    proxy: Arc<ResidentProxyPlan>,
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
        proxy,
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
            let _ = time::timeout(RESIDENT_TCP_PROBE_FAILED_HANDLER_JOIN_GRACE, &mut *handle).await;
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

pub(crate) fn sanitize_probe_event(event: Value) -> String {
    event
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
}
