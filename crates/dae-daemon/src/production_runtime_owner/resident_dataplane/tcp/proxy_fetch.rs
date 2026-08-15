use super::*;

use crate::boring_tls::{
    BoringTlsVerification, build_boring_tls_context, connect_boring_tls_async,
};

pub(crate) const RESIDENT_TCP_FAILED_HANDLER_JOIN_GRACE: Duration = Duration::from_millis(100);

mod dns;

pub(crate) use self::dns::{
    exchange_resident_proxy_dns_tcp_stream_async, run_resident_proxy_dns_tcp_connection_async,
};

struct ResidentProxyTcpHandlerGuard {
    stop: SharedResidentStopSignal,
    handle: tokio::task::JoinHandle<Result<Value, String>>,
}

impl ResidentProxyTcpHandlerGuard {
    fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn handle_mut(&mut self) -> &mut tokio::task::JoinHandle<Result<Value, String>> {
        &mut self.handle
    }
}

impl Drop for ResidentProxyTcpHandlerGuard {
    fn drop(&mut self) {
        self.stop();
        self.handle.abort();
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_resident_proxy_http_response_async(
    binding: ResidentProxyBinding,
    tls: bool,
    target: &str,
    host: &str,
    request: &[u8],
    response_limit: usize,
    timeout: Duration,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) -> Result<Vec<u8>, String> {
    let sniff_payload = if tls { Vec::new() } else { request.to_vec() };
    exchange_resident_proxy_tcp_stream_async(
        binding,
        target,
        false,
        sniff_payload,
        host.to_owned(),
        timeout,
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
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

pub(crate) async fn join_resident_tcp_handler_after_exchange_async(
    handle: &mut tokio::task::JoinHandle<Result<Value, String>>,
    timeout: Duration,
    response_failed: bool,
) -> Result<Value, String> {
    let join_timeout = if response_failed {
        std::cmp::min(timeout, RESIDENT_TCP_FAILED_HANDLER_JOIN_GRACE)
    } else {
        timeout
    };
    match time::timeout(join_timeout, &mut *handle).await {
        Ok(joined) => joined.map_err(|err| format!("join resident TCP handler: {err}"))?,
        Err(_) => {
            handle.abort();
            let _ = time::timeout(RESIDENT_TCP_FAILED_HANDLER_JOIN_GRACE, &mut *handle).await;
            if response_failed {
                Err("join resident TCP handler: timeout after exchange failure".to_owned())
            } else {
                Err("join resident TCP handler: timeout".to_owned())
            }
        }
    }
}

pub(crate) fn sanitize_probe_event(event: Value) -> String {
    event
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange_resident_proxy_tcp_stream_async<F, Fut>(
    binding: ResidentProxyBinding,
    target: &str,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    timeout: Duration,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    exchange: F,
) -> Result<Vec<u8>, String>
where
    F: FnOnce(TokioTcpStream) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    let owner_deadline = dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), timeout);
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

    let mut handler = start_resident_proxy_tcp_handler(
        binding,
        target,
        dial_ip,
        sniff_payload,
        sniff_domain,
        accepted,
        peer,
        listen_addr,
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
        Some(owner_deadline),
    );

    let response_result = exchange(client).await;
    handler.stop();
    let handler_result = join_resident_tcp_handler_after_exchange_async(
        handler.handle_mut(),
        timeout,
        response_result.is_err(),
    )
    .await;
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

#[allow(clippy::too_many_arguments)]
fn start_resident_proxy_tcp_handler(
    binding: ResidentProxyBinding,
    target: &str,
    dial_ip: bool,
    sniff_payload: Vec<u8>,
    sniff_domain: String,
    accepted: TokioTcpStream,
    peer: SocketAddr,
    listen_addr: SocketAddr,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> ResidentProxyTcpHandlerGuard {
    let proxy = binding.plan();
    let mark = binding.effective_socket_mark();
    let selection = TcpProxySelection {
        mptcp: proxy.mptcp,
        route: TcpRouteSelection {
            initial_outbound: 0,
            final_outbound: 0,
            final_mark: mark,
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
        proxy: binding,
    };
    let sniff = TcpSniffReport {
        payload: sniff_payload,
        domain: sniff_domain,
        error: None,
    };
    let stop = ResidentStopSignal::shared();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    let handler_stop = Arc::clone(&stop);
    let handler_metrics = Arc::clone(&metrics);
    let original_dst = listen_addr;
    let handle = tokio::spawn(async move {
        let mut inbound = accepted;
        let runtime_dispatch = selection.proxy.execution().protocol.runtime_dispatch();
        if runtime_dispatch == ResidentTcpRuntimeDispatch::PolicyClosed {
            Err(format!(
                "resident TCP probe dispatcher policy-closed for UDP-only exact protocol shape {:?}",
                selection.proxy.execution().protocol
            ))
        } else if runtime_dispatch == ResidentTcpRuntimeDispatch::Vless {
            handle_proxy_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                handler_stop,
                sniff,
                &handler_metrics,
            )
            .await
        } else if runtime_dispatch == ResidentTcpRuntimeDispatch::FrameTls {
            handle_frame_tls_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                handler_stop,
                sniff,
                &handler_metrics,
                anytls_owner_registry.as_ref(),
                owner_deadline,
            )
            .await
        } else if runtime_dispatch == ResidentTcpRuntimeDispatch::Quic {
            handle_quic_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                handler_stop,
                sniff,
                &handler_metrics,
                hysteria2_owner_registry.as_ref(),
                tuic_owner_registry.as_ref(),
                juicity_owner_registry.as_ref(),
                owner_deadline,
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
    ResidentProxyTcpHandlerGuard { stop, handle }
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
    let context = build_boring_tls_context(BoringTlsVerification::SystemRoots)
        .map_err(|error| format!("resident proxy fetch create BoringSSL context: {error}"))?;
    let mut tls = time::timeout(timeout, connect_boring_tls_async(&context, host, stream))
        .await
        .map_err(|_| "resident proxy fetch HTTPS handshake timeout".to_owned())?
        .map_err(|err| format!("resident proxy fetch BoringSSL handshake: {err}"))?;
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
