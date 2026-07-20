// DNS listener tasks keep bind sockets, routing, shutdown, and metrics handles explicit.
#![allow(clippy::too_many_arguments)]

use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{
    TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
};
use tokio::sync::Semaphore;
use tokio::time;

use super::dns::{
    DNS_MAX_UDP_MESSAGE_SIZE, ResidentDnsPlan, ResidentDnsTraceSummary, ResidentDnsTransportTrace,
    build_dns_server_failure_response, handle_resident_dns_local_trace_async,
    read_dns_tcp_payload_async, write_dns_tcp_payload_async,
};
#[cfg(test)]
use super::dns::{
    DNS_TRANSPORT_OUTCOME_SUCCESS, DNS_TRANSPORT_ROUTE_DIRECT, DNS_TRANSPORT_TARGET_FAMILY_IPV4,
    DNS_TRANSPORT_TARGET_FAMILY_IPV6,
};
use super::*;

const DNS_BIND_READ_LIMIT: usize = DNS_MAX_UDP_MESSAGE_SIZE;
const DNS_BIND_UDP_MAX_INFLIGHT: usize = 128;
const DNS_BIND_TCP_MAX_INFLIGHT: usize = 128;
const DNS_BIND_TCP_IO_TIMEOUT: std::time::Duration = RESIDENT_UDP_RESPONSE_TIMEOUT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentDnsBindEndpoint {
    udp: bool,
    tcp: bool,
    addr: SocketAddr,
}

impl ResidentDnsBindEndpoint {
    const fn network(self) -> &'static str {
        match (self.tcp, self.udp) {
            (true, true) => "tcp+udp",
            (true, false) => "tcp",
            (false, true) => "udp",
            (false, false) => "none",
        }
    }
}

pub(super) struct ResidentDnsBindListener {
    udp_socket: Option<UdpSocket>,
    tcp_listener: Option<StdTcpListener>,
    configured: String,
    endpoint: ResidentDnsBindEndpoint,
    udp_local_addr: Option<SocketAddr>,
    tcp_local_addr: Option<SocketAddr>,
}

impl ResidentDnsBindListener {
    pub(super) fn report(&self) -> Value {
        json!({
            "enabled": true,
            "network": self.endpoint.network(),
            "configured": self.configured,
            "udp_local_addr": self.udp_local_addr.map(|addr| addr.to_string()),
            "tcp_local_addr": self.tcp_local_addr.map(|addr| addr.to_string()),
            "status": "pass",
        })
    }
}

pub(super) fn disabled_dns_bind_listener_report() -> Value {
    json!({
        "enabled": false,
        "network": "none",
        "status": "disabled",
        "reason": "dns.bind is empty",
    })
}

pub(super) fn prepare_resident_dns_bind_listener(
    bind: &str,
) -> Result<Option<ResidentDnsBindListener>, String> {
    let Some(endpoint) = parse_resident_dns_bind_endpoint(bind)? else {
        return Ok(None);
    };
    let udp_socket = if endpoint.udp {
        let socket = UdpSocket::bind(endpoint.addr)
            .map_err(|err| format!("bind resident DNS UDP listener {}: {err}", endpoint.addr))?;
        socket
            .set_nonblocking(true)
            .map_err(|err| format!("set resident DNS UDP listener nonblocking: {err}"))?;
        Some(socket)
    } else {
        None
    };
    let tcp_listener = if endpoint.tcp {
        let listener = StdTcpListener::bind(endpoint.addr)
            .map_err(|err| format!("bind resident DNS TCP listener {}: {err}", endpoint.addr))?;
        listener
            .set_nonblocking(true)
            .map_err(|err| format!("set resident DNS TCP listener nonblocking: {err}"))?;
        Some(listener)
    } else {
        None
    };
    let udp_local_addr = udp_socket
        .as_ref()
        .map(UdpSocket::local_addr)
        .transpose()
        .map_err(|err| format!("read resident DNS UDP listener local addr: {err}"))?;
    let tcp_local_addr = tcp_listener
        .as_ref()
        .map(StdTcpListener::local_addr)
        .transpose()
        .map_err(|err| format!("read resident DNS TCP listener local addr: {err}"))?;
    Ok(Some(ResidentDnsBindListener {
        udp_socket,
        tcp_listener,
        configured: bind.trim().to_owned(),
        endpoint,
        udp_local_addr,
        tcp_local_addr,
    }))
}

pub(super) async fn run_resident_dns_bind_listener_async(
    mut listener: ResidentDnsBindListener,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    let configured = listener.configured.clone();
    let mut tasks = Vec::new();
    if let Some(socket) = listener.udp_socket.take() {
        let local_addr = listener.udp_local_addr.expect("udp local addr was read");
        match TokioUdpSocket::from_std(socket) {
            Ok(socket) => {
                tasks.push(tokio::spawn(run_resident_dns_udp_bind_listener_async(
                    socket,
                    configured.clone(),
                    local_addr,
                    Arc::clone(&dns),
                    Arc::clone(&stop),
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    Arc::clone(&metrics),
                )));
            }
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "dns_bind_listener_start_failed",
                    "configured": configured,
                    "local_addr": local_addr.to_string(),
                    "network": "udp",
                    "error": format!("adopt async resident DNS UDP listener: {err}"),
                }),
            ),
        }
    }
    if let Some(tcp_listener) = listener.tcp_listener.take() {
        let local_addr = listener.tcp_local_addr.expect("tcp local addr was read");
        match TokioTcpListener::from_std(tcp_listener) {
            Ok(tcp_listener) => {
                tasks.push(tokio::spawn(run_resident_dns_tcp_bind_listener_async(
                    tcp_listener,
                    configured.clone(),
                    local_addr,
                    dns,
                    stop,
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    metrics,
                )));
            }
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "dns_bind_listener_start_failed",
                    "configured": configured,
                    "local_addr": local_addr.to_string(),
                    "network": "tcp",
                    "error": format!("adopt async resident DNS TCP listener: {err}"),
                }),
            ),
        }
    }
    if tasks.is_empty() {
        append_event(
            &event_file,
            &event_lock,
            json!({
                "event": "dns_bind_listener_start_failed",
                "configured": configured,
                "error": "no resident DNS bind listener socket was started",
            }),
        );
        return;
    }
    for task in tasks {
        let _ = task.await;
    }
}

async fn run_resident_dns_udp_bind_listener_async(
    socket: TokioUdpSocket,
    configured: String,
    local_addr: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_started",
            "configured": configured,
            "local_addr": local_addr.to_string(),
            "network": "udp",
            "handler": "resident-dns-udp",
            "max_inflight": DNS_BIND_UDP_MAX_INFLIGHT,
        }),
    );
    let socket = Arc::new(socket);
    let semaphore = Arc::new(Semaphore::new(DNS_BIND_UDP_MAX_INFLIGHT));
    let mut tasks = tokio::task::JoinSet::new();
    let mut buf = vec![0_u8; DNS_BIND_READ_LIMIT];
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            received = socket.recv_from(&mut buf) => {
                let (read, peer) = match received {
                    Ok(received) => received,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        if !stop.load(Ordering::Relaxed) {
                            append_event(
                                &event_file,
                                &event_lock,
                                json!({
                                    "event": "dns_bind_receive_failed",
                                    "local_addr": local_addr.to_string(),
                                    "network": "udp",
                                    "error": err.to_string(),
                                }),
                            );
                        }
                        continue;
                    }
                };
                let request = buf[..read].to_vec();
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        metrics.add_upload(request.len());
                        let _ = send_resident_dns_udp_bind_failure_response(
                            &socket,
                            peer,
                            &request,
                            metrics.as_ref(),
                        ).await;
                        append_event(
                            &event_file,
                            &event_lock,
                            json!({
                                "event": "dns_bind_overloaded",
                                "local_addr": local_addr.to_string(),
                                "peer": peer.to_string(),
                                "network": "udp",
                                "max_inflight": DNS_BIND_UDP_MAX_INFLIGHT,
                            }),
                        );
                        continue;
                    }
                    Err(tokio::sync::TryAcquireError::Closed) => break,
                };
                tasks.spawn(handle_resident_dns_udp_bind_packet_async(
                    Arc::clone(&socket),
                    local_addr,
                    peer,
                    Arc::clone(&dns),
                    request,
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    Arc::clone(&metrics),
                    permit,
                ));
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {}
        }
    }
    if time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_stopped",
            "local_addr": local_addr.to_string(),
            "network": "udp",
        }),
    );
}

async fn handle_resident_dns_udp_bind_packet_async(
    socket: Arc<TokioUdpSocket>,
    local_addr: SocketAddr,
    peer: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    request: Vec<u8>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    metrics.udp_opened();
    metrics.add_upload(request.len());
    let result = handle_resident_dns_local_trace_async(&dns, local_addr, &request).await;
    match result {
        Ok(result) => {
            let response = result.response;
            let response_len = response.len();
            match socket.send_to(&response, peer).await {
                Ok(sent) => {
                    metrics.add_download(sent);
                    append_event(
                        &event_file,
                        &event_lock,
                        dns_path_chosen_event(DnsPathChosenEventInput {
                            local_addr,
                            peer,
                            network: "udp",
                            handler: "resident-dns-udp",
                            request_bytes: request.len(),
                            response_bytes: response_len,
                            sent_bytes: Some(sent),
                            send_error: None,
                            trace: &result.trace,
                        }),
                    );
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_query_finished",
                            "local_addr": local_addr.to_string(),
                            "peer": peer.to_string(),
                            "network": "udp",
                            "request_bytes": request.len(),
                            "response_bytes": response_len,
                            "sent_bytes": sent,
                            "handler": "resident-dns-udp",
                        }),
                    );
                }
                Err(err) => {
                    let err = err.to_string();
                    append_event(
                        &event_file,
                        &event_lock,
                        dns_path_chosen_event(DnsPathChosenEventInput {
                            local_addr,
                            peer,
                            network: "udp",
                            handler: "resident-dns-udp",
                            request_bytes: request.len(),
                            response_bytes: response_len,
                            sent_bytes: None,
                            send_error: Some(&err),
                            trace: &result.trace,
                        }),
                    );
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_response_send_failed",
                            "local_addr": local_addr.to_string(),
                            "peer": peer.to_string(),
                            "network": "udp",
                            "request_bytes": request.len(),
                            "response_bytes": response_len,
                            "error": err,
                        }),
                    );
                }
            }
        }
        Err(err) => {
            let _ = send_resident_dns_udp_bind_failure_response(
                &socket,
                peer,
                &request,
                metrics.as_ref(),
            )
            .await;
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "dns_bind_query_failed",
                    "local_addr": local_addr.to_string(),
                    "peer": peer.to_string(),
                    "network": "udp",
                    "request_bytes": request.len(),
                    "error": err,
                }),
            );
        }
    }
    metrics.udp_closed();
}

async fn send_resident_dns_udp_bind_failure_response(
    socket: &TokioUdpSocket,
    peer: SocketAddr,
    request: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let Some(response) = dns_bind_failure_response(request) else {
        return Ok(());
    };
    let sent = socket
        .send_to(&response, peer)
        .await
        .map_err(|err| format!("send DNS bind UDP failure response: {err}"))?;
    metrics.add_download(sent);
    Ok(())
}

async fn run_resident_dns_tcp_bind_listener_async(
    listener: TokioTcpListener,
    configured: String,
    local_addr: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_started",
            "configured": configured,
            "local_addr": local_addr.to_string(),
            "network": "tcp",
            "handler": "resident-dns-tcp",
            "max_inflight": DNS_BIND_TCP_MAX_INFLIGHT,
        }),
    );
    let semaphore = Arc::new(Semaphore::new(DNS_BIND_TCP_MAX_INFLIGHT));
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        if !stop.load(Ordering::Relaxed) {
                            append_event(
                                &event_file,
                                &event_lock,
                                json!({
                                    "event": "dns_bind_accept_failed",
                                    "local_addr": local_addr.to_string(),
                                    "network": "tcp",
                                    "error": err.to_string(),
                                }),
                            );
                        }
                        continue;
                    }
                };
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        append_event(
                            &event_file,
                            &event_lock,
                            json!({
                                "event": "dns_bind_overloaded",
                                "local_addr": local_addr.to_string(),
                                "peer": peer.to_string(),
                                "network": "tcp",
                                "max_inflight": DNS_BIND_TCP_MAX_INFLIGHT,
                            }),
                        );
                        drop(stream);
                        continue;
                    }
                    Err(tokio::sync::TryAcquireError::Closed) => break,
                };
                tokio::spawn(handle_resident_dns_tcp_bind_connection_async(
                    stream,
                    peer,
                    local_addr,
                    Arc::clone(&dns),
                    Arc::clone(&stop),
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    Arc::clone(&metrics),
                    permit,
                ));
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP) => {}
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "dns_bind_listener_stopped",
            "local_addr": local_addr.to_string(),
            "network": "tcp",
        }),
    );
}

async fn handle_resident_dns_tcp_bind_connection_async(
    mut stream: TokioTcpStream,
    peer: SocketAddr,
    local_addr: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let request = match read_dns_tcp_payload_bind_timeout_async(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(err) => {
                append_event(
                    &event_file,
                    &event_lock,
                    json!({
                        "event": "dns_bind_receive_failed",
                        "local_addr": local_addr.to_string(),
                        "peer": peer.to_string(),
                        "network": "tcp",
                        "error": err,
                    }),
                );
                return;
            }
        };
        metrics.add_upload(request.len());
        let result = handle_resident_dns_local_trace_async(&dns, local_addr, &request).await;
        match result {
            Ok(result) => {
                let response = result.response;
                let response_len = response.len();
                if let Err(err) =
                    write_dns_tcp_payload_bind_timeout_async(&mut stream, &response).await
                {
                    let err = err.to_string();
                    append_event(
                        &event_file,
                        &event_lock,
                        dns_path_chosen_event(DnsPathChosenEventInput {
                            local_addr,
                            peer,
                            network: "tcp",
                            handler: "resident-dns-tcp",
                            request_bytes: request.len(),
                            response_bytes: response_len,
                            sent_bytes: None,
                            send_error: Some(&err),
                            trace: &result.trace,
                        }),
                    );
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_response_send_failed",
                            "local_addr": local_addr.to_string(),
                            "peer": peer.to_string(),
                            "network": "tcp",
                            "request_bytes": request.len(),
                            "response_bytes": response_len,
                            "error": err,
                        }),
                    );
                    return;
                }
                metrics.add_download(response_len);
                append_event(
                    &event_file,
                    &event_lock,
                    dns_path_chosen_event(DnsPathChosenEventInput {
                        local_addr,
                        peer,
                        network: "tcp",
                        handler: "resident-dns-tcp",
                        request_bytes: request.len(),
                        response_bytes: response_len,
                        sent_bytes: Some(response_len + 2),
                        send_error: None,
                        trace: &result.trace,
                    }),
                );
                append_event(
                    &event_file,
                    &event_lock,
                    json!({
                        "event": "dns_bind_query_finished",
                        "local_addr": local_addr.to_string(),
                        "peer": peer.to_string(),
                        "network": "tcp",
                        "request_bytes": request.len(),
                        "response_bytes": response_len,
                        "sent_bytes": response_len + 2,
                        "handler": "resident-dns-tcp",
                    }),
                );
            }
            Err(err) => {
                let _ = write_resident_dns_tcp_bind_failure_response(
                    &mut stream,
                    &request,
                    metrics.as_ref(),
                )
                .await;
                append_event(
                    &event_file,
                    &event_lock,
                    json!({
                        "event": "dns_bind_query_failed",
                        "local_addr": local_addr.to_string(),
                        "peer": peer.to_string(),
                        "network": "tcp",
                        "request_bytes": request.len(),
                        "error": err,
                    }),
                );
            }
        }
    }
}

async fn write_resident_dns_tcp_bind_failure_response(
    stream: &mut TokioTcpStream,
    request: &[u8],
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let Some(response) = dns_bind_failure_response(request) else {
        return Ok(());
    };
    write_dns_tcp_payload_bind_timeout_async(stream, &response).await?;
    metrics.add_download(response.len());
    Ok(())
}

async fn read_dns_tcp_payload_bind_timeout_async(
    stream: &mut TokioTcpStream,
) -> Result<Option<Vec<u8>>, String> {
    read_dns_tcp_payload_with_timeout_async(stream, DNS_BIND_TCP_IO_TIMEOUT).await
}

async fn read_dns_tcp_payload_with_timeout_async<S>(
    stream: &mut S,
    timeout: std::time::Duration,
) -> Result<Option<Vec<u8>>, String>
where
    S: AsyncRead + Unpin,
{
    time::timeout(timeout, read_dns_tcp_payload_async(stream))
        .await
        .map_err(|_| "DNS TCP bind read timeout".to_owned())?
}

async fn write_dns_tcp_payload_bind_timeout_async(
    stream: &mut TokioTcpStream,
    payload: &[u8],
) -> Result<(), String> {
    write_dns_tcp_payload_with_timeout_async(stream, payload, DNS_BIND_TCP_IO_TIMEOUT).await
}

async fn write_dns_tcp_payload_with_timeout_async<S>(
    stream: &mut S,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    time::timeout(timeout, write_dns_tcp_payload_async(stream, payload))
        .await
        .map_err(|_| "DNS TCP bind write timeout".to_owned())?
}

fn dns_bind_failure_response(request: &[u8]) -> Option<Vec<u8>> {
    build_dns_server_failure_response(request).ok()
}

struct DnsPathChosenEventInput<'a> {
    local_addr: SocketAddr,
    peer: SocketAddr,
    network: &'a str,
    handler: &'a str,
    request_bytes: usize,
    response_bytes: usize,
    sent_bytes: Option<usize>,
    send_error: Option<&'a str>,
    trace: &'a ResidentDnsTraceSummary,
}

fn dns_path_chosen_event(input: DnsPathChosenEventInput<'_>) -> Value {
    let mut event = json!({
        "event": "dns_path_chosen",
        "local_addr": input.local_addr.to_string(),
        "peer": input.peer.to_string(),
        "network": input.network,
        "handler": input.handler,
        "request_bytes": input.request_bytes,
        "response_bytes": input.response_bytes,
        "sent_bytes": input.sent_bytes,
        "qname": &input.trace.qname,
        "qtype": input.trace.qtype,
        "qclass": input.trace.qclass,
        "cache": &input.trace.cache,
        "routing": &input.trace.request_routing,
        "request_routing": &input.trace.request_routing,
        "response_routing": &input.trace.response_routing,
        "upstream": &input.trace.upstream,
        "upstream_scheme": input.trace.upstream_scheme,
        "upstream_chain": &input.trace.upstream_chain,
        "reroutes": input.trace.reroutes,
        "fallback": input.trace.fallback,
        "rcode": input.trace.rcode,
        "reason": &input.trace.reason,
        "total_ms": input.trace.total_ms,
        "cache_ms": input.trace.cache_ms,
        "routing_ms": input.trace.routing_ms,
        "upstream_ms": input.trace.upstream_ms,
        "transport_attempts": dns_transport_attempts_value(&input.trace.transport_attempts),
    });
    if let Some(send_error) = input.send_error
        && let Some(map) = event.as_object_mut()
    {
        map.insert(
            "send_error".to_owned(),
            Value::String(send_error.to_owned()),
        );
    }
    event
}

fn dns_transport_attempts_value(attempts: &[ResidentDnsTransportTrace]) -> Value {
    Value::Array(
        attempts
            .iter()
            .map(|attempt| {
                json!({
                    "upstream": &attempt.upstream,
                    "scheme": attempt.scheme,
                    "target": &attempt.target,
                    "target_family": attempt.target_family,
                    "l4proto": attempt.l4proto,
                    "route": attempt.route,
                    "elapsed_ms": attempt.elapsed_ms,
                    "outcome": attempt.outcome,
                    "error": &attempt.error,
                })
            })
            .collect(),
    )
}

fn parse_resident_dns_bind_endpoint(bind: &str) -> Result<Option<ResidentDnsBindEndpoint>, String> {
    let bind = bind.trim();
    if bind.is_empty() {
        return Ok(None);
    }
    let (tcp, udp, addr) = if let Some((scheme, addr)) = bind.split_once("://") {
        let mut tcp = false;
        let mut udp = false;
        for item in scheme.split('+') {
            match item {
                "tcp" => tcp = true,
                "udp" => udp = true,
                other => {
                    return Err(format!(
                        "resident DNS bind listener has unsupported protocol {other:?} in dns.bind {bind:?}"
                    ));
                }
            }
        }
        if !tcp && !udp {
            return Err(format!(
                "resident DNS bind listener has no protocol in dns.bind {bind:?}"
            ));
        }
        (tcp, udp, addr)
    } else {
        (false, true, bind)
    };
    let addr = addr
        .parse::<SocketAddr>()
        .map_err(|err| format!("parse dns.bind {bind:?} as socket addr: {err}"))?;
    Ok(Some(ResidentDnsBindEndpoint { udp, tcp, addr }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use dae_dns::{
        DNS_DEFAULT_PORT, DNS_FLAG_RESPONSE, DNS_HEADER_LEN, DNS_RCODE_MASK, DNS_RCODE_SERVFAIL,
        DnsPacketView,
    };

    const QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    fn dns_bind_test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_DEFAULT_PORT)
    }

    fn dns_bind_endpoint(udp: bool, tcp: bool) -> ResidentDnsBindEndpoint {
        ResidentDnsBindEndpoint {
            udp,
            tcp,
            addr: dns_bind_test_addr(),
        }
    }

    fn dns_bind_value(scheme: Option<&str>) -> String {
        match scheme {
            Some(scheme) => format!("{scheme}://{}", dns_bind_test_addr()),
            None => dns_bind_test_addr().to_string(),
        }
    }

    #[test]
    fn resident_dns_bind_endpoint_accepts_empty_udp_and_tcp_forms() {
        let udp = dns_bind_endpoint(true, false);
        let tcp = dns_bind_endpoint(false, true);
        let both = dns_bind_endpoint(true, true);

        assert_eq!(parse_resident_dns_bind_endpoint("").unwrap(), None);
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(None)).unwrap(),
            Some(udp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("udp"))).unwrap(),
            Some(udp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("tcp"))).unwrap(),
            Some(tcp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("tcp+udp"))).unwrap(),
            Some(both)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint(&dns_bind_value(Some("udp+tcp"))).unwrap(),
            Some(both)
        );
    }

    #[test]
    fn resident_dns_bind_endpoint_rejects_invalid_values() {
        assert!(parse_resident_dns_bind_endpoint(&Ipv4Addr::LOCALHOST.to_string()).is_err());
        assert!(parse_resident_dns_bind_endpoint(&dns_bind_value(Some("http"))).is_err());
    }

    #[test]
    fn dns_path_chosen_event_exposes_trace_summary_fields() {
        let local_addr = dns_bind_test_addr();
        let peer = SocketAddr::new(
            local_addr.ip(),
            local_addr
                .port()
                .saturating_add(u16::from(QUERY[0] != QUERY[1])),
        );
        let handler = "resident-dns-udp";
        let network = handler.strip_prefix("resident-dns-").unwrap();
        let request = DnsPacketView::parse(QUERY).unwrap();
        let question = request.questions().next().unwrap();
        let qname = question.qname_to_canonical_string().unwrap();
        let qtype = question.qtype();
        let qclass = question.qclass();
        let upstream_tag = qname.trim_end_matches('.').to_owned();
        let upstream = Some(upstream_tag.clone());
        let upstream_scheme = Some(network);
        let upstream_chain = vec![upstream_tag.clone()];
        let reroutes = 0_usize;
        let fallback = false;
        let rcode = Some(u16::from(QUERY[3] & DNS_RCODE_MASK as u8));
        let request_bytes = QUERY.len();
        let response_bytes = request_bytes.saturating_add(DNS_HEADER_LEN);
        let sent_bytes = Some(response_bytes);
        let transport_target = local_addr.to_string();
        let mut trace = ResidentDnsTraceSummary::new_for_test(qname.clone(), qtype, qclass);
        trace.upstream = upstream.clone();
        trace.upstream_scheme = upstream_scheme;
        trace.upstream_chain = upstream_chain.clone();
        trace.reroutes = reroutes;
        trace.fallback = fallback;
        trace.rcode = rcode;
        let reason = format!("{}:{}", trace.request_routing, trace.response_routing);
        trace.reason = reason.clone();
        trace.cache_ms = u64::try_from(request.question_count()).unwrap_or_default();
        trace.routing_ms = u64::try_from(request_bytes).unwrap_or_default();
        trace.upstream_ms = u64::try_from(response_bytes).unwrap_or_default();
        trace.total_ms = trace
            .cache_ms
            .saturating_add(trace.routing_ms)
            .saturating_add(trace.upstream_ms);
        trace.transport_attempts = vec![ResidentDnsTransportTrace {
            upstream: upstream_tag,
            scheme: network,
            target: transport_target.clone(),
            target_family: if local_addr.is_ipv6() {
                DNS_TRANSPORT_TARGET_FAMILY_IPV6
            } else {
                DNS_TRANSPORT_TARGET_FAMILY_IPV4
            },
            l4proto: network,
            route: DNS_TRANSPORT_ROUTE_DIRECT,
            elapsed_ms: trace.upstream_ms,
            outcome: DNS_TRANSPORT_OUTCOME_SUCCESS,
            error: None,
        }];
        let event = dns_path_chosen_event(DnsPathChosenEventInput {
            local_addr,
            peer,
            network,
            handler,
            request_bytes,
            response_bytes,
            sent_bytes,
            send_error: None,
            trace: &trace,
        });

        assert_eq!(event["event"], "dns_path_chosen");
        assert_eq!(event["network"], network);
        assert_eq!(event["handler"], handler);
        assert_eq!(event["qname"], qname);
        assert_eq!(event["qtype"], qtype);
        assert_eq!(event["qclass"], qclass);
        assert_eq!(event["cache"], trace.cache);
        assert_eq!(event["routing"], trace.request_routing);
        assert_eq!(event["request_routing"], trace.request_routing);
        assert_eq!(event["response_routing"], trace.response_routing);
        assert_eq!(event["upstream"], json!(upstream));
        assert_eq!(event["upstream_scheme"], json!(upstream_scheme));
        assert_eq!(event["upstream_chain"][0], upstream_chain[0]);
        assert_eq!(event["reroutes"], reroutes);
        assert_eq!(event["fallback"], fallback);
        assert_eq!(event["rcode"], json!(rcode));
        assert_eq!(event["sent_bytes"], json!(sent_bytes));
        assert_eq!(event["reason"], reason);
        assert_eq!(event["total_ms"], trace.total_ms);
        assert_eq!(event["cache_ms"], trace.cache_ms);
        assert_eq!(event["routing_ms"], trace.routing_ms);
        assert_eq!(event["upstream_ms"], trace.upstream_ms);
        assert_eq!(
            event["transport_attempts"][0]["route"],
            DNS_TRANSPORT_ROUTE_DIRECT
        );
        assert_eq!(event["transport_attempts"][0]["target"], transport_target);
        assert_eq!(
            event["transport_attempts"][0]["target_family"],
            if local_addr.is_ipv6() {
                DNS_TRANSPORT_TARGET_FAMILY_IPV6
            } else {
                DNS_TRANSPORT_TARGET_FAMILY_IPV4
            }
        );
    }

    #[test]
    fn dns_bind_failure_response_returns_servfail_for_valid_query() {
        let response = dns_bind_failure_response(QUERY).unwrap();
        let flags = u16::from_be_bytes([response[2], response[3]]);

        assert_eq!(&response[0..2], &QUERY[0..2]);
        assert_eq!(flags & DNS_RCODE_MASK, DNS_RCODE_SERVFAIL);
        assert_eq!(&response[DNS_HEADER_LEN..], &QUERY[DNS_HEADER_LEN..]);
    }

    #[test]
    fn dns_bind_failure_response_ignores_non_request_payload() {
        let mut response = QUERY.to_vec();
        response[2] |= (DNS_FLAG_RESPONSE >> 8) as u8;

        assert!(dns_bind_failure_response(&response).is_none());
        assert!(dns_bind_failure_response(&[]).is_none());
    }

    #[tokio::test]
    async fn dns_bind_tcp_read_timeout_closes_slow_client() {
        let (_client, mut server) = tokio::io::duplex(64);

        let err = read_dns_tcp_payload_with_timeout_async(&mut server, Duration::from_millis(1))
            .await
            .unwrap_err();

        assert!(err.contains("read timeout"));
    }

    #[tokio::test]
    async fn dns_bind_tcp_write_timeout_closes_slow_client() {
        let (mut client, _server) = tokio::io::duplex(1);

        let err =
            write_dns_tcp_payload_with_timeout_async(&mut client, QUERY, Duration::from_millis(1))
                .await
                .unwrap_err();

        assert!(err.contains("write timeout"));
    }
}
