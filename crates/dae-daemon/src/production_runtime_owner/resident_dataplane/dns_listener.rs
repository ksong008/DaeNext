use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
};
use tokio::time;

use super::dns::{ResidentDnsPlan, handle_resident_dns_local_async};
use super::*;

const DNS_BIND_READ_LIMIT: usize = 4096;
const DNS_BIND_TCP_READ_LIMIT: usize = u16::MAX as usize;

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

pub(super) fn resident_dns_bind_listener_loop(
    listener: ResidentDnsBindListener,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "dns_bind_listener_start_failed", "error": err.to_string()}),
            );
            return;
        }
    };
    runtime.block_on(run_resident_dns_bind_listener_async(
        listener, dns, stop, event_file, event_lock, metrics,
    ));
}

async fn run_resident_dns_bind_listener_async(
    mut listener: ResidentDnsBindListener,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
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
    stop: Arc<AtomicBool>,
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
        }),
    );
    let mut buf = vec![0_u8; DNS_BIND_READ_LIMIT];
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
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
                metrics.udp_opened();
                metrics.add_upload(read);
                let response = handle_resident_dns_local_async(&dns, local_addr, &buf[..read]).await;
                match response {
                    Ok(response) => {
                        let response_len = response.len();
                        match socket.send_to(&response, peer).await {
                            Ok(sent) => {
                                metrics.add_download(sent);
                                append_event(
                                    &event_file,
                                    &event_lock,
                                    json!({
                                        "event": "dns_bind_query_finished",
                                        "local_addr": local_addr.to_string(),
                                        "peer": peer.to_string(),
                                        "network": "udp",
                                        "request_bytes": read,
                                        "response_bytes": response_len,
                                        "sent_bytes": sent,
                                        "handler": "resident-dns-udp",
                                    }),
                                );
                            }
                            Err(err) => append_event(
                                &event_file,
                                &event_lock,
                                json!({
                                    "event": "dns_bind_response_send_failed",
                                    "local_addr": local_addr.to_string(),
                                    "peer": peer.to_string(),
                                    "network": "udp",
                                    "request_bytes": read,
                                    "response_bytes": response_len,
                                    "error": err.to_string(),
                                }),
                            ),
                        }
                    }
                    Err(err) => append_event(
                        &event_file,
                        &event_lock,
                        json!({
                            "event": "dns_bind_query_failed",
                            "local_addr": local_addr.to_string(),
                            "peer": peer.to_string(),
                            "network": "udp",
                            "request_bytes": read,
                            "error": err,
                        }),
                    ),
                }
                metrics.udp_closed();
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
            "network": "udp",
        }),
    );
}

async fn run_resident_dns_tcp_bind_listener_async(
    listener: TokioTcpListener,
    configured: String,
    local_addr: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
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
        }),
    );
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
                tokio::spawn(handle_resident_dns_tcp_bind_connection_async(
                    stream,
                    peer,
                    local_addr,
                    Arc::clone(&dns),
                    Arc::clone(&stop),
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    Arc::clone(&metrics),
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
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let request = match read_dns_tcp_payload_async(&mut stream).await {
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
        let response = handle_resident_dns_local_async(&dns, local_addr, &request).await;
        match response {
            Ok(response) => {
                let response_len = response.len();
                if let Err(err) = write_dns_tcp_payload_async(&mut stream, &response).await {
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
            Err(err) => append_event(
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
            ),
        }
    }
}

async fn read_dns_tcp_payload_async(
    stream: &mut TokioTcpStream,
) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0_u8; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(format!("read DNS TCP request length: {err}")),
    }
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 {
        return Err("DNS TCP request has empty payload".to_owned());
    }
    if len > DNS_BIND_TCP_READ_LIMIT {
        return Err(format!("DNS TCP request length {len} exceeds read limit"));
    }
    let mut payload = vec![0_u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|err| format!("read DNS TCP request payload: {err}"))?;
    Ok(Some(payload))
}

async fn write_dns_tcp_payload_async(
    stream: &mut TokioTcpStream,
    payload: &[u8],
) -> Result<(), String> {
    let len = u16::try_from(payload.len())
        .map_err(|_| format!("DNS TCP response exceeds frame limit: {}", payload.len()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| format!("write DNS TCP response length: {err}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|err| format!("write DNS TCP response payload: {err}"))?;
    stream
        .flush()
        .await
        .map_err(|err| format!("flush DNS TCP response: {err}"))
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

    #[test]
    fn resident_dns_bind_endpoint_accepts_empty_udp_and_tcp_forms() {
        let udp = ResidentDnsBindEndpoint {
            udp: true,
            tcp: false,
            addr: "127.0.0.1:8053".parse().unwrap(),
        };
        let tcp = ResidentDnsBindEndpoint {
            udp: false,
            tcp: true,
            addr: "127.0.0.1:8053".parse().unwrap(),
        };
        let both = ResidentDnsBindEndpoint {
            udp: true,
            tcp: true,
            addr: "127.0.0.1:8053".parse().unwrap(),
        };

        assert_eq!(parse_resident_dns_bind_endpoint("").unwrap(), None);
        assert_eq!(
            parse_resident_dns_bind_endpoint("127.0.0.1:8053").unwrap(),
            Some(udp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint("udp://127.0.0.1:8053").unwrap(),
            Some(udp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint("tcp://127.0.0.1:8053").unwrap(),
            Some(tcp)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint("tcp+udp://127.0.0.1:8053").unwrap(),
            Some(both)
        );
        assert_eq!(
            parse_resident_dns_bind_endpoint("udp+tcp://127.0.0.1:8053").unwrap(),
            Some(both)
        );
    }

    #[test]
    fn resident_dns_bind_endpoint_rejects_invalid_values() {
        assert!(parse_resident_dns_bind_endpoint("127.0.0.1").is_err());
        assert!(parse_resident_dns_bind_endpoint("http://127.0.0.1:8053").is_err());
    }
}
