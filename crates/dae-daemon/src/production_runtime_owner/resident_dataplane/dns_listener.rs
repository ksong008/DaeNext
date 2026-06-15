use std::io;
use std::net::{SocketAddr, UdpSocket};

use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time;

use super::dns::{ResidentDnsPlan, handle_resident_dns_udp_async};
use super::*;

const DNS_BIND_READ_LIMIT: usize = 4096;

pub(super) struct ResidentDnsBindListener {
    socket: UdpSocket,
    configured: String,
    local_addr: SocketAddr,
}

impl ResidentDnsBindListener {
    pub(super) fn report(&self) -> Value {
        json!({
            "enabled": true,
            "network": "udp",
            "configured": self.configured,
            "local_addr": self.local_addr.to_string(),
            "status": "pass",
        })
    }
}

pub(super) fn disabled_dns_bind_listener_report() -> Value {
    json!({
        "enabled": false,
        "network": "udp",
        "status": "disabled",
        "reason": "dns.bind is empty",
    })
}

pub(super) fn prepare_resident_dns_bind_listener(
    bind: &str,
) -> Result<Option<ResidentDnsBindListener>, String> {
    let Some(addr) = parse_resident_dns_bind_addr(bind)? else {
        return Ok(None);
    };
    let socket =
        UdpSocket::bind(addr).map_err(|err| format!("bind resident DNS listener {addr}: {err}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set resident DNS listener nonblocking: {err}"))?;
    let local_addr = socket
        .local_addr()
        .map_err(|err| format!("read resident DNS listener local addr: {err}"))?;
    Ok(Some(ResidentDnsBindListener {
        socket,
        configured: bind.trim().to_owned(),
        local_addr,
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
    listener: ResidentDnsBindListener,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    let configured = listener.configured.clone();
    let local_addr = listener.local_addr;
    let socket = match TokioUdpSocket::from_std(listener.socket) {
        Ok(socket) => socket,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "dns_bind_listener_start_failed",
                    "configured": configured,
                    "local_addr": local_addr.to_string(),
                    "error": format!("adopt async resident DNS listener: {err}"),
                }),
            );
            return;
        }
    };
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
                                    "error": err.to_string(),
                                }),
                            );
                        }
                        continue;
                    }
                };
                metrics.udp_opened();
                metrics.add_upload(read);
                let response = handle_resident_dns_udp_async(&dns, local_addr, &buf[..read]).await;
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
                                        "request_bytes": read,
                                        "response_bytes": response_len,
                                        "sent_bytes": sent,
                                        "handler": "resident-dns-udp",
                                    }),
                                );
                            }
                            Err(err) => {
                                append_event(
                                    &event_file,
                                    &event_lock,
                                    json!({
                                        "event": "dns_bind_response_send_failed",
                                        "local_addr": local_addr.to_string(),
                                        "peer": peer.to_string(),
                                        "request_bytes": read,
                                        "response_bytes": response_len,
                                        "error": err.to_string(),
                                    }),
                                );
                            }
                        }
                    }
                    Err(err) => {
                        append_event(
                            &event_file,
                            &event_lock,
                            json!({
                                "event": "dns_bind_query_failed",
                                "local_addr": local_addr.to_string(),
                                "peer": peer.to_string(),
                                "request_bytes": read,
                                "error": err,
                            }),
                        );
                    }
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

fn parse_resident_dns_bind_addr(bind: &str) -> Result<Option<SocketAddr>, String> {
    let bind = bind.trim();
    if bind.is_empty() {
        return Ok(None);
    }
    let addr = bind
        .strip_prefix("udp://")
        .or_else(|| bind.strip_prefix("tcp+udp://"))
        .unwrap_or(bind);
    if bind.starts_with("tcp://") {
        return Err(
            "resident DNS bind listener currently supports UDP dns.bind, not tcp-only dns.bind"
                .to_owned(),
        );
    }
    addr.parse::<SocketAddr>()
        .map(Some)
        .map_err(|err| format!("parse dns.bind {bind:?} as socket addr: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_dns_bind_addr_accepts_empty_and_udp_forms() {
        assert_eq!(parse_resident_dns_bind_addr("").unwrap(), None);
        assert_eq!(
            parse_resident_dns_bind_addr("127.0.0.1:8053").unwrap(),
            Some("127.0.0.1:8053".parse().unwrap())
        );
        assert_eq!(
            parse_resident_dns_bind_addr("udp://127.0.0.1:8053").unwrap(),
            Some("127.0.0.1:8053".parse().unwrap())
        );
        assert_eq!(
            parse_resident_dns_bind_addr("tcp+udp://127.0.0.1:8053").unwrap(),
            Some("127.0.0.1:8053".parse().unwrap())
        );
    }

    #[test]
    fn resident_dns_bind_addr_rejects_tcp_only_and_invalid_values() {
        assert!(parse_resident_dns_bind_addr("tcp://127.0.0.1:8053").is_err());
        assert!(parse_resident_dns_bind_addr("127.0.0.1").is_err());
    }
}
