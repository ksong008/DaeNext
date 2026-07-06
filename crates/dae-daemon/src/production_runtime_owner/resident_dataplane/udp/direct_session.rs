use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use sha2::Digest;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::*;

const UDP_DIRECT_OUTBOUND: &str = "direct";
const UDP_DIRECT_HANDLER: &str = "direct-udp";
const UDP_DIRECT_POLICY: &str = "fixed";
const UDP_DIRECT_PROTOCOL: &str = "direct";
const UDP_DIRECT_SESSION_EXECUTOR: &str = "tokio-direct-udp";
const UDP_DIRECT_UNDERLAY_REUSE: &str = "udp-socket-reused";
const UDP_DIRECT_RESPONSE_CAPACITY: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(super) struct UdpDirectSessionKey {
    peer: SocketAddr,
    original_destination: SocketAddr,
    mark: u32,
}

impl UdpDirectSessionKey {
    pub(super) fn new(peer: SocketAddr, original_destination: SocketAddr, mark: u32) -> Self {
        Self {
            peer,
            original_destination,
            mark,
        }
    }

    pub(super) fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub(super) fn original_destination(&self) -> SocketAddr {
        self.original_destination
    }

    pub(super) fn mark(&self) -> u32 {
        self.mark
    }

    pub(super) fn idle_timeout(&self) -> Duration {
        if self.original_destination.port() == dae_dns::DNS_DEFAULT_PORT {
            RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT
        } else {
            RESIDENT_UDP_SESSION_IDLE_TIMEOUT
        }
    }

    pub(super) fn to_value(&self) -> serde_json::Value {
        let source_display = resident_socket_addr_display(self.peer);
        let destination_display = resident_socket_addr_display(self.original_destination);
        let session_hash = direct_session_hash(self.peer, self.original_destination, self.mark);
        json!({
            "schemaVersion": 1,
            "manager": "resident-udp-session-manager",
            "outbound": UDP_DIRECT_OUTBOUND,
            "peer": source_display,
            "originalDestination": destination_display,
            "sourceDisplay": source_display,
            "destinationDisplay": destination_display,
            "packetSemantics": UdpPacketSemantics::Direct.as_str(),
            "sessionHash": session_hash,
            "limitSource": "resident-udp-session-limit",
            "directMark": self.mark,
            "sessionIdentity": {
                "schemaVersion": 1,
                "outbound": UDP_DIRECT_OUTBOUND,
                "sourceDisplay": source_display,
                "destinationDisplay": destination_display,
                "packetSemantics": UdpPacketSemantics::Direct.as_str(),
                "sessionHash": session_hash,
            },
        })
    }
}

impl PartialEq for UdpDirectSessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.peer == other.peer
            && self.original_destination == other.original_destination
            && self.mark == other.mark
    }
}

impl Eq for UdpDirectSessionKey {}

impl Hash for UdpDirectSessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.peer.hash(state);
        self.original_destination.hash(state);
        self.mark.hash(state);
    }
}

pub(super) struct ManagedDirectUdpPacket {
    pub(super) packet: UdpOriginalDstPacket,
    pub(super) original_dst: SocketAddr,
    pub(super) dscp: u8,
}

pub(super) struct UdpDirectSessionEntry {
    pub(super) sender: mpsc::Sender<ManagedDirectUdpPacket>,
    pub(super) handle: JoinHandle<()>,
}

#[derive(Clone)]
pub(super) struct UdpDirectSessionActorContext {
    pub(super) event_file: PathBuf,
    pub(super) event_lock: Arc<Mutex<()>>,
    pub(super) metrics: Arc<ResidentDataplaneMetrics>,
    pub(super) active_sessions: Arc<AtomicUsize>,
}

pub(super) fn spawn_udp_direct_session_actor(
    key: UdpDirectSessionKey,
    context: UdpDirectSessionActorContext,
    receiver: mpsc::Receiver<ManagedDirectUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpDirectSessionKey>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_udp_direct_session_actor(key, context, receiver, cleanup_tx).await;
    })
}

async fn run_udp_direct_session_actor(
    key: UdpDirectSessionKey,
    context: UdpDirectSessionActorContext,
    mut receiver: mpsc::Receiver<ManagedDirectUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpDirectSessionKey>,
) {
    let _guard = UdpManagedSessionGuard::new(
        Arc::clone(&context.active_sessions),
        Arc::clone(&context.metrics),
    );
    append_event(
        &context.event_file,
        &context.event_lock,
        json!({
            "event": "udp_session_started",
            "packetSession": key.to_value(),
        }),
    );

    let mut packets = 0_u64;
    let mut stop_reason = "queue-closed".to_owned();
    let mut session: Option<DirectUdpSession> = None;
    let idle_timeout = key.idle_timeout();
    let idle_timer = time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    loop {
        tokio::select! {
            maybe_managed = receiver.recv() => {
                let managed = match maybe_managed {
                    Some(managed) => managed,
                    None => break,
                };
                idle_timer
                    .as_mut()
                    .reset(time::Instant::now() + idle_timeout);
                packets += 1;
                if session.is_none() {
                    match DirectUdpSession::open(managed.original_dst, key.mark()).await {
                        Ok(opened) => session = Some(opened),
                        Err(err) => {
                            append_udp_direct_exchange_failed(
                                &context,
                                &key,
                                managed.original_dst,
                                managed.packet.payload.len(),
                                Some(managed.dscp),
                                err,
                            );
                            continue;
                        }
                    }
                }
                let send_result = match session.as_ref() {
                    Some(session) => time::timeout(
                        RESIDENT_UDP_RESPONSE_TIMEOUT,
                        session.send(&managed.packet.payload, managed.original_dst),
                    )
                    .await,
                    None => continue,
                };
                match send_result {
                    Ok(Ok(())) => {
                        context.metrics.add_upload(managed.packet.payload.len());
                    }
                    Ok(Err(err)) => {
                        append_udp_direct_exchange_failed(
                            &context,
                            &key,
                            managed.original_dst,
                            managed.packet.payload.len(),
                            Some(managed.dscp),
                            err,
                        );
                    }
                    Err(_) => {
                        append_udp_direct_exchange_failed(
                            &context,
                            &key,
                            managed.original_dst,
                            managed.packet.payload.len(),
                            Some(managed.dscp),
                            format!(
                                "direct UDP send timed out after {}ms",
                                RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis()
                            ),
                        );
                        stop_reason = "execute-timeout".to_owned();
                        break;
                    }
                }
                if let Some(session) = session.as_mut()
                    && let Err(err) = drain_direct_udp_session_responses(&key, &context, session).await {
                        stop_reason = err;
                        break;
                    }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP), if session.is_some() => {
                if let Some(session) = session.as_mut()
                    && let Err(err) = drain_direct_udp_session_responses(&key, &context, session).await {
                        stop_reason = err;
                        break;
                    }
            }
            _ = &mut idle_timer => {
                stop_reason = "idle-timeout".to_owned();
                break;
            }
        }
    }

    append_event(
        &context.event_file,
        &context.event_lock,
        json!({
            "event": "udp_session_stopped",
            "reason": stop_reason,
            "packet_count": packets,
            "packetSession": key.to_value(),
        }),
    );
    let _ = cleanup_tx.send(key).await;
}

async fn drain_direct_udp_session_responses(
    key: &UdpDirectSessionKey,
    context: &UdpDirectSessionActorContext,
    session: &mut DirectUdpSession,
) -> Result<(), String> {
    for _ in 0..16 {
        let Some((upstream_peer, response)) = session.poll_response()? else {
            return Ok(());
        };
        match send_udp_reply(upstream_peer, key.peer(), &response) {
            Ok(()) => {
                context.metrics.add_download(response.len());
                append_udp_direct_packet_finished(context, key, upstream_peer, response.len());
            }
            Err(err) => {
                append_event(
                    &context.event_file,
                    &context.event_lock,
                    json!({
                        "event": "udp_reply_failed",
                        "peer": resident_socket_addr_display(key.peer()),
                        "original_dst": resident_socket_addr_display(key.original_destination()),
                        "upstream_peer": resident_socket_addr_display(upstream_peer),
                        "error": err,
                    }),
                );
                return Err(format!("direct-reply-failed: {err}"));
            }
        }
    }
    Ok(())
}

struct DirectUdpSession {
    socket: tokio::net::UdpSocket,
    response_buf: Vec<u8>,
}

impl DirectUdpSession {
    async fn open(target: SocketAddr, mark: u32) -> Result<Self, String> {
        let bind = udp_unspecified_bind_addr_for_remote(target);
        let socket =
            UdpSocket::bind(bind).map_err(|err| format!("bind direct UDP socket: {err}"))?;
        if mark != 0 {
            set_socket_mark(socket.as_raw_fd(), mark)
                .map_err(|err| format!("set direct UDP SO_MARK {mark}: {err}"))?;
        }
        socket
            .set_nonblocking(true)
            .map_err(|err| format!("set direct UDP socket nonblocking: {err}"))?;
        let socket = tokio::net::UdpSocket::from_std(socket)
            .map_err(|err| format!("adopt direct UDP socket into tokio: {err}"))?;
        Ok(Self {
            socket,
            response_buf: Vec::new(),
        })
    }

    async fn send(&self, payload: &[u8], target: SocketAddr) -> Result<(), String> {
        self.socket
            .send_to(payload, target)
            .await
            .map_err(|err| format!("send direct UDP datagram to {target}: {err}"))?;
        Ok(())
    }

    fn poll_response(&mut self) -> Result<Option<(SocketAddr, Vec<u8>)>, String> {
        if self.response_buf.len() < UDP_DIRECT_RESPONSE_CAPACITY {
            self.response_buf.resize(UDP_DIRECT_RESPONSE_CAPACITY, 0);
        }
        match self.socket.try_recv_from(&mut self.response_buf) {
            Ok((read, peer)) => Ok(Some((peer, self.response_buf[..read].to_vec()))),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(format!("receive direct UDP datagram: {err}")),
        }
    }
}

fn append_udp_direct_packet_finished(
    context: &UdpDirectSessionActorContext,
    key: &UdpDirectSessionKey,
    upstream_peer: SocketAddr,
    response_len: usize,
) {
    append_event(
        &context.event_file,
        &context.event_lock,
        json!({
            "event": "udp_packet_finished",
            "peer": resident_socket_addr_display(key.peer()),
            "original_dst": resident_socket_addr_display(key.original_destination()),
            "upstream_peer": resident_socket_addr_display(upstream_peer),
            "outbound_kind": UDP_DIRECT_OUTBOUND,
            "network": resident_udp_network_name(key.original_destination()),
            "outbound": UDP_DIRECT_OUTBOUND,
            "policy": UDP_DIRECT_POLICY,
            "dialer": UDP_DIRECT_OUTBOUND,
            "ip": resident_socket_addr_display(key.original_destination()),
            "protocol": UDP_DIRECT_PROTOCOL,
            "handler": UDP_DIRECT_HANDLER,
            "request_len": 0,
            "response_len": response_len,
            "reply_forwarded": true,
            "sessionExecutor": UDP_DIRECT_SESSION_EXECUTOR,
            "underlayReuse": UDP_DIRECT_UNDERLAY_REUSE,
            "packetSession": key.to_value(),
        }),
    );
}

fn append_udp_direct_exchange_failed(
    context: &UdpDirectSessionActorContext,
    key: &UdpDirectSessionKey,
    original_dst: SocketAddr,
    request_len: usize,
    dscp: Option<u8>,
    err: String,
) {
    let mut event = json!({
        "event": "udp_exchange_failed",
        "peer": resident_socket_addr_display(key.peer()),
        "original_dst": resident_socket_addr_display(original_dst),
        "outbound_kind": UDP_DIRECT_OUTBOUND,
        "network": resident_udp_network_name(original_dst),
        "outbound": UDP_DIRECT_OUTBOUND,
        "policy": UDP_DIRECT_POLICY,
        "dialer": UDP_DIRECT_OUTBOUND,
        "ip": resident_socket_addr_display(original_dst),
        "protocol": UDP_DIRECT_PROTOCOL,
        "handler": UDP_DIRECT_HANDLER,
        "request_len": request_len,
        "error": err,
        "packetSession": key.to_value(),
    });
    if let Some(dscp) = dscp {
        event["dscp"] = json!(dscp);
    }
    append_event(&context.event_file, &context.event_lock, event);
}

fn udp_unspecified_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn direct_session_hash(peer: SocketAddr, original_dst: SocketAddr, mark: u32) -> String {
    let mut hasher = sha2::Sha256::new();
    update_direct_hash_part(&mut hasher, "udp-direct-session");
    update_direct_hash_part(&mut hasher, &peer.to_string());
    update_direct_hash_part(&mut hasher, &original_dst.to_string());
    update_direct_hash_part(&mut hasher, &mark.to_string());
    let digest = hasher.finalize();
    let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn update_direct_hash_part(hasher: &mut sha2::Sha256, part: &str) {
    use sha2::Digest;
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;
    use std::thread;

    #[tokio::test(flavor = "current_thread")]
    async fn direct_udp_session_can_exchange_with_local_echo() {
        let upstream = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut buf = [0_u8; 64];
            let (read, peer) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..read], b"ping");
            upstream.send_to(b"pong", peer).unwrap();
        });

        let mut session = DirectUdpSession::open(upstream_addr, 0).await.unwrap();
        session.send(b"ping", upstream_addr).await.unwrap();
        let mut got = None;
        for _ in 0..50 {
            if let Some((peer, payload)) = session.poll_response().unwrap() {
                got = Some((peer, payload));
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        let (peer, payload) = got.expect("direct UDP response");
        assert_eq!(peer, upstream_addr);
        assert_eq!(payload, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn direct_udp_session_key_separates_mark_and_family() {
        let peer = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10000);
        let dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3478);
        let key = UdpDirectSessionKey::new(peer, dst, 0x1234);
        let same = UdpDirectSessionKey::new(peer, dst, 0x1234);
        let other_mark = UdpDirectSessionKey::new(peer, dst, 0x5678);
        assert_eq!(key, same);
        assert_ne!(key, other_mark);
        assert_eq!(key.to_value()["packetSemantics"], "direct");
        assert_eq!(key.to_value()["directMark"], 0x1234);
    }
}
