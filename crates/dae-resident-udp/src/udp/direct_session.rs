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
const UDP_DIRECT_RESPONSE_DRAIN_BUDGET: usize = 16;

#[derive(Clone, Debug)]
pub struct UdpDirectSessionKey {
    peer: SocketAddr,
    original_destination: SocketAddr,
    mark: u32,
}

impl UdpDirectSessionKey {
    pub fn new(peer: SocketAddr, original_destination: SocketAddr, mark: u32) -> Self {
        Self {
            peer,
            original_destination,
            mark,
        }
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn original_destination(&self) -> SocketAddr {
        self.original_destination
    }

    pub fn mark(&self) -> u32 {
        self.mark
    }

    pub fn idle_timeout(&self, session_idle_timeout: Duration) -> Duration {
        if self.original_destination.port() == dae_dns::DNS_DEFAULT_PORT {
            RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT
        } else {
            session_idle_timeout
        }
    }

    pub fn to_value(&self) -> serde_json::Value {
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
            "sourceContract": ResidentUdpSourceContract::direct().json(),
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

pub struct ManagedDirectUdpPacket {
    pub packet: UdpOriginalDstPacket,
    pub original_dst: SocketAddr,
    pub dscp: u8,
}

pub struct UdpDirectSessionEntry {
    pub sender: mpsc::Sender<ManagedDirectUdpPacket>,
    pub handle: JoinHandle<()>,
}

pub type UdpDirectSessionActorContext = Arc<UdpSessionSharedContext>;

pub fn spawn_udp_direct_session_actor(
    key: UdpDirectSessionKey,
    actor_id: u64,
    context: UdpDirectSessionActorContext,
    receiver: mpsc::Receiver<ManagedDirectUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_udp_direct_session_actor(key, actor_id, context, receiver, cleanup_tx).await;
    })
}

async fn run_udp_direct_session_actor(
    key: UdpDirectSessionKey,
    actor_id: u64,
    context: UdpDirectSessionActorContext,
    mut receiver: mpsc::Receiver<ManagedDirectUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
) {
    let _cleanup_guard = UdpSessionCleanupGuard::new(
        key.clone(),
        actor_id,
        cleanup_tx,
        Arc::clone(&context.metrics),
    );
    let _guard = UdpManagedSessionGuard::new(
        Arc::clone(&context.active_sessions),
        Arc::clone(&context.metrics),
    );
    append_event_with_metadata(
        &context.event_file,
        &context.event_lock,
        ResidentEventMetadata::new(ResidentEventKind::UdpSessionStarted),
        || {
            json!({
                "event": ResidentEventKind::UdpSessionStarted.name(),
                "packetSession": key.to_value(),
            })
        },
    );

    let mut packets = 0_u64;
    let mut stop_reason = "queue-closed".to_owned();
    let mut session: Option<DirectUdpSession> = None;
    let idle_timeout = key.idle_timeout(context.session_idle_timeout);
    let idle_timer = time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    let mut stop_listener = context.actor_stop.listener();
    'session: loop {
        tokio::select! {
            biased;
            _ = stop_listener.cancelled() => {
                stop_reason = "generation-stop".to_owned();
                break;
            }
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
                    let opened = tokio::select! {
                        biased;
                        _ = stop_listener.cancelled() => {
                            stop_reason = "generation-stop".to_owned();
                            break 'session;
                        }
                        opened = DirectUdpSession::open(managed.original_dst, key.mark()) => opened,
                    };
                    match opened {
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
                    Some(session) => tokio::select! {
                        biased;
                        _ = stop_listener.cancelled() => {
                            stop_reason = "generation-stop".to_owned();
                            break 'session;
                        }
                        result = time::timeout(
                            RESIDENT_UDP_RESPONSE_TIMEOUT,
                            session.send(&managed.packet.payload, managed.original_dst),
                        ) => result,
                    },
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
                if let Some(session) = session.as_mut() {
                    let drain = drain_direct_udp_session_responses(&key, &context, session);
                    tokio::select! {
                        biased;
                        _ = stop_listener.cancelled() => {
                            stop_reason = "generation-stop".to_owned();
                            break 'session;
                        }
                        result = drain => if let Err(err) = result {
                            stop_reason = err;
                            break 'session;
                        }
                    }
                }
            }
            readiness = wait_direct_udp_session_response(session.as_ref()), if session.is_some() => {
                if let Err(err) = readiness {
                    stop_reason = err;
                    break;
                }
                if let Some(session) = session.as_mut() {
                    let drain = drain_direct_udp_session_responses(&key, &context, session);
                    tokio::select! {
                        biased;
                        _ = stop_listener.cancelled() => {
                            stop_reason = "generation-stop".to_owned();
                            break 'session;
                        }
                        result = drain => if let Err(err) = result {
                            stop_reason = err;
                            break 'session;
                        }
                    }
                }
            }
            _ = &mut idle_timer => {
                stop_reason = "idle-timeout".to_owned();
                break;
            }
            _ = wait_direct_udp_response_buffer_reclaim(
                session.as_ref(),
                context.response_buffer_idle_timeout,
            ), if session.as_ref().is_some_and(DirectUdpSession::has_response_buffer) => {
                if let Some(session) = session.as_mut() {
                    session.reclaim_response_buffer_if_idle(
                        time::Instant::now(),
                        context.response_buffer_idle_timeout,
                    );
                }
            }
        }
    }

    append_event_with_metadata(
        &context.event_file,
        &context.event_lock,
        ResidentEventMetadata::new(ResidentEventKind::UdpSessionStopped),
        || {
            json!({
                "event": ResidentEventKind::UdpSessionStopped.name(),
                "reason": stop_reason,
                "packet_count": packets,
                "packetSession": key.to_value(),
            })
        },
    );
}

async fn wait_direct_udp_session_response(
    session: Option<&DirectUdpSession>,
) -> Result<(), String> {
    match session {
        Some(session) => session.wait_readable().await,
        None => std::future::pending().await,
    }
}

async fn wait_direct_udp_response_buffer_reclaim(
    session: Option<&DirectUdpSession>,
    idle_timeout: Duration,
) {
    let Some(deadline) =
        session.and_then(|session| session.response_buffer_reclaim_deadline(idle_timeout))
    else {
        return std::future::pending().await;
    };
    time::sleep_until(deadline).await;
}

async fn drain_direct_udp_session_responses(
    key: &UdpDirectSessionKey,
    context: &UdpDirectSessionActorContext,
    session: &mut DirectUdpSession,
) -> Result<(), String> {
    for _ in 0..UDP_DIRECT_RESPONSE_DRAIN_BUDGET {
        let Some((upstream_peer, response)) = session.try_recv_response()? else {
            return Ok(());
        };
        let fixed_target =
            validate_direct_udp_response(key.original_destination(), upstream_peer, response);
        let response_len = fixed_target.payload_len();
        let validation = fixed_target.validation();
        match validation {
            UdpFixedTargetValidation::Validated => context.metrics.udp_response_validated(),
            UdpFixedTargetValidation::CompatibilityUnverified => {
                context.metrics.udp_response_compatibility_unverified()
            }
            UdpFixedTargetValidation::Dropped(_) => {
                context.metrics.udp_response_dropped(response_len);
                continue;
            }
        }
        let Some(response) = fixed_target.into_payload().ok() else {
            continue;
        };
        match context
            .udp_reply
            .send(key.original_destination(), key.peer(), response)
            .await
        {
            Ok(()) => {
                context.metrics.add_download(response_len);
                append_udp_direct_packet_finished(context, key, upstream_peer, response_len);
            }
            Err(err) => {
                if err.should_log() {
                    append_event_with_metadata(
                        &context.event_file,
                        &context.event_lock,
                        ResidentEventMetadata::new(ResidentEventKind::UdpReplyFailed),
                        || {
                            json!({
                                "event": ResidentEventKind::UdpReplyFailed.name(),
                                "peer": resident_socket_addr_display(key.peer()),
                                "original_dst": resident_socket_addr_display(key.original_destination()),
                                "upstream_peer": resident_socket_addr_display(upstream_peer),
                                "error": err.to_string(),
                            })
                        },
                    );
                }
                return Err(format!("direct-reply-failed: {err}"));
            }
        }
    }
    Ok(())
}

fn validate_direct_udp_response(
    expected_target: SocketAddr,
    upstream_peer: SocketAddr,
    payload: Vec<u8>,
) -> UdpFixedTargetPayload {
    let mut response = UdpExchangeResult::new(payload, "direct-udp")
        .with_decoded_response_identity(Some(upstream_peer), None);
    response.take_fixed_target_payload(UdpFixedTargetExpectation::decoded_source(expected_target))
}

struct DirectUdpSession {
    socket: tokio::net::UdpSocket,
    response_buf: Vec<u8>,
    response_buffer_last_used: Option<time::Instant>,
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
            response_buffer_last_used: None,
        })
    }

    async fn send(&self, payload: &[u8], target: SocketAddr) -> Result<(), String> {
        self.socket
            .send_to(payload, target)
            .await
            .map_err(|err| format!("send direct UDP datagram to {target}: {err}"))?;
        Ok(())
    }

    async fn wait_readable(&self) -> Result<(), String> {
        self.socket
            .readable()
            .await
            .map_err(|err| format!("await direct UDP response readiness: {err}"))
    }

    fn try_recv_response(&mut self) -> Result<Option<(SocketAddr, Vec<u8>)>, String> {
        if self.response_buf.len() < UDP_DIRECT_RESPONSE_CAPACITY {
            self.response_buf.resize(UDP_DIRECT_RESPONSE_CAPACITY, 0);
        }
        self.response_buffer_last_used = Some(time::Instant::now());
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

    fn has_response_buffer(&self) -> bool {
        self.response_buf.capacity() != 0
    }

    fn response_buffer_reclaim_deadline(&self, idle_timeout: Duration) -> Option<time::Instant> {
        self.response_buffer_last_used
            .and_then(|last_used| last_used.checked_add(idle_timeout))
    }

    fn reclaim_response_buffer_if_idle(
        &mut self,
        now: time::Instant,
        idle_timeout: Duration,
    ) -> bool {
        let Some(deadline) = self.response_buffer_reclaim_deadline(idle_timeout) else {
            return false;
        };
        if now < deadline {
            return false;
        }
        self.response_buf = Vec::new();
        self.response_buffer_last_used = None;
        true
    }
}

fn append_udp_direct_packet_finished(
    context: &UdpDirectSessionActorContext,
    key: &UdpDirectSessionKey,
    upstream_peer: SocketAddr,
    response_len: usize,
) {
    append_event_with_metadata(
        &context.event_file,
        &context.event_lock,
        ResidentEventMetadata::new(ResidentEventKind::UdpPacketFinished).with_route_log_context(),
        || {
            json!({
                "event": ResidentEventKind::UdpPacketFinished.name(),
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
            })
        },
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
        time::timeout(Duration::from_secs(1), session.wait_readable())
            .await
            .expect("direct UDP response readiness timeout")
            .unwrap();
        let (peer, payload) = session
            .try_recv_response()
            .unwrap()
            .expect("direct UDP response");
        assert_eq!(peer, upstream_addr);
        assert_eq!(payload, b"pong");
        server.join().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_udp_session_preserves_near_maximum_datagram() {
        const PAYLOAD_BYTES: usize = 60 * 1024;
        let upstream = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let payload = vec![0x5a; PAYLOAD_BYTES];
        let expected = payload.clone();
        let server = thread::spawn(move || {
            let mut buf = vec![0_u8; UDP_DIRECT_RESPONSE_CAPACITY];
            let (read, peer) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(read, PAYLOAD_BYTES);
            upstream.send_to(&buf[..read], peer).unwrap();
        });

        let mut session = DirectUdpSession::open(upstream_addr, 0).await.unwrap();
        session.send(&payload, upstream_addr).await.unwrap();
        time::timeout(Duration::from_secs(2), session.wait_readable())
            .await
            .expect("near-maximum direct UDP response readiness timeout")
            .unwrap();
        let (_, response) = session.try_recv_response().unwrap().unwrap();
        assert_eq!(response, expected);
        server.join().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_udp_session_waits_for_socket_readiness_without_polling() {
        let upstream = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let session = DirectUdpSession::open(upstream_addr, 0).await.unwrap();

        assert!(
            time::timeout(Duration::from_millis(20), session.wait_readable())
                .await
                .is_err(),
            "an idle direct UDP socket must remain pending"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_udp_session_releases_idle_max_datagram_buffer() {
        let upstream = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let mut session = DirectUdpSession::open(upstream.local_addr().unwrap(), 0)
            .await
            .unwrap();
        session.response_buf.resize(UDP_DIRECT_RESPONSE_CAPACITY, 0);
        let timeout = Duration::from_secs(30);
        let now = time::Instant::now();
        session.response_buffer_last_used = now.checked_sub(timeout + Duration::from_secs(1));
        assert!(session.reclaim_response_buffer_if_idle(now, timeout));
        assert_eq!(session.response_buf.capacity(), 0);
        assert!(session.response_buffer_last_used.is_none());
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
        assert_eq!(
            key.to_value()["sourceContract"]["compatibilityMode"],
            "strict-fixed-target"
        );
    }

    #[test]
    fn direct_udp_drops_datagrams_from_a_different_wire_source() {
        let expected: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let unexpected: SocketAddr = "192.0.2.11:3478".parse().unwrap();
        let accepted = validate_direct_udp_response(expected, expected, b"accepted".to_vec());
        assert_eq!(accepted.validation(), UdpFixedTargetValidation::Validated);
        assert_eq!(accepted.into_payload().unwrap(), b"accepted");

        let rejected = validate_direct_udp_response(expected, unexpected, b"rejected".to_vec());
        assert_eq!(
            rejected.validation(),
            UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
        );
        assert_eq!(rejected.payload_len(), b"rejected".len());
        assert!(rejected.into_payload().is_err());
    }
}
