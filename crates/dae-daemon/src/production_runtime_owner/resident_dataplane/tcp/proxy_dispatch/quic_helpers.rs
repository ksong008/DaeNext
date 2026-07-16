use super::*;

use crate::production_runtime_owner::resident_dataplane::{
    resolve_socket_addr_candidates, try_socket_addr_candidates,
};

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

const HYSTERIA2_SALAMANDER_SALT_LEN: usize = 8;
const HYSTERIA2_SALAMANDER_HASH_LEN: usize = 32;
pub(crate) async fn relay_tcp_over_quic_stream_async(
    inbound: &mut TokioTcpStream,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let mut stats = DirectTcpRelayStats::default();
    let mut inbound_closed = false;
    let mut proxy_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut proxy_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);

    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            read = inbound.read(&mut inbound_buf), if !inbound_closed && !proxy_closed => {
                match read {
                    Ok(0) => {
                        inbound_closed = true;
                        let _ = send.finish();
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(read) => {
                        send.write_all(&inbound_buf[..read])
                            .await
                            .map_err(|err| format!("write client payload to QUIC stream: {err}"))?;
                        send.flush()
                            .await
                            .map_err(|err| format!("flush QUIC stream: {err}"))?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        let _ = send.finish();
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read inbound TCP for QUIC stream relay: {err}")),
                }
            }
            read = recv.read(&mut proxy_buf), if !proxy_closed => {
                match read {
                    Ok(None) => {
                        proxy_closed = true;
                        let _ = inbound.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Ok(Some(read)) => {
                        if let Err(err) = inbound.write_all(&proxy_buf[..read]).await {
                            if is_graceful_stream_close_error(&err) {
                                break;
                            }
                            return Err(format!("write QUIC stream payload to client: {err}"));
                        }
                        stats.direct_to_client += read;
                        metrics.add_download(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) => return Err(format!("read QUIC stream payload: {err}")),
                }
            }
            _ = &mut idle_deadline => {
                return Err("resident QUIC stream relay idle timeout".to_owned());
            }
        }

        if proxy_closed {
            break;
        }
    }
    Ok(stats)
}

pub(crate) fn open_marked_quic_endpoint_for_remote(
    mark: u32,
    remote: SocketAddr,
    context: QuicEndpointOpenContext,
) -> Result<ObservedQuicEndpoint, String> {
    open_marked_quic_endpoint_with_runtime(
        mark,
        quinn::default_runtime(),
        remote,
        quic_bind_addr_for_remote(remote),
        QuicEndpointUnderlay::Ordinary,
        context,
    )
}

pub(crate) fn open_marked_hysteria2_quic_endpoint_for_remote(
    mark: u32,
    obfs: &ResidentHysteria2ObfsPlan,
    remote: SocketAddr,
    context: QuicEndpointOpenContext,
) -> Result<ObservedQuicEndpoint, String> {
    open_marked_hysteria2_quic_endpoint_with_bind(
        mark,
        obfs,
        remote,
        quic_bind_addr_for_remote(remote),
        context,
    )
}

fn open_marked_hysteria2_quic_endpoint_with_bind(
    mark: u32,
    obfs: &ResidentHysteria2ObfsPlan,
    remote: SocketAddr,
    bind: SocketAddr,
    context: QuicEndpointOpenContext,
) -> Result<ObservedQuicEndpoint, String> {
    let runtime = quinn::default_runtime();
    let runtime = if obfs.is_salamander() {
        let runtime = runtime.ok_or_else(|| "no quinn runtime available".to_owned())?;
        Some(Arc::new(Hysteria2SalamanderRuntime {
            inner: runtime,
            key: Arc::new(obfs.password.clone().into_bytes()),
        }) as Arc<dyn quinn::Runtime>)
    } else {
        runtime
    };
    let underlay = if obfs.is_salamander() {
        QuicEndpointUnderlay::Salamander
    } else {
        QuicEndpointUnderlay::Ordinary
    };
    open_marked_quic_endpoint_with_runtime(mark, runtime, remote, bind, underlay, context)
}

fn quic_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn open_marked_quic_endpoint_with_runtime(
    mark: u32,
    runtime: Option<Arc<dyn quinn::Runtime>>,
    remote: SocketAddr,
    bind: SocketAddr,
    underlay: QuicEndpointUnderlay,
    context: QuicEndpointOpenContext,
) -> Result<ObservedQuicEndpoint, String> {
    open_observed_quic_endpoint(mark, runtime, remote, bind, underlay, context)
}

struct Hysteria2SalamanderRuntime {
    inner: Arc<dyn quinn::Runtime>,
    key: Arc<Vec<u8>>,
}

impl fmt::Debug for Hysteria2SalamanderRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2SalamanderRuntime")
            .field("inner", &self.inner)
            .field("key", &"[redacted]")
            .finish()
    }
}

impl quinn::Runtime for Hysteria2SalamanderRuntime {
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.inner.new_timer(i)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future);
    }

    fn wrap_udp_socket(
        &self,
        t: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        let inner = self.inner.wrap_udp_socket(t)?;
        Ok(Arc::new(Hysteria2SalamanderUdpSocket {
            inner,
            key: Arc::clone(&self.key),
        }))
    }

    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }
}

struct Hysteria2SalamanderUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    key: Arc<Vec<u8>>,
}

impl fmt::Debug for Hysteria2SalamanderUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hysteria2SalamanderUdpSocket")
            .field("inner", &self.inner)
            .field("key", &"[redacted]")
            .finish()
    }
}

impl quinn::AsyncUdpSocket for Hysteria2SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 {
            return self.inner.try_send(transmit);
        }
        for chunk in transmit.contents.chunks(segment_size) {
            let packet = salamander_obfuscate_packet(&self.key, chunk);
            let obfs_transmit = udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            self.inner.try_send(&obfs_transmit)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let count = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            };
            if salamander_deobfuscate_received(&self.key, bufs, meta, count) {
                return Poll::Ready(Ok(count));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn salamander_obfuscate_packet(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HYSTERIA2_SALAMANDER_SALT_LEN + payload.len());
    let mut salt = [0_u8; HYSTERIA2_SALAMANDER_SALT_LEN];
    if getrandom::fill(&mut salt).is_err() {
        fastrand::fill(&mut salt);
    }
    out.extend_from_slice(&salt);
    let hash = salamander_hash(key, &salt);
    for (index, byte) in payload.iter().enumerate() {
        out.push(*byte ^ hash[index % HYSTERIA2_SALAMANDER_HASH_LEN]);
    }
    out
}

fn salamander_deobfuscate_received(
    key: &[u8],
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [udp::RecvMeta],
    count: usize,
) -> bool {
    if count > bufs.len() || count > meta.len() {
        return false;
    }
    for index in 0..count {
        if !salamander_deobfuscate_one(key, &mut bufs[index], &mut meta[index]) {
            return false;
        }
    }
    true
}

fn salamander_deobfuscate_one(
    key: &[u8],
    buf: &mut IoSliceMut<'_>,
    meta: &mut udp::RecvMeta,
) -> bool {
    if meta.len <= HYSTERIA2_SALAMANDER_SALT_LEN || meta.len > buf.len() {
        return false;
    }
    let raw = &mut buf[..meta.len];
    let mut salt = [0_u8; HYSTERIA2_SALAMANDER_SALT_LEN];
    salt.copy_from_slice(&raw[..HYSTERIA2_SALAMANDER_SALT_LEN]);
    let hash = salamander_hash(key, &salt);
    let payload_len = raw.len() - HYSTERIA2_SALAMANDER_SALT_LEN;
    for index in 0..payload_len {
        raw[index] = raw[index + HYSTERIA2_SALAMANDER_SALT_LEN]
            ^ hash[index % HYSTERIA2_SALAMANDER_HASH_LEN];
    }
    meta.len = payload_len;
    meta.stride = payload_len;
    true
}

fn salamander_hash(key: &[u8], salt: &[u8; HYSTERIA2_SALAMANDER_SALT_LEN]) -> [u8; 32] {
    let mut hasher =
        Blake2bVar::new(HYSTERIA2_SALAMANDER_HASH_LEN).expect("BLAKE2b-256 output length is valid");
    hasher.update(key);
    hasher.update(salt);
    let mut hash = [0_u8; HYSTERIA2_SALAMANDER_HASH_LEN];
    hasher
        .finalize_variable(&mut hash)
        .expect("BLAKE2b-256 output buffer is valid");
    hash
}

pub(crate) async fn resolve_proxy_udp_addr_candidates_async(
    proxy: &ResidentProxyPlan,
) -> Result<Vec<SocketAddr>, String> {
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    resolve_socket_addr_candidates(&target, RESIDENT_CONNECT_TIMEOUT, "resolve QUIC endpoint").await
}

pub(crate) async fn resolve_hysteria2_quic_remote_candidates_async(
    proxy: &ResidentProxyPlan,
    port_hop_ports: &[u16],
) -> Result<Vec<SocketAddr>, String> {
    let selected_port = if port_hop_ports.is_empty() {
        proxy.server_port
    } else {
        port_hop_ports[fastrand::usize(..port_hop_ports.len())]
    };
    let target = format!("{}:{selected_port}", proxy.server_host);
    resolve_socket_addr_candidates(
        &target,
        RESIDENT_CONNECT_TIMEOUT,
        "resolve Hysteria2 QUIC endpoint",
    )
    .await
}

pub(crate) async fn connect_quic_endpoint_candidates_async<F>(
    candidates: &[SocketAddr],
    server_name: &str,
    timeout: Duration,
    context: &str,
    mut endpoint_for_remote: F,
) -> Result<(SocketAddr, ObservedQuicEndpoint, quinn::Connection), String>
where
    F: FnMut(SocketAddr) -> Result<ObservedQuicEndpoint, String>,
{
    let (remote, (endpoint, connection)) =
        try_socket_addr_candidates(candidates, context, |remote| {
            let endpoint = endpoint_for_remote(remote);
            let server_name = server_name.to_owned();
            async move {
                let endpoint = endpoint?;
                let connecting = match endpoint.connect(remote, &server_name) {
                    Ok(connecting) => connecting,
                    Err(err) => {
                        endpoint.mark_failed();
                        endpoint.close(0_u32.into(), b"resolved candidate connect failed");
                        endpoint.wait_idle().await;
                        return Err(format!("start QUIC connect: {err}"));
                    }
                };
                match time::timeout(timeout, connecting).await {
                    Ok(Ok(connection)) => Ok((endpoint, connection)),
                    Ok(Err(err)) => {
                        endpoint.mark_failed();
                        endpoint.close(0_u32.into(), b"resolved candidate connect failed");
                        endpoint.wait_idle().await;
                        Err(format!("await QUIC connect: {err}"))
                    }
                    Err(_) => {
                        endpoint.mark_failed();
                        endpoint.close(0_u32.into(), b"resolved candidate connect timeout");
                        endpoint.wait_idle().await;
                        Err("QUIC connect timeout".to_owned())
                    }
                }
            }
        })
        .await?;
    Ok((remote, endpoint, connection))
}

pub(crate) fn set_socket_mark(fd: i32, mark: u32) -> std::io::Result<()> {
    let mark = mark as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_bind_addr_follows_remote_ip_family() {
        let v4_remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let v6_remote = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443);

        assert!(quic_bind_addr_for_remote(v4_remote).is_ipv4());
        assert!(quic_bind_addr_for_remote(v6_remote).is_ipv6());
    }

    #[test]
    fn hysteria2_salamander_packet_wrapper_roundtrips_payload() {
        let key = b"obfs-secret";
        let payload = b"fixture-quic-packet";
        let packet = salamander_obfuscate_packet(key, payload);
        assert_eq!(packet.len(), HYSTERIA2_SALAMANDER_SALT_LEN + payload.len());
        assert_ne!(&packet[HYSTERIA2_SALAMANDER_SALT_LEN..], payload);

        let mut storage = packet;
        let len = storage.len();
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [udp::RecvMeta {
            len,
            stride: len,
            ..Default::default()
        }];
        assert!(salamander_deobfuscate_received(
            key, &mut bufs, &mut meta, 1
        ));
        assert_eq!(meta[0].len, payload.len());
        assert_eq!(&bufs[0][..payload.len()], payload);
    }

    #[tokio::test]
    async fn salamander_endpoint_charge_uses_wrapped_receive_segment_count() {
        let generation = dae_runtime_control::OwnerGeneration::new(8_204);
        let context = QuicEndpointOpenContext::from_identity_parts(
            QuicEndpointProtocol::Hysteria2,
            QuicEndpointCallerClass::BackgroundHealth,
            generation,
            QuicEndpointIdentityRole::ProtocolCarrier,
            &[b"salamander-charge-test"],
        );
        let endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
            0,
            &ResidentHysteria2ObfsPlan::salamander("test-obfs-key".to_owned()),
            "127.0.0.1:443".parse().unwrap(),
            context,
        )
        .unwrap();
        endpoint.mark_ready();
        let snapshot = quic_endpoint_metrics_snapshot(generation.get());
        let charge = &snapshot["endpoints"][0]["chargedBytes"];
        assert_eq!(charge["receiveSegments"], 1);
        assert_eq!(
            charge["receiveSlab"],
            quinn::EndpointConfig::default()
                .get_max_udp_payload_size()
                .min(64 * 1024)
                * quinn::udp::BATCH_SIZE as u64
        );
        endpoint.close(0_u32.into(), b"salamander charge test complete");
        endpoint.wait_idle().await;
        drop(endpoint);
    }
}
