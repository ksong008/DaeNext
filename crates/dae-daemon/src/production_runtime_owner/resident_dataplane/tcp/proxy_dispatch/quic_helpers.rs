use super::*;

use crate::production_runtime_owner::resident_dataplane::{
    RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, authority_from_host_port,
    resolve_socket_addr_candidates, try_socket_addr_candidates,
};

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use dae_runtime_control::{AbsoluteDeadline, OwnerCancellationSignal};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

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
    deadline: AbsoluteDeadline,
    cancellation: &OwnerCancellationSignal,
) -> Result<ObservedQuicEndpoint, String> {
    open_marked_quic_endpoint_with_runtime(
        mark,
        quinn::default_runtime(),
        remote,
        quic_bind_addr_for_remote(remote),
        QuicEndpointUnderlay::Ordinary,
        context,
        QuicEndpointAdmissionContext::new(deadline, cancellation),
    )
}

pub(crate) fn open_marked_hysteria2_quic_endpoint_for_remote(
    mark: u32,
    obfs: &ResidentHysteria2ObfsPlan,
    port_hopping: Option<Hysteria2PortHoppingRuntimeConfig>,
    remote: SocketAddr,
    context: QuicEndpointOpenContext,
    deadline: AbsoluteDeadline,
    cancellation: &OwnerCancellationSignal,
) -> Result<ObservedQuicEndpoint, String> {
    let bind = quic_bind_addr_for_remote(remote);
    let transition_socket_limit = port_hopping
        .as_ref()
        .map(|config| config.transition_socket_limit);
    let runtime = quinn::default_runtime();
    let mut runtime = if obfs.is_salamander() {
        let runtime = runtime.ok_or_else(|| "no quinn runtime available".to_owned())?;
        Some(Arc::new(Hysteria2SalamanderRuntime {
            inner: runtime,
            key: Arc::new(obfs.password.clone().into_bytes()),
        }) as Arc<dyn quinn::Runtime>)
    } else {
        runtime
    };
    if let Some(config) = port_hopping {
        let inner = runtime.ok_or_else(|| "no quinn runtime available".to_owned())?;
        runtime = Some(Arc::new(Hysteria2PortHoppingRuntime::new(
            inner, config, remote,
        )));
    }
    let underlay = match (obfs.is_salamander(), transition_socket_limit) {
        (false, None) => QuicEndpointUnderlay::Ordinary,
        (true, None) => QuicEndpointUnderlay::Salamander,
        (false, Some(transition_socket_limit)) => QuicEndpointUnderlay::PortHopping {
            transition_socket_limit,
        },
        (true, Some(transition_socket_limit)) => QuicEndpointUnderlay::SalamanderPortHopping {
            transition_socket_limit,
        },
    };
    open_marked_quic_endpoint_with_runtime(
        mark,
        runtime,
        remote,
        bind,
        underlay,
        context,
        QuicEndpointAdmissionContext::new(deadline, cancellation),
    )
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
    admission_context: QuicEndpointAdmissionContext<'_>,
) -> Result<ObservedQuicEndpoint, String> {
    open_observed_quic_endpoint(
        mark,
        runtime,
        remote,
        bind,
        underlay,
        context,
        admission_context,
    )
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
    let mut out = Vec::with_capacity(HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD + payload.len());
    let mut salt = [0_u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD];
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
    if meta.len <= HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD || meta.len > buf.len() {
        return false;
    }
    let raw = &mut buf[..meta.len];
    let mut salt = [0_u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD];
    salt.copy_from_slice(&raw[..HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD]);
    let hash = salamander_hash(key, &salt);
    let payload_len = raw.len() - HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD;
    for index in 0..payload_len {
        raw[index] = raw[index + HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD]
            ^ hash[index % HYSTERIA2_SALAMANDER_HASH_LEN];
    }
    meta.len = payload_len;
    meta.stride = payload_len;
    true
}

fn salamander_hash(key: &[u8], salt: &[u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD]) -> [u8; 32] {
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
    deadline: AbsoluteDeadline,
) -> Result<Vec<SocketAddr>, String> {
    let target = format!("{}:{}", proxy.server_host, proxy.server_port);
    let timeout = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "resolve QUIC endpoint: connect deadline elapsed".to_owned())?;
    resolve_socket_addr_candidates(&target, timeout, "resolve QUIC endpoint").await
}

pub(crate) async fn resolve_hysteria2_quic_remote_candidates_async(
    proxy: &ResidentProxyPlan,
    port_hop_ports: &[u16],
    resolved_candidate_limit: usize,
    deadline: AbsoluteDeadline,
) -> Result<Vec<SocketAddr>, String> {
    let target = authority_from_host_port(&proxy.server_host, proxy.server_port);
    let timeout = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "resolve Hysteria2 QUIC endpoint: connect deadline elapsed".to_owned())?;
    let resolved =
        resolve_socket_addr_candidates(&target, timeout, "resolve Hysteria2 QUIC endpoint").await?;
    if port_hop_ports.is_empty() {
        return Ok(resolved);
    }
    expand_hysteria2_port_hop_candidates(&resolved, port_hop_ports, resolved_candidate_limit)
}

fn expand_hysteria2_port_hop_candidates(
    resolved: &[SocketAddr],
    port_hop_ports: &[u16],
    resolved_candidate_limit: usize,
) -> Result<Vec<SocketAddr>, String> {
    let candidate_count = resolved
        .len()
        .checked_mul(port_hop_ports.len())
        .ok_or_else(|| "Hysteria2 resolved port-hopping candidate count overflow".to_owned())?;
    if candidate_count > resolved_candidate_limit {
        return Err(format!(
            "Hysteria2 resolved port-hopping candidate count {candidate_count} exceeds budget {resolved_candidate_limit}"
        ));
    }
    let mut candidates = Vec::with_capacity(candidate_count);
    for resolved_addr in resolved {
        for &port in port_hop_ports {
            candidates.push(SocketAddr::new(resolved_addr.ip(), port));
        }
    }
    fastrand::shuffle(&mut candidates);
    Ok(candidates)
}

pub(crate) async fn connect_quic_endpoint_candidates_async<F>(
    candidates: &[SocketAddr],
    server_name: &str,
    deadline: AbsoluteDeadline,
    context: &str,
    mut endpoint_for_remote: F,
) -> Result<(SocketAddr, ObservedQuicEndpoint, quinn::Connection), String>
where
    F: FnMut(
        SocketAddr,
        AbsoluteDeadline,
        &OwnerCancellationSignal,
    ) -> Result<ObservedQuicEndpoint, String>,
{
    let cancellation = OwnerCancellationSignal::new();
    let (remote, (endpoint, connection)) =
        try_socket_addr_candidates(candidates, context, |remote| {
            let endpoint = endpoint_for_remote(remote, deadline, &cancellation);
            let server_name = server_name.to_owned();
            async move {
                let endpoint = endpoint?;
                let connecting = match endpoint.connect(remote, &server_name) {
                    Ok(connecting) => connecting,
                    Err(err) => {
                        endpoint.mark_failed();
                        endpoint.close(0_u32.into(), b"resolved candidate connect failed");
                        wait_quic_endpoint_idle_after_close(&endpoint).await;
                        return Err(format!("start QUIC connect: {err}"));
                    }
                };
                let remaining = deadline.remaining_at(Instant::now()).ok_or_else(|| {
                    endpoint.mark_failed();
                    "QUIC connect deadline elapsed".to_owned()
                })?;
                match time::timeout(remaining, connecting).await {
                    Ok(Ok(connection)) => Ok((endpoint, connection)),
                    Ok(Err(err)) => {
                        endpoint.mark_failed();
                        endpoint.close(0_u32.into(), b"resolved candidate connect failed");
                        wait_quic_endpoint_idle_after_close(&endpoint).await;
                        Err(format!("await QUIC connect: {err}"))
                    }
                    Err(_) => {
                        endpoint.mark_failed();
                        endpoint.close(0_u32.into(), b"resolved candidate connect timeout");
                        wait_quic_endpoint_idle_after_close(&endpoint).await;
                        Err("QUIC connect timeout".to_owned())
                    }
                }
            }
        })
        .await?;
    Ok((remote, endpoint, connection))
}

pub(crate) async fn connect_hysteria2_quic_endpoint_candidates_async<F>(
    candidates: &[SocketAddr],
    server_name: &str,
    has_certificate_pin: bool,
    requires_webpki: bool,
    deadline: AbsoluteDeadline,
    mut endpoint_for_remote: F,
) -> Result<(SocketAddr, ObservedQuicEndpoint, quinn::Connection), Hysteria2Failure>
where
    F: FnMut(
        SocketAddr,
        AbsoluteDeadline,
        &OwnerCancellationSignal,
    ) -> Result<ObservedQuicEndpoint, Hysteria2Failure>,
{
    if candidates.is_empty() {
        return Err(Hysteria2Failure::new(
            Hysteria2FailureClass::NetworkAddress,
            "hysteria2-resolve",
            "Hysteria2 server resolved to no usable address",
        ));
    }

    let cancellation = OwnerCancellationSignal::new();
    let mut first_retryable_failure = None;
    for &remote in candidates {
        let endpoint = match endpoint_for_remote(remote, deadline, &cancellation) {
            Ok(endpoint) => endpoint,
            Err(failure) => {
                if failure.allows_candidate_retry() {
                    first_retryable_failure.get_or_insert(failure);
                    continue;
                }
                return Err(failure);
            }
        };
        let connecting = match endpoint.connect(remote, server_name) {
            Ok(connecting) => connecting,
            Err(error) => {
                let failure = classify_hysteria2_connect_start_error(&error);
                endpoint.mark_failed();
                endpoint.close(0_u32.into(), b"Hysteria2 candidate connect failed");
                wait_quic_endpoint_idle_after_close(&endpoint).await;
                if failure.allows_candidate_retry() {
                    first_retryable_failure.get_or_insert(failure);
                    continue;
                }
                return Err(failure);
            }
        };
        let Some(remaining) = deadline.remaining_at(Instant::now()) else {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), b"Hysteria2 connect deadline elapsed");
            wait_quic_endpoint_idle_after_close(&endpoint).await;
            return Err(Hysteria2Failure::new(
                Hysteria2FailureClass::Deadline,
                "hysteria2-connect-deadline",
                "Hysteria2 QUIC connect deadline elapsed",
            ));
        };
        match time::timeout(remaining, connecting).await {
            Ok(Ok(connection)) => return Ok((remote, endpoint, connection)),
            Ok(Err(error)) => {
                let failure = classify_hysteria2_connection_error(
                    &error,
                    has_certificate_pin,
                    requires_webpki,
                );
                endpoint.mark_failed();
                endpoint.close(0_u32.into(), b"Hysteria2 candidate handshake failed");
                wait_quic_endpoint_idle_after_close(&endpoint).await;
                if failure.allows_candidate_retry() {
                    first_retryable_failure.get_or_insert(failure);
                    continue;
                }
                return Err(failure);
            }
            Err(_) => {
                endpoint.mark_failed();
                endpoint.close(0_u32.into(), b"Hysteria2 connect deadline elapsed");
                wait_quic_endpoint_idle_after_close(&endpoint).await;
                return Err(Hysteria2Failure::new(
                    Hysteria2FailureClass::Deadline,
                    "hysteria2-connect-deadline",
                    "Hysteria2 QUIC connect deadline elapsed",
                ));
            }
        }
    }

    Err(first_retryable_failure.unwrap_or_else(|| {
        Hysteria2Failure::new(
            Hysteria2FailureClass::NetworkAddress,
            "hysteria2-connect-candidates",
            "Hysteria2 has no usable network address candidate",
        )
    }))
}

fn classify_hysteria2_connect_start_error(error: &quinn::ConnectError) -> Hysteria2Failure {
    let (class, operation, detail) = match error {
        quinn::ConnectError::InvalidRemoteAddress(_) => (
            Hysteria2FailureClass::NetworkAddress,
            "hysteria2-connect-address",
            "Hysteria2 QUIC remote address is unusable",
        ),
        quinn::ConnectError::EndpointStopping => (
            Hysteria2FailureClass::Draining,
            "hysteria2-endpoint-draining",
            "Hysteria2 QUIC Endpoint is draining",
        ),
        quinn::ConnectError::CidsExhausted => (
            Hysteria2FailureClass::Resource,
            "hysteria2-connection-id-capacity",
            "Hysteria2 QUIC connection-ID capacity is exhausted",
        ),
        quinn::ConnectError::InvalidServerName(_)
        | quinn::ConnectError::NoDefaultClientConfig
        | quinn::ConnectError::UnsupportedVersion => (
            Hysteria2FailureClass::Configuration,
            "hysteria2-connect-configuration",
            "Hysteria2 QUIC client configuration is invalid",
        ),
    };
    Hysteria2Failure::new(class, operation, detail)
}

fn classify_hysteria2_connection_error(
    error: &quinn::ConnectionError,
    has_certificate_pin: bool,
    requires_webpki: bool,
) -> Hysteria2Failure {
    if let Some(code) = hysteria2_crypto_error_code(error) {
        let pin_alert =
            quinn::TransportErrorCode::crypto(u8::from(rustls::AlertDescription::AccessDenied));
        if has_certificate_pin && (!requires_webpki || code == pin_alert) {
            return Hysteria2Failure::new(
                Hysteria2FailureClass::TlsPin,
                "hysteria2-tls-pin",
                "Hysteria2 certificate pin verification failed",
            );
        }
        return Hysteria2Failure::new(
            Hysteria2FailureClass::TlsCertificate,
            "hysteria2-tls-certificate",
            "Hysteria2 TLS certificate verification failed",
        );
    }

    let (class, operation, detail) = match error {
        quinn::ConnectionError::LocallyClosed => (
            Hysteria2FailureClass::Cancelled,
            "hysteria2-connect-cancelled",
            "Hysteria2 QUIC connect was cancelled locally",
        ),
        quinn::ConnectionError::CidsExhausted => (
            Hysteria2FailureClass::Resource,
            "hysteria2-connection-id-capacity",
            "Hysteria2 QUIC connection-ID capacity is exhausted",
        ),
        quinn::ConnectionError::VersionMismatch
        | quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::TimedOut => (
            Hysteria2FailureClass::NetworkPort,
            "hysteria2-connect-port",
            "Hysteria2 QUIC handshake did not reach a usable server port",
        ),
    };
    Hysteria2Failure::new(class, operation, detail)
}

fn hysteria2_crypto_error_code(
    error: &quinn::ConnectionError,
) -> Option<quinn::TransportErrorCode> {
    let code = match error {
        quinn::ConnectionError::TransportError(error) => error.code,
        quinn::ConnectionError::ConnectionClosed(error) => error.error_code,
        _ => return None,
    };
    let raw = u64::from(code);
    (0x100..0x200).contains(&raw).then_some(code)
}

pub(crate) async fn wait_quic_endpoint_idle_after_close(endpoint: &ObservedQuicEndpoint) -> bool {
    time::timeout(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE, endpoint.wait_idle())
        .await
        .is_ok()
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
    use crate::production_runtime_owner::resident_dataplane::ResidentRuntimeProfile;

    #[test]
    fn quic_bind_addr_follows_remote_ip_family() {
        let v4_remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let v6_remote = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443);

        assert!(quic_bind_addr_for_remote(v4_remote).is_ipv4());
        assert!(quic_bind_addr_for_remote(v6_remote).is_ipv6());
    }

    #[test]
    fn hysteria2_port_hop_candidates_expand_both_address_families_with_a_hard_budget() {
        let resolved = [
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];
        let mut candidates =
            expand_hysteria2_port_hop_candidates(&resolved, &[443, 8443], 4).unwrap();
        candidates.sort_unstable();
        let mut expected = vec![
            "192.0.2.1:443".parse().unwrap(),
            "192.0.2.1:8443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "[2001:db8::1]:8443".parse().unwrap(),
        ];
        expected.sort_unstable();
        assert_eq!(candidates, expected);

        let error = expand_hysteria2_port_hop_candidates(&resolved, &[443, 8443], 3).unwrap_err();
        assert!(error.contains("candidate count 4 exceeds budget 3"));
    }

    #[test]
    fn hysteria2_tls_failures_are_terminal_and_redacted() {
        let certificate = quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
            error_code: quinn::TransportErrorCode::crypto(u8::from(
                rustls::AlertDescription::UnknownCA,
            )),
            frame_type: None,
            reason: Bytes::from_static(b"private.example certificate canary"),
        });
        let certificate = classify_hysteria2_connection_error(&certificate, true, true);
        assert_eq!(certificate.class(), Hysteria2FailureClass::TlsCertificate);
        assert_eq!(
            certificate.retry_disposition(),
            Hysteria2RetryDisposition::Terminal
        );
        assert!(!certificate.to_string().contains("private.example"));

        let pin = quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
            error_code: quinn::TransportErrorCode::crypto(u8::from(
                rustls::AlertDescription::AccessDenied,
            )),
            frame_type: None,
            reason: Bytes::from_static(b"0123456789abcdef pin canary"),
        });
        let pin = classify_hysteria2_connection_error(&pin, true, true);
        assert_eq!(pin.class(), Hysteria2FailureClass::TlsPin);
        assert_eq!(pin.retry_disposition(), Hysteria2RetryDisposition::Terminal);
        assert!(!pin.to_string().contains("0123456789abcdef"));
    }

    #[test]
    fn hysteria2_network_port_failure_is_the_only_handshake_retry_class() {
        let failure =
            classify_hysteria2_connection_error(&quinn::ConnectionError::TimedOut, false, true);
        assert_eq!(failure.class(), Hysteria2FailureClass::NetworkPort);
        assert_eq!(failure.retry_disposition(), Hysteria2RetryDisposition::Port);
        assert!(failure.allows_candidate_retry());

        let cancelled = classify_hysteria2_connection_error(
            &quinn::ConnectionError::LocallyClosed,
            false,
            true,
        );
        assert_eq!(cancelled.class(), Hysteria2FailureClass::Cancelled);
        assert!(!cancelled.allows_candidate_retry());
    }

    #[test]
    fn hysteria2_salamander_packet_wrapper_roundtrips_payload() {
        let key = b"obfs-secret";
        let payload = b"fixture-quic-packet";
        assert_eq!(ResidentHysteria2ObfsPlan::none().udp_packet_overhead(), 0);
        assert_eq!(
            ResidentHysteria2ObfsPlan::salamander("fixture-key".to_owned()).udp_packet_overhead(),
            HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD
        );
        let packet = salamander_obfuscate_packet(key, payload);
        assert_eq!(
            packet.len(),
            HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD + payload.len()
        );
        assert_ne!(&packet[HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD..], payload);

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
        let cancellation = OwnerCancellationSignal::new();
        let endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
            0,
            &ResidentHysteria2ObfsPlan::salamander("test-obfs-key".to_owned()),
            None,
            "127.0.0.1:443".parse().unwrap(),
            context,
            AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(1)),
            &cancellation,
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

    #[tokio::test]
    async fn salamander_port_hopping_charges_three_udp_sockets_but_one_quic_owner() {
        let generation = dae_runtime_control::OwnerGeneration::new(8_205);
        let context = QuicEndpointOpenContext::from_identity_parts(
            QuicEndpointProtocol::Hysteria2,
            QuicEndpointCallerClass::BackgroundHealth,
            generation,
            QuicEndpointIdentityRole::ProtocolCarrier,
            &[b"salamander-port-hopping-charge-test"],
        );
        let cancellation = OwnerCancellationSignal::new();
        let metrics = Arc::new(Hysteria2PortHoppingMetrics::default());
        let resources =
            Hysteria2OwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
        let port_hopping = Hysteria2PortHoppingRuntimeConfig::new(
            vec![
                "127.0.0.1:443".parse().unwrap(),
                "127.0.0.1:8443".parse().unwrap(),
            ],
            Duration::from_secs(30),
            0,
            resources.port_hop_transition_socket_limit(),
            Arc::clone(&metrics),
        )
        .unwrap();
        let endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
            0,
            &ResidentHysteria2ObfsPlan::salamander("test-obfs-key".to_owned()),
            Some(port_hopping),
            "127.0.0.1:443".parse().unwrap(),
            context,
            AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(1)),
            &cancellation,
        )
        .unwrap();
        endpoint.mark_ready();
        let snapshot = quic_endpoint_metrics_snapshot(generation.get());
        assert_eq!(snapshot["liveStates"]["total"], 1);
        assert_eq!(
            snapshot["endpoints"][0]["underlay"],
            "salamander-port-hopping"
        );
        let charge = &snapshot["endpoints"][0]["chargedBytes"];
        assert_eq!(charge["receiveSegments"], 1);
        assert_eq!(charge["udpSocketCount"], 3);
        assert_eq!(metrics.snapshot()["activeSockets"], 1);

        endpoint.close(0_u32.into(), b"port hopping charge test complete");
        endpoint.wait_idle().await;
        drop(endpoint);
        tokio::task::yield_now().await;
        assert_eq!(metrics.snapshot()["activeSockets"], 0);
    }
}

#[cfg(test)]
#[path = "quic_helpers_port_hopping_tests.rs"]
mod port_hopping_live_tests;
