use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
#[cfg(test)]
use bytes::Bytes;
use dae_outbound_quic::hysteria2::HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD;
#[cfg(test)]
use dae_outbound_quic::hysteria2::build_hysteria2_runtime_client_config_with_udp_overhead;
#[cfg(test)]
use dae_resident_core::{Hysteria2OwnerResourceProfile, ResidentRuntimeProfile};
use dae_resident_core::{QuicCandidateRaceResourceProfile, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE};
use dae_resident_model::{ResidentHysteria2ObfsPlan, ResidentProxyPlan};
use dae_runtime_control::{AbsoluteDeadline, OwnerCancellationSignal};
use quinn::udp;
use tokio::time;

#[cfg(test)]
use crate::hysteria2_failure::Hysteria2RetryDisposition;
use crate::hysteria2_failure::{Hysteria2Failure, Hysteria2FailureClass};
#[cfg(test)]
use crate::hysteria2_port_hopping::Hysteria2PortHoppingMetrics;
use crate::hysteria2_port_hopping::{
    Hysteria2PortHoppingRuntime, Hysteria2PortHoppingRuntimeConfig,
};
use crate::quic_candidate_race::{
    QuicCandidateAttemptFailure, QuicCandidateRaceFailure, race_quic_candidates,
};
use crate::{
    ObservedQuicEndpoint, QuicEndpointAdmissionContext, QuicEndpointOpenContext,
    QuicEndpointOpenError, QuicEndpointUnderlay, authority_from_host_port,
    open_observed_quic_endpoint_waiting, resolve_socket_addr_candidates,
    wait_quic_endpoint_idle_after_close_for,
};
#[cfg(test)]
use crate::{
    QuicEndpointCallerClass, QuicEndpointIdentityRole, QuicEndpointProtocol,
    quic_endpoint_metrics_snapshot,
};

async fn wait_quic_endpoint_idle_after_close(endpoint: &ObservedQuicEndpoint) -> bool {
    wait_quic_endpoint_idle_after_close_for(endpoint, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE).await
}

const HYSTERIA2_SALAMANDER_HASH_LEN: usize = 32;
const HYSTERIA2_SALAMANDER_SALT_BATCH: usize = 64;
pub(crate) async fn open_marked_hysteria2_quic_endpoint_for_remote(
    mark: u32,
    obfs: &ResidentHysteria2ObfsPlan,
    port_hopping: Option<Hysteria2PortHoppingRuntimeConfig>,
    remote: SocketAddr,
    context: QuicEndpointOpenContext,
    deadline: AbsoluteDeadline,
    cancellation: &OwnerCancellationSignal,
) -> Result<ObservedQuicEndpoint, QuicEndpointOpenError> {
    let bind = quic_bind_addr_for_remote(remote);
    let transition_socket_limit = port_hopping
        .as_ref()
        .map(|config| config.transition_socket_limit);
    // Install below port hopping so every replacement socket has the same cap.
    let runtime = quinn::default_runtime().map(crate::quic_endpoint::tiered_runtime);
    let mut runtime = if obfs.is_salamander() {
        let runtime = runtime.ok_or(QuicEndpointOpenError::Construction)?;
        Some(Arc::new(Hysteria2SalamanderRuntime {
            inner: runtime,
            key: Arc::new(obfs.password.clone().into_bytes()),
        }) as Arc<dyn quinn::Runtime>)
    } else {
        runtime
    };
    if let Some(config) = port_hopping {
        let inner = runtime.ok_or(QuicEndpointOpenError::Construction)?;
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
    open_observed_quic_endpoint_waiting(
        mark,
        runtime,
        remote,
        bind,
        underlay,
        context,
        QuicEndpointAdmissionContext::new(deadline, cancellation),
    )
    .await
}

fn quic_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
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
        // Quinn enables GRO while wrapping. Disable it afterwards because this
        // adapter decodes one salt per datagram and advertises one segment.
        #[cfg(target_os = "linux")]
        let socket = t.try_clone()?;
        let inner = self.inner.wrap_udp_socket(t)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let disabled: libc::c_int = 0;
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    (&disabled as *const libc::c_int).cast(),
                    std::mem::size_of_val(&disabled) as libc::socklen_t,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ENOPROTOOPT) {
                    return Err(error);
                }
            }
        }
        Ok(Arc::new(Hysteria2SalamanderUdpSocket {
            inner,
            key: Arc::clone(&self.key),
            send_state: Mutex::new(SalamanderSendState::new()),
        }))
    }

    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }
}

struct Hysteria2SalamanderUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    key: Arc<Vec<u8>>,
    send_state: Mutex<SalamanderSendState>,
}

struct SalamanderSendState {
    packet: Vec<u8>,
    salts: dae_resident_core::WireRandomPool<
        { HYSTERIA2_SALAMANDER_SALT_BATCH * HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD },
    >,
}

impl SalamanderSendState {
    fn new() -> Self {
        Self {
            packet: Vec::new(),
            salts: dae_resident_core::WireRandomPool::default(),
        }
    }

    fn take_salt(&mut self) -> io::Result<[u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD]> {
        let mut salt = [0_u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD];
        self.salts.fill(&mut salt)?;
        Ok(salt)
    }
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty Salamander segment",
            ));
        }
        let mut send_state = self
            .send_state
            .lock()
            .map_err(|_| io::Error::other("Hysteria2 Salamander send state lock is poisoned"))?;
        // One atomic GSO submission avoids duplicating accepted prefixes on a
        // WouldBlock retry. Each wire datagram still has an independent salt.
        send_state.packet.clear();
        for chunk in transmit.contents.chunks(segment_size) {
            let salt = send_state.take_salt()?;
            let start = send_state.packet.len();
            send_state.packet.extend_from_slice(&salt);
            send_state.packet.extend_from_slice(chunk);
            let hash = salamander_hash(&self.key, &salt);
            salamander_xor_in_place(
                &mut send_state.packet[start + HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD..],
                &hash,
            );
        }
        let wire_segment = segment_size
            .checked_add(HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Salamander segment size overflow",
                )
            })?;
        self.inner.try_send(&udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &send_state.packet,
            segment_size: transmit.segment_size.map(|_| wire_segment),
            src_ip: transmit.src_ip,
        })
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
        self.inner.max_transmit_segments().min(32)
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
fn salamander_obfuscate_packet_into(
    key: &[u8],
    payload: &[u8],
    salt: &[u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD],
    out: &mut Vec<u8>,
) {
    out.clear();
    out.extend_from_slice(salt);
    out.extend_from_slice(payload);
    let hash = salamander_hash(key, salt);
    salamander_xor_in_place(&mut out[HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD..], &hash);
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
    raw.copy_within(HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD.., 0);
    salamander_xor_in_place(&mut raw[..payload_len], &hash);
    meta.len = payload_len;
    meta.stride = payload_len;
    true
}

fn salamander_xor_in_place(payload: &mut [u8], hash: &[u8; HYSTERIA2_SALAMANDER_HASH_LEN]) {
    let mut chunks = payload.chunks_exact_mut(HYSTERIA2_SALAMANDER_HASH_LEN);
    for chunk in &mut chunks {
        for (byte, hash_byte) in chunk.iter_mut().zip(hash) {
            *byte ^= *hash_byte;
        }
    }
    for (index, byte) in chunks.into_remainder().iter_mut().enumerate() {
        *byte ^= hash[index];
    }
}

#[cfg(test)]
fn salamander_obfuscate_packet(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut salt = [0_u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD];
    dae_resident_core::fill_wire_random(&mut salt).expect("test salt entropy");
    let mut out = Vec::with_capacity(HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD + payload.len());
    salamander_obfuscate_packet_into(key, payload, &salt, &mut out);
    out
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
    resolve_socket_addr_candidates(&target, timeout, "resolve QUIC endpoint")
        .await
        .map_err(|err| err.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Hysteria2ResolvedRemotePlan {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) ports: Arc<Vec<u16>>,
    pub(crate) port_hopping: bool,
}

pub(crate) async fn resolve_hysteria2_quic_remote_plan_async(
    proxy: &ResidentProxyPlan,
    port_hop_ports: &[u16],
    deadline: AbsoluteDeadline,
) -> Result<Hysteria2ResolvedRemotePlan, String> {
    let target = authority_from_host_port(&proxy.server_host, proxy.server_port);
    let timeout = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "resolve Hysteria2 QUIC endpoint: connect deadline elapsed".to_owned())?;
    let resolved =
        resolve_socket_addr_candidates(&target, timeout, "resolve Hysteria2 QUIC endpoint")
            .await
            .map_err(|err| err.to_string())?;
    let mut addresses = Vec::with_capacity(resolved.len());
    for candidate in resolved {
        if !addresses.contains(&candidate.ip()) {
            addresses.push(candidate.ip());
        }
    }
    if addresses.is_empty() {
        return Err("resolve Hysteria2 QUIC endpoint: no usable IP address".to_owned());
    }
    let port_hopping = !port_hop_ports.is_empty();
    let ports = if port_hopping {
        Arc::new(port_hop_ports.to_vec())
    } else {
        Arc::new(vec![proxy.server_port])
    };
    Ok(Hysteria2ResolvedRemotePlan {
        addresses,
        ports,
        port_hopping,
    })
}

pub(crate) fn hysteria2_initial_remote_candidates(
    plan: &Hysteria2ResolvedRemotePlan,
    attempt_limit: usize,
) -> Result<Vec<SocketAddr>, String> {
    hysteria2_initial_remote_candidates_with(plan, attempt_limit, fastrand::usize)
}

fn hysteria2_initial_remote_candidates_with<F>(
    plan: &Hysteria2ResolvedRemotePlan,
    attempt_limit: usize,
    mut random_index: F,
) -> Result<Vec<SocketAddr>, String>
where
    F: FnMut(std::ops::Range<usize>) -> usize,
{
    if plan.addresses.is_empty() {
        return Err("Hysteria2 initial remote plan has no address".to_owned());
    }
    if plan.ports.is_empty() {
        return Err("Hysteria2 initial remote plan has no port".to_owned());
    }
    if !plan.port_hopping {
        return Ok(plan
            .addresses
            .iter()
            .map(|address| SocketAddr::new(*address, plan.ports[0]))
            .collect());
    }
    if attempt_limit == 0 {
        return Err("Hysteria2 initial connect attempt limit must be nonzero".to_owned());
    }

    let unique_candidate_count = plan.addresses.len().saturating_mul(plan.ports.len());
    let candidate_count = attempt_limit.min(unique_candidate_count);
    let port_starts = plan
        .addresses
        .iter()
        .map(|_| random_index(0..plan.ports.len()))
        .collect::<Vec<_>>();
    let mut address_visits = vec![0_usize; plan.addresses.len()];
    let mut candidates = Vec::with_capacity(candidate_count);
    for attempt in 0..candidate_count {
        let address_index = attempt % plan.addresses.len();
        let port_index = port_starts[address_index].wrapping_add(address_visits[address_index])
            % plan.ports.len();
        address_visits[address_index] += 1;
        candidates.push(SocketAddr::new(
            plan.addresses[address_index],
            plan.ports[port_index],
        ));
    }
    Ok(candidates)
}

pub async fn connect_quic_endpoint_candidates_async<F>(
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
    race_quic_candidates(
        candidates,
        deadline,
        &cancellation,
        QuicCandidateRaceResourceProfile::selected(),
        |remote, attempt_deadline, attempt_cancellation| {
            let endpoint = endpoint_for_remote(remote, attempt_deadline, &attempt_cancellation);
            let server_name = server_name.to_owned();
            async move {
                let endpoint = endpoint.map_err(QuicCandidateAttemptFailure::Retryable)?;
                connect_quic_candidate_async(
                    remote,
                    endpoint,
                    &server_name,
                    attempt_deadline,
                    attempt_cancellation,
                )
                .await
            }
        },
    )
    .await
    .map_err(|failure| format_quic_candidate_race_failure(context, failure))
}

struct QuicCandidateEndpointGuard {
    endpoint: Option<ObservedQuicEndpoint>,
}

impl QuicCandidateEndpointGuard {
    fn new(endpoint: ObservedQuicEndpoint) -> Self {
        Self {
            endpoint: Some(endpoint),
        }
    }

    fn endpoint(&self) -> &ObservedQuicEndpoint {
        self.endpoint
            .as_ref()
            .expect("QUIC candidate guard owns its endpoint")
    }

    fn into_endpoint(mut self) -> ObservedQuicEndpoint {
        self.endpoint
            .take()
            .expect("QUIC candidate guard owns its endpoint")
    }

    async fn close(mut self, reason: &'static [u8]) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), reason);
            wait_quic_endpoint_idle_after_close(&endpoint).await;
        }
    }
}

impl Drop for QuicCandidateEndpointGuard {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.mark_failed();
            endpoint.close(0_u32.into(), b"QUIC candidate attempt dropped");
            drop(endpoint.cancellation_guard());
        }
    }
}

async fn connect_quic_candidate_async(
    remote: SocketAddr,
    endpoint: ObservedQuicEndpoint,
    server_name: &str,
    deadline: AbsoluteDeadline,
    cancellation: OwnerCancellationSignal,
) -> Result<
    (SocketAddr, ObservedQuicEndpoint, quinn::Connection),
    QuicCandidateAttemptFailure<String>,
> {
    let guard = QuicCandidateEndpointGuard::new(endpoint);
    let connecting = match guard.endpoint().connect(remote, server_name) {
        Ok(connecting) => connecting,
        Err(err) => {
            guard.close(b"resolved candidate connect failed").await;
            return Err(QuicCandidateAttemptFailure::Retryable(format!(
                "start QUIC connect: {err}"
            )));
        }
    };
    let Some(remaining) = deadline.remaining_at(Instant::now()) else {
        guard.close(b"resolved candidate connect deadline").await;
        return Err(QuicCandidateAttemptFailure::Retryable(
            "QUIC connect deadline elapsed".to_owned(),
        ));
    };
    tokio::select! {
        result = time::timeout(remaining, connecting) => {
            match result {
                Ok(Ok(connection)) => Ok((remote, guard.into_endpoint(), connection)),
                Ok(Err(err)) => {
                    guard.close(b"resolved candidate connect failed").await;
                    Err(QuicCandidateAttemptFailure::Retryable(format!("await QUIC connect: {err}")))
                }
                Err(_) => {
                    guard.close(b"resolved candidate connect timeout").await;
                    Err(QuicCandidateAttemptFailure::Retryable("QUIC connect timeout".to_owned()))
                }
            }
        }
        _ = cancellation.cancelled() => {
            guard.close(b"resolved candidate connect cancelled").await;
            Err(QuicCandidateAttemptFailure::Retryable("QUIC candidate connect cancelled".to_owned()))
        }
    }
}

fn format_quic_candidate_race_failure(
    context: &str,
    failure: QuicCandidateRaceFailure<String>,
) -> String {
    match failure {
        QuicCandidateRaceFailure::Empty => {
            format!("{context}: no resolved address candidates")
        }
        QuicCandidateRaceFailure::Exhausted {
            candidate_count,
            failures,
        } => format_quic_candidate_failures(
            context,
            "failed",
            candidate_count,
            candidate_count,
            failures,
        ),
        QuicCandidateRaceFailure::Deadline {
            candidate_count,
            started_count,
            failures,
        } => format_quic_candidate_failures(
            context,
            "deadline elapsed",
            candidate_count,
            started_count,
            failures,
        ),
        QuicCandidateRaceFailure::Cancelled(reason) => {
            format!("{context}: resolved address candidate race was cancelled: {reason:?}")
        }
        QuicCandidateRaceFailure::Terminal { candidate, error } => {
            format!("{context}: terminal candidate {candidate} failure: {error}")
        }
    }
}

fn format_quic_candidate_failures(
    context: &str,
    outcome: &str,
    candidate_count: usize,
    started_count: usize,
    failures: Vec<(SocketAddr, String)>,
) -> String {
    let mut message = format!(
        "{context}: resolved address candidate race {outcome} after starting {started_count} of {candidate_count} candidates"
    );
    for (candidate, detail) in &failures {
        message.push_str(&format!("; {candidate}: {detail}"));
    }
    let omitted = candidate_count.saturating_sub(failures.len());
    if omitted > 0 {
        message.push_str(&format!("; {omitted} candidate details omitted"));
    }
    message
}

pub(crate) struct Hysteria2ConnectionFailure {
    failure: Hysteria2Failure,
    endpoint: Option<ObservedQuicEndpoint>,
}

impl Hysteria2ConnectionFailure {
    pub(crate) fn without_endpoint(failure: Hysteria2Failure) -> Self {
        Self {
            failure,
            endpoint: None,
        }
    }

    pub(crate) fn into_parts(self) -> (Hysteria2Failure, Option<ObservedQuicEndpoint>) {
        (self.failure, self.endpoint)
    }
}

pub(crate) async fn connect_hysteria2_quic_endpoint_candidates_async<F, Fut>(
    candidates: &[SocketAddr],
    server_name: &str,
    has_certificate_pin: bool,
    requires_webpki: bool,
    deadline: AbsoluteDeadline,
    cancellation: &OwnerCancellationSignal,
    mut endpoint_for_remote: F,
) -> Result<(SocketAddr, ObservedQuicEndpoint, quinn::Connection), Hysteria2ConnectionFailure>
where
    F: FnMut(SocketAddr, AbsoluteDeadline, OwnerCancellationSignal) -> Fut,
    Fut: Future<Output = Result<ObservedQuicEndpoint, Hysteria2Failure>> + Send,
{
    if let Err(reason) = cancellation.check() {
        return Err(Hysteria2ConnectionFailure::without_endpoint(
            hysteria2_cancellation_failure(reason),
        ));
    }
    race_quic_candidates(
        candidates,
        deadline,
        cancellation,
        QuicCandidateRaceResourceProfile::selected(),
        |remote, attempt_deadline, attempt_cancellation| {
            let endpoint =
                endpoint_for_remote(remote, attempt_deadline, attempt_cancellation.clone());
            let server_name = server_name.to_owned();
            async move {
                let endpoint = endpoint.await.map_err(|failure| {
                    if failure.allows_candidate_retry() {
                        QuicCandidateAttemptFailure::Retryable(failure)
                    } else {
                        QuicCandidateAttemptFailure::Terminal(failure)
                    }
                })?;
                connect_hysteria2_quic_candidate_async(
                    remote,
                    endpoint,
                    &server_name,
                    has_certificate_pin,
                    requires_webpki,
                    attempt_deadline,
                    attempt_cancellation,
                )
                .await
            }
        },
    )
    .await
    .map_err(hysteria2_candidate_race_failure)
}

async fn connect_hysteria2_quic_candidate_async(
    remote: SocketAddr,
    endpoint: ObservedQuicEndpoint,
    server_name: &str,
    has_certificate_pin: bool,
    requires_webpki: bool,
    deadline: AbsoluteDeadline,
    cancellation: OwnerCancellationSignal,
) -> Result<
    (SocketAddr, ObservedQuicEndpoint, quinn::Connection),
    QuicCandidateAttemptFailure<Hysteria2Failure>,
> {
    let guard = QuicCandidateEndpointGuard::new(endpoint);
    let connecting = match guard.endpoint().connect(remote, server_name) {
        Ok(connecting) => connecting,
        Err(error) => {
            let failure = classify_hysteria2_connect_start_error(&error);
            guard.close(b"Hysteria2 candidate connect failed").await;
            return Err(hysteria2_candidate_attempt_failure(failure));
        }
    };
    let Some(remaining) = deadline.remaining_at(Instant::now()) else {
        guard.close(b"Hysteria2 candidate deadline elapsed").await;
        return Err(QuicCandidateAttemptFailure::Retryable(
            hysteria2_candidate_connect_timeout(),
        ));
    };
    tokio::select! {
        result = time::timeout(remaining, connecting) => {
            match result {
                Ok(Ok(connection)) => Ok((remote, guard.into_endpoint(), connection)),
                Ok(Err(error)) => {
                    let failure = classify_hysteria2_connection_error(
                        &error,
                        has_certificate_pin,
                        requires_webpki,
                    );
                    guard.close(b"Hysteria2 candidate handshake failed").await;
                    Err(hysteria2_candidate_attempt_failure(failure))
                }
                Err(_) => {
                    guard.close(b"Hysteria2 candidate connect timeout").await;
                    Err(QuicCandidateAttemptFailure::Retryable(
                        hysteria2_candidate_connect_timeout(),
                    ))
                }
            }
        }
        reason = cancellation.cancelled() => {
            guard.close(b"Hysteria2 candidate connect cancelled").await;
            Err(QuicCandidateAttemptFailure::Terminal(
                hysteria2_cancellation_failure(reason),
            ))
        }
    }
}

fn hysteria2_candidate_attempt_failure(
    failure: Hysteria2Failure,
) -> QuicCandidateAttemptFailure<Hysteria2Failure> {
    if failure.allows_candidate_retry() {
        QuicCandidateAttemptFailure::Retryable(failure)
    } else {
        QuicCandidateAttemptFailure::Terminal(failure)
    }
}

fn hysteria2_candidate_connect_timeout() -> Hysteria2Failure {
    Hysteria2Failure::new(
        Hysteria2FailureClass::NetworkPort,
        "hysteria2-connect-port-timeout",
        "Hysteria2 QUIC handshake did not reach the selected server port",
    )
}

fn hysteria2_candidate_race_failure(
    failure: QuicCandidateRaceFailure<Hysteria2Failure>,
) -> Hysteria2ConnectionFailure {
    let failure = match failure {
        QuicCandidateRaceFailure::Empty => Hysteria2Failure::new(
            Hysteria2FailureClass::NetworkAddress,
            "hysteria2-resolve",
            "Hysteria2 server resolved to no usable address",
        ),
        QuicCandidateRaceFailure::Exhausted { failures, .. } => failures
            .into_iter()
            .next()
            .map(|(_, failure)| failure)
            .unwrap_or_else(|| {
                Hysteria2Failure::new(
                    Hysteria2FailureClass::NetworkAddress,
                    "hysteria2-connect-candidates",
                    "Hysteria2 has no usable network address candidate",
                )
            }),
        QuicCandidateRaceFailure::Deadline { .. } => Hysteria2Failure::new(
            Hysteria2FailureClass::Deadline,
            "hysteria2-connect-deadline",
            "Hysteria2 QUIC connect deadline elapsed",
        ),
        QuicCandidateRaceFailure::Cancelled(reason) => hysteria2_cancellation_failure(reason),
        QuicCandidateRaceFailure::Terminal { error, .. } => error,
    };
    Hysteria2ConnectionFailure::without_endpoint(failure)
}

fn hysteria2_cancellation_failure(
    reason: dae_runtime_control::OwnerCancellation,
) -> Hysteria2Failure {
    match reason {
        dae_runtime_control::OwnerCancellation::DeadlineElapsed => Hysteria2Failure::new(
            Hysteria2FailureClass::Deadline,
            "hysteria2-connect-deadline",
            "Hysteria2 QUIC connect deadline elapsed",
        ),
        dae_runtime_control::OwnerCancellation::GenerationDraining => Hysteria2Failure::new(
            Hysteria2FailureClass::Draining,
            "hysteria2-generation-draining",
            "Hysteria2 owner generation is draining",
        ),
        dae_runtime_control::OwnerCancellation::CallerCancelled
        | dae_runtime_control::OwnerCancellation::OwnerFault
        | dae_runtime_control::OwnerCancellation::DependencyFailed => Hysteria2Failure::new(
            Hysteria2FailureClass::Cancelled,
            "hysteria2-connect-cancelled",
            "Hysteria2 QUIC connect was cancelled",
        ),
    }
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
        let pin_alert = quinn::TransportErrorCode::crypto(TLS_ALERT_ACCESS_DENIED);
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

#[cfg(test)]
const TLS_ALERT_UNKNOWN_CA: u8 = 48;
const TLS_ALERT_ACCESS_DENIED: u8 = 49;

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

#[cfg(test)]
#[path = "quic_transport_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "quic_helpers_port_hopping_tests.rs"]
mod port_hopping_live_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "quic_transport_gro_tests.rs"]
mod gro_tests;

#[cfg(test)]
#[path = "quic_transport_send_tests.rs"]
mod send_tests;
