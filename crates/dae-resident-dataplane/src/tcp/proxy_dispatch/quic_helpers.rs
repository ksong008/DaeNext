use super::*;

use crate::{
    QuicCandidateRaceResourceProfile, authority_from_host_port, resolve_socket_addr_candidates,
};

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use dae_runtime_control::{AbsoluteDeadline, OwnerCancellationSignal};

const HYSTERIA2_SALAMANDER_HASH_LEN: usize = 32;
const HYSTERIA2_SALAMANDER_SALT_BATCH: usize = 64;
const QUIC_STREAM_RELAY_BUFFER_SIZE: usize = 16 * 1024;
pub(crate) async fn relay_tcp_over_quic_stream_async(
    inbound: &mut TokioTcpStream,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    let (inbound_read, inbound_write) = inbound.split();
    let upload = relay_quic_stream_upload(inbound_read, send, progress.clone(), metrics);
    let download = relay_quic_stream_download(recv, inbound_write, progress.clone(), metrics);
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident QUIC stream relay idle timeout",
        None,
    )
    .await
}

async fn relay_quic_stream_upload(
    mut inbound: tokio::net::tcp::ReadHalf<'_>,
    send: &mut quinn::SendStream,
    progress: ResidentDuplexProgress,
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let mut buffer = [0_u8; QUIC_STREAM_RELAY_BUFFER_SIZE];
    loop {
        let read = match inbound.read(&mut buffer).await {
            Ok(0) => {
                let _ = send.finish();
                return Ok(());
            }
            Ok(read) => read,
            Err(err) if is_graceful_stream_close_error(&err) => {
                let _ = send.finish();
                return Ok(());
            }
            Err(err) => return Err(format!("read inbound TCP for QUIC stream relay: {err}")),
        };
        send.write_all(&buffer[..read])
            .await
            .map_err(|err| format!("write client payload to QUIC stream: {err}"))?;
        // Quinn queues stream data from poll_write; its AsyncWrite poll_flush is an immediate
        // no-op. Avoid constructing and polling that redundant future for every relay chunk.
        progress.record_upload(read);
        metrics.add_upload(read);
    }
}

async fn relay_quic_stream_download(
    recv: &mut quinn::RecvStream,
    mut inbound: tokio::net::tcp::WriteHalf<'_>,
    progress: ResidentDuplexProgress,
    metrics: &ResidentDataplaneMetrics,
) -> Result<(), String> {
    let mut buffer = [0_u8; QUIC_STREAM_RELAY_BUFFER_SIZE];
    loop {
        let Some(read) = recv
            .read(&mut buffer)
            .await
            .map_err(|err| format!("read QUIC stream payload: {err}"))?
        else {
            let _ = inbound.shutdown().await;
            return Ok(());
        };
        if let Err(err) = inbound.write_all(&buffer[..read]).await {
            if is_graceful_stream_close_error(&err) {
                return Ok(());
            }
            return Err(format!("write QUIC stream payload to client: {err}"));
        }
        progress.record_download(read);
        metrics.add_download(read);
    }
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
    let runtime = quinn::default_runtime();
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
    salts: Vec<u8>,
    next_salt: usize,
}

impl SalamanderSendState {
    fn new() -> Self {
        let mut state = Self {
            packet: Vec::new(),
            salts: vec![
                0_u8;
                HYSTERIA2_SALAMANDER_SALT_BATCH * HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD
            ],
            next_salt: 0,
        };
        state.refill_salts();
        state
    }

    fn refill_salts(&mut self) {
        if getrandom::fill(&mut self.salts).is_err() {
            fastrand::fill(&mut self.salts);
        }
        self.next_salt = 0;
    }

    fn take_salt(&mut self) -> [u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD] {
        if self.next_salt + HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD > self.salts.len() {
            self.refill_salts();
        }
        let mut salt = [0_u8; HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD];
        let end = self.next_salt + HYSTERIA2_SALAMANDER_UDP_PACKET_OVERHEAD;
        salt.copy_from_slice(&self.salts[self.next_salt..end]);
        self.next_salt = end;
        salt
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
            return self.inner.try_send(transmit);
        }
        let mut send_state = self
            .send_state
            .lock()
            .map_err(|_| io::Error::other("Hysteria2 Salamander send state lock is poisoned"))?;
        for chunk in transmit.contents.chunks(segment_size) {
            let salt = send_state.take_salt();
            salamander_obfuscate_packet_into(&self.key, chunk, &salt, &mut send_state.packet);
            let obfs_transmit = udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &send_state.packet,
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
    if getrandom::fill(&mut salt).is_err() {
        fastrand::fill(&mut salt);
    }
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
mod tests {
    use super::*;
    use crate::ResidentRuntimeProfile;

    #[test]
    fn quic_bind_addr_follows_remote_ip_family() {
        let v4_remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let v6_remote = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443);

        assert!(quic_bind_addr_for_remote(v4_remote).is_ipv4());
        assert!(quic_bind_addr_for_remote(v6_remote).is_ipv6());
    }

    #[test]
    fn hysteria2_initial_port_selection_is_bounded_independently_of_port_set_size() {
        let addresses = vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        for port_count in [2, 3_001, 4_001] {
            let plan = Hysteria2ResolvedRemotePlan {
                addresses: addresses.clone(),
                ports: Arc::new(
                    (0..port_count)
                        .map(|offset| 10_000 + offset as u16)
                        .collect(),
                ),
                port_hopping: true,
            };
            let candidates = hysteria2_initial_remote_candidates_with(&plan, 4, |_| 0).unwrap();
            assert_eq!(candidates.len(), 4);
            assert_eq!(candidates[0], "192.0.2.1:10000".parse().unwrap());
            assert_eq!(candidates[1], "[2001:db8::1]:10000".parse().unwrap());
            assert_eq!(candidates[2], "192.0.2.1:10001".parse().unwrap());
            assert_eq!(candidates[3], "[2001:db8::1]:10001".parse().unwrap());
        }
    }

    #[test]
    fn hysteria2_fixed_port_keeps_every_resolved_address() {
        let plan = Hysteria2ResolvedRemotePlan {
            addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            ports: Arc::new(vec![443]),
            port_hopping: false,
        };
        let candidates = hysteria2_initial_remote_candidates_with(&plan, 1, |_| {
            panic!("fixed-port selection must not request randomness")
        })
        .unwrap();
        assert_eq!(
            candidates,
            vec![
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn hysteria2_tls_failures_are_terminal_and_redacted() {
        let certificate = quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
            error_code: quinn::TransportErrorCode::crypto(TLS_ALERT_UNKNOWN_CA),
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
            error_code: quinn::TransportErrorCode::crypto(TLS_ALERT_ACCESS_DENIED),
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
        .await
        .unwrap();
        endpoint.mark_ready();
        let snapshot = quic_endpoint_metrics_snapshot(generation.get());
        let charge = &snapshot["endpoints"][0]["chargedBytes"];
        assert_eq!(charge["receiveSegments"], 1);
        assert_eq!(
            charge["receiveSlab"],
            quinn_boring::helpers::default_endpoint_config()
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
            vec!["127.0.0.1".parse().unwrap()],
            Arc::new(vec![443, 8443]),
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
        .await
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
