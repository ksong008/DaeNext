use std::collections::{HashMap, VecDeque};
use std::os::fd::AsRawFd;
use std::sync::{
    Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use crate::{
    ResidentDataplaneMetrics, ResidentDnsUdpRuntimeConfig, ResidentUdpPayloadAdmission,
    ResidentUdpPayloadPermit,
};
use dae_datapath::udp_io::{UdpSendMessage, try_sendmmsg};

use super::super::*;

pub(crate) const DNS_UDP_REQUEST_ID_SPACE: usize = (u16::MAX as usize) + 1;
mod actor;
mod executor;
mod id_allocator;
use self::actor::run_udp_multiplex_actor;
#[cfg(test)]
use self::actor::{
    expire_pending_udp_requests, handle_udp_multiplex_response, next_udp_multiplex_deadline,
    validate_and_restore_udp_multiplex_response,
};
pub(crate) use self::executor::ResidentDnsUdpActorExecutor;
pub(crate) use self::id_allocator::DnsRequestIdAllocator;

#[derive(Clone)]
pub(in crate::dns) struct ResidentDnsUdpMultiplexHandle {
    sender: tokio::sync::mpsc::Sender<UdpMultiplexRequest>,
    cancellation_notify: Arc<tokio::sync::Notify>,
    metrics: Arc<ResidentDataplaneMetrics>,
    payload_admission: ResidentUdpPayloadAdmission,
    _lifecycle: Arc<ResidentDnsUdpActorLifecycle>,
    #[cfg(test)]
    attempts: usize,
    attempt_timeout: Duration,
}

pub(crate) struct ResidentDnsUdpActorLifecycle {
    stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl ResidentDnsUdpActorLifecycle {
    pub(crate) fn new() -> (Arc<Self>, tokio::sync::oneshot::Receiver<()>) {
        let (stop, stop_receiver) = tokio::sync::oneshot::channel();
        (
            Arc::new(Self {
                stop: Mutex::new(Some(stop)),
            }),
            stop_receiver,
        )
    }

    pub(crate) fn stop(&self) {
        if let Ok(mut stop) = self.stop.lock()
            && let Some(stop) = stop.take()
        {
            let _ = stop.send(());
        }
    }
}

impl Drop for ResidentDnsUdpActorLifecycle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) struct ResidentDnsUdpActorCompletion {
    finished: AtomicBool,
    notify: tokio::sync::Notify,
}

impl ResidentDnsUdpActorCompletion {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            finished: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        })
    }

    pub(crate) fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(crate) async fn wait(&self, deadline: tokio::time::Instant) -> bool {
        loop {
            if self.finished.load(Ordering::Acquire) {
                return true;
            }
            let notified = self.notify.notified();
            if self.finished.load(Ordering::Acquire) {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.finished.load(Ordering::Acquire);
            }
        }
    }
}

struct UdpMultiplexActorMetricGuard {
    metrics: Arc<ResidentDataplaneMetrics>,
    fatal: bool,
}

impl Drop for UdpMultiplexActorMetricGuard {
    fn drop(&mut self) {
        self.metrics.dns_udp_actor_closed(self.fatal);
    }
}

pub(crate) struct ResidentDnsUdpActorRegistration<T> {
    pub(crate) handle: T,
    pub(crate) lifecycle: Weak<ResidentDnsUdpActorLifecycle>,
    pub(crate) completion: Arc<ResidentDnsUdpActorCompletion>,
    pub(crate) task: tokio::task::JoinHandle<bool>,
}

#[derive(Clone)]
struct UdpMultiplexActorConfig {
    queue_capacity: usize,
    pending_capacity: usize,
    inflight_window: usize,
    send_batch_limit: usize,
    attempt_timeout: Duration,
    idle_timeout: Option<Duration>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl UdpMultiplexActorConfig {
    fn new(runtime: &ResidentDnsUdpRuntimeConfig, metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        let pending_capacity = runtime.pending_limit.clamp(1, DNS_UDP_REQUEST_ID_SPACE);
        Self {
            queue_capacity: runtime.queue_depth.max(1),
            pending_capacity,
            inflight_window: runtime.inflight_window.clamp(1, pending_capacity),
            send_batch_limit: runtime.send_batch_limit.clamp(1, 32),
            attempt_timeout: runtime.attempt_timeout,
            idle_timeout: runtime.actor_idle_timeout,
            metrics,
        }
    }
}

struct UdpMultiplexRequest {
    payload: Vec<u8>,
    deadline: time::Instant,
    _payload_admission: ResidentUdpPayloadPermit,
    response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

struct UdpMultiplexCancellationGuard {
    notify: Arc<tokio::sync::Notify>,
    armed: bool,
}

impl Drop for UdpMultiplexCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.notify.notify_one();
        }
    }
}

struct PendingUdpRequest {
    upstream_id: u16,
    original_id: u16,
    generation: u64,
    deadline: time::Instant,
    questions: Vec<PendingDnsQuestion>,
    response: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingDnsQuestion {
    qname_wire: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingUdpDeadline {
    id: u16,
    generation: u64,
    deadline: time::Instant,
}

impl PendingDnsQuestion {
    fn matches(&self, qname_wire: &[u8], qtype: u16, qclass: u16) -> bool {
        self.qtype == qtype
            && self.qclass == qclass
            && self.qname_wire.eq_ignore_ascii_case(qname_wire)
    }
}

#[cfg(test)]
pub(in crate::dns) async fn open_udp_multiplex_handle(
    target: SocketAddr,
    mark: u32,
) -> Result<ResidentDnsUdpMultiplexHandle, String> {
    let runtime = ResidentDnsUdpRuntimeConfig::standalone();
    let metrics = Arc::new(ResidentDataplaneMetrics::default());
    open_udp_multiplex_handle_with_config(target, mark, &runtime, metrics).await
}

#[cfg(test)]
async fn open_udp_multiplex_handle_with_config(
    target: SocketAddr,
    mark: u32,
    runtime: &ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<ResidentDnsUdpMultiplexHandle, String> {
    let socket = open_connected_dns_udp_socket(target, mark).await?;
    let opened = start_udp_multiplex_actor(target, socket, runtime, metrics);
    Ok(opened.handle)
}

fn start_udp_multiplex_actor(
    target: SocketAddr,
    socket: tokio::net::UdpSocket,
    runtime: &ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> ResidentDnsUdpActorRegistration<ResidentDnsUdpMultiplexHandle> {
    let config = UdpMultiplexActorConfig::new(runtime, Arc::clone(&metrics));
    let (sender, receiver) = tokio::sync::mpsc::channel(config.queue_capacity);
    let cancellation_notify = Arc::new(tokio::sync::Notify::new());
    let actor_cancellation_notify = Arc::clone(&cancellation_notify);
    let (lifecycle, stop_receiver) = ResidentDnsUdpActorLifecycle::new();
    let completion = ResidentDnsUdpActorCompletion::new();
    metrics.dns_udp_actor_opened();
    let task_metrics = Arc::clone(&metrics);
    let task = tokio::spawn(async move {
        let mut metric_guard = UdpMultiplexActorMetricGuard {
            metrics: task_metrics,
            fatal: false,
        };
        let fatal = run_udp_multiplex_actor(
            target,
            socket,
            receiver,
            stop_receiver,
            actor_cancellation_notify,
            config,
        )
        .await;
        metric_guard.fatal = fatal;
        fatal
    });
    ResidentDnsUdpActorRegistration {
        handle: ResidentDnsUdpMultiplexHandle {
            sender,
            cancellation_notify,
            metrics,
            payload_admission: runtime.payload_admission.clone(),
            _lifecycle: Arc::clone(&lifecycle),
            #[cfg(test)]
            attempts: runtime.attempts,
            attempt_timeout: runtime.attempt_timeout,
        },
        lifecycle: Arc::downgrade(&lifecycle),
        completion,
        task,
    }
}

impl ResidentDnsUdpMultiplexHandle {
    pub(in crate::dns) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub(in crate::dns) fn record_retry(&self) {
        self.metrics.dns_udp_retry();
    }

    pub(in crate::dns) fn record_recreated(&self) {
        self.metrics.dns_udp_forwarder_recreated();
    }

    #[cfg(test)]
    pub(in crate::dns) async fn exchange(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut failures = Vec::new();
        for attempt in 0..self.attempts {
            if attempt > 0 {
                self.metrics.dns_udp_retry();
            }
            match self.exchange_once(payload).await {
                Ok(response) => return Ok(response),
                Err(err) => failures.push(err),
            }
        }
        Err(format!(
            "receive DNS UDP response timeout after {} attempts: {}",
            self.attempts,
            failures.join("; ")
        ))
    }

    #[cfg(test)]
    pub(in crate::dns) async fn exchange_once(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.exchange_once_until(payload, time::Instant::now() + self.attempt_timeout)
            .await
    }

    pub(in crate::dns) async fn exchange_once_until(
        &self,
        payload: &[u8],
        request_deadline: time::Instant,
    ) -> Result<Vec<u8>, String> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let payload_admission = self.payload_admission.try_acquire(payload.len()).map_err(
            |error| {
                format!(
                    "DNS UDP queued payload byte limit reached: requested={}, current={}, limit={}",
                    error.requested, error.current, error.limit
                )
            },
        )?;
        let attempt_deadline = request_deadline.min(time::Instant::now() + self.attempt_timeout);
        let queued = time::timeout_at(
            attempt_deadline,
            self.sender.send(UdpMultiplexRequest {
                payload: payload.to_vec(),
                deadline: attempt_deadline,
                _payload_admission: payload_admission,
                response: response_tx,
            }),
        )
        .await;
        match queued {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err("DNS UDP multiplex actor is closed".to_owned()),
            Err(_) => {
                self.metrics.dns_udp_queue_wait_timeout();
                return Err("DNS UDP multiplex request queue wait timeout".to_owned());
            }
        }
        let mut cancellation = UdpMultiplexCancellationGuard {
            notify: Arc::clone(&self.cancellation_notify),
            armed: true,
        };
        let result = time::timeout_at(attempt_deadline, response_rx).await;
        if result.is_ok() {
            cancellation.armed = false;
        }
        result
            .map_err(|_| "DNS UDP multiplex exchange timeout".to_owned())?
            .map_err(|_| "DNS UDP multiplex actor dropped response".to_owned())?
    }
}

fn dns_packet_id(payload: &[u8]) -> Result<u16, String> {
    let Some(id) = payload.get(0..2) else {
        return Err("DNS packet is too short to read request id".to_owned());
    };
    Ok(u16::from_be_bytes([id[0], id[1]]))
}

fn pending_dns_questions(request: &DnsPacketView<'_>) -> Vec<PendingDnsQuestion> {
    request
        .questions()
        .map(|question| PendingDnsQuestion {
            qname_wire: question.qname_wire().to_vec(),
            qtype: question.qtype(),
            qclass: question.qclass(),
        })
        .collect()
}

fn rewrite_dns_packet_id_in_place(payload: &mut [u8], id: u16) {
    if payload.len() >= 2 {
        payload[0..2].copy_from_slice(&id.to_be_bytes());
    }
}

async fn open_connected_dns_udp_socket(
    target: SocketAddr,
    mark: u32,
) -> Result<tokio::net::UdpSocket, String> {
    let bind = match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket =
        std::net::UdpSocket::bind(bind).map_err(|err| format!("bind DNS UDP socket: {err}"))?;
    apply_resident_udp_socket_buffer_tuning(&socket);
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set DNS UDP SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set DNS UDP nonblocking: {err}"))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt async DNS UDP socket: {err}"))?;
    socket
        .connect(target)
        .await
        .map_err(|err| format!("connect DNS UDP socket to {target}: {err}"))?;
    Ok(socket)
}

#[cfg(test)]
mod tests;
