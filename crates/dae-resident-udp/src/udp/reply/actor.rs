use super::*;
use serde_json::Value;
use std::fmt;
use std::hash::BuildHasher;
use std::hash::RandomState;
use std::sync::OnceLock;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use dae_resident_core::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
};

mod socket;
use socket::{UdpReplySocketCache, send_udp_reply, send_udp_reply_batch};

#[derive(Debug)]
pub enum UdpReplyError {
    Closing,
    QueueFull,
    PayloadLimit(ResidentUdpPayloadAdmissionError),
    DispatcherClosed,
    ResponseTimedOut,
    Socket(String),
}

impl UdpReplyError {
    pub fn should_log(&self) -> bool {
        matches!(self, Self::Socket(_))
    }
}

impl fmt::Display for UdpReplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closing => formatter.write_str("resident UDP reply dispatcher is closing"),
            Self::QueueFull => formatter.write_str("resident UDP reply queue is full"),
            Self::PayloadLimit(error) => write!(
                formatter,
                "resident UDP queued payload byte limit reached: requested={}, current={}, limit={}",
                error.requested, error.current, error.limit
            ),
            Self::DispatcherClosed => formatter.write_str("resident UDP reply dispatcher stopped"),
            Self::ResponseTimedOut => write!(
                formatter,
                "resident UDP reply timed out after {}ms",
                RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis()
            ),
            Self::Socket(error) => formatter.write_str(error),
        }
    }
}

enum UdpReplyCompletion {
    Result(oneshot::Sender<Result<(), UdpReplyError>>),
    Reclaim(oneshot::Sender<Result<Vec<u8>, UdpReplyError>>),
}

struct UdpReplyRequest {
    work: ResidentUdpWorkGuard,
    original_dst: SocketAddr,
    peer: SocketAddr,
    payload: Vec<u8>,
    _payload_admission: ResidentUdpPayloadPermit,
    deadline: time::Instant,
    response: Option<UdpReplyCompletion>,
    download_bytes_on_success: usize,
}

#[derive(Clone)]
pub struct UdpReplyHandle {
    senders: Arc<Vec<mpsc::Sender<UdpReplyRequest>>>,
    closing: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    payload_admission: ResidentUdpPayloadAdmission,
}

impl UdpReplyHandle {
    pub async fn send(
        &self,
        original_dst: SocketAddr,
        peer: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<(), UdpReplyError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(UdpReplyError::Closing);
        }
        let payload_admission = self
            .payload_admission
            .try_acquire(payload.len())
            .map_err(UdpReplyError::PayloadLimit)?;
        let deadline = time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT;
        let (response, receiver) = oneshot::channel();
        let sender = self.sender_for(original_dst, peer);
        let permit = match sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => {
                match time::timeout_at(deadline, sender.reserve()).await {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(UdpReplyError::DispatcherClosed),
                    Err(_) => {
                        self.metrics.udp_reply_queue_full();
                        self.metrics.udp_reply_failed();
                        return Err(UdpReplyError::QueueFull);
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(UdpReplyError::DispatcherClosed);
            }
        };
        if self.closing.load(Ordering::Acquire) {
            return Err(UdpReplyError::Closing);
        }
        permit.send(UdpReplyRequest {
            work: ResidentUdpWorkGuard::new(Arc::clone(&self.metrics), ResidentUdpWorkStage::Reply),
            original_dst,
            peer,
            payload,
            _payload_admission: payload_admission,
            deadline,
            response: Some(UdpReplyCompletion::Result(response)),
            download_bytes_on_success: 0,
        });
        self.metrics.udp_reply_queued();
        match time::timeout_at(deadline, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(UdpReplyError::DispatcherClosed),
            Err(_) => Err(UdpReplyError::ResponseTimedOut),
        }
    }

    pub async fn send_reclaimable(
        &self,
        original_dst: SocketAddr,
        peer: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, UdpReplyError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(UdpReplyError::Closing);
        }
        let payload_admission = self
            .payload_admission
            .try_acquire(payload.len())
            .map_err(UdpReplyError::PayloadLimit)?;
        let deadline = time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT;
        let (response, receiver) = oneshot::channel();
        let sender = self.sender_for(original_dst, peer);
        let permit = match sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => {
                match time::timeout_at(deadline, sender.reserve()).await {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(UdpReplyError::DispatcherClosed),
                    Err(_) => {
                        self.metrics.udp_reply_queue_full();
                        self.metrics.udp_reply_failed();
                        return Err(UdpReplyError::QueueFull);
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(UdpReplyError::DispatcherClosed);
            }
        };
        if self.closing.load(Ordering::Acquire) {
            return Err(UdpReplyError::Closing);
        }
        permit.send(UdpReplyRequest {
            work: ResidentUdpWorkGuard::new(Arc::clone(&self.metrics), ResidentUdpWorkStage::Reply),
            original_dst,
            peer,
            payload,
            _payload_admission: payload_admission,
            deadline,
            response: Some(UdpReplyCompletion::Reclaim(response)),
            download_bytes_on_success: 0,
        });
        self.metrics.udp_reply_queued();
        match time::timeout_at(deadline, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(UdpReplyError::DispatcherClosed),
            Err(_) => Err(UdpReplyError::ResponseTimedOut),
        }
    }

    pub fn try_send_detached(
        &self,
        original_dst: SocketAddr,
        peer: SocketAddr,
        payload: Vec<u8>,
        count_download_on_success: bool,
    ) -> Result<(), UdpReplyError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(UdpReplyError::Closing);
        }
        let payload_admission = self
            .payload_admission
            .try_acquire(payload.len())
            .map_err(UdpReplyError::PayloadLimit)?;
        let download_bytes_on_success = if count_download_on_success {
            payload.len()
        } else {
            0
        };
        self.sender_for(original_dst, peer)
            .try_send(UdpReplyRequest {
                work: ResidentUdpWorkGuard::new(
                    Arc::clone(&self.metrics),
                    ResidentUdpWorkStage::Reply,
                ),
                original_dst,
                peer,
                payload,
                _payload_admission: payload_admission,
                deadline: time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT,
                response: None,
                download_bytes_on_success,
            })
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => {
                    self.metrics.udp_reply_queue_full();
                    self.metrics.udp_reply_failed();
                    UdpReplyError::QueueFull
                }
                mpsc::error::TrySendError::Closed(_) => UdpReplyError::DispatcherClosed,
            })?;
        self.metrics.udp_reply_queued();
        Ok(())
    }

    fn sender_for(
        &self,
        original_dst: SocketAddr,
        peer: SocketAddr,
    ) -> &mpsc::Sender<UdpReplyRequest> {
        &self.senders[stable_udp_reply_shard(original_dst, peer, self.senders.len())]
    }
}

fn stable_udp_reply_shard(original_dst: SocketAddr, peer: SocketAddr, shard_count: usize) -> usize {
    (stable_udp_reply_hash(original_dst, peer) as usize) % shard_count.max(1)
}

fn stable_udp_reply_hash(original_dst: SocketAddr, peer: SocketAddr) -> u64 {
    static STATE: OnceLock<RandomState> = OnceLock::new();
    STATE
        .get_or_init(RandomState::new)
        .hash_one((original_dst, peer))
}

fn partitioned_udp_reply_capacity(total: usize, shard_index: usize, shard_count: usize) -> usize {
    let total = total.max(1);
    let shard_count = shard_count.max(1).min(total);
    let shard_index = shard_index.min(shard_count - 1);
    let base = total / shard_count;
    let remainder = total % shard_count;
    base + usize::from(shard_index < remainder)
}

pub struct UdpReplyDispatcher {
    handle: UdpReplyHandle,
    stops: Vec<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<usize>>,
}

impl UdpReplyDispatcher {
    pub fn start(
        shard_count: usize,
        queue_depth: usize,
        socket_cache_capacity: usize,
        socket_idle_timeout: Duration,
        send_batch_limit: usize,
        payload_admission: ResidentUdpPayloadAdmission,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        let queue_depth = queue_depth.max(1);
        let socket_cache_capacity = socket_cache_capacity.max(1);
        let shard_count = shard_count
            .max(1)
            .min(queue_depth)
            .min(socket_cache_capacity);
        let closing = Arc::new(AtomicBool::new(false));
        let mut senders = Vec::with_capacity(shard_count);
        let mut stops = Vec::with_capacity(shard_count);
        let mut tasks = Vec::with_capacity(shard_count);
        for shard_index in 0..shard_count {
            let shard_queue_depth =
                partitioned_udp_reply_capacity(queue_depth, shard_index, shard_count);
            let shard_cache_capacity =
                partitioned_udp_reply_capacity(socket_cache_capacity, shard_index, shard_count);
            let (sender, receiver) = mpsc::channel(shard_queue_depth);
            let (stop, stop_receiver) = oneshot::channel();
            let task_metrics = Arc::clone(&metrics);
            tasks.push(tokio::spawn(async move {
                run_udp_reply_actor(
                    receiver,
                    stop_receiver,
                    shard_cache_capacity,
                    socket_idle_timeout,
                    send_batch_limit,
                    task_metrics,
                )
                .await
            }));
            senders.push(sender);
            stops.push(stop);
        }
        Self {
            handle: UdpReplyHandle {
                senders: Arc::new(senders),
                closing,
                metrics,
                payload_admission,
            },
            stops,
            tasks,
        }
    }

    pub fn handle(&self) -> UdpReplyHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self, deadline: time::Instant) -> Value {
        self.handle.closing.store(true, Ordering::Release);
        for stop in self.stops.drain(..) {
            let _ = stop.send(());
        }
        let task_count = self.tasks.len();
        let mut closed_sockets = 0_usize;
        let mut joined = 0_usize;
        let mut forced = 0_usize;
        let mut cancelled = 0_usize;
        let mut panicked = 0_usize;
        let mut errors = Vec::new();
        let mut completed_safely = true;
        let mut graceful = true;
        for task in &mut self.tasks {
            let shutdown = shutdown_resident_owned_task(task, deadline).await;
            completed_safely &= shutdown.status() == "pass";
            graceful &= shutdown.graceful();
            closed_sockets = closed_sockets.saturating_add(shutdown.output.unwrap_or(0));
            joined += usize::from(shutdown.joined);
            forced += usize::from(shutdown.forced);
            cancelled += usize::from(shutdown.cancelled);
            panicked += usize::from(shutdown.panicked);
            if let Some(error) = shutdown.error {
                errors.push(error);
            }
        }
        let completion_mode = if !completed_safely {
            "incomplete"
        } else if forced != 0 {
            "forced-bounded"
        } else {
            "graceful"
        };
        let first_error = errors.first().cloned();
        json!({
            "status": if completed_safely { "pass" } else { "fail" },
            "safetyStatus": if completed_safely { "pass" } else { "fail" },
            "graceful": graceful,
            "completionMode": completion_mode,
            "closedSockets": closed_sockets,
            "taskJoined": joined == task_count,
            "taskForced": forced != 0,
            "taskCancelled": cancelled != 0,
            "taskPanicked": panicked != 0,
            "joinError": first_error,
            "taskCount": task_count,
            "tasksJoined": joined,
            "tasksForced": forced,
            "tasksCancelled": cancelled,
            "tasksPanicked": panicked,
            "joinErrors": errors,
        })
    }
}

async fn run_udp_reply_actor(
    mut receiver: mpsc::Receiver<UdpReplyRequest>,
    mut stop: oneshot::Receiver<()>,
    socket_cache_capacity: usize,
    socket_idle_timeout: Duration,
    send_batch_limit: usize,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> usize {
    let mut cache = UdpReplySocketCache::new(socket_cache_capacity);
    let socket_idle_timeout = socket_idle_timeout.max(Duration::from_millis(1));
    let mut eviction = time::interval_at(
        time::Instant::now() + socket_idle_timeout,
        socket_idle_timeout,
    );
    eviction.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    // Keep the bounded batch container owned by the reply actor.  The old
    // loop allocated a fresh Vec for every receive wakeup even though the
    // batch limit is fixed by the runtime profile.  Reusing this storage
    // removes allocator traffic from every protocol's UDP reply path without
    // changing queue bounds or sendmmsg admission.
    let mut requests = Vec::with_capacity(send_batch_limit.clamp(1, 32));
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            _ = eviction.tick() => {
                let evicted = cache.evict_idle(time::Instant::now(), socket_idle_timeout);
                if evicted != 0 {
                    metrics.udp_reply_socket_idle_evicted(evicted);
                }
            }
            request = receiver.recv() => {
                let Some(request) = request else {
                    break;
                };
                requests.push(request);
                if !cfg!(feature = "test-scalar-udp-send") {
                    while requests.len() < send_batch_limit.max(1) {
                        match receiver.try_recv() {
                            Ok(request) => requests.push(request),
                            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }
                }
                for request in &mut requests {
                    request.work.transition(ResidentUdpWorkStage::Processing);
                }
                let results = if requests.len() > 1 {
                    send_udp_reply_batch(&mut cache, &metrics, &requests).await
                } else {
                    vec![send_udp_reply(&mut cache, &metrics, &requests[0]).await]
                };
                for (request, result) in requests.drain(..).zip(results) {
                    if result.is_err() {
                        metrics.udp_reply_failed();
                    } else if request.download_bytes_on_success > 0 {
                        metrics.add_download(request.download_bytes_on_success);
                    }
                    if let Some(response) = request.response {
                        match response {
                            UdpReplyCompletion::Result(response) => {
                                let _ = response.send(result);
                            }
                            UdpReplyCompletion::Reclaim(response) => {
                                let result = match result {
                                    Ok(()) => Ok(request.payload),
                                    Err(error) => Err(error),
                                };
                                let _ = response.send(result);
                            }
                        }
                    }
                }
            }
        }
    }
    receiver.close();
    cache.len()
}

#[cfg(test)]
pub(in crate::udp) fn test_reply_handle(
    metrics: Arc<ResidentDataplaneMetrics>,
) -> (UdpReplyHandle, mpsc::Receiver<Vec<u8>>, JoinHandle<()>) {
    let (sender, mut receiver) = mpsc::channel::<UdpReplyRequest>(16);
    let (delivered, packets) = mpsc::channel(64);
    let handle = UdpReplyHandle {
        senders: Arc::new(vec![sender]),
        closing: Arc::new(AtomicBool::new(false)),
        metrics: Arc::clone(&metrics),
        payload_admission: ResidentUdpPayloadAdmission::new(1, 1024 * 1024),
    };
    let task = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            metrics.add_download(request.download_bytes_on_success);
            if delivered.send(request.payload.clone()).await.is_err() {
                break;
            }
            match request.response {
                Some(UdpReplyCompletion::Reclaim(sender)) => {
                    let _ = sender.send(Ok(request.payload));
                }
                Some(UdpReplyCompletion::Result(sender)) => {
                    let _ = sender.send(Ok(()));
                }
                None => {}
            }
        }
    });
    (handle, packets, task)
}

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
