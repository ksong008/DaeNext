use super::*;
use serde_json::Value;
use std::fmt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::production_runtime_owner::resident_dataplane::udp::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
};

mod socket;
use socket::{UdpReplySocketCache, send_udp_reply, send_udp_reply_batch};

#[derive(Debug)]
pub(in super::super) enum UdpReplyError {
    Closing,
    QueueFull,
    PayloadLimit(ResidentUdpPayloadAdmissionError),
    DispatcherClosed,
    ResponseTimedOut,
    Socket(String),
}

impl UdpReplyError {
    pub(in super::super) fn should_log(&self) -> bool {
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

struct UdpReplyRequest {
    original_dst: SocketAddr,
    peer: SocketAddr,
    payload: Vec<u8>,
    _payload_admission: ResidentUdpPayloadPermit,
    deadline: time::Instant,
    response: Option<oneshot::Sender<Result<(), UdpReplyError>>>,
    download_bytes_on_success: usize,
}

#[derive(Clone)]
pub(in super::super) struct UdpReplyHandle {
    senders: Arc<Vec<mpsc::Sender<UdpReplyRequest>>>,
    closing: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    payload_admission: ResidentUdpPayloadAdmission,
}

impl UdpReplyHandle {
    pub(in super::super) async fn send(
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
            original_dst,
            peer,
            payload,
            _payload_admission: payload_admission,
            deadline,
            response: Some(response),
            download_bytes_on_success: 0,
        });
        self.metrics.udp_reply_queued();
        match time::timeout_at(deadline, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(UdpReplyError::DispatcherClosed),
            Err(_) => Err(UdpReplyError::ResponseTimedOut),
        }
    }

    pub(in super::super) fn try_send_detached(
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
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for address in [original_dst, peer] {
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                hash = stable_udp_reply_hash_bytes(hash, &[4]);
                hash = stable_udp_reply_hash_bytes(hash, &ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                hash = stable_udp_reply_hash_bytes(hash, &[6]);
                hash = stable_udp_reply_hash_bytes(hash, &ip.octets());
            }
        }
        hash = stable_udp_reply_hash_bytes(hash, &address.port().to_be_bytes());
    }
    hash
}

fn stable_udp_reply_hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn partitioned_udp_reply_capacity(total: usize, shard_index: usize, shard_count: usize) -> usize {
    let total = total.max(1);
    let shard_count = shard_count.max(1).min(total);
    let shard_index = shard_index.min(shard_count - 1);
    let base = total / shard_count;
    let remainder = total % shard_count;
    base + usize::from(shard_index < remainder)
}

pub(in super::super) struct UdpReplyDispatcher {
    handle: UdpReplyHandle,
    stops: Vec<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<usize>>,
}

impl UdpReplyDispatcher {
    pub(in super::super) fn start(
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

    pub(in super::super) fn handle(&self) -> UdpReplyHandle {
        self.handle.clone()
    }

    pub(in super::super) async fn shutdown(mut self, deadline: time::Instant) -> Value {
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
                        let _ = response.send(result);
                    }
                }
            }
        }
    }
    receiver.close();
    cache.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;

    #[tokio::test]
    async fn reply_dispatcher_shutdown_joins_without_open_sockets() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let dispatcher = UdpReplyDispatcher::start(
            2,
            2,
            2,
            Duration::from_secs(1),
            2,
            ResidentUdpPayloadAdmission::new(1, 1024),
            metrics,
        );
        assert_eq!(
            dispatcher
                .shutdown(time::Instant::now() + RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE)
                .await["closedSockets"],
            0
        );
    }

    #[tokio::test]
    async fn reply_dispatcher_preserves_joined_ownership_at_expired_deadline() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let dispatcher = UdpReplyDispatcher::start(
            2,
            2,
            2,
            Duration::from_secs(1),
            2,
            ResidentUdpPayloadAdmission::new(1, 1024),
            metrics,
        );

        let report = dispatcher.shutdown(time::Instant::now()).await;

        assert_eq!(report["status"], "pass");
        assert_eq!(report["safetyStatus"], "pass");
        assert_eq!(report["taskJoined"], true);
        assert!(matches!(
            report["completionMode"].as_str(),
            Some("graceful" | "forced-bounded")
        ));
        assert!(report.get("error").is_none());
    }

    #[tokio::test]
    async fn reply_handle_waits_for_bounded_queue_capacity() {
        let (sender, mut receiver) = mpsc::channel(1);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let handle = UdpReplyHandle {
            senders: Arc::new(vec![sender]),
            closing: Arc::new(AtomicBool::new(false)),
            metrics: Arc::clone(&metrics),
            payload_admission: ResidentUdpPayloadAdmission::new(1, 1024),
        };
        let target: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (response, _response_rx) = oneshot::channel();
        handle.senders[0]
            .try_send(UdpReplyRequest {
                original_dst: target,
                peer,
                payload: vec![1],
                _payload_admission: ResidentUdpPayloadAdmission::new(1, 1024)
                    .try_acquire(1)
                    .unwrap(),
                deadline: time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT,
                response: Some(response),
                download_bytes_on_success: 0,
            })
            .unwrap();

        let send = tokio::spawn(async move { handle.send(target, peer, vec![2]).await });
        tokio::task::yield_now().await;
        assert!(!send.is_finished());

        let first = receiver.recv().await.unwrap();
        let _ = first.response.unwrap().send(Ok(()));
        let second = receiver.recv().await.unwrap();
        let _ = second.response.unwrap().send(Ok(()));

        send.await.unwrap().unwrap();
        assert_eq!(metrics.snapshot()["udpReplyQueueFull"].as_u64().unwrap(), 0);
        assert_eq!(metrics.snapshot()["udpReplyQueued"].as_u64().unwrap(), 1);
    }

    #[test]
    fn only_socket_errors_are_emitted_as_per_packet_events() {
        assert!(!UdpReplyError::QueueFull.should_log());
        assert!(
            !UdpReplyError::PayloadLimit(ResidentUdpPayloadAdmissionError {
                requested: 2,
                current: 1,
                limit: 1,
            })
            .should_log()
        );
        assert!(!UdpReplyError::ResponseTimedOut.should_log());
        assert!(UdpReplyError::Socket("fatal".to_owned()).should_log());
    }

    #[tokio::test]
    async fn detached_reply_uses_the_bounded_queue_without_a_waiter_task() {
        let (sender, mut receiver) = mpsc::channel(1);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let payload_admission = ResidentUdpPayloadAdmission::new(1, 1024);
        let handle = UdpReplyHandle {
            senders: Arc::new(vec![sender]),
            closing: Arc::new(AtomicBool::new(false)),
            metrics,
            payload_admission: payload_admission.clone(),
        };
        let target: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:10000".parse().unwrap();

        handle
            .try_send_detached(target, peer, vec![1, 2, 3], true)
            .unwrap();
        let request = receiver.recv().await.unwrap();
        assert_eq!(payload_admission.current(), 3);
        assert!(request.response.is_none());
        assert_eq!(request.download_bytes_on_success, 3);
        drop(request);
        assert_eq!(payload_admission.current(), 0);
    }

    #[test]
    fn reply_shard_hash_is_stable_and_separates_address_families() {
        let ipv4_target: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let ipv4_peer: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let ipv6_target: SocketAddr = "[::ffff:127.0.0.1]:53".parse().unwrap();
        let ipv6_peer: SocketAddr = "[::ffff:127.0.0.1]:10000".parse().unwrap();

        assert_eq!(
            stable_udp_reply_shard(ipv4_target, ipv4_peer, 2),
            stable_udp_reply_shard(ipv4_target, ipv4_peer, 2)
        );
        assert_ne!(
            stable_udp_reply_hash(ipv4_target, ipv4_peer),
            stable_udp_reply_hash(ipv6_target, ipv6_peer)
        );
    }

    #[test]
    fn reply_shard_partitions_preserve_total_queue_and_cache_capacity() {
        for total in [1, 2, 3, 7, 512] {
            for requested_shards in [1, 2, 4] {
                let shard_count = requested_shards.min(total);
                let partitioned_total = (0..shard_count)
                    .map(|index| partitioned_udp_reply_capacity(total, index, requested_shards))
                    .sum::<usize>();
                assert_eq!(partitioned_total, total);
            }
        }
    }

    #[tokio::test]
    async fn blocked_reply_shard_does_not_delay_an_independent_shard() {
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (second_sender, mut second_receiver) = mpsc::channel(1);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let payload_admission = ResidentUdpPayloadAdmission::new(1, 1024);
        let handle = UdpReplyHandle {
            senders: Arc::new(vec![first_sender, second_sender]),
            closing: Arc::new(AtomicBool::new(false)),
            metrics,
            payload_admission: payload_admission.clone(),
        };
        let target: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let peers = (10_000..=u16::MAX)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .fold([None, None], |mut selected, peer| {
                let shard = stable_udp_reply_shard(target, peer, 2);
                if selected[shard].is_none() {
                    selected[shard] = Some(peer);
                }
                selected
            });
        let first_peer = peers[0].expect("a tuple must hash to the first shard");
        let second_peer = peers[1].expect("a tuple must hash to the second shard");
        let occupied_payload = payload_admission.try_acquire(1).unwrap();
        handle.senders[0]
            .try_send(UdpReplyRequest {
                original_dst: target,
                peer: first_peer,
                payload: vec![1],
                _payload_admission: occupied_payload,
                deadline: time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT,
                response: None,
                download_bytes_on_success: 0,
            })
            .unwrap();

        let blocked_handle = handle.clone();
        let blocked =
            tokio::spawn(async move { blocked_handle.send(target, first_peer, vec![2]).await });
        tokio::task::yield_now().await;
        assert!(!blocked.is_finished());

        let progressing_handle = handle.clone();
        let progressing =
            tokio::spawn(
                async move { progressing_handle.send(target, second_peer, vec![3]).await },
            );
        let mut second_request = second_receiver.recv().await.unwrap();
        second_request
            .response
            .take()
            .unwrap()
            .send(Ok(()))
            .unwrap();
        drop(second_request);
        progressing.await.unwrap().unwrap();
        assert!(!blocked.is_finished());

        drop(first_receiver.recv().await.unwrap());
        let mut first_request = first_receiver.recv().await.unwrap();
        first_request.response.take().unwrap().send(Ok(())).unwrap();
        drop(first_request);
        blocked.await.unwrap().unwrap();
        assert_eq!(payload_admission.current(), 0);
    }
}
