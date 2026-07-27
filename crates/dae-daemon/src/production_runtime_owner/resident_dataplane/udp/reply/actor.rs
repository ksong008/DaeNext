use super::*;
use serde_json::Value;
use std::fmt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::production_runtime_owner::udp_payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
};

mod socket;
use socket::{UdpReplySocketCache, send_udp_reply};

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
    sender: mpsc::Sender<UdpReplyRequest>,
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
        let permit = match self.sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => {
                match time::timeout_at(deadline, self.sender.reserve()).await {
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
        self.sender
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
}

pub(in super::super) struct UdpReplyDispatcher {
    handle: UdpReplyHandle,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<usize>,
}

impl UdpReplyDispatcher {
    pub(in super::super) fn start(
        queue_depth: usize,
        socket_cache_capacity: usize,
        socket_idle_timeout: Duration,
        payload_admission: ResidentUdpPayloadAdmission,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(queue_depth.max(1));
        let (stop, stop_receiver) = oneshot::channel();
        let closing = Arc::new(AtomicBool::new(false));
        let task_metrics = Arc::clone(&metrics);
        let task = tokio::spawn(async move {
            run_udp_reply_actor(
                receiver,
                stop_receiver,
                socket_cache_capacity.max(1),
                socket_idle_timeout,
                task_metrics,
            )
            .await
        });
        Self {
            handle: UdpReplyHandle {
                sender,
                closing,
                metrics,
                payload_admission,
            },
            stop: Some(stop),
            task,
        }
    }

    pub(in super::super) fn handle(&self) -> UdpReplyHandle {
        self.handle.clone()
    }

    pub(in super::super) async fn shutdown(mut self, deadline: time::Instant) -> Value {
        self.handle.closing.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let shutdown = shutdown_resident_owned_task(&mut self.task, deadline).await;
        let status = shutdown.status();
        let safety_status = shutdown.safety_status();
        let graceful = shutdown.graceful();
        let completion_mode = shutdown.completion_mode();
        json!({
            "status": status,
            "safetyStatus": safety_status,
            "graceful": graceful,
            "completionMode": completion_mode,
            "closedSockets": shutdown.output,
            "taskJoined": shutdown.joined,
            "taskForced": shutdown.forced,
            "taskCancelled": shutdown.cancelled,
            "taskPanicked": shutdown.panicked,
            "joinError": shutdown.error,
        })
    }
}

async fn run_udp_reply_actor(
    mut receiver: mpsc::Receiver<UdpReplyRequest>,
    mut stop: oneshot::Receiver<()>,
    socket_cache_capacity: usize,
    socket_idle_timeout: Duration,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> usize {
    let mut cache = UdpReplySocketCache::new(socket_cache_capacity);
    let socket_idle_timeout = socket_idle_timeout.max(Duration::from_millis(1));
    let mut eviction = time::interval_at(
        time::Instant::now() + socket_idle_timeout,
        socket_idle_timeout,
    );
    eviction.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
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
                let result = send_udp_reply(&mut cache, &metrics, &request).await;
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
            Duration::from_secs(1),
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
            Duration::from_secs(1),
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
            sender,
            closing: Arc::new(AtomicBool::new(false)),
            metrics: Arc::clone(&metrics),
            payload_admission: ResidentUdpPayloadAdmission::new(1, 1024),
        };
        let target: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (response, _response_rx) = oneshot::channel();
        handle
            .sender
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
            sender,
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
}
