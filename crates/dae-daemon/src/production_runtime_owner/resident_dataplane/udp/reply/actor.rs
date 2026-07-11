use super::*;
use std::fmt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

mod socket;
use socket::{UdpReplySocketCache, send_udp_reply};

#[derive(Debug)]
pub(in super::super) enum UdpReplyError {
    Closing,
    QueueFull,
    DispatcherClosed,
    TimedOut,
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
            Self::DispatcherClosed => formatter.write_str("resident UDP reply dispatcher stopped"),
            Self::TimedOut => write!(
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
    deadline: time::Instant,
    response: oneshot::Sender<Result<(), UdpReplyError>>,
}

#[derive(Clone)]
pub(in super::super) struct UdpReplyHandle {
    sender: mpsc::Sender<UdpReplyRequest>,
    closing: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
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
        let deadline = time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT;
        let (response, receiver) = oneshot::channel();
        match self.sender.try_send(UdpReplyRequest {
            original_dst,
            peer,
            payload,
            deadline,
            response,
        }) {
            Ok(()) => self.metrics.udp_reply_queued(),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.udp_reply_queue_full();
                self.metrics.udp_reply_failed();
                return Err(UdpReplyError::QueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(UdpReplyError::DispatcherClosed);
            }
        }
        match time::timeout_at(deadline, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(UdpReplyError::DispatcherClosed),
            Err(_) => Err(UdpReplyError::TimedOut),
        }
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
                task_metrics,
            )
            .await
        });
        Self {
            handle: UdpReplyHandle {
                sender,
                closing,
                metrics,
            },
            stop: Some(stop),
            task,
        }
    }

    pub(in super::super) fn handle(&self) -> UdpReplyHandle {
        self.handle.clone()
    }

    pub(in super::super) async fn shutdown(mut self) -> Result<usize, UdpReplyError> {
        self.handle.closing.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, &mut self.task).await {
            Ok(Ok(socket_count)) => Ok(socket_count),
            Ok(Err(err)) => Err(UdpReplyError::Socket(format!(
                "resident UDP reply actor join failed: {err}"
            ))),
            Err(_) => {
                self.task.abort();
                Err(UdpReplyError::TimedOut)
            }
        }
    }
}

async fn run_udp_reply_actor(
    mut receiver: mpsc::Receiver<UdpReplyRequest>,
    mut stop: oneshot::Receiver<()>,
    socket_cache_capacity: usize,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> usize {
    let mut cache = UdpReplySocketCache::new(socket_cache_capacity);
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            request = receiver.recv() => {
                let Some(request) = request else {
                    break;
                };
                let result = send_udp_reply(&mut cache, &metrics, &request).await;
                if result.is_err() {
                    metrics.udp_reply_failed();
                }
                let _ = request.response.send(result);
            }
        }
    }
    receiver.close();
    cache.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reply_dispatcher_shutdown_joins_without_open_sockets() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let dispatcher = UdpReplyDispatcher::start(2, 2, metrics);
        assert_eq!(dispatcher.shutdown().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn reply_handle_rejects_when_its_bounded_queue_is_full() {
        let (sender, _receiver) = mpsc::channel(1);
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let handle = UdpReplyHandle {
            sender,
            closing: Arc::new(AtomicBool::new(false)),
            metrics: Arc::clone(&metrics),
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
                deadline: time::Instant::now() + RESIDENT_UDP_RESPONSE_TIMEOUT,
                response,
            })
            .unwrap();

        let err = handle.send(target, peer, vec![2]).await.unwrap_err();
        assert!(matches!(err, UdpReplyError::QueueFull));
        assert_eq!(metrics.snapshot()["udpReplyQueueFull"].as_u64().unwrap(), 1);
    }

    #[test]
    fn only_socket_errors_are_emitted_as_per_packet_events() {
        assert!(!UdpReplyError::QueueFull.should_log());
        assert!(!UdpReplyError::TimedOut.should_log());
        assert!(UdpReplyError::Socket("fatal".to_owned()).should_log());
    }
}
