use super::*;

// A stalled execution fixture holds real socket/task resources. It exercises
// the production bridge's bounded abort/join path without depending on a peer
// or on the completion timing of any particular proxy protocol.
#[derive(Default)]
pub struct ResidentProxyUdpBridgeTestObservation {
    started: tokio::sync::Notify,
    live: std::sync::atomic::AtomicUsize,
    executing: std::sync::atomic::AtomicUsize,
    cancelled: std::sync::atomic::AtomicUsize,
}

pub struct ResidentProxyUdpBridgeTestSnapshot {
    pub socket_live: usize,
    pub task_live: usize,
    pub execution_future_live: usize,
    pub execution_future_cancelled: usize,
}

impl ResidentProxyUdpBridgeTestObservation {
    pub fn stalled_execution() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub async fn wait_execution_started(&self, deadline: time::Instant) -> bool {
        if self.executing.load(Ordering::Acquire) != 0 {
            return true;
        }
        time::timeout_at(deadline, self.started.notified())
            .await
            .is_ok()
    }
    pub fn snapshot(&self) -> ResidentProxyUdpBridgeTestSnapshot {
        let live = self.live.load(Ordering::Acquire);
        ResidentProxyUdpBridgeTestSnapshot {
            socket_live: live,
            task_live: live,
            execution_future_live: self.executing.load(Ordering::Acquire),
            execution_future_cancelled: self.cancelled.load(Ordering::Acquire),
        }
    }
}

pub async fn open_resident_proxy_udp_bridge_with_test_observation_async(
    _proxy: Arc<ResidentProxyPlan>,
    _original_dst: SocketAddr,
    observation: Arc<ResidentProxyUdpBridgeTestObservation>,
) -> Result<ResidentProxyUdpBridge, String> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| e.to_string())?;
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    struct Guard(Arc<ResidentProxyUdpBridgeTestObservation>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if self.0.executing.swap(0, Ordering::AcqRel) != 0 {
                self.0.cancelled.fetch_add(1, Ordering::AcqRel);
            }
            self.0.live.store(0, Ordering::Release);
        }
    }
    observation.live.store(1, Ordering::Release);
    let guard = Guard(observation.clone());
    let task = tokio::spawn(async move {
        let _guard = guard;
        let _shutdown = shutdown_rx;
        let mut packet = [0_u8; 64];
        socket.recv_from(&mut packet).await.unwrap();
        observation.executing.store(1, Ordering::Release);
        observation.started.notify_one();
        std::future::pending::<()>().await;
        drop(socket);
    });
    Ok(ResidentProxyUdpBridge {
        local_addr,
        shutdown: Some(shutdown_tx),
        task: Some(task),
        last_error: Arc::new(Mutex::new(None)),
    })
}
