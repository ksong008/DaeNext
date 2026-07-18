use serde_json::Value;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;

use super::*;

mod dispatch;
mod shutdown;
mod worker;

use self::shutdown::join_udp_tasks_until_deadline;
use self::worker::run_resident_udp_session_shard;

pub(super) type SharedUdpSniffedDomain = Option<Arc<str>>;

struct ResidentUdpProxyShardPacket {
    key: UdpSessionKey,
    managed: ManagedUdpPacket,
    route: ResidentUdpRouteSelection,
    sniffed_domain: SharedUdpSniffedDomain,
}

struct ResidentUdpDirectShardPacket {
    key: UdpDirectSessionKey,
    managed: ManagedDirectUdpPacket,
    route: ResidentUdpRouteSelection,
    sniffed_domain: SharedUdpSniffedDomain,
}

enum ResidentUdpShardPacket {
    Proxy(ResidentUdpProxyShardPacket),
    Direct(ResidentUdpDirectShardPacket),
}

#[derive(Clone)]
struct ResidentUdpSessionShardContext {
    dns: Arc<ResidentDnsPlan>,
    proxy_groups: SharedResidentProxyGroupMap,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_reply: UdpReplyHandle,
    active_sessions: Arc<AtomicUsize>,
    admission: Arc<Semaphore>,
    session_queue_depth: usize,
    cleanup_queue_depth: usize,
    direct_response_buffer_idle_timeout: Duration,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
}

#[derive(Clone)]
pub(super) struct ResidentUdpSessionShardHandle {
    senders: Arc<Vec<mpsc::Sender<ResidentUdpShardPacket>>>,
    closing: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
}

pub(super) struct ResidentUdpSessionShardPool {
    handle: ResidentUdpSessionShardHandle,
    stops: Vec<oneshot::Sender<time::Instant>>,
    tasks: Vec<JoinHandle<Value>>,
}

impl ResidentUdpSessionShardPool {
    pub(super) fn start(
        runtime_config: &ResidentUdpRuntimeConfig,
        dns: Arc<ResidentDnsPlan>,
        proxy_groups: SharedResidentProxyGroupMap,
        event_file: PathBuf,
        event_lock: Arc<Mutex<()>>,
        metrics: Arc<ResidentDataplaneMetrics>,
        udp_reply: UdpReplyHandle,
        active_sessions: Arc<AtomicUsize>,
        hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    ) -> Self {
        let shard_count = runtime_config.runtime_shards.max(1);
        let queue_depth = runtime_config.per_shard_dispatch_queue_depth();
        let admission = Arc::new(Semaphore::new(runtime_config.session_limit));
        let context = ResidentUdpSessionShardContext {
            dns,
            proxy_groups,
            event_file: event_file.clone(),
            event_lock: Arc::clone(&event_lock),
            metrics: Arc::clone(&metrics),
            udp_reply,
            active_sessions,
            admission,
            session_queue_depth: runtime_config.session_queue_depth,
            cleanup_queue_depth: runtime_config.per_shard_cleanup_queue_depth(),
            direct_response_buffer_idle_timeout: runtime_config.direct_response_buffer_idle_timeout,
            hysteria2_owner_registry,
        };
        let mut senders = Vec::with_capacity(shard_count);
        let mut stops = Vec::with_capacity(shard_count);
        let mut tasks = Vec::with_capacity(shard_count);
        for shard_index in 0..shard_count {
            let (sender, receiver) = mpsc::channel(queue_depth);
            let (stop, stop_receiver) = oneshot::channel();
            let shard_context = context.clone();
            tasks.push(tokio::spawn(async move {
                run_resident_udp_session_shard(shard_index, receiver, stop_receiver, shard_context)
                    .await
            }));
            senders.push(sender);
            stops.push(stop);
        }
        let handle = ResidentUdpSessionShardHandle {
            senders: Arc::new(senders),
            closing: Arc::new(AtomicBool::new(false)),
            metrics,
            event_file,
            event_lock,
        };
        Self {
            handle,
            stops,
            tasks,
        }
    }

    pub(super) fn handle(&self) -> ResidentUdpSessionShardHandle {
        self.handle.clone()
    }

    pub(super) async fn shutdown(mut self, deadline: time::Instant) -> Value {
        self.handle.closing.store(true, Ordering::Release);
        for stop in self.stops.drain(..) {
            let _ = stop.send(deadline);
        }
        let started = Instant::now();
        let (joined, panicked, timed_out) =
            join_udp_tasks_until_deadline(&mut self.tasks, deadline).await;
        if timed_out > 0 {
            self.handle.metrics.udp_session_shutdown_deadline_hit();
        }
        json!({
            "status": if panicked == 0 && timed_out == 0 { "pass" } else { "fail" },
            "shardCount": self.handle.senders.len(),
            "joined": joined,
            "panicked": panicked,
            "timedOut": timed_out,
            "elapsedMs": started.elapsed().as_millis(),
        })
    }
}
