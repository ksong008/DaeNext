use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::*;

pub(super) struct ManagedUdpPacket {
    pub(super) packet: UdpOriginalDstPacket,
    pub(super) original_dst: SocketAddr,
    pub(super) proxy: Arc<ResidentProxyPlan>,
    pub(super) force_proxy_packet: bool,
}

pub(super) struct UdpSessionEntry {
    pub(super) sender: mpsc::Sender<ManagedUdpPacket>,
    pub(super) handle: JoinHandle<()>,
}

#[derive(Clone)]
pub(super) struct UdpSessionActorContext {
    pub(super) dns: Arc<ResidentDnsPlan>,
    pub(super) event_file: PathBuf,
    pub(super) event_lock: Arc<Mutex<()>>,
    pub(super) metrics: Arc<ResidentDataplaneMetrics>,
    pub(super) active_sessions: Arc<AtomicUsize>,
}

pub(super) fn spawn_udp_session_actor(
    key: UdpSessionKey,
    context: UdpSessionActorContext,
    receiver: mpsc::Receiver<ManagedUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpSessionKey>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_udp_session_actor(key, context, receiver, cleanup_tx).await;
    })
}

async fn run_udp_session_actor(
    key: UdpSessionKey,
    context: UdpSessionActorContext,
    mut receiver: mpsc::Receiver<ManagedUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpSessionKey>,
) {
    let _guard = UdpManagedSessionGuard::new(
        Arc::clone(&context.active_sessions),
        Arc::clone(&context.metrics),
    );
    append_event(
        &context.event_file,
        &context.event_lock,
        json!({
            "event": "udp_session_started",
            "packetSession": key.to_value(),
        }),
    );

    let mut packets = 0_u64;
    let mut stop_reason = "queue-closed".to_owned();
    let mut executor: Option<UdpSessionExecutor> = None;
    let mut session_proxy: Option<Arc<ResidentProxyPlan>> = None;
    let idle_timer = time::sleep(RESIDENT_UDP_SESSION_IDLE_TIMEOUT);
    tokio::pin!(idle_timer);
    loop {
        tokio::select! {
            maybe_managed = receiver.recv() => {
                let managed = match maybe_managed {
                    Some(managed) => managed,
                    None => break,
                };
                idle_timer
                    .as_mut()
                    .reset(time::Instant::now() + RESIDENT_UDP_SESSION_IDLE_TIMEOUT);
                packets += 1;
                if executor.is_none() {
                    executor = Some(if managed.force_proxy_packet {
                        UdpSessionExecutor::new_proxy_packet(&managed.proxy)
                    } else {
                        UdpSessionExecutor::new(&managed.proxy, managed.original_dst)
                    });
                    session_proxy = Some(Arc::clone(&managed.proxy));
                }
                let exchange = match executor.as_mut() {
                    Some(executor) => {
                        executor
                            .execute(
                                &context.dns,
                                &managed.proxy,
                                managed.original_dst,
                                &managed.packet.payload,
                            )
                            .await
                    }
                    None => Err("UDP session executor was not initialized".to_owned()),
                };
                record_udp_exchange_result(
                    &managed.proxy,
                    managed.packet,
                    managed.original_dst,
                    context.event_file.clone(),
                    Arc::clone(&context.event_lock),
                    Arc::clone(&context.metrics),
                    exchange,
                );
                if let (Some(executor), Some(proxy)) = (executor.as_mut(), session_proxy.as_ref())
                    && let Err(err) = drain_udp_session_responses(&key, &context, executor, proxy).await {
                        stop_reason = err;
                        break;
                    }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP), if executor.is_some() => {
                if let (Some(executor), Some(proxy)) = (executor.as_mut(), session_proxy.as_ref())
                    && let Err(err) = drain_udp_session_responses(&key, &context, executor, proxy).await {
                        stop_reason = err;
                        break;
                    }
            }
            _ = &mut idle_timer => {
                stop_reason = "idle-timeout".to_owned();
                break;
            }
        }
    }

    if let Some(mut executor) = executor {
        executor.shutdown().await;
    }
    append_event(
        &context.event_file,
        &context.event_lock,
        json!({
            "event": "udp_session_stopped",
            "reason": stop_reason,
            "packet_count": packets,
            "packetSession": key.to_value(),
        }),
    );
    let _ = cleanup_tx.send(key).await;
}

async fn drain_udp_session_responses(
    key: &UdpSessionKey,
    context: &UdpSessionActorContext,
    executor: &mut UdpSessionExecutor,
    proxy: &Arc<ResidentProxyPlan>,
) -> Result<(), String> {
    for _ in 0..16 {
        let exchange = match executor.poll_response().await {
            Ok(Some(exchange)) => exchange,
            Ok(None) => return Ok(()),
            Err(err) => {
                record_udp_session_response_result(
                    proxy,
                    key.peer(),
                    key.original_destination(),
                    context.event_file.clone(),
                    Arc::clone(&context.event_lock),
                    Arc::clone(&context.metrics),
                    Err(err.clone()),
                );
                return Err(format!("upstream-read-failed: {err}"));
            }
        };
        record_udp_session_response_result(
            proxy,
            key.peer(),
            key.original_destination(),
            context.event_file.clone(),
            Arc::clone(&context.event_lock),
            Arc::clone(&context.metrics),
            Ok(exchange),
        );
    }
    Ok(())
}

struct UdpManagedSessionGuard {
    active_sessions: Arc<AtomicUsize>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl UdpManagedSessionGuard {
    fn new(active_sessions: Arc<AtomicUsize>, metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        active_sessions.fetch_add(1, Ordering::Relaxed);
        metrics.udp_opened();
        Self {
            active_sessions,
            metrics,
        }
    }
}

impl Drop for UdpManagedSessionGuard {
    fn drop(&mut self) {
        self.metrics.udp_closed();
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}
