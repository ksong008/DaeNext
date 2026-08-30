use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use dae_outbound_core::NetworkType;

use super::*;

mod response;
use self::response::{drain_udp_session_responses, wait_and_record_udp_session_response};

pub struct ManagedUdpPacket {
    pub packet: UdpOriginalDstPacket,
    pub original_dst: SocketAddr,
    pub proxy: ResidentProxyBinding,
    pub data_udp_network_type: Option<NetworkType>,
    pub data_udp_availability: ResidentDataUdpAvailabilityHandle,
    pub force_proxy_packet: bool,
    pub dscp: u8,
}

pub struct UdpSessionEntry {
    pub sender: mpsc::Sender<ManagedUdpPacket>,
    pub handle: JoinHandle<()>,
}

pub struct UdpSessionSharedContext {
    pub event_file: PathBuf,
    pub event_lock: Arc<Mutex<()>>,
    pub metrics: Arc<ResidentDataplaneMetrics>,
    pub udp_reply: UdpReplyHandle,
    pub active_sessions: Arc<AtomicUsize>,
    pub hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    pub tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    pub juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    pub anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    pub session_idle_timeout: Duration,
    pub proxy_session_idle_timeout: Duration,
    pub response_buffer_idle_timeout: Duration,
    pub actor_stop: SharedResidentStopSignal,
}

pub type UdpSessionActorContext = Arc<UdpSessionSharedContext>;

pub fn spawn_udp_session_actor(
    key: UdpSessionKey,
    actor_id: u64,
    context: UdpSessionActorContext,
    receiver: mpsc::Receiver<ManagedUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_udp_session_actor(key, actor_id, context, receiver, cleanup_tx).await;
    })
}

async fn run_udp_session_actor(
    key: UdpSessionKey,
    actor_id: u64,
    context: UdpSessionActorContext,
    mut receiver: mpsc::Receiver<ManagedUdpPacket>,
    cleanup_tx: mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
) {
    let _cleanup_guard = UdpSessionCleanupGuard::new(
        key.clone(),
        actor_id,
        cleanup_tx,
        Arc::clone(&context.metrics),
    );
    let _guard = UdpManagedSessionGuard::new(
        Arc::clone(&context.active_sessions),
        Arc::clone(&context.metrics),
    );
    let packet_session = key.to_value();
    append_event_with_metadata(
        &context.event_file,
        &context.event_lock,
        ResidentEventMetadata::new(ResidentEventKind::UdpSessionStarted),
        || {
            json!({
                "event": ResidentEventKind::UdpSessionStarted.name(),
                "packetSession": packet_session.clone(),
            })
        },
    );

    let mut packets = 0_u64;
    let mut stop_reason = "queue-closed".to_owned();
    let mut executor: Option<UdpSessionExecutor> = None;
    let mut session_proxy: Option<ResidentProxyBinding> = None;
    let idle_timeout = key.idle_timeout(context.proxy_session_idle_timeout);
    let idle_timer = time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    let response_buffer_timer = time::sleep(context.response_buffer_idle_timeout);
    tokio::pin!(response_buffer_timer);
    let mut response_buffer_timer_armed = false;
    let mut stop_listener = context.actor_stop.listener();
    'session: loop {
        tokio::select! {
            biased;
            _ = stop_listener.cancelled() => {
                stop_reason = "generation-stop".to_owned();
                break;
            }
            maybe_managed = receiver.recv() => {
                let managed = match maybe_managed {
                    Some(managed) => managed,
                    None => break,
                };
                let activity_at = time::Instant::now();
                idle_timer.as_mut().reset(activity_at + idle_timeout);
                packets += 1;
                if executor.is_none() {
                    let mut selected_executor = if managed.force_proxy_packet {
                        UdpSessionExecutor::new_proxy_packet_with_transport_owner(
                            managed.proxy.clone(),
                            context.hysteria2_owner_registry.clone(),
                            context.tuic_owner_registry.clone(),
                            context.juicity_owner_registry.clone(),
                            context.anytls_owner_registry.clone(),
                        )
                    } else {
                        UdpSessionExecutor::new_with_transport_owner(
                            managed.proxy.clone(),
                            managed.original_dst,
                            context.hysteria2_owner_registry.clone(),
                            context.tuic_owner_registry.clone(),
                            context.juicity_owner_registry.clone(),
                            context.anytls_owner_registry.clone(),
                        )
                    };
                    selected_executor.set_runtime_metrics(Arc::clone(&context.metrics));
                    executor = Some(selected_executor);
                    session_proxy = Some(managed.proxy.clone());
                }
                let (exchange, execute_timed_out) = match executor.as_mut() {
                    Some(executor) => tokio::select! {
                        biased;
                        _ = stop_listener.cancelled() => {
                            stop_reason = "generation-stop".to_owned();
                            break 'session;
                        }
                        result = time::timeout(
                            RESIDENT_UDP_RESPONSE_TIMEOUT,
                            executor.execute_proxy_packet(
                                &managed.proxy,
                                managed.original_dst,
                                &managed.packet.payload,
                            ),
                        ) => match result {
                            Ok(exchange) => (exchange, false),
                            Err(_) => (
                                Err(format!(
                                    "UDP session executor timed out after {}ms",
                                    RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis()
                                )),
                                true,
                            ),
                        }
                    },
                    None => (
                        Err("UDP session executor was not initialized".to_owned()),
                        false,
                    ),
                };
                if exchange.is_ok()
                    && let Some(network_type) = managed.data_udp_network_type
                {
                    managed
                        .data_udp_availability
                        .record(network_type, unix_now_secs());
                }
                tokio::select! {
                    biased;
                    _ = stop_listener.cancelled() => {
                        stop_reason = "generation-stop".to_owned();
                        break 'session;
                    }
                    _ = record_udp_exchange_result(
                        &managed.proxy,
                        managed.packet,
                        managed.original_dst,
                        managed.dscp,
                        context.event_file.clone(),
                        Arc::clone(&context.event_lock),
                        Arc::clone(&context.metrics),
                        &context.udp_reply,
                        &packet_session,
                        exchange,
                    ) => {}
                }
                if execute_timed_out {
                    stop_reason = "execute-timeout".to_owned();
                    break;
                }
                if let (Some(executor), Some(proxy)) = (executor.as_mut(), session_proxy.as_ref())
                {
                    let drain = drain_udp_session_responses(
                        &key,
                        &context,
                        executor,
                        proxy,
                        &packet_session,
                    );
                    tokio::select! {
                        biased;
                        _ = stop_listener.cancelled() => {
                            stop_reason = "generation-stop".to_owned();
                            break 'session;
                        }
                        result = drain => if let Err(err) = result {
                            stop_reason = err;
                            break 'session;
                        }
                    }
                }
                if !response_buffer_timer_armed
                    && executor
                        .as_ref()
                        .is_some_and(UdpSessionExecutor::has_response_buffer)
                {
                    response_buffer_timer
                        .as_mut()
                        .reset(activity_at + context.response_buffer_idle_timeout);
                    response_buffer_timer_armed = true;
                }
            }
            response = wait_and_record_udp_session_response(
                &key,
                &context,
                &mut executor,
                session_proxy.as_ref(),
                &packet_session,
            ), if executor.is_some() && session_proxy.is_some() => {
                if let Err(err) = response {
                    stop_reason = err;
                    break;
                }
                if !response_buffer_timer_armed
                    && executor
                        .as_ref()
                        .is_some_and(UdpSessionExecutor::has_response_buffer)
                {
                    response_buffer_timer.as_mut().reset(
                        time::Instant::now() + context.response_buffer_idle_timeout,
                    );
                    response_buffer_timer_armed = true;
                }
            }
            _ = &mut response_buffer_timer, if response_buffer_timer_armed => {
                if let Some(executor) = executor.as_mut() {
                    executor.reclaim_response_buffer();
                }
                response_buffer_timer_armed = false;
            }
            _ = &mut idle_timer => {
                stop_reason = "idle-timeout".to_owned();
                break;
            }
        }
    }

    if let Some(mut executor) = executor {
        let _ = time::timeout(RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE, executor.shutdown()).await;
    }
    append_event_with_metadata(
        &context.event_file,
        &context.event_lock,
        ResidentEventMetadata::new(ResidentEventKind::UdpSessionStopped),
        || {
            json!({
                "event": ResidentEventKind::UdpSessionStopped.name(),
                "reason": stop_reason,
                "packet_count": packets,
                "packetSession": packet_session,
            })
        },
    );
}

pub(super) struct UdpManagedSessionGuard {
    active_sessions: Arc<AtomicUsize>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl UdpManagedSessionGuard {
    pub(super) fn new(
        active_sessions: Arc<AtomicUsize>,
        metrics: Arc<ResidentDataplaneMetrics>,
    ) -> Self {
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
