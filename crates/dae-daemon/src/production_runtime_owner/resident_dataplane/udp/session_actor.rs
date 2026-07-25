use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use dae_outbound::NetworkType;

use crate::production_runtime_owner::resident_dataplane::unix_now_secs;

use super::*;

mod response;
use self::response::{drain_udp_session_responses, wait_and_record_udp_session_response};

pub(super) struct ManagedUdpPacket {
    pub(super) packet: UdpOriginalDstPacket,
    pub(super) original_dst: SocketAddr,
    pub(super) proxy: ResidentProxyBinding,
    pub(super) data_udp_network_type: Option<NetworkType>,
    pub(super) data_udp_availability: ResidentDataUdpAvailabilityHandle,
    pub(super) force_proxy_packet: bool,
    pub(super) dscp: u8,
}

pub(super) struct UdpSessionEntry {
    pub(super) sender: mpsc::Sender<ManagedUdpPacket>,
    pub(super) handle: JoinHandle<()>,
}

pub(super) struct UdpSessionSharedContext {
    pub(super) event_file: PathBuf,
    pub(super) event_lock: Arc<Mutex<()>>,
    pub(super) metrics: Arc<ResidentDataplaneMetrics>,
    pub(super) udp_reply: UdpReplyHandle,
    pub(super) active_sessions: Arc<AtomicUsize>,
    pub(super) hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    pub(super) tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    pub(super) juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    pub(super) anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    pub(super) response_buffer_idle_timeout: Duration,
}

pub(super) type UdpSessionActorContext = Arc<UdpSessionSharedContext>;

pub(super) fn spawn_udp_session_actor(
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
    let mut session_proxy: Option<ResidentProxyBinding> = None;
    let idle_timeout = key.idle_timeout();
    let idle_timer = time::sleep(idle_timeout);
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
                    .reset(time::Instant::now() + idle_timeout);
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
                    Some(executor) => match time::timeout(
                        RESIDENT_UDP_RESPONSE_TIMEOUT,
                        executor.execute_proxy_packet(
                            &managed.proxy,
                            managed.original_dst,
                            &managed.packet.payload,
                        ),
                    )
                    .await
                    {
                        Ok(exchange) => (exchange, false),
                        Err(_) => (
                            Err(format!(
                                "UDP session executor timed out after {}ms",
                                RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis()
                            )),
                            true,
                        ),
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
                record_udp_exchange_result(
                    &managed.proxy,
                    managed.packet,
                    managed.original_dst,
                    managed.dscp,
                    context.event_file.clone(),
                    Arc::clone(&context.event_lock),
                    Arc::clone(&context.metrics),
                    &context.udp_reply,
                    exchange,
                )
                .await;
                if execute_timed_out {
                    stop_reason = "execute-timeout".to_owned();
                    break;
                }
                if let (Some(executor), Some(proxy)) = (executor.as_mut(), session_proxy.as_ref())
                    && let Err(err) = drain_udp_session_responses(&key, &context, executor, proxy).await {
                        stop_reason = err;
                        break;
                    }
            }
            response = wait_and_record_udp_session_response(
                &key,
                &context,
                &mut executor,
                session_proxy.as_ref(),
            ), if executor.is_some() && session_proxy.is_some() => {
                if let Err(err) = response {
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
