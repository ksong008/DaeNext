use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use dae_outbound_core::NetworkType;

use super::*;

mod response;
use self::response::{drain_udp_session_responses, wait_and_record_udp_session_response};

pub struct ManagedUdpPacket {
    pub work: Option<ResidentUdpWorkGuard>,
    pub packet: UdpOriginalDstPacket,
    pub original_dst: SocketAddr,
    pub proxy: ResidentProxyBinding,
    pub data_udp_network_type: Option<NetworkType>,
    pub data_udp_availability: ResidentDataUdpAvailabilityHandle,
    pub force_proxy_packet: bool,
    pub dscp: u8,
}

pub(super) struct UdpQueuedPacketGuard<'a> {
    metrics: &'a ResidentDataplaneMetrics,
    bytes: usize,
    completed: bool,
}

impl<'a> UdpQueuedPacketGuard<'a> {
    pub(super) fn new(metrics: &'a ResidentDataplaneMetrics, bytes: usize) -> Self {
        Self {
            metrics,
            bytes,
            completed: false,
        }
    }

    pub(super) fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for UdpQueuedPacketGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.metrics.udp_session_queued_dropped(self.bytes);
        }
    }
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
    pub outbound_send_batch_limit: usize,
    pub actor_stop: SharedResidentStopSignal,
}

impl UdpSessionSharedContext {
    pub(super) fn outbound_batch_limit(&self) -> usize {
        if cfg!(feature = "test-scalar-udp-send") {
            1
        } else {
            self.outbound_send_batch_limit.clamp(1, 32)
        }
    }

    pub(super) fn collect_outbound_batch<T>(
        &self,
        first: T,
        receiver: &mut mpsc::Receiver<T>,
    ) -> Vec<T> {
        let mut batch = vec![first];
        while batch.len() < self.outbound_batch_limit() {
            match receiver.try_recv() {
                Ok(packet) => batch.push(packet),
                Err(_) => break,
            }
        }
        batch
    }
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
    let mut executor: Option<Box<UdpSessionExecutor>> = None;
    let mut session_proxy: Option<ResidentProxyBinding> = None;
    let idle_timeout = key.idle_timeout(context.proxy_session_idle_timeout);
    let mut last_activity = time::Instant::now();
    let idle_timer = time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    let response_buffer_timer = time::sleep(idle_timeout);
    tokio::pin!(response_buffer_timer);
    let mut armed_response_buffer_deadline = None;
    let mut stop_listener = context.actor_stop.listener();
    'session: loop {
        // Invalid/partial responses must not starve the deadline through the
        // biased receive branch when the upstream stays continuously readable.
        if time::Instant::now() >= last_activity + idle_timeout && receiver.is_empty() {
            receiver.close();
            if receiver.is_empty() {
                stop_reason = "idle-timeout".to_owned();
                break;
            }
            // An enqueue won the idle/close race. Drain that accepted work;
            // the sealed channel prevents any later packet joining this actor.
        }
        let response_buffer_deadline = executor.as_ref().and_then(|executor| {
            executor.response_buffer_reclaim_deadline(context.response_buffer_idle_timeout)
        });
        if response_buffer_deadline != armed_response_buffer_deadline {
            if let Some(deadline) = response_buffer_deadline {
                response_buffer_timer.as_mut().reset(deadline);
            }
            armed_response_buffer_deadline = response_buffer_deadline;
        }
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
                    executor = Some(Box::new(selected_executor));
                    session_proxy = Some(managed.proxy.clone());
                }
                let batch_limit = context.outbound_batch_limit();
                let can_batch = executor.as_mut().is_some_and(|executor| executor.begin_datagram_batch(batch_limit));
                let batch = if can_batch { context.collect_outbound_batch(managed, &mut receiver) } else { vec![managed] };
                // Dequeued batch members remain accepted queued work until
                // their exchange result is recorded. Cancellation must also
                // account for members no longer present in the receiver.
                let batch = batch.into_iter().map(|managed| {
                    let guard = UdpQueuedPacketGuard::new(&context.metrics, managed.packet.payload.len());
                    (managed, guard)
                }).collect::<Vec<_>>();
                let mut completed = Vec::with_capacity(batch.len());
                for (mut managed, queued) in batch {
                    let mut work = managed.work.take();
                    if let Some(work) = work.as_mut() { work.transition(ResidentUdpWorkStage::Processing); }
                    last_activity = time::Instant::now();
                    packets += 1;
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
                                    "UDP session executor timed out after {}ms (stage={})",
                                    RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis(),
                                    executor.execution_stage()
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
                    completed.push((managed, work, exchange, execute_timed_out, queued));
                    if execute_timed_out { break; }
                }
                let sent = if can_batch {
                    let mark = session_proxy.as_ref().map_or(0, |proxy| proxy.effective_socket_mark());
                    let Some(executor) = executor.as_mut() else { stop_reason = "executor-missing".to_owned(); break 'session; };
                    tokio::select! {
                        biased;
                        _ = stop_listener.cancelled() => { stop_reason = "generation-stop".to_owned(); break 'session; }
                        result = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, executor.flush_datagram_batch(mark)) => result,
                    }
                } else { Ok(Vec::new()) };
                let mut sent = match sent {
                    Ok(sent) => sent.into_iter(),
                    Err(_) => {
                        for (_, _, exchange, timed_out, _) in &mut completed {
                            if exchange.is_ok() { *exchange = Err("UDP outbound batch send timed out".to_owned()); }
                            *timed_out = true;
                        }
                        Vec::new().into_iter()
                    }
                };
                for (managed, _work, mut exchange, execute_timed_out, mut queued) in completed {
                    if can_batch && exchange.is_ok() && let Some(Err(error)) = sent.next() {
                        exchange = Err(error);
                    }
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
                        &context.event_file,
                        &context.event_lock,
                        &context.metrics,
                        &context.udp_reply,
                        &packet_session,
                        exchange,
                        &mut last_activity,
                    ) => {}
                }
                queued.complete();
                if execute_timed_out {
                    stop_reason = "execute-timeout".to_owned();
                    break 'session;
                }
                }
                if let (Some(executor), Some(proxy)) = (executor.as_mut(), session_proxy.as_ref())
                {
                    let drain = drain_udp_session_responses(
                        &key,
                        &context,
                        executor,
                        proxy,
                        &packet_session,
                        &mut last_activity,
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
            }
            response = wait_and_record_udp_session_response(
                &key,
                &context,
                &mut executor,
                session_proxy.as_ref(),
                &packet_session,
                &mut last_activity,
            ), if executor.is_some() && session_proxy.is_some() => {
                if let Err(err) = response {
                    stop_reason = err;
                    break;
                }
            }
            _ = &mut response_buffer_timer, if response_buffer_deadline.is_some() => {
                if let Some(executor) = executor.as_mut() {
                    executor.reclaim_response_buffer_if_idle(
                        time::Instant::now(), context.response_buffer_idle_timeout,
                    );
                }
            }
            _ = &mut idle_timer => {
                if time::Instant::now() < last_activity + idle_timeout || !receiver.is_empty() {
                    idle_timer.as_mut().reset(last_activity + idle_timeout);
                    continue;
                }
                receiver.close();
                if !receiver.is_empty() { continue; }
                stop_reason = "idle-timeout".to_owned();
                break;
            }
        }
    }

    let queued_dropped = finish_udp_actor_queue(
        &mut receiver,
        &context.metrics,
        |packet| packet.packet.payload.len(),
        async {
            if let Some(mut executor) = executor {
                executor.shutdown().await;
            }
        },
    )
    .await;
    append_event_with_metadata(
        &context.event_file,
        &context.event_lock,
        ResidentEventMetadata::new(ResidentEventKind::UdpSessionStopped),
        || {
            json!({
                "event": ResidentEventKind::UdpSessionStopped.name(),
                "reason": stop_reason,
                "packet_count": packets,
                "queued_dropped": queued_dropped,
                "packetSession": packet_session,
            })
        },
    );
}

pub(super) async fn finish_udp_actor_queue<T>(
    receiver: &mut mpsc::Receiver<T>,
    metrics: &ResidentDataplaneMetrics,
    payload_len: impl Fn(&T) -> usize,
    shutdown: impl std::future::Future<Output = ()>,
) -> usize {
    let dropped = close_udp_actor_queue(receiver, metrics, payload_len);
    let _ = time::timeout(RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE, shutdown).await;
    dropped
}

pub(super) fn close_udp_actor_queue<T>(
    receiver: &mut mpsc::Receiver<T>,
    metrics: &ResidentDataplaneMetrics,
    payload_len: impl Fn(&T) -> usize,
) -> usize {
    // Seal before any awaited shutdown; successful earlier enqueue is not a
    // claim of delivery. Release all queued payload/work leases explicitly.
    receiver.close();
    let mut dropped = 0;
    while let Ok(packet) = receiver.try_recv() {
        metrics.udp_session_queued_dropped(payload_len(&packet));
        dropped += 1;
    }
    dropped
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

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn boxed_udp_executor_keeps_the_actor_state_pointer_sized() {
        assert_eq!(
            std::mem::size_of::<Option<Box<UdpSessionExecutor>>>(),
            std::mem::size_of::<usize>()
        );
        assert!(
            std::mem::size_of::<Option<Box<UdpSessionExecutor>>>()
                < std::mem::size_of::<Option<UdpSessionExecutor>>()
        );
    }
}

#[cfg(test)]
#[path = "session_actor/close_tests.rs"]
mod close_tests;
