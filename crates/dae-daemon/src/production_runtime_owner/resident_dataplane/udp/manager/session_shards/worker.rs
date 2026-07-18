use tokio::sync::OwnedSemaphorePermit;

use super::*;

struct ResidentUdpProxyShardEntry {
    actor_id: u64,
    session: UdpSessionEntry,
    _admission: OwnedSemaphorePermit,
}

struct ResidentUdpDirectShardEntry {
    actor_id: u64,
    session: UdpDirectSessionEntry,
    _admission: OwnedSemaphorePermit,
}

pub(super) async fn run_resident_udp_session_shard(
    shard_index: usize,
    mut receiver: mpsc::Receiver<ResidentUdpShardPacket>,
    mut stop: oneshot::Receiver<time::Instant>,
    context: ResidentUdpSessionShardContext,
) -> Value {
    let mut proxy_sessions = HashMap::<UdpSessionKey, ResidentUdpProxyShardEntry>::new();
    let mut direct_sessions = HashMap::<UdpDirectSessionKey, ResidentUdpDirectShardEntry>::new();
    let (proxy_cleanup_tx, mut proxy_cleanup_rx) =
        mpsc::channel::<UdpSessionCleanup<UdpSessionKey>>(context.cleanup_queue_depth);
    let (direct_cleanup_tx, mut direct_cleanup_rx) =
        mpsc::channel::<UdpSessionCleanup<UdpDirectSessionKey>>(context.cleanup_queue_depth);
    let mut next_actor_id = 0_u64;

    let shutdown_deadline = loop {
        tokio::select! {
            biased;
            deadline = &mut stop => {
                receiver.close();
                break deadline.unwrap_or_else(|_| time::Instant::now());
            }
            Some(cleanup) = proxy_cleanup_rx.recv() => {
                retire_proxy_session_if_current(cleanup, &mut proxy_sessions, &context).await;
            }
            Some(cleanup) = direct_cleanup_rx.recv() => {
                retire_direct_session_if_current(cleanup, &mut direct_sessions, &context).await;
            }
            packet = receiver.recv() => {
                let Some(packet) = packet else {
                    break time::Instant::now();
                };
                match packet {
                    ResidentUdpShardPacket::Proxy(packet) => handle_proxy_shard_packet(
                        packet,
                        &context,
                        &proxy_cleanup_tx,
                        &mut proxy_sessions,
                        &mut next_actor_id,
                    ).await,
                    ResidentUdpShardPacket::Direct(packet) => handle_direct_shard_packet(
                        packet,
                        &context,
                        &direct_cleanup_tx,
                        &mut direct_sessions,
                        &mut next_actor_id,
                    ).await,
                }
            }
        }
    };

    receiver.close();
    drop(proxy_cleanup_rx);
    drop(direct_cleanup_rx);
    drop(proxy_cleanup_tx);
    drop(direct_cleanup_tx);

    let mut tasks = Vec::with_capacity(proxy_sessions.len() + direct_sessions.len());
    for (_, entry) in proxy_sessions.drain() {
        drop(entry.session.sender);
        tasks.push(entry.session.handle);
    }
    for (_, entry) in direct_sessions.drain() {
        drop(entry.session.sender);
        tasks.push(entry.session.handle);
    }
    let (joined, panicked, timed_out) =
        join_udp_tasks_until_deadline(&mut tasks, shutdown_deadline).await;
    if timed_out > 0 {
        context.metrics.udp_session_shutdown_deadline_hit();
    }
    for _ in 0..panicked {
        context.metrics.udp_session_actor_panicked();
    }
    json!({
        "shardIndex": shard_index,
        "status": if panicked == 0 && timed_out == 0 { "pass" } else { "fail" },
        "joined": joined,
        "panicked": panicked,
        "timedOut": timed_out,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpSessionDispatchOutcome {
    Queued,
    QueueFull,
    AdmissionRejected,
    ActorUnavailable,
}

enum UdpSessionSend<Packet> {
    Queued,
    Full(Packet),
    Closed(Packet),
}

fn classify_session_send<Packet>(
    result: Result<(), mpsc::error::TrySendError<Packet>>,
) -> UdpSessionSend<Packet> {
    match result {
        Ok(()) => UdpSessionSend::Queued,
        Err(mpsc::error::TrySendError::Full(packet)) => UdpSessionSend::Full(packet),
        Err(mpsc::error::TrySendError::Closed(packet)) => UdpSessionSend::Closed(packet),
    }
}

impl UdpSessionDispatchOutcome {
    fn queued(self) -> bool {
        self == Self::Queued
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Queued => UDP_ROUTE_REASON_QUEUED,
            Self::QueueFull => UDP_ROUTE_REASON_QUEUE_FULL,
            Self::AdmissionRejected => UDP_ROUTE_REASON_LIMIT,
            Self::ActorUnavailable => UDP_ROUTE_REASON_SESSION_UNAVAILABLE,
        }
    }
}

async fn handle_proxy_shard_packet(
    packet: ResidentUdpProxyShardPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    next_actor_id: &mut u64,
) {
    let mut route_event = udp_route_chosen_event(
        packet.managed.packet.peer,
        packet.managed.original_dst,
        &packet.route,
        Some(&packet.managed.proxy),
        Some(&packet.key),
        packet.sniffed_domain.as_deref().unwrap_or_default(),
        packet.managed.dscp,
        true,
        UDP_ROUTE_REASON_QUEUED,
    );
    let outcome = dispatch_proxy_packet(
        packet.key,
        packet.managed,
        context,
        cleanup_tx,
        sessions,
        next_actor_id,
    )
    .await;
    route_event["task_queued"] = json!(outcome.queued());
    route_event["reason"] = json!(outcome.reason());
    append_event(&context.event_file, &context.event_lock, route_event);
}

async fn handle_direct_shard_packet(
    packet: ResidentUdpDirectShardPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    next_actor_id: &mut u64,
) {
    let mut route_event = udp_direct_route_chosen_event(
        packet.managed.packet.peer,
        packet.managed.original_dst,
        &packet.route,
        &packet.key,
        packet.sniffed_domain.as_deref().unwrap_or_default(),
        packet.managed.dscp,
        true,
        UDP_ROUTE_REASON_QUEUED,
    );
    let outcome = dispatch_direct_packet(
        packet.key,
        packet.managed,
        context,
        cleanup_tx,
        sessions,
        next_actor_id,
    )
    .await;
    route_event["task_queued"] = json!(outcome.queued());
    route_event["reason"] = json!(outcome.reason());
    append_event(&context.event_file, &context.event_lock, route_event);
}

async fn dispatch_proxy_packet(
    key: UdpSessionKey,
    mut managed: ManagedUdpPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    next_actor_id: &mut u64,
) -> UdpSessionDispatchOutcome {
    for attempt in 0..2 {
        let existed = sessions.contains_key(&key);
        if !existed && !create_proxy_session(&key, context, cleanup_tx, sessions, next_actor_id) {
            return UdpSessionDispatchOutcome::AdmissionRejected;
        }
        let result = sessions
            .get(&key)
            .expect("proxy UDP session exists after creation")
            .session
            .sender
            .try_send(managed);
        match classify_session_send(result) {
            UdpSessionSend::Queued => {
                if existed {
                    context.metrics.udp_session_reused();
                }
                return UdpSessionDispatchOutcome::Queued;
            }
            UdpSessionSend::Full(_returned) => {
                context.metrics.udp_session_queue_full();
                return UdpSessionDispatchOutcome::QueueFull;
            }
            UdpSessionSend::Closed(returned) => {
                managed = returned;
                retire_proxy_session(&key, sessions, context).await;
                if attempt == 0 {
                    context.metrics.udp_session_stale_recreated();
                }
            }
        }
    }
    UdpSessionDispatchOutcome::ActorUnavailable
}

async fn dispatch_direct_packet(
    key: UdpDirectSessionKey,
    mut managed: ManagedDirectUdpPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    next_actor_id: &mut u64,
) -> UdpSessionDispatchOutcome {
    for attempt in 0..2 {
        let existed = sessions.contains_key(&key);
        if !existed && !create_direct_session(&key, context, cleanup_tx, sessions, next_actor_id) {
            return UdpSessionDispatchOutcome::AdmissionRejected;
        }
        let result = sessions
            .get(&key)
            .expect("direct UDP session exists after creation")
            .session
            .sender
            .try_send(managed);
        match classify_session_send(result) {
            UdpSessionSend::Queued => {
                if existed {
                    context.metrics.udp_session_reused();
                }
                return UdpSessionDispatchOutcome::Queued;
            }
            UdpSessionSend::Full(_returned) => {
                context.metrics.udp_session_queue_full();
                return UdpSessionDispatchOutcome::QueueFull;
            }
            UdpSessionSend::Closed(returned) => {
                managed = returned;
                retire_direct_session(&key, sessions, context).await;
                if attempt == 0 {
                    context.metrics.udp_session_stale_recreated();
                }
            }
        }
    }
    UdpSessionDispatchOutcome::ActorUnavailable
}

fn create_proxy_session(
    key: &UdpSessionKey,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    next_actor_id: &mut u64,
) -> bool {
    let Ok(admission) = Arc::clone(&context.admission).try_acquire_owned() else {
        context.metrics.udp_session_admission_rejected();
        return false;
    };
    let (sender, receiver) = mpsc::channel(context.session_queue_depth);
    let actor_id = allocate_actor_id(next_actor_id);
    let actor_context = UdpSessionActorContext {
        dns: Arc::clone(&context.dns),
        proxy_groups: Arc::clone(&context.proxy_groups),
        event_file: context.event_file.clone(),
        event_lock: Arc::clone(&context.event_lock),
        metrics: Arc::clone(&context.metrics),
        udp_reply: context.udp_reply.clone(),
        active_sessions: Arc::clone(&context.active_sessions),
        hysteria2_owner_registry: context.hysteria2_owner_registry.clone(),
        tuic_owner_registry: context.tuic_owner_registry.clone(),
        juicity_owner_registry: context.juicity_owner_registry.clone(),
    };
    let handle = spawn_udp_session_actor(
        key.clone(),
        actor_id,
        actor_context,
        receiver,
        cleanup_tx.clone(),
    );
    sessions.insert(
        key.clone(),
        ResidentUdpProxyShardEntry {
            actor_id,
            session: UdpSessionEntry { sender, handle },
            _admission: admission,
        },
    );
    context.metrics.udp_session_created();
    true
}

fn create_direct_session(
    key: &UdpDirectSessionKey,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    next_actor_id: &mut u64,
) -> bool {
    let Ok(admission) = Arc::clone(&context.admission).try_acquire_owned() else {
        context.metrics.udp_session_admission_rejected();
        return false;
    };
    let (sender, receiver) = mpsc::channel(context.session_queue_depth);
    let actor_id = allocate_actor_id(next_actor_id);
    let actor_context = UdpDirectSessionActorContext {
        event_file: context.event_file.clone(),
        event_lock: Arc::clone(&context.event_lock),
        metrics: Arc::clone(&context.metrics),
        udp_reply: context.udp_reply.clone(),
        active_sessions: Arc::clone(&context.active_sessions),
        response_buffer_idle_timeout: context.direct_response_buffer_idle_timeout,
    };
    let handle = spawn_udp_direct_session_actor(
        key.clone(),
        actor_id,
        actor_context,
        receiver,
        cleanup_tx.clone(),
    );
    sessions.insert(
        key.clone(),
        ResidentUdpDirectShardEntry {
            actor_id,
            session: UdpDirectSessionEntry { sender, handle },
            _admission: admission,
        },
    );
    context.metrics.udp_session_created();
    true
}

fn allocate_actor_id(next_actor_id: &mut u64) -> u64 {
    *next_actor_id = next_actor_id.wrapping_add(1).max(1);
    *next_actor_id
}

fn cleanup_matches_actor(current_actor_id: u64, cleanup_actor_id: u64) -> bool {
    current_actor_id == cleanup_actor_id
}

async fn retire_proxy_session_if_current(
    cleanup: UdpSessionCleanup<UdpSessionKey>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    context: &ResidentUdpSessionShardContext,
) {
    if sessions
        .get(&cleanup.key)
        .is_some_and(|entry| cleanup_matches_actor(entry.actor_id, cleanup.actor_id))
    {
        retire_proxy_session(&cleanup.key, sessions, context).await;
    }
}

async fn retire_direct_session_if_current(
    cleanup: UdpSessionCleanup<UdpDirectSessionKey>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    context: &ResidentUdpSessionShardContext,
) {
    if sessions
        .get(&cleanup.key)
        .is_some_and(|entry| cleanup_matches_actor(entry.actor_id, cleanup.actor_id))
    {
        retire_direct_session(&cleanup.key, sessions, context).await;
    }
}

async fn retire_proxy_session(
    key: &UdpSessionKey,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    context: &ResidentUdpSessionShardContext,
) {
    if let Some(entry) = sessions.remove(key)
        && entry.session.handle.await.is_err()
    {
        context.metrics.udp_session_actor_panicked();
    }
}

async fn retire_direct_session(
    key: &UdpDirectSessionKey,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    context: &ResidentUdpSessionShardContext,
) {
    if let Some(entry) = sessions.remove(key)
        && entry.session.handle.await.is_err()
    {
        context.metrics.udp_session_actor_panicked();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_and_closed_session_channels_remain_distinct() {
        let (full_sender, mut full_receiver) = mpsc::channel(1);
        full_sender.try_send(1_u8).unwrap();
        assert!(matches!(
            classify_session_send(full_sender.try_send(2_u8)),
            UdpSessionSend::Full(2)
        ));
        assert_eq!(full_receiver.recv().await, Some(1));

        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        assert!(matches!(
            classify_session_send(closed_sender.try_send(3_u8)),
            UdpSessionSend::Closed(3)
        ));
    }

    #[test]
    fn stale_cleanup_cannot_remove_a_recreated_actor() {
        assert!(cleanup_matches_actor(12, 12));
        assert!(!cleanup_matches_actor(13, 12));
    }
}
