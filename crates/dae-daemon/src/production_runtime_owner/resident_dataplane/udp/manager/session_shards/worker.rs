use tokio::sync::OwnedSemaphorePermit;

use super::*;

struct ResidentUdpProxyShardEntry {
    session: UdpSessionEntry,
    _admission: OwnedSemaphorePermit,
}

struct ResidentUdpDirectShardEntry {
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
        mpsc::channel::<UdpSessionKey>(context.cleanup_queue_depth);
    let (direct_cleanup_tx, mut direct_cleanup_rx) =
        mpsc::channel::<UdpDirectSessionKey>(context.cleanup_queue_depth);

    let shutdown_deadline = loop {
        tokio::select! {
            biased;
            deadline = &mut stop => {
                receiver.close();
                break deadline.unwrap_or_else(|_| time::Instant::now());
            }
            Some(key) = proxy_cleanup_rx.recv() => {
                if let Some(entry) = proxy_sessions.remove(&key) {
                    let _ = entry.session.handle.await;
                }
            }
            Some(key) = direct_cleanup_rx.recv() => {
                if let Some(entry) = direct_sessions.remove(&key) {
                    let _ = entry.session.handle.await;
                }
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
                    ),
                    ResidentUdpShardPacket::Direct(packet) => handle_direct_shard_packet(
                        packet,
                        &context,
                        &direct_cleanup_tx,
                        &mut direct_sessions,
                    ),
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
    json!({
        "shardIndex": shard_index,
        "status": if panicked == 0 && timed_out == 0 { "pass" } else { "fail" },
        "joined": joined,
        "panicked": panicked,
        "timedOut": timed_out,
    })
}

fn handle_proxy_shard_packet(
    packet: ResidentUdpProxyShardPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionKey>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
) {
    if !sessions.contains_key(&packet.key) {
        let Ok(admission) = Arc::clone(&context.admission).try_acquire_owned() else {
            context.metrics.udp_session_admission_rejected();
            record_proxy_shard_packet_result(&packet, context, false, UDP_ROUTE_REASON_LIMIT);
            return;
        };
        let (sender, receiver) = mpsc::channel(context.session_queue_depth);
        let actor_context = UdpSessionActorContext {
            dns: Arc::clone(&context.dns),
            proxy_groups: Arc::clone(&context.proxy_groups),
            event_file: context.event_file.clone(),
            event_lock: Arc::clone(&context.event_lock),
            metrics: Arc::clone(&context.metrics),
            udp_reply: context.udp_reply.clone(),
            active_sessions: Arc::clone(&context.active_sessions),
        };
        let handle = spawn_udp_session_actor(
            packet.key.clone(),
            actor_context,
            receiver,
            cleanup_tx.clone(),
        );
        sessions.insert(
            packet.key.clone(),
            ResidentUdpProxyShardEntry {
                session: UdpSessionEntry { sender, handle },
                _admission: admission,
            },
        );
        context.metrics.udp_session_created();
    } else {
        context.metrics.udp_session_reused();
    }
    let Some(entry) = sessions.get(&packet.key) else {
        return;
    };
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
    let queue_full = entry.session.sender.try_send(packet.managed).is_err();
    if queue_full {
        context.metrics.udp_session_queue_full();
        route_event["task_queued"] = json!(false);
        route_event["reason"] = json!(UDP_ROUTE_REASON_QUEUE_FULL);
    }
    append_event(&context.event_file, &context.event_lock, route_event);
}

fn handle_direct_shard_packet(
    packet: ResidentUdpDirectShardPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpDirectSessionKey>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
) {
    if !sessions.contains_key(&packet.key) {
        let Ok(admission) = Arc::clone(&context.admission).try_acquire_owned() else {
            context.metrics.udp_session_admission_rejected();
            record_direct_shard_packet_result(&packet, context, false, UDP_ROUTE_REASON_LIMIT);
            return;
        };
        let (sender, receiver) = mpsc::channel(context.session_queue_depth);
        let actor_context = UdpDirectSessionActorContext {
            event_file: context.event_file.clone(),
            event_lock: Arc::clone(&context.event_lock),
            metrics: Arc::clone(&context.metrics),
            udp_reply: context.udp_reply.clone(),
            active_sessions: Arc::clone(&context.active_sessions),
        };
        let handle = spawn_udp_direct_session_actor(
            packet.key.clone(),
            actor_context,
            receiver,
            cleanup_tx.clone(),
        );
        sessions.insert(
            packet.key.clone(),
            ResidentUdpDirectShardEntry {
                session: UdpDirectSessionEntry { sender, handle },
                _admission: admission,
            },
        );
        context.metrics.udp_session_created();
    } else {
        context.metrics.udp_session_reused();
    }
    let Some(entry) = sessions.get(&packet.key) else {
        return;
    };
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
    let queue_full = entry.session.sender.try_send(packet.managed).is_err();
    if queue_full {
        context.metrics.udp_session_queue_full();
        route_event["task_queued"] = json!(false);
        route_event["reason"] = json!(UDP_ROUTE_REASON_QUEUE_FULL);
    }
    append_event(&context.event_file, &context.event_lock, route_event);
}

fn record_proxy_shard_packet_result(
    packet: &ResidentUdpProxyShardPacket,
    context: &ResidentUdpSessionShardContext,
    queued: bool,
    reason: &str,
) {
    append_event(
        &context.event_file,
        &context.event_lock,
        udp_route_chosen_event(
            packet.managed.packet.peer,
            packet.managed.original_dst,
            &packet.route,
            Some(&packet.managed.proxy),
            Some(&packet.key),
            packet.sniffed_domain.as_deref().unwrap_or_default(),
            packet.managed.dscp,
            queued,
            reason,
        ),
    );
}

fn record_direct_shard_packet_result(
    packet: &ResidentUdpDirectShardPacket,
    context: &ResidentUdpSessionShardContext,
    queued: bool,
    reason: &str,
) {
    append_event(
        &context.event_file,
        &context.event_lock,
        udp_direct_route_chosen_event(
            packet.managed.packet.peer,
            packet.managed.original_dst,
            &packet.route,
            &packet.key,
            packet.sniffed_domain.as_deref().unwrap_or_default(),
            packet.managed.dscp,
            queued,
            reason,
        ),
    );
}
