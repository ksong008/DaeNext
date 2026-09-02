use super::*;

struct ResidentUdpProxyShardEntry {
    actor_id: u64,
    session: UdpSessionEntry,
    _admission: ResidentUdpSessionPermit,
}

struct ResidentUdpDirectShardEntry {
    actor_id: u64,
    session: UdpDirectSessionEntry,
    _admission: ResidentUdpSessionPermit,
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
    let mut retired_sessions = UdpSessionReaper::new(context.cleanup_queue_depth);
    let mut retired_joined = 0_usize;
    let mut next_actor_id = 0_u64;
    let mut reconcile_interval = time::interval(Duration::from_secs(1));
    reconcile_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    let shutdown_deadline = loop {
        tokio::select! {
            biased;
            deadline = &mut stop => {
                receiver.close();
                break deadline.unwrap_or_else(|_| time::Instant::now());
            }
            completion = retired_sessions.join_next(), if !retired_sessions.is_empty() => {
                if completion == Some(true) {
                    context.metrics.udp_session_actor_panicked();
                } else if completion == Some(false) {
                    retired_joined = retired_joined.saturating_add(1);
                }
            }
            Some(cleanup) = proxy_cleanup_rx.recv(), if retired_sessions.has_capacity() => {
                retire_proxy_session_if_current(
                    cleanup,
                    &mut proxy_sessions,
                    &mut retired_sessions,
                );
            }
            Some(cleanup) = direct_cleanup_rx.recv(), if retired_sessions.has_capacity() => {
                retire_direct_session_if_current(
                    cleanup,
                    &mut direct_sessions,
                    &mut retired_sessions,
                );
            }
            _ = reconcile_interval.tick() => {
                reconcile_finished_proxy_sessions(&mut proxy_sessions, &mut retired_sessions);
                reconcile_finished_direct_sessions(&mut direct_sessions, &mut retired_sessions);
            }
            packet = receiver.recv(), if retired_sessions.has_capacity() => {
                let Some(packet) = packet else {
                    break time::Instant::now();
                };
                match packet {
                    ResidentUdpShardPacket::Proxy(packet) => handle_proxy_shard_packet(
                        packet,
                        &context,
                        &proxy_cleanup_tx,
                        &mut proxy_sessions,
                        &mut retired_sessions,
                        &mut next_actor_id,
                    ).await,
                    ResidentUdpShardPacket::Direct(packet) => handle_direct_shard_packet(
                        packet,
                        &context,
                        &direct_cleanup_tx,
                        &mut direct_sessions,
                        &mut retired_sessions,
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

    for (_, entry) in proxy_sessions.drain() {
        drop(entry.session.sender);
        retired_sessions.retire_for_shutdown(entry.session.handle);
    }
    for (_, entry) in direct_sessions.drain() {
        drop(entry.session.sender);
        retired_sessions.retire_for_shutdown(entry.session.handle);
    }
    let (joined, panicked, timed_out) = retired_sessions
        .join_until_deadline(shutdown_deadline)
        .await;
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
        "retiredJoinedDuringRuntime": retired_joined,
        "panicked": panicked,
        "timedOut": timed_out,
    })
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

async fn handle_proxy_shard_packet(
    packet: ResidentUdpProxyShardPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
    next_actor_id: &mut u64,
) {
    dispatch_proxy_packet(
        packet.key,
        packet.managed,
        packet.route,
        packet.sniffed_domain,
        context,
        cleanup_tx,
        sessions,
        retired_sessions,
        next_actor_id,
    )
    .await;
}

async fn handle_direct_shard_packet(
    packet: ResidentUdpDirectShardPacket,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
    next_actor_id: &mut u64,
) {
    let _outcome = dispatch_direct_packet(
        packet.key,
        packet.managed,
        packet.route,
        packet.sniffed_domain,
        context,
        cleanup_tx,
        sessions,
        retired_sessions,
        next_actor_id,
    )
    .await;
}

async fn dispatch_proxy_packet(
    key: UdpSessionKey,
    mut managed: ManagedUdpPacket,
    route: ResidentUdpRouteSelection,
    sniffed_domain: SharedUdpSniffedDomain,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
    next_actor_id: &mut u64,
) {
    let peer = managed.packet.peer;
    let original_dst = managed.original_dst;
    let dscp = managed.dscp;
    let mut route_event = None;
    for attempt in 0..2 {
        let lookup_key = key.clone();
        let (existed, result) = match sessions.entry(lookup_key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let result = entry.get().session.sender.try_send(managed);
                (true, result)
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let Some(session) = create_proxy_session(&key, context, cleanup_tx, next_actor_id)
                else {
                    append_proxy_route_event(
                        context,
                        route_event.take().or_else(|| {
                            build_proxy_route_event(
                                peer,
                                original_dst,
                                &route,
                                &managed.proxy,
                                &key,
                                sniffed_domain.as_deref().unwrap_or_default(),
                                dscp,
                            )
                        }),
                        false,
                        UDP_ROUTE_REASON_LIMIT,
                    );
                    return;
                };
                if route_event.is_none() {
                    route_event = build_proxy_route_event(
                        peer,
                        original_dst,
                        &route,
                        &managed.proxy,
                        &key,
                        sniffed_domain.as_deref().unwrap_or_default(),
                        dscp,
                    );
                }
                let result = entry.insert(session).session.sender.try_send(managed);
                (false, result)
            }
        };
        match classify_session_send(result) {
            UdpSessionSend::Queued => {
                if existed {
                    context.metrics.udp_session_reused();
                }
                append_proxy_route_event(
                    context,
                    route_event.take(),
                    true,
                    UDP_ROUTE_REASON_QUEUED,
                );
                return;
            }
            UdpSessionSend::Full(returned) => {
                context.metrics.udp_session_queue_full();
                append_proxy_route_event(
                    context,
                    route_event.take().or_else(|| {
                        build_proxy_route_event(
                            peer,
                            original_dst,
                            &route,
                            &returned.proxy,
                            &key,
                            sniffed_domain.as_deref().unwrap_or_default(),
                            dscp,
                        )
                    }),
                    false,
                    UDP_ROUTE_REASON_QUEUE_FULL,
                );
                return;
            }
            UdpSessionSend::Closed(returned) => {
                managed = returned;
                retire_proxy_session(&key, sessions, retired_sessions);
                if attempt == 0 {
                    context.metrics.udp_session_stale_recreated();
                }
            }
        }
    }
    append_proxy_route_event(
        context,
        route_event.or_else(|| {
            build_proxy_route_event(
                peer,
                original_dst,
                &route,
                &managed.proxy,
                &key,
                sniffed_domain.as_deref().unwrap_or_default(),
                dscp,
            )
        }),
        false,
        UDP_ROUTE_REASON_SESSION_UNAVAILABLE,
    );
}

async fn dispatch_direct_packet(
    key: UdpDirectSessionKey,
    mut managed: ManagedDirectUdpPacket,
    route: ResidentUdpRouteSelection,
    sniffed_domain: SharedUdpSniffedDomain,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
    next_actor_id: &mut u64,
) {
    let peer = managed.packet.peer;
    let original_dst = managed.original_dst;
    let dscp = managed.dscp;
    let mut route_event = None;
    for attempt in 0..2 {
        let lookup_key = key.clone();
        let (existed, result) = match sessions.entry(lookup_key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let result = entry.get().session.sender.try_send(managed);
                (true, result)
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let Some(session) = create_direct_session(&key, context, cleanup_tx, next_actor_id)
                else {
                    append_direct_route_event(
                        context,
                        route_event.take().or_else(|| {
                            build_direct_route_event(
                                peer,
                                original_dst,
                                &route,
                                &key,
                                sniffed_domain.as_deref().unwrap_or_default(),
                                dscp,
                            )
                        }),
                        false,
                        UDP_ROUTE_REASON_LIMIT,
                    );
                    return;
                };
                if route_event.is_none() {
                    route_event = build_direct_route_event(
                        peer,
                        original_dst,
                        &route,
                        &key,
                        sniffed_domain.as_deref().unwrap_or_default(),
                        dscp,
                    );
                }
                let result = entry.insert(session).session.sender.try_send(managed);
                (false, result)
            }
        };
        match classify_session_send(result) {
            UdpSessionSend::Queued => {
                if existed {
                    context.metrics.udp_session_reused();
                }
                append_direct_route_event(
                    context,
                    route_event.take(),
                    true,
                    UDP_ROUTE_REASON_QUEUED,
                );
                return;
            }
            UdpSessionSend::Full(_returned) => {
                context.metrics.udp_session_queue_full();
                append_direct_route_event(
                    context,
                    route_event.take().or_else(|| {
                        build_direct_route_event(
                            peer,
                            original_dst,
                            &route,
                            &key,
                            sniffed_domain.as_deref().unwrap_or_default(),
                            dscp,
                        )
                    }),
                    false,
                    UDP_ROUTE_REASON_QUEUE_FULL,
                );
                return;
            }
            UdpSessionSend::Closed(returned) => {
                managed = returned;
                retire_direct_session(&key, sessions, retired_sessions);
                if attempt == 0 {
                    context.metrics.udp_session_stale_recreated();
                }
            }
        }
    }
    append_direct_route_event(
        context,
        route_event.or_else(|| {
            build_direct_route_event(
                peer,
                original_dst,
                &route,
                &key,
                sniffed_domain.as_deref().unwrap_or_default(),
                dscp,
            )
        }),
        false,
        UDP_ROUTE_REASON_SESSION_UNAVAILABLE,
    );
}

fn build_proxy_route_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    proxy: &ResidentProxyPlan,
    key: &UdpSessionKey,
    sniffed_domain: &str,
    dscp: u8,
) -> Option<(ResidentEventAdmission, Value)> {
    admit_event(ResidentEventMetadata::new(
        ResidentEventKind::UdpRouteChosen,
    ))
    .map(|admission| {
        (
            admission,
            udp_route_chosen_event(
                peer,
                original_dst,
                route,
                Some(proxy),
                Some(key),
                sniffed_domain,
                dscp,
                true,
                UDP_ROUTE_REASON_QUEUED,
            ),
        )
    })
}

fn append_proxy_route_event(
    context: &ResidentUdpSessionShardContext,
    route_event: Option<(ResidentEventAdmission, Value)>,
    task_queued: bool,
    reason: &str,
) {
    let Some((admission, mut event)) = route_event else {
        return;
    };
    event["task_queued"] = json!(task_queued);
    event["reason"] = json!(reason);
    append_admitted_event(&context.event_file, &context.event_lock, admission, event);
}

fn build_direct_route_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    key: &UdpDirectSessionKey,
    sniffed_domain: &str,
    dscp: u8,
) -> Option<(ResidentEventAdmission, Value)> {
    admit_event(ResidentEventMetadata::new(
        ResidentEventKind::UdpRouteChosen,
    ))
    .map(|admission| {
        (
            admission,
            udp_direct_route_chosen_event(
                peer,
                original_dst,
                route,
                key,
                sniffed_domain,
                dscp,
                true,
                UDP_ROUTE_REASON_QUEUED,
            ),
        )
    })
}

fn append_direct_route_event(
    context: &ResidentUdpSessionShardContext,
    route_event: Option<(ResidentEventAdmission, Value)>,
    task_queued: bool,
    reason: &str,
) {
    let Some((admission, mut event)) = route_event else {
        return;
    };
    event["task_queued"] = json!(task_queued);
    event["reason"] = json!(reason);
    append_admitted_event(&context.event_file, &context.event_lock, admission, event);
}

fn create_proxy_session(
    key: &UdpSessionKey,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpSessionKey>>,
    next_actor_id: &mut u64,
) -> Option<ResidentUdpProxyShardEntry> {
    let Ok(admission) = try_reserve_session(&context.admission) else {
        context.metrics.udp_session_admission_rejected();
        return None;
    };
    let (sender, receiver) = mpsc::channel(context.session_queue_depth);
    let actor_id = allocate_actor_id(next_actor_id);
    let actor_context = Arc::clone(&context.shared);
    let handle = spawn_udp_session_actor(
        key.clone(),
        actor_id,
        actor_context,
        receiver,
        cleanup_tx.clone(),
    );
    context.metrics.udp_session_created();
    Some(ResidentUdpProxyShardEntry {
        actor_id,
        session: UdpSessionEntry { sender, handle },
        _admission: admission,
    })
}

fn create_direct_session(
    key: &UdpDirectSessionKey,
    context: &ResidentUdpSessionShardContext,
    cleanup_tx: &mpsc::Sender<UdpSessionCleanup<UdpDirectSessionKey>>,
    next_actor_id: &mut u64,
) -> Option<ResidentUdpDirectShardEntry> {
    let Ok(admission) = try_reserve_session(&context.admission) else {
        context.metrics.udp_session_admission_rejected();
        return None;
    };
    let (sender, receiver) = mpsc::channel(context.session_queue_depth);
    let actor_id = allocate_actor_id(next_actor_id);
    let actor_context = Arc::clone(&context.shared);
    let handle = spawn_udp_direct_session_actor(
        key.clone(),
        actor_id,
        actor_context,
        receiver,
        cleanup_tx.clone(),
    );
    context.metrics.udp_session_created();
    Some(ResidentUdpDirectShardEntry {
        actor_id,
        session: UdpDirectSessionEntry { sender, handle },
        _admission: admission,
    })
}

fn try_reserve_session(
    admission: &Arc<ResidentUdpSessionAdmission>,
) -> Result<ResidentUdpSessionPermit, ()> {
    admission.try_acquire().map_err(|_| ())
}

fn allocate_actor_id(next_actor_id: &mut u64) -> u64 {
    *next_actor_id = next_actor_id.wrapping_add(1).max(1);
    *next_actor_id
}

fn cleanup_matches_actor(current_actor_id: u64, cleanup_actor_id: u64) -> bool {
    current_actor_id == cleanup_actor_id
}

fn retire_proxy_session_if_current(
    cleanup: UdpSessionCleanup<UdpSessionKey>,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
) {
    if sessions
        .get(&cleanup.key)
        .is_some_and(|entry| cleanup_matches_actor(entry.actor_id, cleanup.actor_id))
    {
        retire_proxy_session(&cleanup.key, sessions, retired_sessions);
    }
}

fn retire_direct_session_if_current(
    cleanup: UdpSessionCleanup<UdpDirectSessionKey>,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
) {
    if sessions
        .get(&cleanup.key)
        .is_some_and(|entry| cleanup_matches_actor(entry.actor_id, cleanup.actor_id))
    {
        retire_direct_session(&cleanup.key, sessions, retired_sessions);
    }
}

fn retire_proxy_session(
    key: &UdpSessionKey,
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
) {
    if let Some(entry) = sessions.remove(key) {
        retired_sessions
            .retire(entry.session.handle)
            .expect("UDP session reaper capacity is reserved before packet dispatch");
    }
}

fn retire_direct_session(
    key: &UdpDirectSessionKey,
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
) {
    if let Some(entry) = sessions.remove(key) {
        retired_sessions
            .retire(entry.session.handle)
            .expect("UDP session reaper capacity is reserved before packet dispatch");
    }
}

fn reconcile_finished_proxy_sessions(
    sessions: &mut HashMap<UdpSessionKey, ResidentUdpProxyShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
) {
    let finished: Vec<UdpSessionKey> = sessions
        .iter()
        .filter(|(_, entry)| entry.session.handle.is_finished())
        .map(|(key, _)| key.clone())
        .collect();
    for key in finished {
        if let Some(entry) = sessions.remove(&key)
            && let Err(handle) = retired_sessions.retire(entry.session.handle)
        {
            drop(handle);
        }
    }
}

fn reconcile_finished_direct_sessions(
    sessions: &mut HashMap<UdpDirectSessionKey, ResidentUdpDirectShardEntry>,
    retired_sessions: &mut UdpSessionReaper,
) {
    let finished: Vec<UdpDirectSessionKey> = sessions
        .iter()
        .filter(|(_, entry)| entry.session.handle.is_finished())
        .map(|(key, _)| key.clone())
        .collect();
    for key in finished {
        if let Some(entry) = sessions.remove(&key)
            && let Err(handle) = retired_sessions.retire(entry.session.handle)
        {
            drop(handle);
        }
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

    #[test]
    fn automatic_session_admission_has_no_fixed_count_rejection() {
        let admission = Arc::new(ResidentUdpSessionAdmission::new(None));
        let mut permits = Vec::new();
        for _ in 0..65_536 {
            permits.push(try_reserve_session(&admission).unwrap());
        }
        assert_eq!(admission.current(), 65_536);
    }

    #[test]
    fn configured_session_admission_releases_capacity_on_drop() {
        let admission = Arc::new(ResidentUdpSessionAdmission::new(Some(2)));
        let first = try_reserve_session(&admission).unwrap();
        let second = try_reserve_session(&admission).unwrap();
        assert!(try_reserve_session(&admission).is_err());
        drop(first);
        assert!(try_reserve_session(&admission).is_ok());
        drop(second);
    }
}
