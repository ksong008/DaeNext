pub(super) fn resident_udp_loop(
    socket: std::net::UdpSocket,
    proxy_group: Arc<ResidentProxyGroupPlan>,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    worker_limit: usize,
    worker_stack_bytes: usize,
) {
    if let Err(err) = socket.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "udp_socket_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "udp_worker_started",
            "proxy_group": proxy_group.group_name,
            "group_policy": proxy_group.group_policy_name(),
            "candidate_count": proxy_group.candidate_count(),
            "admitted_candidate_count": proxy_group.admitted_candidate_count(),
            "worker_limit": worker_limit,
            "worker_stack_bytes": worker_stack_bytes,
            "packetSessionManager": {
                "schemaVersion": 1,
                "manager": "bounded-resident-packet-session",
                "workerLimit": worker_limit,
                "keyFields": ["graphId", "outbound", "peer", "originalDestination", "packetSemantics"],
            },
        }),
    );
    let active_workers = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        let packet = match recv_udp_with_original_dst(&socket, 2048) {
            Ok(packet) => packet,
            Err(err)
                if err.contains("WouldBlock")
                    || err.contains("Resource temporarily unavailable") =>
            {
                continue;
            }
            Err(err) => {
                if !stop.load(Ordering::Relaxed) {
                    append_event(
                        &event_file,
                        &event_lock,
                        json!({"event": "udp_receive_failed", "error": err}),
                    );
                }
                continue;
            }
        };
        let Some(original_dst) = packet.original_dst else {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": packet.peer.to_string()}),
            );
            continue;
        };
        let active = active_workers.load(Ordering::Relaxed);
        if active >= worker_limit {
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_packet_dropped",
                    "reason": "resident UDP packet worker limit reached",
                    "peer": packet.peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "active_workers": active,
                    "worker_limit": worker_limit,
                }),
            );
            continue;
        }

        active_workers.fetch_add(1, Ordering::Relaxed);
        let active_workers_for_task = Arc::clone(&active_workers);
        let proxy_group = Arc::clone(&proxy_group);
        let dns = Arc::clone(&dns);
        let task_event_file = event_file.clone();
        let task_event_lock = Arc::clone(&event_lock);
        let metrics = Arc::clone(&metrics);
        let spawn_peer = packet.peer.to_string();
        let spawn_original_dst = original_dst.to_string();
        let spawn_result = thread::Builder::new()
            .name("dae-resident-udp-packet".to_owned())
            .stack_size(worker_stack_bytes)
            .spawn(move || {
                let packet_metrics = Arc::clone(&metrics);
                let _guard = UdpPacketWorkerGuard::new(active_workers_for_task, metrics);
                handle_udp_packet(
                    proxy_group,
                    dns,
                    packet,
                    original_dst,
                    task_event_file,
                    task_event_lock,
                    packet_metrics,
                );
            });
        if let Err(err) = spawn_result {
            active_workers.fetch_sub(1, Ordering::Relaxed);
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_worker_spawn_failed",
                    "peer": spawn_peer,
                    "original_dst": spawn_original_dst,
                    "error": err.to_string(),
                }),
            );
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({"event": "udp_worker_stopped"}),
    );
}

struct UdpPacketWorkerGuard {
    active_workers: Arc<AtomicUsize>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl UdpPacketWorkerGuard {
    fn new(active_workers: Arc<AtomicUsize>, metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        metrics.udp_opened();
        Self {
            active_workers,
            metrics,
        }
    }
}

impl Drop for UdpPacketWorkerGuard {
    fn drop(&mut self) {
        self.metrics.udp_closed();
        self.active_workers.fetch_sub(1, Ordering::Relaxed);
    }
}
