use super::*;

pub(crate) fn resident_udp_loop(
    socket: std::net::UdpSocket,
    proxy_group: Arc<ResidentProxyGroupPlan>,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    session_limit: usize,
    session_queue_depth: usize,
) {
    run_resident_udp_session_manager(
        socket,
        proxy_group,
        dns,
        stop,
        event_file,
        event_lock,
        metrics,
        active_sessions,
        session_limit,
        session_queue_depth,
    );
}
