// UDP worker startup keeps socket, routing, session, shutdown, and metrics ownership explicit.
#![allow(clippy::too_many_arguments)]

use serde_json::Value;

use super::*;

pub(crate) fn resident_udp_loop(
    socket: std::net::UdpSocket,
    proxy_groups: SharedResidentProxyGroupMap,
    default_outbound: u8,
    routing_tuple_map_id: Option<u32>,
    routing_matcher: RoutingMatcher,
    dial_mode: TcpDialMode,
    so_mark_from_dae: u32,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    active_sessions: Arc<AtomicUsize>,
    runtime_config: ResidentUdpRuntimeConfig,
    health_resuscitation: ResidentHealthResuscitationHandle,
) -> Value {
    run_resident_udp_session_manager(
        socket,
        proxy_groups,
        default_outbound,
        routing_tuple_map_id,
        routing_matcher,
        dial_mode,
        so_mark_from_dae,
        dns,
        stop,
        event_file,
        event_lock,
        metrics,
        active_sessions,
        runtime_config,
        health_resuscitation,
    )
}
