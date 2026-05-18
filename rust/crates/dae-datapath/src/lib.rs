pub mod dial;
pub mod packet_sniffer;
pub mod route;
pub mod tcp_direct;
pub mod tcp_route_dial;
pub mod udp_direct;
pub mod udp_endpoint;
pub mod udp_task;

#[cfg(test)]
mod tests;

pub use dial::{magic_network, magic_network_bytes};
pub use packet_sniffer::{PACKET_SNIFFER_POOL_MAX_ENTRIES, PACKET_SNIFFER_TTL_MS};
pub use route::{RouteLoopResult, RouteRule, route_loop};
pub use tcp_direct::{
    TcpDirectConnection, TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, bind_loopback_tcp_listener_on_port, magic_tcp_connect,
    mptcp_socket_supported,
};
pub use tcp_route_dial::{
    ChooseDialTargetDecision, OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT,
    OUTBOUND_USER_DEFINED_MAX, OUTBOUND_USER_DEFINED_MIN, RouteDialTcpPlan, RouteDialTcpPlanInput,
    TcpDialMode, choose_dial_target, outbound_is_reserved, route_dial_tcp_plan,
};
pub use udp_direct::{UdpDirectPacketConn, UdpDirectSocketOptions, UdpDirectSocketReport};
pub use udp_endpoint::{
    ANYFROM_TIMEOUT_MS, DEFAULT_NAT_TIMEOUT_MS, DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
    DNS_NAT_TIMEOUT_MS, MAX_RETRY, normalize_udp_endpoint_pool_max_entries,
    udp_endpoint_pool_trim_target,
};
pub use udp_task::{UDP_TASK_POOL_MAX_QUEUES, UDP_TASK_QUEUE_LENGTH, UdpTaskPoolModel};
