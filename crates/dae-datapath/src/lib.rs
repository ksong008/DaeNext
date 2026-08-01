#![deny(unsafe_op_in_unsafe_fn)]

pub mod active;
pub mod active_handoff;
pub mod dial;
pub mod packet_sniffer;
pub mod route;
pub mod tcp_direct;
pub mod tcp_liveness;
pub mod tcp_route_dial;
pub mod udp_direct;
pub mod udp_endpoint;
pub mod udp_task;

#[cfg(test)]
mod tests;

pub use active::{
    ACTIVE_TCP_CLIENT_NETNS, ACTIVE_TCP_DEFAULT_CLIENT_IP, ACTIVE_TCP_DEFAULT_MPTCP,
    ACTIVE_TCP_DEFAULT_SO_MARK, ACTIVE_TCP_DEFAULT_TARGET_IP, ACTIVE_TCP_DEFAULT_TARGET_PORT,
    ACTIVE_TCP_LAN_CLIENT_IFACE, ACTIVE_TCP_LAN_FILTER_PREF, ACTIVE_TCP_LAN_GATEWAY_IP,
    ACTIVE_TCP_LAN_HOST_IFACE, ACTIVE_TCP_LAN_SECTION, ACTIVE_TCP_MATCH_TYPE_FALLBACK,
    ACTIVE_TCP_OUTBOUND_PROXY, ACTIVE_TCP_ROUTING_MAP_KERNEL_NAME, ACTIVE_TCP_ROUTING_MAP_KEY,
    ACTIVE_TCP_ROUTING_MAP_KEY_SIZE, ACTIVE_TCP_ROUTING_MAP_VALUE_SIZE,
    ACTIVE_UDP_DEFAULT_TARGET_IP, ACTIVE_UDP_DEFAULT_TARGET_PORT, ActiveTcpRoutingMapContract,
    ActiveTcpTopologyContract, ActiveUdpEndpointContract, active_tcp_routing_fallback_value,
    active_tcp_routing_map_contract, active_tcp_topology_contract, active_udp_endpoint_contract,
};
pub use active_handoff::{
    ActiveHandoffDecision, ActiveHandoffKey, ActiveHandoffState, ActiveL4, ActiveTcpHandoffInput,
    ActiveUdpHandoffInput,
};
pub use dial::{magic_network, magic_network_bytes, magic_network_len, write_magic_network_bytes};
pub use packet_sniffer::{PACKET_SNIFFER_POOL_MAX_ENTRIES, PACKET_SNIFFER_TTL_MS};
pub use route::{RouteLoopResult, RouteRule, route_loop};
pub use tcp_direct::{
    TcpDirectConnectAttempt, TcpDirectConnectState, TcpDirectConnection, TcpDirectDialOptions,
    TcpDirectDialReport, TcpLoopbackListenerReport, bind_loopback_tcp_listener,
    bind_loopback_tcp_listener_on_port, magic_tcp_connect, mptcp_socket_supported,
    tcp_direct_connect_finish, tcp_direct_connect_start,
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
