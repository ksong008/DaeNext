use super::*;
use dae_dns::DNS_DEFAULT_PORT;

pub fn resident_udp_proxy_handler_name(proxy: &ResidentProxyPlan) -> &'static str {
    proxy.execution_plan().udp.executor_label()
}

pub fn udp_probe_packet_session_value(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    handler: &str,
    packet_semantics: UdpPacketSemantics,
) -> serde_json::Value {
    packet_session_value(
        UdpPacketSessionIdentity::probe(proxy, original_dst, packet_semantics),
        Some(handler),
    )
}

pub fn udp_packet_semantics_for_destination(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
) -> UdpPacketSemantics {
    if original_dst.port() == DNS_DEFAULT_PORT {
        UdpPacketSemantics::Dns
    } else {
        udp_packet_semantics(proxy)
    }
}

pub(super) fn udp_packet_semantics(proxy: &ResidentProxyPlan) -> UdpPacketSemantics {
    proxy.execution_plan().udp.packet_semantics()
}
