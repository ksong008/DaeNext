use super::*;
pub(crate) fn live_handoff_json(handoff: &LiveLoadedTproxyListenSocketMap) -> Value {
    json!({
        "status": "pass",
        "map": {
            "id": handoff.map.id,
            "name": handoff.map.name,
            "map_type": handoff.map.map_type,
            "key_size": handoff.map.key_size,
            "value_size": handoff.map.value_size,
            "max_entries": handoff.map.max_entries,
            "flags": handoff.map.flags,
        },
        "new_map_ids": handoff.new_map_ids,
        "keys_updated": handoff.keys_updated,
        "tcp_listener_fd_observed": handoff.tcp_listener_fd >= 0,
        "udp_socket_fd_observed": handoff.udp_socket_fd >= 0,
        "tcp_options": socket_options_json(&handoff.tcp_options),
        "udp_options": socket_options_json(&handoff.udp_options),
    })
}

pub(crate) fn socket_options_json(options: &TproxySocketOptions) -> Value {
    json!({
        "ip_transparent": options.ip_transparent,
        "ipv6_transparent": options.ipv6_transparent,
        "so_reuseaddr": options.so_reuseaddr,
        "ip_recvorigdstaddr": options.ip_recvorigdstaddr,
        "ipv6_recvorigdstaddr": options.ipv6_recvorigdstaddr,
        "original_dst_capture_ready": options.original_dst_capture_ready,
    })
}

pub(crate) fn socket_options_verified(
    tcp: &TproxySocketOptions,
    udp: &TproxySocketOptions,
) -> bool {
    (tcp.ip_transparent || tcp.ipv6_transparent)
        && tcp.so_reuseaddr
        && tcp.original_dst_capture_ready
        && (udp.ip_transparent || udp.ipv6_transparent)
        && udp.so_reuseaddr
        && udp.original_dst_capture_ready
}
