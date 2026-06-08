fn resident_tcp_flow_stack_bytes() -> usize {
    bounded_env_usize(
        RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
        RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
    )
}

fn resident_udp_packet_workers() -> usize {
    bounded_env_usize(
        RESIDENT_UDP_PACKET_WORKERS_ENV,
        RESIDENT_UDP_PACKET_WORKERS_DEFAULT,
        RESIDENT_UDP_PACKET_WORKERS_MIN,
        RESIDENT_UDP_PACKET_WORKERS_MAX,
    )
}

fn resident_udp_packet_stack_bytes() -> usize {
    bounded_env_usize(
        RESIDENT_UDP_PACKET_STACK_BYTES_ENV,
        RESIDENT_UDP_PACKET_STACK_BYTES_DEFAULT,
        RESIDENT_UDP_PACKET_STACK_BYTES_MIN,
        RESIDENT_UDP_PACKET_STACK_BYTES_MAX,
    )
}

fn bounded_env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}
