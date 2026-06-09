use super::*;
pub(super) fn resident_tcp_flow_stack_bytes() -> usize {
    bounded_env_usize_with_legacy(
        RESIDENT_TCP_FLOW_STACK_BYTES_ENV,
        RESIDENT_TCP_FLOW_STACK_BYTES_LEGACY_ENV,
        RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
        RESIDENT_TCP_FLOW_STACK_BYTES_MIN,
        RESIDENT_TCP_FLOW_STACK_BYTES_MAX,
    )
}

pub(super) fn resident_udp_session_limit() -> usize {
    bounded_env_usize_with_legacy(
        RESIDENT_UDP_SESSION_LIMIT_ENV,
        RESIDENT_UDP_SESSION_LIMIT_LEGACY_ENV,
        RESIDENT_UDP_SESSION_LIMIT_DEFAULT,
        RESIDENT_UDP_SESSION_LIMIT_MIN,
        RESIDENT_UDP_SESSION_LIMIT_MAX,
    )
}

pub(super) fn bounded_env_usize_with_legacy(
    name: &str,
    legacy_name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> usize {
    std::env::var(name)
        .or_else(|_| std::env::var(legacy_name))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}
