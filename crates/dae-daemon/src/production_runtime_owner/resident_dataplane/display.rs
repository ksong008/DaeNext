use std::net::{IpAddr, SocketAddr};

use dae_outbound::NetworkType;

pub(super) fn resident_normalized_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), addr.port()))
            .unwrap_or(SocketAddr::V6(addr)),
        SocketAddr::V4(_) => addr,
    }
}

pub(super) fn resident_socket_addr_display(addr: SocketAddr) -> String {
    resident_normalized_socket_addr(addr).to_string()
}

pub(super) fn resident_tcp_network_name(addr: SocketAddr) -> &'static str {
    if resident_normalized_socket_addr(addr).is_ipv6() {
        "tcp6"
    } else {
        "tcp4"
    }
}

pub(super) fn resident_udp_network_name(addr: SocketAddr) -> &'static str {
    if resident_normalized_socket_addr(addr).is_ipv6() {
        "udp6"
    } else {
        "udp4"
    }
}

pub(super) fn resident_tcp_selector_network_type(addr: SocketAddr) -> NetworkType {
    if resident_normalized_socket_addr(addr).is_ipv6() {
        NetworkType::TCP6
    } else {
        NetworkType::TCP4
    }
}

pub(super) fn resident_udp_selector_network_type(addr: SocketAddr) -> NetworkType {
    if resident_normalized_socket_addr(addr).is_ipv6() {
        NetworkType::DNS_UDP6
    } else {
        NetworkType::DNS_UDP4
    }
}
