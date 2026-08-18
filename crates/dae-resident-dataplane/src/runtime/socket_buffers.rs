use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use super::*;

pub(crate) fn resident_udp_socket_buffer_bytes() -> usize {
    resident_usize_from_env(
        RESIDENT_UDP_SOCKET_BUFFER_BYTES_ENV,
        RESIDENT_UDP_SOCKET_BUFFER_BYTES_DEFAULT,
        RESIDENT_UDP_SOCKET_BUFFER_BYTES_MIN,
        RESIDENT_UDP_SOCKET_BUFFER_BYTES_MAX,
    )
}

pub(crate) fn apply_resident_udp_socket_buffer_tuning(socket: &UdpSocket) {
    apply_udp_socket_buffer_tuning(socket.as_raw_fd(), resident_udp_socket_buffer_bytes());
}

fn resident_usize_from_env(name: &'static str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_udp_socket_buffer_defaults_are_bounded() {
        let value = resident_udp_socket_buffer_bytes();
        assert!(value >= RESIDENT_UDP_SOCKET_BUFFER_BYTES_MIN);
        assert!(value <= RESIDENT_UDP_SOCKET_BUFFER_BYTES_MAX);
    }
}
