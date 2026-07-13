use std::io;
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
    let bytes = resident_udp_socket_buffer_bytes();
    let _ = set_socket_buffer_bytes(socket.as_raw_fd(), libc::SO_RCVBUF, bytes);
    let _ = set_socket_buffer_bytes(socket.as_raw_fd(), libc::SO_SNDBUF, bytes);
}

fn resident_usize_from_env(name: &'static str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

fn set_socket_buffer_bytes(fd: i32, option: i32, bytes: usize) -> io::Result<()> {
    let value: libc::c_int = bytes.min(i32::MAX as usize) as libc::c_int;
    let status = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&value as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
