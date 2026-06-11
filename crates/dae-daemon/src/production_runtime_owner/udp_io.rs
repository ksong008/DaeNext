use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::UdpDirectSocketReport;
use serde_json::{Value, json};

pub(super) struct UdpOriginalDstPacket {
    pub(super) payload: Vec<u8>,
    pub(super) peer: SocketAddr,
    pub(super) original_dst: Option<SocketAddr>,
}

pub(super) fn recv_udp_with_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, String> {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match recvmsg_udp_original_dst(socket, expected_len) {
            Ok(packet) => return Ok(packet),
            Err(err) if err.contains("WouldBlock") && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err)
                if err.contains("Resource temporarily unavailable")
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err),
        }
    }
}

pub(super) fn try_recv_udp_with_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, String> {
    recvmsg_udp_original_dst(socket, expected_len)
}

fn recvmsg_udp_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, String> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;
    let fd = socket.as_raw_fd();
    let mut data = vec![0_u8; expected_len.max(2048)];
    let mut control = [0_u8; 256];
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut peer as *mut libc::sockaddr_storage).cast::<libc::c_void>();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = control.len();
    let read = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if read < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    data.truncate(read as usize);
    let peer = sockaddr_storage_to_addr(&peer)
        .ok_or_else(|| "receive UDP packet from unsupported address family".to_owned())?;
    let mut original_dst = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == IP_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in>());
                original_dst = Some(SocketAddr::V4(sockaddr_in_to_v4(addr)));
                break;
            }
            if (*cmsg).cmsg_level == libc::SOL_IPV6 && (*cmsg).cmsg_type == IPV6_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in6>());
                original_dst = Some(sockaddr_in6_to_addr(addr));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok(UdpOriginalDstPacket {
        payload: data,
        peer,
        original_dst,
    })
}

fn sockaddr_in_to_v4(addr: libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(addr.sin_port),
    )
}

fn sockaddr_in6_to_addr(addr: libc::sockaddr_in6) -> SocketAddr {
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    if let Some(v4) = ip.to_ipv4_mapped() {
        SocketAddr::V4(SocketAddrV4::new(v4, port))
    } else {
        SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            addr.sin6_flowinfo,
            addr.sin6_scope_id,
        ))
    }
}

fn sockaddr_storage_to_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr = unsafe {
                std::ptr::read(
                    (storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                )
            };
            Some(SocketAddr::V4(sockaddr_in_to_v4(addr)))
        }
        libc::AF_INET6 => {
            let addr = unsafe {
                std::ptr::read(
                    (storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                )
            };
            Some(sockaddr_in6_to_addr(addr))
        }
        _ => None,
    }
}

pub(super) fn udp_direct_report_json(report: &UdpDirectSocketReport, target: SocketAddr) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
        "target": target.to_string(),
    })
}
