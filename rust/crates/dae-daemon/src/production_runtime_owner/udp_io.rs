use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::UdpDirectSocketReport;
use serde_json::{Value, json};

pub(super) struct UdpOriginalDstPacket {
    pub(super) payload: Vec<u8>,
    pub(super) peer: SocketAddrV4,
    pub(super) original_dst: Option<SocketAddrV4>,
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

fn recvmsg_udp_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, String> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    let fd = socket.as_raw_fd();
    let mut data = vec![0_u8; expected_len.max(2048)];
    let mut control = [0_u8; 128];
    let mut peer: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut peer as *mut libc::sockaddr_in).cast::<libc::c_void>();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = control.len();
    let read = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if read < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    data.truncate(read as usize);
    let peer = sockaddr_in_to_v4(peer);
    let mut original_dst = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == IP_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in>());
                original_dst = Some(sockaddr_in_to_v4(addr));
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

pub(super) fn udp_direct_report_json(
    report: &UdpDirectSocketReport,
    target: SocketAddrV4,
) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
        "target": target.to_string(),
    })
}
