use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::UdpDirectSocketReport;
use serde_json::{Value, json};

const UDP_RECV_DEFAULT_CAPACITY: usize = 2048;
const UDP_RECV_MAX_RETAINED_CAPACITY: usize = 64 * 1024;

pub(super) struct UdpOriginalDstPacket {
    pub(super) payload: UdpPayload,
    pub(super) peer: SocketAddr,
    pub(super) original_dst: Option<SocketAddr>,
}

#[derive(Clone)]
pub(super) struct UdpPayloadPool {
    inner: Arc<Mutex<Vec<Vec<u8>>>>,
    max_idle: usize,
}

impl UdpPayloadPool {
    pub(super) fn new(max_idle: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
            max_idle,
        }
    }

    fn take(&self, min_capacity: usize) -> Vec<u8> {
        let mut buffer = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(min_capacity));
        buffer.clear();
        if buffer.capacity() < min_capacity {
            buffer.reserve(min_capacity - buffer.capacity());
        }
        buffer
    }

    fn recycle(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() == 0 || buffer.capacity() > UDP_RECV_MAX_RETAINED_CAPACITY {
            return;
        }
        buffer.clear();
        let mut idle = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if idle.len() < self.max_idle {
            idle.push(buffer);
        }
    }
}

pub(super) struct UdpPayload {
    bytes: Vec<u8>,
    pool: Option<UdpPayloadPool>,
}

impl UdpPayload {
    fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes, pool: None }
    }

    fn from_pool(bytes: Vec<u8>, pool: &UdpPayloadPool) -> Self {
        Self {
            bytes,
            pool: Some(pool.clone()),
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for UdpPayload {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.recycle(std::mem::take(&mut self.bytes));
        }
    }
}

impl Deref for UdpPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for UdpPayload {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq<&[u8]> for UdpPayload {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
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

pub(super) fn try_recv_udp_with_original_dst_from_pool(
    socket: &UdpSocket,
    expected_len: usize,
    payload_pool: &UdpPayloadPool,
) -> Result<UdpOriginalDstPacket, String> {
    recvmsg_udp_original_dst_with_pool(socket, expected_len, Some(payload_pool))
}

fn recvmsg_udp_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, String> {
    recvmsg_udp_original_dst_with_pool(socket, expected_len, None)
}

fn recvmsg_udp_original_dst_with_pool(
    socket: &UdpSocket,
    expected_len: usize,
    payload_pool: Option<&UdpPayloadPool>,
) -> Result<UdpOriginalDstPacket, String> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;
    let fd = socket.as_raw_fd();
    let recv_capacity = expected_len.max(UDP_RECV_DEFAULT_CAPACITY);
    let mut data = match payload_pool {
        Some(pool) => pool.take(recv_capacity),
        None => Vec::with_capacity(recv_capacity),
    };
    let mut control = [0_u8; 256];
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let spare = &mut data.spare_capacity_mut()[..recv_capacity];
    let mut iov = libc::iovec {
        iov_base: spare.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: spare.len(),
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
        if let Some(pool) = payload_pool {
            pool.recycle(data);
        }
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: recvmsg initialized exactly `read` bytes in the spare capacity
    // pointed to by the iovec above, and no safe code can read beyond that len.
    unsafe {
        data.set_len(read as usize);
    }
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
    let payload = match payload_pool {
        Some(pool) => UdpPayload::from_pool(data, pool),
        None => UdpPayload::from_vec(data),
    };
    Ok(UdpOriginalDstPacket {
        payload,
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
