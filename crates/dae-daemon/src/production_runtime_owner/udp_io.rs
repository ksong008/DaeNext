use std::fmt;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::UdpDirectSocketReport;
use serde_json::{Value, json};

use super::udp_payload_admission::{
    ResidentUdpPayloadAdmission, ResidentUdpPayloadAdmissionError, ResidentUdpPayloadPermit,
};

pub(super) const UDP_RECV_DEFAULT_CAPACITY: usize = 2048;
const UDP_RECV_MAX_RETAINED_CAPACITY: usize = 64 * 1024;
const UDP_RECV_MAX_DATAGRAM_CAPACITY: usize = u16::MAX as usize;

#[derive(Debug)]
pub(super) enum UdpOriginalDstRecvError {
    Io(io::Error),
    Truncated { capacity: usize },
    ControlTruncated,
    UnsupportedAddressFamily,
}

impl UdpOriginalDstRecvError {
    pub(super) fn is_would_block(&self) -> bool {
        matches!(self, Self::Io(err) if err.kind() == io::ErrorKind::WouldBlock)
    }

    pub(super) fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }
}

impl fmt::Display for UdpOriginalDstRecvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(formatter, "{err}"),
            Self::Truncated { capacity } => {
                write!(
                    formatter,
                    "UDP datagram exceeded receive capacity {capacity}"
                )
            }
            Self::ControlTruncated => formatter.write_str("UDP control metadata was truncated"),
            Self::UnsupportedAddressFamily => {
                formatter.write_str("receive UDP packet from unsupported address family")
            }
        }
    }
}

pub(super) struct UdpOriginalDstPacket {
    pub(super) payload: UdpPayload,
    pub(super) peer: SocketAddr,
    pub(super) original_dst: Option<SocketAddr>,
}

#[derive(Clone)]
pub(super) struct UdpPayloadPool {
    inner: Arc<Mutex<UdpPayloadPoolState>>,
    max_idle: usize,
    max_idle_bytes: usize,
}

#[derive(Default)]
struct UdpPayloadPoolState {
    buffers: Vec<Vec<u8>>,
    retained_bytes: usize,
}

impl UdpPayloadPool {
    pub(super) fn new(max_idle: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(UdpPayloadPoolState::default())),
            max_idle,
            max_idle_bytes: max_idle.saturating_mul(UDP_RECV_DEFAULT_CAPACITY),
        }
    }

    fn take(&self, min_capacity: usize) -> Vec<u8> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut buffer = state
            .buffers
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(min_capacity));
        state.retained_bytes = state.retained_bytes.saturating_sub(buffer.capacity());
        drop(state);
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
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let retained_bytes = state.retained_bytes.saturating_add(buffer.capacity());
        if state.buffers.len() < self.max_idle && retained_bytes <= self.max_idle_bytes {
            state.retained_bytes = retained_bytes;
            state.buffers.push(buffer);
        }
    }
}

pub(super) struct UdpPayload {
    bytes: Vec<u8>,
    pool: Option<UdpPayloadPool>,
    admission: Option<ResidentUdpPayloadPermit>,
}

impl UdpPayload {
    fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            pool: None,
            admission: None,
        }
    }

    fn from_pool(bytes: Vec<u8>, pool: &UdpPayloadPool) -> Self {
        Self {
            bytes,
            pool: Some(pool.clone()),
            admission: None,
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn admit(
        &mut self,
        admission: &ResidentUdpPayloadAdmission,
    ) -> Result<(), ResidentUdpPayloadAdmissionError> {
        if self.admission.is_some() {
            return Ok(());
        }
        self.admission = Some(admission.try_acquire(self.bytes.len())?);
        Ok(())
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
            Err(err) if err.is_would_block() && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}

pub(super) fn try_recv_udp_with_original_dst_from_pool(
    socket: &UdpSocket,
    expected_len: usize,
    payload_pool: &UdpPayloadPool,
) -> Result<UdpOriginalDstPacket, UdpOriginalDstRecvError> {
    recvmsg_udp_original_dst_with_pool(socket, expected_len, Some(payload_pool))
}

fn recvmsg_udp_original_dst(
    socket: &UdpSocket,
    expected_len: usize,
) -> Result<UdpOriginalDstPacket, UdpOriginalDstRecvError> {
    recvmsg_udp_original_dst_with_pool(socket, expected_len, None)
}

fn recvmsg_udp_original_dst_with_pool(
    socket: &UdpSocket,
    expected_len: usize,
    payload_pool: Option<&UdpPayloadPool>,
) -> Result<UdpOriginalDstPacket, UdpOriginalDstRecvError> {
    let datagram_len = peek_udp_datagram_len(socket)?;
    let recv_capacity = expected_len
        .max(UDP_RECV_DEFAULT_CAPACITY)
        .max(datagram_len.min(UDP_RECV_MAX_DATAGRAM_CAPACITY));
    recvmsg_udp_original_dst_with_capacity(socket, recv_capacity, payload_pool)
}

fn peek_udp_datagram_len(socket: &UdpSocket) -> Result<usize, UdpOriginalDstRecvError> {
    let fd = socket.as_raw_fd();
    let mut byte = std::mem::MaybeUninit::<u8>::uninit();
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let read = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_PEEK | libc::MSG_TRUNC) };
    if read < 0 {
        return Err(UdpOriginalDstRecvError::Io(io::Error::last_os_error()));
    }
    Ok(read as usize)
}

fn recvmsg_udp_original_dst_with_capacity(
    socket: &UdpSocket,
    recv_capacity: usize,
    payload_pool: Option<&UdpPayloadPool>,
) -> Result<UdpOriginalDstPacket, UdpOriginalDstRecvError> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;
    let fd = socket.as_raw_fd();
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
        return Err(UdpOriginalDstRecvError::Io(io::Error::last_os_error()));
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        if let Some(pool) = payload_pool {
            pool.recycle(data);
        }
        return Err(UdpOriginalDstRecvError::Truncated {
            capacity: recv_capacity,
        });
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        if let Some(pool) = payload_pool {
            pool.recycle(data);
        }
        return Err(UdpOriginalDstRecvError::ControlTruncated);
    }
    // SAFETY: recvmsg initialized exactly `read` bytes in the spare capacity
    // pointed to by the iovec above, and no safe code can read beyond that len.
    unsafe {
        data.set_len(read as usize);
    }
    let peer =
        sockaddr_storage_to_addr(&peer).ok_or(UdpOriginalDstRecvError::UnsupportedAddressFamily)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_receive_preserves_datagrams_larger_than_the_default_capacity() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = (0..8192).map(|index| index as u8).collect::<Vec<_>>();
        sender
            .send_to(&payload, receiver.local_addr().unwrap())
            .unwrap();

        let packet = recv_udp_with_original_dst(&receiver, UDP_RECV_DEFAULT_CAPACITY).unwrap();
        assert_eq!(packet.payload.as_slice(), payload.as_slice());
    }

    #[test]
    fn udp_receive_reports_kernel_truncation_instead_of_accepting_partial_payload() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(&vec![7_u8; 4096], receiver.local_addr().unwrap())
            .unwrap();

        let err =
            recvmsg_udp_original_dst_with_capacity(&receiver, UDP_RECV_DEFAULT_CAPACITY, None)
                .err()
                .unwrap();
        assert!(err.is_truncated());
    }

    #[test]
    fn udp_payload_pool_bounds_idle_capacity_by_configured_pool_size() {
        let pool = UdpPayloadPool::new(2);
        pool.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        pool.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        pool.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        let state = pool.inner.lock().unwrap();
        assert_eq!(state.buffers.len(), 2);
        assert_eq!(
            state.retained_bytes,
            2_usize.saturating_mul(UDP_RECV_DEFAULT_CAPACITY)
        );
    }

    #[test]
    fn udp_payload_returns_generation_byte_admission_when_dropped() {
        let admission = ResidentUdpPayloadAdmission::new(3, 1024);
        let mut payload = UdpPayload::from_vec(vec![0_u8; 768]);
        payload.admit(&admission).unwrap();
        assert_eq!(admission.current(), 768);
        drop(payload);
        assert_eq!(admission.current(), 0);
    }
}
