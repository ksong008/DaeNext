use std::fmt;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

#[path = "udp_io/syscall_batch.rs"]
mod syscall_batch;
pub use syscall_batch::{UdpBatchReceiver, UdpSendMessage, try_sendmmsg};

pub const UDP_RECV_DEFAULT_CAPACITY: usize = 2048;
const UDP_RECV_MAX_RETAINED_CAPACITY: usize = 64 * 1024;
const UDP_RECV_MAX_DATAGRAM_CAPACITY: usize = u16::MAX as usize;

#[derive(Debug)]
pub enum UdpOriginalDstRecvError {
    Io(io::Error),
    Truncated { capacity: usize },
    ControlTruncated,
    UnsupportedAddressFamily,
}

impl UdpOriginalDstRecvError {
    pub fn is_would_block(&self) -> bool {
        matches!(self, Self::Io(err) if err.kind() == io::ErrorKind::WouldBlock)
    }

    #[cfg(test)]
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

pub struct UdpOriginalDstPacket {
    pub payload: UdpPayload,
    pub peer: SocketAddr,
    pub original_dst: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct UdpPayloadPool {
    inner: Arc<UdpPayloadPoolInner>,
}

struct UdpPayloadPoolInner {
    shards: Box<[UdpPayloadPoolShard]>,
    next_take_shard: AtomicUsize,
}

struct UdpPayloadPoolShard {
    state: Mutex<UdpPayloadPoolState>,
    max_idle: usize,
    max_idle_bytes: usize,
}

struct UdpPayloadPoolLease {
    pool: UdpPayloadPool,
    shard_index: usize,
}

#[derive(Default)]
struct UdpPayloadPoolState {
    buffers: Vec<Vec<u8>>,
    retained_bytes: usize,
}

impl UdpPayloadPool {
    pub fn new(max_idle: usize, requested_shards: usize) -> Self {
        let shard_count = requested_shards.max(1).min(max_idle.max(1));
        let base_idle = max_idle / shard_count;
        let extra_idle = max_idle % shard_count;
        let shards = (0..shard_count)
            .map(|shard_index| {
                let max_idle = base_idle + usize::from(shard_index < extra_idle);
                UdpPayloadPoolShard {
                    state: Mutex::new(UdpPayloadPoolState::default()),
                    max_idle,
                    max_idle_bytes: max_idle.saturating_mul(UDP_RECV_DEFAULT_CAPACITY),
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            inner: Arc::new(UdpPayloadPoolInner {
                shards,
                next_take_shard: AtomicUsize::new(0),
            }),
        }
    }

    fn take(&self, min_capacity: usize) -> (Vec<u8>, UdpPayloadPoolLease) {
        let shard_index = if self.inner.shards.len() == 1 {
            0
        } else {
            self.inner.next_take_shard.fetch_add(1, Ordering::Relaxed) % self.inner.shards.len()
        };
        let shard = &self.inner.shards[shard_index];
        let mut state = shard
            .state
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
        (
            buffer,
            UdpPayloadPoolLease {
                pool: self.clone(),
                shard_index,
            },
        )
    }

    #[cfg(test)]
    fn retained_snapshot(&self) -> (usize, usize) {
        self.inner
            .shards
            .iter()
            .fold((0_usize, 0_usize), |(buffers, bytes), shard| {
                let state = shard
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                (
                    buffers.saturating_add(state.buffers.len()),
                    bytes.saturating_add(state.retained_bytes),
                )
            })
    }

    #[cfg(test)]
    fn retained_shard_snapshot(&self, shard_index: usize) -> (usize, usize) {
        let shard = &self.inner.shards[shard_index];
        let state = shard
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state.buffers.len(), state.retained_bytes)
    }
}

impl UdpPayloadPoolLease {
    fn recycle(self, mut buffer: Vec<u8>) {
        if buffer.capacity() == 0 || buffer.capacity() > UDP_RECV_MAX_RETAINED_CAPACITY {
            return;
        }
        buffer.clear();
        let shard = &self.pool.inner.shards[self.shard_index];
        let mut state = shard
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let retained_bytes = state.retained_bytes.saturating_add(buffer.capacity());
        if state.buffers.len() < shard.max_idle && retained_bytes <= shard.max_idle_bytes {
            state.retained_bytes = retained_bytes;
            state.buffers.push(buffer);
        }
    }
}

pub struct UdpPayload {
    bytes: Vec<u8>,
    pool: Option<UdpPayloadPoolLease>,
    retained_owner: Option<Box<dyn Send>>,
}

impl UdpPayload {
    fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            pool: None,
            retained_owner: None,
        }
    }

    fn from_pool(bytes: Vec<u8>, pool: UdpPayloadPoolLease) -> Self {
        Self {
            bytes,
            pool: Some(pool),
            retained_owner: None,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn attach_retained_owner<T: Send + 'static>(&mut self, owner: T) -> Result<(), T> {
        if self.retained_owner.is_some() {
            return Err(owner);
        }
        self.retained_owner = Some(Box::new(owner));
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

pub fn recv_udp_with_original_dst(
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

pub fn try_recv_udp_with_original_dst_from_pool(
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
    let fd = socket.as_raw_fd();
    let (mut data, mut pool_lease) = match payload_pool {
        Some(pool) => {
            let (data, lease) = pool.take(recv_capacity);
            (data, Some(lease))
        }
        None => (Vec::with_capacity(recv_capacity), None),
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
        if let Some(lease) = pool_lease.take() {
            lease.recycle(data);
        }
        return Err(UdpOriginalDstRecvError::Io(io::Error::last_os_error()));
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        if let Some(lease) = pool_lease.take() {
            lease.recycle(data);
        }
        return Err(UdpOriginalDstRecvError::Truncated {
            capacity: recv_capacity,
        });
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        if let Some(lease) = pool_lease.take() {
            lease.recycle(data);
        }
        return Err(UdpOriginalDstRecvError::ControlTruncated);
    }
    // SAFETY: recvmsg initialized exactly `read` bytes in the spare capacity
    // pointed to by the iovec above, and no safe code can read beyond that len.
    unsafe {
        data.set_len(read as usize);
    }
    let Some(peer) = sockaddr_storage_to_addr(&peer) else {
        if let Some(lease) = pool_lease.take() {
            lease.recycle(data);
        }
        return Err(UdpOriginalDstRecvError::UnsupportedAddressFamily);
    };
    let original_dst = original_dst_from_msghdr(&msg);
    let payload = match pool_lease {
        Some(lease) => UdpPayload::from_pool(data, lease),
        None => UdpPayload::from_vec(data),
    };
    Ok(UdpOriginalDstPacket {
        payload,
        peer,
        original_dst,
    })
}

fn original_dst_from_msghdr(msg: &libc::msghdr) -> Option<SocketAddr> {
    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == IP_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in>());
                return Some(SocketAddr::V4(sockaddr_in_to_v4(addr)));
            }
            if (*cmsg).cmsg_level == libc::SOL_IPV6 && (*cmsg).cmsg_type == IPV6_ORIGDSTADDR {
                let addr = *(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in6>());
                return Some(sockaddr_in6_to_addr(addr));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::thread;
    use std::time::{Duration, Instant};

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
        let pool = UdpPayloadPool::new(2, 1);
        let (_, first) = pool.take(UDP_RECV_DEFAULT_CAPACITY);
        let (_, second) = pool.take(UDP_RECV_DEFAULT_CAPACITY);
        let (_, third) = pool.take(UDP_RECV_DEFAULT_CAPACITY);
        first.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        second.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        third.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        let (buffers, retained_bytes) = pool.retained_snapshot();
        assert_eq!(buffers, 2);
        assert_eq!(
            retained_bytes,
            2_usize.saturating_mul(UDP_RECV_DEFAULT_CAPACITY)
        );
    }

    #[test]
    fn udp_payload_pool_preserves_global_budget_across_shards() {
        let pool = UdpPayloadPool::new(5, 3);
        let leases = (0..9)
            .map(|_| pool.take(UDP_RECV_DEFAULT_CAPACITY).1)
            .collect::<Vec<_>>();
        for lease in leases {
            lease.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        }

        assert_eq!(
            pool.retained_snapshot(),
            (5, 5_usize.saturating_mul(UDP_RECV_DEFAULT_CAPACITY))
        );
        assert_eq!(
            pool.retained_shard_snapshot(0),
            (2, 2_usize.saturating_mul(UDP_RECV_DEFAULT_CAPACITY))
        );
        assert_eq!(
            pool.retained_shard_snapshot(1),
            (2, 2_usize.saturating_mul(UDP_RECV_DEFAULT_CAPACITY))
        );
        assert_eq!(
            pool.retained_shard_snapshot(2),
            (1, UDP_RECV_DEFAULT_CAPACITY)
        );
    }

    #[test]
    fn udp_payload_pool_recycles_into_originating_shard() {
        let pool = UdpPayloadPool::new(4, 2);
        let (_, first_lease) = pool.take(UDP_RECV_DEFAULT_CAPACITY);
        let (_, second_lease) = pool.take(UDP_RECV_DEFAULT_CAPACITY);

        assert_eq!(first_lease.shard_index, 0);
        assert_eq!(second_lease.shard_index, 1);
        second_lease.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        assert_eq!(pool.retained_shard_snapshot(0), (0, 0));
        assert_eq!(
            pool.retained_shard_snapshot(1),
            (1, UDP_RECV_DEFAULT_CAPACITY)
        );
        first_lease.recycle(Vec::with_capacity(UDP_RECV_DEFAULT_CAPACITY));
        assert_eq!(
            pool.retained_shard_snapshot(0),
            (1, UDP_RECV_DEFAULT_CAPACITY)
        );
    }

    #[test]
    fn udp_payload_pool_clone_shares_retained_buffers() {
        let pool = UdpPayloadPool::new(2, 2);
        let clone = pool.clone();
        let (buffer, lease) = clone.take(UDP_RECV_DEFAULT_CAPACITY);
        lease.recycle(buffer);

        assert_eq!(pool.retained_snapshot(), (1, UDP_RECV_DEFAULT_CAPACITY));
    }

    #[test]
    fn udp_payload_pool_recycles_buffers_after_receive_errors() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let pool = UdpPayloadPool::new(2, 1);

        let err = match recvmsg_udp_original_dst_with_capacity(
            &receiver,
            UDP_RECV_DEFAULT_CAPACITY,
            Some(&pool),
        ) {
            Ok(_) => panic!("empty nonblocking socket unexpectedly returned a datagram"),
            Err(err) => err,
        };

        assert!(err.is_would_block());
        assert_eq!(pool.retained_snapshot(), (1, UDP_RECV_DEFAULT_CAPACITY));
    }

    #[test]
    fn udp_payload_pool_recycles_truncated_datagram_buffer() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(&[1_u8, 2, 3], receiver.local_addr().unwrap())
            .unwrap();
        let pool = UdpPayloadPool::new(2, 1);

        let err = match recvmsg_udp_original_dst_with_capacity(&receiver, 2, Some(&pool)) {
            Ok(_) => panic!("undersized receive buffer unexpectedly accepted a datagram"),
            Err(err) => err,
        };

        assert!(err.is_truncated());
        assert_eq!(pool.retained_snapshot(), (1, 2));
    }

    #[test]
    fn udp_payload_drops_its_retained_owner() {
        let drops = Arc::new(AtomicUsize::new(0));
        #[derive(Debug)]
        struct DropCounter(Arc<AtomicUsize>);
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut payload = UdpPayload::from_vec(vec![0_u8; 768]);
        payload
            .attach_retained_owner(DropCounter(Arc::clone(&drops)))
            .unwrap();
        drop(payload);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[ignore = "explicit high-concurrency buffer ownership microbenchmark"]
    fn udp_payload_pool_high_concurrency_microbenchmark() {
        const TOTAL_OPERATIONS: usize = 1_048_576;
        const CONCURRENCY_LEVELS: [usize; 5] = [1, 4, 16, 64, 256];
        let runtime_shards = thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1)
            .min(32);
        for concurrency in CONCURRENCY_LEVELS {
            let shared_pool = UdpPayloadPool::new(1_024, 1);
            let shared = benchmark_payload_buffers(concurrency, TOTAL_OPERATIONS, move |_| {
                shared_pool.clone()
            });
            let sharded_pool = UdpPayloadPool::new(1_024, runtime_shards);
            let sharded = benchmark_payload_buffers(concurrency, TOTAL_OPERATIONS, move |_| {
                sharded_pool.clone()
            });
            let allocated = benchmark_payload_allocations(concurrency, TOTAL_OPERATIONS);
            eprintln!(
                "udp_payload_pool_concurrency_benchmark {}",
                serde_json::json!({
                    "concurrency": concurrency,
                    "operations": TOTAL_OPERATIONS,
                    "runtimeShards": runtime_shards,
                    "sharedPoolNsPerOperation": shared.as_nanos() / TOTAL_OPERATIONS as u128,
                    "shardedPoolNsPerOperation": sharded.as_nanos() / TOTAL_OPERATIONS as u128,
                    "allocateNsPerOperation": allocated.as_nanos() / TOTAL_OPERATIONS as u128,
                })
            );
        }
    }

    fn benchmark_payload_buffers(
        concurrency: usize,
        total_operations: usize,
        pool_for_worker: impl Fn(usize) -> UdpPayloadPool,
    ) -> Duration {
        let operations_per_worker = total_operations.div_ceil(concurrency);
        let started = Instant::now();
        thread::scope(|scope| {
            for worker in 0..concurrency {
                let pool = pool_for_worker(worker);
                scope.spawn(move || {
                    for _ in 0..operations_per_worker {
                        let (mut buffer, lease) = pool.take(UDP_RECV_DEFAULT_CAPACITY);
                        buffer.resize(UDP_RECV_DEFAULT_CAPACITY, 0);
                        black_box(buffer.as_mut_slice());
                        lease.recycle(buffer);
                    }
                });
            }
        });
        started.elapsed()
    }

    fn benchmark_payload_allocations(concurrency: usize, total_operations: usize) -> Duration {
        let operations_per_worker = total_operations.div_ceil(concurrency);
        let started = Instant::now();
        thread::scope(|scope| {
            for _ in 0..concurrency {
                scope.spawn(move || {
                    for _ in 0..operations_per_worker {
                        let mut buffer = vec![0_u8; UDP_RECV_DEFAULT_CAPACITY];
                        black_box(buffer.as_mut_slice());
                    }
                });
            }
        });
        started.elapsed()
    }
}
