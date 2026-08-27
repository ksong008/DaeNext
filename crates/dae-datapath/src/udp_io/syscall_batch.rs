use super::*;
use std::os::fd::RawFd;

pub const UDP_RECV_SYSCALL_BATCH_LIMIT_MAX: usize = 32;

struct UdpBatchRecvSlot {
    payload: Vec<u8>,
    control: [u8; 256],
    peer: libc::sockaddr_storage,
}

pub struct UdpBatchReceiver {
    enabled: bool,
    slots: Box<[UdpBatchRecvSlot]>,
    #[cfg(any(test, feature = "test-support"))]
    forced_errno: Option<i32>,
}

pub struct UdpBatchRecvOutcome {
    pub truncated: usize,
    pub control_truncated: usize,
    pub invalid: usize,
    pub syscall_count: usize,
    pub batch_datagrams: usize,
    pub fallback_activated: Option<String>,
}

impl UdpBatchReceiver {
    pub fn new(limit: usize) -> Self {
        let enabled = !cfg!(feature = "test-scalar-udp-recv") && limit > 1;
        let slot_count = if enabled {
            limit.clamp(2, UDP_RECV_SYSCALL_BATCH_LIMIT_MAX)
        } else {
            0
        };
        let slots = (0..slot_count)
            .map(|_| UdpBatchRecvSlot {
                payload: vec![0_u8; UDP_RECV_MAX_DATAGRAM_CAPACITY],
                control: [0_u8; 256],
                peer: unsafe { std::mem::zeroed() },
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            enabled,
            slots,
            #[cfg(any(test, feature = "test-support"))]
            forced_errno: None,
        }
    }

    #[cfg(all(
        any(test, feature = "test-support"),
        not(feature = "test-scalar-udp-recv")
    ))]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn try_recv(
        &mut self,
        socket: &UdpSocket,
        payload_pool: &UdpPayloadPool,
        remaining_budget: usize,
        packets: &mut Vec<UdpOriginalDstPacket>,
    ) -> Result<UdpBatchRecvOutcome, UdpOriginalDstRecvError> {
        if !self.enabled || remaining_budget <= 1 {
            return self.try_recv_scalar(socket, payload_pool, packets);
        }
        match self.try_recvmmsg(socket, payload_pool, remaining_budget, packets) {
            Ok(outcome) => Ok(outcome),
            Err(UdpOriginalDstRecvError::Io(err))
                if matches!(err.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) =>
            {
                let reason = format!("recvmmsg unavailable for socket lifetime: {err}");
                self.enabled = false;
                self.slots = Vec::new().into_boxed_slice();
                let mut outcome = self.try_recv_scalar(socket, payload_pool, packets)?;
                outcome.fallback_activated = Some(reason);
                Ok(outcome)
            }
            Err(err) => Err(err),
        }
    }

    fn try_recv_scalar(
        &self,
        socket: &UdpSocket,
        payload_pool: &UdpPayloadPool,
        packets: &mut Vec<UdpOriginalDstPacket>,
    ) -> Result<UdpBatchRecvOutcome, UdpOriginalDstRecvError> {
        match try_recv_udp_with_original_dst_from_pool(
            socket,
            UDP_RECV_DEFAULT_CAPACITY,
            payload_pool,
        ) {
            Ok(packet) => {
                packets.push(packet);
                Ok(UdpBatchRecvOutcome {
                    truncated: 0,
                    control_truncated: 0,
                    invalid: 0,
                    syscall_count: 2,
                    batch_datagrams: 0,
                    fallback_activated: None,
                })
            }
            Err(UdpOriginalDstRecvError::Truncated { .. }) => Ok(UdpBatchRecvOutcome {
                truncated: 1,
                control_truncated: 0,
                invalid: 0,
                syscall_count: 2,
                batch_datagrams: 0,
                fallback_activated: None,
            }),
            Err(UdpOriginalDstRecvError::ControlTruncated) => Ok(UdpBatchRecvOutcome {
                truncated: 0,
                control_truncated: 1,
                invalid: 0,
                syscall_count: 2,
                batch_datagrams: 0,
                fallback_activated: None,
            }),
            Err(UdpOriginalDstRecvError::UnsupportedAddressFamily) => Ok(UdpBatchRecvOutcome {
                truncated: 0,
                control_truncated: 0,
                invalid: 1,
                syscall_count: 2,
                batch_datagrams: 0,
                fallback_activated: None,
            }),
            Err(err) => Err(err),
        }
    }

    fn try_recvmmsg(
        &mut self,
        socket: &UdpSocket,
        payload_pool: &UdpPayloadPool,
        remaining_budget: usize,
        packets: &mut Vec<UdpOriginalDstPacket>,
    ) -> Result<UdpBatchRecvOutcome, UdpOriginalDstRecvError> {
        let count = remaining_budget.min(self.slots.len());
        let mut iovecs: [libc::iovec; UDP_RECV_SYSCALL_BATCH_LIMIT_MAX] =
            unsafe { std::mem::zeroed() };
        let mut messages: [libc::mmsghdr; UDP_RECV_SYSCALL_BATCH_LIMIT_MAX] =
            unsafe { std::mem::zeroed() };
        for index in 0..count {
            let slot = &mut self.slots[index];
            iovecs[index] = libc::iovec {
                iov_base: slot.payload.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: slot.payload.capacity(),
            };
            messages[index].msg_hdr.msg_name =
                (&mut slot.peer as *mut libc::sockaddr_storage).cast::<libc::c_void>();
            messages[index].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            messages[index].msg_hdr.msg_iov = &mut iovecs[index];
            messages[index].msg_hdr.msg_iovlen = 1;
            messages[index].msg_hdr.msg_control = slot.control.as_mut_ptr().cast::<libc::c_void>();
            messages[index].msg_hdr.msg_controllen = slot.control.len();
        }

        let received = loop {
            #[cfg(any(test, feature = "test-support"))]
            let result = if let Some(errno) = self.forced_errno.take() {
                Err(io::Error::from_raw_os_error(errno))
            } else {
                recvmmsg_syscall(socket.as_raw_fd(), &mut messages[..count])
            };
            #[cfg(not(any(test, feature = "test-support")))]
            let result = recvmmsg_syscall(socket.as_raw_fd(), &mut messages[..count]);
            match result {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                result => break result.map_err(UdpOriginalDstRecvError::Io)?,
            }
        };

        let mut outcome = UdpBatchRecvOutcome {
            truncated: 0,
            control_truncated: 0,
            invalid: 0,
            syscall_count: 1,
            batch_datagrams: received,
            fallback_activated: None,
        };
        for (index, message) in messages.iter().enumerate().take(received) {
            if message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                outcome.truncated = outcome.truncated.saturating_add(1);
                continue;
            }
            if message.msg_hdr.msg_flags & libc::MSG_CTRUNC != 0 {
                outcome.control_truncated = outcome.control_truncated.saturating_add(1);
                continue;
            }
            let Some(peer) = sockaddr_storage_to_addr(&self.slots[index].peer) else {
                outcome.invalid = outcome.invalid.saturating_add(1);
                continue;
            };
            let read = message.msg_len as usize;
            if read > self.slots[index].payload.capacity() {
                outcome.truncated = outcome.truncated.saturating_add(1);
                continue;
            }
            unsafe {
                self.slots[index].payload.set_len(read);
            }
            let (mut payload, lease) = payload_pool.take(UDP_RECV_MAX_DATAGRAM_CAPACITY);
            std::mem::swap(&mut payload, &mut self.slots[index].payload);
            payload.truncate(read);
            packets.push(UdpOriginalDstPacket {
                payload: UdpPayload::from_pool(payload, lease),
                peer,
                original_dst: original_dst_from_msghdr(&message.msg_hdr),
            });
        }
        Ok(outcome)
    }

    #[cfg(all(
        any(test, feature = "test-support"),
        not(feature = "test-scalar-udp-recv")
    ))]
    pub fn force_next_errno(&mut self, errno: i32) {
        self.forced_errno = Some(errno);
    }
}

fn recvmmsg_syscall(fd: RawFd, messages: &mut [libc::mmsghdr]) -> io::Result<usize> {
    let received = unsafe {
        libc::recvmmsg(
            fd,
            messages.as_mut_ptr(),
            messages.len() as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if received < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(received as usize)
    }
}

pub struct UdpSendMessage<'a> {
    pub payload: &'a [u8],
    pub peer: Option<SocketAddr>,
}

pub fn try_sendmmsg(fd: RawFd, datagrams: &[UdpSendMessage<'_>]) -> io::Result<usize> {
    if datagrams.is_empty() {
        return Ok(0);
    }
    let count = datagrams.len().min(UDP_RECV_SYSCALL_BATCH_LIMIT_MAX);
    let mut addresses: [libc::sockaddr_storage; UDP_RECV_SYSCALL_BATCH_LIMIT_MAX] =
        unsafe { std::mem::zeroed() };
    let mut address_lengths = [0 as libc::socklen_t; UDP_RECV_SYSCALL_BATCH_LIMIT_MAX];
    let mut iovecs: [libc::iovec; UDP_RECV_SYSCALL_BATCH_LIMIT_MAX] = unsafe { std::mem::zeroed() };
    let mut messages: [libc::mmsghdr; UDP_RECV_SYSCALL_BATCH_LIMIT_MAX] =
        unsafe { std::mem::zeroed() };
    for (index, datagram) in datagrams[..count].iter().enumerate() {
        iovecs[index] = libc::iovec {
            iov_base: datagram.payload.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: datagram.payload.len(),
        };
        messages[index].msg_hdr.msg_iov = &mut iovecs[index];
        messages[index].msg_hdr.msg_iovlen = 1;
        if let Some(peer) = datagram.peer {
            let (storage, length) = socket_addr_to_storage(peer);
            addresses[index] = storage;
            address_lengths[index] = length;
            messages[index].msg_hdr.msg_name =
                (&mut addresses[index] as *mut libc::sockaddr_storage).cast::<libc::c_void>();
            messages[index].msg_hdr.msg_namelen = address_lengths[index];
        }
    }
    loop {
        let sent = unsafe {
            libc::sendmmsg(
                fd,
                messages.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if sent < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let sent = sent as usize;
        debug_assert!(
            (0..sent)
                .all(|index| messages[index].msg_len as usize == datagrams[index].payload.len())
        );
        return Ok(sent);
    }
}

fn socket_addr_to_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(addr) => {
            let value = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                    value,
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr) => {
            let value = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                std::ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                    value,
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sendmmsg_sends_ipv4_datagrams_without_waiting_for_a_batch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = receiver.local_addr().unwrap();
        let payloads = [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()];
        let datagrams = payloads
            .iter()
            .map(|payload| UdpSendMessage {
                payload,
                peer: Some(target),
            })
            .collect::<Vec<_>>();
        assert_eq!(try_sendmmsg(sender.as_raw_fd(), &datagrams).unwrap(), 3);
        let mut received = Vec::new();
        for _ in 0..3 {
            let mut buf = [0_u8; 16];
            let read = receiver.recv(&mut buf).unwrap();
            received.push(buf[..read].to_vec());
        }
        assert_eq!(
            received,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
    }

    #[test]
    fn sendmmsg_supports_connected_ipv6_when_available() {
        let Ok(receiver) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let sender = UdpSocket::bind("[::1]:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        let payloads = [b"v6-a".as_slice(), b"v6-b".as_slice()];
        let datagrams = payloads
            .iter()
            .map(|payload| UdpSendMessage {
                payload,
                peer: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(try_sendmmsg(sender.as_raw_fd(), &datagrams).unwrap(), 2);
    }
}
