use super::*;

pub(super) struct UdpIngressBatch {
    pub(super) truncated: usize,
    pub(super) control_truncated: usize,
    pub(super) invalid: usize,
    pub(super) budget_hit: bool,
    pub(super) syscall_count: usize,
    pub(super) batch_syscalls: usize,
    pub(super) batch_datagrams: usize,
    pub(super) batch_max: usize,
    pub(super) would_block: usize,
    pub(super) fallback_activated: Option<String>,
}

pub(super) async fn recv_udp_batch_with_original_dst_async(
    socket: &AsyncFd<UdpSocket>,
    payload_pool: &UdpPayloadPool,
    batch_receiver: &mut UdpBatchReceiver,
    drain_budget: usize,
    packets: &mut Vec<UdpOriginalDstPacket>,
) -> Result<UdpIngressBatch, String> {
    let drain_budget = drain_budget.max(1);
    packets.clear();
    if packets.capacity() < drain_budget.min(32) {
        packets.reserve(drain_budget.min(32) - packets.capacity());
    }
    let mut truncated = 0_usize;
    let mut control_truncated = 0_usize;
    let mut invalid = 0_usize;
    let mut syscall_count = 0_usize;
    let mut batch_syscalls = 0_usize;
    let mut batch_datagrams = 0_usize;
    let mut batch_max = 0_usize;
    let mut would_block = 0_usize;
    let mut fallback_activated = None;
    loop {
        let mut guard = socket
            .readable()
            .await
            .map_err(|err| format!("await UDP socket readiness: {err}"))?;
        loop {
            let remaining = drain_budget
                .saturating_sub(
                    packets
                        .len()
                        .saturating_add(truncated)
                        .saturating_add(control_truncated)
                        .saturating_add(invalid),
                )
                .max(1);
            let attempt = guard.try_io(|inner| {
                let packets_before = packets.len();
                batch_receiver
                    .try_recv(inner.get_ref(), payload_pool, remaining, packets)
                    .map(|outcome| (packets.len().saturating_sub(packets_before), outcome))
                    .map_err(|err| {
                        if err.is_would_block() {
                            io::Error::from(io::ErrorKind::WouldBlock)
                        } else {
                            io::Error::other(err.to_string())
                        }
                    })
            });
            match attempt {
                Ok(Ok((packet_count, mut outcome))) => {
                    let received = packet_count
                        .saturating_add(outcome.truncated)
                        .saturating_add(outcome.control_truncated)
                        .saturating_add(outcome.invalid);
                    syscall_count = syscall_count.saturating_add(outcome.syscall_count);
                    if outcome.batch_datagrams != 0 {
                        batch_syscalls = batch_syscalls.saturating_add(1);
                        batch_datagrams = batch_datagrams.saturating_add(outcome.batch_datagrams);
                        batch_max = batch_max.max(outcome.batch_datagrams);
                    }
                    truncated = truncated.saturating_add(outcome.truncated);
                    control_truncated = control_truncated.saturating_add(outcome.control_truncated);
                    invalid = invalid.saturating_add(outcome.invalid);
                    if fallback_activated.is_none() {
                        fallback_activated = outcome.fallback_activated.take();
                    }
                    debug_assert_ne!(received, 0, "ready UDP receive made no progress");
                }
                Ok(Err(err)) => {
                    packets.clear();
                    return Err(err.to_string());
                }
                Err(_)
                    if !packets.is_empty()
                        || truncated != 0
                        || control_truncated != 0
                        || invalid != 0 =>
                {
                    would_block = would_block.saturating_add(1);
                    syscall_count = syscall_count.saturating_add(1);
                    return Ok(UdpIngressBatch {
                        truncated,
                        control_truncated,
                        invalid,
                        budget_hit: false,
                        syscall_count,
                        batch_syscalls,
                        batch_datagrams,
                        batch_max,
                        would_block,
                        fallback_activated,
                    });
                }
                Err(_) => {
                    would_block = would_block.saturating_add(1);
                    syscall_count = syscall_count.saturating_add(1);
                    break;
                }
            }
            if packets
                .len()
                .saturating_add(truncated)
                .saturating_add(control_truncated)
                .saturating_add(invalid)
                >= drain_budget
            {
                return Ok(UdpIngressBatch {
                    truncated,
                    control_truncated,
                    invalid,
                    budget_hit: true,
                    syscall_count,
                    batch_syscalls,
                    batch_datagrams,
                    batch_max,
                    would_block,
                    fallback_activated,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ingress_batch_obeys_its_drain_budget_without_losing_packets() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for value in [1_u8, 2, 3] {
            sender.send_to(&[value], target).unwrap();
        }
        let socket = AsyncFd::new(receiver).unwrap();
        let pool = UdpPayloadPool::new(4, 1);
        let mut batch_receiver = UdpBatchReceiver::new(2);
        let mut packets = Vec::new();

        let first = recv_udp_batch_with_original_dst_async(
            &socket,
            &pool,
            &mut batch_receiver,
            2,
            &mut packets,
        )
        .await
        .unwrap();
        assert_eq!(packets.len(), 2);
        assert!(first.budget_hit);
        if !cfg!(feature = "test-scalar-udp-recv") {
            assert_eq!(first.syscall_count, 1);
            assert_eq!(first.batch_syscalls, 1);
            assert_eq!(first.batch_datagrams, 2);
        }
        let second = recv_udp_batch_with_original_dst_async(
            &socket,
            &pool,
            &mut batch_receiver,
            2,
            &mut packets,
        )
        .await
        .unwrap();
        assert_eq!(packets.len(), 1);
        assert!(!second.budget_hit);
        assert_eq!(second.truncated, 0);
    }

    #[tokio::test]
    async fn ingress_batch_preserves_zero_length_and_large_datagrams() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(&[], target).unwrap();
        sender.send_to(&vec![0x5a; 16 * 1024], target).unwrap();
        let socket = AsyncFd::new(receiver).unwrap();
        let pool = UdpPayloadPool::new(4, 1);
        let mut batch_receiver = UdpBatchReceiver::new(8);
        let mut packets = Vec::new();

        let _batch = recv_udp_batch_with_original_dst_async(
            &socket,
            &pool,
            &mut batch_receiver,
            8,
            &mut packets,
        )
        .await
        .unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].payload.len(), 0);
        assert_eq!(packets[1].payload.len(), 16 * 1024);
        assert!(packets[1].payload.iter().all(|byte| *byte == 0x5a));
    }

    #[cfg(not(feature = "test-scalar-udp-recv"))]
    #[tokio::test]
    async fn ingress_falls_back_to_scalar_for_socket_lifetime() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"fallback", target).unwrap();
        let socket = AsyncFd::new(receiver).unwrap();
        let pool = UdpPayloadPool::new(4, 1);
        let mut batch_receiver = UdpBatchReceiver::new(8);
        batch_receiver.force_next_errno(libc::ENOSYS);
        let mut packets = Vec::new();

        let batch = recv_udp_batch_with_original_dst_async(
            &socket,
            &pool,
            &mut batch_receiver,
            8,
            &mut packets,
        )
        .await
        .unwrap();
        assert_eq!(packets.len(), 1);
        assert!(batch.fallback_activated.is_some());
        assert!(!batch_receiver.is_enabled());
    }

    #[cfg(not(feature = "test-scalar-udp-recv"))]
    #[tokio::test]
    async fn ingress_retries_interrupted_recvmmsg_without_losing_the_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"retry-eintr", target).unwrap();
        let socket = AsyncFd::new(receiver).unwrap();
        let pool = UdpPayloadPool::new(4, 1);
        let mut batch_receiver = UdpBatchReceiver::new(8);
        batch_receiver.force_next_errno(libc::EINTR);
        let mut packets = Vec::new();

        let batch = recv_udp_batch_with_original_dst_async(
            &socket,
            &pool,
            &mut batch_receiver,
            8,
            &mut packets,
        )
        .await
        .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(&*packets[0].payload, b"retry-eintr");
        assert!(batch.fallback_activated.is_none());
        assert!(batch_receiver.is_enabled());
    }
}
