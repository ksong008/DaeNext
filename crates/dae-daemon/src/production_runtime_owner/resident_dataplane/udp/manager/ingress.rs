use super::*;

pub(super) struct UdpIngressBatch {
    pub(super) packets: Vec<UdpOriginalDstPacket>,
    pub(super) truncated: usize,
    pub(super) budget_hit: bool,
}

enum UdpIngressAttempt {
    Packet(UdpOriginalDstPacket),
    Truncated,
}

pub(super) async fn recv_udp_batch_with_original_dst_async(
    socket: &AsyncFd<UdpSocket>,
    payload_pool: &UdpPayloadPool,
    drain_budget: usize,
) -> Result<UdpIngressBatch, String> {
    let drain_budget = drain_budget.max(1);
    let mut packets = Vec::with_capacity(drain_budget.min(32));
    let mut truncated = 0_usize;
    loop {
        let mut guard = socket
            .readable()
            .await
            .map_err(|err| format!("await UDP socket readiness: {err}"))?;
        loop {
            let attempt = guard.try_io(|inner| {
                match try_recv_udp_with_original_dst_from_pool(
                    inner.get_ref(),
                    UDP_RECV_DEFAULT_CAPACITY,
                    payload_pool,
                ) {
                    Ok(packet) => Ok(UdpIngressAttempt::Packet(packet)),
                    Err(err) if err.is_truncated() => Ok(UdpIngressAttempt::Truncated),
                    Err(err) if err.is_would_block() => {
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                    Err(err) => Err(io::Error::other(err.to_string())),
                }
            });
            match attempt {
                Ok(Ok(UdpIngressAttempt::Packet(packet))) => packets.push(packet),
                Ok(Ok(UdpIngressAttempt::Truncated)) => truncated += 1,
                Ok(Err(err)) => return Err(err.to_string()),
                Err(_) if !packets.is_empty() || truncated != 0 => {
                    return Ok(UdpIngressBatch {
                        packets,
                        truncated,
                        budget_hit: false,
                    });
                }
                Err(_) => break,
            }
            if packets.len().saturating_add(truncated) >= drain_budget {
                return Ok(UdpIngressBatch {
                    packets,
                    truncated,
                    budget_hit: true,
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

        let first = recv_udp_batch_with_original_dst_async(&socket, &pool, 2)
            .await
            .unwrap();
        assert_eq!(first.packets.len(), 2);
        assert!(first.budget_hit);
        let second = recv_udp_batch_with_original_dst_async(&socket, &pool, 2)
            .await
            .unwrap();
        assert_eq!(second.packets.len(), 1);
        assert!(!second.budget_hit);
        assert_eq!(second.truncated, 0);
    }
}
