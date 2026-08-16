use super::*;

#[derive(Debug)]
enum TuicUdpDatagramSendFailure {
    TooLarge,
    Fatal(String),
}

trait TuicUdpDatagramSender {
    fn max_datagram_size(&self) -> Option<usize>;

    fn send_datagram(&mut self, datagram: Bytes) -> Result<(), TuicUdpDatagramSendFailure>;
}

impl TuicUdpDatagramSender for quinn::Connection {
    fn max_datagram_size(&self) -> Option<usize> {
        quinn::Connection::max_datagram_size(self)
    }

    fn send_datagram(&mut self, datagram: Bytes) -> Result<(), TuicUdpDatagramSendFailure> {
        quinn::Connection::send_datagram(self, datagram).map_err(|err| match err {
            quinn::SendDatagramError::TooLarge => TuicUdpDatagramSendFailure::TooLarge,
            other => TuicUdpDatagramSendFailure::Fatal(other.to_string()),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TuicUdpSendReport {
    pub(super) whole_datagram_sent: bool,
    pub(super) datagrams_sent: usize,
    pub(super) fragment_layouts: usize,
    pub(super) final_max_wire_size: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn send_tuic_udp_payload(
    connection: &quinn::Connection,
    association_id: u16,
    packet_id: u16,
    target: &str,
    payload: &[u8],
    packet_ids: &mut QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
) -> Result<TuicUdpSendReport, String> {
    let mut connection = connection.clone();
    send_tuic_udp_payload_with(
        &mut connection,
        association_id,
        packet_id,
        target,
        payload,
        packet_ids,
        resources,
    )
}

#[cfg(test)]
fn send_tuic_udp_packet_with<S>(
    sender: &mut S,
    packet: &TuicUdpPacket,
    packet_ids: &mut QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
) -> Result<TuicUdpSendReport, String>
where
    S: TuicUdpDatagramSender,
{
    let target = packet
        .target()
        .ok_or_else(|| "complete TUIC UDP packet is missing its target".to_owned())?;
    send_tuic_udp_payload_with(
        sender,
        packet.association_id(),
        packet.packet_id(),
        target,
        packet.payload(),
        packet_ids,
        resources,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_tuic_udp_payload_with<S>(
    sender: &mut S,
    association_id: u16,
    packet_id: u16,
    target: &str,
    payload: &[u8],
    packet_ids: &mut QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
) -> Result<TuicUdpSendReport, String>
where
    S: TuicUdpDatagramSender,
{
    let whole = encode_tuic_udp_payload(association_id, packet_id, 1, 0, Some(target), payload)
        .map_err(|err| format!("encode complete TUIC UDP datagram: {err}"))?;
    match sender.send_datagram(Bytes::from(whole)) {
        Ok(()) => {
            return Ok(TuicUdpSendReport {
                whole_datagram_sent: true,
                datagrams_sent: 1,
                fragment_layouts: 0,
                final_max_wire_size: sender.max_datagram_size(),
            });
        }
        Err(TuicUdpDatagramSendFailure::TooLarge) => {}
        Err(TuicUdpDatagramSendFailure::Fatal(err)) => {
            return Err(format!("send complete TUIC UDP datagram: {err}"));
        }
    }

    let packet = TuicUdpPacket::new(association_id, packet_id, target, payload)
        .map_err(|err| format!("build oversized TUIC UDP packet: {err}"))?;

    let mut max_wire_size = sender.max_datagram_size().ok_or_else(|| {
        "TUIC peer disabled QUIC datagrams after reporting an oversized datagram".to_owned()
    })?;
    let mut datagrams_sent = 0_usize;
    for fragment_layout in 1..=resources.pmtu_retries() {
        let packet_id = packet_ids.allocate()?;
        let fragments =
            fragment_tuic_udp_packet(&packet, packet_id, max_wire_size).map_err(|err| {
                format!("fragment TUIC UDP datagram for {max_wire_size}-byte QUIC limit: {err}")
            })?;
        let mut restart_max_wire_size = None;
        for fragment in fragments {
            let encoded = encode_tuic_udp_packet(&fragment)
                .map_err(|err| format!("encode TUIC UDP fragment: {err}"))?;
            match sender.send_datagram(Bytes::from(encoded)) {
                Ok(()) => datagrams_sent = datagrams_sent.saturating_add(1),
                Err(TuicUdpDatagramSendFailure::Fatal(err)) => {
                    return Err(format!("send TUIC UDP fragment: {err}"));
                }
                Err(TuicUdpDatagramSendFailure::TooLarge) => {
                    let reduced = sender.max_datagram_size().ok_or_else(|| {
                        "TUIC peer disabled QUIC datagrams during PMTU retry".to_owned()
                    })?;
                    if reduced >= max_wire_size {
                        return Err(format!(
                            "TUIC QUIC datagram limit did not decrease after TooLarge: {max_wire_size} -> {reduced}"
                        ));
                    }
                    restart_max_wire_size = Some(reduced);
                    break;
                }
            }
        }
        let Some(reduced) = restart_max_wire_size else {
            return Ok(TuicUdpSendReport {
                whole_datagram_sent: false,
                datagrams_sent,
                fragment_layouts: fragment_layout,
                final_max_wire_size: Some(max_wire_size),
            });
        };
        max_wire_size = reduced;
    }
    Err(format!(
        "TUIC UDP PMTU retry budget exhausted after {} fragment layouts",
        resources.pmtu_retries()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResidentRuntimeProfile;

    struct SizeBoundedSender {
        max_wire_size: usize,
        attempts: Vec<Vec<u8>>,
        successful: Vec<Vec<u8>>,
        shrink_after_success: Option<(usize, usize)>,
        forced_too_large_attempt: Option<usize>,
    }

    impl SizeBoundedSender {
        fn new(max_wire_size: usize) -> Self {
            Self {
                max_wire_size,
                attempts: Vec::new(),
                successful: Vec::new(),
                shrink_after_success: None,
                forced_too_large_attempt: None,
            }
        }
    }

    impl TuicUdpDatagramSender for SizeBoundedSender {
        fn max_datagram_size(&self) -> Option<usize> {
            Some(self.max_wire_size)
        }

        fn send_datagram(&mut self, datagram: Bytes) -> Result<(), TuicUdpDatagramSendFailure> {
            self.attempts.push(datagram.to_vec());
            if self.forced_too_large_attempt == Some(self.attempts.len())
                || datagram.len() > self.max_wire_size
            {
                return Err(TuicUdpDatagramSendFailure::TooLarge);
            }
            self.successful.push(datagram.to_vec());
            if let Some((successful_count, reduced)) = self.shrink_after_success
                && self.successful.len() == successful_count
            {
                self.max_wire_size = reduced;
            }
            Ok(())
        }
    }

    fn resources() -> QuicUdpDatagramResourceProfile {
        QuicUdpDatagramResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
    }

    fn packet_ids() -> QuicUdpPacketIdAllocator {
        QuicUdpPacketIdAllocator::new(resources())
    }

    #[test]
    fn payload_matrix_uses_canonical_fragment_shape() {
        for target in ["192.0.2.1:53", "[2001:db8::1]:53"] {
            for payload_len in [1_400, 1_500, 4_096] {
                let payload = vec![payload_len as u8; payload_len];
                let packet = TuicUdpPacket::new(7, 1, target, &payload).unwrap();
                let mut sender = SizeBoundedSender::new(1_200);
                let report =
                    send_tuic_udp_packet_with(&mut sender, &packet, &mut packet_ids(), resources())
                        .unwrap();
                assert!(!report.whole_datagram_sent);
                assert_eq!(report.fragment_layouts, 1);
                let decoded = sender
                    .successful
                    .iter()
                    .map(|datagram| decode_tuic_udp_packet(datagram).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(decoded[0].target(), Some(target));
                assert!(
                    decoded
                        .iter()
                        .skip(1)
                        .all(|fragment| fragment.target().is_none())
                );
                let reassembled = decoded
                    .iter()
                    .flat_map(|fragment| fragment.payload().iter().copied())
                    .collect::<Vec<_>>();
                assert_eq!(reassembled, payload);
            }
        }
    }

    #[test]
    fn lower_pmtu_restarts_with_a_new_packet_id() {
        let packet = TuicUdpPacket::new(8, 1, "192.0.2.2:5353", vec![5; 4_096]).unwrap();
        let mut sender = SizeBoundedSender::new(1_250);
        sender.shrink_after_success = Some((1, 900));
        let report =
            send_tuic_udp_packet_with(&mut sender, &packet, &mut packet_ids(), resources())
                .unwrap();
        assert_eq!(report.fragment_layouts, 2);
        assert_eq!(report.final_max_wire_size, Some(900));
        let decoded = sender
            .successful
            .iter()
            .map(|datagram| decode_tuic_udp_packet(datagram).unwrap())
            .collect::<Vec<_>>();
        assert_ne!(decoded[0].packet_id(), decoded.last().unwrap().packet_id());
    }

    #[test]
    fn repeated_too_large_without_a_lower_limit_fails_closed() {
        let packet = TuicUdpPacket::new(9, 1, "192.0.2.3:53", vec![3; 4_096]).unwrap();
        let mut sender = SizeBoundedSender::new(1_250);
        sender.forced_too_large_attempt = Some(3);
        let err = send_tuic_udp_packet_with(&mut sender, &packet, &mut packet_ids(), resources())
            .unwrap_err();
        assert!(err.contains("did not decrease"));
    }
}
