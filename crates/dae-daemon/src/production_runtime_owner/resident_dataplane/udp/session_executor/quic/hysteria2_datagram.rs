use super::*;

#[derive(Debug)]
enum Hysteria2UdpDatagramSendFailure {
    TooLarge,
    Fatal(String),
}

trait Hysteria2UdpDatagramSender {
    fn max_datagram_size(&self) -> Option<usize>;

    fn send_datagram(&mut self, datagram: Bytes) -> Result<(), Hysteria2UdpDatagramSendFailure>;
}

impl Hysteria2UdpDatagramSender for quinn::Connection {
    fn max_datagram_size(&self) -> Option<usize> {
        quinn::Connection::max_datagram_size(self)
    }

    fn send_datagram(&mut self, datagram: Bytes) -> Result<(), Hysteria2UdpDatagramSendFailure> {
        quinn::Connection::send_datagram(self, datagram).map_err(|err| match err {
            quinn::SendDatagramError::TooLarge => Hysteria2UdpDatagramSendFailure::TooLarge,
            other => Hysteria2UdpDatagramSendFailure::Fatal(other.to_string()),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct Hysteria2UdpSendReport {
    pub(super) whole_datagram_sent: bool,
    pub(super) datagrams_sent: usize,
    pub(super) fragment_layouts: usize,
    pub(super) final_max_wire_size: Option<usize>,
}

pub(super) fn send_hysteria2_udp_message(
    connection: &quinn::Connection,
    message: &Hysteria2UdpMessage,
    packet_ids: &mut QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
) -> Result<Hysteria2UdpSendReport, String> {
    let mut connection = connection.clone();
    send_hysteria2_udp_message_with(&mut connection, message, packet_ids, resources)
}

fn send_hysteria2_udp_message_with<S>(
    sender: &mut S,
    message: &Hysteria2UdpMessage,
    packet_ids: &mut QuicUdpPacketIdAllocator,
    resources: QuicUdpDatagramResourceProfile,
) -> Result<Hysteria2UdpSendReport, String>
where
    S: Hysteria2UdpDatagramSender,
{
    let whole = encode_hysteria2_udp_message(message)
        .map_err(|err| format!("encode complete Hysteria2 UDP datagram: {err}"))?;
    match sender.send_datagram(Bytes::from(whole)) {
        Ok(()) => {
            return Ok(Hysteria2UdpSendReport {
                whole_datagram_sent: true,
                datagrams_sent: 1,
                fragment_layouts: 0,
                final_max_wire_size: sender.max_datagram_size(),
            });
        }
        Err(Hysteria2UdpDatagramSendFailure::TooLarge) => {}
        Err(Hysteria2UdpDatagramSendFailure::Fatal(err)) => {
            return Err(format!("send complete Hysteria2 UDP datagram: {err}"));
        }
    }

    let mut max_wire_size = sender.max_datagram_size().ok_or_else(|| {
        "Hysteria2 peer disabled QUIC datagrams after reporting an oversized datagram".to_owned()
    })?;
    let mut datagrams_sent = 0_usize;
    for fragment_layout in 1..=resources.pmtu_retries() {
        let packet_id = packet_ids.allocate()?;
        let fragments =
            fragment_hysteria2_udp_message(message, packet_id, max_wire_size).map_err(|err| {
                format!(
                    "fragment Hysteria2 UDP datagram for {max_wire_size}-byte QUIC limit: {err}"
                )
            })?;
        let mut restart_max_wire_size = None;
        for fragment in fragments {
            let encoded = encode_hysteria2_udp_message(&fragment)
                .map_err(|err| format!("encode Hysteria2 UDP fragment: {err}"))?;
            match sender.send_datagram(Bytes::from(encoded)) {
                Ok(()) => datagrams_sent = datagrams_sent.saturating_add(1),
                Err(Hysteria2UdpDatagramSendFailure::Fatal(err)) => {
                    return Err(format!("send Hysteria2 UDP fragment: {err}"));
                }
                Err(Hysteria2UdpDatagramSendFailure::TooLarge) => {
                    let reduced = sender.max_datagram_size().ok_or_else(|| {
                        "Hysteria2 peer disabled QUIC datagrams during PMTU retry".to_owned()
                    })?;
                    if reduced >= max_wire_size {
                        return Err(format!(
                            "Hysteria2 QUIC datagram limit did not decrease after TooLarge: {max_wire_size} -> {reduced}"
                        ));
                    }
                    restart_max_wire_size = Some(reduced);
                    break;
                }
            }
        }
        let Some(reduced) = restart_max_wire_size else {
            return Ok(Hysteria2UdpSendReport {
                whole_datagram_sent: false,
                datagrams_sent,
                fragment_layouts: fragment_layout,
                final_max_wire_size: Some(max_wire_size),
            });
        };
        max_wire_size = reduced;
    }
    Err(format!(
        "Hysteria2 UDP PMTU retry budget exhausted after {} fragment layouts",
        resources.pmtu_retries()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::ResidentRuntimeProfile;

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

    impl Hysteria2UdpDatagramSender for SizeBoundedSender {
        fn max_datagram_size(&self) -> Option<usize> {
            Some(self.max_wire_size)
        }

        fn send_datagram(
            &mut self,
            datagram: Bytes,
        ) -> Result<(), Hysteria2UdpDatagramSendFailure> {
            self.attempts.push(datagram.to_vec());
            if self.forced_too_large_attempt == Some(self.attempts.len())
                || datagram.len() > self.max_wire_size
            {
                return Err(Hysteria2UdpDatagramSendFailure::TooLarge);
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
    fn whole_datagram_is_attempted_before_fragmentation() {
        let message = Hysteria2UdpMessage::new(7, "192.0.2.1:53", b"dns-query").unwrap();
        let mut sender = SizeBoundedSender::new(1_250);
        let report =
            send_hysteria2_udp_message_with(&mut sender, &message, &mut packet_ids(), resources())
                .unwrap();
        assert!(report.whole_datagram_sent);
        assert_eq!(report.datagrams_sent, 1);
        assert_eq!(report.fragment_layouts, 0);
        let decoded = decode_hysteria2_udp_message(&sender.successful[0]).unwrap();
        assert_eq!(decoded.packet_id(), 0);
        assert_eq!(decoded.fragment_count(), 1);
    }

    #[test]
    fn payload_matrix_fragments_with_ipv4_and_ipv6_targets() {
        for target in ["192.0.2.1:53", "[2001:db8::1]:53"] {
            let payload_capacity = hysteria2_udp_payload_capacity(target).unwrap();
            for payload_len in [1_250, 1_400, 1_500, payload_capacity] {
                let payload = vec![payload_len as u8; payload_len];
                let message = Hysteria2UdpMessage::new(9, target, &payload).unwrap();
                let mut sender = SizeBoundedSender::new(1_200);
                let report = send_hysteria2_udp_message_with(
                    &mut sender,
                    &message,
                    &mut packet_ids(),
                    resources(),
                )
                .unwrap();
                assert!(!report.whole_datagram_sent);
                assert_eq!(report.fragment_layouts, 1);
                let mut decoded = sender
                    .successful
                    .iter()
                    .map(|datagram| decode_hysteria2_udp_message(datagram).unwrap())
                    .collect::<Vec<_>>();
                decoded.sort_by_key(Hysteria2UdpMessage::fragment_id);
                assert!(decoded.len() > 1);
                assert!(decoded.iter().all(|fragment| fragment.target() == target));
                assert!(decoded.iter().all(|fragment| fragment.packet_id() != 0));
                assert!(
                    decoded
                        .iter()
                        .all(|fragment| fragment.encoded_len() <= 1_200)
                );
                let reassembled = decoded
                    .iter()
                    .flat_map(|fragment| fragment.payload().iter().copied())
                    .collect::<Vec<_>>();
                assert_eq!(reassembled, payload);
            }
        }
        assert!(Hysteria2UdpMessage::new(1, "192.0.2.1:53", []).is_err());
    }

    #[test]
    fn reduced_pmtu_restarts_from_original_payload_with_new_packet_id() {
        let target = "[2001:db8::2]:5353";
        let payload = vec![5; hysteria2_udp_payload_capacity(target).unwrap()];
        let message = Hysteria2UdpMessage::new(11, target, &payload).unwrap();
        let mut sender = SizeBoundedSender::new(1_250);
        sender.shrink_after_success = Some((1, 900));
        let report =
            send_hysteria2_udp_message_with(&mut sender, &message, &mut packet_ids(), resources())
                .unwrap();
        assert_eq!(report.fragment_layouts, 2);
        assert_eq!(report.final_max_wire_size, Some(900));

        let decoded = sender
            .successful
            .iter()
            .map(|datagram| decode_hysteria2_udp_message(datagram).unwrap())
            .collect::<Vec<_>>();
        let first_packet_id = decoded[0].packet_id();
        let final_packet_id = decoded.last().unwrap().packet_id();
        assert_ne!(first_packet_id, final_packet_id);
        assert_eq!(
            decoded
                .iter()
                .filter(|fragment| fragment.packet_id() == first_packet_id)
                .count(),
            1
        );
        let mut final_fragments = decoded
            .iter()
            .filter(|fragment| fragment.packet_id() == final_packet_id)
            .collect::<Vec<_>>();
        final_fragments.sort_by_key(|fragment| fragment.fragment_id());
        assert_eq!(
            final_fragments.len(),
            final_fragments[0].fragment_count() as usize
        );
        let reassembled = final_fragments
            .iter()
            .flat_map(|fragment| fragment.payload().iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn repeated_too_large_without_lower_limit_fails_closed() {
        let target = "192.0.2.2:53";
        let message = Hysteria2UdpMessage::new(
            13,
            target,
            vec![3; hysteria2_udp_payload_capacity(target).unwrap()],
        )
        .unwrap();
        let mut sender = SizeBoundedSender::new(1_250);
        sender.forced_too_large_attempt = Some(3);
        let err =
            send_hysteria2_udp_message_with(&mut sender, &message, &mut packet_ids(), resources())
                .unwrap_err();
        assert!(err.contains("did not decrease"));
    }
}
