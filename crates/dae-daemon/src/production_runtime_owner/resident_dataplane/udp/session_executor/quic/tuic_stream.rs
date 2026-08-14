use super::*;

pub(super) async fn send_tuic_udp_stream_packet(
    connection: &quinn::Connection,
    packet: &TuicUdpPacket,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<(), String> {
    let encoded = encode_tuic_udp_stream_packet(packet)
        .map_err(|err| format!("encode TUIC UDP stream packet: {err}"))?;
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or_else(|| "TUIC UDP stream packet deadline elapsed".to_owned())?;
    time::timeout(remaining, async {
        let mut stream = connection
            .open_uni()
            .await
            .map_err(|err| format!("open TUIC UDP packet stream: {err}"))?;
        stream
            .write_all(&encoded)
            .await
            .map_err(|err| format!("write TUIC UDP packet stream: {err}"))?;
        stream
            .finish()
            .map_err(|err| format!("finish TUIC UDP packet stream: {err}"))?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "TUIC UDP stream packet deadline elapsed".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_mode_encodes_one_complete_packet_without_datagram_fragmentation() {
        let payload = vec![7_u8; u16::MAX as usize];
        let packet = TuicUdpPacket::new(9, 11, "[2001:db8::1]:5353", &payload).unwrap();
        let encoded = encode_tuic_udp_stream_packet(&packet).unwrap();
        let decoded = dae_outbound::tuic::decode_tuic_udp_stream_packet(&encoded).unwrap();
        assert_eq!(decoded.association_id(), 9);
        assert_eq!(decoded.packet_id(), 11);
        assert_eq!(decoded.fragment_count(), 1);
        assert_eq!(decoded.fragment_id(), 0);
        assert_eq!(decoded.target(), Some("[2001:db8::1]:5353"));
        assert_eq!(decoded.payload(), payload);
    }
}
