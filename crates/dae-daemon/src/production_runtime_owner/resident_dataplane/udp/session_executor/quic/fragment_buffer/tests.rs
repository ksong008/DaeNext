use super::*;

#[test]
fn fragments_reassemble_by_packet_id() {
    let mut buffer = QuicUdpFragmentBuffer::default();
    assert!(
        buffer
            .push(7, 1, 3, b"middle-".to_vec(), "Hysteria2")
            .unwrap()
            .is_none()
    );
    assert!(
        buffer
            .push(7, 2, 3, b"tail".to_vec(), "Hysteria2")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        buffer
            .push(7, 0, 3, b"head-".to_vec(), "Hysteria2")
            .unwrap()
            .unwrap(),
        b"head-middle-tail"
    );
}

#[test]
fn expired_incomplete_packets_no_longer_hold_capacity() {
    let now = Instant::now();
    let mut buffer = QuicUdpFragmentBuffer::default();
    for packet_id in 0..QUIC_UDP_FRAGMENT_MAX_PENDING as u16 {
        assert!(
            buffer
                .push_at(now, packet_id, 0, 2, vec![1], "TUIC")
                .unwrap()
                .is_none()
        );
    }
    assert!(
        buffer
            .push_at(
                now,
                QUIC_UDP_FRAGMENT_MAX_PENDING as u16,
                0,
                2,
                vec![2],
                "TUIC",
            )
            .unwrap_err()
            .contains("buffer is full")
    );

    assert!(
        buffer
            .push_at(
                now + QUIC_UDP_FRAGMENT_TTL,
                QUIC_UDP_FRAGMENT_MAX_PENDING as u16,
                0,
                2,
                vec![2],
                "TUIC",
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(buffer.pending.len(), 1);
}

#[test]
fn late_fragment_does_not_join_an_expired_packet() {
    let now = Instant::now();
    let mut buffer = QuicUdpFragmentBuffer::default();
    assert!(
        buffer
            .push_at(now, 9, 0, 2, b"old".to_vec(), "Hysteria2")
            .unwrap()
            .is_none()
    );

    assert!(
        buffer
            .push_at(
                now + QUIC_UDP_FRAGMENT_TTL,
                9,
                1,
                2,
                b"late".to_vec(),
                "Hysteria2",
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(buffer.pending.get(&9).unwrap().parts.len(), 1);
}
