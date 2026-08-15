use super::*;
use crate::ResidentRuntimeProfile;

fn resources() -> QuicUdpDatagramResourceProfile {
    QuicUdpDatagramResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
}

fn buffer(max_reassembled_bytes: usize) -> QuicUdpFragmentBuffer {
    QuicUdpFragmentBuffer::new(resources(), max_reassembled_bytes)
}

#[test]
fn fragments_reassemble_by_packet_id() {
    let mut buffer = buffer(4_096);
    assert!(matches!(
        buffer
            .push(7, 1, 3, b"middle-".to_vec(), "Hysteria2")
            .unwrap(),
        QuicUdpFragmentOutcome::Pending
    ));
    assert!(matches!(
        buffer.push(7, 2, 3, b"tail".to_vec(), "Hysteria2").unwrap(),
        QuicUdpFragmentOutcome::Pending
    ));
    let outcome = buffer
        .push(7, 0, 3, b"head-".to_vec(), "Hysteria2")
        .unwrap();
    let QuicUdpFragmentOutcome::Complete(payload) = outcome else {
        panic!("complete fragment set must yield one payload");
    };
    assert_eq!(payload, b"head-middle-tail");
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.pending_packets, 0);
    assert_eq!(snapshot.pending_bytes, 0);
    assert_eq!(snapshot.quarantined_packets, 1);
    assert_eq!(snapshot.high_water_packets, 1);
    assert_eq!(snapshot.high_water_bytes, b"head-middle-tail".len());
}

#[test]
fn expired_incomplete_packets_release_count_and_bytes() {
    let now = Instant::now();
    let mut buffer = buffer(4_096);
    for packet_id in 0..resources().pending_fragment_packets() as u16 {
        assert!(matches!(
            buffer
                .push_at(now, packet_id, 0, 2, vec![1], "TUIC")
                .unwrap(),
            QuicUdpFragmentOutcome::Pending
        ));
    }
    assert!(
        buffer
            .push_at(
                now,
                resources().pending_fragment_packets() as u16,
                0,
                2,
                vec![2],
                "TUIC",
            )
            .unwrap_err()
            .contains("packet budget is full")
    );

    buffer.expire_at(now + resources().fragment_ttl());
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.pending_packets, 0);
    assert_eq!(snapshot.pending_bytes, 0);
    assert_eq!(
        snapshot.expired_packets,
        resources().pending_fragment_packets() as u64
    );
}

#[test]
fn late_fragment_is_quarantined_instead_of_starting_a_new_packet() {
    let now = Instant::now();
    let mut buffer = buffer(4_096);
    assert!(matches!(
        buffer
            .push_at(now, 9, 0, 2, b"old".to_vec(), "Hysteria2")
            .unwrap(),
        QuicUdpFragmentOutcome::Pending
    ));

    buffer.expire_at(now + resources().fragment_ttl());
    let outcome = buffer
        .push_at(
            now + resources().fragment_ttl(),
            9,
            1,
            2,
            b"late".to_vec(),
            "Hysteria2",
        )
        .unwrap();
    assert!(matches!(
        outcome,
        QuicUdpFragmentOutcome::Late(payload) if payload.len() == 4
    ));
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.pending_packets, 0);
    assert_eq!(snapshot.pending_bytes, 0);
    assert_eq!(snapshot.late_fragments, 1);
}

#[test]
fn duplicate_replacement_keeps_exact_byte_accounting() {
    let now = Instant::now();
    let mut buffer = buffer(4_096);
    assert!(matches!(
        buffer.push_at(now, 11, 0, 2, vec![1; 100], "TUIC").unwrap(),
        QuicUdpFragmentOutcome::Pending
    ));
    assert!(matches!(
        buffer.push_at(now, 11, 0, 2, vec![2; 10], "TUIC").unwrap(),
        QuicUdpFragmentOutcome::Pending
    ));
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.pending_packets, 1);
    assert_eq!(snapshot.pending_bytes, 10);
    assert_eq!(snapshot.duplicate_fragments, 1);

    let outcome = buffer.push_at(now, 11, 1, 2, vec![3; 20], "TUIC").unwrap();
    let QuicUdpFragmentOutcome::Complete(payload) = outcome else {
        panic!("replacement fragment set must complete");
    };
    assert_eq!(payload.len(), 30);
    assert_eq!(&payload[..10], &[2; 10]);
    assert_eq!(&payload[10..], &[3; 20]);
    assert_eq!(buffer.snapshot().pending_bytes, 0);
}

#[test]
fn lower_per_packet_limit_releases_and_quarantines_buffered_fragments() {
    let now = Instant::now();
    let mut buffer = buffer(4_096);
    assert!(matches!(
        buffer
            .push_at_with_reassembly_limit(
                now,
                QuicUdpFragmentInput {
                    packet_id: 17,
                    fragment_id: 0,
                    fragment_count: 3,
                    payload: vec![1; 80],
                },
                100,
                "Hysteria2",
            )
            .unwrap(),
        QuicUdpFragmentOutcome::Pending
    ));

    let error = buffer
        .push_at_with_reassembly_limit(
            now,
            QuicUdpFragmentInput {
                packet_id: 17,
                fragment_id: 1,
                fragment_count: 3,
                payload: vec![2; 5],
            },
            70,
            "Hysteria2",
        )
        .unwrap_err();
    assert!(error.contains("decreased below buffered payload"));
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.pending_packets, 0);
    assert_eq!(snapshot.pending_bytes, 0);
    assert_eq!(snapshot.quarantined_packets, 1);
    assert_eq!(snapshot.rejected_fragments, 1);
    assert_eq!(snapshot.rejected_bytes, 5);

    assert!(matches!(
        buffer
            .push_at_with_reassembly_limit(
                now,
                QuicUdpFragmentInput {
                    packet_id: 17,
                    fragment_id: 2,
                    fragment_count: 3,
                    payload: vec![3; 5],
                },
                100,
                "Hysteria2",
            )
            .unwrap(),
        QuicUdpFragmentOutcome::Late(payload) if payload.len() == 5
    ));
    assert_eq!(buffer.snapshot().pending_packets, 0);
}

#[test]
fn global_fragment_byte_budget_is_independent_from_packet_count() {
    let now = Instant::now();
    let mut buffer = buffer(u16::MAX as usize);
    for packet_id in [1, 2] {
        assert!(matches!(
            buffer
                .push_at(now, packet_id, 0, 2, vec![1; 60 * 1024], "TUIC")
                .unwrap(),
            QuicUdpFragmentOutcome::Pending
        ));
    }
    assert!(
        buffer
            .push_at(now, 3, 0, 2, vec![1; 60 * 1024], "TUIC")
            .unwrap_err()
            .contains("byte budget exceeded")
    );
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.pending_packets, 2);
    assert_eq!(snapshot.pending_bytes, 120 * 1024);
    assert_eq!(snapshot.rejected_fragments, 1);
    assert_eq!(snapshot.rejected_bytes, 60 * 1024);
}

#[test]
fn clear_reconciles_all_active_fragment_resources() {
    let mut buffer = buffer(4_096);
    assert!(matches!(
        buffer.push(12, 0, 2, vec![1; 512], "Hysteria2").unwrap(),
        QuicUdpFragmentOutcome::Pending
    ));
    buffer.clear();
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.pending_packets, 0);
    assert_eq!(snapshot.pending_bytes, 0);
    assert_eq!(snapshot.quarantined_packets, 0);
}
