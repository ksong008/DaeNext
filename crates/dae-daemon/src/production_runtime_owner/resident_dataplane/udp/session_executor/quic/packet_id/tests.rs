use super::*;

#[test]
fn active_packet_ids_are_unique_until_the_lease_window_is_full() {
    let now = Instant::now();
    let mut allocator = QuicUdpPacketIdAllocator::default();
    for expected in 1..=u16::MAX {
        assert_eq!(allocator.allocate_at(now).unwrap(), expected);
    }

    assert!(
        allocator
            .allocate_at(now)
            .unwrap_err()
            .contains("exhausted")
    );
}

#[test]
fn expired_packet_ids_are_reused_in_allocator_order() {
    let now = Instant::now();
    let mut allocator = QuicUdpPacketIdAllocator::default();
    assert_eq!(allocator.allocate_at(now).unwrap(), 1);
    assert_eq!(allocator.allocate_at(now).unwrap(), 2);
    allocator.next = 1;

    assert_eq!(allocator.allocate_at(now).unwrap(), 3);
    allocator.next = 1;
    assert_eq!(
        allocator
            .allocate_at(now + QUIC_UDP_PACKET_ID_LEASE_TTL)
            .unwrap(),
        1
    );
}

#[test]
fn clear_releases_bitmap_and_restarts_sequence() {
    let mut allocator = QuicUdpPacketIdAllocator::default();
    assert_eq!(allocator.allocate().unwrap(), 1);
    assert!(allocator.bitmap.is_some());

    allocator.clear();

    assert!(allocator.bitmap.is_none());
    assert!(allocator.leases.is_empty());
    assert_eq!(allocator.allocate().unwrap(), 1);
}
