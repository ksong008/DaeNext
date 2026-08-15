use super::*;
use crate::ResidentRuntimeProfile;

fn resources() -> QuicUdpDatagramResourceProfile {
    QuicUdpDatagramResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory)
}

fn allocator() -> QuicUdpPacketIdAllocator {
    QuicUdpPacketIdAllocator::new(resources())
}

#[test]
fn active_packet_ids_are_unique_until_the_lease_window_is_full() {
    let now = Instant::now();
    let mut allocator = allocator();
    for expected in 1..=resources().packet_id_leases() as u16 {
        assert_eq!(allocator.allocate_at(now).unwrap(), expected);
    }

    assert!(
        allocator
            .allocate_at(now)
            .unwrap_err()
            .contains("lease budget is full")
    );
}

#[test]
fn expired_packet_ids_are_reused_in_allocator_order() {
    let now = Instant::now();
    let mut allocator = allocator();
    assert_eq!(allocator.allocate_at(now).unwrap(), 1);
    assert_eq!(allocator.allocate_at(now).unwrap(), 2);
    allocator.next = 1;

    assert_eq!(allocator.allocate_at(now).unwrap(), 3);
    allocator.next = 1;
    assert_eq!(
        allocator
            .allocate_at(now + resources().packet_id_lease_ttl())
            .unwrap(),
        1
    );
    assert_eq!(
        allocator.next_expiration(),
        Some(now + resources().packet_id_lease_ttl() * 2)
    );
}

#[test]
fn clear_releases_bitmap_and_restarts_sequence() {
    let mut allocator = allocator();
    assert_eq!(allocator.allocate().unwrap(), 1);
    assert!(allocator.bitmap.is_some());

    allocator.clear();

    assert!(allocator.bitmap.is_none());
    assert!(allocator.leases.is_empty());
    assert_eq!(allocator.allocate().unwrap(), 1);
}
