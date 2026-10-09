use super::*;
use dae_resident_core::ResidentRuntimeProfile;

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
    for expected in 1..=(resources().packet_id_lease_ranges() * 64 - 1) as u16 {
        assert_eq!(allocator.allocate_at(now).unwrap(), expected);
    }

    assert!(
        allocator
            .allocate_at(now)
            .unwrap_err()
            .contains("lease range budget is full")
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

#[test]
fn range_deadline_never_releases_its_newer_ids_early() {
    let now = Instant::now();
    let mut ids = allocator();
    assert_eq!(ids.allocate_at(now).unwrap(), 1);
    let later = now + std::time::Duration::from_secs(1);
    assert_eq!(ids.allocate_at(later).unwrap(), 2);
    ids.expire_at(now + resources().packet_id_lease_ttl());
    assert!(ids.is_leased(1));
    assert!(ids.is_leased(2));
    ids.expire_at(later + resources().packet_id_lease_ttl());
    assert!(!ids.is_leased(1));
    assert!(!ids.is_leased(2));
}

#[test]
fn balanced_profile_covers_the_wire_id_space_without_increasing_record_size() {
    let resources =
        QuicUdpDatagramResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
    let mut ids = QuicUdpPacketIdAllocator::new(resources);
    let now = Instant::now();
    for expected in 1..=u16::MAX {
        assert_eq!(ids.allocate_at(now).unwrap(), expected);
    }
    assert_eq!(ids.leases.len(), 1024);
    assert!(std::mem::size_of::<QuicUdpPacketIdLease>() <= std::mem::size_of::<(u16, Instant)>());
    assert!(
        ids.allocate_at(now)
            .unwrap_err()
            .contains("window is exhausted")
    );
    assert_eq!(
        ids.allocate_at(now + resources.packet_id_lease_ttl())
            .unwrap(),
        1
    );
    assert_eq!(
        ids.bitmap
            .as_ref()
            .unwrap()
            .iter()
            .map(|word| word.count_ones())
            .sum::<u32>(),
        1
    );
}

#[test]
fn sustained_allocation_wraps_without_reusing_unexpired_ids() {
    let resources =
        QuicUdpDatagramResourceProfile::from_runtime_profile(ResidentRuntimeProfile::Balanced);
    let mut ids = QuicUdpPacketIdAllocator::new(resources);
    let start = Instant::now();
    let mut seen = vec![None; usize::from(u16::MAX) + 1];
    for step in 0..140_000_u64 {
        let now = start + std::time::Duration::from_micros(step * 300);
        let id = usize::from(ids.allocate_at(now).unwrap());
        if let Some(previous) = seen[id] {
            assert!(now >= previous + resources.packet_id_lease_ttl());
        }
        seen[id] = Some(now);
        assert!(ids.leases.len() <= resources.packet_id_lease_ranges());
    }
    assert_eq!(
        ids.leased_ids,
        ids.bitmap
            .as_ref()
            .unwrap()
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum::<usize>()
    );
}
