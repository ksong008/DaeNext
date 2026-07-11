use std::collections::VecDeque;
use std::time::Instant;

use crate::production_runtime_owner::resident_dataplane::RESIDENT_UDP_RESPONSE_TIMEOUT;

const QUIC_UDP_PACKET_ID_BITMAP_WORD_BITS: usize = u64::BITS as usize;
const QUIC_UDP_PACKET_ID_BITMAP_WORDS: usize =
    (u16::MAX as usize + 1) / QUIC_UDP_PACKET_ID_BITMAP_WORD_BITS;
const QUIC_UDP_PACKET_ID_LEASE_TTL: std::time::Duration = RESIDENT_UDP_RESPONSE_TIMEOUT;

struct QuicUdpPacketIdLease {
    packet_id: u16,
    expires_at: Instant,
}

pub(super) struct QuicUdpPacketIdAllocator {
    next: u16,
    bitmap: Option<Box<[u64]>>,
    leases: VecDeque<QuicUdpPacketIdLease>,
}

impl Default for QuicUdpPacketIdAllocator {
    fn default() -> Self {
        Self {
            next: 1,
            bitmap: None,
            leases: VecDeque::new(),
        }
    }
}

impl QuicUdpPacketIdAllocator {
    pub(super) fn allocate(&mut self) -> Result<u16, String> {
        self.allocate_at(Instant::now())
    }

    fn allocate_at(&mut self, now: Instant) -> Result<u16, String> {
        self.expire_at(now);
        for _ in 0..usize::from(u16::MAX) {
            let packet_id = self.next;
            self.next = if packet_id == u16::MAX {
                1
            } else {
                packet_id + 1
            };
            if self.is_leased(packet_id) {
                continue;
            }
            self.set_leased(packet_id, true);
            self.leases.push_back(QuicUdpPacketIdLease {
                packet_id,
                expires_at: now.checked_add(QUIC_UDP_PACKET_ID_LEASE_TTL).unwrap_or(now),
            });
            return Ok(packet_id);
        }
        Err("QUIC UDP packet ID lease window is exhausted".to_owned())
    }

    fn expire_at(&mut self, now: Instant) {
        while self
            .leases
            .front()
            .is_some_and(|lease| lease.expires_at <= now)
        {
            if let Some(lease) = self.leases.pop_front() {
                self.set_leased(lease.packet_id, false);
            }
        }
    }

    fn is_leased(&self, packet_id: u16) -> bool {
        let Some(bitmap) = self.bitmap.as_ref() else {
            return false;
        };
        let index = packet_id as usize;
        bitmap[index / QUIC_UDP_PACKET_ID_BITMAP_WORD_BITS]
            & (1_u64 << (index % QUIC_UDP_PACKET_ID_BITMAP_WORD_BITS))
            != 0
    }

    fn set_leased(&mut self, packet_id: u16, leased: bool) {
        let bitmap = self
            .bitmap
            .get_or_insert_with(|| vec![0_u64; QUIC_UDP_PACKET_ID_BITMAP_WORDS].into_boxed_slice());
        let index = packet_id as usize;
        let word = &mut bitmap[index / QUIC_UDP_PACKET_ID_BITMAP_WORD_BITS];
        let mask = 1_u64 << (index % QUIC_UDP_PACKET_ID_BITMAP_WORD_BITS);
        if leased {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }

    pub(super) fn clear(&mut self) {
        self.next = 1;
        self.bitmap = None;
        self.leases.clear();
    }
}

#[cfg(test)]
mod tests;
