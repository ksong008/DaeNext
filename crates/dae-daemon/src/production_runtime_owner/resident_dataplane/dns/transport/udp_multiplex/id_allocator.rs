use std::collections::VecDeque;
use std::time::Duration;

use super::*;

const DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS: usize = u64::BITS as usize;
const DNS_UDP_REQUEST_ID_BITMAP_WORDS: usize =
    DNS_UDP_REQUEST_ID_SPACE / DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS;

pub(in crate::production_runtime_owner::resident_dataplane) struct UdpRequestIdAllocator {
    occupied: [u64; DNS_UDP_REQUEST_ID_BITMAP_WORDS],
    quarantined: [u64; DNS_UDP_REQUEST_ID_BITMAP_WORDS],
    quarantine_deadlines: VecDeque<(u16, time::Instant)>,
    pub(super) next_id: u16,
    in_use: usize,
    quarantine_duration: Duration,
}

impl Default for UdpRequestIdAllocator {
    fn default() -> Self {
        Self::new(ResidentDnsUdpRuntimeConfig::standalone().attempt_timeout)
    }
}

impl UdpRequestIdAllocator {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        quarantine_duration: Duration,
    ) -> Self {
        Self {
            occupied: [0_u64; DNS_UDP_REQUEST_ID_BITMAP_WORDS],
            quarantined: [0_u64; DNS_UDP_REQUEST_ID_BITMAP_WORDS],
            quarantine_deadlines: VecDeque::new(),
            next_id: 0,
            in_use: 0,
            quarantine_duration,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn allocate(
        &mut self,
        capacity: usize,
    ) -> Result<u16, String> {
        self.allocate_at(capacity, time::Instant::now())
    }

    pub(super) fn allocate_at(
        &mut self,
        capacity: usize,
        now: time::Instant,
    ) -> Result<u16, String> {
        self.reap_quarantine(now);
        let capacity = capacity.min(DNS_UDP_REQUEST_ID_SPACE);
        if self.in_use >= capacity {
            return Err("DNS UDP multiplex pending queue is full".to_owned());
        }
        if self.in_use.saturating_add(self.quarantine_deadlines.len()) >= DNS_UDP_REQUEST_ID_SPACE {
            return Err("DNS UDP multiplex request id space is quarantined".to_owned());
        }
        for _ in 0..DNS_UDP_REQUEST_ID_SPACE {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if self.is_unavailable(candidate) {
                continue;
            }
            self.set_occupied(candidate, true);
            self.in_use += 1;
            return Ok(candidate);
        }
        Err("DNS UDP multiplex request id space is exhausted".to_owned())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn release(&mut self, id: u16) {
        self.release_at(id, time::Instant::now());
    }

    pub(super) fn release_at(&mut self, id: u16, now: time::Instant) {
        if !self.is_occupied(id) {
            return;
        }
        self.set_occupied(id, false);
        self.in_use = self.in_use.saturating_sub(1);
        self.set_quarantined(id, true);
        self.quarantine_deadlines
            .push_back((id, now + self.quarantine_duration));
    }

    pub(super) fn is_occupied(&self, id: u16) -> bool {
        let (word, bit) = dns_udp_request_id_bitmap_slot(id);
        self.occupied[word] & (1_u64 << bit) != 0
    }

    fn set_occupied(&mut self, id: u16, occupied: bool) {
        let (word, bit) = dns_udp_request_id_bitmap_slot(id);
        let mask = 1_u64 << bit;
        if occupied {
            self.occupied[word] |= mask;
        } else {
            self.occupied[word] &= !mask;
        }
    }

    fn is_unavailable(&self, id: u16) -> bool {
        self.is_occupied(id) || self.is_quarantined(id)
    }

    pub(super) fn is_quarantined(&self, id: u16) -> bool {
        let (word, bit) = dns_udp_request_id_bitmap_slot(id);
        self.quarantined[word] & (1_u64 << bit) != 0
    }

    fn set_quarantined(&mut self, id: u16, quarantined: bool) {
        let (word, bit) = dns_udp_request_id_bitmap_slot(id);
        let mask = 1_u64 << bit;
        if quarantined {
            self.quarantined[word] |= mask;
        } else {
            self.quarantined[word] &= !mask;
        }
    }

    pub(super) fn reap_quarantine(&mut self, now: time::Instant) {
        while self
            .quarantine_deadlines
            .front()
            .is_some_and(|(_, deadline)| *deadline <= now)
        {
            let Some((id, _)) = self.quarantine_deadlines.pop_front() else {
                break;
            };
            self.set_quarantined(id, false);
        }
    }
}

fn dns_udp_request_id_bitmap_slot(id: u16) -> (usize, usize) {
    let index = id as usize;
    (
        index / DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS,
        index % DNS_UDP_REQUEST_ID_BITMAP_WORD_BITS,
    )
}
