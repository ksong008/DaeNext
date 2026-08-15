use std::collections::BTreeMap;
use std::time::Instant;

use crate::QuicUdpDatagramResourceProfile;

#[derive(Debug)]
pub(super) enum QuicUdpFragmentOutcome {
    Pending,
    Complete(Vec<u8>),
    Late(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct QuicUdpFragmentBufferSnapshot {
    pub(super) pending_packets: usize,
    pub(super) pending_bytes: usize,
    pub(super) quarantined_packets: usize,
    pub(super) high_water_packets: usize,
    pub(super) high_water_bytes: usize,
    pub(super) accepted_fragments: u64,
    pub(super) duplicate_fragments: u64,
    pub(super) expired_packets: u64,
    pub(super) late_fragments: u64,
    pub(super) rejected_fragments: u64,
    pub(super) rejected_bytes: u64,
}

pub(super) struct QuicUdpFragmentBuffer {
    resources: QuicUdpDatagramResourceProfile,
    max_reassembled_bytes: usize,
    pending: BTreeMap<u16, PendingQuicUdpFragments>,
    pending_bytes: usize,
    quarantined: BTreeMap<u16, Instant>,
    high_water_packets: usize,
    high_water_bytes: usize,
    accepted_fragments: u64,
    duplicate_fragments: u64,
    expired_packets: u64,
    late_fragments: u64,
    rejected_fragments: u64,
    rejected_bytes: u64,
}

struct PendingQuicUdpFragments {
    total: u8,
    parts: BTreeMap<u8, Vec<u8>>,
    bytes: usize,
    reassembly_limit: usize,
    expires_at: Instant,
}

struct QuicUdpFragmentInput {
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    payload: Vec<u8>,
}

impl QuicUdpFragmentBuffer {
    pub(super) fn new(
        resources: QuicUdpDatagramResourceProfile,
        max_reassembled_bytes: usize,
    ) -> Self {
        Self {
            resources,
            max_reassembled_bytes,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            quarantined: BTreeMap::new(),
            high_water_packets: 0,
            high_water_bytes: 0,
            accepted_fragments: 0,
            duplicate_fragments: 0,
            expired_packets: 0,
            late_fragments: 0,
            rejected_fragments: 0,
            rejected_bytes: 0,
        }
    }

    pub(super) fn push(
        &mut self,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        payload: Vec<u8>,
        label: &str,
    ) -> Result<QuicUdpFragmentOutcome, String> {
        self.push_with_reassembly_limit(
            packet_id,
            fragment_id,
            fragment_count,
            payload,
            self.max_reassembled_bytes,
            label,
        )
    }

    pub(super) fn push_with_reassembly_limit(
        &mut self,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        payload: Vec<u8>,
        reassembly_limit: usize,
        label: &str,
    ) -> Result<QuicUdpFragmentOutcome, String> {
        self.push_at_with_reassembly_limit(
            Instant::now(),
            QuicUdpFragmentInput {
                packet_id,
                fragment_id,
                fragment_count,
                payload,
            },
            reassembly_limit,
            label,
        )
    }

    #[cfg(test)]
    fn push_at(
        &mut self,
        now: Instant,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        payload: Vec<u8>,
        label: &str,
    ) -> Result<QuicUdpFragmentOutcome, String> {
        self.push_at_with_reassembly_limit(
            now,
            QuicUdpFragmentInput {
                packet_id,
                fragment_id,
                fragment_count,
                payload,
            },
            self.max_reassembled_bytes,
            label,
        )
    }

    fn push_at_with_reassembly_limit(
        &mut self,
        now: Instant,
        fragment: QuicUdpFragmentInput,
        reassembly_limit: usize,
        label: &str,
    ) -> Result<QuicUdpFragmentOutcome, String> {
        let QuicUdpFragmentInput {
            packet_id,
            fragment_id,
            fragment_count,
            payload,
        } = fragment;
        if fragment_count == 0 || fragment_id >= fragment_count {
            self.reject(payload.len());
            return Err(format!(
                "invalid {label} UDP fragment fields: fragment_id={fragment_id} fragment_count={fragment_count}"
            ));
        }
        if payload.is_empty() {
            self.reject(0);
            return Err(format!("empty {label} UDP fragment payload"));
        }
        self.expire_at(now);
        let reassembly_limit = reassembly_limit.min(self.max_reassembled_bytes);
        if reassembly_limit == 0 {
            if self.pending.contains_key(&packet_id) {
                self.remove_pending(packet_id);
                self.quarantine(packet_id, now);
            }
            self.reject(payload.len());
            return Err(format!("{label} UDP reassembly limit is zero"));
        }
        if fragment_count == 1 {
            if payload.len() > reassembly_limit {
                self.reject(payload.len());
                return Err(format!(
                    "{label} UDP payload exceeds reassembly budget: {} > {} bytes",
                    payload.len(),
                    reassembly_limit
                ));
            }
            return Ok(QuicUdpFragmentOutcome::Complete(payload));
        }
        if self.quarantined.contains_key(&packet_id) {
            self.late_fragments = self.late_fragments.saturating_add(1);
            return Ok(QuicUdpFragmentOutcome::Late(payload));
        }
        if let Some(entry) = self.pending.get(&packet_id)
            && entry.total != fragment_count
        {
            let previous = entry.total;
            self.remove_pending(packet_id);
            self.quarantine(packet_id, now);
            self.reject(payload.len());
            return Err(format!(
                "{label} UDP fragment count changed for packet {packet_id}: {previous} -> {fragment_count}"
            ));
        }

        let reassembly_limit = self
            .pending
            .get(&packet_id)
            .map_or(reassembly_limit, |entry| {
                entry.reassembly_limit.min(reassembly_limit)
            });
        if let Some(previous_bytes) = self.pending.get(&packet_id).map(|entry| entry.bytes)
            && previous_bytes > reassembly_limit
        {
            self.remove_pending(packet_id);
            self.quarantine(packet_id, now);
            self.reject(payload.len());
            return Err(format!(
                "{label} UDP reassembly budget decreased below buffered payload: {previous_bytes} > {reassembly_limit} bytes"
            ));
        }

        let is_new_packet = !self.pending.contains_key(&packet_id);
        if is_new_packet && self.pending.len() >= self.resources.pending_fragment_packets() {
            self.reject(payload.len());
            return Err(format!("{label} UDP fragment packet budget is full"));
        }
        let previous_fragment_bytes = self
            .pending
            .get(&packet_id)
            .and_then(|entry| entry.parts.get(&fragment_id))
            .map_or(0, Vec::len);
        let previous_packet_bytes = self.pending.get(&packet_id).map_or(0, |entry| entry.bytes);
        let next_packet_bytes = previous_packet_bytes
            .checked_sub(previous_fragment_bytes)
            .and_then(|bytes| bytes.checked_add(payload.len()))
            .ok_or_else(|| format!("{label} UDP fragment byte accounting overflow"))?;
        if next_packet_bytes > reassembly_limit {
            self.remove_pending(packet_id);
            self.quarantine(packet_id, now);
            self.reject(payload.len());
            return Err(format!(
                "{label} UDP reassembled payload exceeds budget: {next_packet_bytes} > {} bytes",
                reassembly_limit
            ));
        }
        let next_pending_bytes = self
            .pending_bytes
            .checked_sub(previous_fragment_bytes)
            .and_then(|bytes| bytes.checked_add(payload.len()))
            .ok_or_else(|| format!("{label} UDP global fragment byte accounting overflow"))?;
        if next_pending_bytes > self.resources.pending_fragment_bytes() {
            self.reject(payload.len());
            return Err(format!(
                "{label} UDP fragment byte budget exceeded: {next_pending_bytes} > {} bytes",
                self.resources.pending_fragment_bytes()
            ));
        }

        let expires_at = now
            .checked_add(self.resources.fragment_ttl())
            .unwrap_or(now);
        let complete = {
            let entry = self
                .pending
                .entry(packet_id)
                .or_insert_with(|| PendingQuicUdpFragments {
                    total: fragment_count,
                    parts: BTreeMap::new(),
                    bytes: 0,
                    reassembly_limit,
                    expires_at,
                });
            entry.reassembly_limit = entry.reassembly_limit.min(reassembly_limit);
            if entry.parts.insert(fragment_id, payload).is_some() {
                self.duplicate_fragments = self.duplicate_fragments.saturating_add(1);
            }
            entry.bytes = next_packet_bytes;
            entry.parts.len() == fragment_count as usize
        };
        self.pending_bytes = next_pending_bytes;
        self.accepted_fragments = self.accepted_fragments.saturating_add(1);
        self.high_water_packets = self.high_water_packets.max(self.pending.len());
        self.high_water_bytes = self.high_water_bytes.max(self.pending_bytes);
        if !complete {
            return Ok(QuicUdpFragmentOutcome::Pending);
        }

        let entry = self
            .pending
            .remove(&packet_id)
            .ok_or_else(|| format!("{label} UDP fragment packet disappeared"))?;
        self.pending_bytes = self.pending_bytes.saturating_sub(entry.bytes);
        self.quarantine(packet_id, now);
        let mut out = Vec::with_capacity(entry.bytes);
        for id in 0..entry.total {
            let part = entry.parts.get(&id).ok_or_else(|| {
                format!("{label} UDP fragment packet {packet_id} missing fragment {id}")
            })?;
            out.extend_from_slice(part);
        }
        Ok(QuicUdpFragmentOutcome::Complete(out))
    }

    pub(super) fn next_expiration(&self) -> Option<Instant> {
        self.pending.values().map(|entry| entry.expires_at).min()
    }

    pub(super) fn contains_pending(&self, packet_id: u16) -> bool {
        self.pending.contains_key(&packet_id)
    }

    pub(super) fn expire(&mut self) {
        self.expire_at(Instant::now());
    }

    fn expire_at(&mut self, now: Instant) {
        let expired: Vec<u16> = self
            .pending
            .iter()
            .filter_map(|(packet_id, entry)| (entry.expires_at <= now).then_some(*packet_id))
            .collect();
        for packet_id in expired {
            self.remove_pending(packet_id);
            self.quarantine(packet_id, now);
            self.expired_packets = self.expired_packets.saturating_add(1);
        }
        self.quarantined.retain(|_, expires_at| *expires_at > now);
    }

    fn remove_pending(&mut self, packet_id: u16) {
        if let Some(entry) = self.pending.remove(&packet_id) {
            self.pending_bytes = self.pending_bytes.saturating_sub(entry.bytes);
        }
    }

    fn quarantine(&mut self, packet_id: u16, now: Instant) {
        let limit = self.resources.pending_fragment_packets();
        if !self.quarantined.contains_key(&packet_id) && self.quarantined.len() >= limit {
            let oldest = self
                .quarantined
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(packet_id, _)| *packet_id);
            if let Some(oldest) = oldest {
                self.quarantined.remove(&oldest);
            }
        }
        let expires_at = now
            .checked_add(self.resources.fragment_quarantine_ttl())
            .unwrap_or(now);
        self.quarantined.insert(packet_id, expires_at);
    }

    fn reject(&mut self, bytes: usize) {
        self.rejected_fragments = self.rejected_fragments.saturating_add(1);
        self.rejected_bytes = self.rejected_bytes.saturating_add(bytes as u64);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn snapshot(&self) -> QuicUdpFragmentBufferSnapshot {
        QuicUdpFragmentBufferSnapshot {
            pending_packets: self.pending.len(),
            pending_bytes: self.pending_bytes,
            quarantined_packets: self.quarantined.len(),
            high_water_packets: self.high_water_packets,
            high_water_bytes: self.high_water_bytes,
            accepted_fragments: self.accepted_fragments,
            duplicate_fragments: self.duplicate_fragments,
            expired_packets: self.expired_packets,
            late_fragments: self.late_fragments,
            rejected_fragments: self.rejected_fragments,
            rejected_bytes: self.rejected_bytes,
        }
    }

    pub(super) fn clear(&mut self) {
        self.pending.clear();
        self.pending_bytes = 0;
        self.quarantined.clear();
    }
}

#[cfg(test)]
mod tests;
