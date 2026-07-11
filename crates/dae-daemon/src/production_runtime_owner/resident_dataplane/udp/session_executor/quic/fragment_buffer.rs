use std::collections::BTreeMap;
use std::time::Instant;

use crate::production_runtime_owner::resident_dataplane::RESIDENT_UDP_RESPONSE_TIMEOUT;

const QUIC_UDP_FRAGMENT_MAX_PENDING: usize = 64;
const QUIC_UDP_FRAGMENT_TTL: std::time::Duration = RESIDENT_UDP_RESPONSE_TIMEOUT;

#[derive(Default)]
pub(super) struct QuicUdpFragmentBuffer {
    pending: BTreeMap<u16, PendingQuicUdpFragments>,
}

struct PendingQuicUdpFragments {
    total: u8,
    parts: BTreeMap<u8, Vec<u8>>,
    expires_at: Instant,
}

impl QuicUdpFragmentBuffer {
    pub(super) fn push(
        &mut self,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
        payload: Vec<u8>,
        label: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        self.push_at(
            Instant::now(),
            packet_id,
            frag_id,
            frag_count,
            payload,
            label,
        )
    }

    fn push_at(
        &mut self,
        now: Instant,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
        payload: Vec<u8>,
        label: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        if frag_count == 0 || frag_id >= frag_count {
            return Err(format!(
                "invalid {label} UDP fragment fields: frag_id={frag_id} frag_count={frag_count}"
            ));
        }
        self.expire_at(now);
        if frag_count == 1 {
            return Ok(Some(payload));
        }
        if !self.pending.contains_key(&packet_id)
            && self.pending.len() >= QUIC_UDP_FRAGMENT_MAX_PENDING
        {
            return Err(format!("{label} UDP fragment buffer is full"));
        }
        if let Some(entry) = self.pending.get(&packet_id)
            && entry.total != frag_count
        {
            let previous = entry.total;
            self.pending.remove(&packet_id);
            return Err(format!(
                "{label} UDP fragment count changed for packet {packet_id}: {previous} -> {frag_count}"
            ));
        }
        let expires_at = now.checked_add(QUIC_UDP_FRAGMENT_TTL).unwrap_or(now);
        let complete = {
            let entry = self
                .pending
                .entry(packet_id)
                .or_insert_with(|| PendingQuicUdpFragments {
                    total: frag_count,
                    parts: BTreeMap::new(),
                    expires_at,
                });
            entry.parts.insert(frag_id, payload);
            entry.parts.len() == frag_count as usize
        };
        if !complete {
            return Ok(None);
        }
        let entry = self
            .pending
            .remove(&packet_id)
            .ok_or_else(|| format!("{label} UDP fragment packet disappeared"))?;
        let mut out = Vec::new();
        for id in 0..entry.total {
            let part = entry.parts.get(&id).ok_or_else(|| {
                format!("{label} UDP fragment packet {packet_id} missing fragment {id}")
            })?;
            let reassembled_len = out
                .len()
                .checked_add(part.len())
                .ok_or_else(|| format!("{label} UDP reassembled payload size overflow"))?;
            if reassembled_len > u16::MAX as usize {
                return Err(format!(
                    "{label} UDP reassembled payload too large: {reassembled_len} bytes"
                ));
            }
            out.extend_from_slice(part);
        }
        Ok(Some(out))
    }

    fn expire_at(&mut self, now: Instant) {
        self.pending.retain(|_, entry| entry.expires_at > now);
    }

    pub(super) fn clear(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests;
