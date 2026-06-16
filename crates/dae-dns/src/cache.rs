use std::net::IpAddr;

use crate::cache_key::{DnsCacheKey, DnsCacheKeyView};
use crate::error::DnsError;
use crate::message::{
    DnsAnswer, DnsPacketQuestionView, restore_packed_response_request_id,
    restore_packed_response_request_id_into,
};

mod entries;

use entries::DnsCacheEntries;

pub const DNS_CACHE_MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCacheEntry {
    pub route_owner_key: String,
    pub domain_bitmap: Vec<u32>,
    pub ips: Vec<IpAddr>,
    pub has_any_ip: bool,
    pub deadline_unix: i64,
    pub original_deadline_unix: i64,
    pub packed_response: Vec<u8>,
}

impl DnsCacheEntry {
    pub fn new(deadline_unix: i64, original_deadline_unix: i64) -> Self {
        Self {
            route_owner_key: String::new(),
            domain_bitmap: Vec::new(),
            ips: Vec::new(),
            has_any_ip: false,
            deadline_unix,
            original_deadline_unix,
            packed_response: Vec::new(),
        }
    }

    pub fn cache_expires_at(&self) -> i64 {
        self.deadline_unix.max(self.original_deadline_unix)
    }

    pub fn lookup_deadline(&self, ignore_fixed_ttl: bool) -> i64 {
        if ignore_fixed_ttl {
            self.original_deadline_unix
        } else {
            self.deadline_unix
        }
    }

    pub fn fill_packed_response(&self, request_id: u16) -> Option<Vec<u8>> {
        restore_packed_response_request_id(&self.packed_response, request_id)
    }

    pub fn fill_packed_response_into(&self, request_id: u16, out: &mut Vec<u8>) -> Option<()> {
        restore_packed_response_request_id_into(&self.packed_response, request_id, out)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsCacheStats {
    pub hit_total: u64,
    pub expired_removal_total: u64,
    pub remove_callback_total: u64,
}

#[derive(Clone, Debug)]
pub struct DnsCacheStore {
    capacity: usize,
    entries: DnsCacheEntries,
    stats: DnsCacheStats,
}

impl Default for DnsCacheStore {
    fn default() -> Self {
        Self::new(DNS_CACHE_MAX_ENTRIES)
    }
}

impl DnsCacheStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: DnsCacheEntries::new(capacity),
            stats: DnsCacheStats::default(),
        }
    }

    pub fn insert(&mut self, now_unix: i64, key: DnsCacheKey, mut entry: DnsCacheEntry) {
        entry.route_owner_key = key.to_string();
        self.insert_entry(now_unix, key, entry);
    }

    pub fn insert_without_route_owner_key(
        &mut self,
        now_unix: i64,
        key: DnsCacheKey,
        entry: DnsCacheEntry,
    ) {
        self.insert_entry(now_unix, key, entry);
    }

    fn insert_entry(&mut self, now_unix: i64, key: DnsCacheKey, entry: DnsCacheEntry) {
        if !self.entries.contains_key(&key) {
            self.evict_entries(now_unix);
        }
        self.entries.insert(key, entry);
    }

    pub fn lookup(
        &mut self,
        now_unix: i64,
        key: &DnsCacheKey,
        ignore_fixed_ttl: bool,
    ) -> Option<DnsCacheEntry> {
        self.lookup_ref(now_unix, key, ignore_fixed_ttl).cloned()
    }

    pub fn lookup_ref(
        &mut self,
        now_unix: i64,
        key: &DnsCacheKey,
        ignore_fixed_ttl: bool,
    ) -> Option<&DnsCacheEntry> {
        let (lookup_deadline, cache_expires_at) = {
            let entry = self.entries.get(key)?;
            (
                entry.lookup_deadline(ignore_fixed_ttl),
                entry.cache_expires_at(),
            )
        };
        if lookup_deadline > now_unix {
            self.stats.hit_total += 1;
            return self.entries.get(key);
        }
        if cache_expires_at > now_unix {
            return None;
        }
        self.entries.remove(key);
        self.stats.expired_removal_total += 1;
        self.stats.remove_callback_total += 1;
        None
    }

    pub fn lookup_view(
        &mut self,
        now_unix: i64,
        key: DnsCacheKeyView<'_>,
        ignore_fixed_ttl: bool,
    ) -> Option<&DnsCacheEntry> {
        let (lookup_deadline, cache_expires_at) = {
            let entry = self.entries.get_view(key)?;
            (
                entry.lookup_deadline(ignore_fixed_ttl),
                entry.cache_expires_at(),
            )
        };
        if lookup_deadline > now_unix {
            self.stats.hit_total += 1;
            return self.entries.get_view(key);
        }
        if cache_expires_at > now_unix {
            return None;
        }
        self.entries.remove_view(key);
        self.stats.expired_removal_total += 1;
        self.stats.remove_callback_total += 1;
        None
    }

    pub fn lookup_packet_question(
        &mut self,
        now_unix: i64,
        question: &DnsPacketQuestionView<'_>,
        ignore_fixed_ttl: bool,
    ) -> Result<Option<&DnsCacheEntry>, DnsError> {
        let (lookup_deadline, cache_expires_at) = {
            let Some(entry) = self.entries.get_packet_question(question)? else {
                return Ok(None);
            };
            (
                entry.lookup_deadline(ignore_fixed_ttl),
                entry.cache_expires_at(),
            )
        };
        if lookup_deadline > now_unix {
            self.stats.hit_total += 1;
            return self.entries.get_packet_question(question);
        }
        if cache_expires_at > now_unix {
            return Ok(None);
        }
        self.entries.remove_packet_question(question)?;
        self.stats.expired_removal_total += 1;
        self.stats.remove_callback_total += 1;
        Ok(None)
    }

    pub fn sweep(&mut self, now_unix: i64) -> Vec<DnsCacheEntry> {
        let removed = self.entries.remove_expired_entries(now_unix);
        self.stats.expired_removal_total += removed.len() as u64;
        self.stats.remove_callback_total += removed.len() as u64;
        removed
    }

    pub fn cache_stats_entries(&self, now_unix: i64) -> usize {
        self.entries.live_count(now_unix)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains_key(&self, key: &DnsCacheKey) -> bool {
        self.entries.contains_key(key)
    }

    pub fn stats(&self) -> &DnsCacheStats {
        &self.stats
    }

    fn evict_entries(&mut self, now_unix: i64) {
        let expired_count = self.entries.remove_expired(now_unix);
        self.stats.expired_removal_total += expired_count as u64;
        self.stats.remove_callback_total += expired_count as u64;

        while self.entries.len() >= self.capacity {
            let Some(oldest_key) = self.entries.oldest_key() else {
                break;
            };
            self.entries.remove(&oldest_key);
            self.stats.remove_callback_total += 1;
        }
    }
}

pub fn effective_deadline_from_ttl(
    now_unix: i64,
    upstream_ttl: i64,
    fixed_domain_ttl: Option<i64>,
) -> (i64, i64) {
    let original = now_unix + upstream_ttl;
    let effective = fixed_domain_ttl
        .map(|ttl| now_unix + ttl)
        .unwrap_or(original);
    (effective, original)
}

pub fn min_answer_ttl(answers: &[DnsAnswer]) -> Option<u32> {
    answers.iter().map(DnsAnswer::ttl).min()
}

pub fn summarize_answer_ips(answers: &[DnsAnswer]) -> (Vec<IpAddr>, bool) {
    let mut ips = Vec::new();
    let mut has_any_ip = false;
    for answer in answers {
        if let Some(ip) = answer.ip() {
            has_any_ip = true;
            if !ip.is_unspecified() {
                ips.push(ip);
            }
        }
    }
    (ips, has_any_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_ttl_eviction_and_stats_match_golden_fixture() {
        let fixture = dae_golden::load_json("dns/cache/ttl_eviction_stats.json").unwrap();
        let now = fixture["now_unix"].as_i64().unwrap();

        for case in fixture["cases"].as_array().unwrap() {
            match case["name"].as_str().unwrap() {
                "min-answer-ttl" => {
                    let ttls: Vec<DnsAnswer> = case["answer_ttls"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|ttl| DnsAnswer::Other {
                            name: "example.com.".to_owned(),
                            qtype: 1,
                            ttl: ttl.as_u64().unwrap() as u32,
                        })
                        .collect();
                    let ttl = min_answer_ttl(&ttls).unwrap() as i64;
                    assert_eq!(
                        effective_deadline_from_ttl(now, ttl, None),
                        (
                            case["effective_deadline"].as_i64().unwrap(),
                            case["original_deadline"].as_i64().unwrap()
                        )
                    );
                }
                "fixed-domain-ttl" | "fixed-domain-ttl-zero" => {
                    let got = effective_deadline_from_ttl(
                        now,
                        case["upstream_ttl"].as_i64().unwrap(),
                        Some(case["fixed_domain_ttl"].as_i64().unwrap()),
                    );
                    assert_eq!(
                        got,
                        (
                            case["effective_deadline"].as_i64().unwrap(),
                            case["original_deadline"].as_i64().unwrap()
                        )
                    );
                }
                "explicit-deadline-ignores-fixed-ttl" => {
                    let explicit = case["explicit_deadline"].as_i64().unwrap();
                    assert_eq!(explicit, case["effective_deadline"].as_i64().unwrap());
                    assert_eq!(explicit, case["original_deadline"].as_i64().unwrap());
                }
                name => panic!("unexpected ttl case: {name}"),
            }
        }

        let eviction = &fixture["eviction"];
        let mut store = DnsCacheStore::new(eviction["capacity"].as_u64().unwrap() as usize);
        let existing = eviction["existing"].as_array().unwrap();
        let deadlines = eviction["deadlines"].as_array().unwrap();
        for (name, deadline) in existing.iter().zip(deadlines) {
            store.insert(
                now,
                DnsCacheKey::new(name.as_str().unwrap(), 1, 1),
                DnsCacheEntry::new(deadline.as_i64().unwrap(), deadline.as_i64().unwrap()),
            );
        }
        store.insert(
            now,
            DnsCacheKey::new(eviction["insert"].as_str().unwrap(), 1, 1),
            DnsCacheEntry::new(now + 600, now + 600),
        );
        assert_eq!(
            store.len(),
            eviction["size_after"].as_u64().unwrap() as usize
        );
        for removed in eviction["removed"].as_array().unwrap() {
            assert!(!store.contains_key(&DnsCacheKey::new(removed.as_str().unwrap(), 1, 1)));
        }

        let stats = &fixture["stats_no_mutation"];
        let mut stats_store = DnsCacheStore::new(8);
        stats_store.entries.insert(
            DnsCacheKey::new("expired.example.", 1, 1),
            DnsCacheEntry::new(now - 60, now - 60),
        );
        stats_store.entries.insert(
            DnsCacheKey::new("client-expired.example.", 1, 1),
            DnsCacheEntry::new(now - 60, now + 60),
        );
        stats_store.entries.insert(
            DnsCacheKey::new("live.example.", 1, 1),
            DnsCacheEntry::new(now + 60, now + 60),
        );
        assert_eq!(
            stats_store.cache_stats_entries(now),
            stats["cache_stats_live"].as_u64().unwrap() as usize
        );
        assert_eq!(
            stats_store.len(),
            stats["map_size_after_cache_stats"].as_u64().unwrap() as usize
        );
        assert_eq!(
            stats_store.stats().remove_callback_total,
            stats["remove_callback_called"].as_u64().unwrap()
        );
    }

    #[test]
    fn packet_question_lookup_and_packed_response_into_match_owned_paths() {
        let now = 1_700_000_000_i64;
        let request = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'E',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'C', b'O', b'M', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let view = crate::message::DnsPacketView::parse(&request).unwrap();
        let question = view.questions().next().unwrap();

        let mut entry = DnsCacheEntry::new(now + 60, now + 60);
        entry.packed_response = vec![0, 0, 0x81, 0x80];

        let mut store = DnsCacheStore::new(8);
        store.insert_without_route_owner_key(now, DnsCacheKey::new("example.com.", 1, 1), entry);
        let found = store
            .lookup_packet_question(now, &question, false)
            .unwrap()
            .expect("packet question cache hit");
        let mut restored = Vec::with_capacity(found.packed_response.len());
        found
            .fill_packed_response_into(view.id(), &mut restored)
            .expect("packed response restore into");
        assert_eq!(restored, vec![0x12, 0x34, 0x81, 0x80]);
        assert_eq!(store.stats().hit_total, 1);
    }
}
