use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::cache::DnsCacheEntry;
use crate::cache_key::{DnsCacheKey, DnsCacheKeyView, hash_dns_cache_key_wire_parts};
use crate::error::DnsError;
use crate::message::DnsPacketQuestionView;
use hashbrown::{Equivalent, HashMap};

const DNS_CACHE_SMALL_BACKEND_MAX_ENTRIES: usize = 16;

#[derive(Clone, Debug)]
pub(super) enum DnsCacheEntries {
    Small(Vec<(DnsCacheKey, Arc<DnsCacheEntry>)>),
    Map {
        entries: HashMap<DnsCacheKey, Arc<DnsCacheEntry>>,
        deadlines: BTreeSet<(i64, DnsCacheKey)>,
    },
}

impl DnsCacheEntries {
    pub(super) fn new(capacity: usize) -> Self {
        if capacity <= DNS_CACHE_SMALL_BACKEND_MAX_ENTRIES {
            Self::Small(Vec::new())
        } else {
            Self::Map {
                entries: HashMap::new(),
                deadlines: BTreeSet::new(),
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Small(entries) => entries.len(),
            Self::Map { entries, .. } => entries.len(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Small(entries) => entries.is_empty(),
            Self::Map { entries, .. } => entries.is_empty(),
        }
    }

    pub(super) fn get(&self, key: &DnsCacheKey) -> Option<&DnsCacheEntry> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .find_map(|(candidate, entry)| (candidate == key).then_some(entry.as_ref())),
            Self::Map { entries, .. } => entries.get(key).map(Arc::as_ref),
        }
    }

    pub(super) fn shared(&self, key: &DnsCacheKey) -> Option<Arc<DnsCacheEntry>> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map(|(_, entry)| Arc::clone(entry)),
            Self::Map { entries, .. } => entries.get(key).map(Arc::clone),
        }
    }

    pub(super) fn expired_shared(
        &self,
        now: i64,
        limit: usize,
    ) -> Vec<(DnsCacheKey, Arc<DnsCacheEntry>)> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .filter(|(_, entry)| entry.cache_expires_at() <= now)
                .take(limit)
                .map(|(key, entry)| (key.clone(), Arc::clone(entry)))
                .collect(),
            Self::Map { entries, deadlines } => deadlines
                .iter()
                .take_while(|(deadline, _)| *deadline <= now)
                .take(limit)
                .filter_map(|(_, key)| {
                    entries
                        .get(key)
                        .map(|entry| (key.clone(), Arc::clone(entry)))
                })
                .collect(),
        }
    }

    pub(super) fn get_view(&self, key: DnsCacheKeyView<'_>) -> Option<&DnsCacheEntry> {
        match self {
            Self::Small(entries) => entries.iter().find_map(|(candidate, entry)| {
                candidate.matches_view(key).then_some(entry.as_ref())
            }),
            Self::Map { entries, .. } => entries.get(&key).map(Arc::as_ref),
        }
    }

    pub(super) fn get_packet_question(
        &self,
        question: &DnsPacketQuestionView<'_>,
    ) -> Result<Option<&DnsCacheEntry>, DnsError> {
        match self {
            Self::Small(entries) => {
                for (candidate, entry) in entries {
                    if packet_question_matches_key(question, candidate)? {
                        return Ok(Some(entry.as_ref()));
                    }
                }
                Ok(None)
            }
            Self::Map { entries, .. } => Ok(entries
                .get(&DnsPacketQuestionCacheKey(question))
                .map(Arc::as_ref)),
        }
    }

    pub(super) fn contains_key(&self, key: &DnsCacheKey) -> bool {
        match self {
            Self::Small(entries) => entries.iter().any(|(candidate, _)| candidate == key),
            Self::Map { entries, .. } => entries.contains_key(key),
        }
    }

    pub(super) fn for_each(&self, mut f: impl FnMut(&DnsCacheKey, &DnsCacheEntry)) {
        match self {
            Self::Small(entries) => {
                for (key, entry) in entries {
                    f(key, entry.as_ref());
                }
            }
            Self::Map { entries, .. } => {
                for (key, entry) in entries {
                    f(key, entry.as_ref());
                }
            }
        }
    }

    pub(super) fn for_each_shared(&self, mut f: impl FnMut(&DnsCacheKey, &Arc<DnsCacheEntry>)) {
        match self {
            Self::Small(entries) => {
                for (key, entry) in entries {
                    f(key, entry);
                }
            }
            Self::Map { entries, .. } => {
                for (key, entry) in entries {
                    f(key, entry);
                }
            }
        }
    }

    pub(super) fn insert(&mut self, key: DnsCacheKey, entry: DnsCacheEntry) {
        match self {
            Self::Small(entries) => {
                if let Some((_, existing)) =
                    entries.iter_mut().find(|(candidate, _)| candidate == &key)
                {
                    *existing = Arc::new(entry);
                    return;
                }
                entries.push((key, Arc::new(entry)));
            }
            Self::Map { entries, deadlines } => {
                if let Some(old) = entries.get(&key) {
                    deadlines.remove(&(old.cache_expires_at(), key.clone()));
                }
                deadlines.insert((entry.cache_expires_at(), key.clone()));
                entries.insert(key, Arc::new(entry));
            }
        }
    }

    pub(super) fn remove(&mut self, key: &DnsCacheKey) -> Option<Arc<DnsCacheEntry>> {
        match self {
            Self::Small(entries) => {
                let index = entries.iter().position(|(candidate, _)| candidate == key)?;
                Some(entries.swap_remove(index).1)
            }
            Self::Map { entries, deadlines } => {
                let (stored_key, entry) = entries.remove_entry(key)?;
                deadlines.remove(&(entry.cache_expires_at(), stored_key));
                Some(entry)
            }
        }
    }

    pub(super) fn remove_view(&mut self, key: DnsCacheKeyView<'_>) -> Option<Arc<DnsCacheEntry>> {
        match self {
            Self::Small(entries) => {
                let index = entries
                    .iter()
                    .position(|(candidate, _)| candidate.matches_view(key))?;
                Some(entries.swap_remove(index).1)
            }
            Self::Map { entries, deadlines } => {
                let (stored_key, entry) = entries.remove_entry(&key)?;
                deadlines.remove(&(entry.cache_expires_at(), stored_key));
                Some(entry)
            }
        }
    }

    pub(super) fn remove_packet_question(
        &mut self,
        question: &DnsPacketQuestionView<'_>,
    ) -> Result<Option<Arc<DnsCacheEntry>>, DnsError> {
        Ok(self
            .remove_packet_question_entry(question)?
            .map(|(_, entry)| entry))
    }

    pub(super) fn remove_packet_question_entry(
        &mut self,
        question: &DnsPacketQuestionView<'_>,
    ) -> Result<Option<(DnsCacheKey, Arc<DnsCacheEntry>)>, DnsError> {
        match self {
            Self::Small(entries) => {
                let mut index = 0;
                while index < entries.len() {
                    if packet_question_matches_key(question, &entries[index].0)? {
                        return Ok(Some(entries.swap_remove(index)));
                    }
                    index += 1;
                }
                Ok(None)
            }
            Self::Map { entries, deadlines } => {
                let result = entries.remove_entry(&DnsPacketQuestionCacheKey(question));
                if let Some((key, entry)) = &result {
                    deadlines.remove(&(entry.cache_expires_at(), key.clone()));
                }
                Ok(result)
            }
        }
    }

    pub(super) fn remove_expired(&mut self, now_unix: i64) -> usize {
        match self {
            Self::Small(entries) => {
                let before = entries.len();
                let mut index = 0;
                while index < entries.len() {
                    if entries[index].1.cache_expires_at() <= now_unix {
                        entries.swap_remove(index);
                    } else {
                        index += 1;
                    }
                }
                before - entries.len()
            }
            Self::Map { entries, deadlines } => {
                let before = entries.len();
                while deadlines
                    .first()
                    .is_some_and(|(deadline, _)| *deadline <= now_unix)
                {
                    let (deadline, key) = deadlines.pop_first().expect("deadline exists");
                    if entries
                        .get(&key)
                        .is_some_and(|entry| entry.cache_expires_at() == deadline)
                    {
                        entries.remove(&key);
                    }
                }
                before - entries.len()
            }
        }
    }

    pub(super) fn remove_expired_entries(
        &mut self,
        now_unix: i64,
        limit: usize,
    ) -> Vec<(DnsCacheKey, Arc<DnsCacheEntry>)> {
        match self {
            Self::Small(entries) => {
                let mut removed = Vec::new();
                let mut index = 0;
                while index < entries.len() && removed.len() < limit {
                    if entries[index].1.cache_expires_at() <= now_unix {
                        removed.push(entries.swap_remove(index));
                    } else {
                        index += 1;
                    }
                }
                removed
            }
            Self::Map { entries, deadlines } => {
                let mut removed = Vec::new();
                let mut examined = 0;
                while examined < limit
                    && deadlines
                        .first()
                        .is_some_and(|(deadline, _)| *deadline <= now_unix)
                {
                    let (deadline, key) = deadlines.pop_first().expect("deadline exists");
                    examined += 1;
                    if entries
                        .get(&key)
                        .is_some_and(|entry| entry.cache_expires_at() == deadline)
                        && let Some(entry) = entries.remove(&key)
                    {
                        removed.push((key, entry));
                    }
                }
                removed
            }
        }
    }

    pub(super) fn next_expiry_unix(&self) -> Option<i64> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .map(|(_, entry)| entry.cache_expires_at())
                .min(),
            Self::Map { deadlines, .. } => deadlines.first().map(|(deadline, _)| *deadline),
        }
    }

    pub(super) fn live_count(&self, now_unix: i64) -> usize {
        match self {
            Self::Small(entries) => entries
                .iter()
                .filter(|(_, entry)| entry.cache_expires_at() > now_unix)
                .count(),
            Self::Map { entries, .. } => entries
                .values()
                .filter(|entry| entry.cache_expires_at() > now_unix)
                .count(),
        }
    }

    pub(super) fn oldest_key(&mut self) -> Option<DnsCacheKey> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .min_by_key(|(_, entry)| entry.cache_expires_at())
                .map(|(key, _)| key.clone()),
            Self::Map { entries, deadlines } => {
                // Normal mutations maintain both indexes. Recover defensively if
                // an old/missing record is encountered, instead of repeatedly
                // selecting a key whose removal cannot make progress.
                if deadlines.len() != entries.len()
                    || deadlines.first().is_some_and(|(deadline, key)| {
                        entries
                            .get(key)
                            .is_none_or(|entry| entry.cache_expires_at() != *deadline)
                    })
                {
                    *deadlines = entries
                        .iter()
                        .map(|(key, entry)| (entry.cache_expires_at(), key.clone()))
                        .collect();
                }
                deadlines.first().map(|(_, key)| key.clone())
            }
        }
    }
}

fn packet_question_matches_key(
    question: &DnsPacketQuestionView<'_>,
    key: &DnsCacheKey,
) -> Result<bool, DnsError> {
    if question.qtype() != key.qtype || question.qclass() != key.qclass {
        return Ok(false);
    }
    question.qname_canonical_eq_ignore_ascii_case(&key.qname)
}

impl Equivalent<DnsCacheKey> for DnsCacheKeyView<'_> {
    fn equivalent(&self, key: &DnsCacheKey) -> bool {
        key.matches_view(*self)
    }
}

struct DnsPacketQuestionCacheKey<'a>(&'a DnsPacketQuestionView<'a>);

impl Hash for DnsPacketQuestionCacheKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_dns_cache_key_wire_parts(self.0.qname_wire(), self.0.qtype(), self.0.qclass(), state);
    }
}

impl Equivalent<DnsCacheKey> for DnsPacketQuestionCacheKey<'_> {
    fn equivalent(&self, key: &DnsCacheKey) -> bool {
        packet_question_matches_key(self.0, key).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_victim_recovers_missing_stale_and_incomplete_deadlines() {
        let mut index = DnsCacheEntries::new(4096);
        let a = DnsCacheKey::new("a.example", 1, 1);
        let b = DnsCacheKey::new("b.example", 1, 1);
        index.insert(a.clone(), DnsCacheEntry::new(100, 100));
        index.insert(b.clone(), DnsCacheEntry::new(200, 200));
        if let DnsCacheEntries::Map { deadlines, .. } = &mut index {
            deadlines.clear();
            deadlines.insert((10, DnsCacheKey::new("missing.example", 1, 1)));
            deadlines.insert((20, b.clone()));
        }
        assert_eq!(index.oldest_key(), Some(a.clone()));
        index.remove(&a).unwrap();
        assert_eq!(index.oldest_key(), Some(b.clone()));
        if let DnsCacheEntries::Map { deadlines, .. } = &mut index {
            deadlines.clear();
        }
        assert_eq!(index.oldest_key(), Some(b));
    }

    #[test]
    fn expired_stale_index_does_not_remove_a_refreshed_entry() {
        let mut index = DnsCacheEntries::new(4096);
        let key = DnsCacheKey::new("a.example", 1, 1);
        index.insert(key.clone(), DnsCacheEntry::new(200, 200));
        if let DnsCacheEntries::Map { deadlines, .. } = &mut index {
            deadlines.insert((10, key.clone()));
        }
        assert!(index.remove_expired_entries(20, 1).is_empty());
        assert!(index.get(&key).is_some());
        assert_eq!(index.next_expiry_unix(), Some(200));
    }

    #[test]
    fn deadline_index_tracks_replace_remove_sweep_and_restore() {
        let mut entries = DnsCacheEntries::new(4096);
        let a = DnsCacheKey::new("a.example", 1, 1);
        let b = DnsCacheKey::new("b.example", 1, 1);
        for tick in 0..1000 {
            entries.insert(a.clone(), DnsCacheEntry::new(tick + 1, tick + 2));
            match &entries {
                DnsCacheEntries::Map { entries, deadlines } => {
                    assert_eq!(entries.len(), deadlines.len())
                }
                _ => unreachable!(),
            }
        }
        entries.insert(b.clone(), DnsCacheEntry::new(50, 60));
        assert_eq!(entries.next_expiry_unix(), Some(60));
        let removed = entries.remove_expired_entries(1001, 1);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].0, b);
        assert_eq!(entries.next_expiry_unix(), Some(1001));
        entries.insert(removed[0].0.clone(), removed[0].1.as_ref().clone());
        assert_eq!(entries.next_expiry_unix(), Some(60));
        entries
            .remove_view(DnsCacheKeyView {
                qname: "B.EXAMPLE",
                qtype: 1,
                qclass: 1,
            })
            .unwrap();
        assert_eq!(entries.next_expiry_unix(), Some(1001));
        entries.remove(&a).unwrap();
        assert!(entries.next_expiry_unix().is_none());
    }
}
