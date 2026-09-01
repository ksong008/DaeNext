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
    Map(HashMap<DnsCacheKey, Arc<DnsCacheEntry>>),
}

impl DnsCacheEntries {
    pub(super) fn new(capacity: usize) -> Self {
        if capacity <= DNS_CACHE_SMALL_BACKEND_MAX_ENTRIES {
            Self::Small(Vec::new())
        } else {
            Self::Map(HashMap::new())
        }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Small(entries) => entries.len(),
            Self::Map(entries) => entries.len(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Small(entries) => entries.is_empty(),
            Self::Map(entries) => entries.is_empty(),
        }
    }

    pub(super) fn get(&self, key: &DnsCacheKey) -> Option<&DnsCacheEntry> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .find_map(|(candidate, entry)| (candidate == key).then_some(entry.as_ref())),
            Self::Map(entries) => entries.get(key).map(Arc::as_ref),
        }
    }

    pub(super) fn get_view(&self, key: DnsCacheKeyView<'_>) -> Option<&DnsCacheEntry> {
        match self {
            Self::Small(entries) => entries.iter().find_map(|(candidate, entry)| {
                candidate.matches_view(key).then_some(entry.as_ref())
            }),
            Self::Map(entries) => entries.get(&key).map(Arc::as_ref),
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
            Self::Map(entries) => Ok(entries
                .get(&DnsPacketQuestionCacheKey(question))
                .map(Arc::as_ref)),
        }
    }

    pub(super) fn contains_key(&self, key: &DnsCacheKey) -> bool {
        match self {
            Self::Small(entries) => entries.iter().any(|(candidate, _)| candidate == key),
            Self::Map(entries) => entries.contains_key(key),
        }
    }

    pub(super) fn for_each(&self, mut f: impl FnMut(&DnsCacheKey, &DnsCacheEntry)) {
        match self {
            Self::Small(entries) => {
                for (key, entry) in entries {
                    f(key, entry.as_ref());
                }
            }
            Self::Map(entries) => {
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
            Self::Map(entries) => {
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
            Self::Map(entries) => {
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
            Self::Map(entries) => entries.remove(key),
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
            Self::Map(entries) => entries.remove(&key),
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
            Self::Map(entries) => Ok(entries.remove_entry(&DnsPacketQuestionCacheKey(question))),
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
            Self::Map(entries) => {
                let before = entries.len();
                entries.retain(|_, entry| entry.cache_expires_at() > now_unix);
                before - entries.len()
            }
        }
    }

    pub(super) fn remove_expired_entries(
        &mut self,
        now_unix: i64,
    ) -> Vec<(DnsCacheKey, Arc<DnsCacheEntry>)> {
        match self {
            Self::Small(entries) => {
                let mut removed = Vec::new();
                let mut index = 0;
                while index < entries.len() {
                    if entries[index].1.cache_expires_at() <= now_unix {
                        removed.push(entries.swap_remove(index));
                    } else {
                        index += 1;
                    }
                }
                removed
            }
            Self::Map(entries) => entries
                .extract_if(|_, entry| entry.cache_expires_at() <= now_unix)
                .collect(),
        }
    }

    pub(super) fn next_expiry_unix(&self) -> Option<i64> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .map(|(_, entry)| entry.cache_expires_at())
                .min(),
            Self::Map(entries) => entries.values().map(|entry| entry.cache_expires_at()).min(),
        }
    }

    pub(super) fn live_count(&self, now_unix: i64) -> usize {
        match self {
            Self::Small(entries) => entries
                .iter()
                .filter(|(_, entry)| entry.cache_expires_at() > now_unix)
                .count(),
            Self::Map(entries) => entries
                .values()
                .filter(|entry| entry.cache_expires_at() > now_unix)
                .count(),
        }
    }

    pub(super) fn oldest_key(&self) -> Option<DnsCacheKey> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .min_by_key(|(_, entry)| entry.cache_expires_at())
                .map(|(key, _)| key.clone()),
            Self::Map(entries) => entries
                .iter()
                .min_by_key(|(_, entry)| entry.cache_expires_at())
                .map(|(key, _)| key.clone()),
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
