use std::collections::HashMap;

use crate::cache::DnsCacheEntry;
use crate::cache_key::{DnsCacheKey, DnsCacheKeyView};
use crate::error::DnsError;
use crate::message::DnsPacketQuestionView;

const DNS_CACHE_SMALL_BACKEND_MAX_ENTRIES: usize = 16;

#[derive(Clone, Debug)]
pub(super) enum DnsCacheEntries {
    Small(Vec<(DnsCacheKey, DnsCacheEntry)>),
    Map(HashMap<DnsCacheKey, DnsCacheEntry>),
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
                .find_map(|(candidate, entry)| (candidate == key).then_some(entry)),
            Self::Map(entries) => entries.get(key),
        }
    }

    pub(super) fn get_view(&self, key: DnsCacheKeyView<'_>) -> Option<&DnsCacheEntry> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .find_map(|(candidate, entry)| candidate.matches_view(key).then_some(entry)),
            Self::Map(entries) => {
                let owned = DnsCacheKey::new(key.qname, key.qtype, key.qclass);
                entries.get(&owned)
            }
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
                        return Ok(Some(entry));
                    }
                }
                Ok(None)
            }
            Self::Map(entries) => {
                let owned = packet_question_cache_key(question)?;
                Ok(entries.get(&owned))
            }
        }
    }

    pub(super) fn contains_key(&self, key: &DnsCacheKey) -> bool {
        match self {
            Self::Small(entries) => entries.iter().any(|(candidate, _)| candidate == key),
            Self::Map(entries) => entries.contains_key(key),
        }
    }

    pub(super) fn insert(&mut self, key: DnsCacheKey, entry: DnsCacheEntry) {
        match self {
            Self::Small(entries) => {
                if let Some((_, existing)) =
                    entries.iter_mut().find(|(candidate, _)| candidate == &key)
                {
                    *existing = entry;
                    return;
                }
                entries.push((key, entry));
            }
            Self::Map(entries) => {
                entries.insert(key, entry);
            }
        }
    }

    pub(super) fn remove(&mut self, key: &DnsCacheKey) -> Option<DnsCacheEntry> {
        match self {
            Self::Small(entries) => {
                let index = entries.iter().position(|(candidate, _)| candidate == key)?;
                Some(entries.swap_remove(index).1)
            }
            Self::Map(entries) => entries.remove(key),
        }
    }

    pub(super) fn remove_view(&mut self, key: DnsCacheKeyView<'_>) -> Option<DnsCacheEntry> {
        match self {
            Self::Small(entries) => {
                let index = entries
                    .iter()
                    .position(|(candidate, _)| candidate.matches_view(key))?;
                Some(entries.swap_remove(index).1)
            }
            Self::Map(entries) => {
                let owned = DnsCacheKey::new(key.qname, key.qtype, key.qclass);
                entries.remove(&owned)
            }
        }
    }

    pub(super) fn remove_packet_question(
        &mut self,
        question: &DnsPacketQuestionView<'_>,
    ) -> Result<Option<DnsCacheEntry>, DnsError> {
        match self {
            Self::Small(entries) => {
                let mut index = 0;
                while index < entries.len() {
                    if packet_question_matches_key(question, &entries[index].0)? {
                        return Ok(Some(entries.swap_remove(index).1));
                    }
                    index += 1;
                }
                Ok(None)
            }
            Self::Map(entries) => {
                let owned = packet_question_cache_key(question)?;
                Ok(entries.remove(&owned))
            }
        }
    }

    pub(super) fn expired_keys(&self, now_unix: i64) -> Vec<DnsCacheKey> {
        match self {
            Self::Small(entries) => entries
                .iter()
                .filter_map(|(key, entry)| {
                    (entry.cache_expires_at() <= now_unix).then_some(key.clone())
                })
                .collect(),
            Self::Map(entries) => entries
                .iter()
                .filter_map(|(key, entry)| {
                    (entry.cache_expires_at() <= now_unix).then_some(key.clone())
                })
                .collect(),
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
                let expired: Vec<DnsCacheKey> = entries
                    .iter()
                    .filter_map(|(key, entry)| {
                        (entry.cache_expires_at() <= now_unix).then_some(key.clone())
                    })
                    .collect();
                let removed = expired.len();
                for key in expired {
                    entries.remove(&key);
                }
                removed
            }
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

fn packet_question_cache_key(
    question: &DnsPacketQuestionView<'_>,
) -> Result<DnsCacheKey, DnsError> {
    Ok(DnsCacheKey {
        qname: question.qname_to_canonical_string()?,
        qtype: question.qtype(),
        qclass: question.qclass(),
    })
}
