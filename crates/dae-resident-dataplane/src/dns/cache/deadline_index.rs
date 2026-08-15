use std::collections::BTreeSet;

use super::ResidentDnsResponseCacheKey;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ResidentDnsCacheDeadline {
    pub(super) expires_at: i64,
    generation: u64,
    pub(super) key: ResidentDnsResponseCacheKey,
}

#[derive(Debug, Default)]
pub(super) struct ResidentDnsCacheDeadlineIndex {
    entries: BTreeSet<ResidentDnsCacheDeadline>,
    next_generation: u64,
}

impl ResidentDnsCacheDeadlineIndex {
    pub(super) fn insert(
        &mut self,
        key: ResidentDnsResponseCacheKey,
        expires_at: i64,
    ) -> ResidentDnsCacheDeadline {
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let deadline = ResidentDnsCacheDeadline {
            expires_at,
            generation: self.next_generation,
            key,
        };
        self.entries.insert(deadline.clone());
        deadline
    }

    pub(super) fn remove(&mut self, deadline: &ResidentDnsCacheDeadline) {
        self.entries.remove(deadline);
    }

    pub(super) fn pop_expired(&mut self, now_unix: i64) -> Option<ResidentDnsCacheDeadline> {
        if self
            .entries
            .first()
            .is_none_or(|deadline| deadline.expires_at > now_unix)
        {
            return None;
        }
        self.entries.pop_first()
    }

    pub(super) fn pop_first(&mut self) -> Option<ResidentDnsCacheDeadline> {
        self.entries.pop_first()
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}
