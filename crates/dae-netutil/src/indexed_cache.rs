//! Bounded indexed LRU with borrowed lookup and verified hash collisions.
use std::collections::{HashMap, hash_map::RandomState};
use std::hash::{BuildHasher, Hash};

pub struct IndexedCache<T> {
    buckets: HashMap<u64, Vec<(u64, T)>>,
    hash: RandomState,
    capacity: usize,
    len: usize,
    clock: u64,
}

impl<T> IndexedCache<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            buckets: HashMap::new(),
            hash: RandomState::new(),
            capacity,
            len: 0,
            clock: 0,
        }
    }
    pub fn hash(&self, key: impl Hash) -> u64 {
        self.hash.hash_one(key)
    }
    pub fn get(&mut self, hash: u64, matches: impl Fn(&T) -> bool) -> Option<&T> {
        let (stamp, value) = self
            .buckets
            .get_mut(&hash)?
            .iter_mut()
            .find(|(_, value)| matches(value))?;
        self.clock = self.clock.saturating_add(1);
        *stamp = self.clock;
        Some(value)
    }
    /// Callers can drop retired values after releasing their cache lock.
    pub fn insert(&mut self, hash: u64, value: T) -> Option<T> {
        let retired = if self.len == self.capacity {
            let (&old_hash, index, _) = self
                .buckets
                .iter()
                .flat_map(|(hash, entries)| {
                    entries
                        .iter()
                        .enumerate()
                        .map(move |(i, (stamp, _))| (hash, i, stamp))
                })
                .min_by_key(|(_, _, stamp)| **stamp)
                .expect("nonempty cache");
            let entries = self.buckets.get_mut(&old_hash).unwrap();
            let (_, value) = entries.swap_remove(index);
            if entries.is_empty() {
                self.buckets.remove(&old_hash);
            }
            self.len -= 1;
            Some(value)
        } else {
            None
        };
        self.clock = self.clock.saturating_add(1);
        self.buckets
            .entry(hash)
            .or_default()
            .push((self.clock, value));
        self.len += 1;
        retired
    }
}

#[cfg(test)]
mod tests;
