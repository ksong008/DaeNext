use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use dae_dns::DnsCacheKey;

#[derive(Debug, Default)]
pub(super) struct ResponseRevisions {
    state: Mutex<ResponseRevisionState>,
}

#[derive(Debug, Default)]
struct ResponseRevisionState {
    epoch: Arc<()>,
    sequence: u64,
    pending: HashMap<DnsCacheKey, PendingResponses>,
}

#[derive(Debug, Default)]
struct PendingResponses {
    count: usize,
    committed: u64,
}

/// A version remains tracked only while responses for this key are in progress.
/// Keeping the last committed version until every older response has ended
/// avoids both stale commits and a permanent table of removed-key tombstones.
#[derive(Debug)]
pub(super) struct ResponseRevision {
    revisions: Arc<ResponseRevisions>,
    pub(super) key: DnsCacheKey,
    sequence: u64,
    epoch: Arc<()>,
}

impl ResponseRevisions {
    fn lock_state(&self) -> MutexGuard<'_, ResponseRevisionState> {
        self.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            // TTL cannot reject older plans. A fresh identity invalidates every
            // outstanding token, including its Drop, before bookkeeping resets.
            *state = ResponseRevisionState::default();
            self.state.clear_poison();
            state
        })
    }

    pub(super) fn begin(self: &Arc<Self>, key: &DnsCacheKey) -> Result<ResponseRevision, String> {
        let mut state = self.lock_state();
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| "resident DNS response revision exhausted".to_owned())?;
        state.sequence = sequence;
        let pending = state.pending.entry(key.clone()).or_default();
        pending.count = pending
            .count
            .checked_add(1)
            .ok_or_else(|| "resident DNS response revision count exhausted".to_owned())?;
        Ok(ResponseRevision {
            revisions: Arc::clone(self),
            key: key.clone(),
            sequence,
            epoch: Arc::clone(&state.epoch),
        })
    }

    pub(super) fn invalidate(&self, key: &DnsCacheKey) -> Result<(), String> {
        let mut state = self.lock_state();
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| "resident DNS response revision exhausted".to_owned())?;
        state.sequence = sequence;
        if let Some(pending) = state.pending.get_mut(key) {
            pending.committed = sequence;
        }
        Ok(())
    }
}

impl ResponseRevision {
    // Writers must hold the domain routing mutation lock through this check,
    // routing/cache publication, and committed(). begin()/Drop do not acquire
    // any routing or cache locks, so revision bookkeeping cannot invert them.
    pub(super) fn can_commit(&self) -> Result<bool, String> {
        let state = self.revisions.lock_state();
        Ok(Arc::ptr_eq(&self.epoch, &state.epoch)
            && state
                .pending
                .get(&self.key)
                .is_some_and(|pending| pending.committed < self.sequence))
    }

    pub(super) fn committed(&self) -> Result<(), String> {
        let mut state = self.revisions.lock_state();
        if !Arc::ptr_eq(&self.epoch, &state.epoch) {
            return Err("resident DNS response revision invalidated by poison recovery".to_owned());
        }
        let pending = state.pending.get_mut(&self.key).ok_or_else(|| {
            "resident DNS response revision was released before commit".to_owned()
        })?;
        pending.committed = pending.committed.max(self.sequence);
        Ok(())
    }
}

impl Drop for ResponseRevision {
    fn drop(&mut self) {
        let mut state = self.revisions.lock_state();
        if !Arc::ptr_eq(&self.epoch, &state.epoch) {
            return;
        }
        if let Some(pending) = state.pending.get_mut(&self.key) {
            pending.count = pending.count.saturating_sub(1);
            if pending.count == 0 {
                state.pending.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests;
