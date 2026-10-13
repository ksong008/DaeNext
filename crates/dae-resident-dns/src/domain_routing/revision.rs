use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dae_dns::DnsCacheKey;

#[derive(Debug, Default)]
pub(super) struct ResponseRevisions {
    state: Mutex<ResponseRevisionState>,
}

#[derive(Debug, Default)]
struct ResponseRevisionState {
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
}

impl ResponseRevisions {
    pub(super) fn begin(self: &Arc<Self>, key: &DnsCacheKey) -> Result<ResponseRevision, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response revision lock poisoned".to_owned())?;
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| "resident DNS response revision exhausted".to_owned())?;
        state.sequence = sequence;
        state.pending.entry(key.clone()).or_default().count += 1;
        Ok(ResponseRevision {
            revisions: Arc::clone(self),
            key: key.clone(),
            sequence,
        })
    }

    pub(super) fn invalidate(&self, key: &DnsCacheKey) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "resident DNS response revision lock poisoned".to_owned())?;
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
        let state = self
            .revisions
            .state
            .lock()
            .map_err(|_| "resident DNS response revision lock poisoned".to_owned())?;
        Ok(state
            .pending
            .get(&self.key)
            .is_some_and(|pending| pending.committed < self.sequence))
    }

    pub(super) fn committed(&self) -> Result<(), String> {
        let mut state = self
            .revisions
            .state
            .lock()
            .map_err(|_| "resident DNS response revision lock poisoned".to_owned())?;
        let pending = state.pending.get_mut(&self.key).ok_or_else(|| {
            "resident DNS response revision was released before commit".to_owned()
        })?;
        pending.committed = pending.committed.max(self.sequence);
        Ok(())
    }
}

impl Drop for ResponseRevision {
    fn drop(&mut self) {
        let mut state = self
            .revisions
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(pending) = state.pending.get_mut(&self.key) {
            pending.count -= 1;
            if pending.count == 0 {
                state.pending.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests;
