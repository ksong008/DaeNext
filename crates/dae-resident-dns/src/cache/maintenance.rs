use super::*;
use std::{mem::DropGuard, sync::MutexGuard};

pub(super) fn lock_cache_shard(
    shard: &Mutex<ResidentDnsRuntimeCacheState>,
) -> MutexGuard<'_, ResidentDnsRuntimeCacheState> {
    match shard.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            // Only a panic unwinding while this mutex is held poisons it;
            // ordinary upstream errors do not. Partially mutated entries and
            // deadlines cannot be trusted, so reset the entire shard, including
            // unexpired responses, deadlines and local statistics, before
            // clearing poison. Healthy shards and acquired Arc snapshots stay
            // valid. Subsequent misses need the upstream again and can fail if
            // it is unavailable. This cache owns no routing state: the separate
            // routing cache retains owners and their original expiry deadlines.
            let mut state = poisoned.into_inner();
            *state = ResidentDnsRuntimeCacheState::default();
            shard.clear_poison();
            state
        }
    }
}

impl ResidentDnsRuntimeCache {
    pub(super) fn sweep_all_if_due(&self, now_unix: i64) {
        let reserved = now_unix.saturating_add(DNS_RUNTIME_CACHE_SWEEP_INTERVAL_SECS);
        let Ok(previous) =
            self.next_sweep
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    (next <= now_unix).then_some(reserved)
                })
        else {
            return;
        };
        // Reserve the scan so other writers do not all walk the shards. If the
        // scan unwinds, release its reservation for the next writer to retry.
        let reservation = DropGuard::new((), |()| {
            let _ = self.next_sweep.compare_exchange(
                reserved,
                previous,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        });
        #[cfg(test)]
        tests::interrupt_scan_if_requested(self);
        for shard in &self.shards {
            let mut state = lock_cache_shard(shard);
            sweep_expired_if_due(&mut state, now_unix);
        }
        DropGuard::dismiss(reservation);
    }
}

#[cfg(test)]
mod tests;
