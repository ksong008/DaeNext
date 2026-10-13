use super::*;
use std::sync::MutexGuard;

pub(super) fn lock_cache_shard(
    shard: &Mutex<ResidentDnsRuntimeCacheState>,
) -> MutexGuard<'_, ResidentDnsRuntimeCacheState> {
    match shard.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            // Responses are an optional cache with no external owner. A panic
            // can leave its entry and deadline indexes inconsistent; discard
            // this shard rather than reuse partially mutated state or disable
            // unrelated queries permanently. Routing owners live separately.
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
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    (next <= now_unix).then_some(reserved)
                })
        else {
            return;
        };
        // Reserve the scan so other writers do not all walk the shards. If the
        // scan unwinds, release its reservation for the next writer to retry.
        let mut reservation = SweepReservation {
            gate: &self.next_sweep,
            previous,
            reserved,
            completed: false,
        };
        for shard in &self.shards {
            let mut state = lock_cache_shard(shard);
            sweep_expired_if_due(&mut state, now_unix);
        }
        reservation.completed = true;
    }
}

struct SweepReservation<'a> {
    gate: &'a AtomicI64,
    previous: i64,
    reserved: i64,
    completed: bool,
}

impl Drop for SweepReservation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.gate.compare_exchange(
                self.reserved,
                self.previous,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }
}

#[cfg(test)]
mod tests;
