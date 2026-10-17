use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

trait ClockSource {
    fn wall_unix(&self) -> i64;
    fn monotonic(&self) -> Instant;
}

struct SystemClock;
impl ClockSource for SystemClock {
    fn wall_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
            .unwrap_or(0)
    }
    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

// Keep the existing absolute-deadline indexes in a single process-local epoch.
// Only elapsed monotonic time advances this clock; NTP/manual wall changes do
// not change response, original-TTL, owner, sweep or reload expiration order.
struct CacheClock<S> {
    source: S,
    epoch: Instant,
    epoch_unix: i64,
}
impl<S: ClockSource> CacheClock<S> {
    fn new(source: S) -> Self {
        let epoch = source.monotonic();
        let epoch_unix = source.wall_unix();
        Self {
            source,
            epoch,
            epoch_unix,
        }
    }
    fn now(&self) -> i64 {
        self.epoch_unix.saturating_add(
            self.source
                .monotonic()
                .saturating_duration_since(self.epoch)
                .as_secs()
                .min(i64::MAX as u64) as i64,
        )
    }
}
fn clock() -> &'static CacheClock<SystemClock> {
    static CLOCK: OnceLock<CacheClock<SystemClock>> = OnceLock::new();
    CLOCK.get_or_init(|| CacheClock::new(SystemClock))
}
pub(crate) fn cache_now() -> i64 {
    clock().now()
}
pub(crate) fn cache_epoch() -> Instant {
    clock().epoch
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore};
    use std::cell::Cell;
    use std::time::Duration;
    struct FakeClock {
        wall: Cell<i64>,
        mono: Cell<Instant>,
    }
    impl ClockSource for FakeClock {
        fn wall_unix(&self) -> i64 {
            self.wall.get()
        }
        fn monotonic(&self) -> Instant {
            self.mono.get()
        }
    }
    #[test]
    fn wall_clock_steps_do_not_change_fixed_original_ttls_or_reload_deadlines() {
        let clock = CacheClock::new(FakeClock {
            wall: Cell::new(1_700_000_000),
            mono: Cell::new(Instant::now()),
        });
        let key = DnsCacheKey::new("clock.example", 1, 1);
        let now = clock.now();
        let mut source = DnsCacheStore::new(4096);
        source.insert(now, key.clone(), DnsCacheEntry::new(now + 5, now + 10));
        for wall in [now - 3600, now + 86400, -1, i64::MAX] {
            clock.source.wall.set(wall);
            assert_eq!(clock.now(), now);
            assert!(source.lookup_ref(clock.now(), &key, false).is_some());
        }
        clock.source.mono.set(clock.epoch + Duration::from_secs(6));
        assert!(source.lookup_ref(clock.now(), &key, false).is_none());
        assert!(source.lookup_ref(clock.now(), &key, true).is_some());
        let snapshot = source.snapshot_live_entries_shared(clock.now());
        let mut restored = DnsCacheStore::new(4096);
        for (key, entry) in snapshot {
            restored.insert(clock.now(), key, (*entry).clone());
        }
        assert_eq!(restored.next_expiry_unix(), Some(now + 10));
        clock.source.mono.set(clock.epoch + Duration::from_secs(10));
        assert!(restored.lookup_ref(clock.now(), &key, true).is_none());
        assert!(source.lookup_ref(clock.now(), &key, true).is_none());
    }
}
