use super::*;

pub(super) fn idle_reclaim_busy_quiet_window(
    now: Instant,
    busy_count: u64,
    busy_completion_count: u64,
    required: Duration,
) -> AllocatorLowTrafficWindow {
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    let Ok(mut state) = state_lock.lock() else {
        return AllocatorLowTrafficWindow {
            elapsed: Duration::ZERO,
            ready: false,
        };
    };
    if busy_count > 0 {
        state.previous_busy_count = busy_count;
        state.previous_busy_completion_count = busy_completion_count;
        state.heavy_task_quiet_since = None;
        return AllocatorLowTrafficWindow {
            elapsed: Duration::ZERO,
            ready: false,
        };
    }
    if state.previous_busy_count > 0 || busy_completion_count > state.previous_busy_completion_count
    {
        state.previous_busy_count = 0;
        state.previous_busy_completion_count = busy_completion_count;
        state.heavy_task_quiet_since = Some(now);
    }
    let Some(since) = state.heavy_task_quiet_since else {
        return AllocatorLowTrafficWindow {
            elapsed: required,
            ready: true,
        };
    };
    let elapsed = now.saturating_duration_since(since);
    if elapsed >= required {
        state.heavy_task_quiet_since = None;
    }
    AllocatorLowTrafficWindow {
        elapsed,
        ready: elapsed >= required,
    }
}

pub(super) fn idle_reclaim_post_burst_quiet_window(
    now: Instant,
    allocated: u64,
    required: Duration,
) -> (bool, AllocatorLowTrafficWindow) {
    let state_lock =
        ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
    let Ok(mut state) = state_lock.lock() else {
        return (
            false,
            AllocatorLowTrafficWindow {
                elapsed: Duration::ZERO,
                ready: false,
            },
        );
    };
    state.allocated_high_water = state.allocated_high_water.max(allocated);
    let released = state.allocated_high_water.saturating_sub(allocated);
    let released_percent = released.saturating_mul(100) / state.allocated_high_water.max(1);
    let post_burst = released >= ALLOCATOR_IDLE_RECLAIM_POST_BURST_THRESHOLD_BYTES
        || released_percent >= ALLOCATOR_IDLE_RECLAIM_POST_BURST_THRESHOLD_PERCENT;
    if !post_burst {
        state.post_burst_quiet_since = None;
        return (
            false,
            AllocatorLowTrafficWindow {
                elapsed: required,
                ready: true,
            },
        );
    }
    let since = state.post_burst_quiet_since.get_or_insert(now);
    let elapsed = now.saturating_duration_since(*since);
    (
        true,
        AllocatorLowTrafficWindow {
            elapsed,
            ready: elapsed >= required,
        },
    )
}

pub(super) fn reset_idle_reclaim_allocated_high_water(allocated: u64) {
    if let Ok(mut state) = ALLOCATOR_IDLE_RECLAIM_STATE
        .get_or_init(|| Mutex::new(default_idle_reclaim_state()))
        .lock()
    {
        state.allocated_high_water = allocated;
        state.post_burst_quiet_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_burst_waits_for_the_full_quiet_window() {
        let state_lock =
            ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
        let mut state = state_lock.lock().unwrap();
        *state = default_idle_reclaim_state();
        state.allocated_high_water = 64 * 1024 * 1024;
        drop(state);
        let started_at = Instant::now();

        let (post_burst, first) = idle_reclaim_post_burst_quiet_window(
            started_at,
            48 * 1024 * 1024,
            Duration::from_secs(30),
        );
        let (_, ready) = idle_reclaim_post_burst_quiet_window(
            started_at + Duration::from_secs(30),
            48 * 1024 * 1024,
            Duration::from_secs(30),
        );

        assert!(post_burst);
        assert!(!first.ready);
        assert_eq!(first.elapsed, Duration::ZERO);
        assert!(ready.ready);
        assert_eq!(ready.elapsed, Duration::from_secs(30));
    }

    #[test]
    fn a_short_busy_lease_completion_starts_the_quiet_window() {
        let state_lock =
            ALLOCATOR_IDLE_RECLAIM_STATE.get_or_init(|| Mutex::new(default_idle_reclaim_state()));
        let mut state = state_lock.lock().unwrap();
        *state = default_idle_reclaim_state();
        state.previous_busy_completion_count = 10;
        drop(state);
        let started_at = Instant::now();

        let first = idle_reclaim_busy_quiet_window(started_at, 0, 11, Duration::from_secs(10));
        let ready = idle_reclaim_busy_quiet_window(
            started_at + Duration::from_secs(10),
            0,
            11,
            Duration::from_secs(10),
        );

        assert!(!first.ready);
        assert!(ready.ready);
    }
}
