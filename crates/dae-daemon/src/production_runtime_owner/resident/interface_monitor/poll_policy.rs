use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const STEADY_POLL: Duration = Duration::from_secs(2);
const HOST_UNAVAILABLE_POLL: Duration = Duration::from_millis(250);
const RECOVERY_SETTLE_POLL: Duration = Duration::from_secs(1);
const STOP_CHECK_INTERVAL: Duration = Duration::from_millis(100);

pub(super) fn interval(
    reattach_required: bool,
    structurally_ready: bool,
    reattach_ready: bool,
) -> Duration {
    if !reattach_required {
        STEADY_POLL
    } else if structurally_ready && !reattach_ready {
        RECOVERY_SETTLE_POLL
    } else {
        HOST_UNAVAILABLE_POLL
    }
}

pub(super) fn interval_from_snapshot(snapshot: &Value) -> Duration {
    interval(
        snapshot["reattachRequired"].as_bool().unwrap_or(false),
        snapshot["recoveryDebounce"]["structurallyReady"]
            .as_bool()
            .unwrap_or(false),
        snapshot["reattachReady"].as_bool().unwrap_or(false),
    )
}

pub(super) fn report() -> Value {
    json!({
        "steadyMs": duration_millis(STEADY_POLL),
        "hostUnavailableMs": duration_millis(HOST_UNAVAILABLE_POLL),
        "recoverySettleMs": duration_millis(RECOVERY_SETTLE_POLL),
        "policy": "steady polling remains low frequency; a missing host resource is rechecked quickly; a structurally ready replacement must remain stable across the settle interval",
    })
}

pub(super) fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

pub(super) fn sleep_interruptibly(stop: &AtomicBool, duration: Duration) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        thread::sleep((deadline - now).min(STOP_CHECK_INTERVAL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_interface_polling_is_fast_only_while_recovery_is_pending() {
        assert_eq!(interval(false, true, false), Duration::from_secs(2));
        assert_eq!(interval(true, false, false), Duration::from_millis(250));
        assert_eq!(interval(true, true, false), Duration::from_secs(1));
        assert_eq!(interval(true, true, true), Duration::from_millis(250));
    }
}
