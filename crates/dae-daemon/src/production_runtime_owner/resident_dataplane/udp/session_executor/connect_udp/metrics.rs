use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConnectUdpConnectionRetirementReason {
    GoAway,
    Reset,
    Other,
}

#[derive(Default)]
pub(super) struct ConnectUdpPoolEvents {
    connection_retirements: AtomicUsize,
    goaway_events: AtomicUsize,
    reset_events: AtomicUsize,
    queue_full_events: AtomicUsize,
    mtu_rejections: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ConnectUdpPoolEventSnapshot {
    pub(super) connection_retirements: usize,
    pub(super) goaway_events: usize,
    pub(super) reset_events: usize,
    pub(super) queue_full_events: usize,
    pub(super) mtu_rejections: usize,
}

impl ConnectUdpPoolEvents {
    pub(super) fn record_retirement(&self, reason: ConnectUdpConnectionRetirementReason) {
        self.connection_retirements.fetch_add(1, Ordering::Relaxed);
        match reason {
            ConnectUdpConnectionRetirementReason::GoAway => {
                self.goaway_events.fetch_add(1, Ordering::Relaxed);
            }
            ConnectUdpConnectionRetirementReason::Reset => {
                self.reset_events.fetch_add(1, Ordering::Relaxed);
            }
            ConnectUdpConnectionRetirementReason::Other => {}
        }
    }

    pub(super) fn record_reset(&self) {
        self.reset_events.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_queue_full(&self) {
        self.queue_full_events.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_mtu_rejection(&self) {
        self.mtu_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> ConnectUdpPoolEventSnapshot {
        ConnectUdpPoolEventSnapshot {
            connection_retirements: self.connection_retirements.load(Ordering::Relaxed),
            goaway_events: self.goaway_events.load(Ordering::Relaxed),
            reset_events: self.reset_events.load(Ordering::Relaxed),
            queue_full_events: self.queue_full_events.load(Ordering::Relaxed),
            mtu_rejections: self.mtu_rejections.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_snapshot_keeps_retirement_reason_and_pressure_separate() {
        let events = ConnectUdpPoolEvents::default();
        events.record_retirement(ConnectUdpConnectionRetirementReason::GoAway);
        events.record_retirement(ConnectUdpConnectionRetirementReason::Reset);
        events.record_retirement(ConnectUdpConnectionRetirementReason::Other);
        events.record_reset();
        events.record_queue_full();
        events.record_mtu_rejection();
        assert_eq!(
            events.snapshot(),
            ConnectUdpPoolEventSnapshot {
                connection_retirements: 3,
                goaway_events: 1,
                reset_events: 2,
                queue_full_events: 1,
                mtu_rejections: 1,
            }
        );
    }
}
