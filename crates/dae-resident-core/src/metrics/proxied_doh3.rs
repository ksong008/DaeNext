use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use super::ResidentDataplaneMetrics;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxiedDoh3CleanupMetricObservation {
    endpoint_forced_drop: bool,
    driver_aborted: bool,
    bridge_aborted: bool,
    failed: bool,
}

impl ProxiedDoh3CleanupMetricObservation {
    pub const fn new(
        endpoint_forced_drop: bool,
        driver_aborted: bool,
        bridge_aborted: bool,
        failed: bool,
    ) -> Self {
        Self {
            endpoint_forced_drop,
            driver_aborted,
            bridge_aborted,
            failed,
        }
    }

    fn forced(self) -> bool {
        self.endpoint_forced_drop || self.driver_aborted || self.bridge_aborted
    }
}

#[derive(Debug, Default)]
pub(super) struct ProxiedDoh3CleanupMetrics {
    completed: AtomicU64,
    graceful: AtomicU64,
    forced: AtomicU64,
    failed: AtomicU64,
    endpoint_forced_drop: AtomicU64,
    driver_aborted: AtomicU64,
    bridge_aborted: AtomicU64,
}

impl ProxiedDoh3CleanupMetrics {
    pub fn record(&self, input: ProxiedDoh3CleanupMetricObservation) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        if input.endpoint_forced_drop {
            self.endpoint_forced_drop.fetch_add(1, Ordering::Relaxed);
        }
        if input.driver_aborted {
            self.driver_aborted.fetch_add(1, Ordering::Relaxed);
        }
        if input.bridge_aborted {
            self.bridge_aborted.fetch_add(1, Ordering::Relaxed);
        }
        if input.failed {
            self.failed.fetch_add(1, Ordering::Relaxed);
        } else if input.forced() {
            self.forced.fetch_add(1, Ordering::Relaxed);
        } else {
            self.graceful.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> Value {
        json!({
            "completedTotal": self.completed.load(Ordering::Relaxed),
            "completionClasses": {
                "graceful": self.graceful.load(Ordering::Relaxed),
                "forced": self.forced.load(Ordering::Relaxed),
                "failed": self.failed.load(Ordering::Relaxed),
            },
            "forcedComponents": {
                "endpointDrop": self.endpoint_forced_drop.load(Ordering::Relaxed),
                "driverAbort": self.driver_aborted.load(Ordering::Relaxed),
                "bridgeAbort": self.bridge_aborted.load(Ordering::Relaxed),
            },
        })
    }
}

impl ResidentDataplaneMetrics {
    pub fn record_proxied_doh3_cleanup(&self, observation: ProxiedDoh3CleanupMetricObservation) {
        self.proxied_doh3_cleanup.record(observation);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn proxied_doh3_cleanup_snapshot(&self) -> Value {
        self.proxied_doh3_cleanup.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_classes_and_forced_components_are_counted_independently() {
        let metrics = ProxiedDoh3CleanupMetrics::default();
        metrics.record(ProxiedDoh3CleanupMetricObservation {
            endpoint_forced_drop: false,
            driver_aborted: false,
            bridge_aborted: false,
            failed: false,
        });
        metrics.record(ProxiedDoh3CleanupMetricObservation {
            endpoint_forced_drop: true,
            driver_aborted: true,
            bridge_aborted: true,
            failed: false,
        });
        metrics.record(ProxiedDoh3CleanupMetricObservation {
            endpoint_forced_drop: false,
            driver_aborted: true,
            bridge_aborted: false,
            failed: true,
        });

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["completedTotal"], 3);
        assert_eq!(snapshot["completionClasses"]["graceful"], 1);
        assert_eq!(snapshot["completionClasses"]["forced"], 1);
        assert_eq!(snapshot["completionClasses"]["failed"], 1);
        assert_eq!(snapshot["forcedComponents"]["endpointDrop"], 1);
        assert_eq!(snapshot["forcedComponents"]["driverAbort"], 2);
        assert_eq!(snapshot["forcedComponents"]["bridgeAbort"], 1);
    }

    #[test]
    fn cleanup_classes_are_queryable_from_the_runtime_snapshot() {
        let metrics = ResidentDataplaneMetrics::default();
        metrics.record_proxied_doh3_cleanup(ProxiedDoh3CleanupMetricObservation::new(
            true, true, false, false,
        ));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot["proxiedDoh3Cleanup"]["completedTotal"], 1);
        assert_eq!(
            snapshot["proxiedDoh3Cleanup"]["completionClasses"]["forced"],
            1
        );
        assert_eq!(
            snapshot["proxiedDoh3Cleanup"]["forcedComponents"]["endpointDrop"],
            1
        );
        assert_eq!(
            snapshot["proxiedDoh3Cleanup"]["forcedComponents"]["driverAbort"],
            1
        );
    }
}
