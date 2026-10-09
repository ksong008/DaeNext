use super::*;

#[cfg(any(test, feature = "test-support"))]
use dae_resident_core::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use dae_resident_core::{ProxiedDoh3CleanupMetricObservation, ResidentOwnedTaskShutdownCompletion};

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug)]
struct ProxiedDoh3CleanupProfile {
    drain_grace: std::time::Duration,
}

#[cfg(any(test, feature = "test-support"))]
impl ProxiedDoh3CleanupProfile {
    const CURRENT: Self = Self {
        drain_grace: RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxiedDoh3CleanupDeadline(time::Instant);

impl ProxiedDoh3CleanupDeadline {
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_profile() -> Self {
        Self(time::Instant::now() + ProxiedDoh3CleanupProfile::CURRENT.drain_grace)
    }

    pub const fn instant(self) -> time::Instant {
        self.0
    }

    pub const fn from_instant(deadline: time::Instant) -> Self {
        Self(deadline)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_timeout(timeout: std::time::Duration) -> Self {
        Self(time::Instant::now() + timeout)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxiedDoh3EndpointCompletion {
    Idle,
    ForcedDrop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxiedDoh3DriverCompletion {
    Finished,
    Aborted,
}

#[derive(Debug)]
pub struct ProxiedDoh3CleanupOutcome {
    pub deadline: ProxiedDoh3CleanupDeadline,
    pub client_discarded: bool,
    pub connection_closed: bool,
    pub endpoint: Option<ProxiedDoh3EndpointCompletion>,
    pub driver: Option<ProxiedDoh3DriverCompletion>,
    pub bridge: Option<ResidentOwnedTaskShutdownCompletion>,
    pub failures: Vec<String>,
}

impl ProxiedDoh3CleanupOutcome {
    pub fn has_forced_completion(&self) -> bool {
        self.endpoint == Some(ProxiedDoh3EndpointCompletion::ForcedDrop)
            || self.driver == Some(ProxiedDoh3DriverCompletion::Aborted)
            || self.bridge == Some(ResidentOwnedTaskShutdownCompletion::Aborted)
    }

    pub fn endpoint_forced_drop(&self) -> bool {
        self.endpoint == Some(ProxiedDoh3EndpointCompletion::ForcedDrop)
    }

    pub fn driver_aborted(&self) -> bool {
        self.driver == Some(ProxiedDoh3DriverCompletion::Aborted)
    }

    pub fn bridge_aborted(&self) -> bool {
        self.bridge == Some(ResidentOwnedTaskShutdownCompletion::Aborted)
    }

    pub fn failed(&self) -> bool {
        !self.failures.is_empty()
    }

    pub fn record_metrics(&self, metrics: &ResidentDataplaneMetrics) {
        metrics.record_proxied_doh3_cleanup(ProxiedDoh3CleanupMetricObservation::new(
            self.endpoint_forced_drop(),
            self.driver_aborted(),
            self.bridge_aborted(),
            self.failed(),
        ));
    }

    fn completion_label<T: std::fmt::Debug>(completion: Option<T>) -> String {
        completion.map_or_else(|| "not-acquired".to_owned(), |value| format!("{value:?}"))
    }

    fn deadline_label(&self) -> &'static str {
        if time::Instant::now() >= self.deadline.instant() {
            "reached"
        } else {
            "open"
        }
    }
}

impl std::fmt::Display for ProxiedDoh3CleanupOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "client={}, connection={}, endpoint={}, driver={}, bridge={}, deadline={}",
            if self.client_discarded {
                "discarded"
            } else {
                "not-acquired"
            },
            if self.connection_closed {
                "closed"
            } else {
                "not-acquired"
            },
            Self::completion_label(self.endpoint),
            Self::completion_label(self.driver),
            Self::completion_label(self.bridge),
            self.deadline_label(),
        )
    }
}
