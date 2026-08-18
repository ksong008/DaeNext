use super::*;

#[cfg(test)]
use crate::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use crate::ResidentOwnedTaskShutdownCompletion;
use crate::metrics::ProxiedDoh3CleanupMetricObservation;

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct ProxiedDoh3CleanupProfile {
    drain_grace: std::time::Duration,
}

#[cfg(test)]
impl ProxiedDoh3CleanupProfile {
    const CURRENT: Self = Self {
        drain_grace: RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct ProxiedDoh3CleanupDeadline(time::Instant);

impl ProxiedDoh3CleanupDeadline {
    #[cfg(test)]
    pub(in super::super) fn from_profile() -> Self {
        Self(time::Instant::now() + ProxiedDoh3CleanupProfile::CURRENT.drain_grace)
    }

    pub(in super::super) const fn instant(self) -> time::Instant {
        self.0
    }

    pub(in super::super) const fn from_instant(deadline: time::Instant) -> Self {
        Self(deadline)
    }

    #[cfg(test)]
    pub(in super::super) fn from_timeout(timeout: std::time::Duration) -> Self {
        Self(time::Instant::now() + timeout)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum ProxiedDoh3EndpointCompletion {
    Idle,
    ForcedDrop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum ProxiedDoh3DriverCompletion {
    Finished,
    Aborted,
}

#[derive(Debug)]
pub(in super::super) struct ProxiedDoh3CleanupOutcome {
    pub(in super::super) deadline: ProxiedDoh3CleanupDeadline,
    pub(in super::super) client_discarded: bool,
    pub(in super::super) connection_closed: bool,
    pub(in super::super) endpoint: Option<ProxiedDoh3EndpointCompletion>,
    pub(in super::super) driver: Option<ProxiedDoh3DriverCompletion>,
    pub(in super::super) bridge: Option<ResidentOwnedTaskShutdownCompletion>,
    pub(in super::super) failures: Vec<String>,
}

impl ProxiedDoh3CleanupOutcome {
    pub(in super::super) fn has_forced_completion(&self) -> bool {
        self.endpoint == Some(ProxiedDoh3EndpointCompletion::ForcedDrop)
            || self.driver == Some(ProxiedDoh3DriverCompletion::Aborted)
            || self.bridge == Some(ResidentOwnedTaskShutdownCompletion::Aborted)
    }

    pub(in super::super) fn endpoint_forced_drop(&self) -> bool {
        self.endpoint == Some(ProxiedDoh3EndpointCompletion::ForcedDrop)
    }

    pub(in super::super) fn driver_aborted(&self) -> bool {
        self.driver == Some(ProxiedDoh3DriverCompletion::Aborted)
    }

    pub(in super::super) fn bridge_aborted(&self) -> bool {
        self.bridge == Some(ResidentOwnedTaskShutdownCompletion::Aborted)
    }

    pub(in super::super) fn failed(&self) -> bool {
        !self.failures.is_empty()
    }

    pub(in super::super) fn record_metrics(&self, metrics: &ResidentDataplaneMetrics) {
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
