use super::network_state::{WanMonitorPolicy, WanNetworkState};

#[derive(Debug)]
pub(super) struct WanBaselineTracker {
    baseline: WanNetworkState,
    candidate: Option<WanNetworkState>,
    stable_observations: u32,
}

impl WanBaselineTracker {
    pub(super) fn new(baseline: WanNetworkState) -> Self {
        Self {
            baseline,
            candidate: None,
            stable_observations: 0,
        }
    }

    pub(super) fn baseline(&self) -> &WanNetworkState {
        &self.baseline
    }

    pub(super) fn observe(
        &mut self,
        policy: &WanMonitorPolicy,
        current: &WanNetworkState,
        required_stable_observations: u32,
    ) {
        if self.baseline.verified() {
            return;
        }
        if !can_adopt_current_state(policy, current) {
            self.candidate = None;
            self.stable_observations = 0;
            return;
        }

        if self.candidate.as_ref() == Some(current) {
            self.stable_observations = self.stable_observations.saturating_add(1);
        } else {
            self.candidate = Some(current.clone());
            self.stable_observations = 1;
        }
        if self.stable_observations >= required_stable_observations.max(1) {
            self.baseline = current.clone();
            self.candidate = None;
            self.stable_observations = 0;
        }
    }
}

fn can_adopt_current_state(policy: &WanMonitorPolicy, current: &WanNetworkState) -> bool {
    if !current.verified() {
        return false;
    }
    if !policy.auto_enabled {
        return true;
    }
    let current_auto_ifaces = current.auto_route_ifaces.iter().cloned().collect();
    !policy.auto_route_set_changed_from_initial(&current_auto_ifaces)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;

    use super::*;
    use crate::production_runtime_owner::resident::interface_monitor::network_state::{
        DefaultRouteFingerprint, InterfaceAddressFingerprint, NetworkFamily,
    };

    #[test]
    fn explicit_wan_adopts_a_verified_stable_baseline_without_reload() {
        let policy = explicit_policy("wan0");
        let mut tracker = WanBaselineTracker::new(unverified_state("wan0"));
        let current = state("wan0", "192.0.2.10");

        tracker.observe(&policy, &current, 2);
        assert!(!tracker.baseline().verified());
        tracker.observe(&policy, &current, 2);
        assert_eq!(tracker.baseline(), &current);
    }

    #[test]
    fn a_changing_candidate_restarts_baseline_adoption() {
        let policy = explicit_policy("wan0");
        let mut tracker = WanBaselineTracker::new(unverified_state("wan0"));
        let first = state("wan0", "192.0.2.10");
        let second = state("wan0", "192.0.2.20");

        tracker.observe(&policy, &first, 2);
        tracker.observe(&policy, &second, 2);
        assert!(!tracker.baseline().verified());
        tracker.observe(&policy, &second, 2);
        assert_eq!(tracker.baseline(), &second);
    }

    #[test]
    fn auto_wan_does_not_adopt_a_different_route_interface_as_its_baseline() {
        let policy = WanMonitorPolicy {
            auto_enabled: true,
            explicit_ifaces: BTreeSet::new(),
            initial_resolved_ifaces: BTreeSet::from(["wan0".to_owned()]),
        };
        let mut tracker = WanBaselineTracker::new(unverified_state("wan0"));
        let current = state("wan1", "198.51.100.10");

        for _ in 0..3 {
            tracker.observe(&policy, &current, 2);
        }
        assert!(!tracker.baseline().verified());
    }

    #[test]
    fn unverified_current_state_never_advances_baseline_adoption() {
        let policy = explicit_policy("wan0");
        let baseline = unverified_state("wan0");
        let mut tracker = WanBaselineTracker::new(baseline.clone());
        let current = unverified_state("wan0");

        for _ in 0..3 {
            tracker.observe(&policy, &current, 2);
        }
        assert_eq!(tracker.baseline(), &baseline);
    }

    fn explicit_policy(iface: &str) -> WanMonitorPolicy {
        WanMonitorPolicy {
            auto_enabled: false,
            explicit_ifaces: BTreeSet::from([iface.to_owned()]),
            initial_resolved_ifaces: BTreeSet::from([iface.to_owned()]),
        }
    }

    fn unverified_state(iface: &str) -> WanNetworkState {
        let mut state = state(iface, "192.0.2.10");
        state
            .errors
            .push("temporary observation failure".to_owned());
        state
    }

    fn state(iface: &str, address: &str) -> WanNetworkState {
        WanNetworkState {
            routes: vec![DefaultRouteFingerprint {
                family: NetworkFamily::Ipv4,
                interface: iface.to_owned(),
                gateway: "192.0.2.1".parse::<IpAddr>().unwrap(),
                metric: 0,
            }],
            addresses: BTreeMap::from([(
                iface.to_owned(),
                vec![InterfaceAddressFingerprint {
                    family: NetworkFamily::Ipv4,
                    address: address.parse::<IpAddr>().unwrap(),
                    prefix_len: 24,
                    peer: None,
                    scope: 0,
                }],
            )]),
            auto_route_ifaces: vec![iface.to_owned()],
            errors: Vec::new(),
        }
    }
}
