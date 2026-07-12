use std::collections::{BTreeMap, BTreeSet};

use super::InterfaceObservation;
use super::network_state::{WanMonitorPolicy, WanNetworkState};

pub(super) const REATTACH_REASON_WAN_ADDRESS_CHANGED: &str = "wan-address-changed";
pub(super) const REATTACH_REASON_WAN_DEFAULT_ROUTE_CHANGED: &str = "wan-default-route-changed";
pub(super) const REATTACH_REASON_WAN_INTERFACE_SET_CHANGED: &str = "wan-interface-set-changed";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoveryCandidate {
    pub(super) interfaces: BTreeMap<String, InterfaceObservation>,
    pub(super) wan: Option<WanNetworkState>,
}

#[derive(Debug, Default)]
pub(super) struct RecoveryDebounce {
    candidate: Option<RecoveryCandidate>,
    stable_observations: u32,
}

impl RecoveryDebounce {
    pub(super) fn observe(
        &mut self,
        candidate: Option<RecoveryCandidate>,
        required_stable_observations: u32,
    ) -> (u32, bool) {
        let required_stable_observations = required_stable_observations.max(1);
        let Some(candidate) = candidate else {
            self.candidate = None;
            self.stable_observations = 0;
            return (0, false);
        };
        if self.candidate.as_ref() == Some(&candidate) {
            self.stable_observations = self.stable_observations.saturating_add(1);
        } else {
            self.candidate = Some(candidate);
            self.stable_observations = 1;
        }
        (
            self.stable_observations,
            self.stable_observations >= required_stable_observations,
        )
    }
}

pub(super) fn wan_network_change_reasons(
    policy: &WanMonitorPolicy,
    baseline: &WanNetworkState,
    current: &WanNetworkState,
) -> Vec<&'static str> {
    if !current.verified() {
        return Vec::new();
    }
    let mut reasons = Vec::new();
    let current_auto_ifaces = current.auto_route_ifaces.iter().cloned().collect();
    let auto_route_set_changed = if baseline.verified() {
        let baseline_auto_ifaces = baseline
            .auto_route_ifaces
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        baseline_auto_ifaces != current_auto_ifaces
    } else {
        policy.auto_route_set_changed_from_initial(&current_auto_ifaces)
    };
    if policy.auto_enabled && auto_route_set_changed {
        reasons.push(REATTACH_REASON_WAN_INTERFACE_SET_CHANGED);
    }
    if baseline.verified() {
        if baseline.routes != current.routes {
            reasons.push(REATTACH_REASON_WAN_DEFAULT_ROUTE_CHANGED);
        }
        if baseline.addresses != current.addresses {
            reasons.push(REATTACH_REASON_WAN_ADDRESS_CHANGED);
        }
    }
    reasons
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::production_runtime_owner::resident::interface_monitor::network_state::{
        DefaultRouteFingerprint, InterfaceAddressFingerprint, NetworkFamily,
    };
    use std::net::IpAddr;

    fn state(address: &str, gateway: &str, iface: &str) -> WanNetworkState {
        WanNetworkState {
            routes: vec![DefaultRouteFingerprint {
                family: NetworkFamily::Ipv4,
                interface: iface.to_owned(),
                gateway: gateway.parse::<IpAddr>().unwrap(),
                metric: 0,
            }],
            addresses: BTreeMap::from([(
                iface.to_owned(),
                vec![InterfaceAddressFingerprint {
                    family: NetworkFamily::Ipv4,
                    address: address.parse::<IpAddr>().unwrap(),
                    prefix_len: 32,
                    peer: None,
                    scope: 0,
                }],
            )]),
            auto_route_ifaces: vec![iface.to_owned()],
            errors: Vec::new(),
        }
    }

    #[test]
    fn network_change_reasons_cover_same_interface_address_and_gateway_changes() {
        let policy = auto_policy("wan0");
        let baseline = state("192.0.2.10", "192.0.2.1", "wan0");
        let changed = state("192.0.2.20", "192.0.2.254", "wan0");
        let reasons = wan_network_change_reasons(&policy, &baseline, &changed);
        assert!(reasons.contains(&REATTACH_REASON_WAN_ADDRESS_CHANGED));
        assert!(reasons.contains(&REATTACH_REASON_WAN_DEFAULT_ROUTE_CHANGED));
        assert!(!reasons.contains(&REATTACH_REASON_WAN_INTERFACE_SET_CHANGED));
    }

    #[test]
    fn network_change_reasons_cover_auto_interface_rename() {
        let policy = auto_policy("ppp0");
        let baseline = state("192.0.2.10", "192.0.2.1", "ppp0");
        let changed = state("198.51.100.20", "198.51.100.1", "ppp1");
        let reasons = wan_network_change_reasons(&policy, &baseline, &changed);
        assert!(reasons.contains(&REATTACH_REASON_WAN_INTERFACE_SET_CHANGED));
        assert!(reasons.contains(&REATTACH_REASON_WAN_ADDRESS_CHANGED));
        assert!(reasons.contains(&REATTACH_REASON_WAN_DEFAULT_ROUTE_CHANGED));
    }

    #[test]
    fn recovery_candidate_must_be_stable_before_ready() {
        let candidate = RecoveryCandidate {
            interfaces: BTreeMap::new(),
            wan: Some(state("192.0.2.10", "192.0.2.1", "wan0")),
        };
        let mut debounce = RecoveryDebounce::default();
        assert_eq!(debounce.observe(Some(candidate.clone()), 2), (1, false));
        assert_eq!(debounce.observe(Some(candidate), 2), (2, true));
        assert_eq!(debounce.observe(None, 2), (0, false));
    }

    #[test]
    fn candidate_change_restarts_the_stability_window() {
        let first = RecoveryCandidate {
            interfaces: BTreeMap::new(),
            wan: Some(state("192.0.2.10", "192.0.2.1", "wan0")),
        };
        let second = RecoveryCandidate {
            interfaces: BTreeMap::new(),
            wan: Some(state("192.0.2.20", "192.0.2.1", "wan0")),
        };
        let mut debounce = RecoveryDebounce::default();

        assert_eq!(debounce.observe(Some(first), 2), (1, false));
        assert_eq!(debounce.observe(Some(second.clone()), 2), (1, false));
        assert_eq!(debounce.observe(Some(second), 2), (2, true));
    }

    #[test]
    fn verified_auto_state_can_recover_when_initial_proc_observation_failed() {
        let policy = auto_policy("ppp0");
        let mut baseline = state("192.0.2.10", "192.0.2.1", "ppp0");
        baseline.errors.push("temporary read failure".to_owned());
        let current = state("198.51.100.20", "198.51.100.1", "ppp1");

        let reasons = wan_network_change_reasons(&policy, &baseline, &current);

        assert_eq!(reasons, [REATTACH_REASON_WAN_INTERFACE_SET_CHANGED]);
    }

    #[test]
    fn unverified_explicit_baseline_does_not_arm_a_periodic_reload() {
        let policy = WanMonitorPolicy {
            auto_enabled: false,
            explicit_ifaces: BTreeSet::from(["wan0".to_owned()]),
            initial_resolved_ifaces: BTreeSet::from(["wan0".to_owned()]),
        };
        let mut baseline = state("192.0.2.10", "192.0.2.1", "wan0");
        baseline.errors.push("temporary read failure".to_owned());
        let current = state("192.0.2.10", "192.0.2.1", "wan0");

        assert!(wan_network_change_reasons(&policy, &baseline, &current).is_empty());
    }

    fn auto_policy(initial_iface: &str) -> WanMonitorPolicy {
        WanMonitorPolicy {
            auto_enabled: true,
            explicit_ifaces: BTreeSet::new(),
            initial_resolved_ifaces: BTreeSet::from([initial_iface.to_owned()]),
        }
    }
}
