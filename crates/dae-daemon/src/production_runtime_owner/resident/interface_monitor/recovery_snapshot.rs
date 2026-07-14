use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Value, json};

use super::network_state::{NetworkFamily, WanMonitorPolicy, WanNetworkState};
use super::recovery_state::{
    REATTACH_REASON_WAN_INTERFACE_SET_CHANGED, RecoveryCandidate, RecoveryDebounce,
    wan_network_change_reasons,
};
use super::*;

pub(super) fn interface_monitor_snapshot_with_wan_state(
    sys_class_net: &Path,
    specs: &[InterfaceMonitorSpec],
    policy: &WanMonitorPolicy,
    baseline_wan: &WanNetworkState,
    current_wan: &WanNetworkState,
    debounce: &mut RecoveryDebounce,
) -> Value {
    let current_auto_ifaces = current_wan
        .auto_route_ifaces
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required_wan_ifaces = policy.current_required_ifaces(current_wan);
    let network_reasons = wan_network_change_reasons(policy, baseline_wan, current_wan);
    let auto_route_set_changed =
        network_reasons.contains(&REATTACH_REASON_WAN_INTERFACE_SET_CHANGED);
    let mut recovery_reasons = network_reasons
        .iter()
        .map(|reason| (*reason).to_owned())
        .collect::<Vec<_>>();
    let mut candidate_interfaces = BTreeMap::<String, InterfaceObservation>::new();
    let mut interfaces = Vec::with_capacity(specs.len());
    let mut identity_reattach_required = false;
    let mut structurally_ready = true;

    for spec in specs {
        let current = observe_interface(sys_class_net, &spec.iface);
        let status = interface_monitor_status(&spec.initial, &current);
        let is_lan = spec.roles.contains(&INTERFACE_ROLE_LAN);
        let is_wan = spec.roles.contains(&INTERFACE_ROLE_WAN);
        let required_by_current_wan = is_wan
            && (!policy.auto_enabled
                || policy.explicit_ifaces.contains(&spec.iface)
                || current_auto_ifaces.contains(&spec.iface));
        let required_now = is_lan || required_by_current_wan;
        if required_now {
            candidate_interfaces.insert(spec.iface.clone(), current.clone());
            if status.reattach_required {
                identity_reattach_required = true;
                for reason in &status.reasons {
                    push_unique_reason(&mut recovery_reasons, reason);
                }
            }
            structurally_ready &= status.reattach_ready;
        } else if !(auto_route_set_changed && is_wan) && status.reattach_required {
            identity_reattach_required = true;
            structurally_ready &= status.reattach_ready;
            for reason in &status.reasons {
                push_unique_reason(&mut recovery_reasons, reason);
            }
        }
        interfaces.push(json!({
            "interface": spec.iface,
            "roles": spec.roles,
            "exists": current.exists,
            "state": status.state,
            "reattachRequired": status.reattach_required,
            "reattachReady": status.reattach_ready,
            "reattachReasons": status.reasons,
            "requiredByCurrentWanState": required_by_current_wan,
            "initial": interface_observation_json(&spec.initial),
            "current": interface_observation_json(&current),
            "expectedIfindex": spec.initial.ifindex,
            "observedIfindex": current.ifindex,
            "expectedMtu": spec.initial.mtu,
            "observedMtu": current.mtu,
            "expectedArphrdType": spec.initial.arphrd,
            "observedArphrdType": current.arphrd,
            "expectedLinkLayer": spec.initial.link_layer,
            "observedLinkLayer": current.link_layer,
        }));
    }

    let mut current_wan_candidates = Vec::new();
    for iface in &required_wan_ifaces {
        let current = candidate_interfaces
            .entry(iface.clone())
            .or_insert_with(|| observe_interface(sys_class_net, iface));
        let identity_ready = current.exists && current.errors.is_empty();
        let address_state_ready =
            required_wan_address_state_ready(baseline_wan, current_wan, iface);
        let ready = identity_ready && address_state_ready;
        structurally_ready &= ready;
        current_wan_candidates.push(json!({
            "interface": iface,
            "exists": current.exists,
            "ready": ready,
            "identityReady": identity_ready,
            "addressStateReady": address_state_ready,
            "current": interface_observation_json(current),
        }));
    }
    if policy.auto_enabled {
        structurally_ready &= current_wan.verified() && !current_wan.auto_route_ifaces.is_empty();
    }
    if current_wan.verified() && !baseline_wan.routes.is_empty() && current_wan.routes.is_empty() {
        structurally_ready = false;
    }

    let reattach_required = identity_reattach_required || !network_reasons.is_empty();
    let candidate = (reattach_required && structurally_ready).then(|| RecoveryCandidate {
        interfaces: candidate_interfaces,
        wan: current_wan.verified().then(|| current_wan.clone()),
    });
    let debounce_observation = debounce.observe(candidate, INTERFACE_RECOVERY_STABLE_OBSERVATIONS);
    let reattach_ready =
        reattach_required && structurally_ready && debounce_observation.stable_ready;
    let poll_interval =
        poll_policy::interval(reattach_required, structurally_ready, reattach_ready);
    json!({
        "schemaVersion": 2,
        "status": if reattach_required || !baseline_wan.verified() || !current_wan.verified() { MONITOR_STATUS_DEGRADED } else { MONITOR_STATUS_PASS },
        "checkedAtUnix": unix_now_secs(),
        "pollIntervalMs": poll_policy::duration_millis(poll_interval),
        "pollPolicy": poll_policy::report(),
        "monitorRunning": true,
        "reattachImplemented": true,
        "reattachRequired": reattach_required,
        "reattachReady": reattach_ready,
        "reattachReasons": recovery_reasons,
        "recoveryDebounce": {
            "structurallyReady": structurally_ready,
            "baselineVerified": baseline_wan.verified(),
            "observationVerified": current_wan.verified(),
            "candidateRevision": debounce_observation.candidate_revision,
            "stableObservations": debounce_observation.stable_observations,
            "requiredStableObservations": INTERFACE_RECOVERY_STABLE_OBSERVATIONS,
        },
        "startupLazyBindAllowed": false,
        "wanPolicy": {
            "autoEnabled": policy.auto_enabled,
            "explicitInterfaces": policy.explicit_ifaces,
            "initialResolvedInterfaces": policy.initial_resolved_ifaces,
        },
        "wanState": {
            "baseline": baseline_wan.to_json(),
            "current": current_wan.to_json(),
            "currentCandidates": current_wan_candidates,
        },
        "interfaces": interfaces,
    })
}

fn push_unique_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_owned());
    }
}

fn required_wan_address_state_ready(
    baseline: &WanNetworkState,
    current: &WanNetworkState,
    iface: &str,
) -> bool {
    if !baseline.verified() || !current.verified() {
        return true;
    }
    let routed_families = current
        .routes
        .iter()
        .filter(|route| route.interface == iface)
        .map(|route| route.family)
        .collect::<BTreeSet<_>>();
    let required_classes = address_classes(baseline, iface)
        .into_iter()
        .filter(|(family, _)| routed_families.contains(family))
        .collect::<BTreeSet<_>>();
    required_classes.is_subset(&address_classes(current, iface))
}

fn address_classes(state: &WanNetworkState, iface: &str) -> BTreeSet<(NetworkFamily, u8)> {
    state
        .addresses
        .get(iface)
        .into_iter()
        .flatten()
        .map(|address| (address.family, address.scope))
        .collect()
}
