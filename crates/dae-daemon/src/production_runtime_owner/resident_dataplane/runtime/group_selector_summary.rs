use super::*;
use dae_outbound::{AliveDialerSet, DialerGroup};

const RUNTIME_GROUP_SELECTION_SOURCE_FIXED: &str = "fixed";
const RUNTIME_GROUP_SELECTION_SOURCE_MIN: &str = "min-runtime-selector";
const RUNTIME_GROUP_SELECTION_SOURCE_RANDOM: &str = "random-alive-set";
const RUNTIME_GROUP_SELECTION_SOURCE_UNAVAILABLE: &str = "unavailable";
const RUNTIME_GROUP_SELECTOR_DEFAULT_NETWORK_TYPE: NetworkType = NetworkType::TCP4;

pub(crate) fn resident_group_selector_snapshot_map(
    groups: &[Arc<plan::ResidentProxyGroupPlan>],
) -> BTreeMap<String, Value> {
    groups
        .iter()
        .map(|group| {
            (
                group.group_name.clone(),
                resident_group_selector_snapshot(group.as_ref()),
            )
        })
        .collect()
}

fn resident_group_selector_snapshot(group: &plan::ResidentProxyGroupPlan) -> Value {
    let mut snapshot = resident_group_selector_base_snapshot(group);
    match group.group_policy {
        plan::ResidentGroupPolicyPlan::Fixed { index } => {
            apply_fixed_group_selection(group, index, &mut snapshot);
        }
        plan::ResidentGroupPolicyPlan::Random => {
            apply_random_group_selection(group, &mut snapshot);
        }
        plan::ResidentGroupPolicyPlan::MinLastLatency
        | plan::ResidentGroupPolicyPlan::MinAverage10
        | plan::ResidentGroupPolicyPlan::MinMovingAverage => {
            apply_min_group_selection(group, &mut snapshot);
        }
    }
    snapshot
}

fn resident_group_selector_base_snapshot(group: &plan::ResidentProxyGroupPlan) -> Value {
    let health_dimensions = group
        .health_state_snapshots()
        .into_iter()
        .map(|snapshot| {
            json!({
                "nodeTag": snapshot.node_tag,
                "linkHash": snapshot.link_hash,
                "executionIdentity": snapshot.execution_identity,
                "networkType": snapshot.network_type.string_without_dns(),
                "networkDimension": snapshot.network_type.dimension_name(),
                "healthState": snapshot.health_state.as_str(),
                "latencyMs": snapshot.latency_ms,
                "alive": snapshot.alive,
                "checkedAtUnix": snapshot.checked_at_unix,
                "lastSuccessAtUnix": snapshot.last_success_at_unix,
                "lastFailureAtUnix": snapshot.last_failure_at_unix,
                "lastUnknownAtUnix": snapshot.last_unknown_at_unix,
                "targetIdentity": snapshot.target_identity,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "group": group.group_name,
        "policy": group.group_policy_name(),
        "candidateCount": group.candidate_count(),
        "admittedCandidateCount": group.admitted_candidate_count(),
        "selectedNodeTag": Value::Null,
        "selectedLinkHash": Value::Null,
        "selectedRedactedLinkSource": Value::Null,
        "selectedNetworkType": Value::Null,
        "selectedNetworkDimension": Value::Null,
        "selectedHealthState": Value::Null,
        "selectedLatencyMs": Value::Null,
        "selectedCheckedAtUnix": Value::Null,
        "aliveCandidateCount": Value::Null,
        "selectionSource": RUNTIME_GROUP_SELECTION_SOURCE_UNAVAILABLE,
        "healthBootstrap": group.health_bootstrap_snapshot_json(),
        "healthDimensions": health_dimensions,
    })
}

fn apply_fixed_group_selection(
    group: &plan::ResidentProxyGroupPlan,
    fixed_index: usize,
    snapshot: &mut Value,
) {
    let selected = group
        .candidates
        .iter()
        .find(|candidate| candidate.match_index == fixed_index);
    if let Some(candidate) = selected {
        apply_candidate_identity(snapshot, candidate);
        snapshot["selectionSource"] = json!(RUNTIME_GROUP_SELECTION_SOURCE_FIXED);
        if let Some(health) =
            preferred_fixed_candidate_health(group, &candidate.binding.plan().node_tag)
        {
            snapshot["selectedNetworkType"] = json!(health.network_type.string_without_dns());
            snapshot["selectedNetworkDimension"] = json!(health.network_type.dimension_name());
            snapshot["selectedHealthState"] = json!(health.health_state.as_str());
            snapshot["selectedLatencyMs"] = json!(health.latency_ms);
            snapshot["selectedCheckedAtUnix"] = json!(health.checked_at_unix);
            snapshot["aliveCandidateCount"] = match health.health_state {
                dae_outbound::HealthState::Alive => json!(1),
                dae_outbound::HealthState::Dead | dae_outbound::HealthState::Unavailable => {
                    json!(0)
                }
                dae_outbound::HealthState::Unknown => Value::Null,
            };
        }
    }
}

fn preferred_fixed_candidate_health(
    group: &plan::ResidentProxyGroupPlan,
    node_tag: &str,
) -> Option<plan::ResidentProxyLatencySnapshot> {
    group
        .health_state_snapshots()
        .into_iter()
        .filter(|snapshot| {
            snapshot.node_tag == node_tag
                && matches!(snapshot.network_type, NetworkType::TCP4 | NetworkType::TCP6)
        })
        .reduce(|current, next| {
            let current_rank = runtime_health_state_rank(current.health_state);
            let next_rank = runtime_health_state_rank(next.health_state);
            if next_rank < current_rank
                || (next_rank == current_rank && next.checked_at_unix > current.checked_at_unix)
            {
                next
            } else {
                current
            }
        })
}

fn runtime_health_state_rank(state: dae_outbound::HealthState) -> u8 {
    match state {
        dae_outbound::HealthState::Alive => 0,
        dae_outbound::HealthState::Dead => 1,
        dae_outbound::HealthState::Unknown => 2,
        dae_outbound::HealthState::Unavailable => 3,
    }
}

fn apply_random_group_selection(group: &plan::ResidentProxyGroupPlan, snapshot: &mut Value) {
    let network_types = runtime_group_tcp_network_types(group);
    let alive_count = group
        .selector
        .lock()
        .ok()
        .and_then(|selector| first_alive_count(&selector, &network_types));
    snapshot["aliveCandidateCount"] = alive_count.map_or(Value::Null, |count| json!(count));
    snapshot["selectionSource"] = json!(RUNTIME_GROUP_SELECTION_SOURCE_RANDOM);
}

fn apply_min_group_selection(group: &plan::ResidentProxyGroupPlan, snapshot: &mut Value) {
    let network_types = runtime_group_tcp_network_types(group);
    let Ok(selector) = group.selector.lock() else {
        return;
    };
    let selected = first_min_selected_candidate(group, &selector, &network_types);
    if let Some(selected) = selected {
        apply_candidate_identity(snapshot, selected.candidate);
        snapshot["selectedNetworkType"] = json!(selected.network_type.string_without_dns());
        snapshot["selectedNetworkDimension"] = json!(selected.network_type.dimension_name());
        snapshot["selectedHealthState"] = json!("alive");
        snapshot["selectedLatencyMs"] = json!(selected.latency_ms);
        snapshot["selectedCheckedAtUnix"] = selected
            .checked_at_unix
            .map_or(Value::Null, |checked_at| json!(checked_at));
        snapshot["aliveCandidateCount"] = selected
            .alive_candidate_count
            .map_or(Value::Null, |count| json!(count));
        snapshot["selectionSource"] = json!(RUNTIME_GROUP_SELECTION_SOURCE_MIN);
    } else {
        snapshot["aliveCandidateCount"] =
            first_alive_count(&selector, &network_types).map_or(Value::Null, |count| json!(count));
    }
}

struct RuntimeSelectedCandidate<'a> {
    candidate: &'a plan::ResidentProxyCandidatePlan,
    network_type: NetworkType,
    latency_ms: i64,
    checked_at_unix: Option<i64>,
    alive_candidate_count: Option<usize>,
}

fn first_min_selected_candidate<'a>(
    group: &'a plan::ResidentProxyGroupPlan,
    selector: &DialerGroup,
    network_types: &[NetworkType],
) -> Option<RuntimeSelectedCandidate<'a>> {
    for network_type in network_types {
        let Some(alive_set) = selector.alive_set(*network_type) else {
            continue;
        };
        let alive_candidate_count = Some(alive_set.alive_count());
        let Some((index, latency_ms)) = alive_set.get_min_latency() else {
            continue;
        };
        let candidate = group.candidates.get(index)?;
        let checked_at_unix = selector
            .dialers
            .get(index)
            .map(|dialer| dialer.last_latency_snapshot(*network_type))
            .and_then(|(_, alive, checked_at, ok)| (ok && alive).then_some(checked_at));
        return Some(RuntimeSelectedCandidate {
            candidate,
            network_type: *network_type,
            latency_ms,
            checked_at_unix,
            alive_candidate_count,
        });
    }
    None
}

fn first_alive_count(selector: &DialerGroup, network_types: &[NetworkType]) -> Option<usize> {
    network_types.iter().find_map(|network_type| {
        selector
            .alive_set(*network_type)
            .map(AliveDialerSet::alive_count)
    })
}

fn runtime_group_tcp_network_types(group: &plan::ResidentProxyGroupPlan) -> Vec<NetworkType> {
    let mut network_types = Vec::new();
    for target in &group.probe_profile.tcp_check.targets {
        if let Some(network_type) = target.network_type_hint() {
            push_unique_runtime_group_network_type(&mut network_types, network_type);
        }
    }
    if network_types.is_empty() {
        network_types.extend([
            RUNTIME_GROUP_SELECTOR_DEFAULT_NETWORK_TYPE,
            NetworkType::TCP6,
        ]);
    }
    network_types
}

fn push_unique_runtime_group_network_type(
    network_types: &mut Vec<NetworkType>,
    network_type: NetworkType,
) {
    if !network_types.contains(&network_type) {
        network_types.push(network_type);
    }
}

fn apply_candidate_identity(snapshot: &mut Value, candidate: &plan::ResidentProxyCandidatePlan) {
    snapshot["selectedNodeTag"] = json!(candidate.binding.plan().node_tag);
    snapshot["selectedLinkHash"] = json!(candidate.link_hash);
    snapshot["selectedRedactedLinkSource"] = json!(candidate.redacted_link_source);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_group_selector_snapshot_reports_runtime_selected_candidate() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://127.0.0.1:1080#node_a'
                node_b: 'socks5://127.0.0.1:1081#node_b'
            }
            group {
                proxy {
                    filter: name(node_a, node_b)
                    policy: min
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = test_proxy_group(&plan);
        group
            .record_check_result("node_a", NetworkType::TCP4, Some(80), 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, Some(30), 2)
            .unwrap();

        let snapshot = resident_group_selector_snapshot(group);

        assert_eq!(snapshot["group"], json!("proxy"));
        assert_eq!(snapshot["policy"], json!("min"));
        assert_eq!(snapshot["selectedNodeTag"], json!("node_b"));
        assert_eq!(snapshot["selectedNetworkType"], json!("tcp4"));
        assert_eq!(snapshot["selectedNetworkDimension"], json!("tcp4"));
        assert_eq!(snapshot["selectedHealthState"], json!("alive"));
        assert_eq!(snapshot["selectedLatencyMs"], json!(30));
        assert_eq!(snapshot["aliveCandidateCount"], json!(2));
        assert!(
            snapshot["healthDimensions"]
                .as_array()
                .is_some_and(|dimensions| dimensions.iter().any(|dimension| {
                    dimension["nodeTag"] == json!("node_b")
                        && dimension["networkDimension"] == json!("tcp4")
                        && dimension["healthState"] == json!("alive")
                }))
        );
    }

    #[test]
    fn min_group_selector_snapshot_uses_next_network_type_when_primary_is_dead() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://127.0.0.1:1080#node_a'
                node_b: 'socks5://127.0.0.1:1081#node_b'
            }
            group {
                proxy {
                    filter: name(node_a, node_b)
                    policy: min
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = test_proxy_group(&plan);
        group
            .record_check_result("node_a", NetworkType::TCP4, None, 1)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP4, None, 2)
            .unwrap();
        group
            .record_check_result("node_a", NetworkType::TCP6, Some(70), 3)
            .unwrap();
        group
            .record_check_result("node_b", NetworkType::TCP6, Some(20), 4)
            .unwrap();

        let snapshot = resident_group_selector_snapshot(group);

        assert_eq!(snapshot["selectedNodeTag"], json!("node_b"));
        assert_eq!(snapshot["selectedNetworkType"], json!("tcp6"));
        assert_eq!(snapshot["selectedLatencyMs"], json!(20));
        assert_eq!(snapshot["aliveCandidateCount"], json!(2));
    }

    #[test]
    fn random_group_selector_snapshot_does_not_sample_a_current_node() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://127.0.0.1:1080#node_a'
                node_b: 'socks5://127.0.0.1:1081#node_b'
            }
            group {
                proxy {
                    filter: name(node_a, node_b)
                    policy: random
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = test_proxy_group(&plan);

        let snapshot = resident_group_selector_snapshot(group);

        assert_eq!(snapshot["group"], json!("proxy"));
        assert_eq!(snapshot["policy"], json!("random"));
        assert!(snapshot["selectedNodeTag"].is_null());
        assert_eq!(snapshot["aliveCandidateCount"], json!(0));
        assert_eq!(
            snapshot["selectionSource"],
            json!(RUNTIME_GROUP_SELECTION_SOURCE_RANDOM)
        );
    }

    #[test]
    fn fixed_group_selector_snapshot_reports_fixed_candidate_without_health_state() {
        let config = parse_test_config(
            r#"
            global {
                lan_interface: daerust0
            }
            node {
                node_a: 'socks5://127.0.0.1:1080#node_a'
                node_b: 'socks5://127.0.0.1:1081#node_b'
            }
            group {
                proxy {
                    filter: name(node_a, node_b)
                    policy: fixed(1)
                }
            }
            routing {
                l4proto(tcp) -> proxy
                fallback: direct
            }
            "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let group = test_proxy_group(&plan);

        let snapshot = resident_group_selector_snapshot(group);

        assert_eq!(snapshot["group"], json!("proxy"));
        assert_eq!(snapshot["policy"], json!("fixed"));
        assert_eq!(snapshot["selectedNodeTag"], json!("node_b"));
        assert_eq!(
            snapshot["selectionSource"],
            json!(RUNTIME_GROUP_SELECTION_SOURCE_FIXED)
        );
    }

    fn parse_test_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    fn test_proxy_group(plan: &plan::ResidentDataplanePlan) -> &plan::ResidentProxyGroupPlan {
        plan.proxies
            .values()
            .find(|group| group.group_name == "proxy")
            .unwrap()
    }
}
