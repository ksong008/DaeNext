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
    json!({
        "group": group.group_name,
        "policy": group.group_policy_name(),
        "candidateCount": group.candidate_count(),
        "admittedCandidateCount": group.admitted_candidate_count(),
        "selectedNodeTag": Value::Null,
        "selectedLinkHash": Value::Null,
        "selectedRedactedLinkSource": Value::Null,
        "selectedNetworkType": Value::Null,
        "selectedLatencyMs": Value::Null,
        "selectedCheckedAtUnix": Value::Null,
        "aliveCandidateCount": Value::Null,
        "selectionSource": RUNTIME_GROUP_SELECTION_SOURCE_UNAVAILABLE,
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
        snapshot["aliveCandidateCount"] = json!(group.admitted_candidate_count());
        snapshot["selectionSource"] = json!(RUNTIME_GROUP_SELECTION_SOURCE_FIXED);
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
    for target in &group.tcp_check.targets {
        if let Some(network_type) = target.network_type_hint() {
            push_unique_runtime_group_network_type(&mut network_types, network_type);
        }
    }
    if network_types.is_empty() {
        network_types.push(RUNTIME_GROUP_SELECTOR_DEFAULT_NETWORK_TYPE);
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
    snapshot["selectedNodeTag"] = json!(candidate.proxy.node_tag);
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
        assert_eq!(snapshot["selectedLatencyMs"], json!(30));
        assert_eq!(snapshot["aliveCandidateCount"], json!(2));
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
        assert_eq!(snapshot["aliveCandidateCount"], json!(2));
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
