use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::stable_digest;

#[derive(Clone, Debug)]
pub(super) struct ReloadPlanSnapshot {
    pub(super) config: &'static str,
    pub(super) dns: &'static str,
    pub(super) routing: &'static str,
    pub(super) groups: &'static [(&'static str, &'static str)],
    pub(super) nodes: &'static [(&'static str, &'static str)],
    pub(super) proxy_graph: &'static [(&'static str, &'static str)],
}

pub(super) fn reference_reload_plan_snapshot() -> ReloadPlanSnapshot {
    ReloadPlanSnapshot {
        config: "global-log-info-resource-defaults",
        dns: "dns-bind-default-upstream-default",
        routing: "routing-fallback-proxy-group",
        groups: &[("default", "policy-min-two-candidates")],
        nodes: &[("primary", "node-primary-capability-hash")],
        proxy_graph: &[("primary", "graph-primary-capability-hash")],
    }
}

pub(super) fn changed_node_reload_plan_snapshot() -> ReloadPlanSnapshot {
    ReloadPlanSnapshot {
        nodes: &[("primary", "node-primary-updated-capability-hash")],
        proxy_graph: &[("primary", "graph-primary-updated-capability-hash")],
        ..reference_reload_plan_snapshot()
    }
}

pub(super) fn reload_plan_identity_value(snapshot: &ReloadPlanSnapshot) -> Value {
    let group_hashes = named_digest_map(snapshot.groups);
    let node_hashes = named_digest_map(snapshot.nodes);
    let proxy_graph_hashes = named_digest_map(snapshot.proxy_graph);
    let config_hash = stable_digest(snapshot.config);
    let dns_hash = stable_digest(snapshot.dns);
    let routing_hash = stable_digest(snapshot.routing);
    let identity_input = format!(
        "config={config_hash};dns={dns_hash};routing={routing_hash};groups={group_hashes:?};nodes={node_hashes:?};proxyGraph={proxy_graph_hashes:?}"
    );
    json!({
        "schemaVersion": 1,
        "configHash": config_hash,
        "dnsHash": dns_hash,
        "routingHash": routing_hash,
        "groupHashes": group_hashes,
        "nodeHashes": node_hashes,
        "proxyGraphHashes": proxy_graph_hashes,
        "planHash": stable_digest(&identity_input),
        "rawConfigStored": false,
        "rawNodeLinksStored": false,
    })
}

pub(super) fn reload_diff_contract_value(
    before: &ReloadPlanSnapshot,
    changed: &ReloadPlanSnapshot,
) -> Value {
    let equal = reload_diff_value(before, before);
    let single_node_change = reload_diff_value(before, changed);
    let pass = equal["unchangedNodeCount"].as_u64() == Some(before.nodes.len() as u64)
        && equal["changedNodeCount"].as_u64() == Some(0)
        && single_node_change["changedNodeCount"].as_u64() == Some(1)
        && single_node_change["changedProxyGraphCount"].as_u64() == Some(1)
        && single_node_change["unchangedGroupCount"].as_u64() == Some(before.groups.len() as u64)
        && single_node_change["dnsCompatible"].as_bool() == Some(true)
        && single_node_change["routingCompatible"].as_bool() == Some(true);
    json!({
        "status": if pass { "pass" } else { "fail" },
        "equalConfig": equal,
        "singleNodeChange": single_node_change,
    })
}

pub(super) fn reload_diff_value(before: &ReloadPlanSnapshot, after: &ReloadPlanSnapshot) -> Value {
    let before_identity = reload_plan_identity_value(before);
    let after_identity = reload_plan_identity_value(after);
    let group_diff = named_digest_diff(before.groups, after.groups);
    let node_diff = named_digest_diff(before.nodes, after.nodes);
    let proxy_graph_diff = named_digest_diff(before.proxy_graph, after.proxy_graph);
    let dns_compatible = before_identity["dnsHash"] == after_identity["dnsHash"];
    let routing_compatible = before_identity["routingHash"] == after_identity["routingHash"];
    json!({
        "schemaVersion": 1,
        "beforePlanHash": before_identity["planHash"],
        "afterPlanHash": after_identity["planHash"],
        "configCompatible": before_identity["configHash"] == after_identity["configHash"],
        "dnsCompatible": dns_compatible,
        "routingCompatible": routing_compatible,
        "unchangedGroupCount": group_diff.unchanged.len(),
        "changedGroupCount": group_diff.changed.len(),
        "addedGroupCount": group_diff.added.len(),
        "removedGroupCount": group_diff.removed.len(),
        "unchangedNodeCount": node_diff.unchanged.len(),
        "changedNodeCount": node_diff.changed.len(),
        "addedNodeCount": node_diff.added.len(),
        "removedNodeCount": node_diff.removed.len(),
        "unchangedProxyGraphCount": proxy_graph_diff.unchanged.len(),
        "changedProxyGraphCount": proxy_graph_diff.changed.len(),
        "addedProxyGraphCount": proxy_graph_diff.added.len(),
        "removedProxyGraphCount": proxy_graph_diff.removed.len(),
        "unchangedGroups": group_diff.unchanged,
        "changedGroups": group_diff.changed,
        "addedGroups": group_diff.added,
        "removedGroups": group_diff.removed,
        "unchangedNodes": node_diff.unchanged,
        "changedNodes": node_diff.changed,
        "addedNodes": node_diff.added,
        "removedNodes": node_diff.removed,
        "unchangedProxyGraphs": proxy_graph_diff.unchanged,
        "changedProxyGraphs": proxy_graph_diff.changed,
        "addedProxyGraphs": proxy_graph_diff.added,
        "removedProxyGraphs": proxy_graph_diff.removed,
    })
}

pub(super) fn reload_state_reuse_value(diff_contract: &Value) -> Value {
    let Some(diff) = diff_contract.get("singleNodeChange") else {
        return json!({"status": "fail", "error": "missing single-node reload diff"});
    };
    let dns_reused = diff["dnsCompatible"].as_bool().unwrap_or(false);
    let routing_reused = diff["routingCompatible"].as_bool().unwrap_or(false);
    let unchanged_groups = diff["unchangedGroupCount"].as_u64().unwrap_or(0);
    let unchanged_nodes = diff["unchangedNodeCount"].as_u64().unwrap_or(0);
    let unchanged_proxy_graphs = diff["unchangedProxyGraphCount"].as_u64().unwrap_or(0);
    let changed_nodes = diff["changedNodeCount"].as_u64().unwrap_or(0);
    let changed_proxy_graphs = diff["changedProxyGraphCount"].as_u64().unwrap_or(0);
    let passed = dns_reused
        && routing_reused
        && unchanged_groups > 0
        && changed_nodes == changed_proxy_graphs
        && changed_nodes > 0;
    json!({
        "status": if passed { "pass" } else { "fail" },
        "latencySnapshotsReusedForUnchangedNodes": unchanged_nodes,
        "aliveStateReusedForUnchangedGroups": unchanged_groups,
        "proxyGraphsReused": unchanged_proxy_graphs,
        "proxyGraphsRebuilt": changed_proxy_graphs,
        "dnsCacheReuse": if dns_reused { "compatible" } else { "discard" },
        "routingMapUpdate": if routing_reused { "diff" } else { "rebuild" },
        "healthCheckScheduleReuse": unchanged_groups,
    })
}

#[derive(Debug)]
struct NamedDigestDiff {
    unchanged: Vec<String>,
    changed: Vec<String>,
    added: Vec<String>,
    removed: Vec<String>,
}

fn named_digest_diff(
    before: &[(&'static str, &'static str)],
    after: &[(&'static str, &'static str)],
) -> NamedDigestDiff {
    let before_map = named_digest_map(before);
    let after_map = named_digest_map(after);
    let before_names = before_map.keys().cloned().collect::<BTreeSet<_>>();
    let after_names = after_map.keys().cloned().collect::<BTreeSet<_>>();
    let mut unchanged = Vec::new();
    let mut changed = Vec::new();
    for name in before_names.intersection(&after_names) {
        if before_map.get(name) == after_map.get(name) {
            unchanged.push(name.clone());
        } else {
            changed.push(name.clone());
        }
    }
    NamedDigestDiff {
        unchanged,
        changed,
        added: after_names.difference(&before_names).cloned().collect(),
        removed: before_names.difference(&after_names).cloned().collect(),
    }
}

fn named_digest_map(values: &[(&'static str, &'static str)]) -> BTreeMap<String, u64> {
    values
        .iter()
        .map(|(name, value)| ((*name).to_owned(), stable_digest(value)))
        .collect()
}
