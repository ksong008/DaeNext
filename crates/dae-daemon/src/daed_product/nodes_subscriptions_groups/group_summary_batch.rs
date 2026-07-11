use super::group_summary::{GroupCandidateRow, GroupMaterializedCandidateSummary};
use super::*;

mod load;

use load::{GroupSummaryDataset, SubscriptionBindingRow};

const GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT: usize = 5;

pub(super) fn list_group_summaries_batched(
    conn: &Connection,
    runtime_selectors: &BTreeMap<String, Value>,
) -> io::Result<Value> {
    let dataset = GroupSummaryDataset::load(conn)?;
    let mut items = Vec::with_capacity(dataset.groups.len());
    for group in &dataset.groups {
        let runtime_selection = runtime_selectors.get(&group.name);
        let direct = dataset
            .direct_candidates
            .get(&group.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let bindings = dataset
            .bindings
            .get(&group.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        items.push(render_group_summary(
            group,
            direct,
            bindings,
            &dataset,
            runtime_selection,
        )?);
    }
    Ok(json!({"items": items}))
}

fn render_group_summary(
    group: &load::GroupSummaryRow,
    direct: &[GroupCandidateRow],
    bindings: &[SubscriptionBindingRow],
    dataset: &GroupSummaryDataset,
    runtime_selection: Option<&Value>,
) -> io::Result<Value> {
    let mut materialized = GroupMaterializedCandidateSummary::new(runtime_selection);
    let mut seen_tags = HashSet::<RuntimeNodeTag>::new();
    for candidate in direct {
        materialized.push_unique(
            &mut seen_tags,
            candidate.clone(),
            GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT,
        );
    }
    let mut subscription_summaries = Vec::with_capacity(bindings.len());
    for binding in bindings {
        subscription_summaries.push(render_subscription_summary(
            binding,
            dataset,
            &mut materialized,
            &mut seen_tags,
        )?);
    }
    let policy_params = dataset
        .policy_params
        .get(&group.id)
        .cloned()
        .unwrap_or_default();
    let first_node = direct
        .first()
        .map(|candidate| candidate.node.clone())
        .unwrap_or(Value::Null);
    let sample_nodes = direct
        .iter()
        .take(GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT)
        .map(|candidate| candidate.node.clone())
        .collect::<Vec<_>>();
    Ok(json!({
        "id": group.id,
        "name": group.name,
        "policy": group.policy,
        "policyParams": policy_params,
        "version": group.version,
        "nodeCount": direct.len(),
        "subscriptionCount": bindings.len(),
        "firstNode": first_node,
        "sampleNodes": sample_nodes,
        "materializedCandidateCount": materialized.count,
        "sampleMaterializedCandidates": materialized.sample_nodes,
        "currentNode": materialized.current_node,
        "bestNode": materialized.best_node,
        "runtimeSelectedNode": materialized.runtime_selected_node,
        "runtimeSelectedNetworkType": runtime_selection_field(runtime_selection, "selectedNetworkType"),
        "runtimeSelectedLatencyMs": runtime_selection_field(runtime_selection, "selectedLatencyMs"),
        "runtimeSelectionSource": runtime_selection_field(runtime_selection, "selectionSource"),
        "runtimeAliveCandidateCount": runtime_selection_field(runtime_selection, "aliveCandidateCount"),
        "subscriptions": subscription_summaries,
    }))
}

fn render_subscription_summary(
    binding: &SubscriptionBindingRow,
    dataset: &GroupSummaryDataset,
    materialized: &mut GroupMaterializedCandidateSummary,
    seen_tags: &mut HashSet<RuntimeNodeTag>,
) -> io::Result<Value> {
    let filter = compile_name_filter(binding.name_filter_regex.as_deref())?;
    let candidates = dataset
        .subscription_candidates
        .get(&binding.subscription_id)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut matched_count = 0usize;
    let mut sample_matched_nodes = Vec::new();
    for candidate in candidates {
        if !node_matches_name_filter(&candidate.node, filter.as_ref()) {
            continue;
        }
        matched_count = matched_count.saturating_add(1);
        if sample_matched_nodes.len() < GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT {
            sample_matched_nodes.push(candidate.node.clone());
        }
        materialized.push_unique(
            seen_tags,
            candidate.clone(),
            GROUP_SUMMARY_MATCHED_NODE_SAMPLE_LIMIT,
        );
    }
    Ok(json!({
        "subscriptionId": binding.subscription_id,
        "nameFilterRegex": binding.name_filter_regex,
        "matchedCount": matched_count,
        "sampleMatchedNodes": sample_matched_nodes,
        "updatedAt": binding.updated_at,
        "status": binding.status,
        "info": binding.info,
        "link": binding.link,
        "tag": binding.tag,
    }))
}

fn runtime_selection_field(runtime_selection: Option<&Value>, field: &str) -> Value {
    runtime_selection
        .and_then(|value| value.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}
