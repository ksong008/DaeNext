use std::collections::HashSet;

use dae_product_core::{RuntimeNodeTag, runtime_node_tag};
use serde_json::Value;

use crate::runtime_link_hash;

#[derive(Clone)]
pub(super) struct GroupCandidateRow {
    pub(super) node: Value,
    pub(super) latency_ms: Option<i64>,
    pub(super) alive: bool,
}

#[derive(Clone)]
struct RuntimeGroupSelectionMatcher {
    selected_node_tag: Option<RuntimeNodeTag>,
    selected_link_hash: Option<String>,
}

pub(super) struct GroupMaterializedCandidateSummary {
    pub(super) count: usize,
    pub(super) sample_nodes: Vec<Value>,
    pub(super) current_node: Value,
    pub(super) best_node: Value,
    pub(super) runtime_selected_node: Value,
    runtime_selection: Option<RuntimeGroupSelectionMatcher>,
    best_latency_ms: Option<i64>,
    best_order: usize,
}

impl GroupMaterializedCandidateSummary {
    pub(super) fn new(runtime_selector: Option<&Value>) -> Self {
        Self {
            count: 0,
            sample_nodes: Vec::new(),
            current_node: Value::Null,
            best_node: Value::Null,
            runtime_selected_node: Value::Null,
            runtime_selection: RuntimeGroupSelectionMatcher::from_snapshot(runtime_selector),
            best_latency_ms: None,
            best_order: usize::MAX,
        }
    }

    pub(super) fn push_unique(
        &mut self,
        seen_tags: &mut HashSet<RuntimeNodeTag>,
        candidate: GroupCandidateRow,
        sample_limit: usize,
    ) {
        let tag = runtime_node_tag(&candidate.node);
        if !seen_tags.insert(tag) {
            return;
        }

        let order = self.count;
        self.count = self.count.saturating_add(1);
        if self.current_node.is_null() {
            self.current_node = candidate.node.clone();
        }
        if self.sample_nodes.len() < sample_limit {
            self.sample_nodes.push(candidate.node.clone());
        }
        if self.runtime_selected_node.is_null()
            && let Some(selection) = self.runtime_selection.as_ref()
            && selection.matches_node(&candidate.node)
        {
            self.runtime_selected_node = candidate.node.clone();
        }
        let Some(latency_ms) = candidate.latency_ms.filter(|_| candidate.alive) else {
            return;
        };
        let replace_best = match self.best_latency_ms {
            Some(current_latency) => {
                latency_ms < current_latency
                    || (latency_ms == current_latency && order < self.best_order)
            }
            None => true,
        };
        if replace_best {
            self.best_latency_ms = Some(latency_ms);
            self.best_order = order;
            self.best_node = candidate.node.clone();
            self.current_node = candidate.node;
        }
    }
}

impl RuntimeGroupSelectionMatcher {
    fn from_snapshot(snapshot: Option<&Value>) -> Option<Self> {
        let selected_node_tag = snapshot
            .and_then(|value| value.get("selectedNodeTag"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(RuntimeNodeTag::from_existing);
        let selected_link_hash = snapshot
            .and_then(|value| value.get("selectedLinkHash"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if selected_node_tag.is_none() && selected_link_hash.is_none() {
            return None;
        }
        Some(Self {
            selected_node_tag,
            selected_link_hash,
        })
    }

    fn matches_node(&self, node: &Value) -> bool {
        if let Some(selected_node_tag) = self.selected_node_tag.as_ref()
            && runtime_node_tag(node) == *selected_node_tag
        {
            return true;
        }
        if let Some(selected_link_hash) = self.selected_link_hash.as_deref()
            && node
                .get("link")
                .and_then(Value::as_str)
                .map(runtime_link_hash)
                .as_deref()
                == Some(selected_link_hash)
        {
            return true;
        }
        false
    }
}
