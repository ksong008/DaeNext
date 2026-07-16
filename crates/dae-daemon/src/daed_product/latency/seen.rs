use std::collections::HashSet;

use serde_json::Value;

use super::runtime_snapshots::runtime_link_hash;
use super::storage::runtime_latency_snapshot_link_hash;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct LatencyProbeSeenLinks {
    link_hashes: HashSet<String>,
}

impl LatencyProbeSeenLinks {
    pub(crate) fn record_snapshot(&mut self, snapshot: &Value) {
        if let Some(link_hash) = runtime_latency_snapshot_link_hash(snapshot) {
            self.link_hashes.insert(link_hash.to_owned());
        }
    }

    pub(crate) fn record_snapshots(&mut self, snapshots: &[Value]) {
        for snapshot in snapshots {
            self.record_snapshot(snapshot);
        }
    }

    pub(crate) fn contains_link(&self, link: &str) -> bool {
        self.link_hashes.contains(&runtime_link_hash(link))
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.link_hashes.len()
    }
}
