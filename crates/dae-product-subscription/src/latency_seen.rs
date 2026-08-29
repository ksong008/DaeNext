use std::collections::HashSet;

use serde_json::Value;

use crate::{runtime_latency_snapshot_link_hash, runtime_link_hash};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LatencyProbeSeenLinks {
    link_hashes: HashSet<String>,
}

impl LatencyProbeSeenLinks {
    pub fn record_snapshot(&mut self, snapshot: &Value) {
        if let Some(link_hash) = runtime_latency_snapshot_link_hash(snapshot) {
            self.link_hashes.insert(link_hash.to_owned());
        }
    }

    pub fn record_snapshots(&mut self, snapshots: &[Value]) {
        for snapshot in snapshots {
            self.record_snapshot(snapshot);
        }
    }

    pub fn contains_link(&self, link: &str) -> bool {
        self.link_hashes.contains(&runtime_link_hash(link))
    }

    pub fn len(&self) -> usize {
        self.link_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.link_hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn seen_links_deduplicate_runtime_snapshots_by_link_identity() {
        let mut seen = LatencyProbeSeenLinks::default();
        seen.record_snapshots(&[
            json!({"linkHash": runtime_link_hash("socks5://one.example:1080")}),
            json!({"linkHash": runtime_link_hash("socks5://one.example:1080")}),
        ]);

        assert_eq!(seen.len(), 1);
        assert!(seen.contains_link("socks5://one.example:1080"));
        assert!(!seen.contains_link("socks5://two.example:1080"));
    }
}
