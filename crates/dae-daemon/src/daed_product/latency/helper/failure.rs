use super::*;

pub(super) fn latency_probe_failure_snapshots(
    links: &[String],
    reload_generation: u64,
    reason: &str,
    detail: &str,
) -> Vec<Value> {
    let checked_at = unix_now() as i64;
    links
        .iter()
        .filter(|link| !link.is_empty())
        .map(|link| {
            let display_name = node_name_from_link(link);
            let link_hash = runtime_link_hash(link);
            let redacted_source = runtime_redacted_link_source(link);
            json!({
                "name": display_name.as_str(),
                "displayName": display_name.as_str(),
                "graphId": graph_id_from_runtime_link_hash(&link_hash),
                "reloadGeneration": reload_generation,
                "linkHash": link_hash.as_str(),
                "linkIdentity": runtime_link_identity_value(&display_name, &link_hash, &redacted_source),
                "admission": {
                    "status": "fail-closed",
                    "unsupportedReason": detail,
                },
                "latencyMs": Value::Null,
                "alive": false,
                "checkedAtUnix": checked_at,
                "message": format!("{reason}: {detail}"),
                "scope": "proxy-tcp-check",
            })
        })
        .collect()
}

pub(crate) fn latency_probe_failure_snapshots_for_unseen_links(
    links: &[String],
    reload_generation: u64,
    reason: &str,
    detail: &str,
    seen_links: &LatencyProbeSeenLinks,
) -> Vec<Value> {
    let unseen_links = links
        .iter()
        .filter(|link| !seen_links.contains_link(link))
        .cloned()
        .collect::<Vec<_>>();
    latency_probe_failure_snapshots(&unseen_links, reload_generation, reason, detail)
}

fn graph_id_from_runtime_link_hash(link_hash: &str) -> String {
    let graph_hash = link_hash.trim_start_matches("sha256:");
    format!("resident-graph:{}", &graph_hash[..16.min(graph_hash.len())])
}
