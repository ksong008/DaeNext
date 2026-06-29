use super::*;

pub(super) fn runtime_traffic_metrics_snapshot(runtime: &ProductRuntimeInstance) -> Option<Value> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.resident_dataplane_metrics_snapshot(),
        ProductRuntimeInstance::Fake(_) => None,
    }
}

pub(super) fn runtime_instance_node_latencies(runtime: &ProductRuntimeInstance) -> Vec<Value> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.snapshot_node_latencies(),
        ProductRuntimeInstance::Fake(_) => Vec::new(),
    }
}

pub(super) fn successful_latency_seed_snapshots(
    values: impl IntoIterator<Item = Value>,
) -> Vec<Value> {
    let mut by_link_hash = BTreeMap::<String, Value>::new();
    for value in values {
        if !latency_seed_snapshot_is_success(&value) {
            continue;
        }
        let Some(link_hash) = runtime_latency_snapshot_link_hash(&value) else {
            continue;
        };
        if link_hash.is_empty() {
            continue;
        }
        by_link_hash.insert(link_hash.to_owned(), value);
    }
    by_link_hash.into_values().collect()
}

fn latency_seed_snapshot_is_success(snapshot: &Value) -> bool {
    snapshot.get("latencyMs").and_then(Value::as_i64).is_some()
        && snapshot
            .get("alive")
            .and_then(Value::as_bool)
            .unwrap_or(true)
}

pub(super) fn apply_runtime_traffic_metric_carry(metrics: &mut Value, key: &str, carry: u64) {
    if carry == 0 {
        return;
    }
    metrics[key] = json!(runtime_traffic_metric_u64(metrics, key).saturating_add(carry));
}

pub(super) fn runtime_traffic_metric_u64(metrics: &Value, key: &str) -> u64 {
    metrics
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
        })
        .unwrap_or(0)
}
