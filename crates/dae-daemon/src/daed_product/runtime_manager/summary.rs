use super::*;

pub(super) fn runtime_instance_health_states(runtime: &ProductRuntimeInstance) -> Vec<Value> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.snapshot_health_states(),
        ProductRuntimeInstance::Fake(_) => Vec::new(),
    }
}

pub(super) fn runtime_instance_dns_reload_snapshot(
    runtime: &ProductRuntimeInstance,
) -> Result<Option<ResidentDnsReloadSnapshot>, String> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.dns_reload_snapshot().map(Some),
        ProductRuntimeInstance::Fake(_) => Ok(None),
    }
}

pub(super) fn runtime_health_seed_snapshots(values: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut by_link_hash = BTreeMap::<String, Value>::new();
    for value in values {
        let Some(execution_identity) = value
            .get("executionIdentity")
            .and_then(Value::as_str)
            .or_else(|| runtime_latency_snapshot_link_hash(&value))
        else {
            continue;
        };
        if execution_identity.is_empty() {
            continue;
        }
        let dimension = value
            .get("networkDimension")
            .and_then(Value::as_str)
            .or_else(|| value.get("networkType").and_then(Value::as_str))
            .unwrap_or("tcp4");
        let key = format!("{execution_identity}|{dimension}");
        let replace = by_link_hash
            .get(&key)
            .map(|current| {
                value
                    .get("checkedAtUnix")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    >= current
                        .get("checkedAtUnix")
                        .and_then(Value::as_i64)
                        .unwrap_or(0)
            })
            .unwrap_or(true);
        if replace {
            by_link_hash.insert(key, value);
        }
    }
    by_link_hash.into_values().collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_seed_merge_keys_execution_identity_and_exact_dimension() {
        let values = runtime_health_seed_snapshots([
            json!({
                "executionIdentity": "sha256:execution",
                "linkHash": "sha256:old-display",
                "networkDimension": "tcp4",
                "healthState": "alive",
                "latencyMs": 45,
                "checkedAtUnix": 10,
            }),
            json!({
                "executionIdentity": "sha256:execution",
                "linkHash": "sha256:new-display",
                "networkDimension": "tcp4",
                "healthState": "dead",
                "latencyMs": null,
                "checkedAtUnix": 11,
            }),
            json!({
                "executionIdentity": "sha256:execution",
                "linkHash": "sha256:new-display",
                "networkDimension": "tcp6",
                "healthState": "unavailable",
                "latencyMs": null,
                "checkedAtUnix": 12,
            }),
        ]);
        assert_eq!(values.len(), 2);
        assert!(values.iter().any(|value| {
            value["networkDimension"] == json!("tcp4")
                && value["healthState"] == json!("dead")
                && value["checkedAtUnix"] == json!(11)
        }));
        assert!(values.iter().any(|value| {
            value["networkDimension"] == json!("tcp6")
                && value["healthState"] == json!("unavailable")
                && value["checkedAtUnix"] == json!(12)
        }));
    }
}
