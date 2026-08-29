use std::collections::BTreeMap;

use serde_json::Value;

pub fn runtime_health_seed_snapshots(values: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut snapshots = BTreeMap::<String, Value>::new();
    for value in values {
        let Some(execution_identity) = value
            .get("executionIdentity")
            .and_then(Value::as_str)
            .or_else(|| {
                value.get("linkHash").and_then(Value::as_str).or_else(|| {
                    value
                        .pointer("/linkIdentity/linkHash")
                        .and_then(Value::as_str)
                })
            })
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
        let replace = snapshots
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
            snapshots.insert(key, value);
        }
    }
    snapshots.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    #[test]
    fn health_seed_uses_link_identity_when_execution_identity_is_missing() {
        let values = runtime_health_seed_snapshots([json!({
            "linkIdentity": {"linkHash": "sha256:link"},
            "checkedAtUnix": 1,
        })]);
        assert_eq!(values.len(), 1);
    }
}
