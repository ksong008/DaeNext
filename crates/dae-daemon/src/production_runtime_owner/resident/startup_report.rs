use super::*;
pub(super) fn compact_start_report_for_runtime(start_report: &Value) -> Value {
    let attach_backend = actual_resident_attach_backend(start_report).or_else(|| {
        start_report
            .pointer("/resident_interface_backend_policy/effective_backend")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let netns_link_mode = selected_netns_link_mode(start_report).or_else(|| {
        start_report
            .pointer("/topology_values/requested_netns_link_mode")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let startup_evidence = startup_evidence_from_report(start_report);
    json!({
        "name": start_report["name"].clone(),
        "status": start_report["status"].clone(),
        "artifact_dir": start_report["artifact_dir"].clone(),
        "start_file": start_report["start_file"].clone(),
        "cleanup_file": start_report["cleanup_file"].clone(),
        "tproxy_port": start_report["tproxy_port"].clone(),
        "resident_runtime_started": start_report["resident_runtime_started"].clone(),
        "resident_dataplane": start_report["resident_dataplane"].clone(),
        "resident_interface_monitor": start_report["resident_interface_monitor"].clone(),
        "resident_datapath_binding_registry": start_report["resident_datapath_binding_registry"].clone(),
        "resident_datapath_binding_postflight": start_report["resident_datapath_binding_postflight"].clone(),
        "runtimeGeneration": start_report["runtimeGeneration"].clone(),
        "attachBackend": attach_backend,
        "netnsLinkMode": netns_link_mode,
        "startupEvidence": startup_evidence,
        "stored_summary_only": true,
        "full_start_report_file": start_report["start_file"].clone(),
    })
}

pub(super) fn resident_start_failure_summary(start_report: &Value) -> Option<String> {
    let mut failures = Vec::new();
    collect_startup_blocking_failures(start_report, &mut failures);
    if failures.is_empty() {
        collect_failed_statuses("$", start_report, &mut failures);
    }
    if failures.is_empty() {
        None
    } else {
        Some(failures.join("; "))
    }
}

fn collect_startup_blocking_failures(start_report: &Value, failures: &mut Vec<String>) {
    for path in [
        "topology_readiness",
        "param_image",
        "native_param_image",
        "loaded_map_handoff",
        "resident_cgroup_attach",
        "resident_wan_attach",
        "resident_lan_attach",
        "resident_lan_routing",
        "resident_dataplane",
        "host_attach_show",
        "peer_attach_show",
        "resident_outbound_connectivity",
        "resident_interface_monitor",
        "resident_datapath_binding_postflight",
    ] {
        let pointer = format!("/{}", path.replace('.', "/"));
        if let Some(value) = start_report.pointer(&pointer) {
            collect_failed_statuses(path, value, failures);
        }
        if failures.len() >= 4 {
            return;
        }
    }
}

fn collect_failed_statuses(path: &str, value: &Value, failures: &mut Vec<String>) {
    if failures.len() >= 4 {
        return;
    }
    match value {
        Value::Object(map) => {
            if path != "$"
                && map.get("status").and_then(Value::as_str) == Some("fail")
                && let Some(detail) = failed_object_summary(path, map)
            {
                failures.push(detail);
                if failures.len() >= 4 {
                    return;
                }
            }
            for (key, child) in map {
                let child_path = if path == "$" {
                    key.to_owned()
                } else {
                    format!("{path}.{key}")
                };
                collect_failed_statuses(&child_path, child, failures);
                if failures.len() >= 4 {
                    return;
                }
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                collect_failed_statuses(&format!("{path}[{index}]"), child, failures);
                if failures.len() >= 4 {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn failed_object_summary(path: &str, map: &serde_json::Map<String, Value>) -> Option<String> {
    let label = map
        .get("name")
        .or_else(|| map.get("role"))
        .or_else(|| map.get("interface"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(path);
    failure_detail(map).map(|detail| format!("{label}: {detail}"))
}

fn failure_detail(map: &serde_json::Map<String, Value>) -> Option<String> {
    for key in ["blocker", "error", "reason", "message", "stderr"] {
        if let Some(detail) = map.get(key).and_then(compact_failure_value) {
            return Some(detail);
        }
    }
    map.get("missing")
        .and_then(compact_failure_value)
        .or_else(|| Some("status=fail".to_owned()))
}

fn compact_failure_value(value: &Value) -> Option<String> {
    let raw = match value {
        Value::String(value) => value.clone(),
        Value::Array(values) => values
            .iter()
            .filter_map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| (!value.is_null()).then(|| value.to_string()))
            })
            .collect::<Vec<_>>()
            .join(", "),
        Value::Null => String::new(),
        value => value.to_string(),
    };
    let mut compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return None;
    }
    const MAX_DETAIL_CHARS: usize = 280;
    if compact.chars().count() > MAX_DETAIL_CHARS {
        compact = compact.chars().take(MAX_DETAIL_CHARS).collect();
        compact.push_str("...");
    }
    Some(compact)
}
