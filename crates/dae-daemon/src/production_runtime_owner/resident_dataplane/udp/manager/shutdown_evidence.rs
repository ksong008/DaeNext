use serde_json::Value;

pub(super) fn cleanup_report_passed(report: &Value) -> bool {
    report["status"].as_str() == Some("pass")
}

pub(super) fn udp_generation_cleanup_passed(
    session_shards: &Value,
    dns: &Value,
    reply: &Value,
) -> bool {
    cleanup_report_passed(session_shards)
        && cleanup_report_passed(dns)
        && cleanup_report_passed(reply)
}

pub(super) fn udp_manager_cleanup_passed(
    active_sessions: usize,
    retired_generation_failures: u64,
    retired_component_failures: u64,
    queued_payload_released: bool,
) -> bool {
    active_sessions == 0
        && retired_generation_failures == 0
        && retired_component_failures == 0
        && queued_payload_released
}

pub(super) fn udp_cleanup_completion<'a>(
    cleanup_passed: bool,
    reports: impl IntoIterator<Item = &'a Value>,
) -> (bool, &'static str) {
    if !cleanup_passed {
        return (false, "incomplete");
    }
    let mut forced = false;
    let mut degraded = false;
    for report in reports {
        forced |= cleanup_report_contains_mode(report, "forced-bounded");
        degraded |= cleanup_report_contains_mode(report, "completed-degraded")
            || cleanup_report_contains_false_graceful(report);
    }
    if forced {
        return (false, "forced-bounded");
    }
    if degraded {
        return (false, "completed-degraded");
    }
    (true, "graceful")
}

pub(super) fn record_udp_cleanup_mode(report: &Value, forced: &mut u64, degraded: &mut u64) {
    if cleanup_report_contains_mode(report, "forced-bounded") {
        *forced = forced.saturating_add(1);
    } else if cleanup_report_contains_mode(report, "completed-degraded")
        || cleanup_report_contains_false_graceful(report)
    {
        *degraded = degraded.saturating_add(1);
    }
}

fn cleanup_report_contains_mode(report: &Value, expected: &str) -> bool {
    match report {
        Value::Object(fields) => {
            fields.get("completionMode").and_then(Value::as_str) == Some(expected)
                || fields
                    .values()
                    .any(|value| cleanup_report_contains_mode(value, expected))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| cleanup_report_contains_mode(value, expected)),
        _ => false,
    }
}

fn cleanup_report_contains_false_graceful(report: &Value) -> bool {
    match report {
        Value::Object(fields) => {
            fields.get("graceful").and_then(Value::as_bool) == Some(false)
                || fields.values().any(cleanup_report_contains_false_graceful)
        }
        Value::Array(values) => values.iter().any(cleanup_report_contains_false_graceful),
        _ => false,
    }
}
