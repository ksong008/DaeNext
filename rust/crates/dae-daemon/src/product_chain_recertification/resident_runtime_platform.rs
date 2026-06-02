use serde_json::{Value, json};

use super::ProductChainRecertificationOptions;
use super::path_string;

#[derive(Debug, Clone)]
pub(super) struct ResidentRuntimePlatformGateReport {
    pub(super) report: Value,
    pub(super) blockers: Vec<String>,
}

pub(super) fn resident_runtime_platform_gate_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    resident_default_daemon_switch_gate: &Value,
) -> ResidentRuntimePlatformGateReport {
    if !executed {
        return ResidentRuntimePlatformGateReport {
            report: json!({
                "name": "resident-runtime-platform-v1",
                "status": "not-executed",
                "requested": false,
                "resident_runtime_platform_ready": false,
                "resident_runtime_resource_gate_ready": false,
                "blockers": [],
            }),
            blockers: Vec::new(),
        };
    }

    let requested = true;
    let binary_source_provided = resident_default_daemon_switch_gate["binary_source_provided"]
        .as_bool()
        .unwrap_or(false);
    let binary_source_exists = resident_default_daemon_switch_gate["binary_source_exists"]
        .as_bool()
        .unwrap_or(false);
    let binary_source = resident_default_daemon_switch_gate["binary_source"].clone();
    let candidate_service_contract =
        resident_default_daemon_switch_gate["candidate_service_contract"].clone();
    let candidate_executed = candidate_service_contract["executed"]
        .as_bool()
        .unwrap_or(false);
    let candidate_passed = candidate_service_contract["passed"]
        .as_bool()
        .unwrap_or(false);
    let resident_run_service_contract_ready =
        candidate_service_contract["resident_run_service_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let reload_command_service_contract_ready =
        candidate_service_contract["reload_command_service_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let systemd_notify_ready_supported =
        candidate_service_contract["systemd_notify_ready_supported"]
            .as_bool()
            .unwrap_or(false);
    let reload_failure_rollback_supported =
        candidate_service_contract["reload_failure_rollback_supported"]
            .as_bool()
            .unwrap_or(false);
    let invalid_runtime_config_rejected_before_current_swap =
        candidate_service_contract["invalid_runtime_config_rejected_before_current_swap"]
            .as_bool()
            .unwrap_or(false);
    let reload_start_failure_attempts_previous_runtime_restore =
        candidate_service_contract["reload_start_failure_attempts_previous_runtime_restore"]
            .as_bool()
            .unwrap_or(false);
    let resident_production_dataplane_ready =
        candidate_service_contract["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_runtime_platform_contract_ready =
        candidate_service_contract["resident_runtime_platform_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_runtime_typed_report_ready =
        candidate_service_contract["resident_runtime_typed_report_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_runtime_resource_gate_ready =
        candidate_service_contract["resident_runtime_resource_gate_ready"]
            .as_bool()
            .unwrap_or(false);
    let lifecycle_contract =
        candidate_service_contract["resident_runtime_lifecycle_contract"].clone();
    let lifecycle_contract_ready = lifecycle_contract["pid_file"].is_string()
        && lifecycle_contract["progress_file"].is_string()
        && lifecycle_contract["abort_file"].is_string()
        && lifecycle_contract["ready_record_file_supported"]
            .as_bool()
            .unwrap_or(false)
        && lifecycle_contract["cleanup_report"].is_string()
        && lifecycle_contract["start_report"].is_string();
    let resource_limits = candidate_service_contract["resident_runtime_resource_limits"].clone();
    let max_rss_bytes = resource_limits["max_rss_bytes"].as_u64().unwrap_or(0);
    let max_thread_count = resource_limits["max_thread_count"].as_u64().unwrap_or(0);
    let max_fd_count = resource_limits["max_fd_count"].as_u64().unwrap_or(0);
    let max_report_size_bytes = resource_limits["max_report_size_bytes"]
        .as_u64()
        .unwrap_or(0);
    let service_contract_report_size_bytes =
        candidate_service_contract["service_contract_report_size_bytes"]
            .as_u64()
            .unwrap_or(0);
    let memory_thread_fd_limits_declared =
        max_rss_bytes > 0 && max_thread_count > 0 && max_fd_count > 0;
    let report_size_gate_passed = max_report_size_bytes > 0
        && service_contract_report_size_bytes > 0
        && service_contract_report_size_bytes <= max_report_size_bytes;
    let resource_gate = json!({
        "status": if resident_runtime_resource_gate_ready
            && memory_thread_fd_limits_declared
            && report_size_gate_passed
        {
            "pass"
        } else {
            "blocked"
        },
        "ready": resident_runtime_resource_gate_ready
            && memory_thread_fd_limits_declared
            && report_size_gate_passed,
        "observed_scope": "candidate service-contract report and declared resident runtime limits",
        "resident_memory_rss_bytes": Value::Null,
        "resident_thread_count": Value::Null,
        "resident_fd_count": Value::Null,
        "resident_report_size_bytes": service_contract_report_size_bytes,
        "max_rss_bytes": max_rss_bytes,
        "max_thread_count": max_thread_count,
        "max_fd_count": max_fd_count,
        "max_report_size_bytes": max_report_size_bytes,
        "memory_thread_fd_limits_declared": memory_thread_fd_limits_declared,
        "report_size_gate_passed": report_size_gate_passed,
    });
    let resident_runtime_resource_gate_passed = resource_gate["ready"].as_bool().unwrap_or(false);
    let resident_runtime_platform_ready = requested
        && binary_source_provided
        && binary_source_exists
        && candidate_executed
        && candidate_passed
        && resident_run_service_contract_ready
        && reload_command_service_contract_ready
        && systemd_notify_ready_supported
        && reload_failure_rollback_supported
        && invalid_runtime_config_rejected_before_current_swap
        && reload_start_failure_attempts_previous_runtime_restore
        && resident_production_dataplane_ready
        && resident_runtime_platform_contract_ready
        && resident_runtime_typed_report_ready
        && lifecycle_contract_ready
        && resident_runtime_resource_gate_passed;

    let mut blockers = Vec::new();
    if !binary_source_provided {
        blockers.push("C4 resident runtime candidate binary source is not provided".to_owned());
    } else if !binary_source_exists {
        blockers.push("C4 resident runtime candidate binary source is absent".to_owned());
    }
    if binary_source_provided && binary_source_exists && !candidate_executed {
        blockers.push("C4 resident runtime candidate service-contract was not executed".to_owned());
    }
    if candidate_executed && !candidate_passed {
        blockers
            .push("C4 resident runtime candidate service-contract command did not pass".to_owned());
    }
    if !resident_run_service_contract_ready {
        blockers.push("C4 resident run service contract is not ready".to_owned());
    }
    if !reload_command_service_contract_ready {
        blockers.push("C4 resident reload command service contract is not ready".to_owned());
    }
    if !systemd_notify_ready_supported {
        blockers.push("C4 systemd notify ready/reload/stop contract is not declared".to_owned());
    }
    if !reload_failure_rollback_supported {
        blockers.push("C4 reload failure rollback support is not declared".to_owned());
    }
    if !invalid_runtime_config_rejected_before_current_swap {
        blockers.push(
            "C4 invalid config rejection before current runtime swap is not declared".to_owned(),
        );
    }
    if !reload_start_failure_attempts_previous_runtime_restore {
        blockers.push(
            "C4 previous runtime restore after reload start failure is not declared".to_owned(),
        );
    }
    if !resident_production_dataplane_ready {
        blockers.push("C4 resident production dataplane is not ready".to_owned());
    }
    if !resident_runtime_platform_contract_ready {
        blockers.push("C4 resident runtime platform contract is not declared".to_owned());
    }
    if !resident_runtime_typed_report_ready {
        blockers.push("C4 resident runtime typed report contract is not ready".to_owned());
    }
    if !lifecycle_contract_ready {
        blockers.push(
            "C4 pid/progress/ready/abort/cleanup lifecycle contract is incomplete".to_owned(),
        );
    }
    if !resident_runtime_resource_gate_passed {
        blockers.push("C4 memory/thread/fd/report-size resource gate is not ready".to_owned());
    }

    ResidentRuntimePlatformGateReport {
        report: json!({
            "name": "resident-runtime-platform-v1",
            "status": if resident_runtime_platform_ready { "pass" } else { "blocked" },
            "requested": requested,
            "resident_runtime_platform_ready": resident_runtime_platform_ready,
            "binary_source": binary_source,
            "binary_source_provided": binary_source_provided,
            "binary_source_exists": binary_source_exists,
            "candidate_service_contract": candidate_service_contract,
            "resident_run_service_contract_ready": resident_run_service_contract_ready,
            "reload_command_service_contract_ready": reload_command_service_contract_ready,
            "systemd_notify_ready_supported": systemd_notify_ready_supported,
            "reload_failure_rollback_supported": reload_failure_rollback_supported,
            "invalid_runtime_config_rejected_before_current_swap": invalid_runtime_config_rejected_before_current_swap,
            "reload_start_failure_attempts_previous_runtime_restore": reload_start_failure_attempts_previous_runtime_restore,
            "resident_production_dataplane_ready": resident_production_dataplane_ready,
            "resident_runtime_platform_contract_ready": resident_runtime_platform_contract_ready,
            "resident_runtime_typed_report_ready": resident_runtime_typed_report_ready,
            "resident_runtime_resource_gate_ready": resident_runtime_resource_gate_ready,
            "resident_runtime_resource_gate_passed": resident_runtime_resource_gate_passed,
            "resident_runtime_report_schema": candidate_service_contract["resident_runtime_report_schema"].clone(),
            "resident_runtime_lifecycle_contract": lifecycle_contract,
            "resident_runtime_resource_gate": resource_gate,
            "pid_progress_ready_abort_cleanup_contract_ready": lifecycle_contract_ready,
            "requires_candidate_binary": true,
            "candidate_binary_source_hint": options.resident_default_daemon_binary_source.as_ref().map(|path| path_string(path)),
            "blockers": blockers,
        }),
        blockers,
    }
}
