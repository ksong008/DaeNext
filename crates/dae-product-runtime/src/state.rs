use std::sync::Arc;

use dae_config::Config;
use dae_product_core::product_now_text;
use serde_json::{Value, json};

use crate::{RuntimeApplyState, RuntimeTrafficCarry, RuntimeTransitionIdentity};

#[derive(Debug)]
pub struct ProductRuntimeState<R> {
    pub runtime: Option<R>,
    pub config: Option<Arc<Config>>,
    pub config_content: Option<Arc<str>>,
    pub last_error: Option<String>,
    pub last_transition_at: Option<String>,
    pub runtime_started_at: Option<String>,
    pub last_report: Option<Arc<Value>>,
    pub reload_count: u64,
    pub allocator_publication_id: u64,
    pub stop_count: u64,
    pub lifecycle_epoch: u64,
    pub traffic_carry: RuntimeTrafficCarry,
    pub cleanup: RuntimeCleanupState,
    pub apply: RuntimeApplyState,
    pub active_generation: Option<String>,
    pub pending_process_transition: Option<Value>,
    pub transition_identity: Option<RuntimeTransitionIdentity>,
    pub process_baseline_config: Option<Arc<Config>>,
}

impl<R> Default for ProductRuntimeState<R> {
    fn default() -> Self {
        Self {
            runtime: None,
            config: None,
            config_content: None,
            last_error: None,
            last_transition_at: None,
            runtime_started_at: None,
            last_report: None,
            reload_count: 0,
            allocator_publication_id: 0,
            stop_count: 0,
            lifecycle_epoch: 0,
            traffic_carry: RuntimeTrafficCarry::default(),
            cleanup: RuntimeCleanupState::default(),
            apply: RuntimeApplyState::default(),
            active_generation: None,
            pending_process_transition: None,
            transition_identity: None,
            process_baseline_config: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeCleanupState {
    pub running: bool,
    pub epoch: u64,
    pub mode: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub last_report: Option<Arc<Value>>,
    pub last_error: Option<String>,
    pub last_start_blocker: Option<String>,
}

impl RuntimeCleanupState {
    pub fn begin(&mut self, epoch: u64, mode: &str) {
        self.running = true;
        self.epoch = epoch;
        self.mode = Some(mode.to_owned());
        self.started_at = Some(product_now_text());
        self.finished_at = None;
        self.last_report = None;
        self.last_error = None;
        self.last_start_blocker = None;
    }

    pub fn finish(&mut self, report: Option<Value>) {
        self.running = false;
        self.finished_at = Some(product_now_text());
        self.last_error = cleanup_report_error(report.as_ref());
        self.last_start_blocker = cleanup_start_blocker_from_report(report.as_ref());
        self.last_report = report.map(Arc::new);
    }

    pub fn summary(&self) -> Value {
        json!({
            "running": self.running,
            "state": if self.running {
                "running"
            } else if self.last_error.is_some() {
                "failed"
            } else if self.finished_at.is_some() {
                "done"
            } else {
                "idle"
            },
            "epoch": self.epoch,
            "mode": self.mode,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "lastError": self.last_error,
            "lastStartBlocker": self.last_start_blocker,
            "lastReport": self.last_report.as_deref(),
        })
    }
}

fn cleanup_report_error(report: Option<&Value>) -> Option<String> {
    let report = report?;
    if report.get("status").and_then(Value::as_str) == Some("pass") {
        return None;
    }
    let failed_steps = report
        .get("cleanup_steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|step| {
            matches!(
                step["status"].as_str(),
                Some("fail" | "partial" | "timed_out")
            )
        })
        .filter_map(|step| step["name"].as_str())
        .take(8)
        .collect::<Vec<_>>()
        .join(",");
    let failed_step_details = report
        .get("cleanup_steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|step| {
            matches!(
                step["status"].as_str(),
                Some("fail" | "partial" | "timed_out")
            )
        })
        .take(8)
        .map(cleanup_step_failure_detail)
        .collect::<Vec<_>>();
    Some(format!(
        "runtime cleanup failed: cleanup_step_failed={}, failed_steps={}, failed_step_details={}, loaded_map_cleaned={}, cleanup_command_timed_out={}, sys_fs_bpf_dae_mutated={}, leftovers_after_cleanup={}",
        report
            .get("cleanup_step_failed")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        if failed_steps.is_empty() {
            "none"
        } else {
            &failed_steps
        },
        Value::Array(failed_step_details),
        report
            .get("loaded_map_cleaned")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        report
            .get("cleanup_command_timed_out")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        report
            .get("sys_fs_bpf_dae_mutated")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        report
            .get("leftovers_after_cleanup")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned())
    ))
}

fn cleanup_step_failure_detail(step: &Value) -> Value {
    let mut detail = serde_json::Map::new();
    for key in [
        "name",
        "status",
        "safetyStatus",
        "graceful",
        "completionMode",
        "task_count_timed_out",
        "task_count_aborted",
        "task_count_pending",
        "task_count_detached",
        "task_count_panicked",
        "active_tcp_connections_at_shutdown",
        "active_udp_connections_at_shutdown",
        "udp_sessions_active_at_shutdown",
        "resource_release",
    ] {
        if let Some(value) = step.get(key) {
            detail.insert(key.to_owned(), value.clone());
        }
    }
    let owner_release_details = compact_owner_release_failure_details(step);
    if !owner_release_details.is_empty() {
        detail.insert(
            "ownerReleaseDetails".to_owned(),
            Value::Object(owner_release_details),
        );
    }
    Value::Object(detail)
}

fn compact_owner_release_failure_details(step: &Value) -> serde_json::Map<String, Value> {
    let mut details = serde_json::Map::new();
    let specifications = [
        (
            "hysteria2Owners",
            "hysteria2",
            "hysteria2_owners",
            &[
                "registeredKeys",
                "activeOwners",
                "activeLogicalLeases",
                "activeUdpSessions",
                "currentUdpQueuedBytes",
                "activeUdpSessionQuarantine",
                "registryOwnershipReleased",
                "endpointDrain",
                "shutdownTimedOut",
            ][..],
        ),
        (
            "tuicOwners",
            "tuic",
            "tuic_owners",
            &[
                "registeredKeys",
                "activeOwners",
                "activeLogicalLeases",
                "activeUdpAssociations",
                "currentUdpQueuedBytes",
                "activeAssociationQuarantine",
                "registryOwnershipReleased",
                "endpointDrain",
                "shutdownTimedOut",
            ][..],
        ),
        (
            "juicityOwners",
            "juicity",
            "juicity_owners",
            &[
                "activePools",
                "activePhysicalOwners",
                "activeBuilds",
                "activeLogicalLeases",
                "activeWaiters",
                "registryOwnershipReleased",
                "endpointDrain",
                "shutdownTimedOut",
            ][..],
        ),
    ];
    for (release_key, detail_key, snapshot_key, fields) in specifications {
        if step
            .pointer(&format!("/resource_release/{release_key}"))
            .and_then(Value::as_bool)
            != Some(false)
        {
            continue;
        }
        let mut selected = serde_json::Map::new();
        if let Some(snapshot) = step.get(snapshot_key) {
            for field in fields {
                if let Some(value) = snapshot.get(*field) {
                    selected.insert((*field).to_owned(), value.clone());
                }
            }
        }
        if selected.is_empty() {
            selected.insert("snapshotMissing".to_owned(), json!(true));
        }
        details.insert(detail_key.to_owned(), Value::Object(selected));
    }
    if step
        .pointer("/resource_release/ownedCleanup")
        .and_then(Value::as_bool)
        == Some(false)
    {
        details.insert(
            "ownedCleanup".to_owned(),
            compact_udp_session_manager_cleanup(step),
        );
    }
    details
}

fn compact_udp_session_manager_cleanup(step: &Value) -> Value {
    let Some(manager) = step.pointer("/owned_cleanup/owners/udp-session-manager") else {
        return json!({"snapshotMissing": true});
    };
    let mut selected = serde_json::Map::new();
    for key in [
        "status",
        "safetyStatus",
        "graceful",
        "completionMode",
        "activeSessions",
        "queuedPayloadReleased",
        "retiredGenerationShutdowns",
        "retiredGenerationShutdownFailures",
        "retiredGenerationShutdownForced",
        "retiredGenerationShutdownDegraded",
        "retiredComponentShutdowns",
        "retiredComponentShutdownFailures",
        "retiredComponentShutdownForced",
        "retiredComponentShutdownDegraded",
    ] {
        if let Some(value) = manager.get(key) {
            selected.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(admission) = manager.get("queuedPayloadAdmission") {
        let mut payload = serde_json::Map::new();
        for key in ["generation", "currentBytes", "limitBytes"] {
            if let Some(value) = admission.get(key) {
                payload.insert(key.to_owned(), value.clone());
            }
        }
        selected.insert("queuedPayloadAdmission".to_owned(), Value::Object(payload));
    }
    let failed_generations = manager
        .get("generations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|generation| generation["status"].as_str() != Some("pass"))
        .take(4)
        .map(compact_udp_generation_cleanup)
        .collect::<Vec<_>>();
    if !failed_generations.is_empty() {
        selected.insert(
            "failedGenerations".to_owned(),
            Value::Array(failed_generations),
        );
    }
    Value::Object(selected)
}

fn compact_udp_generation_cleanup(generation: &Value) -> Value {
    let mut selected = serde_json::Map::new();
    for key in [
        "generationId",
        "reloadGeneration",
        "status",
        "safetyStatus",
        "graceful",
        "completionMode",
    ] {
        if let Some(value) = generation.get(key) {
            selected.insert(key.to_owned(), value.clone());
        }
    }
    for (source, target) in [
        ("sessionShards", "sessionShards"),
        ("dnsFastPathDispatcher", "dnsFastPathDispatcher"),
        ("dnsForwarders", "dnsForwarders"),
        ("replyDispatcher", "replyDispatcher"),
    ] {
        if let Some(report) = generation.get(source) {
            selected.insert(target.to_owned(), compact_cleanup_status(report));
        }
    }
    Value::Object(selected)
}

fn compact_cleanup_status(report: &Value) -> Value {
    let mut selected = serde_json::Map::new();
    for key in [
        "status",
        "safetyStatus",
        "graceful",
        "completionMode",
        "joined",
        "panicked",
        "timedOut",
        "forced",
        "detached",
        "taskJoined",
        "taskForced",
        "taskPanicked",
    ] {
        if let Some(value) = report.get(key) {
            selected.insert(key.to_owned(), value.clone());
        }
    }
    Value::Object(selected)
}

fn cleanup_start_blocker_from_report(report: Option<&Value>) -> Option<String> {
    let report = report?;
    if report.get("status").and_then(Value::as_str) == Some("pass") {
        return None;
    }
    let binding_cleanup_failed = report
        .get("binding_cleanup_postflight")
        .is_some_and(|binding| binding["status"].as_str() != Some("pass"));
    let loaded_map_cleaned = report
        .get("loaded_map_cleaned")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cleanup_command_timed_out = report
        .get("cleanup_command_timed_out")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let sys_fs_bpf_dae_mutated = report
        .get("sys_fs_bpf_dae_mutated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let leftovers = report
        .get("leftovers_after_cleanup")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !binding_cleanup_failed
        && loaded_map_cleaned
        && !cleanup_command_timed_out
        && !sys_fs_bpf_dae_mutated
        && leftovers.is_empty()
    {
        return None;
    }
    Some(format!(
        "runtime conflict cleanup failed: binding_cleanup_failed={}, loaded_map_cleaned={}, cleanup_command_timed_out={}, sys_fs_bpf_dae_mutated={}, leftovers_after_cleanup={}",
        binding_cleanup_failed,
        loaded_map_cleaned,
        cleanup_command_timed_out,
        sys_fs_bpf_dae_mutated,
        Value::Array(leftovers),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_state_is_backend_agnostic() {
        let state = ProductRuntimeState::<u8>::default();
        assert!(state.runtime.is_none());
        assert_eq!(state.reload_count, 0);
        assert_eq!(state.cleanup.summary()["state"], "idle");
    }

    #[test]
    fn cleanup_state_keeps_a_failed_start_blocker() {
        let mut cleanup = RuntimeCleanupState::default();
        cleanup.begin(3, "reload-replace");
        cleanup.finish(Some(json!({
            "status": "fail",
            "loaded_map_cleaned": false,
            "leftovers_after_cleanup": ["dae0"],
        })));
        assert_eq!(cleanup.summary()["state"], "failed");
        assert!(cleanup.last_start_blocker.is_some());
    }
}
