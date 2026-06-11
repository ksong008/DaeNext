use std::fs;

use serde_json::{Value, json};

pub(crate) const RUNTIME_STATE_EVIDENCE_ENV: &str = "RUNTIME_STATE_EVIDENCE";

const RUNTIME_STATE_EVIDENCE_SCHEMA: &str = "runtime-state-evidence";

#[derive(Debug, Clone)]
pub(crate) struct RuntimeStateEvidence {
    pub(crate) report: Value,
    pub(crate) blockers: Vec<String>,
    pub(crate) product_package_ready: bool,
    pub(crate) native_product_shell_ready: bool,
    pub(crate) native_orchestration_ready: bool,
    pub(crate) native_control_runtime_api_service_release_ready: bool,
    pub(crate) native_outbound_dependency_ready: bool,
    pub(crate) userland_native_abi_ready: bool,
    pub(crate) rust_product_binary_contract_ready: bool,
    pub(crate) rust_product_lifecycle_contract_ready: bool,
    pub(crate) rust_product_web_api_package_release_contract_ready: bool,
    pub(crate) live_host_contract_ready: bool,
    pub(crate) final_state_artifact_ready: bool,
    pub(crate) typed_report_ready: bool,
    pub(crate) ready: bool,
}

impl RuntimeStateEvidence {
    pub(crate) fn fail_closed(source: Option<String>, blockers: Vec<String>) -> Self {
        Self {
            report: json!({
                "schema": RUNTIME_STATE_EVIDENCE_SCHEMA,
                "schemaVersion": 1,
                "status": "blocked",
                "source": source,
                "ready": false,
                "blockers": blockers,
            }),
            blockers,
            product_package_ready: false,
            native_product_shell_ready: false,
            native_orchestration_ready: false,
            native_control_runtime_api_service_release_ready: false,
            native_outbound_dependency_ready: false,
            userland_native_abi_ready: false,
            rust_product_binary_contract_ready: false,
            rust_product_lifecycle_contract_ready: false,
            rust_product_web_api_package_release_contract_ready: false,
            live_host_contract_ready: false,
            final_state_artifact_ready: false,
            typed_report_ready: false,
            ready: false,
        }
    }
}

pub(crate) fn runtime_state_evidence_from_env() -> RuntimeStateEvidence {
    let source = match std::env::var(RUNTIME_STATE_EVIDENCE_ENV) {
        Ok(source) => source,
        Err(_) => {
            return RuntimeStateEvidence::fail_closed(None, runtime_state_fail_closed_blockers());
        }
    };
    match fs::read_to_string(&source) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(value) => runtime_state_evidence_from_value(Some(source), value),
            Err(err) => RuntimeStateEvidence::fail_closed(
                Some(source),
                vec![format!("parse runtime state evidence ledger: {err}")],
            ),
        },
        Err(err) => RuntimeStateEvidence::fail_closed(
            Some(source),
            vec![format!("read runtime state evidence ledger: {err}")],
        ),
    }
}

pub(crate) fn runtime_state_fail_closed_blockers() -> Vec<String> {
    [
        "generated protocol matrix live evidence is not recorded",
        "native benchmark evidence is not recorded",
        "product package evidence is not recorded",
        "native product shell evidence is not recorded",
        "native orchestration evidence is not recorded",
        "native control/runtime/API/service/release evidence is not recorded",
        "native outbound dependency evidence is not recorded",
        "userland native ABI evidence is not recorded",
        "live host evidence is not recorded",
        "state artifact validation is not recorded",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn runtime_state_evidence_from_value(
    source: Option<String>,
    mut value: Value,
) -> RuntimeStateEvidence {
    let mut blockers = Vec::new();

    require_schema(
        &value,
        "schema",
        RUNTIME_STATE_EVIDENCE_SCHEMA,
        "runtime state evidence schema is invalid",
        &mut blockers,
    );
    require_u64(
        &value,
        "schemaVersion",
        1,
        "runtime state evidence schemaVersion is invalid",
        &mut blockers,
    );
    require_str(
        &value,
        "status",
        "pass",
        "runtime state evidence status is not pass",
        &mut blockers,
    );
    require_nonempty_str(
        &value,
        "liveHost",
        "runtime state live host is not recorded",
        &mut blockers,
    );

    let protocol_matrix_live_evidence_recorded = require_bool(
        &value,
        "protocolMatrixLiveEvidenceRecorded",
        "generated protocol matrix live evidence is not recorded",
        &mut blockers,
    );
    let native_benchmark_evidence_recorded = require_bool(
        &value,
        "nativeBenchmarkEvidenceRecorded",
        "native benchmark evidence is not recorded",
        &mut blockers,
    );
    let product_package_ready = require_bool(
        &value,
        "productPackageReady",
        "product package evidence is not recorded",
        &mut blockers,
    );
    let native_product_shell_ready = require_bool(
        &value,
        "nativeProductShellReady",
        "native product shell evidence is not recorded",
        &mut blockers,
    );
    let native_orchestration_ready = require_bool(
        &value,
        "nativeOrchestrationReady",
        "native orchestration evidence is not recorded",
        &mut blockers,
    );
    let native_control_runtime_api_service_release_ready = require_bool(
        &value,
        "nativeControlRuntimeApiServiceReleaseReady",
        "native control/runtime/API/service/release evidence is not recorded",
        &mut blockers,
    );
    let native_outbound_dependency_ready = require_bool(
        &value,
        "nativeOutboundDependencyReady",
        "native outbound dependency evidence is not recorded",
        &mut blockers,
    );
    let userland_native_abi_ready = require_bool(
        &value,
        "userlandNativeAbiReady",
        "userland native ABI evidence is not recorded",
        &mut blockers,
    );
    let rust_product_binary_contract_ready = require_bool(
        &value,
        "rustProductBinaryContractReady",
        "Rust product binary contract is not ready",
        &mut blockers,
    );
    let rust_product_lifecycle_contract_ready = require_bool(
        &value,
        "rustProductLifecycleContractReady",
        "Rust product lifecycle contract is not ready",
        &mut blockers,
    );
    let rust_product_web_api_package_release_contract_ready = require_bool(
        &value,
        "rustProductWebApiPackageReleaseContractReady",
        "Rust product Web/API/package/release contract is not ready",
        &mut blockers,
    );
    let live_host_replacement_applied = require_bool(
        &value,
        "liveHostReplacementApplied",
        "live host replacement evidence is not recorded",
        &mut blockers,
    );
    let live_host_runtime_validated = require_bool(
        &value,
        "liveHostRuntimeValidated",
        "live host runtime validation is not recorded",
        &mut blockers,
    );
    let final_state_artifact_materialized = require_bool(
        &value,
        "finalStateArtifactMaterialized",
        "final-state artifact materialization is not recorded",
        &mut blockers,
    );
    let final_state_artifact_guard_validated = require_bool(
        &value,
        "finalStateArtifactGuardValidated",
        "final-state artifact guard validation is not recorded",
        &mut blockers,
    );
    let final_state_validation_applied_on_live_host = require_bool(
        &value,
        "finalStateValidationAppliedOnLiveHost",
        "final-state validation on live host is not recorded",
        &mut blockers,
    );
    let final_state_clean_host_state = require_bool(
        &value,
        "finalStateCleanHostState",
        "clean-host state is not recorded",
        &mut blockers,
    );

    if value
        .pointer("/artifacts/finalStateSummary")
        .and_then(Value::as_str)
        .is_none()
    {
        blockers.push("state summary artifact path is not recorded".to_owned());
    }
    if value
        .pointer("/artifacts/liveHostSummary")
        .and_then(Value::as_str)
        .is_none()
    {
        blockers.push("live host summary artifact path is not recorded".to_owned());
    }
    if value
        .pointer("/checks/ipRuleDefaultOnly")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("ip rule state is not recorded".to_owned());
    }
    if value
        .pointer("/checks/noDaedProcess")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("daed process state is not recorded".to_owned());
    }
    if value
        .pointer("/checks/noNativeLinksOrNetns")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("native link/netns state is not recorded".to_owned());
    }

    let live_host_contract_ready = live_host_replacement_applied && live_host_runtime_validated;
    let final_state_artifact_ready = final_state_artifact_materialized
        && final_state_artifact_guard_validated
        && final_state_validation_applied_on_live_host
        && final_state_clean_host_state;
    let typed_report_ready = true;
    let ready = blockers.is_empty()
        && protocol_matrix_live_evidence_recorded
        && native_benchmark_evidence_recorded
        && product_package_ready
        && native_product_shell_ready
        && native_orchestration_ready
        && native_control_runtime_api_service_release_ready
        && native_outbound_dependency_ready
        && userland_native_abi_ready
        && rust_product_binary_contract_ready
        && rust_product_lifecycle_contract_ready
        && rust_product_web_api_package_release_contract_ready
        && live_host_contract_ready
        && final_state_artifact_ready;

    if let Some(object) = value.as_object_mut() {
        object.insert("ready".to_owned(), json!(ready));
        object.insert(
            "validatedBy".to_owned(),
            json!("dae-daemon::runtime_state_evidence"),
        );
        object.insert(
            "normalizedSchema".to_owned(),
            json!(RUNTIME_STATE_EVIDENCE_SCHEMA),
        );
        object.insert(
            "source".to_owned(),
            source.clone().map(Value::String).unwrap_or(Value::Null),
        );
        object.insert("blockers".to_owned(), json!(blockers.clone()));
        object.insert(
            "runtimeStateBooleans".to_owned(),
            json!({
                "productPackageReady": product_package_ready,
                "nativeProductShellReady": native_product_shell_ready,
                "nativeOrchestrationReady": native_orchestration_ready,
                "nativeControlRuntimeApiServiceReleaseReady": native_control_runtime_api_service_release_ready,
                "nativeOutboundDependencyReady": native_outbound_dependency_ready,
                "userlandNativeAbiReady": userland_native_abi_ready,
                "liveHostContractReady": live_host_contract_ready,
                "stateArtifactReady": final_state_artifact_ready,
            }),
        );
    }

    RuntimeStateEvidence {
        report: value,
        blockers,
        product_package_ready,
        native_product_shell_ready,
        native_orchestration_ready,
        native_control_runtime_api_service_release_ready,
        native_outbound_dependency_ready,
        userland_native_abi_ready,
        rust_product_binary_contract_ready,
        rust_product_lifecycle_contract_ready,
        rust_product_web_api_package_release_contract_ready,
        live_host_contract_ready,
        final_state_artifact_ready,
        typed_report_ready,
        ready,
    }
}

fn require_bool(value: &Value, key: &str, blocker: &str, blockers: &mut Vec<String>) -> bool {
    if value.get(key).and_then(Value::as_bool) == Some(true) {
        true
    } else {
        blockers.push(blocker.to_owned());
        false
    }
}

fn require_schema(
    value: &Value,
    key: &str,
    expected: &str,
    blocker: &str,
    blockers: &mut Vec<String>,
) {
    let schema = value.get(key).and_then(Value::as_str);
    if schema != Some(expected) {
        blockers.push(blocker.to_owned());
    }
}

fn require_str(
    value: &Value,
    key: &str,
    expected: &str,
    blocker: &str,
    blockers: &mut Vec<String>,
) {
    if value.get(key).and_then(Value::as_str) != Some(expected) {
        blockers.push(blocker.to_owned());
    }
}

fn require_nonempty_str(value: &Value, key: &str, blocker: &str, blockers: &mut Vec<String>) {
    if value
        .get(key)
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        blockers.push(blocker.to_owned());
    }
}

fn require_u64(value: &Value, key: &str, expected: u64, blocker: &str, blockers: &mut Vec<String>) {
    if value.get(key).and_then(Value::as_u64) != Some(expected) {
        blockers.push(blocker.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_state_evidence_accepts_complete_fixture() {
        let evidence = runtime_state_evidence_from_value(None, complete_fixture());

        assert!(evidence.ready);
        assert!(evidence.blockers.is_empty());
        assert!(evidence.product_package_ready);
        assert!(evidence.live_host_contract_ready);
        assert!(evidence.final_state_artifact_ready);
        assert_eq!(evidence.report["ready"].as_bool(), Some(true));
    }

    #[test]
    fn runtime_state_evidence_rejects_missing_state_validation() {
        let mut fixture = complete_fixture();
        fixture["finalStateValidationAppliedOnLiveHost"] = json!(false);
        let evidence = runtime_state_evidence_from_value(None, fixture);

        assert!(!evidence.ready);
        assert!(!evidence.final_state_artifact_ready);
        assert!(evidence.blockers.iter().any(|blocker| {
            blocker.contains("final-state validation on live host is not recorded")
        }));
    }

    fn complete_fixture() -> Value {
        json!({
            "schema": RUNTIME_STATE_EVIDENCE_SCHEMA,
            "schemaVersion": 1,
            "status": "pass",
            "evidenceDate": "2026-06-06",
            "liveHost": "external-live-validation-path",
            "protocolMatrixLiveEvidenceRecorded": true,
            "nativeBenchmarkEvidenceRecorded": true,
            "productPackageReady": true,
            "nativeProductShellReady": true,
            "nativeOrchestrationReady": true,
            "nativeControlRuntimeApiServiceReleaseReady": true,
            "nativeOutboundDependencyReady": true,
            "userlandNativeAbiReady": true,
            "rustProductBinaryContractReady": true,
            "rustProductLifecycleContractReady": true,
            "rustProductWebApiPackageReleaseContractReady": true,
            "liveHostReplacementApplied": true,
            "liveHostRuntimeValidated": true,
            "finalStateArtifactMaterialized": true,
            "finalStateArtifactGuardValidated": true,
            "finalStateValidationAppliedOnLiveHost": true,
            "finalStateCleanHostState": true,
            "artifacts": {
                "finalStateSummary": "/tmp/runtime-state/state.json",
                "liveHostSummary": "/tmp/runtime-state/summary.json"
            },
            "checks": {
                "ipRuleDefaultOnly": true,
                "noDaedProcess": true,
                "noNativeLinksOrNetns": true
            }
        })
    }
}
