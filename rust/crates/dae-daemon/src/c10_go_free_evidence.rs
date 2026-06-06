use std::fs;

use serde_json::{Value, json};

pub(crate) const C10_GO_FREE_PRODUCT_CHAIN_EVIDENCE_ENV: &str =
    "DAE_C10_GO_FREE_PRODUCT_CHAIN_EVIDENCE";

const C10_EVIDENCE_SCHEMA: &str = "c10-final-go-free-product-chain-evidence";

#[derive(Debug, Clone)]
pub(crate) struct C10GoFreeProductChainEvidence {
    pub(crate) report: Value,
    pub(crate) blockers: Vec<String>,
    pub(crate) default_product_package_go_free: bool,
    pub(crate) go_product_shell_retired: bool,
    pub(crate) go_orchestration_retired: bool,
    pub(crate) go_control_runtime_api_service_release_retired: bool,
    pub(crate) go_outbound_dependency_retired: bool,
    pub(crate) go_compat_oracle_boundary_ready: bool,
    pub(crate) userland_ffi_c_abi_retired: bool,
    pub(crate) go_oracle_default_dependency_retired: bool,
    pub(crate) rust_internal_fallback_normalized: bool,
    pub(crate) rust_product_binary_contract_ready: bool,
    pub(crate) rust_product_lifecycle_contract_ready: bool,
    pub(crate) rust_product_web_api_package_release_contract_ready: bool,
    pub(crate) live_host_contract_ready: bool,
    pub(crate) rollback_model_ready: bool,
    pub(crate) typed_report_ready: bool,
    pub(crate) ready: bool,
}

impl C10GoFreeProductChainEvidence {
    pub(crate) fn fail_closed(source: Option<String>, blockers: Vec<String>) -> Self {
        Self {
            report: json!({
                "schema": C10_EVIDENCE_SCHEMA,
                "schemaVersion": 1,
                "status": "blocked",
                "source": source,
                "ready": false,
                "blockers": blockers,
            }),
            blockers,
            default_product_package_go_free: false,
            go_product_shell_retired: false,
            go_orchestration_retired: false,
            go_control_runtime_api_service_release_retired: false,
            go_outbound_dependency_retired: false,
            go_compat_oracle_boundary_ready: false,
            userland_ffi_c_abi_retired: false,
            go_oracle_default_dependency_retired: false,
            rust_internal_fallback_normalized: false,
            rust_product_binary_contract_ready: false,
            rust_product_lifecycle_contract_ready: false,
            rust_product_web_api_package_release_contract_ready: false,
            live_host_contract_ready: false,
            rollback_model_ready: false,
            typed_report_ready: false,
            ready: false,
        }
    }
}

pub(crate) fn c10_go_free_product_chain_evidence_from_env() -> C10GoFreeProductChainEvidence {
    let Ok(source) = std::env::var(C10_GO_FREE_PRODUCT_CHAIN_EVIDENCE_ENV) else {
        return C10GoFreeProductChainEvidence::fail_closed(None, c10_go_free_default_blockers());
    };
    match fs::read_to_string(&source) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(value) => c10_go_free_product_chain_evidence_from_value(Some(source), value),
            Err(err) => C10GoFreeProductChainEvidence::fail_closed(
                Some(source),
                vec![format!("parse C10 go-free evidence ledger: {err}")],
            ),
        },
        Err(err) => C10GoFreeProductChainEvidence::fail_closed(
            Some(source),
            vec![format!("read C10 go-free evidence ledger: {err}")],
        ),
    }
}

pub(crate) fn c10_go_free_default_blockers() -> Vec<String> {
    [
        "generated protocol matrix live evidence is not recorded",
        "default-ready benchmark evidence is not recorded",
        "go-free artifact build-chain scan has not passed for the default package",
        "userland FFI/C ABI retirement is not proven for the default path",
        "Go oracle/default dependency retirement is not proven for the default path",
        "Rust internal fallback normalization is not proven for the default path",
        "final live host evidence is not recorded",
        "rollback artifact validation is not recorded",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn c10_go_free_product_chain_evidence_from_value(
    source: Option<String>,
    mut value: Value,
) -> C10GoFreeProductChainEvidence {
    let mut blockers = Vec::new();

    require_str(
        &value,
        "schema",
        C10_EVIDENCE_SCHEMA,
        "C10 evidence schema is invalid",
        &mut blockers,
    );
    require_u64(
        &value,
        "schemaVersion",
        1,
        "C10 evidence schemaVersion is invalid",
        &mut blockers,
    );
    require_str(
        &value,
        "status",
        "pass",
        "C10 evidence status is not pass",
        &mut blockers,
    );
    require_nonempty_str(
        &value,
        "liveHost",
        "C10 live host is not recorded",
        &mut blockers,
    );

    let protocol_matrix_live_evidence_recorded = require_bool(
        &value,
        "protocolMatrixLiveEvidenceRecorded",
        "generated protocol matrix live evidence is not recorded",
        &mut blockers,
    );
    let default_ready_benchmark_recorded = require_bool(
        &value,
        "defaultReadyBenchmarkEvidenceRecorded",
        "default-ready benchmark evidence is not recorded",
        &mut blockers,
    );
    let default_product_package_go_free = require_bool(
        &value,
        "defaultProductPackageGoFree",
        "go-free artifact build-chain scan has not passed for the default package",
        &mut blockers,
    );
    let go_product_shell_retired = require_bool(
        &value,
        "goProductShellRetiredFromDefaultPackage",
        "Go product shell retirement is not proven for the default package",
        &mut blockers,
    );
    let go_orchestration_retired = require_bool(
        &value,
        "goOrchestrationRetiredFromDefaultPackage",
        "Go orchestration retirement is not proven for the default package",
        &mut blockers,
    );
    let go_control_runtime_api_service_release_retired = require_bool(
        &value,
        "goControlRuntimeApiServiceReleaseRetiredFromDefaultPackage",
        "Go control/runtime/API/service/release retirement is not proven for the default package",
        &mut blockers,
    );
    let go_outbound_dependency_retired = require_bool(
        &value,
        "goOutboundDependencyRetiredFromDefaultPackage",
        "Go outbound dependency retirement is not proven for the default package",
        &mut blockers,
    );
    let userland_ffi_c_abi_retired = require_bool(
        &value,
        "userlandFfiCabiRetiredFromDefaultPath",
        "userland FFI/C ABI retirement is not proven for the default path",
        &mut blockers,
    );
    let go_oracle_default_dependency_retired = require_bool(
        &value,
        "goOracleDefaultDependencyRetiredFromDefaultPath",
        "Go oracle/default dependency retirement is not proven for the default path",
        &mut blockers,
    );
    let rust_internal_fallback_normalized = require_bool(
        &value,
        "rustInternalFallbackNormalizedForDefaultPath",
        "Rust internal fallback normalization is not proven for the default path",
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
    let live_default_switch_applied = require_bool(
        &value,
        "liveDefaultSwitchApplied",
        "final live default switch evidence is not recorded",
        &mut blockers,
    );
    let live_host_runtime_validated = require_bool(
        &value,
        "liveHostRuntimeValidated",
        "final live host runtime validation is not recorded",
        &mut blockers,
    );
    let rollback_artifact_materialized = require_bool(
        &value,
        "rollbackArtifactMaterialized",
        "rollback artifact materialization is not recorded",
        &mut blockers,
    );
    let rollback_artifact_guard_validated = require_bool(
        &value,
        "rollbackArtifactGuardValidated",
        "rollback artifact guard validation is not recorded",
        &mut blockers,
    );
    let rollback_validation_applied_on_live_host = require_bool(
        &value,
        "rollbackValidationAppliedOnLiveHost",
        "rollback validation on live host is not recorded",
        &mut blockers,
    );
    let rollback_restored_clean_host_state = require_bool(
        &value,
        "rollbackRestoredCleanHostState",
        "rollback clean-host restoration is not recorded",
        &mut blockers,
    );

    if value
        .pointer("/artifacts/rollbackScript")
        .and_then(Value::as_str)
        .is_none()
    {
        blockers.push("rollback script artifact path is not recorded".to_owned());
    }
    if value
        .pointer("/artifacts/rollbackManifest")
        .and_then(Value::as_str)
        .is_none()
    {
        blockers.push("rollback manifest artifact path is not recorded".to_owned());
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
        blockers.push("post-rollback ip rule cleanup is not recorded".to_owned());
    }
    if value
        .pointer("/checks/noDaedProcess")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("post-rollback daed process cleanup is not recorded".to_owned());
    }
    if value
        .pointer("/checks/noDaexLinksOrNetns")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blockers.push("post-rollback DAEX link/netns cleanup is not recorded".to_owned());
    }

    let live_host_contract_ready = live_default_switch_applied && live_host_runtime_validated;
    let rollback_model_ready = rollback_artifact_materialized
        && rollback_artifact_guard_validated
        && rollback_validation_applied_on_live_host
        && rollback_restored_clean_host_state;
    let go_compat_oracle_boundary_ready = go_oracle_default_dependency_retired;
    let typed_report_ready = true;
    let ready = blockers.is_empty()
        && protocol_matrix_live_evidence_recorded
        && default_ready_benchmark_recorded
        && default_product_package_go_free
        && go_product_shell_retired
        && go_orchestration_retired
        && go_control_runtime_api_service_release_retired
        && go_outbound_dependency_retired
        && userland_ffi_c_abi_retired
        && go_oracle_default_dependency_retired
        && rust_internal_fallback_normalized
        && rust_product_binary_contract_ready
        && rust_product_lifecycle_contract_ready
        && rust_product_web_api_package_release_contract_ready
        && live_host_contract_ready
        && rollback_model_ready;

    if let Some(object) = value.as_object_mut() {
        object.insert("ready".to_owned(), json!(ready));
        object.insert(
            "validatedBy".to_owned(),
            json!("dae-daemon::c10_go_free_evidence"),
        );
        object.insert(
            "source".to_owned(),
            source.clone().map(Value::String).unwrap_or(Value::Null),
        );
        object.insert("blockers".to_owned(), json!(blockers.clone()));
        object.insert(
            "goFreeBooleans".to_owned(),
            json!({
                "defaultProductPackageGoFree": default_product_package_go_free,
                "goProductShellRetiredFromDefaultPackage": go_product_shell_retired,
                "goOrchestrationRetiredFromDefaultPackage": go_orchestration_retired,
                "goControlRuntimeApiServiceReleaseRetiredFromDefaultPackage": go_control_runtime_api_service_release_retired,
                "goOutboundDependencyRetiredFromDefaultPackage": go_outbound_dependency_retired,
                "userlandFfiCabiRetiredFromDefaultPath": userland_ffi_c_abi_retired,
                "goOracleDefaultDependencyRetiredFromDefaultPath": go_oracle_default_dependency_retired,
                "rustInternalFallbackNormalizedForDefaultPath": rust_internal_fallback_normalized,
                "liveHostContractReady": live_host_contract_ready,
                "rollbackModelReady": rollback_model_ready,
            }),
        );
    }

    C10GoFreeProductChainEvidence {
        report: value,
        blockers,
        default_product_package_go_free,
        go_product_shell_retired,
        go_orchestration_retired,
        go_control_runtime_api_service_release_retired,
        go_outbound_dependency_retired,
        go_compat_oracle_boundary_ready,
        userland_ffi_c_abi_retired,
        go_oracle_default_dependency_retired,
        rust_internal_fallback_normalized,
        rust_product_binary_contract_ready,
        rust_product_lifecycle_contract_ready,
        rust_product_web_api_package_release_contract_ready,
        live_host_contract_ready,
        rollback_model_ready,
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
    fn c10_go_free_evidence_accepts_complete_final_fixture() {
        let evidence = c10_go_free_product_chain_evidence_from_value(None, complete_fixture());

        assert!(evidence.ready);
        assert!(evidence.blockers.is_empty());
        assert!(evidence.default_product_package_go_free);
        assert!(evidence.live_host_contract_ready);
        assert!(evidence.rollback_model_ready);
        assert_eq!(evidence.report["ready"].as_bool(), Some(true));
    }

    #[test]
    fn c10_go_free_evidence_rejects_missing_rollback_validation() {
        let mut fixture = complete_fixture();
        fixture["rollbackValidationAppliedOnLiveHost"] = json!(false);
        let evidence = c10_go_free_product_chain_evidence_from_value(None, fixture);

        assert!(!evidence.ready);
        assert!(!evidence.rollback_model_ready);
        assert!(evidence.blockers.iter().any(|blocker| {
            blocker.contains("rollback validation on live host is not recorded")
        }));
    }

    fn complete_fixture() -> Value {
        json!({
            "schema": C10_EVIDENCE_SCHEMA,
            "schemaVersion": 1,
            "status": "pass",
            "evidenceDate": "2026-06-06",
            "liveHost": "remote-38",
            "protocolMatrixLiveEvidenceRecorded": true,
            "defaultReadyBenchmarkEvidenceRecorded": true,
            "defaultProductPackageGoFree": true,
            "goProductShellRetiredFromDefaultPackage": true,
            "goOrchestrationRetiredFromDefaultPackage": true,
            "goControlRuntimeApiServiceReleaseRetiredFromDefaultPackage": true,
            "goOutboundDependencyRetiredFromDefaultPackage": true,
            "userlandFfiCabiRetiredFromDefaultPath": true,
            "goOracleDefaultDependencyRetiredFromDefaultPath": true,
            "rustInternalFallbackNormalizedForDefaultPath": true,
            "rustProductBinaryContractReady": true,
            "rustProductLifecycleContractReady": true,
            "rustProductWebApiPackageReleaseContractReady": true,
            "liveDefaultSwitchApplied": true,
            "liveHostRuntimeValidated": true,
            "rollbackArtifactMaterialized": true,
            "rollbackArtifactGuardValidated": true,
            "rollbackValidationAppliedOnLiveHost": true,
            "rollbackRestoredCleanHostState": true,
            "artifacts": {
                "rollbackScript": "/tmp/c10/rollback.sh",
                "rollbackManifest": "/tmp/c10/rollback.json",
                "liveHostSummary": "/tmp/c10/summary.json"
            },
            "checks": {
                "ipRuleDefaultOnly": true,
                "noDaedProcess": true,
                "noDaexLinksOrNetns": true
            }
        })
    }
}
