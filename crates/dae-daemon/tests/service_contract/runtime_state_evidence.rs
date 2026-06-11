use super::*;
#[test]
pub(super) fn runtime_state_admits_only_with_live_evidence() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-runtime-state-evidence-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let evidence_path = root.join("runtime-state-evidence.json");
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&json!({
            "schema": "runtime-state-evidence",
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
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("service-contract")
        .env("RUNTIME_STATE_EVIDENCE", &evidence_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["runtime_state_ready"].as_bool().unwrap());
    assert!(report["live_host_contract_ready"].as_bool().unwrap());
    assert!(report["state_artifact_ready"].as_bool().unwrap());
    assert_eq!(
        report["runtime_state_typed_report"]["status"]
            .as_str()
            .unwrap(),
        "pass"
    );
    assert_eq!(report["runtime_state_ready"], report["runtime_state_ready"]);

    let blocked = Command::new(binary())
        .arg("service-contract")
        .output()
        .unwrap();
    assert!(blocked.status.success());
    let blocked_report: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert!(!blocked_report["runtime_state_ready"].as_bool().unwrap());
    assert!(
        !blocked_report["live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );

    let _ = fs::remove_dir_all(root);
}
