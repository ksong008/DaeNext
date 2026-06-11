use super::*;
#[test]
pub(super) fn candidate_admits_final_native_native_state_only_with_final_live_evidence() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-final-native-evidence-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let evidence_path = root.join("final-native-evidence.json");
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&json!({
            "schema": "final-native-state-evidence",
            "schemaVersion": 1,
            "status": "pass",
            "evidenceDate": "2026-06-06",
            "liveHost": "external-live-validation-path",
            "protocolMatrixLiveEvidenceRecorded": true,
            "nativeBenchmarkEvidenceRecorded": true,
            "finalNativeProductPackageReady": true,
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
                "finalStateSummary": "/tmp/final-native/final-state.json",
                "liveHostSummary": "/tmp/final-native/summary.json"
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
        .env("FINAL_NATIVE_STATE_EVIDENCE", &evidence_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["final_native_state_ready"].as_bool().unwrap());
    assert!(
        report["final_native_live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["final_native_final_state_artifact_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["final_native_state_typed_report"]["status"]
            .as_str()
            .unwrap(),
        "pass"
    );

    let blocked = Command::new(binary())
        .arg("service-contract")
        .output()
        .unwrap();
    assert!(blocked.status.success());
    let blocked_report: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert!(
        !blocked_report["final_native_state_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !blocked_report["final_native_live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );

    let _ = fs::remove_dir_all(root);
}
