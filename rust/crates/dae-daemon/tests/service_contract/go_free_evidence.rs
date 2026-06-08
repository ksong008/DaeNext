use super::*;
#[test]
pub(super) fn candidate_admits_c10_go_free_contract_only_with_final_live_evidence() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-c10-go-free-evidence-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let evidence_path = root.join("c10-evidence.json");
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&json!({
            "schema": "c10-final-go-free-product-chain-evidence",
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
            "releaseDefaultSwitchAdmission": true,
            "productionPackageAdmission": true,
            "goDaewingDefaultPathRemoved": true,
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
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(binary())
        .arg("service-contract")
        .env("DAE_C10_GO_FREE_PRODUCT_CHAIN_EVIDENCE", &evidence_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["go_free_product_chain_ready"].as_bool().unwrap());
    assert!(
        report["go_free_live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(report["go_free_rollback_model_ready"].as_bool().unwrap());
    assert_eq!(
        report["go_free_product_chain_typed_report"]["status"]
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
        !blocked_report["go_free_product_chain_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !blocked_report["go_free_live_host_contract_ready"]
            .as_bool()
            .unwrap()
    );

    let _ = fs::remove_dir_all(root);
}
