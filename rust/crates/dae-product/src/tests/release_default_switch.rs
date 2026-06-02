use super::*;

#[test]
fn release_default_switch_contract_is_c9_and_not_final_go_free() {
    let contract = release_default_switch_contract();

    assert_eq!(contract.name, "release-default-switch-v1");
    assert_eq!(contract.c_phase, "C9");
    assert_eq!(contract.prior_gate, "outbound-production-matrix-v1");
    assert!(contract.contract_ready);
    assert!(contract.default_artifact_path_ready);
    assert!(contract.default_runtime_selector_ready);
    assert!(contract.service_package_scripts_ready);
    assert!(contract.live_evidence_contract_ready);
    assert!(contract.backup_manifest_contract_ready);
    assert!(contract.rollback_rehearsal_contract_ready);
    assert!(contract.host_write_freeze_required);
    assert!(contract.go_product_shell_allowed_until_go_free);
    assert!(!contract.final_go_free_claim);
    assert_eq!(contract.required_live_hosts, vec!["38", "10.10.10.2"]);
    assert_contains_text(&contract.surface, "default candidate path");
    assert_contains_text(&contract.surface, "host-write freeze");
}
