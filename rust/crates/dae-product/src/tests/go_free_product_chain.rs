use super::*;

#[test]
fn go_free_product_chain_contract_is_c10_fail_closed_until_product_shell_retires() {
    let contract = go_free_product_chain_contract();

    assert_eq!(contract.name, "go-free-product-chain-v1");
    assert_eq!(contract.c_phase, "C10");
    assert_eq!(contract.prior_gate, "release-default-switch-v1");
    assert!(contract.contract_ready);
    assert!(!contract.default_product_package_go_free);
    assert!(!contract.go_product_shell_retired);
    assert!(!contract.go_orchestration_retired);
    assert!(!contract.go_control_runtime_api_service_release_retired);
    assert!(!contract.go_outbound_dependency_retired);
    assert!(contract.go_compat_oracle_boundary_ready);
    assert!(!contract.rust_product_binary_contract_ready);
    assert!(!contract.rust_product_lifecycle_contract_ready);
    assert!(!contract.rust_product_web_api_package_release_contract_ready);
    assert!(!contract.live_host_contract_ready);
    assert!(contract.rollback_model_ready);
    assert!(!contract.ready);
    assert_contains_text(&contract.surface, "Rust product binary");
    assert_contains_text(&contract.surface, "Go product shell");
}
