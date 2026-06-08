use super::*;
pub(crate) fn attach_go_free_product_chain_gate_from_report(report: &mut Value) {
    let default_product_package_scan = report
        .get("default_product_package_scan")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "name": "default-product-package-scan",
                "status": "not-recorded",
                "default_product_package_go_free": false,
                "go_product_shell_retired_from_default_package": false,
                "blockers": ["C10 default product package source scan is not recorded"],
            })
        });
    let gate = go_free_product_chain_gate_json(
        report["execute"].as_bool().unwrap_or(false),
        &report["release_default_switch_gate"],
        &report["resident_default_daemon_switch_gate"],
        report["outbound_quic_go_dependency_boundary_preserved"]
            .as_bool()
            .unwrap_or(false),
        report["product_chain_branch_contract_preserved"]
            .as_bool()
            .unwrap_or(false),
        &default_product_package_scan,
    )
    .report;
    upsert_go_free_product_chain_gate(report, gate);
}
