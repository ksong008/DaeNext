use super::*;
pub(crate) fn insert_product_chain_branch_default_fields(
    report: &mut Value,
    fields: ProductChainBranchDefaultReportFields<'_>,
) {
    if let Value::Object(report) = report {
        report.insert(
            "branch_mismatched_sibling_repos".to_owned(),
            json!(fields.branch_mismatched_repos),
        );
        report.insert(
            "expected_product_chain_branches".to_owned(),
            fields.expected_product_chain_branches.clone(),
        );
        report.insert(
            "product_chain_branch_contract_preserved".to_owned(),
            json!(fields.product_chain_branch_contract_preserved),
        );
        report.insert(
            "product_chain_structural_baseline_clean".to_owned(),
            json!(fields.product_chain_structural_baseline_clean),
        );
        report.insert(
            "runtime_control_api_source_baseline_recorded".to_owned(),
            json!(fields.runtime_control_api_source_baseline_recorded),
        );
        report.insert(
            "runtime_control_api_final_admission_recorded".to_owned(),
            json!(fields.runtime_control_api_final_admission_recorded),
        );
        report.insert(
            "daed_wing_runtime_control_api_default_switch_regression_recorded".to_owned(),
            json!(fields.runtime_control_api_final_admission_recorded),
        );
        report.insert(
            "product_chain_default_switch_admission_clean".to_owned(),
            json!(fields.default_switch_admission_clean),
        );
        report.insert(
            "go_fallback_required".to_owned(),
            json!(fields.go_fallback_required),
        );
        report.insert(
            "go_fallback_retired".to_owned(),
            json!(fields.go_fallback_retired),
        );
        report.insert(
            "go_fallback_retirement_scope".to_owned(),
            json!(fields.go_fallback_retirement_scope),
        );
        report.insert("typed_report".to_owned(), fields.typed_report.clone());
    }
}
