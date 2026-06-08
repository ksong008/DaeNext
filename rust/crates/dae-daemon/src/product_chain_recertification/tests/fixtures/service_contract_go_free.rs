use super::*;
pub(crate) fn insert_go_free_product_chain_contract(report: &mut serde_json::Map<String, Value>) {
    report.insert(
        "go_free_product_chain_contract_ready".to_owned(),
        json!(true),
    );
    report.insert("default_product_package_go_free".to_owned(), json!(false));
    report.insert(
        "go_product_shell_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert(
        "go_orchestration_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert(
        "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert(
        "go_outbound_dependency_retired_from_default_package".to_owned(),
        json!(false),
    );
    report.insert("go_compat_oracle_boundary_ready".to_owned(), json!(true));
    report.insert(
        "rust_product_binary_contract_ready".to_owned(),
        json!(false),
    );
    report.insert(
        "rust_product_lifecycle_contract_ready".to_owned(),
        json!(false),
    );
    report.insert(
        "rust_product_web_api_package_release_contract_ready".to_owned(),
        json!(false),
    );
    report.insert("go_free_live_host_contract_ready".to_owned(), json!(false));
    report.insert("go_free_rollback_model_ready".to_owned(), json!(true));
    report.insert(
        "go_free_product_chain_typed_report_ready".to_owned(),
        json!(true),
    );
    report.insert("go_free_product_chain_ready".to_owned(), json!(false));
    report.insert(
        "go_free_product_chain_report_schema".to_owned(),
        json!("go-free-product-chain"),
    );
    report.insert(
        "go_free_product_chain_default_dependency_policy".to_owned(),
        json!(
            "Go dependencies are not allowed in the default product package after this gate passes"
        ),
    );
    report.insert(
        "go_free_product_chain_retained_go_scope".to_owned(),
        json!("oracle/test/compat only until the final product package is proven go-free"),
    );
    report.insert(
        "go_free_product_chain_surface".to_owned(),
        json!([
            "Rust product binary owns run/reload/stop/service-contract",
            "Rust product binary owns Web/API/package/release entry points",
            "Go product shell is absent from default package and release path",
            "Go orchestration and Go outbound dependencies are absent from default package",
            "Go compatibility code is retained only as oracle/test/compat evidence",
            "live host and rollback evidence pass on the final go-free package"
        ]),
    );
    report.insert(
        "go_free_product_chain_typed_report".to_owned(),
        json!({
            "schema": "go-free-product-chain-typed-report",
            "status": "blocked",
            "stage_report_schema": false,
        }),
    );
}
