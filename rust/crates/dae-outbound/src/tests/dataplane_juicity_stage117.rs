use super::*;

#[test]
fn stage117_juicity_h3_dependencies_are_compile_admitted() {
    let admission = juicity::dependency_admission();

    assert_eq!(admission.quinn_version, "0.11.9");
    assert_eq!(admission.h3_version, "0.0.8");
    assert_eq!(admission.h3_quinn_version, "0.0.10");
    assert_eq!(admission.tokio_version, "1.52.3");
    assert!(admission.quinn_endpoint_type.contains("quinn"));
    assert!(admission.quinn_endpoint_type.contains("Endpoint"));
    assert!(admission.h3_quinn_connection_type.contains("h3_quinn"));
    assert!(admission.h3_quinn_connection_type.contains("Connection"));
    assert!(admission.h3_client_builder_type.contains("h3"));
    assert!(admission.h3_client_builder_type.contains("Builder"));
    assert!(admission.tokio_runtime_builder_type.contains("tokio"));
    assert!(admission.tokio_runtime_builder_type.contains("Builder"));
    assert!(admission.quinn_runtime_tokio_feature_admitted);
    assert!(admission.quinn_rustls_aws_lc_rs_feature_admitted);
    assert!(admission.h3_quinn_bridge_admitted);
    assert!(admission.tokio_runtime_admitted);
    assert!(admission.dependency_only);
}
