use super::*;
pub(super) const OUTBOUND_FINGERPRINT_UNDERLAY_BOOL_FIELDS: &[&str] = &[
    "outbound_fingerprint_underlay_contract_ready",
    "standard_tls_underlay_contract_ready",
    "fingerprint_aware_tls_underlay_contract_ready",
    "link_fingerprint_plan_ready",
    "global_fingerprint_plan_ready",
    "unknown_fingerprint_fail_closed_ready",
    "rustls_standard_tls_no_fingerprint_ready",
    "boring_fingerprint_underlay_ready",
    "no_silent_fingerprint_rustls_fallback_ready",
    "fingerprint_underlay_live_evidence_contract_ready",
    "utls_wire_oracle_comparison_recorded",
    "full_utls_parity_not_declared_without_wire_oracle",
    "outbound_fingerprint_underlay_typed_report_ready",
    "go_fingerprint_underlay_fallback_retirement_contract_ready",
    "go_fingerprint_underlay_fallback_retired_candidate",
    "security_underlay_capability_contract_ready",
    "common_security_underlay_ready",
    "expanded_security_underlay_complete",
    "security_underlay_release_gate_ready",
];

pub(super) const OUTBOUND_FINGERPRINT_UNDERLAY_COPY_FIELDS: &[&str] = &[
    "outbound_fingerprint_underlay_report_schema",
    "outbound_fingerprint_underlay_surface",
    "outbound_fingerprint_underlay_typed_report",
    "security_underlay_capability_report_schema",
    "security_underlay_capability_row_count",
    "security_underlay_capability_rows",
    "security_underlay_capability_typed_report",
];

pub(super) const OUTBOUND_PRODUCTION_MATRIX_BOOL_FIELDS: &[&str] = &[
    "outbound_production_matrix_contract_ready",
    "outbound_production_matrix_runtime_state_ready",
    "outbound_matrix_entries_ready",
    "parser_export_metadata_matrix_ready",
    "tcp_udp_dataplane_matrix_ready",
    "transport_underlay_matrix_ready",
    "route_group_connectivity_matrix_ready",
    "reload_behavior_matrix_ready",
    "live_smoke_matrix_ready",
    "go_outbound_fallback_retirement_matrix_ready",
    "outbound_production_matrix_typed_report_ready",
    "go_outbound_fallback_retired_candidate",
    "source_shape_registry_contract_ready",
    "source_shape_registry_open",
    "expanded_source_matrix_open",
    "expanded_source_matrix_complete",
    "expanded_source_matrix_blocked_rows_visible",
    "expanded_source_matrix_release_gate_ready",
    "expanded_source_matrix_c10_ready",
    "excluded_stream_wrapper_source_matrix_open",
    "excluded_stream_wrapper_source_matrix_complete",
    "excluded_stream_wrapper_source_matrix_release_gate_ready",
    "excluded_stream_wrapper_source_matrix_c10_ready",
    "scoped_expanded_source_matrix_complete",
    "scoped_expanded_source_matrix_release_gate_ready",
    "scoped_expanded_source_matrix_c10_ready",
    "stream_wrapper_capability_contract_ready",
    "websocket_wss_loopback_ready",
    "stream_wrapper_resident_source_admission_ready",
    "expanded_stream_wrapper_complete",
    "packet_semantics_capability_contract_ready",
    "common_packet_semantics_ready",
    "packet_semantics_resident_source_admission_ready",
    "expanded_packet_semantics_complete",
    "extension_layer_capability_contract_ready",
    "no_plugin_baseline_ready",
    "plugin_wrapper_resident_source_admission_ready",
    "legacy_layer_resident_source_admission_ready",
    "expanded_extension_layer_complete",
    "transport_option_capability_contract_ready",
    "baseline_transport_options_ready",
    "quic_option_resident_source_admission_ready",
    "secure_endpoint_resident_source_admission_ready",
    "expanded_transport_option_complete",
    "expanded_live_matrix_validation_boundary_ready",
    "expanded_live_matrix_complete",
    "expanded_live_matrix_proxy_path_required",
    "expanded_live_matrix_direct_control_excluded",
    "expanded_live_matrix_benchmark_required",
    "expanded_live_matrix_rollback_artifact_required",
    "expanded_live_matrix_blocked_rows_reduce_pass_threshold",
];

pub(super) const OUTBOUND_PRODUCTION_MATRIX_COPY_FIELDS: &[&str] = &[
    "outbound_production_matrix_report_schema",
    "outbound_production_matrix_entries",
    "outbound_production_matrix_typed_report",
    "source_shape_registry_report_schema",
    "source_shape_registry_schema_version",
    "source_shape_registry_row_count",
    "source_shape_registry_rows",
    "expanded_source_matrix_status_counts",
    "expanded_source_matrix_completion_blocker",
    "expanded_source_matrix_typed_report",
    "excluded_stream_wrapper_source_matrix_report_schema",
    "excluded_stream_wrapper_source_matrix_typed_report",
    "scoped_expanded_source_matrix_evidence_report_schema",
    "scoped_expanded_source_matrix_evidence",
    "scoped_expanded_source_matrix_typed_report",
    "stream_wrapper_capability_report_schema",
    "stream_wrapper_capability_row_count",
    "stream_wrapper_capability_rows",
    "stream_wrapper_capability_typed_report",
    "packet_semantics_capability_report_schema",
    "packet_semantics_capability_row_count",
    "packet_semantics_capability_rows",
    "packet_semantics_capability_typed_report",
    "extension_layer_capability_report_schema",
    "extension_layer_capability_row_count",
    "extension_layer_capability_rows",
    "extension_layer_capability_typed_report",
    "transport_option_capability_report_schema",
    "transport_option_capability_row_count",
    "transport_option_capability_rows",
    "transport_option_capability_typed_report",
    "expanded_live_matrix_validation_boundary_report_schema",
    "expanded_live_matrix_validation_boundary_typed_report",
];

pub(super) const RESIDENT_LIVE_ADAPTER_MATRIX_BOOL_FIELDS: &[&str] = &[
    "resident_live_adapter_matrix_contract_ready",
    "resident_live_adapter_matrix_ready",
    "resident_live_adapter_matrix_runtime_state_ready",
    "resident_live_adapter_entries_ready",
    "resident_live_adapter_planner_admission_ready",
    "resident_live_adapter_tcp_ready",
    "resident_live_adapter_udp_ready",
    "resident_live_adapter_transport_underlay_ready",
    "resident_live_adapter_route_group_connectivity_ready",
    "resident_live_adapter_selected_node_fail_closed_ready",
    "resident_live_adapter_fingerprint_underlay_ready",
    "resident_live_adapter_go_outbound_fallback_retirement_ready",
    "resident_live_adapter_wired_matrix_ready",
    "resident_live_adapter_remote_live_matrix_ready",
    "resident_live_adapter_matrix_typed_report_ready",
];

pub(super) const RESIDENT_LIVE_ADAPTER_MATRIX_COPY_FIELDS: &[&str] = &[
    "resident_live_adapter_wired_handler_count",
    "resident_live_adapter_live_ready_handler_count",
    "resident_live_adapter_matrix_report_schema",
    "resident_live_adapter_matrix_entries",
    "resident_live_adapter_matrix_typed_report",
    "resident_live_adapter_matrix_surface",
];

pub(super) const RELEASE_DEFAULT_SWITCH_BOOL_FIELDS: &[&str] = &[
    "release_default_switch_contract_ready",
    "release_default_artifact_path_ready",
    "default_runtime_selector_no_env_rust_owned_ready",
    "install_service_package_scripts_ready",
    "release_default_switch_live_evidence_contract_ready",
    "backup_manifest_contract_ready",
    "rollback_rehearsal_contract_ready",
    "host_write_freeze_contract_required",
    "go_product_shell_allowed_until_go_free",
    "release_default_switch_final_go_free_claim",
    "release_default_switch_typed_report_ready",
];

pub(super) const RELEASE_DEFAULT_SWITCH_COPY_FIELDS: &[&str] = &[
    "release_default_switch_report_schema",
    "release_default_switch_required_live_hosts",
    "release_default_switch_surface",
    "release_default_switch_typed_report",
];

pub(super) const GO_FREE_PRODUCT_CHAIN_BOOL_FIELDS: &[&str] = &[
    "go_free_product_chain_contract_ready",
    "default_product_package_go_free",
    "go_product_shell_retired_from_default_package",
    "go_orchestration_retired_from_default_package",
    "go_control_runtime_api_service_release_retired_from_default_package",
    "go_outbound_dependency_retired_from_default_package",
    "go_compat_oracle_boundary_ready",
    "rust_product_binary_contract_ready",
    "rust_product_lifecycle_contract_ready",
    "rust_product_web_api_package_release_contract_ready",
    "go_free_live_host_contract_ready",
    "go_free_rollback_model_ready",
    "go_free_product_chain_typed_report_ready",
    "go_free_product_chain_ready",
];

pub(super) const GO_FREE_PRODUCT_CHAIN_COPY_FIELDS: &[&str] = &[
    "go_free_product_chain_report_schema",
    "go_free_product_chain_default_dependency_policy",
    "go_free_product_chain_retained_go_scope",
    "go_free_product_chain_surface",
    "go_free_product_chain_typed_report",
];

pub(super) fn insert_outbound_fingerprint_underlay_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        OUTBOUND_FINGERPRINT_UNDERLAY_BOOL_FIELDS,
    );
    insert_contract_copy_fields(
        report,
        &Value::Null,
        OUTBOUND_FINGERPRINT_UNDERLAY_COPY_FIELDS,
    );
}

pub(super) fn insert_outbound_fingerprint_underlay_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        OUTBOUND_FINGERPRINT_UNDERLAY_BOOL_FIELDS,
    );
    insert_contract_copy_fields(
        report,
        capability,
        OUTBOUND_FINGERPRINT_UNDERLAY_COPY_FIELDS,
    );
}

pub(super) fn insert_outbound_production_matrix_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        OUTBOUND_PRODUCTION_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, &Value::Null, OUTBOUND_PRODUCTION_MATRIX_COPY_FIELDS);
}

pub(super) fn insert_outbound_production_matrix_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        OUTBOUND_PRODUCTION_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, OUTBOUND_PRODUCTION_MATRIX_COPY_FIELDS);
}

pub(super) fn insert_resident_live_adapter_matrix_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        RESIDENT_LIVE_ADAPTER_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(
        report,
        &Value::Null,
        RESIDENT_LIVE_ADAPTER_MATRIX_COPY_FIELDS,
    );
}

pub(super) fn insert_resident_live_adapter_matrix_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        RESIDENT_LIVE_ADAPTER_MATRIX_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, RESIDENT_LIVE_ADAPTER_MATRIX_COPY_FIELDS);
}

pub(super) fn insert_release_default_switch_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        RELEASE_DEFAULT_SWITCH_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, &Value::Null, RELEASE_DEFAULT_SWITCH_COPY_FIELDS);
}

pub(super) fn insert_release_default_switch_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        RELEASE_DEFAULT_SWITCH_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, RELEASE_DEFAULT_SWITCH_COPY_FIELDS);
}

pub(super) fn insert_go_free_product_chain_contract_defaults(report: &mut Value) {
    insert_contract_bool_fields(
        report,
        false,
        &Value::Null,
        GO_FREE_PRODUCT_CHAIN_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, &Value::Null, GO_FREE_PRODUCT_CHAIN_COPY_FIELDS);
}

pub(super) fn insert_go_free_product_chain_contract_success(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
) {
    insert_contract_bool_fields(
        report,
        command_passed,
        capability,
        GO_FREE_PRODUCT_CHAIN_BOOL_FIELDS,
    );
    insert_contract_copy_fields(report, capability, GO_FREE_PRODUCT_CHAIN_COPY_FIELDS);
}

pub(super) fn insert_contract_bool_fields(
    report: &mut Value,
    command_passed: bool,
    capability: &Value,
    fields: &[&str],
) {
    if let Value::Object(report) = report {
        for field in fields {
            report.insert(
                (*field).to_owned(),
                json!(command_passed && capability[*field].as_bool().unwrap_or(false)),
            );
        }
    }
}

pub(super) fn insert_contract_copy_fields(report: &mut Value, capability: &Value, fields: &[&str]) {
    if let Value::Object(report) = report {
        for field in fields {
            report.insert((*field).to_owned(), capability[*field].clone());
        }
    }
}
