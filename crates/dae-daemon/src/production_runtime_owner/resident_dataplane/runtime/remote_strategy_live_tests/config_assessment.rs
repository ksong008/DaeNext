use super::*;
pub(crate) fn resident_live_adapter_config_assessment(
    config: &Config,
    config_path: Option<&Path>,
) -> Value {
    let matrix = resident_live_adapter_matrix_contract();
    let live_evidence = resident_live_matrix_evidence_from_env();
    let node_shapes = plan::resident_node_link_shapes(config);
    let matrix_entries = resident_live_adapter_matrix_entries()
        .iter()
        .map(|entry| {
            let remote_live_matrix =
                resident_live_adapter_entry_remote_live_matrix_ready(entry, &live_evidence);
            let missing = resident_live_adapter_entry_missing(entry, &live_evidence);
            json!({
                "handler": entry.handler,
                "formal_matrix_handler": entry.formal_matrix_handler,
                "udp_semantics": entry.udp_semantics,
                "udp_path_ready": entry.udp_path_ready(),
                "wired_ready": entry.wired_ready(),
                "remote_live_matrix": remote_live_matrix,
                "live_ready": entry.wired_ready() && remote_live_matrix && missing.is_empty(),
                "missing": missing,
            })
        })
        .collect::<Vec<_>>();
    let full_matrix_rows = resident_full_matrix_config_rows(config, &node_shapes);
    let full_matrix_present_rows = full_matrix_rows
        .iter()
        .filter(|row| row["candidate_count"].as_u64().unwrap_or(0) > 0)
        .count();
    let full_matrix_admitted_rows = full_matrix_rows
        .iter()
        .filter(|row| row["planner_status"].as_str() == Some("admitted"))
        .count();
    let source_shape_registry = source_shape_registry_contract();
    let expanded_source_matrix =
        resident_expanded_source_matrix(config, &node_shapes, &full_matrix_rows);
    let expanded_source_matrix_rows = expanded_source_matrix.rows;
    let source_admission_diagnostics = expanded_source_matrix.source_admission_diagnostics;
    let source_materialization_failure_count = source_admission_diagnostics
        .iter()
        .filter(|diagnostic| diagnostic["status"] == "source-materialization-failed")
        .count();
    let unclassified_source_materialization_count = source_admission_diagnostics
        .iter()
        .filter(|diagnostic| diagnostic["status"] == "unclassified-materialized-shape")
        .count();
    let source_ownership_mismatch_count = source_admission_diagnostics
        .iter()
        .filter(|diagnostic| diagnostic["status"] == "source-ownership-mismatch")
        .count();
    let mut source_admission_reason_ids = Vec::new();
    if source_materialization_failure_count > 0 {
        source_admission_reason_ids.push("source-materialization-failed");
    }
    if unclassified_source_materialization_count > 0 {
        source_admission_reason_ids.push("unclassified-materialized-shape");
    }
    if source_ownership_mismatch_count > 0 {
        source_admission_reason_ids.push("source-ownership-mismatch");
    }
    let expanded_source_matrix_status_counts =
        resident_matrix_status_counts(&expanded_source_matrix_rows);
    let expanded_source_matrix_complete = false;
    let matrix_scope = "current-config-formal-handler-matrix";
    let matrix_scope_contract = json!({
        "schemaVersion": 1,
        "scope": matrix_scope,
        "currentConfigMatrixOpen": true,
        "currentAdmittedBaselineOpen": true,
        "sourceShapeRegistryOpen": source_shape_registry.source_shape_registry_open,
        "expandedSourceMatrixOpen": source_shape_registry.expanded_source_matrix_open,
        "expandedSourceMatrixComplete": expanded_source_matrix_complete,
        "currentConfigRows": full_matrix_rows.len(),
        "currentConfigPresentRows": full_matrix_present_rows,
        "currentConfigAdmittedRows": full_matrix_admitted_rows,
        "formalHandlerRows": resident_live_adapter_matrix_entries().len(),
        "productionReadinessMayUseAsSourceMatrix": false,
        "finalStateMayUseAsExpandedSourceMatrix": false,
    });
    let mut report = json!({
        "schema": "resident-live-adapter-config-assessment",
        "schemaVersion": 2,
        "config": config_path.map(redacted_path_identity),
        "configPathRedacted": config_path.is_some(),
        "read_only": true,
        "host_mutation_executed": false,
        "network_io_executed": false,
        "live_traffic_executed": false,
        "matrix_schema": matrix.schema,
        "resident_live_adapter_matrix_ready": matrix.matrix_ready,
        "resident_live_adapter_wired_matrix_ready": matrix.wired_matrix_ready,
        "resident_live_adapter_remote_live_matrix_ready": matrix.remote_live_matrix_ready,
        "resident_live_adapter_remote_live_matrix_evidence": live_evidence.redacted_report(),
        "resident_live_adapter_entries": matrix_entries,
    });
    report["matrix_scope"] = json!(matrix_scope);
    report["current_config_matrix_open"] = json!(true);
    report["current_admitted_baseline_open"] = json!(true);
    report["source_shape_registry_open"] = json!(source_shape_registry.source_shape_registry_open);
    report["expanded_source_matrix_open"] =
        json!(source_shape_registry.expanded_source_matrix_open);
    report["expanded_source_matrix_complete"] = json!(expanded_source_matrix_complete);
    report["matrix_scope_contract"] = matrix_scope_contract;
    report["full_matrix_open"] = json!(true);
    report["full_matrix_scope"] = json!(matrix_scope);
    report["full_matrix_is_expanded_source_matrix"] = json!(false);
    report["full_matrix_production_source_ready"] = json!(false);
    report["full_matrix_expanded_source_final_state_ready"] = json!(false);
    report["full_matrix_row_count"] = json!(full_matrix_rows.len());
    report["full_matrix_present_row_count"] = json!(full_matrix_present_rows);
    report["full_matrix_admitted_row_count"] = json!(full_matrix_admitted_rows);
    report["full_matrix_complete"] = json!(matrix.matrix_ready);
    report["full_matrix_completion_blocker"] = if matrix.matrix_ready {
        Value::Null
    } else {
        json!(
            "real live traffic evidence is required before the resident live adapter matrix can be complete"
        )
    };
    report["source_shape_registry_schema"] = json!(source_shape_registry.schema);
    report["source_shape_registry_schema_version"] = json!(source_shape_registry.schema_version);
    report["source_shape_registry_row_count"] = json!(source_shape_registry.rows.len());
    report["source_shape_registry_contract"] = source_shape_registry.to_value();
    report["expanded_source_matrix_row_count"] = json!(expanded_source_matrix_rows.len());
    report["expanded_source_matrix_status_counts"] = expanded_source_matrix_status_counts;
    report["source_admission_diagnostic_count"] = json!(source_admission_diagnostics.len());
    report["source_materialization_failure_count"] = json!(source_materialization_failure_count);
    report["unclassified_source_materialization_count"] =
        json!(unclassified_source_materialization_count);
    report["source_ownership_mismatch_count"] = json!(source_ownership_mismatch_count);
    report["current_config_source_admission_status"] =
        json!(if source_admission_reason_ids.is_empty() {
            "resolved"
        } else {
            "blocked"
        });
    report["current_config_source_admission_reason_ids"] = json!(source_admission_reason_ids);
    report["source_admission_diagnostics"] = json!(source_admission_diagnostics);
    report["expanded_source_matrix_production_ready"] = json!(false);
    report["expanded_source_matrix_final_state_ready"] = json!(false);
    report["source_matrix_completion_blocker"] = json!(
        "expanded source matrix has fail-closed rows and requires live host, benchmark, and restore evidence"
    );
    report["expanded_source_matrix_rows"] = json!(expanded_source_matrix_rows);
    report["full_matrix_rows"] = json!(full_matrix_rows);

    match build_resident_dataplane_plan(config) {
        Ok(plan) if plan.enabled => {
            let proxies = plan
                .proxies
                .iter()
                .map(|(outbound, group)| {
                    let mut summary = resident_proxy_group_plan_summary_json(group);
                    summary["outbound_index"] = json!(outbound);
                    summary
                })
                .collect::<Vec<_>>();
            let default_proxy = plan
                .default_proxy_snapshot()
                .as_ref()
                .map(resident_proxy_plan_summary_json)
                .unwrap_or(Value::Null);
            let default_group = plan
                .default_proxy_group()
                .map(resident_proxy_group_plan_summary_json)
                .unwrap_or(Value::Null);
            report["status"] = json!("admitted");
            report["planner_admitted"] = json!(true);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(true);
            report["proxy_count"] = json!(plan.proxies.len());
            report["tcp_dial_mode"] = json!(plan.tcp_dial_mode.as_str());
            report["tcp_sniffing_timeout"] = json!(format!("{:?}", plan.sniffing_timeout));
            report["default_proxy"] = default_proxy;
            report["default_group"] = default_group;
            report["proxies"] = json!(proxies);
            report["blockers"] =
                json!(["remote live traffic matrix not executed by this read-only assessment"]);
        }
        Ok(plan) => {
            report["status"] = json!("not-applicable");
            report["planner_admitted"] = json!(false);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(false);
            report["proxy_count"] = json!(plan.proxies.len());
            report["unsupported_reason"] = json!(plan.unsupported_reason);
            report["blockers"] = json!(["no selected proxy plan was admitted"]);
        }
        Err(err) => {
            report["status"] = json!("blocked");
            report["planner_admitted"] = json!(false);
            report["selected_node_fail_closed"] = json!(true);
            report["resident_dataplane_enabled_by_config"] = json!(false);
            report["planner_error"] = json!(sanitize_matrix_error(&err));
            report["blockers"] =
                json!(["selected node shape is not admitted by the live resident adapter"]);
        }
    }
    report
}
