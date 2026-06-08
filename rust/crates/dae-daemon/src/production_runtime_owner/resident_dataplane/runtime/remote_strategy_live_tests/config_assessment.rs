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
    let expanded_source_matrix_rows =
        resident_expanded_source_matrix_rows(config, &node_shapes, &full_matrix_rows);
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
        "releaseGateMayUseAsSourceMatrix": false,
        "c10MayUseAsExpandedSourceMatrix": false,
    });
    let mut report = json!({
        "schema": "resident-live-adapter-config-assessment",
        "config": config_path.map(path_string),
        "read_only": true,
        "host_mutation_executed": false,
        "network_io_executed": false,
        "live_traffic_executed": false,
        "matrix_schema": matrix.schema,
        "resident_live_adapter_matrix_ready": matrix.matrix_ready,
        "resident_live_adapter_wired_matrix_ready": matrix.wired_matrix_ready,
        "resident_live_adapter_remote_live_matrix_ready": matrix.remote_live_matrix_ready,
        "resident_live_adapter_remote_live_matrix_evidence": {
            "env": live_evidence.env,
            "source": live_evidence.source,
            "schema": live_evidence.schema,
            "schemaVersion": live_evidence.schema_version,
            "candidateSha256": live_evidence.candidate_sha256,
            "rowCount": live_evidence.row_count,
            "passCount": live_evidence.pass_count,
            "allPass": live_evidence.all_pass,
            "valid": live_evidence.valid,
            "readyHandlers": live_evidence.ready_handlers.iter().cloned().collect::<Vec<_>>(),
            "error": live_evidence.error,
        },
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
    report["full_matrix_release_gate_source_ready"] = json!(false);
    report["full_matrix_c10_expanded_source_ready"] = json!(false);
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
    report["expanded_source_matrix_release_gate_ready"] = json!(false);
    report["expanded_source_matrix_c10_ready"] = json!(false);
    report["source_matrix_completion_blocker"] = json!(
        "expanded source matrix has fail-closed rows and requires live host, benchmark, and rollback evidence"
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
            report["planner_error"] = json!(err);
            report["blockers"] =
                json!(["selected node shape is not admitted by the live resident adapter"]);
        }
    }
    report
}
