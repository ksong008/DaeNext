use super::*;
#[path = "report_value/context.rs"]
mod context;
pub(super) use self::context::*;
#[path = "report_value/base.rs"]
mod base;
pub(super) use self::base::*;
#[path = "report_value/entry_runtime.rs"]
mod entry_runtime;
pub(super) use self::entry_runtime::*;
#[path = "report_value/owner_gates.rs"]
mod owner_gates;
pub(super) use self::owner_gates::*;
#[path = "report_value/branch_default.rs"]
mod branch_default;
pub(super) use self::branch_default::*;

pub(super) fn report_value(
    options: &ProductChainRecertificationOptions,
    artifact_dir: &Path,
    manifest_file: &Path,
    admission: ProductChainAdmissionEvidence,
    evidence: Option<ProductChainEvidence>,
) -> Value {
    let executed = options.execute;
    let default_path_mutation_requested = options.default_path_mutation_requested;
    let service = evidence
        .as_ref()
        .map(|evidence| evidence.service.clone())
        .unwrap_or_else(|| json!({"status": "not-executed"}));
    let topology = evidence
        .as_ref()
        .map(|evidence| evidence.topology.clone())
        .unwrap_or_else(|| {
            product_chain_topology(options).as_json(&options.dae_wing_repo, &options.daed_repo)
        });
    let go_mod = evidence
        .as_ref()
        .map(|evidence| evidence.go_mod.clone())
        .unwrap_or_else(|| json!({"status": "not-executed"}));
    let repos = evidence
        .as_ref()
        .map(|evidence| evidence.repos.clone())
        .unwrap_or_default();
    let runtime_control_api = evidence
        .as_ref()
        .map(|evidence| evidence.runtime_control_api.clone())
        .unwrap_or_else(|| json!({"status": "not-executed"}));
    let native_owned_entry_gates = evidence
        .as_ref()
        .map(|evidence| evidence.native_owned_entry_gates.clone())
        .unwrap_or_else(|| {
            native_owned_entry_gates_json(false, options, &topology, &service, &runtime_control_api)
                .report
        });
    let native_owned_entry_gate_blockers = evidence
        .as_ref()
        .map(|evidence| evidence.native_owned_entry_gate_blockers.clone())
        .unwrap_or_default();
    let dirty_repos = evidence
        .as_ref()
        .map(|evidence| evidence.dirty_repos.clone())
        .unwrap_or_default();
    let missing_repos = evidence
        .as_ref()
        .map(|evidence| evidence.missing_repos.clone())
        .unwrap_or_default();
    let unavailable_repos = evidence
        .as_ref()
        .map(|evidence| evidence.unavailable_repos.clone())
        .unwrap_or_default();
    let branch_mismatched_repos = evidence
        .as_ref()
        .map(|evidence| evidence.branch_mismatched_repos.clone())
        .unwrap_or_default();
    let service_contract_passed = service["service_contract_preserved"]
        .as_bool()
        .unwrap_or(false);
    let dependency_boundary_preserved = go_mod["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false);
    let runtime_control_api_source_contract_preserved =
        runtime_control_api["runtime_control_api_source_contract_preserved"]
            .as_bool()
            .unwrap_or(false);
    let product_chain_topology_locked = native_owned_entry_gates["product_chain_topology_locked"]
        .as_bool()
        .unwrap_or(false);
    let default_bundle_boundary_clean = native_owned_entry_gates["default_bundle_boundary_clean"]
        .as_bool()
        .unwrap_or(false);
    let default_runtime_selector_rust_owned =
        native_owned_entry_gates["default_runtime_selector_rust_owned"]
            .as_bool()
            .unwrap_or(false);
    let explicit_go_rollback_only = native_owned_entry_gates["explicit_go_rollback_only"]
        .as_bool()
        .unwrap_or(false);
    let runtime_selector_matrix_recorded =
        native_owned_entry_gates["runtime_selector_matrix_recorded"]
            .as_bool()
            .unwrap_or(false);
    let daed_service_contract_ready = native_owned_entry_gates["daed_service_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let c0_c3_entry_gates_clean = product_chain_topology_locked
        && default_bundle_boundary_clean
        && default_runtime_selector_rust_owned
        && explicit_go_rollback_only
        && runtime_selector_matrix_recorded
        && daed_service_contract_ready;
    let resident_default_daemon_switch_gate = resident_default_daemon_switch_gate_json(options);
    let (resident_runtime_platform_gate, resident_runtime_platform_gate_blockers) =
        if let Some(evidence) = evidence.as_ref() {
            (
                evidence.resident_runtime_platform_gate.clone(),
                evidence.resident_runtime_platform_gate_blockers.clone(),
            )
        } else {
            let gate = resident_runtime_platform_gate_json(
                executed,
                options,
                &resident_default_daemon_switch_gate,
            );
            (gate.report, gate.blockers)
        };
    let resident_runtime_platform_ready =
        resident_runtime_platform_gate["resident_runtime_platform_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_runtime_resource_gate_ready =
        resident_runtime_platform_gate["resident_runtime_resource_gate_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_runtime_resource_gate_passed =
        resident_runtime_platform_gate["resident_runtime_resource_gate_passed"]
            .as_bool()
            .unwrap_or(false);
    let (mut control_plane_owner_gate, control_plane_owner_gate_blockers) =
        if let Some(evidence) = evidence.as_ref() {
            (
                evidence.control_plane_owner_gate.clone(),
                evidence.control_plane_owner_gate_blockers.clone(),
            )
        } else {
            let gate = control_plane_owner_gate_json(
                executed,
                options,
                &resident_runtime_platform_gate,
                &resident_default_daemon_switch_gate,
                admission,
            );
            (gate.report, gate.blockers)
        };
    let control_plane_owner_ready = control_plane_owner_gate["control_plane_owner_ready"]
        .as_bool()
        .unwrap_or(false);
    let go_control_plane_fallback_retired_candidate =
        control_plane_owner_gate["go_control_plane_fallback_retired_candidate"]
            .as_bool()
            .unwrap_or(false);
    let control_plane_owner_default_switch_admission_ready =
        go_control_plane_fallback_retired_candidate
            && admission.reload_runtime_parity_admitted
            && admission.matched_benchmark_recorded;
    if let Value::Object(gate) = &mut control_plane_owner_gate {
        gate.insert(
            "control_plane_owner_default_switch_admission_ready".to_owned(),
            json!(control_plane_owner_default_switch_admission_ready),
        );
        gate.insert(
            "admission_reload_runtime_parity_admitted".to_owned(),
            json!(admission.reload_runtime_parity_admitted),
        );
        gate.insert(
            "admission_matched_go_rust_default_daemon_benchmark_recorded".to_owned(),
            json!(admission.matched_benchmark_recorded),
        );
    }
    let (mut datapath_core_gate, datapath_core_gate_blockers) =
        if let Some(evidence) = evidence.as_ref() {
            (
                evidence.datapath_core_gate.clone(),
                evidence.datapath_core_gate_blockers.clone(),
            )
        } else {
            let gate = datapath_core_gate_json(
                executed,
                options,
                &control_plane_owner_gate,
                &resident_default_daemon_switch_gate,
                admission,
            );
            (gate.report, gate.blockers)
        };
    let datapath_core_ready = datapath_core_gate["datapath_core_ready"]
        .as_bool()
        .unwrap_or(false);
    let go_datapath_core_fallback_retired_candidate =
        datapath_core_gate["go_datapath_core_fallback_retired_candidate"]
            .as_bool()
            .unwrap_or(false);
    let datapath_core_default_switch_admission_ready = datapath_core_ready
        && admission.production_dataplane_admitted
        && admission.reload_runtime_parity_admitted
        && admission.matched_benchmark_recorded;
    if let Value::Object(gate) = &mut datapath_core_gate {
        gate.insert(
            "datapath_core_default_switch_admission_ready".to_owned(),
            json!(datapath_core_default_switch_admission_ready),
        );
        gate.insert(
            "admission_production_dataplane_admitted".to_owned(),
            json!(admission.production_dataplane_admitted),
        );
        gate.insert(
            "admission_reload_runtime_parity_admitted".to_owned(),
            json!(admission.reload_runtime_parity_admitted),
        );
        gate.insert(
            "admission_matched_go_rust_default_daemon_benchmark_recorded".to_owned(),
            json!(admission.matched_benchmark_recorded),
        );
    }
    let (mut outbound_fingerprint_underlay_gate, outbound_fingerprint_underlay_gate_blockers) =
        if let Some(evidence) = evidence.as_ref() {
            (
                evidence.outbound_fingerprint_underlay_gate.clone(),
                evidence.outbound_fingerprint_underlay_gate_blockers.clone(),
            )
        } else {
            let gate = outbound_fingerprint_underlay_gate_json(
                executed,
                options,
                &datapath_core_gate,
                &resident_default_daemon_switch_gate,
                admission,
            );
            (gate.report, gate.blockers)
        };
    let outbound_fingerprint_underlay_ready =
        outbound_fingerprint_underlay_gate["outbound_fingerprint_underlay_ready"]
            .as_bool()
            .unwrap_or(false);
    let go_fingerprint_underlay_fallback_retired_candidate =
        outbound_fingerprint_underlay_gate["go_fingerprint_underlay_fallback_retired_candidate"]
            .as_bool()
            .unwrap_or(false);
    let outbound_fingerprint_underlay_default_switch_admission_ready =
        outbound_fingerprint_underlay_ready
            && admission.production_dataplane_admitted
            && admission.reload_runtime_parity_admitted
            && admission.matched_benchmark_recorded;
    if let Value::Object(gate) = &mut outbound_fingerprint_underlay_gate {
        gate.insert(
            "outbound_fingerprint_underlay_default_switch_admission_ready".to_owned(),
            json!(outbound_fingerprint_underlay_default_switch_admission_ready),
        );
        gate.insert(
            "admission_production_dataplane_admitted".to_owned(),
            json!(admission.production_dataplane_admitted),
        );
        gate.insert(
            "admission_reload_runtime_parity_admitted".to_owned(),
            json!(admission.reload_runtime_parity_admitted),
        );
        gate.insert(
            "admission_matched_go_rust_default_daemon_benchmark_recorded".to_owned(),
            json!(admission.matched_benchmark_recorded),
        );
    }
    let (mut outbound_production_matrix_gate, outbound_production_matrix_gate_blockers) =
        if let Some(evidence) = evidence.as_ref() {
            (
                evidence.outbound_production_matrix_gate.clone(),
                evidence.outbound_production_matrix_gate_blockers.clone(),
            )
        } else {
            let gate = outbound_production_matrix_gate_json(
                executed,
                options,
                &outbound_fingerprint_underlay_gate,
                &resident_default_daemon_switch_gate,
                admission,
            );
            (gate.report, gate.blockers)
        };
    let outbound_production_matrix_ready =
        outbound_production_matrix_gate["outbound_production_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let go_outbound_fallback_retired_candidate =
        outbound_production_matrix_gate["go_outbound_fallback_retired_candidate"]
            .as_bool()
            .unwrap_or(false);
    let outbound_production_matrix_default_switch_admission_ready = outbound_production_matrix_ready
        && admission.production_dataplane_admitted
        && admission.reload_runtime_parity_admitted
        && admission.matched_benchmark_recorded;
    if let Value::Object(gate) = &mut outbound_production_matrix_gate {
        gate.insert(
            "outbound_production_matrix_default_switch_admission_ready".to_owned(),
            json!(outbound_production_matrix_default_switch_admission_ready),
        );
        gate.insert(
            "admission_production_dataplane_admitted".to_owned(),
            json!(admission.production_dataplane_admitted),
        );
        gate.insert(
            "admission_reload_runtime_parity_admitted".to_owned(),
            json!(admission.reload_runtime_parity_admitted),
        );
        gate.insert(
            "admission_matched_go_rust_default_daemon_benchmark_recorded".to_owned(),
            json!(admission.matched_benchmark_recorded),
        );
    }
    let sibling_repos_present = missing_repos.is_empty();
    let sibling_repo_status_available = unavailable_repos.is_empty();
    let product_chain_branch_contract_preserved = branch_mismatched_repos.is_empty();
    let clean_product_chain_baseline = sibling_repos_present
        && sibling_repo_status_available
        && dirty_repos.is_empty()
        && product_chain_branch_contract_preserved;
    let runtime_control_api_clean_baseline = runtime_control_api_clean_baseline_json(
        executed,
        clean_product_chain_baseline,
        runtime_control_api_source_contract_preserved,
        admission,
        service_contract_passed,
        dependency_boundary_preserved,
    );
    let runtime_control_api_source_baseline_recorded =
        runtime_control_api_clean_baseline["recorded"]
            .as_bool()
            .unwrap_or(false);
    let runtime_control_api_final_admission_recorded =
        runtime_control_api_clean_baseline["final_admission_recorded"]
            .as_bool()
            .unwrap_or(false);
    let daed_wing_runtime_control_api_regression_recorded =
        runtime_control_api_source_baseline_recorded;
    let product_chain_structural_baseline_clean = executed
        && service_contract_passed
        && dependency_boundary_preserved
        && clean_product_chain_baseline
        && runtime_control_api_source_baseline_recorded
        && c0_c3_entry_gates_clean
        && resident_runtime_platform_ready
        && control_plane_owner_ready
        && datapath_core_ready
        && outbound_fingerprint_underlay_ready
        && outbound_production_matrix_ready;
    let resident_default_daemon_switch_ready = resident_default_daemon_switch_gate["ready"]
        .as_bool()
        .unwrap_or(false);
    let resident_default_daemon_service_contract =
        resident_default_daemon_switch_gate["candidate_service_contract"].clone();
    let default_switch_admission_clean = product_chain_structural_baseline_clean
        && admission.bpf_go_fallback_retired
        && admission.true_rust_default_daemon_admitted
        && runtime_control_api_final_admission_recorded
        && control_plane_owner_default_switch_admission_ready
        && datapath_core_default_switch_admission_ready
        && outbound_fingerprint_underlay_default_switch_admission_ready
        && outbound_production_matrix_default_switch_admission_ready;
    let recertification_clean = product_chain_structural_baseline_clean;
    let default_path_mutation_allowed = default_switch_admission_clean
        && default_path_mutation_requested
        && resident_default_daemon_switch_ready;
    let product_chain_switch_allowed = default_path_mutation_allowed;
    let go_fallback_required = !product_chain_switch_allowed;
    let go_fallback_retired = product_chain_switch_allowed;
    let go_fallback_retirement_scope = if go_fallback_retired {
        "product-chain-default-path-admission"
    } else {
        "blocked-before-product-chain-default-path-admission"
    };
    let production_run_command_replacement_plan = production_run_command_replacement_plan_json(
        options,
        artifact_dir,
        default_path_mutation_allowed,
        resident_default_daemon_switch_ready,
        service_contract_passed,
        go_fallback_required,
        go_fallback_retired,
    );
    let release_default_switch_gate = release_default_switch_gate_json(
        executed,
        options,
        default_switch_admission_clean,
        product_chain_switch_allowed,
        &outbound_production_matrix_gate,
        &resident_default_daemon_switch_gate,
        &production_run_command_replacement_plan,
        None,
        None,
        None,
    )
    .report;
    let release_default_switch_ready = release_default_switch_gate["release_default_switch_ready"]
        .as_bool()
        .unwrap_or(false);
    let release_default_switch_admission_ready =
        release_default_switch_gate["release_default_switch_admission_ready"]
            .as_bool()
            .unwrap_or(false);
    let default_product_package_scan = default_product_package_scan_json(options);
    let go_free_product_chain_gate = go_free_product_chain_gate_json(
        executed,
        &release_default_switch_gate,
        &resident_default_daemon_switch_gate,
        dependency_boundary_preserved,
        product_chain_branch_contract_preserved,
        &default_product_package_scan,
    )
    .report;
    let go_free_product_chain_ready = go_free_product_chain_gate["go_free_product_chain_ready"]
        .as_bool()
        .unwrap_or(false);
    let go_free_product_chain_admission_ready =
        go_free_product_chain_gate["go_free_product_chain_admission_ready"]
            .as_bool()
            .unwrap_or(false);
    let mut remaining_blockers = remaining_blockers(
        admission,
        &dirty_repos,
        &missing_repos,
        &unavailable_repos,
        &branch_mismatched_repos,
        runtime_control_api_source_contract_preserved,
        daed_wing_runtime_control_api_regression_recorded,
        default_path_mutation_requested,
    );
    remaining_blockers.extend(value_string_array(
        &resident_default_daemon_switch_gate["blockers"],
    ));
    remaining_blockers.extend(native_owned_entry_gate_blockers);
    remaining_blockers.extend(resident_runtime_platform_gate_blockers);
    remaining_blockers.extend(control_plane_owner_gate_blockers);
    remaining_blockers.extend(datapath_core_gate_blockers);
    remaining_blockers.extend(outbound_fingerprint_underlay_gate_blockers);
    remaining_blockers.extend(outbound_production_matrix_gate_blockers);
    remaining_blockers.extend(production_run_command_execution_blockers(
        &production_run_command_replacement_plan,
    ));
    remaining_blockers.extend(production_run_command_apply_plan_blockers(
        &production_run_command_replacement_plan,
    ));
    let typed_report = ProductChainTypedReportSummary {
        executed,
        recertification_clean,
        structural_baseline_clean: product_chain_structural_baseline_clean,
        default_switch_admission_clean,
        default_path_mutation_requested,
        default_path_mutation_allowed,
        product_chain_switch_allowed,
        resident_default_daemon_switch_ready,
        admission,
        service_contract_preserved: service_contract_passed,
        dependency_boundary_preserved,
        runtime_control_api_source_contract_preserved,
        product_chain_topology_locked,
        default_bundle_boundary_clean,
        default_runtime_selector_rust_owned,
        explicit_go_rollback_only,
        runtime_selector_matrix_recorded,
        daed_service_contract_ready,
        resident_runtime_platform_ready,
        resident_runtime_resource_gate_ready,
        resident_runtime_resource_gate_passed,
        control_plane_owner_ready,
        go_control_plane_fallback_retired_candidate,
        control_plane_owner_default_switch_admission_ready,
        datapath_core_ready,
        go_datapath_core_fallback_retired_candidate,
        datapath_core_default_switch_admission_ready,
        outbound_fingerprint_underlay_ready,
        go_fingerprint_underlay_fallback_retired_candidate,
        outbound_fingerprint_underlay_default_switch_admission_ready,
        outbound_production_matrix_ready,
        go_outbound_fallback_retired_candidate,
        outbound_production_matrix_default_switch_admission_ready,
        release_default_switch_ready,
        release_default_switch_admission_ready,
        go_free_product_chain_ready,
        go_free_product_chain_admission_ready,
        clean_product_chain_baseline,
        product_chain_branch_contract_preserved,
        go_fallback_required,
        go_fallback_retired,
        remaining_blocker_count: remaining_blockers.len(),
    }
    .to_json();
    let expected_product_chain_branches = expected_product_chain_branches_json();
    let mut report = product_chain_base_report(ProductChainBaseReportFields {
        options,
        artifact_dir,
        manifest_file,
        admission,
        executed,
        topology: &topology,
        service: &service,
        go_mod: &go_mod,
        runtime_control_api: &runtime_control_api,
        default_product_package_scan: &default_product_package_scan,
        repos: &repos,
        dirty_repos: &dirty_repos,
        missing_repos: &missing_repos,
        unavailable_repos: &unavailable_repos,
        service_contract_passed,
        dependency_boundary_preserved,
        runtime_control_api_source_contract_preserved,
        sibling_repos_present,
        sibling_repo_status_available,
        clean_product_chain_baseline,
        runtime_control_api_clean_baseline: &runtime_control_api_clean_baseline,
        daed_wing_runtime_control_api_regression_recorded,
        recertification_clean,
        default_path_mutation_requested,
        default_path_mutation_allowed,
        product_chain_switch_allowed,
        remaining_blockers: &remaining_blockers,
    });
    insert_product_chain_entry_runtime_fields(
        &mut report,
        ProductChainEntryRuntimeReportFields {
            native_owned_entry_gates: &native_owned_entry_gates,
            resident_default_daemon_switch_ready,
            resident_default_daemon_switch_gate: &resident_default_daemon_switch_gate,
            resident_runtime_platform_ready,
            resident_runtime_platform_gate: &resident_runtime_platform_gate,
            resident_default_daemon_service_contract: &resident_default_daemon_service_contract,
            production_run_command_replacement_plan: &production_run_command_replacement_plan,
            product_chain_topology_locked,
            default_bundle_boundary_clean,
            default_runtime_selector_rust_owned,
            explicit_go_rollback_only,
            runtime_selector_matrix_recorded,
            daed_service_contract_ready,
            c0_c3_entry_gates_clean,
        },
    );
    insert_product_chain_owner_gate_fields(
        &mut report,
        ProductChainOwnerGateReportFields {
            control_plane_owner_ready,
            control_plane_owner_gate: &control_plane_owner_gate,
            go_control_plane_fallback_retired_candidate,
            control_plane_owner_default_switch_admission_ready,
            datapath_core_ready,
            datapath_core_gate: &datapath_core_gate,
            go_datapath_core_fallback_retired_candidate,
            datapath_core_default_switch_admission_ready,
            outbound_fingerprint_underlay_ready,
            outbound_fingerprint_underlay_gate: &outbound_fingerprint_underlay_gate,
            go_fingerprint_underlay_fallback_retired_candidate,
            outbound_fingerprint_underlay_default_switch_admission_ready,
            outbound_production_matrix_ready,
            outbound_production_matrix_gate: &outbound_production_matrix_gate,
            go_outbound_fallback_retired_candidate,
            outbound_production_matrix_default_switch_admission_ready,
            release_default_switch_ready,
            release_default_switch_admission_ready,
            release_default_switch_gate: &release_default_switch_gate,
            go_free_product_chain_ready,
            go_free_product_chain_admission_ready,
            go_free_product_chain_gate: &go_free_product_chain_gate,
            resident_runtime_resource_gate_ready,
            resident_runtime_resource_gate_passed,
        },
    );
    insert_product_chain_branch_default_fields(
        &mut report,
        ProductChainBranchDefaultReportFields {
            branch_mismatched_repos: &branch_mismatched_repos,
            expected_product_chain_branches: &expected_product_chain_branches,
            product_chain_branch_contract_preserved,
            product_chain_structural_baseline_clean,
            runtime_control_api_source_baseline_recorded,
            runtime_control_api_final_admission_recorded,
            default_switch_admission_clean,
            go_fallback_required,
            go_fallback_retired,
            go_fallback_retirement_scope,
            typed_report: &typed_report,
        },
    );
    report
}
