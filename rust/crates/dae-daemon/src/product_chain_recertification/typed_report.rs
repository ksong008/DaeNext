use serde_json::{Map, Value, json};

use super::ProductChainAdmissionEvidence;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TypedReportStatus {
    Pass,
    Fail,
    NotExecuted,
}

impl TypedReportStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotExecuted => "not-executed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RuntimeControlApiCleanBaselineReport {
    pub(super) executed: bool,
    pub(super) clean_product_chain_baseline: bool,
    pub(super) runtime_control_api_source_contract_preserved: bool,
    pub(super) admission: ProductChainAdmissionEvidence,
    pub(super) service_contract_preserved: bool,
    pub(super) dependency_boundary_preserved: bool,
}

impl RuntimeControlApiCleanBaselineReport {
    fn source_baseline_recorded(self) -> bool {
        self.executed
            && self.clean_product_chain_baseline
            && self.runtime_control_api_source_contract_preserved
            && self.service_contract_preserved
            && self.dependency_boundary_preserved
    }

    fn final_admission_recorded(self) -> bool {
        self.source_baseline_recorded() && self.admission.true_rust_default_daemon_admitted
    }

    fn status(self) -> TypedReportStatus {
        if self.source_baseline_recorded() {
            TypedReportStatus::Pass
        } else {
            TypedReportStatus::Fail
        }
    }

    fn to_json(self) -> Value {
        let source_baseline_recorded = self.source_baseline_recorded();
        let final_admission_recorded = self.final_admission_recorded();
        json!({
            "status": self.status().as_str(),
            "recorded": source_baseline_recorded,
            "source_baseline_recorded": source_baseline_recorded,
            "final_admission_recorded": final_admission_recorded,
            "execute": self.executed,
            "clean_product_chain_baseline": self.clean_product_chain_baseline,
            "runtime_control_api_source_contract_preserved": self.runtime_control_api_source_contract_preserved,
            "true_rust_default_daemon_admitted": self.admission.true_rust_default_daemon_admitted,
            "true_rust_default_daemon_required_for_final_admission": true,
            "production_dataplane_admitted": self.admission.production_dataplane_admitted,
            "reload_runtime_parity_admitted": self.admission.reload_runtime_parity_admitted,
            "matched_go_rust_default_daemon_benchmark_recorded": self.admission.matched_benchmark_recorded,
            "bpf_go_fallback_retired": self.admission.bpf_go_fallback_retired,
            "service_contract_preserved": self.service_contract_preserved,
            "outbound_quic_go_dependency_boundary_preserved": self.dependency_boundary_preserved,
            "evidence_class": "read-only-daed-wing-daed-runtime-control-api-clean-baseline",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProductChainTypedReportSummary {
    pub(super) executed: bool,
    pub(super) recertification_clean: bool,
    pub(super) structural_baseline_clean: bool,
    pub(super) default_switch_admission_clean: bool,
    pub(super) default_path_mutation_requested: bool,
    pub(super) default_path_mutation_allowed: bool,
    pub(super) product_chain_switch_allowed: bool,
    pub(super) resident_default_daemon_switch_ready: bool,
    pub(super) admission: ProductChainAdmissionEvidence,
    pub(super) service_contract_preserved: bool,
    pub(super) dependency_boundary_preserved: bool,
    pub(super) runtime_control_api_source_contract_preserved: bool,
    pub(super) product_chain_topology_locked: bool,
    pub(super) default_bundle_boundary_clean: bool,
    pub(super) default_runtime_selector_rust_owned: bool,
    pub(super) explicit_go_rollback_only: bool,
    pub(super) runtime_selector_matrix_recorded: bool,
    pub(super) daed_service_contract_ready: bool,
    pub(super) resident_runtime_platform_ready: bool,
    pub(super) resident_runtime_resource_gate_ready: bool,
    pub(super) resident_runtime_resource_gate_passed: bool,
    pub(super) control_plane_owner_ready: bool,
    pub(super) go_control_plane_fallback_retired_candidate: bool,
    pub(super) control_plane_owner_default_switch_admission_ready: bool,
    pub(super) datapath_core_ready: bool,
    pub(super) go_datapath_core_fallback_retired_candidate: bool,
    pub(super) datapath_core_default_switch_admission_ready: bool,
    pub(super) outbound_fingerprint_underlay_ready: bool,
    pub(super) go_fingerprint_underlay_fallback_retired_candidate: bool,
    pub(super) outbound_fingerprint_underlay_default_switch_admission_ready: bool,
    pub(super) outbound_production_matrix_ready: bool,
    pub(super) go_outbound_fallback_retired_candidate: bool,
    pub(super) outbound_production_matrix_default_switch_admission_ready: bool,
    pub(super) release_default_switch_ready: bool,
    pub(super) release_default_switch_admission_ready: bool,
    pub(super) go_free_product_chain_ready: bool,
    pub(super) go_free_product_chain_admission_ready: bool,
    pub(super) clean_product_chain_baseline: bool,
    pub(super) product_chain_branch_contract_preserved: bool,
    pub(super) go_fallback_required: bool,
    pub(super) go_fallback_retired: bool,
    pub(super) remaining_blocker_count: usize,
}

impl ProductChainTypedReportSummary {
    pub(super) fn status(self) -> TypedReportStatus {
        if !self.executed {
            TypedReportStatus::NotExecuted
        } else if self.recertification_clean {
            TypedReportStatus::Pass
        } else {
            TypedReportStatus::Fail
        }
    }

    pub(super) fn to_json(self) -> Value {
        let mut report = Map::new();
        report.insert(
            "schema".to_owned(),
            json!("product-chain-recertification-typed-report"),
        );
        report.insert("formal_surface".to_owned(), json!("product-chain"));
        report.insert("status".to_owned(), json!(self.status().as_str()));
        report.insert("execute".to_owned(), json!(self.executed));
        report.insert(
            "recertification_clean".to_owned(),
            json!(self.recertification_clean),
        );
        report.insert(
            "structural_baseline_clean".to_owned(),
            json!(self.structural_baseline_clean),
        );
        report.insert(
            "default_switch_admission_clean".to_owned(),
            json!(self.default_switch_admission_clean),
        );
        report.insert(
            "default_path_mutation_requested".to_owned(),
            json!(self.default_path_mutation_requested),
        );
        report.insert(
            "default_path_mutation_allowed".to_owned(),
            json!(self.default_path_mutation_allowed),
        );
        report.insert(
            "product_chain_switch_allowed".to_owned(),
            json!(self.product_chain_switch_allowed),
        );
        report.insert(
            "resident_default_daemon_switch_ready".to_owned(),
            json!(self.resident_default_daemon_switch_ready),
        );
        report.insert(
            "production_dataplane_admitted".to_owned(),
            json!(self.admission.production_dataplane_admitted),
        );
        report.insert(
            "reload_runtime_parity_admitted".to_owned(),
            json!(self.admission.reload_runtime_parity_admitted),
        );
        report.insert(
            "matched_go_rust_default_daemon_benchmark_recorded".to_owned(),
            json!(self.admission.matched_benchmark_recorded),
        );
        report.insert(
            "bpf_go_fallback_retired".to_owned(),
            json!(self.admission.bpf_go_fallback_retired),
        );
        report.insert(
            "true_rust_default_daemon_admitted".to_owned(),
            json!(self.admission.true_rust_default_daemon_admitted),
        );
        report.insert(
            "service_contract_preserved".to_owned(),
            json!(self.service_contract_preserved),
        );
        report.insert(
            "outbound_quic_go_dependency_boundary_preserved".to_owned(),
            json!(self.dependency_boundary_preserved),
        );
        report.insert(
            "runtime_control_api_source_contract_preserved".to_owned(),
            json!(self.runtime_control_api_source_contract_preserved),
        );
        report.insert(
            "product_chain_topology_locked".to_owned(),
            json!(self.product_chain_topology_locked),
        );
        report.insert(
            "default_bundle_boundary_clean".to_owned(),
            json!(self.default_bundle_boundary_clean),
        );
        report.insert(
            "default_runtime_selector_rust_owned".to_owned(),
            json!(self.default_runtime_selector_rust_owned),
        );
        report.insert(
            "explicit_go_rollback_only".to_owned(),
            json!(self.explicit_go_rollback_only),
        );
        report.insert(
            "runtime_selector_matrix_recorded".to_owned(),
            json!(self.runtime_selector_matrix_recorded),
        );
        report.insert(
            "daed_service_contract_ready".to_owned(),
            json!(self.daed_service_contract_ready),
        );
        report.insert(
            "resident_runtime_platform_ready".to_owned(),
            json!(self.resident_runtime_platform_ready),
        );
        report.insert(
            "resident_runtime_resource_gate_ready".to_owned(),
            json!(self.resident_runtime_resource_gate_ready),
        );
        report.insert(
            "resident_runtime_resource_gate_passed".to_owned(),
            json!(self.resident_runtime_resource_gate_passed),
        );
        report.insert(
            "control_plane_owner_ready".to_owned(),
            json!(self.control_plane_owner_ready),
        );
        report.insert(
            "go_control_plane_fallback_retired_candidate".to_owned(),
            json!(self.go_control_plane_fallback_retired_candidate),
        );
        report.insert(
            "control_plane_owner_default_switch_admission_ready".to_owned(),
            json!(self.control_plane_owner_default_switch_admission_ready),
        );
        report.insert(
            "datapath_core_ready".to_owned(),
            json!(self.datapath_core_ready),
        );
        report.insert(
            "go_datapath_core_fallback_retired_candidate".to_owned(),
            json!(self.go_datapath_core_fallback_retired_candidate),
        );
        report.insert(
            "datapath_core_default_switch_admission_ready".to_owned(),
            json!(self.datapath_core_default_switch_admission_ready),
        );
        report.insert(
            "outbound_fingerprint_underlay_ready".to_owned(),
            json!(self.outbound_fingerprint_underlay_ready),
        );
        report.insert(
            "go_fingerprint_underlay_fallback_retired_candidate".to_owned(),
            json!(self.go_fingerprint_underlay_fallback_retired_candidate),
        );
        report.insert(
            "outbound_fingerprint_underlay_default_switch_admission_ready".to_owned(),
            json!(self.outbound_fingerprint_underlay_default_switch_admission_ready),
        );
        report.insert(
            "outbound_production_matrix_ready".to_owned(),
            json!(self.outbound_production_matrix_ready),
        );
        report.insert(
            "go_outbound_fallback_retired_candidate".to_owned(),
            json!(self.go_outbound_fallback_retired_candidate),
        );
        report.insert(
            "outbound_production_matrix_default_switch_admission_ready".to_owned(),
            json!(self.outbound_production_matrix_default_switch_admission_ready),
        );
        report.insert(
            "release_default_switch_ready".to_owned(),
            json!(self.release_default_switch_ready),
        );
        report.insert(
            "release_default_switch_admission_ready".to_owned(),
            json!(self.release_default_switch_admission_ready),
        );
        report.insert(
            "go_free_product_chain_ready".to_owned(),
            json!(self.go_free_product_chain_ready),
        );
        report.insert(
            "go_free_product_chain_admission_ready".to_owned(),
            json!(self.go_free_product_chain_admission_ready),
        );
        report.insert(
            "clean_product_chain_baseline".to_owned(),
            json!(self.clean_product_chain_baseline),
        );
        report.insert(
            "product_chain_branch_contract_preserved".to_owned(),
            json!(self.product_chain_branch_contract_preserved),
        );
        report.insert(
            "go_fallback_required".to_owned(),
            json!(self.go_fallback_required),
        );
        report.insert(
            "go_fallback_retired".to_owned(),
            json!(self.go_fallback_retired),
        );
        report.insert(
            "remaining_blocker_count".to_owned(),
            json!(self.remaining_blocker_count),
        );
        report.insert("stage_report_schema".to_owned(), json!(false));
        Value::Object(report)
    }
}

pub(super) fn runtime_control_api_clean_baseline_json(
    executed: bool,
    clean_product_chain_baseline: bool,
    runtime_control_api_source_contract_preserved: bool,
    admission: ProductChainAdmissionEvidence,
    service_contract_preserved: bool,
    dependency_boundary_preserved: bool,
) -> Value {
    RuntimeControlApiCleanBaselineReport {
        executed,
        clean_product_chain_baseline,
        runtime_control_api_source_contract_preserved,
        admission,
        service_contract_preserved,
        dependency_boundary_preserved,
    }
    .to_json()
}

pub(super) fn value_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn remaining_blockers(
    admission: ProductChainAdmissionEvidence,
    dirty_repos: &[String],
    missing_repos: &[String],
    unavailable_repos: &[String],
    branch_mismatched_repos: &[String],
    runtime_control_api_source_contract_preserved: bool,
    daed_wing_runtime_control_api_regression_recorded: bool,
    default_path_mutation_requested: bool,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if !admission.true_rust_default_daemon_admitted {
        blockers.push("true Rust default daemon admission is not present in this run".to_owned());
    }
    if !admission.bpf_go_fallback_retired {
        blockers
            .push("BPF-side Go fallback retirement evidence is not present in this run".to_owned());
    }
    if !default_path_mutation_requested {
        blockers.push(
            "default path mutation was not explicitly requested; service and /usr/bin/dae remain Go-default"
                .to_owned(),
        );
    }
    if !dirty_repos.is_empty() {
        blockers.push(format!(
            "product-chain baseline is dirty in sibling repos: {}",
            dirty_repos.join(", ")
        ));
    }
    if !missing_repos.is_empty() {
        blockers.push(format!(
            "product-chain sibling repos are missing: {}",
            missing_repos.join(", ")
        ));
    }
    if !unavailable_repos.is_empty() {
        blockers.push(format!(
            "product-chain sibling repo git status is unavailable: {}",
            unavailable_repos.join(", ")
        ));
    }
    if !branch_mismatched_repos.is_empty() {
        blockers.push(format!(
            "product-chain sibling repo branches do not match daed2.0 switch contract: {}",
            branch_mismatched_repos.join(", ")
        ));
    }
    if !runtime_control_api_source_contract_preserved {
        blockers.push(
            "dae-wing/daed runtime/control API source contract is incomplete or unreadable"
                .to_owned(),
        );
    }
    if !daed_wing_runtime_control_api_regression_recorded {
        blockers.push(
            "dae-wing and daed runtime/control API recertification still needs an explicit clean baseline run"
                .to_owned(),
        );
    }
    blockers
}
