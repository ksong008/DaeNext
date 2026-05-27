use serde_json::{Value, json};

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
    fn recorded(self) -> bool {
        self.executed
            && self.clean_product_chain_baseline
            && self.runtime_control_api_source_contract_preserved
            && self.admission.true_rust_default_daemon_admitted
            && self.service_contract_preserved
            && self.dependency_boundary_preserved
    }

    fn status(self) -> TypedReportStatus {
        if self.recorded() {
            TypedReportStatus::Pass
        } else {
            TypedReportStatus::Fail
        }
    }

    fn to_json(self) -> Value {
        let recorded = self.recorded();
        json!({
            "status": self.status().as_str(),
            "recorded": recorded,
            "execute": self.executed,
            "clean_product_chain_baseline": self.clean_product_chain_baseline,
            "runtime_control_api_source_contract_preserved": self.runtime_control_api_source_contract_preserved,
            "true_rust_default_daemon_admitted": self.admission.true_rust_default_daemon_admitted,
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
    pub(super) default_path_mutation_requested: bool,
    pub(super) default_path_mutation_allowed: bool,
    pub(super) product_chain_switch_allowed: bool,
    pub(super) resident_default_daemon_switch_ready: bool,
    pub(super) admission: ProductChainAdmissionEvidence,
    pub(super) service_contract_preserved: bool,
    pub(super) dependency_boundary_preserved: bool,
    pub(super) runtime_control_api_source_contract_preserved: bool,
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
        json!({
            "schema": "product-chain-recertification-typed-report-v1",
            "formal_surface": "product-chain",
            "status": self.status().as_str(),
            "execute": self.executed,
            "recertification_clean": self.recertification_clean,
            "default_path_mutation_requested": self.default_path_mutation_requested,
            "default_path_mutation_allowed": self.default_path_mutation_allowed,
            "product_chain_switch_allowed": self.product_chain_switch_allowed,
            "resident_default_daemon_switch_ready": self.resident_default_daemon_switch_ready,
            "production_dataplane_admitted": self.admission.production_dataplane_admitted,
            "reload_runtime_parity_admitted": self.admission.reload_runtime_parity_admitted,
            "matched_go_rust_default_daemon_benchmark_recorded": self.admission.matched_benchmark_recorded,
            "bpf_go_fallback_retired": self.admission.bpf_go_fallback_retired,
            "true_rust_default_daemon_admitted": self.admission.true_rust_default_daemon_admitted,
            "service_contract_preserved": self.service_contract_preserved,
            "outbound_quic_go_dependency_boundary_preserved": self.dependency_boundary_preserved,
            "runtime_control_api_source_contract_preserved": self.runtime_control_api_source_contract_preserved,
            "clean_product_chain_baseline": self.clean_product_chain_baseline,
            "product_chain_branch_contract_preserved": self.product_chain_branch_contract_preserved,
            "go_fallback_required": self.go_fallback_required,
            "go_fallback_retired": self.go_fallback_retired,
            "remaining_blocker_count": self.remaining_blocker_count,
            "stage_report_schema": false,
        })
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
