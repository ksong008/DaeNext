#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseDefaultSwitchContract {
    pub name: &'static str,
    pub c_phase: &'static str,
    pub prior_gate: &'static str,
    pub contract_ready: bool,
    pub default_artifact_path_ready: bool,
    pub default_runtime_selector_ready: bool,
    pub service_package_scripts_ready: bool,
    pub live_evidence_contract_ready: bool,
    pub backup_manifest_contract_ready: bool,
    pub rollback_rehearsal_contract_ready: bool,
    pub host_write_freeze_required: bool,
    pub go_product_shell_allowed_until_go_free: bool,
    pub final_go_free_claim: bool,
    pub required_live_hosts: Vec<&'static str>,
    pub surface: Vec<&'static str>,
}

pub fn release_default_switch_contract() -> ReleaseDefaultSwitchContract {
    ReleaseDefaultSwitchContract {
        name: "release-default-switch",
        c_phase: "C9",
        prior_gate: "outbound-production-matrix",
        contract_ready: true,
        default_artifact_path_ready: true,
        default_runtime_selector_ready: true,
        service_package_scripts_ready: true,
        live_evidence_contract_ready: true,
        backup_manifest_contract_ready: true,
        rollback_rehearsal_contract_ready: true,
        host_write_freeze_required: true,
        go_product_shell_allowed_until_go_free: true,
        final_go_free_claim: false,
        required_live_hosts: vec!["38", "10.10.10.2"],
        surface: vec![
            "release/action/docker/package default candidate path",
            "default runtime selector with no environment override",
            "install service and package script default command contract",
            "candidate service-contract and live evidence record contract",
            "backup manifest and rollback script contract",
            "read-only host-write freeze before any production mutation",
        ],
    }
}
