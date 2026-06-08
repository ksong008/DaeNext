#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductChainRecertificationOptions {
    pub execute: bool,
    pub default_path_mutation_requested: bool,
    pub production_run_command_replacement_dry_run_requested: bool,
    pub production_run_command_replacement_execute_requested: bool,
    pub production_run_command_replacement_apply_plan_requested: bool,
    pub host_default_path_mutation_allow_requested: bool,
    pub local_validation_fresh_install_plan_requested: bool,
    pub local_validation_config_source: Option<PathBuf>,
    pub local_validation_binary_source: Option<PathBuf>,
    pub resident_default_daemon_binary_source: Option<PathBuf>,
    pub dae_repo: PathBuf,
    pub dae_wing_repo: PathBuf,
    pub daed_repo: PathBuf,
    pub outbound_repo: PathBuf,
    pub quic_go_repo: PathBuf,
    pub service_file: PathBuf,
    pub go_mod_file: PathBuf,
}

impl Default for ProductChainRecertificationOptions {
    fn default() -> Self {
        Self {
            execute: false,
            default_path_mutation_requested: false,
            production_run_command_replacement_dry_run_requested: false,
            production_run_command_replacement_execute_requested: false,
            production_run_command_replacement_apply_plan_requested: false,
            host_default_path_mutation_allow_requested: false,
            local_validation_fresh_install_plan_requested: false,
            local_validation_config_source: None,
            local_validation_binary_source: None,
            resident_default_daemon_binary_source: None,
            dae_repo: PathBuf::from("/root/project/dae-daex-align"),
            daed_repo: PathBuf::from("/root/project/daed-daex-align/daed"),
            dae_wing_repo: PathBuf::from("/root/project/daed-daex-align/daed/wing"),
            outbound_repo: PathBuf::from("/root/project/outbound-daex-align"),
            quic_go_repo: PathBuf::from("/root/project/quic-go-daex-align"),
            service_file: PathBuf::from("/root/project/daed-daex-align/daed/install/daed.service"),
            go_mod_file: PathBuf::from("/root/project/dae-daex-align/go.mod"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProductChainAdmissionEvidence {
    pub production_dataplane_admitted: bool,
    pub reload_runtime_parity_admitted: bool,
    pub matched_benchmark_recorded: bool,
    pub bpf_go_fallback_retired: bool,
    pub true_rust_default_daemon_admitted: bool,
}
