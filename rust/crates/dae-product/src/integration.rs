#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaedDaewingContract {
    pub required_surfaces: Vec<&'static str>,
    pub local_dae_contract_fixed: bool,
    pub cross_repo_write_scope: &'static str,
}

pub fn daed_daewing_contract() -> DaedDaewingContract {
    DaedDaewingContract {
        required_surfaces: vec![
            "RuntimeOverview JSON fields",
            "reload progress bytes and paths",
            "validate/export CLI surfaces",
            "API-only dry runtime reload/stop",
            "route-aware HTTP target",
            "node latency snapshots",
            "DNS observability counters",
        ],
        local_dae_contract_fixed: true,
        cross_repo_write_scope: "not in dae-local phase8 commit; dae-wing/daed must be validated in their repos before product rollout",
    }
}
