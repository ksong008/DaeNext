use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub root: PathBuf,
    pub config: PathBuf,
    pub logfile: PathBuf,
    pub disable_timestamp: bool,
    pub disable_pidfile: bool,
    pub disable_sudo: bool,
    pub listener_smoke: bool,
    pub reload_smoke: bool,
    pub production_runtime_owner: ProductionRuntimeOwnerOptions,
    pub production_dataplane_harness: ProductionDataplaneHarnessOptions,
    pub matched_default_benchmark: MatchedDefaultBenchmarkOptions,
    pub product_chain_recertification: ProductChainRecertificationOptions,
    pub product_chain_admission_override: Option<ProductChainAdmissionEvidence>,
    pub product_chain_admission_source: Option<PathBuf>,
}

impl RunOptions {
    pub fn under_root(root: impl Into<PathBuf>, config: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            config: config.into(),
            logfile: root.join("log").join("dae-daemon-optin-run.log"),
            root,
            disable_timestamp: false,
            disable_pidfile: false,
            disable_sudo: false,
            listener_smoke: true,
            reload_smoke: true,
            production_runtime_owner: ProductionRuntimeOwnerOptions::default(),
            production_dataplane_harness: ProductionDataplaneHarnessOptions::default(),
            matched_default_benchmark: MatchedDefaultBenchmarkOptions::default(),
            product_chain_recertification: ProductChainRecertificationOptions::default(),
            product_chain_admission_override: None,
            product_chain_admission_source: None,
        }
    }
}

pub fn default_run_root() -> PathBuf {
    PathBuf::from("/tmp/dae-daemon-optin-run")
}
