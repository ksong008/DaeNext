#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionDataplaneHarnessOptions {
    pub execute: bool,
    pub ack_root_gate: bool,
    pub benchmark_iters: u32,
}

impl Default for ProductionDataplaneHarnessOptions {
    fn default() -> Self {
        Self {
            execute: false,
            ack_root_gate: false,
            benchmark_iters: 5,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DataplaneAdmissionSpec {
    pub(super) check_id: &'static str,
    pub(super) profile: &'static str,
    pub(super) root_prefix: &'static str,
    pub(super) pass_key: &'static str,
    pub(super) benchmark_recorded_key: Option<&'static str>,
}
