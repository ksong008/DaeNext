use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedDefaultBenchmarkOptions {
    pub execute: bool,
    pub ack_root_gate: bool,
    pub iterations: u32,
    pub ready_timeout_ms: u64,
    pub source_dir: PathBuf,
    pub go_tool: PathBuf,
    pub go_work: Option<PathBuf>,
    pub go_binary: Option<PathBuf>,
    pub rust_binary: Option<PathBuf>,
}

impl Default for MatchedDefaultBenchmarkOptions {
    fn default() -> Self {
        Self {
            execute: false,
            ack_root_gate: false,
            iterations: 3,
            ready_timeout_ms: 15_000,
            source_dir: PathBuf::from("."),
            go_tool: PathBuf::from("go"),
            go_work: None,
            go_binary: None,
            rust_binary: None,
        }
    }
}
