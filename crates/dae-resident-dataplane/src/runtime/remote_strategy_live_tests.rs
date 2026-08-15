use super::*;
#[path = "remote_strategy_live_tests/config_assessment.rs"]
mod config_assessment;
#[cfg(test)]
#[path = "remote_strategy_live_tests/live_strategy_tests.rs"]
mod live_strategy_tests;
pub use self::config_assessment::*;
#[path = "remote_strategy_live_tests/udp_probe.rs"]
mod udp_probe;
pub use self::udp_probe::*;

fn redacted_path_identity(path: &Path) -> String {
    link_hash(&path_string(path))
}
