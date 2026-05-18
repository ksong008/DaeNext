pub(crate) mod active_datapath_runner;
pub mod completion;
pub mod error;
pub mod export;
pub(crate) mod outbound_runner;
pub mod progress;
pub mod runner;
pub(crate) mod runtime_host_preflight;
pub(crate) mod runtime_live_plan;
pub(crate) mod runtime_runner;
pub(crate) mod runtime_stage26_candidate;
pub(crate) mod runtime_stage27_candidate;
pub(crate) mod runtime_stage29_preflight;
pub(crate) mod runtime_stage30_attach_cleanup;
pub(crate) mod runtime_stage31_34_gates;
pub(crate) mod runtime_stage35_36_gates;
pub(crate) mod runtime_stage37_gate;
pub(crate) mod runtime_stage38_gate;
pub(crate) mod runtime_stage39_gate;
pub(crate) mod runtime_stage40_gate;
pub(crate) mod runtime_stage41_48_gates;
pub mod surface;
pub(crate) mod userspace_runner;
pub mod validate;

#[cfg(test)]
mod tests;

pub use completion::get_completion;
pub use error::CliError;
pub use export::export_outline_json;
pub use progress::{
    ABORT_FILE, PID_FILE_PATH, ReloadProgress, SIGNAL_PROGRESS_FILE_PATH, parse_progress_content,
};
pub use runner::{RunnerOutput, run_with_args, run_with_args_and_version};
pub use surface::{CliSurface, CommandSpec, cli_surface};
pub use validate::{validate_config_file, validate_config_text};
