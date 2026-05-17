pub mod completion;
pub mod error;
pub mod export;
pub mod progress;
pub mod surface;
pub mod validate;

#[cfg(test)]
mod tests;

pub use completion::get_completion;
pub use error::CliError;
pub use export::export_outline_json;
pub use progress::{
    ABORT_FILE, PID_FILE_PATH, ReloadProgress, SIGNAL_PROGRESS_FILE_PATH, parse_progress_content,
};
pub use surface::{CliSurface, CommandSpec, cli_surface};
pub use validate::validate_config_text;
