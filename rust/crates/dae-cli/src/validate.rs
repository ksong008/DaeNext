use std::path::Path;

use dae_config::merger::merge_config_file;
use dae_config::parser::parse_config;
use dae_config::schema::build_config;

use crate::CliError;

pub fn validate_config_text(input: &str) -> Result<(), CliError> {
    let sections = parse_config(input).map_err(|err| CliError::Config(err.to_string()))?;
    build_config(&sections)
        .map(|_| ())
        .map_err(|err| CliError::Config(err.to_string()))
}

pub fn validate_config_file(path: impl AsRef<Path>) -> Result<usize, CliError> {
    let merged = merge_config_file(path.as_ref().to_path_buf())
        .map_err(|err| CliError::Config(err.to_string()))?;
    build_config(&merged.sections)
        .map(|_| merged.entries.len())
        .map_err(|err| CliError::Config(err.to_string()))
}
