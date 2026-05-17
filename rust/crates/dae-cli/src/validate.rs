use dae_config::parser::parse_config;
use dae_config::schema::build_config;

use crate::CliError;

pub fn validate_config_text(input: &str) -> Result<(), CliError> {
    let sections = parse_config(input).map_err(|err| CliError::Config(err.to_string()))?;
    build_config(&sections)
        .map(|_| ())
        .map_err(|err| CliError::Config(err.to_string()))
}
