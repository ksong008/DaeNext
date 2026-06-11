use std::path::Path;

use dae_config::Config;
use dae_config::merger::merge_config_file;
use dae_config::schema::build_config;

pub fn validate_config_file(path: impl AsRef<Path>) -> Result<usize, String> {
    let merged = merge_config_file(path.as_ref().to_path_buf()).map_err(|err| err.to_string())?;
    build_config(&merged.sections)
        .map(|_| merged.entries.len())
        .map_err(|err| err.to_string())
}

pub fn load_config_file(path: impl AsRef<Path>) -> Result<Config, String> {
    let merged = merge_config_file(path.as_ref().to_path_buf()).map_err(|err| err.to_string())?;
    build_config(&merged.sections).map_err(|err| err.to_string())
}
