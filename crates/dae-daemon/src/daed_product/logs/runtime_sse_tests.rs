use super::*;
#[cfg(test)]
pub(crate) fn set_runtime_log_level_from_config(state: &Path, config: &Config) -> io::Result<()> {
    let level = runtime_log_level_for_config(config);
    set_metadata(state, "runtime_log_level", &level)
}
