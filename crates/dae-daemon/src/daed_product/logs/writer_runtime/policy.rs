use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductLogPolicy {
    pub(crate) runtime_level: String,
    pub(crate) max_entries: i64,
    pub(crate) max_bytes: i64,
}

impl ProductLogPolicy {
    pub(crate) fn load(state: &Path) -> io::Result<Self> {
        let runtime_level = current_runtime_log_level(state)?;
        #[cfg(test)]
        observe_log_settings_read(state);
        let conn = open_state_connection(state)?;
        let (max_entries, max_bytes) = log_settings_tuple(&conn)?;
        Ok(Self {
            runtime_level,
            max_entries,
            max_bytes,
        })
    }
}
