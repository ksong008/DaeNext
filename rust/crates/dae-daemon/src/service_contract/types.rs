use super::*;
pub const PID_FILE_PATH: &str = "/var/run/dae.pid";
pub const PROGRESS_FILE_PATH: &str = "/var/run/dae.progress";
pub const ABORT_FILE_PATH: &str = "/var/run/dae.abort";
pub(crate) const RESIDENT_DATAPLANE_ENV: &str = "DAE_RUST_RESIDENT_DATAPLANE";
pub const DAED_PRIMARY_STATE_STORE: &str = "/etc/daed/daed.db";
pub const DAED_PROTECTED_ROLLBACK_STATE_STORE: &str = "/etc/daed/wing.db";
pub const RESIDENT_RUNTIME_MAX_RSS_BYTES: u64 = 512 * 1024 * 1024;
pub const RESIDENT_RUNTIME_MAX_THREAD_COUNT: u64 = 256;
pub const RESIDENT_RUNTIME_MAX_FD_COUNT: u64 = 1024;
pub const RESIDENT_RUNTIME_MAX_REPORT_SIZE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentRunOptions {
    pub config: PathBuf,
    pub logfile: Option<PathBuf>,
    pub pid_file: PathBuf,
    pub progress_file: PathBuf,
    pub abort_file: PathBuf,
    pub ready_record_file: Option<PathBuf>,
    pub disable_timestamp: bool,
    pub disable_pidfile: bool,
    pub disable_sudo: bool,
}

impl ResidentRunOptions {
    pub fn for_config(config: impl Into<PathBuf>) -> Self {
        Self {
            config: config.into(),
            logfile: None,
            pid_file: PID_FILE_PATH.into(),
            progress_file: PROGRESS_FILE_PATH.into(),
            abort_file: ABORT_FILE_PATH.into(),
            ready_record_file: None,
            disable_timestamp: false,
            disable_pidfile: false,
            disable_sudo: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOptions {
    pub pid: Option<i32>,
    pub pid_file: PathBuf,
    pub progress_file: PathBuf,
    pub abort_file: PathBuf,
    pub abort_connections: bool,
    pub timeout: Option<Duration>,
}

impl Default for ReloadOptions {
    fn default() -> Self {
        Self {
            pid: None,
            pid_file: PID_FILE_PATH.into(),
            progress_file: PROGRESS_FILE_PATH.into(),
            abort_file: ABORT_FILE_PATH.into(),
            abort_connections: false,
            timeout: None,
        }
    }
}
