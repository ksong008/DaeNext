use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl DaemonOutput {
    pub(crate) fn ok(stdout: String) -> Self {
        Self {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        }
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 2,
        }
    }

    pub(crate) fn error(message: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{}\n", message.into()),
            exit_code: 1,
        }
    }
}
