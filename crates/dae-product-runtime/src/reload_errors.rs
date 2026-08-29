use std::fmt;

#[derive(Clone, Debug)]
pub enum RuntimeReloadPrepareError {
    Materialize(String),
    BuildConfig(String),
    NetworkWait(String),
    Preflight(String),
}

impl RuntimeReloadPrepareError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Materialize(_) | Self::BuildConfig(_) => 400,
            Self::NetworkWait(_) => 503,
            Self::Preflight(_) => 409,
        }
    }

    pub fn api_log_message(&self) -> &'static str {
        match self {
            Self::Materialize(_) => "[Reload] Failed to materialize runtime preview",
            Self::BuildConfig(_) => "[Reload] Failed to build runtime config",
            Self::NetworkWait(_) => "[Runtime] Waiting for network before runtime build failed",
            Self::Preflight(_) => "[Reload] Candidate preflight failed",
        }
    }
}

impl fmt::Display for RuntimeReloadPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Materialize(error)
            | Self::BuildConfig(error)
            | Self::NetworkWait(error)
            | Self::Preflight(error) => formatter.write_str(error),
        }
    }
}

#[derive(Clone, Debug)]
pub enum CoordinatedRuntimeReloadError {
    Prepare(RuntimeReloadPrepareError),
    Apply(String),
}

impl From<String> for CoordinatedRuntimeReloadError {
    fn from(error: String) -> Self {
        Self::Apply(error)
    }
}

impl CoordinatedRuntimeReloadError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Prepare(error) => error.http_status(),
            Self::Apply(error) if error.contains("superseded by stop") => 409,
            Self::Apply(_) => 500,
        }
    }

    pub fn api_log_message(&self) -> &'static str {
        match self {
            Self::Prepare(error) => error.api_log_message(),
            Self::Apply(_) => "[Reload] Failed to reload",
        }
    }
}

impl fmt::Display for CoordinatedRuntimeReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare(error) => fmt::Display::fmt(error, formatter),
            Self::Apply(error) => formatter.write_str(error),
        }
    }
}
