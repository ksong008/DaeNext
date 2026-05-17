use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum EngineError {
    AlreadyRunning,
    ContextDeadlineExceeded,
    Disconnected,
    InvalidTarget(String),
    Io(io::Error),
    Parse(String),
    TimeoutSendingShutdown,
    TimeoutWaitingForShutdown,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => write!(f, "runtime is already running"),
            Self::ContextDeadlineExceeded => write!(f, "context deadline exceeded"),
            Self::Disconnected => write!(f, "runtime channel disconnected"),
            Self::InvalidTarget(message) => write!(f, "{message}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Parse(message) => write!(f, "{message}"),
            Self::TimeoutSendingShutdown => write!(f, "timeout sending dae shutdown signal"),
            Self::TimeoutWaitingForShutdown => write!(f, "timeout waiting for dae shutdown"),
        }
    }
}

impl Error for EngineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for EngineError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
