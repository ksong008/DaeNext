use std::error::Error;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum GoldenError {
    RepoRootNotFound {
        start: PathBuf,
    },
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl fmt::Display for GoldenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepoRootNotFound { start } => {
                write!(f, "could not locate dae repo root from {}", start.display())
            }
            Self::Read { path, source } => {
                write!(f, "read golden fixture {}: {}", path.display(), source)
            }
            Self::Json { path, source } => {
                write!(f, "parse golden fixture {}: {}", path.display(), source)
            }
        }
    }
}

impl Error for GoldenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RepoRootNotFound { .. } => None,
            Self::Read { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
        }
    }
}
