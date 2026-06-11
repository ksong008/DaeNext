use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CliError {
    Config(String),
    Progress(String),
    UnsupportedShell(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "{message}"),
            Self::Progress(message) => write!(f, "{message}"),
            Self::UnsupportedShell(shell) => {
                write!(
                    f,
                    "unsupported shell type (must be bash, zsh or fish): {shell}"
                )
            }
        }
    }
}

impl Error for CliError {}
