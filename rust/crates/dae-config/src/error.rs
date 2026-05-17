use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Parse(String),
    Build(String),
    Merge(String),
    Marshal(String),
    Unsupported(&'static str),
}

impl ConfigError {
    pub const fn unsupported(feature: &'static str) -> Self {
        Self::Unsupported(feature)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(message) => write!(f, "parse config: {message}"),
            Self::Build(message) => write!(f, "build config: {message}"),
            Self::Merge(message) => write!(f, "merge config: {message}"),
            Self::Marshal(message) => write!(f, "marshal config: {message}"),
            Self::Unsupported(feature) => write!(f, "{feature} is not implemented"),
        }
    }
}

impl std::error::Error for ConfigError {}
