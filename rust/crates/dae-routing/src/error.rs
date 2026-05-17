use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutingError {
    InvalidPrefix(String),
    InvalidPrefixBits { input: String, bits: u8 },
    InvalidDomainKey(String),
    InvalidRegex(String),
    InvalidFixture(String),
    UnknownOutbound(String),
    UnknownMatchType(String),
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix(input) => write!(f, "invalid prefix: {input}"),
            Self::InvalidPrefixBits { input, bits } => {
                write!(f, "invalid prefix bits {bits}: {input}")
            }
            Self::InvalidDomainKey(key) => write!(f, "invalid domain key: {key}"),
            Self::InvalidRegex(pattern) => write!(f, "invalid regex: {pattern}"),
            Self::InvalidFixture(message) => write!(f, "invalid routing fixture: {message}"),
            Self::UnknownOutbound(outbound) => write!(f, "unknown outbound: {outbound}"),
            Self::UnknownMatchType(match_type) => write!(f, "unknown match type: {match_type}"),
        }
    }
}

impl std::error::Error for RoutingError {}
