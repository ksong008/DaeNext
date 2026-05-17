use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundError {
    NoAliveDialer,
    NoDialerInGroup,
    FixedIndexOutOfRange,
    UnsupportedPolicy(String),
    UnsupportedFilterInput(String),
    UnsupportedFilterKey { input: String, key: String },
    BadRegex(String),
    UnknownAnnotation(String),
    BadDuration(String),
    MissingScheme,
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAliveDialer => f.write_str("no alive dialer"),
            Self::NoDialerInGroup => f.write_str("no dialer in this group"),
            Self::FixedIndexOutOfRange => f.write_str("selected dialer index is out of range"),
            Self::UnsupportedPolicy(policy) => {
                write!(f, "unsupported DialerSelectionPolicy: {policy}")
            }
            Self::UnsupportedFilterInput(input) => {
                write!(f, "unsupported filter input type: {input:?}")
            }
            Self::UnsupportedFilterKey { input, key } => {
                write!(f, "unsupported filter key {key:?} in \"filter: {input}()\"")
            }
            Self::BadRegex(pattern) => write!(f, "bad regexp in filter: {pattern}"),
            Self::UnknownAnnotation(key) => write!(f, "unknown filter annotation: {key}"),
            Self::BadDuration(value) => write!(f, "incorrect latency format: {value}"),
            Self::MissingScheme => f.write_str("missing scheme"),
        }
    }
}

impl std::error::Error for OutboundError {}
