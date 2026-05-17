use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsError {
    InvalidCacheKey(String),
    InvalidHex(String),
    PacketTooShort,
    UnexpectedEof,
    InvalidDnsName,
    CompressionLoop,
    DnsResponseNil,
    DnsRequestReceived,
    MissingQuestion,
    QuestionCountMismatch {
        got: usize,
        want: usize,
    },
    QuestionMismatch {
        index: usize,
        got: String,
        want: String,
    },
    IdMismatch {
        got: u16,
        want: u16,
    },
    DohStatus(String),
    InvalidDohContentType(String),
    UnexpectedDohContentType(String),
    SyntheticAsisOriginalTarget,
    TooBigDnsResp,
    Io(String),
    Resolve(String),
    Timeout,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCacheKey(raw) => write!(f, "invalid dns cache key: {raw}"),
            Self::InvalidHex(input) => write!(f, "invalid hex: {input}"),
            Self::PacketTooShort => f.write_str("dns packet too short"),
            Self::UnexpectedEof => f.write_str("unexpected end of dns packet"),
            Self::InvalidDnsName => f.write_str("invalid dns name"),
            Self::CompressionLoop => f.write_str("dns name compression loop"),
            Self::DnsResponseNil => f.write_str("dns response is nil"),
            Self::DnsRequestReceived => {
                f.write_str("dns response expected but dns request received")
            }
            Self::MissingQuestion => f.write_str("dns response missing question"),
            Self::QuestionCountMismatch { got, want } => {
                write!(f, "dns response question count mismatch: got {got} want {want}")
            }
            Self::QuestionMismatch { index, got, want } => write!(
                f,
                "dns response question mismatch at index {index}: got {got} want {want}"
            ),
            Self::IdMismatch { got, want } => {
                write!(f, "dns response id mismatch: got {got} want {want}")
            }
            Self::DohStatus(status) => write!(f, "doh server returned status {status}"),
            Self::InvalidDohContentType(value) => {
                write!(f, "invalid doh content-type {value:?}")
            }
            Self::UnexpectedDohContentType(value) => {
                write!(f, "unexpected doh content-type {value:?}")
            }
            Self::SyntheticAsisOriginalTarget => f.write_str(
                "dns request routing cannot use \"asis\" for synthetic resolver lookup; configure an explicit upstream instead",
            ),
            Self::TooBigDnsResp => f.write_str("too big dns resp"),
            Self::Io(message) => f.write_str(message),
            Self::Resolve(message) => f.write_str(message),
            Self::Timeout => f.write_str("timeout"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source.to_string())
    }
}
