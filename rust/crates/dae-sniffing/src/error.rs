use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SniffingError {
    NotApplicable,
    NeedMore,
    NotFound,
    DataTooLarge,
    Message(String),
}

impl fmt::Display for SniffingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotApplicable => f.write_str("sniffing error: not applicable"),
            Self::NeedMore => f.write_str("sniffing error: need more"),
            Self::NotFound => f.write_str("sniffing error: not found"),
            Self::DataTooLarge => f.write_str("sniffing error: packet sniffing data too large"),
            Self::Message(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for SniffingError {}

pub fn is_sniffing_error(_err: &SniffingError) -> bool {
    true
}
