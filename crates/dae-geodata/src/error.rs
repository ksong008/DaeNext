use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeoDataError {
    FailedToReadBytes,
    FailedToReadExpectedLenBytes,
    InvalidGeodataFile,
    InvalidGeodataVarintLength,
    EntryTooLarge(u64),
    CodeNotFound,
    InvalidHex(String),
    InvalidUtf8,
    InvalidIpLength(usize),
    InvalidCidrPrefix(u64),
    UnsupportedWireType(u64),
    CountryCodeNotFound(String),
    GeoSiteCodeNotFound(String),
}

impl GeoDataError {
    pub fn is_full_read_fallback_candidate(&self) -> bool {
        matches!(
            self,
            Self::FailedToReadBytes
                | Self::FailedToReadExpectedLenBytes
                | Self::InvalidGeodataFile
                | Self::InvalidGeodataVarintLength
        )
    }
}

impl fmt::Display for GeoDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedToReadBytes => f.write_str("failed to read bytes"),
            Self::FailedToReadExpectedLenBytes => {
                f.write_str("failed to read expected length of bytes")
            }
            Self::InvalidGeodataFile => f.write_str("invalid geodata file"),
            Self::InvalidGeodataVarintLength => f.write_str("invalid geodata varint length"),
            Self::EntryTooLarge(length) => write!(f, "geodata entry too large: {length} bytes"),
            Self::CodeNotFound => f.write_str("code not found"),
            Self::InvalidHex(input) => write!(f, "invalid hex: {input}"),
            Self::InvalidUtf8 => f.write_str("invalid utf-8"),
            Self::InvalidIpLength(length) => write!(f, "invalid IP length: {length}"),
            Self::InvalidCidrPrefix(prefix) => {
                write!(f, "invalid CIDR prefix: {prefix}")
            }
            Self::UnsupportedWireType(wire_type) => {
                write!(f, "unsupported protobuf wire type: {wire_type}")
            }
            Self::CountryCodeNotFound(code) => write!(f, "country code {code} not found"),
            Self::GeoSiteCodeNotFound(code) => write!(f, "code {code} not found"),
        }
    }
}

impl std::error::Error for GeoDataError {}
