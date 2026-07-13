use std::fmt;

mod capsule;
mod datagram;
mod uri_template;
mod varint;

pub use self::capsule::{
    CONNECT_UDP_CAPSULE_TYPE, CONNECT_UDP_CONTEXT_ID, MasqueCapsule, MasqueCapsuleDecoder,
    MasqueCapsuleLimits, encode_connect_udp_capsule, encode_unknown_capsule,
};
pub use self::datagram::{
    MasqueHttpDatagram, MasqueQuarterStreamId, decode_http_datagram, encode_http_datagram,
};
pub use self::uri_template::MasqueUriTemplate;
pub use self::varint::{
    decode_quic_varint_exact, decode_quic_varint_prefix, encode_quic_varint,
    quic_varint_encoded_len,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MasqueCodecError {
    InvalidTemplate(String),
    InvalidCapsule(String),
    InvalidLimits(String),
    VarIntOverflow(u64),
    TruncatedVarInt,
    TrailingVarIntBytes(usize),
    LengthOverflow,
    BufferLimitExceeded { limit: usize, required: usize },
    CapsulePayloadLimitExceeded { limit: usize, actual: u64 },
    DatagramPayloadLimitExceeded { limit: usize, actual: usize },
    UnsupportedContextId(u64),
    InvalidRequestStreamId(u64),
    TruncatedCapsule(usize),
}

impl fmt::Display for MasqueCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTemplate(reason) => {
                write!(f, "invalid CONNECT-UDP URI Template: {reason}")
            }
            Self::InvalidCapsule(reason) => write!(f, "invalid MASQUE Capsule: {reason}"),
            Self::InvalidLimits(reason) => write!(f, "invalid MASQUE codec limits: {reason}"),
            Self::VarIntOverflow(value) => write!(f, "QUIC variable integer overflow: {value}"),
            Self::TruncatedVarInt => f.write_str("truncated QUIC variable integer"),
            Self::TrailingVarIntBytes(bytes) => {
                write!(f, "QUIC variable integer has {bytes} trailing byte(s)")
            }
            Self::LengthOverflow => f.write_str("MASQUE frame length does not fit in memory"),
            Self::BufferLimitExceeded { limit, required } => write!(
                f,
                "MASQUE incremental buffer limit exceeded: limit={limit}, required={required}"
            ),
            Self::CapsulePayloadLimitExceeded { limit, actual } => write!(
                f,
                "MASQUE Capsule payload limit exceeded: limit={limit}, actual={actual}"
            ),
            Self::DatagramPayloadLimitExceeded { limit, actual } => write!(
                f,
                "CONNECT-UDP datagram payload limit exceeded: limit={limit}, actual={actual}"
            ),
            Self::UnsupportedContextId(context_id) => {
                write!(f, "unsupported CONNECT-UDP Context ID {context_id}")
            }
            Self::InvalidRequestStreamId(stream_id) => {
                write!(f, "invalid HTTP/3 request stream ID {stream_id}")
            }
            Self::TruncatedCapsule(buffered) => write!(
                f,
                "truncated MASQUE Capsule at end of stream: buffered={buffered}"
            ),
        }
    }
}

impl std::error::Error for MasqueCodecError {}
