use crate::error::OutboundError;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum GrpcMode {
    #[default]
    Gun,
    Multi,
}

impl GrpcMode {
    pub fn parse_link_value(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "gun" => Ok(Self::Gun),
            "multi" => Ok(Self::Multi),
            value => Err(OutboundError::BadSharedTransport(format!(
                "unsupported Xray gRPC mode: {value}"
            ))),
        }
    }

    pub const fn link_value(self) -> &'static str {
        match self {
            Self::Gun => "gun",
            Self::Multi => "multi",
        }
    }

    pub const fn stream_method(self) -> &'static str {
        match self {
            Self::Gun => "Tun",
            Self::Multi => "TunMulti",
        }
    }
}
