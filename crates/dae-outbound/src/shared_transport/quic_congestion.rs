use std::fmt;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicCongestionController {
    Bbr,
    Cubic,
    NewReno,
}

impl QuicCongestionController {
    pub fn from_config(value: &str) -> Result<Self, QuicCongestionControllerError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "bbr" => Ok(Self::Bbr),
            "cubic" => Ok(Self::Cubic),
            "new_reno" | "new-reno" | "reno" => Ok(Self::NewReno),
            _ => Err(QuicCongestionControllerError),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
        }
    }

    pub fn install(self, transport: &mut quinn::TransportConfig) {
        match self {
            Self::Bbr => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            Self::Cubic => transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
            Self::NewReno => transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            )),
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicCongestionControllerError;

impl fmt::Display for QuicCongestionControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unsupported QUIC congestion controller")
    }
}

impl std::error::Error for QuicCongestionControllerError {}

#[cfg(test)]
mod tests {
    use super::QuicCongestionController;

    #[test]
    fn config_values_normalize_to_canonical_controller_names() {
        for (input, expected, canonical) in [
            ("", QuicCongestionController::Bbr, "bbr"),
            ("BBR", QuicCongestionController::Bbr, "bbr"),
            ("cubic", QuicCongestionController::Cubic, "cubic"),
            ("new-reno", QuicCongestionController::NewReno, "new_reno"),
            ("reno", QuicCongestionController::NewReno, "new_reno"),
        ] {
            let parsed = QuicCongestionController::from_config(input).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), canonical);
        }
        assert!(QuicCongestionController::from_config("brutal").is_err());
    }
}
