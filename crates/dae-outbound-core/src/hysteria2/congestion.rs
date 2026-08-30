use crate::error::OutboundError;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Hysteria2CongestionController {
    #[default]
    Bbr,
    Reno,
}

impl Hysteria2CongestionController {
    pub fn parse(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "bbr" => Ok(Self::Bbr),
            "reno" => Ok(Self::Reno),
            _ => Err(bad_congestion(
                "unsupported Hysteria2 congestion controller",
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bbr => "bbr",
            Self::Reno => "reno",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Hysteria2BbrProfile {
    #[default]
    Standard,
    Conservative,
    Aggressive,
}

impl Hysteria2BbrProfile {
    pub fn parse(value: &str) -> Result<Self, OutboundError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "standard" => Ok(Self::Standard),
            "conservative" => Ok(Self::Conservative),
            "aggressive" => Ok(Self::Aggressive),
            _ => Err(bad_congestion("unsupported Hysteria2 BBR profile")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Conservative => "conservative",
            Self::Aggressive => "aggressive",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hysteria2CongestionConfig {
    pub controller: Hysteria2CongestionController,
    pub bbr_profile: Hysteria2BbrProfile,
    pub disable_loss_compensation: bool,
}

impl Hysteria2CongestionConfig {
    pub fn new(
        controller: &str,
        bbr_profile: &str,
        disable_loss_compensation: bool,
    ) -> Result<Self, OutboundError> {
        let controller = Hysteria2CongestionController::parse(controller)?;
        let bbr_profile = Hysteria2BbrProfile::parse(bbr_profile)?;
        if controller == Hysteria2CongestionController::Reno
            && bbr_profile != Hysteria2BbrProfile::Standard
        {
            return Err(bad_congestion(
                "Hysteria2 BBR profile cannot be combined with Reno",
            ));
        }
        Ok(Self {
            controller,
            bbr_profile,
            disable_loss_compensation,
        })
    }

    pub fn validate_quinn(self) -> Result<Self, OutboundError> {
        if self.controller == Hysteria2CongestionController::Bbr
            && self.bbr_profile != Hysteria2BbrProfile::Standard
        {
            return Err(bad_congestion(
                "the Quinn Hysteria2 provider supports only the standard BBR profile",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Hysteria2ServerBandwidthResponse {
    #[default]
    Pending,
    Auto,
    Unlimited,
    Known,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hysteria2EffectiveCongestionController {
    Brutal,
    Bbr,
    Reno,
}

impl Hysteria2EffectiveCongestionController {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Brutal => "brutal",
            Self::Bbr => "bbr",
            Self::Reno => "reno",
        }
    }
}

impl Hysteria2ServerBandwidthResponse {
    pub const fn code(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Auto => 1,
            Self::Unlimited => 2,
            Self::Known => 3,
        }
    }

    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Auto,
            2 => Self::Unlimited,
            3 => Self::Known,
            _ => Self::Pending,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Auto => "auto",
            Self::Unlimited => "zero",
            Self::Known => "known",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hysteria2CongestionNegotiation {
    pub max_tx: u64,
    pub max_rx: u64,
    pub server_response: Hysteria2ServerBandwidthResponse,
    pub server_rx: u64,
    pub effective_tx: u64,
    pub controller: Hysteria2EffectiveCongestionController,
    pub profile: Hysteria2BbrProfile,
    pub loss_compensation: bool,
}
fn bad_congestion(message: impl Into<String>) -> OutboundError {
    OutboundError::BadHysteria2(message.into())
}
