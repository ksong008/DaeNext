use std::fmt;
use std::str::FromStr;
use std::time::Duration;

pub const UDP_CHECK_LOOKUP_HOST: &str = "connectivitycheck.gstatic.com.";
pub const DEFAULT_DIAL_TIMEOUT_SECS: u64 = 8;
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(DEFAULT_DIAL_TIMEOUT_SECS);
pub const DEFAULT_DIAL_TIMEOUT_STR: &str = "8s";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialMode {
    Ip,
    Domain,
    DomainPlus,
    DomainCao,
}

impl DialMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::DomainPlus => "domain+",
            Self::DomainCao => "domain++",
        }
    }
}

impl fmt::Display for DialMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialModeParseError {
    mode: String,
}

impl DialModeParseError {
    pub fn mode(&self) -> &str {
        &self.mode
    }
}

impl fmt::Display for DialModeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported dial mode: {}", self.mode)
    }
}

impl std::error::Error for DialModeParseError {}

impl FromStr for DialMode {
    type Err = DialModeParseError;

    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode {
            "ip" => Ok(Self::Ip),
            "domain" => Ok(Self::Domain),
            "domain+" => Ok(Self::DomainPlus),
            "domain++" => Ok(Self::DomainCao),
            _ => Err(DialModeParseError {
                mode: mode.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialerSelectionPolicy {
    Random,
    Fixed,
    MinAverage10Latencies,
    MinMovingAverageLatencies,
    MinLastLatency,
}

impl DialerSelectionPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Fixed => "fixed",
            Self::MinAverage10Latencies => "min_avg10",
            Self::MinMovingAverageLatencies => "min_moving_avg",
            Self::MinLastLatency => "min",
        }
    }
}

impl fmt::Display for DialerSelectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_modes_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/dial_mode_policy.json").unwrap();
        let accepted = fixture["dial_modes"]["accepted"].as_array().unwrap();

        for value in accepted {
            let text = value.as_str().unwrap();
            assert_eq!(text.parse::<DialMode>().unwrap().to_string(), text);
        }

        for value in fixture["dial_modes"]["rejected_examples"]
            .as_array()
            .unwrap()
        {
            let text = value.as_str().unwrap();
            let err = text.parse::<DialMode>().unwrap_err();
            assert_eq!(err.to_string(), format!("unsupported dial mode: {text}"));
        }
    }

    #[test]
    fn selection_policy_and_defaults_match_golden_fixture() {
        let fixture = dae_golden::load_json("abi/consts/dial_mode_policy.json").unwrap();
        let policies = [
            DialerSelectionPolicy::Random,
            DialerSelectionPolicy::Fixed,
            DialerSelectionPolicy::MinAverage10Latencies,
            DialerSelectionPolicy::MinMovingAverageLatencies,
            DialerSelectionPolicy::MinLastLatency,
        ];

        let got: Vec<_> = policies.iter().map(ToString::to_string).collect();
        let want: Vec<_> = fixture["dialer_selection_policies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();

        assert_eq!(got, want);
        assert_eq!(
            UDP_CHECK_LOOKUP_HOST,
            fixture["defaults"]["udp_check_lookup_host"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            DEFAULT_DIAL_TIMEOUT_STR,
            fixture["defaults"]["default_dial_timeout"]
                .as_str()
                .unwrap()
        );
        assert_eq!(DEFAULT_DIAL_TIMEOUT, Duration::from_secs(8));
    }
}
