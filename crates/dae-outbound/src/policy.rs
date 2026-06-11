use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectionPolicy {
    Random,
    Fixed { index: usize },
    MinLastLatency,
    MinAverage10,
    MinMovingAverage,
}

impl SelectionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Fixed { .. } => "fixed",
            Self::MinLastLatency => "min",
            Self::MinAverage10 => "min_avg10",
            Self::MinMovingAverage => "min_moving_avg",
        }
    }

    pub fn needs_alive_state(&self) -> bool {
        !matches!(self, Self::Fixed { .. })
    }

    pub fn needs_latency_state(&self) -> bool {
        matches!(
            self,
            Self::MinLastLatency | Self::MinAverage10 | Self::MinMovingAverage
        )
    }
}

pub fn parse_policy(input: &str) -> Result<SelectionPolicy, OutboundError> {
    match input {
        "random" => Ok(SelectionPolicy::Random),
        "min" => Ok(SelectionPolicy::MinLastLatency),
        "min_avg10" | "min_average10" => Ok(SelectionPolicy::MinAverage10),
        "min_moving_avg" => Ok(SelectionPolicy::MinMovingAverage),
        _ if input.starts_with("fixed(") && input.ends_with(')') => {
            let raw = &input[6..input.len() - 1];
            let index = raw
                .parse::<usize>()
                .map_err(|_| OutboundError::UnsupportedPolicy(input.to_owned()))?;
            Ok(SelectionPolicy::Fixed { index })
        }
        _ => Err(OutboundError::UnsupportedPolicy(input.to_owned())),
    }
}
