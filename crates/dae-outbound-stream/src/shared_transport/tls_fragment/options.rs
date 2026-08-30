use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFragmentOptions {
    min_length: usize,
    max_length: usize,
    min_interval_ms: u64,
    max_interval_ms: u64,
}

impl TlsFragmentOptions {
    pub fn new(
        min_length: usize,
        max_length: usize,
        min_interval_ms: u64,
        max_interval_ms: u64,
    ) -> Result<Self, OutboundError> {
        if min_length == 0 {
            return Err(OutboundError::BadSharedTransport(
                "tls fragment min_length must be greater than zero".to_owned(),
            ));
        }
        if max_length < min_length {
            return Err(OutboundError::BadSharedTransport(
                "tls fragment max_length must be greater than or equal to min_length".to_owned(),
            ));
        }
        if max_interval_ms < min_interval_ms {
            return Err(OutboundError::BadSharedTransport(
                "tls fragment max_interval_ms must be greater than or equal to min_interval_ms"
                    .to_owned(),
            ));
        }
        Ok(Self {
            min_length,
            max_length,
            min_interval_ms,
            max_interval_ms,
        })
    }

    pub fn from_ranges(length: &str, interval: &str) -> Result<Self, OutboundError> {
        let (min_length, max_length) = parse_tls_fragment_range(length)?;
        let (min_interval_ms, max_interval_ms) = parse_tls_fragment_range(interval)?;
        Self::new(
            min_length,
            max_length,
            min_interval_ms as u64,
            max_interval_ms as u64,
        )
    }

    pub fn interval_enabled(&self) -> bool {
        self.max_interval_ms != 0
    }

    pub fn min_length(&self) -> usize {
        self.min_length
    }

    pub fn max_length(&self) -> usize {
        self.max_length
    }

    pub fn min_interval_ms(&self) -> u64 {
        self.min_interval_ms
    }

    pub fn max_interval_ms(&self) -> u64 {
        self.max_interval_ms
    }
}

pub fn parse_tls_fragment_range(value: &str) -> Result<(usize, usize), OutboundError> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(OutboundError::BadSharedTransport(format!(
            "invalid range: {value}"
        )));
    }
    let min = parts[0]
        .parse::<usize>()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    let max = parts[1]
        .parse::<usize>()
        .map_err(|err| OutboundError::BadSharedTransport(err.to_string()))?;
    Ok((min, max))
}
