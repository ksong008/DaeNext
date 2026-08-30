use crate::error::OutboundError;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Annotation {
    pub add_latency_ms: i64,
}

impl Annotation {
    pub fn from_params(params: &[(&str, &str)]) -> Result<Self, OutboundError> {
        let mut annotation = Self::default();
        for (key, value) in params {
            match *key {
                "add_latency" => {
                    if annotation.add_latency_ms == 0 {
                        annotation.add_latency_ms = parse_duration_ms(value)?;
                    }
                }
                _ => return Err(OutboundError::UnknownAnnotation((*key).to_owned())),
            }
        }
        Ok(annotation)
    }
}

pub fn parse_duration_ms(value: &str) -> Result<i64, OutboundError> {
    let (number, scale) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1000)
    } else {
        return Err(OutboundError::BadDuration(value.to_owned()));
    };
    number
        .parse::<i64>()
        .map(|n| n * scale)
        .map_err(|_| OutboundError::BadDuration(value.to_owned()))
}
