use std::fmt;
use std::str::FromStr;

const NANOS_PER_MICRO: i128 = 1_000;
const NANOS_PER_MILLI: i128 = 1_000_000;
const NANOS_PER_SEC: i128 = 1_000_000_000;
const NANOS_PER_MIN: i128 = 60 * NANOS_PER_SEC;
const NANOS_PER_HOUR: i128 = 60 * NANOS_PER_MIN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoDuration {
    nanos: i64,
}

impl GoDuration {
    pub const fn from_nanos(nanos: i64) -> Self {
        Self { nanos }
    }

    pub const fn as_nanos(self) -> i64 {
        self.nanos
    }
}

impl Default for GoDuration {
    fn default() -> Self {
        Self::from_nanos(0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseDurationError {
    input: String,
}

impl ParseDurationError {
    fn new(input: &str) -> Self {
        Self {
            input: input.to_owned(),
        }
    }
}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "time: invalid duration \"{}\"", self.input)
    }
}

impl std::error::Error for ParseDurationError {}

impl FromStr for GoDuration {
    type Err = ParseDurationError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_duration(input)
    }
}

impl fmt::Display for GoDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut nanos = self.nanos as i128;
        if nanos < 0 {
            f.write_str("-")?;
            nanos = -nanos;
        }
        if nanos == 0 {
            return f.write_str("0s");
        }

        if nanos < NANOS_PER_SEC {
            return write_subsecond(f, nanos);
        }

        let hours = nanos / NANOS_PER_HOUR;
        nanos %= NANOS_PER_HOUR;
        let minutes = nanos / NANOS_PER_MIN;
        nanos %= NANOS_PER_MIN;
        let seconds = nanos / NANOS_PER_SEC;
        nanos %= NANOS_PER_SEC;

        if hours > 0 {
            write!(f, "{hours}h")?;
            write!(f, "{minutes}m")?;
        } else if minutes > 0 {
            write!(f, "{minutes}m")?;
        }
        if seconds > 0 || nanos > 0 || hours > 0 || minutes > 0 {
            if nanos == 0 {
                write!(f, "{seconds}s")?;
            } else {
                write_seconds_fraction(f, seconds, nanos)?;
            }
        }
        Ok(())
    }
}

fn parse_duration(input: &str) -> Result<GoDuration, ParseDurationError> {
    if input.is_empty() {
        return Err(ParseDurationError::new(input));
    }

    let bytes = input.as_bytes();
    let mut index = 0;
    let mut sign = 1_i128;
    if bytes[index] == b'+' || bytes[index] == b'-' {
        if bytes[index] == b'-' {
            sign = -1;
        }
        index += 1;
        if index == bytes.len() {
            return Err(ParseDurationError::new(input));
        }
    }

    let mut total = 0_i128;
    let mut saw_term = false;
    while index < bytes.len() {
        let term_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let whole_end = index;
        let mut frac_end = index;
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            let frac_start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            if frac_start == index && whole_end == term_start {
                return Err(ParseDurationError::new(input));
            }
            frac_end = index;
        } else if whole_end == term_start {
            return Err(ParseDurationError::new(input));
        }

        let (unit, next) =
            parse_unit(input, index).ok_or_else(|| ParseDurationError::new(input))?;
        index = next;

        let whole = if whole_end == term_start {
            0
        } else {
            input[term_start..whole_end]
                .parse::<i128>()
                .map_err(|_| ParseDurationError::new(input))?
        };
        let mut nanos = whole
            .checked_mul(unit)
            .ok_or_else(|| ParseDurationError::new(input))?;

        if frac_end > whole_end {
            let frac_start = whole_end + 1;
            let frac = &input[frac_start..frac_end];
            if !frac.is_empty() {
                let frac_value = frac
                    .parse::<i128>()
                    .map_err(|_| ParseDurationError::new(input))?;
                let scale = 10_i128
                    .checked_pow(frac.len() as u32)
                    .ok_or_else(|| ParseDurationError::new(input))?;
                nanos += frac_value
                    .checked_mul(unit)
                    .ok_or_else(|| ParseDurationError::new(input))?
                    / scale;
            }
        }

        total = total
            .checked_add(nanos)
            .ok_or_else(|| ParseDurationError::new(input))?;
        saw_term = true;
    }

    if !saw_term {
        return Err(ParseDurationError::new(input));
    }

    let signed = total
        .checked_mul(sign)
        .ok_or_else(|| ParseDurationError::new(input))?;
    let nanos = i64::try_from(signed).map_err(|_| ParseDurationError::new(input))?;
    Ok(GoDuration::from_nanos(nanos))
}

fn parse_unit(input: &str, index: usize) -> Option<(i128, usize)> {
    let rest = &input[index..];
    if rest.starts_with("ns") {
        Some((1, index + 2))
    } else if rest.starts_with("us") {
        Some((NANOS_PER_MICRO, index + 2))
    } else if rest.starts_with("µs") {
        Some((NANOS_PER_MICRO, index + "µs".len()))
    } else if rest.starts_with("μs") {
        Some((NANOS_PER_MICRO, index + "μs".len()))
    } else if rest.starts_with("ms") {
        Some((NANOS_PER_MILLI, index + 2))
    } else if rest.starts_with('s') {
        Some((NANOS_PER_SEC, index + 1))
    } else if rest.starts_with('m') {
        Some((NANOS_PER_MIN, index + 1))
    } else if rest.starts_with('h') {
        Some((NANOS_PER_HOUR, index + 1))
    } else {
        None
    }
}

fn write_subsecond(f: &mut fmt::Formatter<'_>, nanos: i128) -> fmt::Result {
    if nanos % NANOS_PER_MILLI == 0 {
        write!(f, "{}ms", nanos / NANOS_PER_MILLI)
    } else if nanos % NANOS_PER_MICRO == 0 {
        write!(f, "{}µs", nanos / NANOS_PER_MICRO)
    } else {
        write!(f, "{nanos}ns")
    }
}

fn write_seconds_fraction(f: &mut fmt::Formatter<'_>, seconds: i128, nanos: i128) -> fmt::Result {
    let mut frac = format!("{nanos:09}");
    while frac.ends_with('0') {
        frac.pop();
    }
    write!(f, "{seconds}.{frac}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_basic_go_durations() {
        assert_eq!("30s".parse::<GoDuration>().unwrap().to_string(), "30s");
        assert_eq!("1m30s".parse::<GoDuration>().unwrap().to_string(), "1m30s");
        assert_eq!("1h".parse::<GoDuration>().unwrap().to_string(), "1h0m0s");
        assert_eq!("5s".parse::<GoDuration>().unwrap().to_string(), "5s");
        assert!("30".parse::<GoDuration>().is_err());
    }
}
