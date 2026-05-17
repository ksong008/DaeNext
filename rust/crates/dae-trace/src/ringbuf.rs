use std::fmt;

pub const DEFAULT_RINGBUF_SIZE: &str = "64MiB";
pub const MIN_RINGBUF_SIZE_BYTES: u64 = 4 << 10;
pub const RINGBUF_SIZE_ALIGNMENT: u64 = 4 << 10;
pub const DEFAULT_RINGBUF_SIZE_BYTES: u64 = 64 << 20;

const SUFFIXES: &[(&str, u64)] = &[
    ("gib", 1 << 30),
    ("gb", 1 << 30),
    ("g", 1 << 30),
    ("mib", 1 << 20),
    ("mb", 1 << 20),
    ("m", 1 << 20),
    ("kib", 1 << 10),
    ("kb", 1 << 10),
    ("k", 1 << 10),
    ("b", 1),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingbufSizeError {
    message: String,
}

impl RingbufSizeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RingbufSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RingbufSizeError {}

pub fn default_ringbuf_size_bytes() -> u64 {
    DEFAULT_RINGBUF_SIZE_BYTES
}

pub fn parse_ringbuf_size_bytes(value: &str) -> Result<u64, RingbufSizeError> {
    let raw = if value.trim().is_empty() {
        DEFAULT_RINGBUF_SIZE
    } else {
        value.trim()
    };

    let size = parse_binary_byte_size(raw)?;
    if size < MIN_RINGBUF_SIZE_BYTES {
        return Err(RingbufSizeError::new(format!(
            "ring buffer size {raw:?} is too small; expect at least {MIN_RINGBUF_SIZE_BYTES} bytes"
        )));
    }
    if size % RINGBUF_SIZE_ALIGNMENT != 0 {
        return Err(RingbufSizeError::new(format!(
            "ring buffer size {raw:?} must be aligned to {RINGBUF_SIZE_ALIGNMENT} bytes"
        )));
    }
    if !size.is_power_of_two() {
        return Err(RingbufSizeError::new(format!(
            "ring buffer size {raw:?} must be a power of two"
        )));
    }
    if size > u32::MAX as u64 {
        return Err(RingbufSizeError::new(format!(
            "ring buffer size {raw:?} exceeds uint32 map limit"
        )));
    }
    Ok(size)
}

fn parse_binary_byte_size(value: &str) -> Result<u64, RingbufSizeError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(RingbufSizeError::new("ring buffer size cannot be empty"));
    }

    let mut multiplier = 1_u64;
    let mut number_part = normalized.as_str();
    for (suffix, suffix_multiplier) in SUFFIXES {
        if normalized.ends_with(suffix) {
            multiplier = *suffix_multiplier;
            number_part = normalized[..normalized.len() - suffix.len()].trim();
            break;
        }
    }

    if number_part.is_empty() {
        return Err(RingbufSizeError::new(format!(
            "ring buffer size {value:?} is missing its numeric value"
        )));
    }

    let base = number_part.parse::<u64>().map_err(|err| {
        let kind = if err.kind() == &std::num::IntErrorKind::PosOverflow {
            "value out of range"
        } else {
            "invalid syntax"
        };
        RingbufSizeError::new(format!(
            "invalid ring buffer size {value:?}: strconv.ParseUint: parsing {number_part:?}: {kind}"
        ))
    })?;

    base.checked_mul(multiplier).ok_or_else(|| {
        RingbufSizeError::new(format!("ring buffer size {value:?} overflows uint64"))
    })
}
