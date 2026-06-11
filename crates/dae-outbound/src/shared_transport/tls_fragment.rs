use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::error::OutboundError;

pub const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
pub const TLS_RECORD_HEADER_LEN: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFragmentOptions {
    pub min_length: usize,
    pub max_length: usize,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsFragmentStats {
    pub writes: Vec<TlsFragmentWriteReport>,
}

impl TlsFragmentStats {
    pub fn fragmented_write_count(&self) -> usize {
        self.writes.iter().filter(|write| write.fragmented).count()
    }

    pub fn total_fragment_records(&self) -> usize {
        self.writes
            .iter()
            .map(|write| write.fragment_record_count)
            .sum()
    }

    pub fn handshake_record_fragmented(&self) -> bool {
        self.writes
            .iter()
            .any(|write| write.handshake_record_fragmented)
    }

    pub fn all_fragmented_writes_reassembled(&self) -> bool {
        self.writes
            .iter()
            .filter(|write| write.fragmented)
            .all(|write| write.reassembled_record_matches)
    }

    pub fn fragment_payload_lens(&self) -> Vec<usize> {
        self.writes
            .iter()
            .flat_map(|write| write.fragment_payload_lens.iter().copied())
            .collect()
    }

    pub fn first_fragmented_write(&self) -> Option<&TlsFragmentWriteReport> {
        self.writes.iter().find(|write| write.fragmented)
    }
}

pub type SharedTlsFragmentStats = Arc<Mutex<TlsFragmentStats>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFragmentWrite {
    pub bytes: Vec<u8>,
    pub report: TlsFragmentWriteReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFragmentWriteReport {
    pub input_len: usize,
    pub output_len: usize,
    pub first_byte: Option<u8>,
    pub fragmented: bool,
    pub passthrough: bool,
    pub passthrough_reason: Option<&'static str>,
    pub handshake_record_fragmented: bool,
    pub original_record_len: usize,
    pub original_payload_len: usize,
    pub trailing_len: usize,
    pub fragment_record_count: usize,
    pub fragment_payload_lens: Vec<usize>,
    pub min_length: usize,
    pub max_length: usize,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
    pub interval_enabled: bool,
    pub reassembled_record_matches: bool,
}

pub struct TlsFragmentingStream<S> {
    inner: S,
    options: TlsFragmentOptions,
    stats: SharedTlsFragmentStats,
}

impl<S> TlsFragmentingStream<S> {
    pub fn new(inner: S, options: TlsFragmentOptions, stats: SharedTlsFragmentStats) -> Self {
        Self {
            inner,
            options,
            stats,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> Read for TlsFragmentingStream<S>
where
    S: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S> Write for TlsFragmentingStream<S>
where
    S: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let fragmented = fragment_tls_write(buf, &self.options)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        write_fragmented_bytes(&mut self.inner, &fragmented, &self.options)?;
        let mut stats = self
            .stats
            .lock()
            .map_err(|_| io::Error::other("tls fragment stats mutex poisoned"))?;
        stats.writes.push(fragmented.report);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn new_tls_fragment_stats() -> SharedTlsFragmentStats {
    Arc::new(Mutex::new(TlsFragmentStats::default()))
}

pub fn snapshot_tls_fragment_stats(stats: &SharedTlsFragmentStats) -> TlsFragmentStats {
    stats
        .lock()
        .map(|stats| stats.clone())
        .unwrap_or_else(|_| TlsFragmentStats::default())
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

pub fn fragment_tls_write(
    input: &[u8],
    options: &TlsFragmentOptions,
) -> Result<TlsFragmentWrite, OutboundError> {
    if input.len() <= TLS_RECORD_HEADER_LEN {
        return Ok(passthrough_write(input, options, "short-write"));
    }
    if input[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return Ok(passthrough_write(input, options, "not-handshake-record"));
    }
    let record_len = TLS_RECORD_HEADER_LEN + (((input[3] as usize) << 8) | input[4] as usize);
    if input.len() < record_len {
        return Ok(passthrough_write(
            input,
            options,
            "incomplete-handshake-record",
        ));
    }

    let original_payload = &input[TLS_RECORD_HEADER_LEN..record_len];
    let trailing = &input[record_len..];
    let mut output = Vec::with_capacity(input.len() + original_payload.len() / options.min_length);
    let mut fragment_payload_lens = Vec::new();
    let mut reassembled = Vec::with_capacity(original_payload.len());
    let mut from = 0;
    while from < original_payload.len() {
        let to = original_payload
            .len()
            .min(from + deterministic_fragment_len(options));
        let payload = &original_payload[from..to];
        output.extend_from_slice(&input[..3]);
        output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        output.extend_from_slice(payload);
        fragment_payload_lens.push(payload.len());
        reassembled.extend_from_slice(payload);
        from = to;
    }
    output.extend_from_slice(trailing);
    let report = TlsFragmentWriteReport {
        input_len: input.len(),
        output_len: output.len(),
        first_byte: input.first().copied(),
        fragmented: true,
        passthrough: false,
        passthrough_reason: None,
        handshake_record_fragmented: fragment_payload_lens.len() > 1,
        original_record_len: record_len,
        original_payload_len: original_payload.len(),
        trailing_len: trailing.len(),
        fragment_record_count: fragment_payload_lens.len(),
        fragment_payload_lens,
        min_length: options.min_length,
        max_length: options.max_length,
        min_interval_ms: options.min_interval_ms,
        max_interval_ms: options.max_interval_ms,
        interval_enabled: options.interval_enabled(),
        reassembled_record_matches: reassembled == original_payload,
    };
    Ok(TlsFragmentWrite {
        bytes: output,
        report,
    })
}

fn passthrough_write(
    input: &[u8],
    options: &TlsFragmentOptions,
    reason: &'static str,
) -> TlsFragmentWrite {
    TlsFragmentWrite {
        bytes: input.to_vec(),
        report: TlsFragmentWriteReport {
            input_len: input.len(),
            output_len: input.len(),
            first_byte: input.first().copied(),
            fragmented: false,
            passthrough: true,
            passthrough_reason: Some(reason),
            handshake_record_fragmented: false,
            original_record_len: 0,
            original_payload_len: 0,
            trailing_len: 0,
            fragment_record_count: 0,
            fragment_payload_lens: Vec::new(),
            min_length: options.min_length,
            max_length: options.max_length,
            min_interval_ms: options.min_interval_ms,
            max_interval_ms: options.max_interval_ms,
            interval_enabled: options.interval_enabled(),
            reassembled_record_matches: true,
        },
    }
}

fn deterministic_fragment_len(options: &TlsFragmentOptions) -> usize {
    options.min_length
}

fn write_fragmented_bytes<S>(
    inner: &mut S,
    fragmented: &TlsFragmentWrite,
    options: &TlsFragmentOptions,
) -> io::Result<()>
where
    S: Write,
{
    if !fragmented.report.fragmented || !options.interval_enabled() {
        inner.write_all(&fragmented.bytes)?;
        return Ok(());
    }

    let mut offset = 0;
    for payload_len in &fragmented.report.fragment_payload_lens {
        let record_len = TLS_RECORD_HEADER_LEN + payload_len;
        inner.write_all(&fragmented.bytes[offset..offset + record_len])?;
        offset += record_len;
        thread::sleep(Duration::from_millis(options.min_interval_ms));
    }
    if offset < fragmented.bytes.len() {
        inner.write_all(&fragmented.bytes[offset..])?;
    }
    Ok(())
}
