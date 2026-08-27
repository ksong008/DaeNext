use std::sync::{Arc, Mutex};

use super::TlsFragmentOptions;

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

pub fn new_tls_fragment_stats() -> SharedTlsFragmentStats {
    Arc::new(Mutex::new(TlsFragmentStats::default()))
}

pub fn snapshot_tls_fragment_stats(stats: &SharedTlsFragmentStats) -> TlsFragmentStats {
    stats
        .lock()
        .map(|stats| stats.clone())
        .unwrap_or_else(|_| TlsFragmentStats::default())
}

pub(super) fn passthrough_report(
    input: &[u8],
    options: &TlsFragmentOptions,
    reason: &'static str,
) -> TlsFragmentWriteReport {
    TlsFragmentWriteReport {
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
        min_length: options.min_length(),
        max_length: options.max_length(),
        min_interval_ms: options.min_interval_ms(),
        max_interval_ms: options.max_interval_ms(),
        interval_enabled: options.interval_enabled(),
        reassembled_record_matches: true,
    }
}
