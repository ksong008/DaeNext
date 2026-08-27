use crate::error::OutboundError;

use super::report::passthrough_report;
use super::{
    TLS_HANDSHAKE_CONTENT_TYPE, TLS_RECORD_HEADER_LEN, TlsFragmentOptions, TlsFragmentWriteReport,
};

/// A TLS record uses a two-byte payload length. The planner never buffers more
/// than one incomplete record, so this is also its per-connection input bound.
pub const TLS_FRAGMENT_MAX_BUFFERED_RECORD_LEN: usize = TLS_RECORD_HEADER_LEN + u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsFragmentSegment {
    /// Exclusive end offset in [`TlsFragmentPlan::bytes`].
    pub end: usize,
    /// Nonblocking/synchronous delay to apply before writing this segment.
    pub delay_before_ms: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsFragmentPlan {
    bytes: Vec<u8>,
    segments: Vec<TlsFragmentSegment>,
    reports: Vec<TlsFragmentWriteReport>,
}

impl TlsFragmentPlan {
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn segments(&self) -> &[TlsFragmentSegment] {
        &self.segments
    }

    pub fn reports(&self) -> &[TlsFragmentWriteReport] {
        &self.reports
    }

    pub(super) fn append_segment(&mut self, bytes: &[u8], delay_before_ms: u64) {
        if bytes.is_empty() {
            return;
        }
        self.bytes.extend_from_slice(bytes);
        self.segments.push(TlsFragmentSegment {
            end: self.bytes.len(),
            delay_before_ms,
        });
    }

    fn append_passthrough(
        &mut self,
        bytes: &[u8],
        options: &TlsFragmentOptions,
        reason: &'static str,
        collect_report: bool,
    ) {
        if bytes.is_empty() {
            return;
        }
        self.append_segment(bytes, 0);
        if collect_report {
            self.reports
                .push(passthrough_report(bytes, options, reason));
        }
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        Vec<TlsFragmentSegment>,
        Vec<TlsFragmentWriteReport>,
    ) {
        (self.bytes, self.segments, self.reports)
    }
}

pub struct TlsFragmentPlanner {
    options: TlsFragmentOptions,
    rng: fastrand::Rng,
    buffered_record: Vec<u8>,
    passthrough: bool,
    collect_reports: bool,
}

impl TlsFragmentPlanner {
    pub fn new(options: TlsFragmentOptions) -> Self {
        Self::with_rng(options, fastrand::Rng::with_seed(fastrand::u64(..)), false)
    }

    pub(super) fn with_reports(options: TlsFragmentOptions) -> Self {
        Self::with_rng(options, fastrand::Rng::with_seed(fastrand::u64(..)), true)
    }

    fn with_rng(options: TlsFragmentOptions, rng: fastrand::Rng, collect_reports: bool) -> Self {
        Self {
            options,
            rng,
            buffered_record: Vec::new(),
            passthrough: false,
            collect_reports,
        }
    }

    #[cfg(test)]
    fn with_seed(options: TlsFragmentOptions, seed: u64) -> Self {
        Self::with_rng(options, fastrand::Rng::with_seed(seed), true)
    }

    pub fn options(&self) -> &TlsFragmentOptions {
        &self.options
    }

    pub fn buffered_len(&self) -> usize {
        self.buffered_record.len()
    }

    /// Once a non-handshake record is observed, later encrypted application
    /// traffic no longer needs record assembly or an intermediate copy.
    pub fn is_passthrough(&self) -> bool {
        self.passthrough
    }

    pub fn push(&mut self, mut input: &[u8]) -> Result<TlsFragmentPlan, OutboundError> {
        let mut plan = TlsFragmentPlan::default();
        if input.is_empty() {
            return Ok(plan);
        }
        if self.passthrough {
            plan.append_passthrough(
                input,
                &self.options,
                "fragmentation-finished",
                self.collect_reports,
            );
            return Ok(plan);
        }

        while !input.is_empty() {
            if self.buffered_record.is_empty() {
                if input[0] != TLS_HANDSHAKE_CONTENT_TYPE {
                    self.passthrough = true;
                    plan.append_passthrough(
                        input,
                        &self.options,
                        "not-handshake-record",
                        self.collect_reports,
                    );
                    break;
                }
                if input.len() < TLS_RECORD_HEADER_LEN {
                    self.buffered_record.extend_from_slice(input);
                    break;
                }

                let record_len = tls_record_len(input);
                if input.len() < record_len {
                    self.buffered_record.extend_from_slice(input);
                    break;
                }

                self.append_fragmented_record(&mut plan, &input[..record_len]);
                input = &input[record_len..];
                continue;
            }

            if self.buffered_record.len() < TLS_RECORD_HEADER_LEN {
                let needed = TLS_RECORD_HEADER_LEN - self.buffered_record.len();
                let consumed = needed.min(input.len());
                self.buffered_record.extend_from_slice(&input[..consumed]);
                input = &input[consumed..];
                if self.buffered_record.len() < TLS_RECORD_HEADER_LEN {
                    break;
                }
            }

            let record_len = tls_record_len(&self.buffered_record);
            let needed = record_len - self.buffered_record.len();
            let consumed = needed.min(input.len());
            self.buffered_record.extend_from_slice(&input[..consumed]);
            input = &input[consumed..];
            if self.buffered_record.len() < record_len {
                break;
            }

            let record = std::mem::take(&mut self.buffered_record);
            self.append_fragmented_record(&mut plan, &record);
        }

        debug_assert!(self.buffered_record.len() <= TLS_FRAGMENT_MAX_BUFFERED_RECORD_LEN);
        Ok(plan)
    }

    /// Flushes an incomplete record byte-for-byte and disables further
    /// fragmentation. This prevents `poll_flush`/`poll_shutdown` from waiting
    /// forever while preserving stream data if a caller flushes mid-record.
    pub fn finish_incomplete(&mut self) -> TlsFragmentPlan {
        let mut plan = TlsFragmentPlan::default();
        if self.buffered_record.is_empty() {
            return plan;
        }

        let record = std::mem::take(&mut self.buffered_record);
        let reason = if record.len() <= TLS_RECORD_HEADER_LEN {
            "short-write"
        } else {
            "incomplete-handshake-record"
        };
        plan.append_passthrough(&record, &self.options, reason, self.collect_reports);
        self.passthrough = true;
        plan
    }

    pub(super) fn append_fragmented_record(&mut self, plan: &mut TlsFragmentPlan, record: &[u8]) {
        let output_start = plan.bytes.len();
        let segment_start = plan.segments.len();
        let original_payload = &record[TLS_RECORD_HEADER_LEN..];
        let estimated_records = original_payload
            .len()
            .div_ceil(self.options.min_length())
            .max(1);
        plan.bytes
            .reserve(record.len() + estimated_records * TLS_RECORD_HEADER_LEN);
        plan.segments.reserve(estimated_records);

        let mut fragment_payload_lens = self
            .collect_reports
            .then(|| Vec::with_capacity(estimated_records));
        if original_payload.is_empty() {
            plan.append_segment(record, 0);
            if let Some(fragment_payload_lens) = fragment_payload_lens.as_mut() {
                fragment_payload_lens.push(0);
            }
        } else {
            let mut from = 0;
            while from < original_payload.len() {
                let fragment_len = self.sample_fragment_len();
                let to = original_payload
                    .len()
                    .min(from.saturating_add(fragment_len));
                let delay_before_ms = if from == 0 {
                    0
                } else {
                    self.sample_interval_ms()
                };
                let payload = &original_payload[from..to];
                let mut header = [0_u8; TLS_RECORD_HEADER_LEN];
                header[..3].copy_from_slice(&record[..3]);
                header[3..].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                plan.append_segment(&header, delay_before_ms);
                plan.bytes.extend_from_slice(payload);
                if let Some(segment) = plan.segments.last_mut() {
                    segment.end = plan.bytes.len();
                }
                if let Some(fragment_payload_lens) = fragment_payload_lens.as_mut() {
                    fragment_payload_lens.push(payload.len());
                }
                from = to;
            }
        }

        let output_len = plan.bytes.len() - output_start;
        let fragment_record_count = plan.segments.len() - segment_start;
        if self.collect_reports {
            plan.reports.push(TlsFragmentWriteReport {
                input_len: record.len(),
                output_len,
                first_byte: record.first().copied(),
                fragmented: true,
                passthrough: false,
                passthrough_reason: None,
                handshake_record_fragmented: fragment_record_count > 1,
                original_record_len: record.len(),
                original_payload_len: original_payload.len(),
                trailing_len: 0,
                fragment_record_count,
                fragment_payload_lens: fragment_payload_lens.unwrap_or_default(),
                min_length: self.options.min_length(),
                max_length: self.options.max_length(),
                min_interval_ms: self.options.min_interval_ms(),
                max_interval_ms: self.options.max_interval_ms(),
                interval_enabled: self.options.interval_enabled(),
                reassembled_record_matches: true,
            });
        }
    }

    fn sample_fragment_len(&mut self) -> usize {
        if self.options.min_length() == self.options.max_length() {
            self.options.min_length()
        } else {
            self.rng
                .usize(self.options.min_length()..=self.options.max_length())
        }
    }

    fn sample_interval_ms(&mut self) -> u64 {
        if self.options.min_interval_ms() == self.options.max_interval_ms() {
            self.options.min_interval_ms()
        } else {
            self.rng
                .u64(self.options.min_interval_ms()..=self.options.max_interval_ms())
        }
    }
}

pub(super) fn tls_record_len(header: &[u8]) -> usize {
    TLS_RECORD_HEADER_LEN + u16::from_be_bytes([header[3], header[4]]) as usize
}

#[cfg(test)]
mod tests;
