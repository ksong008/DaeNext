use crate::error::OutboundError;

use super::planner::tls_record_len;
use super::report::passthrough_report;
use super::{
    TLS_HANDSHAKE_CONTENT_TYPE, TLS_RECORD_HEADER_LEN, TlsFragmentOptions, TlsFragmentPlan,
    TlsFragmentPlanner, TlsFragmentWrite,
};

/// Compatibility helper for callers that already hold one complete TLS write.
/// Stateful stream users should use [`TlsFragmentPlanner`] instead.
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
    let record_len = tls_record_len(input);
    if input.len() < record_len {
        return Ok(passthrough_write(
            input,
            options,
            "incomplete-handshake-record",
        ));
    }

    let mut planner = TlsFragmentPlanner::with_reports(options.clone());
    let mut plan = TlsFragmentPlan::default();
    planner.append_fragmented_record(&mut plan, &input[..record_len]);
    let trailing = &input[record_len..];
    if !trailing.is_empty() {
        plan.append_segment(trailing, 0);
    }
    let (bytes, _, mut reports) = plan.into_parts();
    let mut report = reports
        .pop()
        .expect("a complete TLS handshake record always produces a report");
    report.input_len = input.len();
    report.output_len = bytes.len();
    report.trailing_len = trailing.len();
    Ok(TlsFragmentWrite { bytes, report })
}

fn passthrough_write(
    input: &[u8],
    options: &TlsFragmentOptions,
    reason: &'static str,
) -> TlsFragmentWrite {
    TlsFragmentWrite {
        bytes: input.to_vec(),
        report: passthrough_report(input, options, reason),
    }
}
