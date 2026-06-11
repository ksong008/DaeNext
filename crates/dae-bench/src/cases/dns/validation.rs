use super::*;
pub(super) fn bench_dns_validation_question_id(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let req = DnsMessage::new(0x1111, false, vec![DnsQuestion::new("example.com.", 1, 1)]);
    let matching = DnsMessage::new(0x1111, true, vec![DnsQuestion::new("example.com.", 1, 1)]);
    let mismatched_id = DnsMessage::new(0x2222, true, vec![DnsQuestion::new("example.com.", 1, 1)]);
    let mismatched_question =
        DnsMessage::new(0x1111, true, vec![DnsQuestion::new("other.example.", 1, 1)]);

    Ok(measure(
        || {
            let mut checksum = 0_u64;
            for (response, require_id) in [
                (&matching, true),
                (&mismatched_id, true),
                (&mismatched_id, false),
                (&mismatched_question, true),
            ] {
                match validate_dns_response_for_request_fast(
                    black_box(&req),
                    Some(black_box(response)),
                    black_box(require_id),
                ) {
                    Ok(_) => checksum ^= 1,
                    Err(err) => checksum ^= err.code(),
                }
            }
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_packet_view_validate_question_id(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    const REQUEST: &[u8] = &[
        0x11, 0x11, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    const MATCHING: &[u8] = &[
        0x11, 0x11, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    const MISMATCHED_ID: &[u8] = &[
        0x22, 0x22, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    const MISMATCHED_QUESTION: &[u8] = &[
        0x11, 0x11, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, b'o', b't',
        b'h', b'e', b'r', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00,
        0x01,
    ];
    const CASES: [(&[u8], bool); 4] = [
        (MATCHING, true),
        (MISMATCHED_ID, true),
        (MISMATCHED_ID, false),
        (MISMATCHED_QUESTION, true),
    ];

    Ok(measure(
        || {
            let mut checksum = 0_u64;
            for (response, require_id) in black_box(CASES) {
                let req = DnsPacketView::parse(black_box(REQUEST)).expect("parse dns request view");
                let resp =
                    DnsPacketView::parse(black_box(response)).expect("parse dns response view");
                match validate_dns_packet_response_for_request_fast(
                    black_box(&req),
                    Some(black_box(&resp)),
                    black_box(require_id),
                ) {
                    Ok(_) => checksum ^= 1,
                    Err(err) => checksum ^= err.code(),
                }
            }
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_resolve_asis_guard(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || match guard_synthetic_asis_lookup(black_box("asis")) {
            Ok(()) => black_box(0),
            Err(err) => black_box(err.to_string().len() as u64),
        },
        iters,
        warmup,
    ))
}
