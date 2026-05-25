use std::hint::black_box;

use dae_dns::{
    DnsCacheEntry, DnsCacheKey, DnsCacheKeyView, DnsCacheStore, DnsMessage, DnsPacketAnswerView,
    DnsPacketView, DnsQuestion, build_doh_request, guard_synthetic_asis_lookup,
    parse_dns_cache_key_view, validate_dns_packet_response_for_request_fast,
    validate_dns_response_for_request_fast, validate_doh_response,
};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "dns/packed_response_restore",
            default_iters: 100_000,
            run: bench_dns_packed_response_restore,
        },
        BenchCase {
            id: "dns/data_zero_id",
            default_iters: 100_000,
            run: bench_dns_data_zero_id,
        },
        BenchCase {
            id: "dns/cache_key_roundtrip",
            default_iters: 100_000,
            run: bench_dns_cache_key_roundtrip,
        },
        BenchCase {
            id: "dns/cache_ttl_lookup",
            default_iters: 10_000,
            run: bench_dns_cache_ttl_lookup,
        },
        BenchCase {
            id: "dns/doh_get_request",
            default_iters: 100_000,
            run: bench_dns_doh_get_request,
        },
        BenchCase {
            id: "dns/doh_post_request",
            default_iters: 10_000,
            run: bench_dns_doh_post_request,
        },
        BenchCase {
            id: "dns/doh_validate_content_type",
            default_iters: 100_000,
            run: bench_dns_doh_validate_content_type,
        },
        BenchCase {
            id: "dns/validation_question_id",
            default_iters: 100_000,
            run: bench_dns_validation_question_id,
        },
        BenchCase {
            id: "dns/packet_view_validate_question_id",
            default_iters: 100_000,
            run: bench_dns_packet_view_validate_question_id,
        },
        BenchCase {
            id: "dns/packet_view_answers_ttl_ip_cname",
            default_iters: 100_000,
            run: bench_dns_packet_view_answers_ttl_ip_cname,
        },
        BenchCase {
            id: "dns/resolve_asis_guard",
            default_iters: 100_000,
            run: bench_dns_resolve_asis_guard,
        },
    ]
}

fn bench_dns_data_zero_id(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let payload = [0x12, 0x34, 0x56, 0x78];
    Ok(measure(
        || {
            let zeroed = dae_dns::dns_data_with_zero_id(black_box(&payload));
            black_box(zeroed[0] as u64 ^ zeroed[1] as u64 ^ zeroed.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_dns_packed_response_restore(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let mut entry = DnsCacheEntry::new(60, 60);
    entry.packed_response = vec![
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01,
    ];
    let mut restored = Vec::with_capacity(entry.packed_response.len());
    Ok(measure(
        || {
            entry
                .fill_packed_response_into(black_box(0x1234), &mut restored)
                .expect("packed response restore");
            black_box(restored.len() as u64 ^ restored[0] as u64 ^ restored[1] as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_dns_cache_key_roundtrip(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let key = DnsCacheKey::new(black_box("Example.COM"), black_box(1), black_box(1));
            let structured = parse_dns_cache_key_view(black_box("example.com.|1|1"))
                .expect("structured dns key");
            let legacy =
                parse_dns_cache_key_view(black_box("example.com.1")).expect("legacy dns key");
            black_box(
                key.qname.len() as u64
                    ^ key.matches_view(structured) as u64
                    ^ ((key.matches_view(legacy) as u64) << 1),
            )
        },
        iters,
        warmup,
    ))
}

fn bench_dns_cache_ttl_lookup(iters: u64, warmup: u64) -> Result<Measurement, String> {
    const NOW: i64 = 1_700_000_000;
    const LIVE_KEY: DnsCacheKeyView<'static> = DnsCacheKeyView {
        qname: "live.example.",
        qtype: 1,
        qclass: 1,
    };
    const CLIENT_EXPIRED_KEY: DnsCacheKeyView<'static> = DnsCacheKeyView {
        qname: "client-expired.example.",
        qtype: 1,
        qclass: 1,
    };
    const EXPIRED_KEY: DnsCacheKeyView<'static> = DnsCacheKeyView {
        qname: "expired.example.",
        qtype: 1,
        qclass: 1,
    };
    const LIVE_QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b'l', b'i',
        b'v', b'e', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    Ok(measure(
        || {
            let mut store = DnsCacheStore::new(8);
            store.insert_without_route_owner_key(
                NOW,
                DnsCacheKey::new(LIVE_KEY.qname, LIVE_KEY.qtype, LIVE_KEY.qclass),
                DnsCacheEntry::new(NOW + 60, NOW + 60),
            );
            store.insert_without_route_owner_key(
                NOW,
                DnsCacheKey::new(
                    CLIENT_EXPIRED_KEY.qname,
                    CLIENT_EXPIRED_KEY.qtype,
                    CLIENT_EXPIRED_KEY.qclass,
                ),
                DnsCacheEntry::new(NOW - 60, NOW + 60),
            );
            store.insert_without_route_owner_key(
                NOW,
                DnsCacheKey::new(EXPIRED_KEY.qname, EXPIRED_KEY.qtype, EXPIRED_KEY.qclass),
                DnsCacheEntry::new(NOW - 60, NOW - 60),
            );

            let mut checksum = 0_u64;
            let live_view = DnsPacketView::parse(black_box(LIVE_QUERY)).expect("live dns query");
            let live_question = live_view.questions().next().expect("live dns question");
            checksum ^= store
                .lookup_packet_question(NOW, black_box(&live_question), false)
                .expect("packet question lookup")
                .is_some() as u64;
            checksum ^= (store
                .lookup_view(NOW, black_box(CLIENT_EXPIRED_KEY), false)
                .is_none() as u64)
                << 1;
            checksum ^= (store
                .lookup_view(NOW, black_box(CLIENT_EXPIRED_KEY), true)
                .is_some() as u64)
                << 2;
            checksum ^= (store
                .lookup_view(NOW, black_box(EXPIRED_KEY), false)
                .is_none() as u64)
                << 3;
            checksum ^= store.stats().hit_total << 4;
            checksum ^= store.stats().expired_removal_total << 8;
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

fn bench_dns_doh_get_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let payload = [0x12, 0x34, 0x56, 0x78];
    Ok(measure(
        || {
            let req = build_doh_request(
                black_box("1.1.1.1:443"),
                black_box("dns.example.com"),
                black_box("/dns-query"),
                black_box(&payload),
            )
            .expect("build doh get request");
            black_box(req.url.len() as u64 ^ req.method.len() as u64 ^ req.body.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_dns_doh_post_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let mut payload = vec![0x12, 0x34];
    payload.extend(std::iter::repeat_n(0xab, 1024));
    Ok(measure(
        || {
            let req = build_doh_request(
                black_box("1.1.1.1:443"),
                black_box("dns.example.com"),
                black_box("/dns-query"),
                black_box(&payload),
            )
            .expect("build doh post request");
            black_box(req.url.len() as u64 ^ req.method.len() as u64 ^ req.body.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_dns_doh_validate_content_type(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let cases: [(u16, &str, &[u8]); 4] = [
        (200, "200 OK", b"application/dns-message"),
        (200, "200 OK", b"application/dns-message; charset=binary"),
        (502, "502 Bad Gateway", b"application/dns-message"),
        (200, "200 OK", b"text/html; charset=utf-8"),
    ];
    Ok(measure(
        || {
            let mut checksum = 0_u64;
            for (status_code, status, content_type) in black_box(cases) {
                match validate_doh_response(status_code, status, content_type) {
                    Ok(_) => checksum ^= 1,
                    Err(err) => checksum ^= err.to_string().len() as u64,
                }
            }
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

fn bench_dns_validation_question_id(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_dns_packet_view_validate_question_id(
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

fn bench_dns_packet_view_answers_ttl_ip_cname(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    const CNAME_PACKET: &[u8] = &[
        0x00, 0x00, 0x81, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x61, 0x6c,
        0x69, 0x61, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10, 0x06, 0x74, 0x61, 0x72,
        0x67, 0x65, 0x74, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, 0x06, 0x74, 0x61,
        0x72, 0x67, 0x65, 0x74, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0xcb, 0x00, 0x71, 0x14,
    ];
    const AAAA_RESPONSE: &[u8] = &[
        0x33, 0x33, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    Ok(measure(
        || {
            let mut checksum = 0_u64;
            for packet in black_box([CNAME_PACKET, AAAA_RESPONSE]) {
                let view = DnsPacketView::parse(packet).expect("parse dns packet view");
                for answer in view.answers() {
                    let answer = answer.expect("dns answer view");
                    checksum ^= answer.ttl() as u64;
                    checksum ^= (answer.qtype() as u64) << 8;
                    if let Some(ip) = answer.ip() {
                        match ip {
                            std::net::IpAddr::V4(addr) => {
                                checksum ^= u32::from(addr) as u64;
                            }
                            std::net::IpAddr::V6(addr) => {
                                let octets = addr.octets();
                                checksum ^= u64::from_be_bytes([
                                    octets[0], octets[1], octets[2], octets[3], octets[4],
                                    octets[5], octets[6], octets[7],
                                ]);
                            }
                        }
                    }
                    if let DnsPacketAnswerView::Cname { target, .. } = answer {
                        checksum ^= target
                            .canonical_eq_ignore_ascii_case("target.example.")
                            .expect("cname target compare")
                            as u64;
                    }
                }
            }
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

fn bench_dns_resolve_asis_guard(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || match guard_synthetic_asis_lookup(black_box("asis")) {
            Ok(()) => black_box(0),
            Err(err) => black_box(err.to_string().len() as u64),
        },
        iters,
        warmup,
    ))
}
