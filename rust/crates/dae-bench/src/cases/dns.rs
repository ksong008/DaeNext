use std::hint::black_box;

use dae_dns::{
    DnsCacheEntry, DnsCacheKey, DnsCacheStore, DnsMessage, DnsQuestion, build_doh_request,
    guard_synthetic_asis_lookup, parse_dns_cache_key, validate_dns_response_for_request,
    validate_doh_response,
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
    Ok(measure(
        || {
            let restored = entry
                .fill_packed_response(black_box(0x1234))
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
            let structured = parse_dns_cache_key(&key.to_string()).expect("structured dns key");
            let legacy = parse_dns_cache_key(black_box("example.com.1")).expect("legacy dns key");
            black_box(
                key.qname.len() as u64
                    ^ structured.qtype as u64
                    ^ structured.qclass as u64
                    ^ legacy.qtype as u64,
            )
        },
        iters,
        warmup,
    ))
}

fn bench_dns_cache_ttl_lookup(iters: u64, warmup: u64) -> Result<Measurement, String> {
    const NOW: i64 = 1_700_000_000;
    Ok(measure(
        || {
            let live_key = DnsCacheKey::new("live.example.", 1, 1);
            let client_expired_key = DnsCacheKey::new("client-expired.example.", 1, 1);
            let expired_key = DnsCacheKey::new("expired.example.", 1, 1);
            let mut store = DnsCacheStore::new(8);
            store.insert(
                NOW,
                live_key.clone(),
                DnsCacheEntry::new(NOW + 60, NOW + 60),
            );
            store.insert(
                NOW,
                client_expired_key.clone(),
                DnsCacheEntry::new(NOW - 60, NOW + 60),
            );
            store.insert(
                NOW,
                expired_key.clone(),
                DnsCacheEntry::new(NOW - 60, NOW - 60),
            );

            let mut checksum = 0_u64;
            checksum ^= store.lookup(NOW, black_box(&live_key), false).is_some() as u64;
            checksum ^= (store
                .lookup(NOW, black_box(&client_expired_key), false)
                .is_none() as u64)
                << 1;
            checksum ^= (store
                .lookup(NOW, black_box(&client_expired_key), true)
                .is_some() as u64)
                << 2;
            checksum ^= (store.lookup(NOW, black_box(&expired_key), false).is_none() as u64) << 3;
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
                match validate_dns_response_for_request(
                    black_box(&req),
                    Some(black_box(response)),
                    black_box(require_id),
                ) {
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
