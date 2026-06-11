use std::hint::black_box;
use std::time::Instant;

use dae_dns::{
    DnsCacheEntry, DnsCacheKey, DnsCacheStore, build_doh_request, dns_data_with_zero_id,
    validate_dns_packet_response_for_request,
};

fn main() {
    let iters = std::env::var("DNS_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100_000);

    bench("dns_cache_key", iters, || {
        black_box(DnsCacheKey::new(
            black_box("Example.COM"),
            black_box(1),
            black_box(1),
        ));
    });

    let mut store = DnsCacheStore::new(8);
    let key = DnsCacheKey::new("example.com.", 1, 1);
    store.insert(0, key.clone(), DnsCacheEntry::new(60, 60));
    bench("dns_cache_lookup", iters, || {
        black_box(
            store
                .lookup(black_box(30), black_box(&key), black_box(false))
                .unwrap(),
        );
    });

    let req = [
        0x11, 0x11, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let resp = [
        0x11, 0x11, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    bench("dns_validate_response", iters, || {
        black_box(
            validate_dns_packet_response_for_request(
                black_box(&req),
                black_box(Some(resp.as_slice())),
                black_box(true),
            )
            .unwrap(),
        );
    });

    let payload = [0x12, 0x34, 0x56, 0x78];
    bench("dns_zero_id", iters, || {
        black_box(dns_data_with_zero_id(black_box(&payload)));
    });

    bench("dns_doh_get_request", iters, || {
        black_box(
            build_doh_request(
                black_box("1.1.1.1:443"),
                black_box("dns.example.com"),
                black_box("/dns-query"),
                black_box(&payload),
            )
            .unwrap(),
        );
    });
}

fn bench(name: &str, iters: u64, mut f: impl FnMut()) {
    for _ in 0..100 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    println!("{name}\t{ns_per_op:.1} ns/op\t{iters} iters");
}
