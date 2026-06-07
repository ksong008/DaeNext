use std::hint::black_box;
use std::time::Instant;

use dae_outbound::anytls::{AnyTLSLink, contract, link};

fn main() {
    let iters = std::env::var("DAE_ANYTLS_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let raw = "anytls://auth@example.com:443?insecure=1&sni=sni.example#basic";
    bench("anytls_parse_link", iters, || {
        let _ = AnyTLSLink::parse(black_box(raw)).unwrap();
    });
    bench("anytls_auth_key", iters, || {
        let _ = link::auth_key(black_box("auth"));
    });
    let settings = link::settings_bytes();
    bench("anytls_frame", iters, || {
        let _ = link::frame(
            black_box(contract::CMD_SETTINGS),
            black_box(1),
            black_box(&settings),
        );
    });
    bench("anytls_underlay_contract", iters, || {
        let _ = link::underlay_contract(black_box("udp"), black_box(1234), black_box(true));
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
