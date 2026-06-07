use std::hint::black_box;
use std::time::Instant;

use dae_outbound::hysteria2::{Hysteria2Link, link};

fn main() {
    let iters = std::env::var("DAE_HYSTERIA2_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let raw = "hy2://user:pass@example.com:443,8443-8445?insecure=true&sni=hop.example&pinSHA256=AA-BB:CC&maxTx=4096&maxRx=8192#hop";
    bench("hysteria2_parse_link", iters, || {
        let _ = Hysteria2Link::parse(black_box(raw)).unwrap();
    });
    let parsed = Hysteria2Link::parse(raw).unwrap();
    bench("hysteria2_export_link", iters, || {
        let _ = black_box(&parsed).export_url();
    });
    bench("hysteria2_pin_normalize", iters, || {
        let _ = link::normalize_pin_sha256(black_box("AA-BB:CC"));
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
