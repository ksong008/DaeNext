use std::hint::black_box;
use std::time::Instant;

use dae_outbound::tuic::{TuicLink, link};

fn main() {
    let iters = std::env::var("DAE_TUIC_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let raw = "tuic://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&alpn=h3,h2&udp_relay_mode=quic#basic";
    bench("tuic_parse_link", iters, || {
        let _ = TuicLink::parse(black_box(raw)).unwrap();
    });
    let parsed = TuicLink::parse(raw).unwrap();
    bench("tuic_export_link", iters, || {
        let _ = black_box(&parsed).export_url();
    });
    bench("tuic_alpn_split", iters, || {
        let _ = link::split_alpn(black_box("h3,h2,http/1.1"));
    });
    bench("tuic_underlay_contract", iters, || {
        let _ = link::underlay_contract(black_box("tcp"), black_box(1234), black_box(true));
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
