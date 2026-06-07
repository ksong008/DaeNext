use std::hint::black_box;
use std::time::Instant;

use dae_outbound::juicity::{JuicityLink, link};

fn main() {
    let iters = std::env::var("DAE_JUICITY_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let raw = "juicity://7c12c745-63a5-433d-9e60-022e469b5bd4:pass@example.com:443?congestion_control=bbr&pinned_certchain_sha256=-__--u_uq80BI0VniavN7_v__vrv7qvNASNFZ4mrze8%3D#basic";
    bench("juicity_parse_link", iters, || {
        let _ = JuicityLink::parse(black_box(raw)).unwrap();
    });
    let parsed = JuicityLink::parse(raw).unwrap();
    bench("juicity_export_link", iters, || {
        let _ = black_box(&parsed).export_url();
    });
    bench("juicity_pinned_decode", iters, || {
        let _ = link::decode_pinned_certchain(black_box(&parsed.pinned_certchain_sha256)).unwrap();
    });
    bench("juicity_underlay_contract", iters, || {
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
