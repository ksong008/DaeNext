use std::hint::black_box;
use std::time::Instant;

use dae_sysdump::{protocol_to_string, route_type_to_string, scope_to_string};

fn main() {
    let iters = std::env::var("DAE_STAGE8_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000_000);

    bench("sysdump_enum_strings", iters, || {
        black_box(scope_to_string(black_box(253)));
        black_box(protocol_to_string(black_box(4)));
        black_box(route_type_to_string(black_box(1)));
    });
}

fn bench(name: &str, iters: u64, mut f: impl FnMut()) {
    for _ in 0..100 {
        f();
    }
    let started = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns_per_op = started.elapsed().as_nanos() as f64 / iters as f64;
    println!("{name}\t{ns_per_op:.1} ns/op\t{iters} iters");
}
