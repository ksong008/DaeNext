use std::hint::black_box;
use std::time::Instant;

use dae_trace::{SkbTraceTracker, TraceEventRecord, parse_ringbuf_size_bytes};

fn main() {
    let iters = std::env::var("TRACE_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000_000);

    bench("trace_ringbuf_parse", iters, |_| {
        black_box(parse_ringbuf_size_bytes(black_box("64MiB")).unwrap());
    });

    let mut tracker = SkbTraceTracker::new();
    bench("trace_tracker_add", iters, |i| {
        let skb = black_box(i % 4096);
        tracker.add(TraceEventRecord::with_payload(skb, 128), black_box("sym"));
    });
}

fn bench(name: &str, iters: u64, mut f: impl FnMut(u64)) {
    for i in 0..100 {
        f(i);
    }
    let started = Instant::now();
    for i in 0..iters {
        f(i);
    }
    let ns_per_op = started.elapsed().as_nanos() as f64 / iters as f64;
    println!("{name}\t{ns_per_op:.1} ns/op\t{iters} iters");
}
