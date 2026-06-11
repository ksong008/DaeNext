use std::hint::black_box;

use dae_trace::{SkbTraceTracker, TraceEventRecord, parse_ringbuf_size_bytes};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "trace/ringbuf_parse",
            default_iters: 100_000,
            run: bench_trace_ringbuf_parse,
        },
        BenchCase {
            id: "trace/tracker_add",
            default_iters: 100_000,
            run: bench_trace_tracker_add,
        },
    ]
}

fn bench_trace_ringbuf_parse(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let size = parse_ringbuf_size_bytes(black_box("64MiB")).expect("ringbuf parse");
            black_box(size)
        },
        iters,
        warmup,
    ))
}

fn bench_trace_tracker_add(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let mut tracker = SkbTraceTracker::new();
    Ok(measure(
        || {
            let next = tracker.tracked_count() as u64;
            tracker.add(
                TraceEventRecord::for_skb(black_box(next % 4096)),
                black_box("sym"),
            );
            black_box(tracker.tracked_count() as u64)
        },
        iters,
        warmup,
    ))
}
