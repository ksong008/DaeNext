use std::hint::black_box;
use std::time::Instant;

use dae_outbound::{
    Annotation, Dialer, DialerGroup, DialerSet, Filter, FilterParam, NetworkType, SelectionPolicy,
};

fn main() {
    let iters = std::env::var("DAE_LINK_PARSER_COMPATIBILITY_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100_000);

    let filter_set = DialerSet {
        dialers: (0..1000)
            .map(|index| Dialer::new(format!("bench-node-{index:04}"), "bench-sub"))
            .collect(),
    };
    let filters = vec![vec![
        Filter::new("name", vec![FilterParam::new("regex", "^bench-node-")]),
        Filter::new("subtag", vec![FilterParam::new("regex", "^bench-")]),
    ]];
    let annotations = vec![Annotation::default()];
    bench("outbound_filter_regex_1000", iters.min(10_000), || {
        black_box(
            filter_set
                .filter_and_annotate(black_box(&filters), black_box(&annotations))
                .unwrap(),
        );
    });

    let mut group = DialerGroup::new(
        "bench",
        (0..4)
            .map(|index| Dialer::new(format!("dialer{index}"), ""))
            .collect(),
        vec![Annotation::default(); 4],
        SelectionPolicy::MinLastLatency,
        false,
        0,
    );
    for (index, latency) in [200, 100, 300, 150].into_iter().enumerate() {
        group.set_last_latency(index, NetworkType::TCP4, latency);
        group.notify_alive(index, NetworkType::TCP4, true);
    }
    bench("outbound_group_select_min", iters, || {
        black_box(
            group
                .select(black_box(NetworkType::TCP4), black_box(false))
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
