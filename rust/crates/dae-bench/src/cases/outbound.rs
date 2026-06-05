use std::hint::black_box;

use dae_outbound::{
    Annotation, Dialer, DialerGroup, DialerSet, Filter, FilterParam, NetworkType, SelectionPolicy,
};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "outbound/select_min_latency",
            default_iters: 100_000,
            run: bench_outbound_select_min_latency,
        },
        BenchCase {
            id: "outbound/filter_annotate_regex",
            default_iters: 1_000,
            run: bench_outbound_filter_annotate_regex,
        },
    ]
}

fn bench_outbound_select_min_latency(iters: u64, warmup: u64) -> Result<Measurement, String> {
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
    Ok(measure(
        || {
            let selected = group
                .select(black_box(NetworkType::TCP4), black_box(false))
                .expect("select min latency");
            black_box(selected.index as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_outbound_filter_annotate_regex(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let set = DialerSet {
        dialers: (0..1000)
            .map(|index| Dialer::new(format!("bench-node-{index:04}"), "bench-sub"))
            .collect(),
    };
    let filters = vec![vec![
        Filter::new("name", vec![FilterParam::new("regex", "^bench-node-")]),
        Filter::new("subtag", vec![FilterParam::new("regex", "^bench-")]),
    ]];
    let annotations = vec![Annotation::default()];

    Ok(measure(
        || {
            let matched = set
                .filter_and_annotate(black_box(&filters), black_box(&annotations))
                .expect("filter and annotate");
            black_box(matched.len() as u64 ^ matched[0].index as u64)
        },
        iters,
        warmup,
    ))
}
