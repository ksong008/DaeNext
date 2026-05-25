use std::hint::black_box;

use dae_sysdump::{protocol_to_string, route_type_to_string, scope_to_string};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![BenchCase {
        id: "sysdump/enum_strings",
        default_iters: 100_000,
        run: bench_sysdump_enum_strings,
    }]
}

fn bench_sysdump_enum_strings(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let scope = scope_to_string(black_box(253));
            let protocol = protocol_to_string(black_box(4));
            let route_type = route_type_to_string(black_box(1));
            black_box((scope.len() ^ protocol.len() ^ route_type.len()) as u64)
        },
        iters,
        warmup,
    ))
}
