use std::hint::black_box;

use dae_daemon::daemon_runtime_native_owner_summary_json;

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![BenchCase {
        id: "daemon/runtime_native_owner_summary",
        default_iters: 100_000,
        run: bench_daemon_runtime_native_owner_summary,
    }]
}

fn bench_daemon_runtime_native_owner_summary(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let summary = daemon_runtime_native_owner_summary_json();
            let groups = summary["accepted_native_groups"]
                .as_array()
                .expect("accepted native groups");
            let blockers = summary["runtime_owner_blockers"]
                .as_array()
                .expect("runtime owner blockers");
            black_box(groups.len() as u64 ^ ((blockers.len() as u64) << 8))
        },
        iters,
        warmup,
    ))
}
