use std::hint::black_box;

use dae_daemon::{
    daemon_runtime_native_owner_summary_json, datapath_outbound_ebpf_deep_area_summary_json,
};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "daemon/runtime_native_owner_summary",
            default_iters: 100_000,
            run: bench_daemon_runtime_native_owner_summary,
        },
        BenchCase {
            id: "daemon/datapath_outbound_ebpf_summary",
            default_iters: 100_000,
            run: bench_datapath_outbound_ebpf_summary,
        },
    ]
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

fn bench_datapath_outbound_ebpf_summary(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let summary = datapath_outbound_ebpf_deep_area_summary_json();
            let surfaces = summary["surfaces"].as_array().expect("deep area surfaces");
            let blockers = summary["final_native_admission_blockers"]
                .as_array()
                .expect("deep area final native admission blockers");
            black_box(surfaces.len() as u64 ^ ((blockers.len() as u64) << 8))
        },
        iters,
        warmup,
    ))
}
