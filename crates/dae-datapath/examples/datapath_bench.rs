use std::time::Instant;

use dae_dataline_bench::{bench_magic_network, bench_udp_trim};

mod dae_dataline_bench {
    use dae_datapath::{magic_network, udp_endpoint_pool_trim_target};
    use dae_ebpf_support::TPROXY_MARK;

    pub fn bench_magic_network(iters: u64) {
        let started = std::time::Instant::now();
        for _ in 0..iters {
            let _ = magic_network("tcp", TPROXY_MARK, true);
        }
        let ns_per_op = started.elapsed().as_nanos() as f64 / iters as f64;
        println!("case_magic_network_mark_mptcp_ns_per_op={ns_per_op:.1}");
    }

    pub fn bench_udp_trim(iters: u64) {
        let started = std::time::Instant::now();
        for _ in 0..iters {
            let _ = udp_endpoint_pool_trim_target(4096);
        }
        let ns_per_op = started.elapsed().as_nanos() as f64 / iters as f64;
        println!("case_udp_endpoint_trim_target_ns_per_op={ns_per_op:.1}");
    }
}

fn main() {
    let iters = std::env::var("DAE_STAGE7_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000_000);
    let total = Instant::now();
    bench_magic_network(iters);
    bench_udp_trim(iters);
    eprintln!(
        "case_datapath_bench_elapsed_ms={}",
        total.elapsed().as_millis()
    );
}
