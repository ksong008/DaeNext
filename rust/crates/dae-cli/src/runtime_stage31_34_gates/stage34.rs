use super::utils::*;
use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage34Options {
    rust_micro_benchmarks_recorded: bool,
}

impl Stage34Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            rust_micro_benchmarks_recorded: false,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--rust-micro-benchmarks-recorded" => opts.rust_micro_benchmarks_recorded = true,
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage34-benchmark-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

pub(super) fn stage34_report(opts: &Stage34Options) -> Value {
    json!({
        "name": "stage34-benchmark-product-chain-admission",
        "stage": "stage34",
        "evidence_class": "benchmark-and-product-chain-default-switch-gate",
        "stage_complete": true,
        "rust_micro_benchmarks_recorded": opts.rust_micro_benchmarks_recorded,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "clean_product_chain_recertification_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "rust_micro_benchmark_contract": {
            "udp_endpoint_trim_4096": udp_endpoint_pool_trim_target(4096),
            "magic_network_mark_mptcp_required": true,
            "domain_routing_owner_merge_required": true
        },
        "benchmark_matrix": [
            {
                "name": "rust-datapath-stage7-micro",
                "command": "DAE_STAGE7_BENCH_ITERS=10000 cargo run --manifest-path rust/Cargo.toml -p dae-datapath --release --example stage7_datapath_bench",
                "records_magic_network_mark_mptcp": true,
                "records_udp_trim": true,
                "matched_go_baseline": false
            },
            {
                "name": "rust-control-stage7-micro",
                "command": "DAE_STAGE7_BENCH_ITERS=10000 cargo run --manifest-path rust/Cargo.toml -p dae-control --release --example stage7_control_bench",
                "records_domain_routing_owner_merge": true,
                "matched_go_baseline": false
            },
            {
                "name": "matched-go-default-vs-rust-candidate-daemon",
                "command": "deferred until true Rust live candidate and active datapath are admitted",
                "matched_go_baseline": true,
                "required_before_default_switch": true
            }
        ],
        "product_chain_requirements": [
            "clean /root/project/dae-wing recertification",
            "clean /root/project/daed recertification",
            "systemd/install/release default path review",
            "rollback to Go-backed daemon verified"
        ],
        "remaining_blockers": remaining_blockers(),
    })
}
