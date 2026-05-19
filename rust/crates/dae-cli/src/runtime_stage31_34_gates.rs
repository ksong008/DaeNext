use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_control::{CoreFlip, DomainRoutingOwnerSnapshot, DomainRoutingTracker, ReloadCoreState};
use dae_datapath::{magic_network_bytes, udp_endpoint_pool_trim_target};
use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore};
use dae_ebpf_support::{DaeParamInput, build_dae_param, map_catalog, pinned_reuse_maps};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

mod stage31;
mod stage32;
mod stage33;
mod stage34;
mod utils;

use stage31::{Stage31Options, stage31_report};
use stage32::{Stage32Options, stage32_report};
use stage33::stage33_report;
use stage34::{Stage34Options, stage34_report};

const DEFAULT_STAGE31_ROOT: &str = "/tmp/dae-stage31-candidate";
const DEFAULT_STAGE31_NETNS: &str = "dae-stage31-ns";
const DEFAULT_STAGE31_HOST_IFACE: &str = "dae31h0";
const DEFAULT_STAGE31_PEER_IFACE: &str = "dae31p0";
const STAGE31_FILTER_PREF: &str = "49152";

pub(crate) fn run_stage31_ebpf_attach_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage31Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage31_report(&opts);
    output_with_execution_status(report, opts.execute_smoke, "filter_cleanup_smoke_passed")
}

pub(crate) fn run_stage32_active_traffic_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage32Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage32_report(&opts);
    output_with_execution_status(report, opts.execute_smoke, "local_traffic_harness_passed")
}

pub(crate) fn run_stage33_reload_rollback_admission(args: &[String]) -> RunnerOutput {
    if !args.is_empty() {
        return RunnerOutput::usage(format!(
            "unsupported runtime stage33-reload-rollback-admission argument: {}",
            args[0]
        ));
    }
    RunnerOutput::ok(format!("{}\n", stage33_report()))
}

pub(crate) fn run_stage34_benchmark_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage34Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    RunnerOutput::ok(format!("{}\n", stage34_report(&opts)))
}

fn output_with_execution_status(report: Value, executed: bool, pass_key: &str) -> RunnerOutput {
    let passed = report[pass_key].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if executed && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}
