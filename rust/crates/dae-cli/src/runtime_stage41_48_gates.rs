use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use dae_ebpf_support::{
    DAE_PARAM_SYMBOL, DAE_PARAM_SYMBOL_SIZE, DaeParamInput, build_dae_param,
    build_dae_param_payload, locate_param_symbol_in_object, read_param_from_object,
    write_param_aware_object,
};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

mod stage41;
mod stage42;
mod static_reports;
mod utils;

use stage41::{Stage41Options, stage41_report};
use stage42::{Stage42Options, stage42_report};
use static_reports::{
    stage43_report, stage44_report, stage45_report, stage46_report, stage47_report, stage48_report,
};

const DEFAULT_SOURCE_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE41_OUTPUT: &str = "/tmp/dae-stage41-candidate/bpf_bpfel.param.o";
const DEFAULT_STAGE42_ROOT: &str = "/tmp/dae-stage42-candidate";
const DEFAULT_STAGE42_IFACE: &str = "dae42p0";
const DEFAULT_STAGE42_SECTION: &str = "tc/dae0_ingress";
const STAGE42_FILTER_PREF: &str = "49420";

const DEFAULT_TPROXY_PORT: u16 = 12345;
const DEFAULT_CONTROL_PLANE_PID: u32 = 77;
const DEFAULT_DAE0_IFINDEX: u32 = 8;
const DEFAULT_DAE_NETNS_ID: u32 = 9;
const DEFAULT_DAE0PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 41];

pub(crate) fn run_stage41_param_object_image_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage41Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage41_report(&opts);
    output_with_required_admission(
        report,
        opts.require_admission,
        "param_object_image_admitted",
    )
}

pub(crate) fn run_stage42_param_object_load_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage42Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage42_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "param_object_tc_attach_smoke_passed",
    )
}

pub(crate) fn run_stage43_production_param_listener_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage43_report())
}

pub(crate) fn run_stage44_active_tcp_tproxy_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage44_report())
}

pub(crate) fn run_stage45_active_udp_tproxy_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage45_report())
}

pub(crate) fn run_stage46_active_dns_tproxy_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage46_report())
}

pub(crate) fn run_stage47_outbound_true_dataplane_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage47_report())
}

pub(crate) fn run_stage48_true_daemon_benchmark_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage48_report())
}

fn output_with_required_admission(
    report: Value,
    require_admission: bool,
    pass_key: &str,
) -> RunnerOutput {
    let passed = report[pass_key].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if require_admission && !passed {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
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

fn static_report_command(args: &[String], report: Value) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported runtime stage41-48 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{report}\n"))
}

#[derive(Debug, Clone)]
struct ParamOptions {
    tproxy_port: u16,
    control_plane_pid: u32,
    dae0_ifindex: u32,
    dae_netns_id: u32,
    dae0peer_mac: [u8; 6],
    has_bpf_get_current_task: bool,
}

impl Default for ParamOptions {
    fn default() -> Self {
        Self {
            tproxy_port: DEFAULT_TPROXY_PORT,
            control_plane_pid: DEFAULT_CONTROL_PLANE_PID,
            dae0_ifindex: DEFAULT_DAE0_IFINDEX,
            dae_netns_id: DEFAULT_DAE_NETNS_ID,
            dae0peer_mac: DEFAULT_DAE0PEER_MAC,
            has_bpf_get_current_task: true,
        }
    }
}

impl ParamOptions {
    fn input(&self) -> DaeParamInput {
        DaeParamInput {
            tproxy_port: self.tproxy_port,
            control_plane_pid: self.control_plane_pid,
            dae0_ifindex: self.dae0_ifindex,
            dae_netns_id: self.dae_netns_id,
            dae0peer_mac: self.dae0peer_mac,
            has_bpf_get_current_task: self.has_bpf_get_current_task,
        }
    }
}
