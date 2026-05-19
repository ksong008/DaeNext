use std::env;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_ebpf_support::{
    DaeParamInput, build_dae_param, map_ids, run_loaded_tproxy_listen_socket_map_fd_smoke,
    write_param_aware_object,
};
use serde_json::{Map, Value, json};

use crate::runner::RunnerOutput;

mod report;
mod smoke;
mod utils;

use report::stage49_report;
use utils::*;

const DEFAULT_STAGE49_ROOT: &str = "/tmp/dae-stage49-candidate";
const DEFAULT_STAGE49_SOURCE_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE49_PEER_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_STAGE49_HOST_SECTION: &str = "tc/dae0_ingress";
const DEFAULT_STAGE49_TPROXY_PORT: u16 = 12345;
const DEFAULT_STAGE49_DAE_NETNS_ID: u32 = 49;
const STAGE49_FILTER_PREF: &str = "49490";
const PRODUCTION_NETNS: &str = "daens";
const PRODUCTION_HOST_IFACE: &str = "dae0";
const PRODUCTION_PEER_IFACE: &str = "dae0peer";
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";

pub(crate) fn run_stage49_production_param_listener_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage49Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage49_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "combined_production_param_listener_smoke_passed",
    )
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

#[derive(Debug, Clone)]
struct Stage49Options {
    root: PathBuf,
    source_object: PathBuf,
    param_object: PathBuf,
    execute_smoke: bool,
    ack_root_gate: bool,
    peer_section: String,
    host_section: String,
    tproxy_port: u16,
    dae_netns_id: u32,
    has_bpf_get_current_task: bool,
}

impl Default for Stage49Options {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_STAGE49_ROOT);
        Self {
            param_object: root.join("bpf_bpfel.param.o"),
            root,
            source_object: PathBuf::from(DEFAULT_STAGE49_SOURCE_OBJECT),
            execute_smoke: false,
            ack_root_gate: false,
            peer_section: DEFAULT_STAGE49_PEER_SECTION.to_owned(),
            host_section: DEFAULT_STAGE49_HOST_SECTION.to_owned(),
            tproxy_port: DEFAULT_STAGE49_TPROXY_PORT,
            dae_netns_id: DEFAULT_STAGE49_DAE_NETNS_ID,
            has_bpf_get_current_task: true,
        }
    }
}

impl Stage49Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => {
                    opts.root = PathBuf::from(next_value(&mut iter, "stage49 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE49_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                "--object" => {
                    opts.source_object = PathBuf::from(next_value(&mut iter, "stage49 --object")?);
                }
                "--param-object" => {
                    opts.param_object =
                        PathBuf::from(next_value(&mut iter, "stage49 --param-object")?);
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--peer-section" => {
                    opts.peer_section = next_value(&mut iter, "stage49 --peer-section")?;
                }
                "--host-section" => {
                    opts.host_section = next_value(&mut iter, "stage49 --host-section")?;
                }
                "--tproxy-port" => {
                    opts.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage49 --tproxy-port")?)?;
                }
                "--dae-netns-id" => {
                    opts.dae_netns_id =
                        parse_u32(&next_value(&mut iter, "stage49 --dae-netns-id")?)?;
                }
                "--has-bpf-get-current-task" => opts.has_bpf_get_current_task = true,
                "--no-bpf-get-current-task" => opts.has_bpf_get_current_task = false,
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage49 --root")?);
                    if opts.param_object
                        == PathBuf::from(DEFAULT_STAGE49_ROOT).join("bpf_bpfel.param.o")
                    {
                        opts.param_object = opts.root.join("bpf_bpfel.param.o");
                    }
                }
                _ if arg.starts_with("--object=") => {
                    opts.source_object =
                        PathBuf::from(value_after_equals(arg, "stage49 --object")?);
                }
                _ if arg.starts_with("--param-object=") => {
                    opts.param_object =
                        PathBuf::from(value_after_equals(arg, "stage49 --param-object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.peer_section = value_after_equals(arg, "stage49 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.host_section = value_after_equals(arg, "stage49 --host-section")?;
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage49 --tproxy-port")?)?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.dae_netns_id =
                        parse_u32(&value_after_equals(arg, "stage49 --dae-netns-id")?)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage49-production-param-listener-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}
