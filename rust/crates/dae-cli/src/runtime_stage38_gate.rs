use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_ebpf_support::{map_ids, run_loaded_listen_socket_map_fd_smoke};
use serde_json::{Value, json};

mod report;
mod smoke;
mod utils;

use report::stage38_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_STAGE38_ROOT: &str = "/tmp/dae-stage38-candidate";
const DEFAULT_STAGE38_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE38_PEER_SECTION: &str = "tc/dae0peer_ingress";
const DEFAULT_STAGE38_HOST_SECTION: &str = "tc/dae0_ingress";
const STAGE38_FILTER_PREF: &str = "49380";
const PRODUCTION_NETNS: &str = "daens";
const PRODUCTION_HOST_IFACE: &str = "dae0";
const PRODUCTION_PEER_IFACE: &str = "dae0peer";
const LISTEN_SOCKET_MAP_KERNEL_NAME: &str = "listen_socket_m";

pub(crate) fn run_stage38_production_dae_attach_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage38Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage38_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "production_name_attach_handoff_smoke_passed",
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
struct Stage38Options {
    root: PathBuf,
    stage37_report: Option<PathBuf>,
    execute_smoke: bool,
    ack_root_gate: bool,
    object_path: PathBuf,
    peer_section: String,
    host_section: String,
}

impl Default for Stage38Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_STAGE38_ROOT),
            stage37_report: None,
            execute_smoke: false,
            ack_root_gate: false,
            object_path: PathBuf::from(DEFAULT_STAGE38_OBJECT),
            peer_section: DEFAULT_STAGE38_PEER_SECTION.to_owned(),
            host_section: DEFAULT_STAGE38_HOST_SECTION.to_owned(),
        }
    }
}

impl Stage38Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => opts.root = PathBuf::from(next_value(&mut iter, "stage38 --root")?),
                "--stage37-report" => {
                    opts.stage37_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage38 --stage37-report",
                    )?));
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--object" => {
                    opts.object_path = PathBuf::from(next_value(&mut iter, "stage38 --object")?);
                }
                "--peer-section" => {
                    opts.peer_section = next_value(&mut iter, "stage38 --peer-section")?;
                }
                "--host-section" => {
                    opts.host_section = next_value(&mut iter, "stage38 --host-section")?;
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage38 --root")?);
                }
                _ if arg.starts_with("--stage37-report=") => {
                    opts.stage37_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage38 --stage37-report",
                    )?));
                }
                _ if arg.starts_with("--object=") => {
                    opts.object_path = PathBuf::from(value_after_equals(arg, "stage38 --object")?);
                }
                _ if arg.starts_with("--peer-section=") => {
                    opts.peer_section = value_after_equals(arg, "stage38 --peer-section")?;
                }
                _ if arg.starts_with("--host-section=") => {
                    opts.host_section = value_after_equals(arg, "stage38 --host-section")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage38-production-dae-attach-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}
