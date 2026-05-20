use std::time::Instant;

use dae_outbound::shared_transport;
use serde_json::{Value, json};

mod report;
mod utils;

use report::stage98_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_GRPC_ADDRESS: &str = "stage98-trojan-go-grpc-cache.example:443";
const DEFAULT_GRPC_SERVICE_NAME: &str = "GunService";
const DEFAULT_GRPC_SERVER_NAME: &str = "stage98-trojan-go-grpc-cache-sni.example";
const DEFAULT_GRPC_DIALER_ID: &str = "stage98-trojan-go-grpc-cache-dialer";

pub(crate) fn run_stage98_trojan_go_grpc_cache_cancellation_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage98Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage98_report(&opts);
    let passed = report["trojan_go_grpc_cache_cancellation_stress_passed"]
        .as_bool()
        .unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage98Options {
    execute_smoke: bool,
    benchmark_iters: usize,
    grpc_address: String,
    grpc_service_name: String,
    grpc_server_name: String,
    grpc_dialer_id: String,
    allow_insecure: bool,
    so_mark: u32,
    mptcp: bool,
}

impl Default for Stage98Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            benchmark_iters: 1,
            grpc_address: DEFAULT_GRPC_ADDRESS.to_owned(),
            grpc_service_name: DEFAULT_GRPC_SERVICE_NAME.to_owned(),
            grpc_server_name: DEFAULT_GRPC_SERVER_NAME.to_owned(),
            grpc_dialer_id: DEFAULT_GRPC_DIALER_ID.to_owned(),
            allow_insecure: true,
            so_mark: 1234,
            mptcp: true,
        }
    }
}

impl Stage98Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" | "--execute-stress" => opts.execute_smoke = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage98 --benchmark-iters")?, arg)?;
                }
                "--grpc-address" => {
                    opts.grpc_address = next_value(&mut iter, "stage98 --grpc-address")?
                }
                "--grpc-service-name" => {
                    opts.grpc_service_name = next_value(&mut iter, "stage98 --grpc-service-name")?
                }
                "--grpc-server-name" => {
                    opts.grpc_server_name = next_value(&mut iter, "stage98 --grpc-server-name")?
                }
                "--grpc-dialer-id" => {
                    opts.grpc_dialer_id = next_value(&mut iter, "stage98 --grpc-dialer-id")?
                }
                "--allow-insecure" => opts.allow_insecure = true,
                "--no-allow-insecure" => opts.allow_insecure = false,
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage98 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--grpc-address=") => {
                    opts.grpc_address = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--grpc-service-name=") => {
                    opts.grpc_service_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--grpc-server-name=") => {
                    opts.grpc_server_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--grpc-dialer-id=") => {
                    opts.grpc_dialer_id = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(arg.split_once('=').unwrap().1, "--so-mark")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage98 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage98 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.grpc_address.is_empty() {
            return Err(RunnerOutput::usage(
                "stage98 --grpc-address must not be empty",
            ));
        }
        if opts.grpc_server_name.is_empty() {
            return Err(RunnerOutput::usage(
                "stage98 --grpc-server-name must not be empty",
            ));
        }
        if opts.grpc_dialer_id.is_empty() {
            return Err(RunnerOutput::usage(
                "stage98 --grpc-dialer-id must not be empty",
            ));
        }
        Ok(opts)
    }

    fn grpc_options(&self) -> shared_transport::GrpcLifecycleOptions {
        shared_transport::GrpcLifecycleOptions::new(
            &self.grpc_address,
            &self.grpc_service_name,
            &self.grpc_server_name,
            &self.grpc_dialer_id,
            self.allow_insecure,
            self.so_mark,
            self.mptcp,
        )
    }
}
