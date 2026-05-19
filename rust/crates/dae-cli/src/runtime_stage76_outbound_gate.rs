use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::{shared_transport, vless};
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage76_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_TARGET: &str = "stage76-vless-grpc.example:443";
const DEFAULT_GRPC_ADDRESS: &str = "stage76-vless-grpc-proxy.example:443";
const DEFAULT_GRPC_SERVICE_NAME: &str = "dae-stage76-grpc";
const DEFAULT_GRPC_SERVER_NAME: &str = "stage76-vless-grpc-sni.example";
const DEFAULT_GRPC_DIALER_ID: &str = "stage76-vless-grpc-dialer";
const DEFAULT_PAYLOAD: &[u8] = b"stage76-vless-grpc-ping";

pub(crate) fn run_stage76_vless_grpc_hunk_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage76Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage76_report(&opts);
    let passed = report["vless_grpc_hunk_smoke_passed"]
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
struct Stage76Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    uuid: String,
    target: String,
    grpc_address: String,
    grpc_service_name: String,
    grpc_server_name: String,
    grpc_dialer_id: String,
    allow_insecure: bool,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage76Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            grpc_address: DEFAULT_GRPC_ADDRESS.to_owned(),
            grpc_service_name: DEFAULT_GRPC_SERVICE_NAME.to_owned(),
            grpc_server_name: DEFAULT_GRPC_SERVER_NAME.to_owned(),
            grpc_dialer_id: DEFAULT_GRPC_DIALER_ID.to_owned(),
            allow_insecure: true,
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage76Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage76 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage76 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage76 --target")?,
                "--grpc-address" => {
                    opts.grpc_address = next_value(&mut iter, "stage76 --grpc-address")?
                }
                "--grpc-service-name" => {
                    opts.grpc_service_name = next_value(&mut iter, "stage76 --grpc-service-name")?
                }
                "--grpc-server-name" => {
                    opts.grpc_server_name = next_value(&mut iter, "stage76 --grpc-server-name")?
                }
                "--grpc-dialer-id" => {
                    opts.grpc_dialer_id = next_value(&mut iter, "stage76 --grpc-dialer-id")?
                }
                "--allow-insecure" => opts.allow_insecure = true,
                "--no-allow-insecure" => opts.allow_insecure = false,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage76 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage76 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage76 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--uuid=") => {
                    opts.uuid = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
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
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(arg.split_once('=').unwrap().1, "--so-mark")?;
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    let timeout_ms = parse_u64(arg.split_once('=').unwrap().1, "--timeout-ms")?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage76 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage76 --benchmark-iters must be greater than zero",
            ));
        }
        vless::password_to_key(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage76 uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage76 target is invalid: {err}")))?;
        if opts.grpc_address.is_empty() {
            return Err(RunnerOutput::usage(
                "stage76 --grpc-address must not be empty",
            ));
        }
        if opts.grpc_service_name.is_empty() {
            opts.grpc_service_name = "GunService".to_owned();
        }
        if opts.grpc_server_name.is_empty() {
            return Err(RunnerOutput::usage(
                "stage76 --grpc-server-name must not be empty",
            ));
        }
        if opts.grpc_dialer_id.is_empty() {
            return Err(RunnerOutput::usage(
                "stage76 --grpc-dialer-id must not be empty",
            ));
        }
        Ok(opts)
    }

    fn grpc_options(&self, address: &str) -> shared_transport::GrpcLifecycleOptions {
        shared_transport::GrpcLifecycleOptions::new(
            address,
            &self.grpc_service_name,
            &self.grpc_server_name,
            &self.grpc_dialer_id,
            self.allow_insecure,
            self.so_mark,
            self.mptcp,
        )
    }
}
