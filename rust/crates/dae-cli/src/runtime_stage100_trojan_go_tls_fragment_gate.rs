use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::shared_transport;
use dae_outbound::trojan;
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage100_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_PASSWORD: &str = "stage100-password";
const DEFAULT_TARGET: &str = "stage100-trojan-go.example:443";
const DEFAULT_TLS_SERVER_NAME: &str = "stage100-trojan-go-fragment.example";
const DEFAULT_WS_HOST: &str = "stage100-fragment-ws-host.example";
const DEFAULT_WS_PATH: &str = "/trojan-go-fragment";
const DEFAULT_PAYLOAD: &[u8] = b"stage100-trojan-go-tls-fragment-ping";
const DEFAULT_FRAGMENT_LENGTH: &str = "64-64";
const DEFAULT_FRAGMENT_INTERVAL: &str = "0-0";

pub(crate) fn run_stage100_trojan_go_tls_fragment_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage100Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage100_report(&opts);
    let passed = report["trojan_go_tls_fragment_smoke_passed"]
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
struct Stage100Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    password: String,
    target: String,
    tls_server_name: String,
    alpn_protocol: String,
    ws_host: String,
    ws_path: String,
    payload: Vec<u8>,
    fragment_length: String,
    fragment_interval: String,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage100Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            password: DEFAULT_PASSWORD.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            tls_server_name: DEFAULT_TLS_SERVER_NAME.to_owned(),
            alpn_protocol: shared_transport::DEFAULT_TLS_ALPN.to_owned(),
            ws_host: DEFAULT_WS_HOST.to_owned(),
            ws_path: DEFAULT_WS_PATH.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            fragment_length: DEFAULT_FRAGMENT_LENGTH.to_owned(),
            fragment_interval: DEFAULT_FRAGMENT_INTERVAL.to_owned(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage100Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage100 --benchmark-iters")?, arg)?;
                }
                "--password" => opts.password = next_value(&mut iter, "stage100 --password")?,
                "--target" => opts.target = next_value(&mut iter, "stage100 --target")?,
                "--tls-server-name" => {
                    opts.tls_server_name = next_value(&mut iter, "stage100 --tls-server-name")?;
                }
                "--alpn" => opts.alpn_protocol = next_value(&mut iter, "stage100 --alpn")?,
                "--ws-host" => opts.ws_host = next_value(&mut iter, "stage100 --ws-host")?,
                "--ws-path" => opts.ws_path = next_value(&mut iter, "stage100 --ws-path")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage100 --payload")?.into_bytes();
                }
                "--fragment-length" => {
                    opts.fragment_length = next_value(&mut iter, "stage100 --fragment-length")?;
                }
                "--fragment-interval" => {
                    opts.fragment_interval = next_value(&mut iter, "stage100 --fragment-interval")?;
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage100 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage100 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--password=") => {
                    opts.password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--tls-server-name=") => {
                    opts.tls_server_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--alpn=") => {
                    opts.alpn_protocol = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--ws-host=") => {
                    opts.ws_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--ws-path=") => {
                    opts.ws_path = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--fragment-length=") => {
                    opts.fragment_length = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--fragment-interval=") => {
                    opts.fragment_interval = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage100 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage100 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.ws_host.trim().is_empty() {
            return Err(RunnerOutput::usage("stage100 --ws-host must not be empty"));
        }
        if opts.ws_path.is_empty() {
            opts.ws_path = "/".to_owned();
        } else if !opts.ws_path.starts_with('/') {
            opts.ws_path = format!("/{}", opts.ws_path);
        }
        trojan::TrojanMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage100 target is invalid: {err}")))?;
        opts.tls_options()
            .map_err(|err| RunnerOutput::usage(format!("stage100 tls options invalid: {err}")))?;
        opts.fragment_options().map_err(|err| {
            RunnerOutput::usage(format!("stage100 tls fragment options invalid: {err}"))
        })?;
        Ok(opts)
    }

    fn tls_options(
        &self,
    ) -> Result<shared_transport::TlsUnderlayOptions, dae_outbound::OutboundError> {
        shared_transport::TlsUnderlayOptions::new(&self.tls_server_name, &self.alpn_protocol)
    }

    fn fragment_options(
        &self,
    ) -> Result<shared_transport::TlsFragmentOptions, dae_outbound::OutboundError> {
        shared_transport::TlsFragmentOptions::from_ranges(
            &self.fragment_length,
            &self.fragment_interval,
        )
    }
}
