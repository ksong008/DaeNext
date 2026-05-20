use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::anytls;
use dae_outbound::shared_transport;
use dae_outbound::socks5::Socks5Address;
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage104_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_AUTH: &str = "stage104-anytls-auth";
const DEFAULT_TARGET: &str = "stage104-anytls-target.example:443";
const DEFAULT_TLS_SERVER_NAME: &str = "stage104-anytls.example";
const DEFAULT_PAYLOAD: &[u8] = b"stage104-anytls-session-frame-ping";

pub(crate) fn run_stage104_anytls_session_frame_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage104Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage104_report(&opts);
    let passed = report["anytls_session_frame_smoke_passed"]
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
struct Stage104Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    auth: String,
    target: String,
    tls_server_name: String,
    alpn_protocol: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage104Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            auth: DEFAULT_AUTH.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            tls_server_name: DEFAULT_TLS_SERVER_NAME.to_owned(),
            alpn_protocol: shared_transport::DEFAULT_TLS_ALPN.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage104Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage104 --benchmark-iters")?, arg)?;
                }
                "--auth" => opts.auth = next_value(&mut iter, "stage104 --auth")?,
                "--target" => opts.target = next_value(&mut iter, "stage104 --target")?,
                "--tls-server-name" => {
                    opts.tls_server_name = next_value(&mut iter, "stage104 --tls-server-name")?;
                }
                "--alpn" => opts.alpn_protocol = next_value(&mut iter, "stage104 --alpn")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage104 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage104 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage104 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--auth=") => {
                    opts.auth = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage104 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage104 --benchmark-iters must be greater than zero",
            ));
        }
        Socks5Address::parse(&opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage104 target is invalid: {err}")))?;
        opts.tls_options()
            .map_err(|err| RunnerOutput::usage(format!("stage104 tls options invalid: {err}")))?;
        Ok(opts)
    }

    fn tls_options(
        &self,
    ) -> Result<shared_transport::TlsUnderlayOptions, dae_outbound::OutboundError> {
        shared_transport::TlsUnderlayOptions::new(&self.tls_server_name, &self.alpn_protocol)
    }
}
