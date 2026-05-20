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

use report::stage105_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_AUTH: &str = "stage105-anytls-auth";
const DEFAULT_ORIGINAL_UDP_TARGET: &str = "stage105-udp.example:5353";
const DEFAULT_TLS_SERVER_NAME: &str = "stage105-anytls.example";
const DEFAULT_FIRST_PAYLOAD: &[u8] = b"stage105-anytls-udp-first-packet";
const DEFAULT_NEXT_PAYLOAD: &[u8] = b"stage105-anytls-udp-next-packet";

pub(crate) fn run_stage105_anytls_udp_packet_stream_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage105Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage105_report(&opts);
    let passed = report["anytls_udp_packet_stream_smoke_passed"]
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
struct Stage105Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    auth: String,
    original_udp_target: String,
    tls_server_name: String,
    alpn_protocol: String,
    first_payload: Vec<u8>,
    next_payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage105Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            auth: DEFAULT_AUTH.to_owned(),
            original_udp_target: DEFAULT_ORIGINAL_UDP_TARGET.to_owned(),
            tls_server_name: DEFAULT_TLS_SERVER_NAME.to_owned(),
            alpn_protocol: shared_transport::DEFAULT_TLS_ALPN.to_owned(),
            first_payload: DEFAULT_FIRST_PAYLOAD.to_vec(),
            next_payload: DEFAULT_NEXT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage105Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage105 --benchmark-iters")?, arg)?;
                }
                "--auth" => opts.auth = next_value(&mut iter, "stage105 --auth")?,
                "--target" | "--original-udp-target" => {
                    opts.original_udp_target =
                        next_value(&mut iter, "stage105 --original-udp-target")?;
                }
                "--tls-server-name" => {
                    opts.tls_server_name = next_value(&mut iter, "stage105 --tls-server-name")?;
                }
                "--alpn" => opts.alpn_protocol = next_value(&mut iter, "stage105 --alpn")?,
                "--first-payload" => {
                    opts.first_payload =
                        next_value(&mut iter, "stage105 --first-payload")?.into_bytes();
                }
                "--next-payload" => {
                    opts.next_payload =
                        next_value(&mut iter, "stage105 --next-payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage105 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage105 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--auth=") => {
                    opts.auth = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") || arg.starts_with("--original-udp-target=") => {
                    opts.original_udp_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--tls-server-name=") => {
                    opts.tls_server_name = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--alpn=") => {
                    opts.alpn_protocol = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--first-payload=") => {
                    opts.first_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--next-payload=") => {
                    opts.next_payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
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
                        "unsupported stage105 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage105 --benchmark-iters must be greater than zero",
            ));
        }
        Socks5Address::parse(&opts.original_udp_target).map_err(|err| {
            RunnerOutput::usage(format!("stage105 original UDP target is invalid: {err}"))
        })?;
        opts.tls_options()
            .map_err(|err| RunnerOutput::usage(format!("stage105 tls options invalid: {err}")))?;
        Ok(opts)
    }

    fn tls_options(
        &self,
    ) -> Result<shared_transport::TlsUnderlayOptions, dae_outbound::OutboundError> {
        shared_transport::TlsUnderlayOptions::new(&self.tls_server_name, &self.alpn_protocol)
    }
}
