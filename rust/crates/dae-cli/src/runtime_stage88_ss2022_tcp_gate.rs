use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::shadowsocks::{self, Ss2022TcpSalts};
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage88_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_CIPHER: &str = "2022-blake3-aes-256-gcm";
const DEFAULT_PASSWORD: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
const DEFAULT_TARGET: &str = "stage88-ss2022-tcp.example:443";
const DEFAULT_PAYLOAD: &[u8] = b"stage88-ss2022-tcp-ping";

pub(crate) fn run_stage88_ss2022_tcp_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage88Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage88_report(&opts);
    let passed = report["ss2022_tcp_smoke_passed"].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage88Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    cipher: String,
    password: String,
    target: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage88Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            cipher: DEFAULT_CIPHER.to_owned(),
            password: DEFAULT_PASSWORD.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage88Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage88 --benchmark-iters")?, arg)?;
                }
                "--cipher" => opts.cipher = next_value(&mut iter, "stage88 --cipher")?,
                "--password" => opts.password = next_value(&mut iter, "stage88 --password")?,
                "--target" => opts.target = next_value(&mut iter, "stage88 --target")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage88 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage88 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage88 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--cipher=") => {
                    opts.cipher = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--password=") => {
                    opts.password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage88 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage88 --benchmark-iters must be greater than zero",
            ));
        }
        shadowsocks::ss2022::validate_psk_list(&opts.cipher, &opts.password)
            .map_err(|err| RunnerOutput::usage(format!("stage88 SS2022 PSK invalid: {err}")))?;
        if opts.password.split(':').count() != 1 {
            return Err(RunnerOutput::usage(
                "stage88 admits SS2022 TCP single PSK only; multi-PSK identity header remains gated",
            ));
        }
        shadowsocks::ShadowsocksMetadata::parse(&opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage88 target is invalid: {err}")))?;
        Ok(opts)
    }
}
