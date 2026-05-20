use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::shadowsocks;
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage95_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_CIPHER: &str = "aes-128-cfb";
const DEFAULT_PASSWORD: &str = "stage95-password";
const DEFAULT_TARGET: &str = "stage95-shadowsocksr.example:9443";
const DEFAULT_PAYLOAD: &[u8] = b"stage95-shadowsocksr-three-layer-ping";
const DEFAULT_OBFS_HOST: &str = "stage95-obfs.example";

pub(crate) fn run_stage95_shadowsocksr_three_layer_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage95Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage95_report(&opts);
    let passed = report["shadowsocksr_three_layer_smoke_passed"]
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
struct Stage95Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    cipher: String,
    password: String,
    target: String,
    payload: Vec<u8>,
    obfs_host: String,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage95Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            cipher: DEFAULT_CIPHER.to_owned(),
            password: DEFAULT_PASSWORD.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            obfs_host: DEFAULT_OBFS_HOST.to_owned(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage95Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage95 --benchmark-iters")?, arg)?;
                }
                "--cipher" => opts.cipher = next_value(&mut iter, "stage95 --cipher")?,
                "--password" => opts.password = next_value(&mut iter, "stage95 --password")?,
                "--target" => opts.target = next_value(&mut iter, "stage95 --target")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage95 --payload")?.into_bytes();
                }
                "--obfs-host" => {
                    opts.obfs_host = next_value(&mut iter, "stage95 --obfs-host")?;
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage95 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage95 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--obfs-host=") => {
                    opts.obfs_host = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage95 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage95 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.cipher != "aes-128-cfb" {
            return Err(RunnerOutput::usage(
                "stage95 supports only aes-128-cfb for SSR stream-cipher admission",
            ));
        }
        shadowsocks::ShadowsocksMetadata::parse(&opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage95 target is invalid: {err}")))?;
        Ok(opts)
    }
}
