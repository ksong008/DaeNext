use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::shadowsocks::{self, AeadTcpSalts};
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage92_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_CIPHER: &str = "aes-128-gcm";
const DEFAULT_PASSWORD: &str = "stage92-password";
const DEFAULT_TARGET: &str = "stage92-sip003-simple-obfs.example:8443";
const DEFAULT_PAYLOAD: &[u8] = b"stage92-sip003-simple-obfs-http-ping";
const DEFAULT_PLUGIN_HOST: &str = "front.example";
const DEFAULT_PLUGIN_PATH: &str = "abc/";

pub(crate) fn run_stage92_sip003_simple_obfs_http_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage92Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage92_report(&opts);
    let passed = report["sip003_simple_obfs_http_smoke_passed"]
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
struct Stage92Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    cipher: String,
    password: String,
    target: String,
    payload: Vec<u8>,
    plugin_host: String,
    plugin_path: String,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage92Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            cipher: DEFAULT_CIPHER.to_owned(),
            password: DEFAULT_PASSWORD.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            plugin_host: DEFAULT_PLUGIN_HOST.to_owned(),
            plugin_path: DEFAULT_PLUGIN_PATH.to_owned(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage92Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage92 --benchmark-iters")?, arg)?;
                }
                "--cipher" => opts.cipher = next_value(&mut iter, "stage92 --cipher")?,
                "--password" => opts.password = next_value(&mut iter, "stage92 --password")?,
                "--target" => opts.target = next_value(&mut iter, "stage92 --target")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage92 --payload")?.into_bytes();
                }
                "--plugin-host" => {
                    opts.plugin_host = next_value(&mut iter, "stage92 --plugin-host")?;
                }
                "--plugin-path" => {
                    opts.plugin_path = next_value(&mut iter, "stage92 --plugin-path")?;
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage92 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage92 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--plugin-host=") => {
                    opts.plugin_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--plugin-path=") => {
                    opts.plugin_path = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage92 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage92 --benchmark-iters must be greater than zero",
            ));
        }
        shadowsocks::cipher_spec(&opts.cipher)
            .map_err(|err| RunnerOutput::usage(format!("stage92 AEAD cipher invalid: {err}")))?;
        shadowsocks::ShadowsocksMetadata::parse(&opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage92 target is invalid: {err}")))?;
        Ok(opts)
    }
}
