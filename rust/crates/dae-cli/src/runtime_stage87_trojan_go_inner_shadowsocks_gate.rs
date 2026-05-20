use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::shadowsocks::{self, AeadTcpSalts};
use dae_outbound::trojan;
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage87_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_CIPHER: &str = "aes-256-gcm";
const DEFAULT_SHADOWSOCKS_PASSWORD: &str = "stage87-ss-password";
const DEFAULT_TROJAN_PASSWORD: &str = "stage87-trojan-password";
const DEFAULT_TARGET: &str = "stage87-trojan-go-inner-ss.example:443";
const DEFAULT_RESPONSE_METADATA_TARGET: &str = "stage87-inner-ss-response.example:9443";
const DEFAULT_PAYLOAD: &[u8] = b"stage87-trojan-go-inner-shadowsocks-ping";

pub(crate) fn run_stage87_trojan_go_inner_shadowsocks_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage87Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage87_report(&opts);
    let passed = report["trojan_go_inner_shadowsocks_smoke_passed"]
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
struct Stage87Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    cipher: String,
    shadowsocks_password: String,
    trojan_password: String,
    target: String,
    response_metadata_target: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage87Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            cipher: DEFAULT_CIPHER.to_owned(),
            shadowsocks_password: DEFAULT_SHADOWSOCKS_PASSWORD.to_owned(),
            trojan_password: DEFAULT_TROJAN_PASSWORD.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            response_metadata_target: DEFAULT_RESPONSE_METADATA_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage87Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage87 --benchmark-iters")?, arg)?;
                }
                "--cipher" => opts.cipher = next_value(&mut iter, "stage87 --cipher")?,
                "--shadowsocks-password" => {
                    opts.shadowsocks_password =
                        next_value(&mut iter, "stage87 --shadowsocks-password")?;
                }
                "--trojan-password" => {
                    opts.trojan_password = next_value(&mut iter, "stage87 --trojan-password")?;
                }
                "--target" => opts.target = next_value(&mut iter, "stage87 --target")?,
                "--response-metadata-target" => {
                    opts.response_metadata_target =
                        next_value(&mut iter, "stage87 --response-metadata-target")?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage87 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage87 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage87 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--cipher=") => {
                    opts.cipher = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--shadowsocks-password=") => {
                    opts.shadowsocks_password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--trojan-password=") => {
                    opts.trojan_password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--response-metadata-target=") => {
                    opts.response_metadata_target = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage87 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage87 --benchmark-iters must be greater than zero",
            ));
        }
        shadowsocks::cipher_spec(&opts.cipher)
            .map_err(|err| RunnerOutput::usage(format!("stage87 requires AEAD cipher: {err}")))?;
        trojan::TrojanMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage87 target is invalid: {err}")))?;
        shadowsocks::ShadowsocksMetadata::parse(&opts.response_metadata_target).map_err(|err| {
            RunnerOutput::usage(format!(
                "stage87 response metadata target is invalid: {err}"
            ))
        })?;
        Ok(opts)
    }
}
