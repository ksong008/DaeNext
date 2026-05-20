use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{UdpDirectPacketConn, UdpDirectSocketOptions, UdpDirectSocketReport};
use dae_outbound::shadowsocks;
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage90_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_AES_CIPHER: &str = "2022-blake3-aes-128-gcm";
const DEFAULT_AES_PASSWORD: &str = "AQIDBAUGBwgJCgsMDQ4PEA==:ERITFBUWFxgZGhscHR4fIA==";
const DEFAULT_CHACHA_CIPHER: &str = "2022-blake3-chacha20-poly1305";
const DEFAULT_CHACHA_PASSWORD: &str = "MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY=";
const DEFAULT_TARGET: &str = "stage90-ss2022-udp.example:5353";
const DEFAULT_RESPONSE_TARGET: &str = "8.8.8.8:53";
const DEFAULT_PAYLOAD: &[u8] = b"stage90-ss2022-udp-ping";

pub(crate) fn run_stage90_ss2022_udp_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage90Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage90_report(&opts);
    let passed = report["ss2022_udp_smoke_passed"].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Stage90Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    aes_cipher: String,
    aes_password: String,
    chacha_cipher: String,
    chacha_password: String,
    target: String,
    response_target: String,
    payload: Vec<u8>,
    so_mark: u32,
    timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage90Branch {
    AesSeparateHeader,
    ChachaMergedHeader,
}

impl Stage90Branch {
    fn client_session_id(self) -> [u8; 8] {
        match self {
            Self::AesSeparateHeader => *b"client90",
            Self::ChachaMergedHeader => *b"client9c",
        }
    }

    fn server_session_id(self) -> [u8; 8] {
        match self {
            Self::AesSeparateHeader => *b"srv90aes",
            Self::ChachaMergedHeader => *b"srv90cha",
        }
    }

    fn stale_session_id(self) -> [u8; 8] {
        match self {
            Self::AesSeparateHeader => *b"stale90a",
            Self::ChachaMergedHeader => *b"stale90c",
        }
    }

    fn nonce_base(self) -> u8 {
        match self {
            Self::AesSeparateHeader => 0,
            Self::ChachaMergedHeader => 0x70,
        }
    }

    fn response_nonce_base(self) -> u8 {
        match self {
            Self::AesSeparateHeader => 0,
            Self::ChachaMergedHeader => 0x90,
        }
    }

    fn cipher<'a>(self, opts: &'a Stage90Options) -> &'a str {
        match self {
            Self::AesSeparateHeader => &opts.aes_cipher,
            Self::ChachaMergedHeader => &opts.chacha_cipher,
        }
    }

    fn password<'a>(self, opts: &'a Stage90Options) -> &'a str {
        match self {
            Self::AesSeparateHeader => &opts.aes_password,
            Self::ChachaMergedHeader => &opts.chacha_password,
        }
    }
}

impl Default for Stage90Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            aes_cipher: DEFAULT_AES_CIPHER.to_owned(),
            aes_password: DEFAULT_AES_PASSWORD.to_owned(),
            chacha_cipher: DEFAULT_CHACHA_CIPHER.to_owned(),
            chacha_password: DEFAULT_CHACHA_PASSWORD.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            response_target: DEFAULT_RESPONSE_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage90Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage90 --benchmark-iters")?, arg)?;
                }
                "--aes-cipher" => opts.aes_cipher = next_value(&mut iter, "stage90 --aes-cipher")?,
                "--aes-password" => {
                    opts.aes_password = next_value(&mut iter, "stage90 --aes-password")?;
                }
                "--chacha-cipher" => {
                    opts.chacha_cipher = next_value(&mut iter, "stage90 --chacha-cipher")?;
                }
                "--chacha-password" => {
                    opts.chacha_password = next_value(&mut iter, "stage90 --chacha-password")?;
                }
                "--target" => opts.target = next_value(&mut iter, "stage90 --target")?,
                "--response-target" => {
                    opts.response_target = next_value(&mut iter, "stage90 --response-target")?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage90 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage90 --so-mark")?, arg)?;
                }
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage90 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--aes-cipher=") => {
                    opts.aes_cipher = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--aes-password=") => {
                    opts.aes_password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--chacha-cipher=") => {
                    opts.chacha_cipher = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--chacha-password=") => {
                    opts.chacha_password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--response-target=") => {
                    opts.response_target = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage90 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage90 --benchmark-iters must be greater than zero",
            ));
        }
        validate_stage90_options(&opts)?;
        Ok(opts)
    }
}
