use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport, UdpDirectPacketConn,
    UdpDirectSocketOptions, UdpDirectSocketReport, bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::socks5::{self, Socks5Address, handshake, udp_packet};
use serde_json::{Value, json};

mod report;
mod server;
mod smoke;
mod utils;

use report::stage56_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_ASSOCIATE_TARGET: &str = "0.0.0.0:0";
const DEFAULT_PACKET_TARGET: &str = "stage56.example:5353";
const DEFAULT_USERNAME: &str = "user";
const DEFAULT_PASSWORD: &str = "pass";
const DEFAULT_PAYLOAD: &[u8] = b"stage56-socks5-udp-ping";
const DEFAULT_RESPONSE: &[u8] = b"stage56-socks5-udp-ack";

pub(crate) fn run_stage56_socks5_udp_associate_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage56Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage56_report(&opts);
    let passed = report["socks5_udp_smoke_passed"].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage56Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    associate_target: String,
    packet_target: String,
    username: String,
    password: String,
    payload: Vec<u8>,
    response: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage56Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            associate_target: DEFAULT_ASSOCIATE_TARGET.to_owned(),
            packet_target: DEFAULT_PACKET_TARGET.to_owned(),
            username: DEFAULT_USERNAME.to_owned(),
            password: DEFAULT_PASSWORD.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            response: DEFAULT_RESPONSE.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage56Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage56 --benchmark-iters")?, arg)?;
                }
                "--associate-target" => {
                    opts.associate_target = next_value(&mut iter, "stage56 --associate-target")?;
                }
                "--packet-target" => {
                    opts.packet_target = next_value(&mut iter, "stage56 --packet-target")?;
                }
                "--username" => opts.username = next_value(&mut iter, "stage56 --username")?,
                "--password" => opts.password = next_value(&mut iter, "stage56 --password")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage56 --payload")?.into_bytes();
                }
                "--response" => {
                    opts.response = next_value(&mut iter, "stage56 --response")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage56 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage56 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--associate-target=") => {
                    opts.associate_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--packet-target=") => {
                    opts.packet_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--username=") => {
                    opts.username = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--password=") => {
                    opts.password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--response=") => {
                    opts.response = arg.split_once('=').unwrap().1.as_bytes().to_vec();
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
                        "unsupported stage56 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage56 --benchmark-iters must be greater than zero",
            ));
        }
        Ok(opts)
    }
}
