use std::io::{ErrorKind, Write};
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

use report::stage80_report;
use utils::*;

use crate::runner::RunnerOutput;

const DEFAULT_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_TARGET: &str = "stage80-vless-xhttp-xmux-target.example:443";
const DEFAULT_XHTTP_HOST: &str = "stage80-vless-xhttp-xmux.example";
const DEFAULT_XHTTP_PATH: &str = "/dae-stage80-xhttp-xmux";
const DEFAULT_XHTTP_MODE: &str = "packet-up";
const DEFAULT_XHTTP_SECURITY: &str = "tls";
const DEFAULT_XHTTP_ALPN: &str = "h2";
const DEFAULT_XHTTP_SESSION_ID: &str = "dae-stage80-xhttp-xmux";
const DEFAULT_XHTTP_SEQ: u64 = 80;
const DEFAULT_PAYLOAD: &[u8] = b"stage80-vless-xhttp-xmux-ping";
const DEFAULT_XMUX_MAX_CONNECTIONS: u32 = 2;
const DEFAULT_XMUX_C_MAX_REUSE_TIMES: u32 = 4;

pub(crate) fn run_stage80_vless_xhttp_xmux_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage80Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage80_report(&opts);
    let passed = report["vless_xhttp_xmux_smoke_passed"]
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
struct Stage80Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    uuid: String,
    target: String,
    xhttp_host: String,
    xhttp_path: String,
    xhttp_mode: String,
    xhttp_security: String,
    xhttp_alpn: String,
    xhttp_session_id: String,
    xhttp_seq: u64,
    xmux_max_connections: u32,
    xmux_c_max_reuse_times: u32,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage80Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            xhttp_host: DEFAULT_XHTTP_HOST.to_owned(),
            xhttp_path: DEFAULT_XHTTP_PATH.to_owned(),
            xhttp_mode: DEFAULT_XHTTP_MODE.to_owned(),
            xhttp_security: DEFAULT_XHTTP_SECURITY.to_owned(),
            xhttp_alpn: DEFAULT_XHTTP_ALPN.to_owned(),
            xhttp_session_id: DEFAULT_XHTTP_SESSION_ID.to_owned(),
            xhttp_seq: DEFAULT_XHTTP_SEQ,
            xmux_max_connections: DEFAULT_XMUX_MAX_CONNECTIONS,
            xmux_c_max_reuse_times: DEFAULT_XMUX_C_MAX_REUSE_TIMES,
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage80Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage80 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage80 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage80 --target")?,
                "--xhttp-host" => opts.xhttp_host = next_value(&mut iter, "stage80 --xhttp-host")?,
                "--xhttp-path" => opts.xhttp_path = next_value(&mut iter, "stage80 --xhttp-path")?,
                "--xhttp-mode" => opts.xhttp_mode = next_value(&mut iter, "stage80 --xhttp-mode")?,
                "--xhttp-security" => {
                    opts.xhttp_security = next_value(&mut iter, "stage80 --xhttp-security")?
                }
                "--xhttp-alpn" => opts.xhttp_alpn = next_value(&mut iter, "stage80 --xhttp-alpn")?,
                "--xhttp-session-id" => {
                    opts.xhttp_session_id = next_value(&mut iter, "stage80 --xhttp-session-id")?
                }
                "--xhttp-seq" => {
                    opts.xhttp_seq =
                        parse_u64(&next_value(&mut iter, "stage80 --xhttp-seq")?, arg)?;
                }
                "--xmux-max-connections" => {
                    opts.xmux_max_connections = parse_u32(
                        &next_value(&mut iter, "stage80 --xmux-max-connections")?,
                        arg,
                    )?;
                }
                "--xmux-c-max-reuse-times" => {
                    opts.xmux_c_max_reuse_times = parse_u32(
                        &next_value(&mut iter, "stage80 --xmux-c-max-reuse-times")?,
                        arg,
                    )?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage80 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage80 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage80 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--xhttp-host=") => {
                    opts.xhttp_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-path=") => {
                    opts.xhttp_path = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-mode=") => {
                    opts.xhttp_mode = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-security=") => {
                    opts.xhttp_security = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-alpn=") => {
                    opts.xhttp_alpn = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-session-id=") => {
                    opts.xhttp_session_id = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-seq=") => {
                    opts.xhttp_seq = parse_u64(arg.split_once('=').unwrap().1, "--xhttp-seq")?;
                }
                _ if arg.starts_with("--xmux-max-connections=") => {
                    opts.xmux_max_connections =
                        parse_u32(arg.split_once('=').unwrap().1, "--xmux-max-connections")?;
                }
                _ if arg.starts_with("--xmux-c-max-reuse-times=") => {
                    opts.xmux_c_max_reuse_times =
                        parse_u32(arg.split_once('=').unwrap().1, "--xmux-c-max-reuse-times")?;
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
                        "unsupported stage80 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage80 --benchmark-iters must be greater than zero",
            ));
        }
        vless::password_to_key(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage80 uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage80 target is invalid: {err}")))?;
        opts.xhttp_options()
            .map_err(|err| RunnerOutput::usage(format!("stage80 xhttp options invalid: {err}")))?;
        Ok(opts)
    }

    fn xhttp_options(
        &self,
    ) -> Result<shared_transport::XHttpLifecycleOptions, dae_outbound::OutboundError> {
        self.xhttp_options_for_seq(self.xhttp_seq)
    }

    fn xhttp_options_for_seq(
        &self,
        seq: u64,
    ) -> Result<shared_transport::XHttpLifecycleOptions, dae_outbound::OutboundError> {
        let xmux = shared_transport::XHttpXmuxOptions::new(
            self.xmux_max_connections,
            self.xmux_c_max_reuse_times,
        )?;
        shared_transport::XHttpLifecycleOptions::new(
            &self.xhttp_host,
            &self.xhttp_path,
            &self.xhttp_mode,
            &self.xhttp_security,
            &self.xhttp_alpn,
            &self.xhttp_session_id,
            seq,
        )
        .map(|options| options.with_xmux(xmux))
    }
}
