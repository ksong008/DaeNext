use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::{shared_transport, vless, vmess};
use serde_json::{Value, json};

mod options;
mod report;
mod smoke;

use options::Stage135Options;
use report::stage135_report;

use crate::runner::RunnerOutput;

const DEFAULT_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_TLS_SERVER_NAME: &str = "stage135-vless-vmess-tls.example";
const DEFAULT_VLESS_WSS_TARGET: &str = "stage135-vless-wss.example:443";
const DEFAULT_VMESS_WSS_TARGET: &str = "stage135-vmess-wss.example:443";
const DEFAULT_VLESS_HTTPUPGRADE_TARGET: &str = "stage135-vless-httpupgrade.example:443";
const DEFAULT_VMESS_HTTPUPGRADE_TARGET: &str = "stage135-vmess-httpupgrade.example:443";
const DEFAULT_WSS_HOST: &str = "stage135-vless-vmess-wss-host.example";
const DEFAULT_WSS_PATH: &str = "/dae-stage135-wss";
const DEFAULT_HTTPUPGRADE_HOST: &str = "stage135-vless-vmess-httpupgrade-host.example";
const DEFAULT_HTTPUPGRADE_PATH: &str = "/dae-stage135-httpupgrade";
const DEFAULT_PAYLOAD: &[u8] = b"stage135-vless-vmess-tls-ping";

pub(crate) fn run_stage135_vless_vmess_tls_wss_httpupgrade_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage135Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage135_report(&opts);
    let passed = report["vless_vmess_tls_wss_httpupgrade_smoke_passed"]
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
