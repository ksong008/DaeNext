use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use dae_outbound::{shared_transport, vless, vmess};
use serde_json::{Value, json};

mod options;
mod report;
mod smoke;

use options::Stage134Options;
use report::stage134_report;

use crate::runner::RunnerOutput;

const DEFAULT_VLESS_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_VMESS_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_VLESS_TARGET: &str = "stage134-vless-grpc-http2-target.example:443";
const DEFAULT_VMESS_TARGET: &str = "stage134-vmess-grpc-http2-target.example:443";
const DEFAULT_GRPC_ADDRESS: &str = "stage134-v2ray-grpc-http2-proxy.example:443";
const DEFAULT_GRPC_SERVICE_NAME: &str = "";
const DEFAULT_GRPC_SERVER_NAME: &str = "stage134-v2ray-grpc-http2-sni.example";
const DEFAULT_GRPC_DIALER_ID: &str = "stage134-v2ray-grpc-http2-dialer";
const DEFAULT_VLESS_PAYLOAD: &[u8] = b"stage134-vless-grpc-http2-ping";
const DEFAULT_VMESS_PAYLOAD: &[u8] = b"stage134-vmess-grpc-http2-ping";

pub(crate) fn run_stage134_vless_vmess_grpc_http2_lifecycle_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage134Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage134_report(&opts);
    let passed = report["vless_vmess_grpc_http2_lifecycle_smoke_passed"]
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
