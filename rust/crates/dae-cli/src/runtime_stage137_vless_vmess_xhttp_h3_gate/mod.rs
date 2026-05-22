use std::time::{Duration, Instant};

use dae_outbound::{shared_transport, vless, vmess};
use serde_json::{Value, json};

mod options;
mod report;
mod smoke;

use options::Stage137Options;
use report::stage137_report;

use crate::runner::RunnerOutput;

const DEFAULT_VLESS_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_VMESS_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_VLESS_TARGET: &str = "stage137-vless-xhttp-h3-target.example:443";
const DEFAULT_VMESS_TARGET: &str = "stage137-vmess-xhttp-h3-target.example:443";
const DEFAULT_XHTTP_HOST: &str = "stage137-vless-vmess-xhttp-h3.example";
const DEFAULT_XHTTP_PATH: &str = "/dae-stage137-xhttp-h3";
const DEFAULT_XHTTP_MODE: &str = "packet-up";
const DEFAULT_XHTTP_SECURITY: &str = "tls";
const DEFAULT_XHTTP_ALPN: &str = "h3";
const DEFAULT_XHTTP_SESSION_ID: &str = "dae-stage137-xhttp-h3-session";
const DEFAULT_XHTTP_SEQ: u64 = 1370;
const DEFAULT_VLESS_PAYLOAD: &[u8] = b"stage137-vless-xhttp-h3-ping";
const DEFAULT_VMESS_PAYLOAD: &[u8] = b"stage137-vmess-xhttp-h3-ping";

pub(crate) fn run_stage137_vless_vmess_xhttp_h3_lifecycle_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage137Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage137_report(&opts);
    let passed = report["vless_vmess_xhttp_h3_lifecycle_smoke_passed"]
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
