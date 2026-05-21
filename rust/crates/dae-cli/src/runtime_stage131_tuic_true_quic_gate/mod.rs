mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage131Options;
use report::stage131_report;

pub(crate) fn run_stage131_tuic_true_quic_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage131Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage131_report(&opts);
    let passed = report["tuic_full_quic_handshake_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["tuic_auth_stream_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["tuic_datagram_packet_relay_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["tuic_congestion_behavior_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["tuic_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap_or(false)
        && !report["tuic_udp_relay_mode_quic_effective_relay_admitted"]
            .as_bool()
            .unwrap_or(true);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}
