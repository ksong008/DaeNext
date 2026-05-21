mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage130Options;
use report::stage130_report;

pub(crate) fn run_stage130_hysteria2_true_quic_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage130Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage130_report(&opts);
    let passed = report["hysteria2_full_quic_handshake_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["hysteria2_stream_mux_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["hysteria2_packet_datagram_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["hysteria2_port_hopping_scheduler_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["hysteria2_true_quic_dataplane_admitted"]
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
