mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage132Options;
use report::stage132_report;

pub(crate) fn run_stage132_quic_h3_family_recertification_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage132Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage132_report(&opts);
    let passed = report["quic_h3_family_true_dataplane_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["hysteria2_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["tuic_true_quic_dataplane_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_true_quic_h3_dataplane_admitted"]
            .as_bool()
            .unwrap_or(false)
        && !report["tuic_udp_relay_mode_quic_effective_relay_admitted"]
            .as_bool()
            .unwrap_or(true)
        && !report["outbound_true_dataplane_admitted"]
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
