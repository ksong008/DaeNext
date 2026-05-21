mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage125Options;
use report::stage125_report;

pub(crate) fn run_stage125_juicity_transport_packet_conn_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage125Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage125_report(&opts);
    let passed = report["juicity_transport_packet_conn_crypto_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_transport_packet_conn_first_iv_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_transport_packet_conn_udp_roundtrip_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_transport_packet_conn_dataplane_admitted"]
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
