mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage120Options;
use report::stage120_report;

pub(crate) fn run_stage120_juicity_packet_state_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage120Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage120_report(&opts);
    let passed = report["juicity_dialauth_record_protocol_state_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_udp_port_zero_transport_packet_conn_route_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_stream_packet_conn_frame_admitted"]
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
