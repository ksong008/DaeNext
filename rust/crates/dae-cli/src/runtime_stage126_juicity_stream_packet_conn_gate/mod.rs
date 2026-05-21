mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage126Options;
use report::stage126_report;

pub(crate) fn run_stage126_juicity_stream_packet_conn_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage126Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage126_report(&opts);
    let passed = report["juicity_stream_packet_conn_live_stream_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_stream_packet_conn_frame_order_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_packet_over_stream_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_stream_packet_conn_dataplane_admitted"]
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
