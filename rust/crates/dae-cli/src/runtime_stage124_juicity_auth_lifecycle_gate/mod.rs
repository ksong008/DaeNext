mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage124Options;
use report::stage124_report;

pub(crate) fn run_stage124_juicity_auth_lifecycle_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage124Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage124_report(&opts);
    let passed = report["juicity_send_authentication_lifecycle_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_underlay_auth_channel_order_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_multiple_dialauth_records_over_auth_stream_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_auth_stream_finish_boundary_admitted"]
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
