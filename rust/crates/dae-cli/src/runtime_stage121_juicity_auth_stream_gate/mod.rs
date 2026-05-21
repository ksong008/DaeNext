mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage121Options;
use report::stage121_report;

pub(crate) fn run_stage121_juicity_auth_stream_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage121Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage121_report(&opts);
    let passed = report["juicity_authenticate_header_layout_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_auth_uni_stream_write_order_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_dialauth_record_over_auth_stream_admitted"]
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
