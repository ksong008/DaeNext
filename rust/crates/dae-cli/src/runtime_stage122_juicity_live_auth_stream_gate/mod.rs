mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage122Options;
use report::stage122_report;

pub(crate) fn run_stage122_juicity_live_auth_stream_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage122Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage122_report(&opts);
    let passed = report["juicity_live_auth_uni_stream_harness_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_live_auth_uni_stream_write_order_admitted"]
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
