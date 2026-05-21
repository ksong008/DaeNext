mod options;
mod report;
mod smoke;

use crate::runner::RunnerOutput;

use options::Stage112Options;
use report::stage112_report;

pub(crate) fn run_stage112_tuic_udp_underlay_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage112Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage112_report(&opts);
    let passed = report["tuic_udp_underlay_socket_smoke_passed"]
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
