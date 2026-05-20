mod options;
mod report;
mod smoke;

use crate::runner::RunnerOutput;

use options::Stage109Options;
use report::stage109_report;

pub(crate) fn run_stage109_hysteria2_udp_underlay_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage109Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage109_report(&opts);
    let passed = report["hysteria2_udp_underlay_smoke_passed"]
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
