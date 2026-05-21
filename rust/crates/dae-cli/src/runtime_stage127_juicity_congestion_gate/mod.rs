mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage127Options;
use report::stage127_report;

pub(crate) fn run_stage127_juicity_congestion_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage127Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage127_report(&opts);
    let passed = report["juicity_congestion_bbr_controller_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_congestion_sustained_relay_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_congestion_behavior_admitted"]
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
