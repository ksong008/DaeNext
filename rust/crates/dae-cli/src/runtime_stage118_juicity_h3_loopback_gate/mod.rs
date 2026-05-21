mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage118Options;
use report::stage118_report;

pub(crate) fn run_stage118_juicity_h3_loopback_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage118Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage118_report(&opts);
    let passed = report["juicity_h3_loopback_smoke_executed"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_h3_handshake_admitted"]
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
