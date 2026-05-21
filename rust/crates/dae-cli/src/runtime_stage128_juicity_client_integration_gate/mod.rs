mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage128Options;
use report::stage128_report;

pub(crate) fn run_stage128_juicity_client_integration_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage128Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage128_report(&opts);
    let passed = report["juicity_client_integration_candidate_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_full_local_client_smoke_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_client_capability_matrix_admitted"]
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
