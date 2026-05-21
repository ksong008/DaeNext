mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage119Options;
use report::stage119_report;

pub(crate) fn run_stage119_juicity_live_certchain_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage119Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage119_report(&opts);
    let passed = report["juicity_pinned_certchain_live_callback_matched"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_tls_certchain_verification_admitted"]
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
