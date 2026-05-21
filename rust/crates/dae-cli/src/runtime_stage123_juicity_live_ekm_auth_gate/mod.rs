mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage123Options;
use report::stage123_report;

pub(crate) fn run_stage123_juicity_live_ekm_auth_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage123Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage123_report(&opts);
    let passed = report["juicity_auth_token_live_ekm_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_live_ekm_auth_header_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_live_ekm_auth_stream_transcript_admitted"]
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
