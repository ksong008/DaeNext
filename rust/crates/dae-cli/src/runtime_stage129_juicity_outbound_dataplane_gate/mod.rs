mod options;
mod report;

use crate::runner::RunnerOutput;

use options::Stage129Options;
use report::stage129_report;

pub(crate) fn run_stage129_juicity_outbound_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage129Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage129_report(&opts);
    let passed = report["juicity_outbound_registry_admitted"]
        .as_bool()
        .unwrap_or(false)
        && report["juicity_group_selection_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_health_policy_admitted"]
            .as_bool()
            .unwrap_or(false)
        && report["juicity_true_quic_h3_dataplane_admitted"]
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
