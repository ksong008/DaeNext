mod report;

use crate::runner::RunnerOutput;

pub(crate) fn run_stage141_vless_reality_synthetic_utls_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage141 argument: {arg}"));
    }
    match report::stage141_report() {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err),
    }
}
