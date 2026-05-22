mod report;

use crate::runner::RunnerOutput;

pub(crate) fn run_stage140_vless_vmess_utls_profile_builder_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage140 argument: {arg}"));
    }
    match report::stage140_report() {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err),
    }
}
