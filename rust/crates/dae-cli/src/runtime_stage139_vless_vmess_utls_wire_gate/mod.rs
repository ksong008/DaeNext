mod fixture;
mod report;

use crate::runner::RunnerOutput;

pub(crate) fn run_stage139_vless_vmess_utls_wire_baseline_gate(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage139 argument: {arg}"));
    }
    match report::stage139_report() {
        Ok(report) => RunnerOutput::ok(format!("{report}\n")),
        Err(err) => RunnerOutput::stdout_error(err),
    }
}
