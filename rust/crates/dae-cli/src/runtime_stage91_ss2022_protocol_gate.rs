use dae_outbound::shadowsocks;
use serde_json::{Value, json};

mod report;

use report::stage91_report;

use crate::runner::RunnerOutput;

pub(crate) fn run_stage91_ss2022_protocol_admission(args: &[String]) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported stage91 argument: {arg}"));
    }
    let report = stage91_report();
    RunnerOutput::ok(format!("{report}\n"))
}
